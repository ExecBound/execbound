# SPDX-License-Identifier: AGPL-3.0-only
"""Shared fixtures for the Arcade tests: the hook carrier, a stated failure and a correction.

The settlement halves reach `_settle` over the existing outcome route — the route the
extension constructs a body for — and `reconcile`. They sit outside `tests/test_arcade.py`
because GC14 and GC17 need a row in the new state before either can falsify anything
about it, which as written neither could.

The carrier half drives the real HTTP surface: one application built from a real runtime
and a real tool map, and one pre hook of the shape `docs/ARCADE.md` describes under "The pre
hook" posted at it. It is a caller and holds no ExecBound state, so the refusals the rows
assert are the deployment's own.
"""

import json
from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from checkpoint_fixtures import (
    GATE_KEY_ID,
    audit_kinds,
    checkpoint,
    register_keypair,
    report,
    scoped,
    signed_record,
)
from context_fixtures import (
    CATALOG,
    SYNTHETIC_FACTS,
    SYNTHETIC_OPERATION,
    seed_synthetic,
    synthetic_bundle,
)
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_execution import world as world

from execbound.app import create_app
from execbound.arcade import ArcadeBlock
from execbound.arcade.boundary import create_arcade
from execbound.execution import reconcile, store
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.runtime import Runtime, executor_verifier
from execbound.surfaces.tokens import TokenKeys

# What a control point states when its tool call did not succeed: the outcome and reason
# `_reported` builds an `AssertedOutcome` from, over the route the extension would use.
FAILURE = {"outcome": "FAILED_EFFECT_UNKNOWN", "reason": "REPORTED_FAILURE"}
# The two verified non-executions a correction may present, and the state each settles at.
CORRECTIONS = (
    ({"outcome": "FAILED_NOT_EXECUTED", "reason": "CANCELLED_NOT_EXECUTED"}, "FAILED_NOT_EXECUTED"),
    ({"outcome": "FAILED_NOT_EXECUTED", "reason": "VERSION_MISMATCH"}, "STALE_AUTHORIZATION"),
)


def verifier(db, world, execution_id):
    """The verifier the outcome route would build, handed to `reconcile` instead."""
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        return executor_verifier(conn, store.read(conn, tenant, execution_id))


def signed(db, world, execution_id, changes, *, private_key=None, key_id=GATE_KEY_ID):
    """One executor-signed record bound to this execution's frozen command."""
    return json.dumps(
        signed_record(db, world, execution_id, private_key=private_key, key_id=key_id, **changes)
    ).encode()


def correct(db, world, execution_id, changes, *, reason="the platform's report was false"):
    return reconcile(
        db,
        world["admin"],
        execution_id,
        reason=reason,
        evidence=signed(db, world, execution_id, changes),
        verifier=verifier(db, world, execution_id),
        clock=world["clock"],
    )


def stated_failure(db, world, admin_engine, action=None):
    """One grant settled by the platform's bare word that the call failed."""
    granted = checkpoint(db, world, action=action)
    grant = granted.view.checkpoint
    assert grant is not None
    view = report(db, world, granted.view.execution_id, grant.report_secret, **FAILURE)
    assert view.state == "FAILED_EFFECT_UNKNOWN"
    return granted.view.execution_id, grant.report_secret


def transitions(admin_engine, tenant, execution_id):
    """Every transition this execution retains, oldest first: from_state, to_state, tier."""
    return [
        (payload.get("from_state"), payload["to_state"], payload.get("tier"))
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.transition" and payload["execution_id"] == str(execution_id)
    ]


def claim_releases(admin_engine, tenant):
    return [
        payload
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.claim_released"
    ]


def rewrite_reason(admin_engine, tenant, execution_id, reason):
    """Rewrite the retained reason over the owner connection; no kernel path writes this.

    `TERMINAL_PAIRS` admits FAILED_EFFECT_UNKNOWN beside REPORTED_FAILURE and nothing else,
    so a settled row in that state whose retained reason is something else exists only
    here. It is what makes `_correctable`'s third fact a refusal rather than a comment.
    """
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.executions "
                "SET result = jsonb_set(result, '{reason}', to_jsonb(CAST(:r AS text))) "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"r": reason, "t": tenant, "e": execution_id},
        )


# The tool the hooks below name, and the operation an operator declared it reaches. The
# guide's example block governs `endpoint.isolate`; see `arcade_world` for what this
# declaration governs instead.
GOVERNED_TOOL = {"toolkit": "endpoint_mock", "name": "ContainDevice", "version": "1.0"}
ARCADE_TOOL = {
    "toolkit": GOVERNED_TOOL["toolkit"],
    "name": GOVERNED_TOOL["name"],
    "versions": [GOVERNED_TOOL["version"]],
    "operation_ref": SYNTHETIC_OPERATION,
    "target": {"kind": "provider_id", "input": "device_id"},
    "inputs": ["device_id"],
    "arguments": {},
    "expect": {"destructive": True, "read_only": False},
}
# The provider id of the world's own endpoint, which is the value the declared `device_id`
# input carries. A `provider_id` selector resolves through `resource_aliases` and never
# through the `resources.provider_id` column, so an alias is what makes one usable.
WORLD_DEVICE = "device-01"
ARCADE_BLOCK = {
    "deadline_seconds": 4.0,
    "tools": [ARCADE_TOOL],
    "ungoverned_toolkits": ["gmail"],
}
# An approval policy over the synthetic contract's own risk fact, which is what puts one
# governed hook in front of a human while another of the same tool passes. The authorization
# pack permits an isolation from a risk of 50, so a target below this threshold and above
# that one is decided without an approval and a target above both waits for a person.
APPROVE_RISKY = (
    'permit(principal, action == ExecBound::Action::"endpoint.isolate", resource) '
    "when { resource.risk_score >= 60 };"
)
# The page a pending answer names. It carries no approval id, because the runtime presents
# the deployment's approvals list and not a row, so what the agent is handed points a human
# at a queue.
APPROVALS_PAGE = "https://execbound.example/approvals"


def governed_target(engine, world, provider_id, *, age=60, facts=None, approver=None):
    """One endpoint a governed hook can name: its facts, its canonical id and its alias.

    ``approver`` provisions one approval scope on the new canonical target, which is what a
    HUMAN_APPROVER needs before it may decide an approval about it; the rows that never
    reach an approval pass none and provision none.
    """
    tenant, resource, canonical = world["identity"].tenant_id, uuid4(), uuid4()
    now = world["clock"].now()
    params = {
        "t": tenant,
        "a": world["account"],
        "r": resource,
        "c": canonical,
        "s": world["inventory"],
        "p": provider_id,
        "n": now,
        "observed": now - timedelta(seconds=age),
        "expires": now + timedelta(days=1),
        "start": now - timedelta(days=1),
        "alias": uuid4(),
    }
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO execbound.canonical_targets VALUES (:t,:c,:n)"), params)
        conn.execute(
            text(
                "INSERT INTO execbound.resources "
                "(tenant_id,account_id,provider,resource_type,resource_id,provider_id,version,"
                "source_id,role,environment,criticality,observed_at) "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:p,'resource-v1',:s,"
                "'workstation','development',2,:observed)"
            ),
            params,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resource_identities "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:c)"
            ),
            params,
        )
        _facts(conn, params, facts)
        _alias(conn, params)
        if approver is not None:
            conn.execute(
                text(
                    "INSERT INTO execbound.approval_scopes "
                    "(tenant_id,approver_id,canonical_target_id,action, space_id) "
                    "VALUES (:t,:approver,:c,'endpoint.isolate', "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                {**params, "approver": approver},
            )
    return resource


def _facts(conn, params, facts=None):
    for name, value in (facts or SYNTHETIC_FACTS).items():
        conn.execute(
            text(
                "INSERT INTO execbound.resource_facts "
                "(tenant_id,account_id,provider,resource_type,resource_id,fact_name,value,"
                "source_id,version,observed_at) "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:name,CAST(:value AS jsonb),"
                ":s,'fact-v1',:observed)"
            ),
            {**params, "name": name, "value": value},
        )


def _alias(conn, params):
    conn.execute(
        text(
            "INSERT INTO execbound.resource_aliases "
            "(tenant_id,alias_id,account_id,provider,resource_type,kind,normalized_value,"
            "resource_id,valid_from,expires_at) "
            "VALUES (:t,:alias,:a,'mock_crowdstrike','endpoint','provider_id',:p,:r,"
            ":start,:expires)"
        ),
        params,
    )


@pytest.fixture
def arcade_world(db, world, owner, admin_engine):
    """A Gate deployment the pre hooks reach, and why its operation is not the guide's example.

    The placement is the checkpoint's Gate placement: an owner-provisioned mapping carrying
    `external_executor`, one registered executor key, and no connector for the account, so
    ExecBound decides and dispatches nothing.

    What differs from the documented example is the operation. The `arcade` block's example
    governs `endpoint.isolate`, whose released context contract sets `incident="required"`,
    and `registry.incident` reads the id from `ActionRequest.claimed_context.incident_id`
    alone, so a hook reaches it only through the tool map's `incident` declaration (AL34).
    The rows here govern `context_fixtures`' synthetic contract instead, which requires no
    incident.
    """
    tenant = world["identity"].tenant_id
    # The private half of the tenant's one executor key, kept exactly as `gate_world` keeps
    # it: the administrator exit of AL20 signs with it, and `signed_record` reads it from
    # here when a scenario does not pass a key of its own.
    world["executor_key"] = register_keypair(owner, world)
    seed_synthetic(
        admin_engine,
        tenant=tenant,
        account=world["account"],
        source=world["inventory"],
        resource=world["target"],
        observed=world["clock"].now() - timedelta(seconds=60),
    )
    with admin_engine.begin() as conn:
        _alias(
            conn,
            {
                "t": tenant,
                "alias": uuid4(),
                "a": world["account"],
                "p": WORLD_DEVICE,
                "r": world["target"],
                "start": world["clock"].now() - timedelta(days=1),
                "expires": world["clock"].now() + timedelta(days=1),
            },
        )
    governed_bundle(db, world)
    return world


# A second operation of the same contract, the same account and the same action, which
# this deployment dispatches itself. It is what an ordinary agent request names while the
# governed one carries `external_executor`, so one active bundle serves both paths and one
# limit rule counts what each of them reserves. Provisioned by `direct_operation` and
# declared by `governed_bundle(direct=True)`.
DIRECT_OPERATION = SYNTHETIC_OPERATION + ".direct"


def direct_operation(engine, world):
    """Provision the ordinary mapping beside the governed one, as an operator would.

    Everything but the reference is the synthetic mapping's, so a request naming it
    resolves the same contract, the same facts and the same action; what differs is that
    the bundle does not declare it externally executed, so admission reserves and hands
    back a dispatch ticket rather than a grant.
    """
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, context_contract_version) "
                "SELECT tenant_id, :direct, account_id, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, context_contract_version "
                "FROM execbound.operation_mappings WHERE tenant_id=:t AND operation_ref=:op"
            ),
            {
                "t": world["identity"].tenant_id,
                "op": SYNTHETIC_OPERATION,
                "direct": DIRECT_OPERATION,
            },
        )


def governed_bundle(db, world, *, limits=(), direct=False, **changes):
    """Activate a synthetic-contract bundle whose governed mapping is externally executed.

    ``direct`` adds the ordinary mapping of `DIRECT_OPERATION` beside it, for the rows that
    need one tenant charging one ceiling from both paths; its own mapping row has to be
    provisioned by `direct_operation` first, because bundle validation reads the tenant's
    registry rather than the bundle's claim about it.
    """
    bundle = synthetic_bundle(world["identity"].tenant_id, world["account"], **changes)
    mapping = bundle.mappings[0].model_copy(update={"external_executor": True})
    mappings = (mapping,)
    if direct:
        mappings += (
            mapping.model_copy(
                update={"operation_ref": DIRECT_OPERATION, "external_executor": False}
            ),
        )
    bundle = bundle.model_copy(update={"mappings": mappings, "limits": tuple(limits)})
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=CATALOG)
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=CATALOG)
    world["bundle"] = bundle
    return bundle


def approving_runtime(db, world):
    """A deployment that names an approvals page, which is what a pending answer carries."""
    return Runtime(
        db,
        [],
        clock=world["clock"],
        catalog=CATALOG,
        approval_url=APPROVALS_PAGE,
        keys=TokenKeys("state-v1", {"state-v1": bytes.fromhex("21" * 32)}),
    )


def hook_block(**changes):
    """The deployment's `arcade` block, varied, validated the way the private file reads it."""
    block = deepcopy(ARCADE_BLOCK)
    block.update(deepcopy(changes))
    return ArcadeBlock.model_validate_json(json.dumps(block))


def pre_hook(**changes):
    """One `PreHookRequest` as `docs/ARCADE.md` describes it: which tool, which inputs, for whom.

    `context.authorization` is present by default and carries an access token, because the
    edge that drops it is only provable against a hook that sends one.
    """
    body = {
        "execution_id": "arcade-execution-1",
        "tool": {**GOVERNED_TOOL, "metadata": {"behavior": {"destructive": True}}},
        "inputs": {"device_id": WORLD_DEVICE},
        "context": {
            "user_id": "analyst@example.test",
            "secrets": ["CROWDSTRIKE_TOKEN"],
            "authorization": [
                {"provider_id": "crowdstrike", "oauth2": {"at": "header.payload.signature"}}
            ],
        },
    }
    body.update(deepcopy(changes))
    return body


def post_hook(**changes):
    """One `PostHookRequest` as `docs/ARCADE.md` describes it: what the platform says it did.

    `success` is absent by default, because it is optional in the published schema and a
    default here would hide the row of the post hook table in `docs/ARCADE.md` that turns on
    its absence. Every caller that means to state a result passes one. `output` and the access
    token are present for the same reason the pre hook's token is: the edge that drops each is
    only provable against a hook that sends it.
    """
    body = {
        "execution_id": "arcade-execution-1",
        "tool": {**GOVERNED_TOOL, "metadata": {"behavior": {"destructive": True}}},
        "context": {
            "user_id": "analyst@example.test",
            "authorization": [
                {"provider_id": "crowdstrike", "oauth2": {"at": "header.payload.signature"}}
            ],
        },
        "output": {"value": {"status": "contained", "note": "vendor-output-marker"}},
    }
    body.update(deepcopy(changes))
    return body


@contextmanager
def arcade_client(db, world, seeded, *, block=None, runtime=None):
    """The application a Gate deployment serves, with the hook routes configured.

    The runtime holds no connector, which is the Gate placement: indexing the connector
    table for one of these executions raises rather than dispatches. Its catalog is the one
    that carries the governed operation's contract.
    """
    if runtime is None:
        runtime = Runtime(db, [], clock=world["clock"], catalog=CATALOG)
    app = create_app(db, runtime=runtime, arcade=block if block is not None else hook_block())
    with TestClient(app) as client:
        yield SimpleNamespace(
            client=client,
            runtime=runtime,
            app=app,
            token=seeded["tokens"][0],
            tenant=world["identity"].tenant_id,
        )


@contextmanager
def arcade_boundary(db, world, seeded, *, block=None, runtime=None):
    """The same deployment behind `create_arcade`, which is what a hook process serves.

    The driver has the same shape `arcade_client` yields, so `pre` and `post` drive either
    one and the difference between them is the boundary alone.
    """
    if runtime is None:
        runtime = Runtime(db, [], clock=world["clock"], catalog=CATALOG)
    app = create_arcade(db, runtime=runtime, arcade=block if block is not None else hook_block())
    with TestClient(app) as client:
        yield SimpleNamespace(
            client=client,
            runtime=runtime,
            app=app,
            token=seeded["tokens"][0],
            tenant=world["identity"].tenant_id,
        )


def pre(driver, *, token=None, headers=None, body=None, **changes):
    """One pre hook delivered over real HTTP, with the agent credential this world holds."""
    sent = {
        "Authorization": "Bearer " + (token if token is not None else driver.token),
        "Content-Type": "application/json",
    }
    sent.update(headers or {})
    raw = body if body is not None else json.dumps(pre_hook(**changes))
    return driver.client.post("/pre", content=raw, headers=sent)


def post(driver, *, token=None, headers=None, body=None, **changes):
    """One post hook delivered over the same surface, on the same agent credential."""
    sent = {
        "Authorization": "Bearer " + (token if token is not None else driver.token),
        "Content-Type": "application/json",
    }
    sent.update(headers or {})
    raw = body if body is not None else json.dumps(post_hook(**changes))
    return driver.client.post("/post", content=raw, headers=sent)


def correlation_rows(engine, tenant, principal=None):
    """This tenant's correlation rows, keyed by the Arcade execution id.

    The report secret is read out in full rather than as a flag, because what the pre hook's
    rule turns on is which Arcade execution holds the secret that settles a grant, and
    `store.ticket_digest(secret) == executions.owner_hash` is what makes that a checkable
    claim rather than a description of one.

    The Arcade execution id alone does not key a row: the table is keyed on the principal
    too, because Arcade's id is the platform's own string and two projects of one tenant can
    choose the same one. `principal` narrows the read to one project. Left out, the read
    covers the tenant and asserts that the ids it returns are unique across it, so a caller
    that meant to read one project's row is told rather than handed whichever row the dict
    comprehension kept.
    """
    with engine.begin() as conn:
        scoped(conn, tenant)
        rows = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT arcade_execution_id, principal_id, idempotency_key, toolkit, "
                    "tool_name, tool_version, reported_metadata, reported_user_id, decision, "
                    "execution_id, operation_id, report_secret, created_at, settled_at, "
                    "reported_success, reported_code, reported_error, "
                    "denial_contradiction_at, inputs_contradiction_at "
                    "FROM execbound.arcade_hooks WHERE tenant_id=:t "
                    "AND (CAST(:p AS uuid) IS NULL OR principal_id = :p)"
                ),
                {"t": tenant, "p": principal},
            ).mappings()
        ]
        keyed = {row["arcade_execution_id"]: row for row in rows}
        assert len(keyed) == len(rows), "two projects hold this Arcade execution id"
        return keyed


def audit_head(engine, tenant):
    """The tenant's chain head: its sequence and its hash, which an append moves."""
    with engine.begin() as conn:
        scoped(conn, tenant)
        row = (
            conn.execute(
                text("SELECT sequence, event_hash FROM execbound.audit_heads WHERE tenant_id=:t"),
                {"t": tenant},
            )
            .mappings()
            .one_or_none()
        )
    return (row["sequence"], row["event_hash"]) if row is not None else None
