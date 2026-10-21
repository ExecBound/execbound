# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL proofs for immutable content and atomic administrative lifecycle."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import cedarpy as cedar_engine
import pytest
import secret_shapes
from soc_fixtures import SECOND_PROVIDER, TEST_CATALOG
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError

from execbound.audit import canonical_json, read_events, verify_chain
from execbound.db import UnsafeDatabaseRole, check_runtime
from execbound.identity import authenticate, new_token
from execbound.policy import store
from execbound.policy.models import BundleContent, LimitRule, LimitSelector, MappingRef
from execbound_harness.demo import CEDAR_SCHEMA

SCHEMA = CEDAR_SCHEMA
PERMIT = "permit(principal, action, resource);"
# Owner-provisioned rows the scoped-rule tests create beside the fixture's account.
INACTIVE_ACCOUNT = uuid4()
FOREIGN_GROUP = uuid4()
# An executor's registered Ed25519 public key is public material, so a fixed one is safe.
EXECUTOR_KEY = "a1" * 32
# A provider only the test catalog binds, so a mapping onto it resolves while the released
# catalog has no binding for it: exactly the operation a checkpoint may not describe.
UNRELEASED_ACCOUNT = uuid4()
UNRELEASED_REF = "endpoint.isolate.unreleased"


class FixedClock:
    def __init__(self, now):
        self.value = now

    def now(self):
        return self.value


@pytest.fixture
def policy_setup(db, seeded, admin_engine):
    admins = []
    account = uuid4()
    with admin_engine.begin() as conn:
        for tenant in seeded["tenants"]:
            principal, credential = uuid4(), uuid4()
            token, digest = new_token(tenant, credential)
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                    "VALUES (:t, :p, 'ADMIN')"
                ),
                {"t": tenant, "p": principal},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.credentials "
                    "(tenant_id, principal_id, credential_id, token_hash, expires_at) "
                    "VALUES (:t, :p, :c, :h, :expires)"
                ),
                {
                    "t": tenant,
                    "p": principal,
                    "c": credential,
                    "h": digest,
                    "expires": datetime.now(UTC) + timedelta(hours=1),
                },
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                    "space_id) "
                    "VALUES (:t, :a, 'mock_crowdstrike', "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                {"t": tenant, "a": account},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.operation_mappings "
                    "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                    "provider_operation, mapping_version, schema_version, "
                    "context_contract_version) VALUES (:t, 'endpoint.isolate', :a, "
                    "'mock_crowdstrike', 'endpoint', 'endpoint.isolate', 'contain', 'map-v1', "
                    "'action.v1', 'endpoint-isolation.v1')"
                ),
                {"t": tenant, "a": account},
            )
            admins.append(token)
    return {
        "admins": [authenticate(db, token) for token in admins],
        "agent": authenticate(db, seeded["tokens"][0]),
        "account": account,
        "clock": FixedClock(datetime.now(UTC)),
    }


def content(setup, *, index=0, **changes):
    fields = {
        "tenant_id": setup["admins"][index].tenant_id,
        "bundle_id": uuid4(),
        "cedar_schema": SCHEMA,
        "authorization_policies": PERMIT,
        "approval_policies": "",
        "mappings": (
            MappingRef(
                operation_ref="endpoint.isolate",
                account_id=setup["account"],
                mapping_version="map-v1",
                schema_version="action.v1",
                context_contract_version="endpoint-isolation.v1",
            ),
        ),
        "limits": (),
    }
    fields.update(changes)
    return BundleContent(**fields)


def draft(db, setup, **changes):
    bundle = content(setup, **changes)
    store.create_bundle(db, setup["admins"][0], bundle, setup["clock"])
    return bundle


def validated(db, setup, **changes):
    bundle = draft(db, setup, **changes)
    store.validate_bundle(db, setup["admins"][0], bundle.bundle_id, setup["clock"])
    return bundle


def limit(**changes):
    fields = {
        "rule_id": "scoped",
        "action": "endpoint.isolate",
        "scope": "principal",
        "window_seconds": 3600,
        "max_targets": 3,
        "budget": "total",
        "on_exceed": "REQUIRE_APPROVAL",
    }
    fields.update(changes)
    return LimitRule(**fields)


def create_group(admin_engine, setup, *, index=0, group_id=None, name="triage"):
    # Direct owner SQL until the group administration API lands.
    group = group_id or uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principal_groups (tenant_id, group_id, name, created_at) "
                "VALUES (:t, :g, :name, :now)"
            ),
            {
                "t": setup["admins"][index].tenant_id,
                "g": group,
                "name": name,
                "now": setup["clock"].now(),
            },
        )
    return group


def register_executor_key(admin_engine, setup, *, index=0, key_id="executor-1", revoked=False):
    # Direct owner SQL rather than the administration API: this seeds a key revoked at
    # creation and must append no audit event to a tenant whose events other assertions
    # read. The runtime role holds SELECT alone, so the runtime engine cannot seed it.
    # An ordinary retirement, because what this exercises is a bundle that needs a live
    # key and not what a revocation means; migration 0026's CHECK constraint refuses a
    # revocation that names no reason at all, which is what this row used to be.
    now = setup["clock"].now()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.executor_keys "
                "(tenant_id, key_id, algorithm, public_key, created_at, revoked_at, "
                "revocation_reason) "
                "VALUES (:t, :k, 'ED25519', :key, :now, :revoked, :reason)"
            ),
            {
                "t": setup["admins"][index].tenant_id,
                "k": key_id,
                "key": EXECUTOR_KEY,
                "now": now,
                "revoked": now if revoked else None,
                "reason": "RETIRED" if revoked else None,
            },
        )


def register_unreleased_mapping(admin_engine, setup, *, index=0):
    """An active mapping onto a provider the test catalog binds and the released one does not."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) "
                "VALUES (:t, :a, :provider, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {
                "t": setup["admins"][index].tenant_id,
                "a": UNRELEASED_ACCOUNT,
                "provider": SECOND_PROVIDER,
            },
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, context_contract_version) "
                "VALUES (:t, :ref, :a, :provider, 'endpoint', 'endpoint.isolate', 'isolate', "
                "'map-v1', 'action.v1', 'endpoint-isolation.v1')"
            ),
            {
                "t": setup["admins"][index].tenant_id,
                "ref": UNRELEASED_REF,
                "a": UNRELEASED_ACCOUNT,
                "provider": SECOND_PROVIDER,
            },
        )


def gate_mapping(setup, **changes):
    fields = {
        "operation_ref": "endpoint.isolate",
        "account_id": setup["account"],
        "mapping_version": "map-v1",
        "schema_version": "action.v1",
        "context_contract_version": "endpoint-isolation.v1",
        "external_executor": True,
    }
    fields.update(changes)
    return MappingRef(**fields)


def states(db, setup):
    with db.transaction(setup["admins"][0].tenant_id) as conn:
        return dict(
            conn.execute(
                text("SELECT bundle_id, state FROM execbound.policy_bundle_lifecycle")
            ).all()
        )


def test_bundle_lifecycle_is_immutable_and_audited(db, policy_setup):
    setup = policy_setup
    admin = setup["admins"][0]
    bundle = content(setup)
    created = store.create_bundle(db, admin, bundle, setup["clock"])
    assert created.content == bundle and created.state == "DRAFT"
    result = store.validate_bundle(db, admin, bundle.bundle_id, setup["clock"])
    assert result.content == bundle and result.state == "VALIDATED"
    result = store.activate_bundle(db, admin, bundle.bundle_id, setup["clock"])
    assert result.content == bundle and result.state == "ACTIVE"
    assert store.load_active_bundle(db, setup["agent"], setup["clock"]) == bundle
    with db.transaction(admin.tenant_id) as conn:
        events = read_events(conn, admin.tenant_id)
        assert [row["kind"] for row in events] == [
            "policy.bundle_created",
            "policy.bundle_validated",
            "policy.bundle_activated",
        ]
        assert all(row["payload"]["content_hash"] == bundle.content_hash for row in events)
        assert verify_chain(events, admin.tenant_id, len(events), events[-1]["event_hash"])


def test_activating_replacement_deselects_prior_bundle(db, policy_setup):
    """`ACTIVE` means "selected by at least one space" since migration 0041, so the bundle
    the space stops selecting returns to VALIDATED rather than being retired: another
    space may select it later, and a baseline two customers share must survive one of
    them moving on."""
    first, second = validated(db, policy_setup), validated(db, policy_setup)
    admin = policy_setup["admins"][0]
    store.activate_bundle(db, admin, first.bundle_id)
    store.activate_bundle(db, admin, second.bundle_id)
    assert states(db, policy_setup) == {first.bundle_id: "VALIDATED", second.bundle_id: "ACTIVE"}
    assert store.load_active_bundle(db, admin) == second
    with db.transaction(admin.tenant_id) as conn:
        events = read_events(conn, admin.tenant_id)
        assert [row["kind"] for row in events[-2:]] == [
            "policy.bundle_deselected",
            "policy.bundle_activated",
        ]
        assert verify_chain(events, admin.tenant_id, len(events), events[-1]["event_hash"])


@pytest.mark.parametrize("method", ["create_bundle", "validate_bundle", "activate_bundle"])
@pytest.mark.parametrize("kind", ["AGENT", "HUMAN_APPROVER", "FORGED_ADMIN"])
def test_mutations_require_persisted_admin(db, policy_setup, admin_engine, method, kind):
    bundle = validated(db, policy_setup)
    identity = policy_setup["agent"]
    if kind == "HUMAN_APPROVER":
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.principals SET kind = 'HUMAN_APPROVER', space_id = NULL "
                    "WHERE principal_id = :p"
                ),
                {"p": identity.principal_id},
            )
        identity = replace(identity, kind="HUMAN_APPROVER")
    elif kind == "FORGED_ADMIN":
        identity = replace(identity, kind="ADMIN")
    argument = content(policy_setup) if method == "create_bundle" else bundle.bundle_id
    with pytest.raises(store.PolicyStoreError, match="Policy store unavailable"):
        getattr(store, method)(db, identity, argument)
    assert states(db, policy_setup) == {bundle.bundle_id: "VALIDATED"}


@pytest.mark.parametrize(
    "change",
    [
        "UPDATE execbound.credentials SET revoked_at = now()",
        "UPDATE execbound.credentials SET expires_at = now() - interval '1 second'",
        "UPDATE execbound.credentials SET expires_at = expires_at + interval '1 hour'",
        "UPDATE execbound.principals SET active = false",
        "UPDATE execbound.principals SET kind = 'AGENT', space_id = "
        "(SELECT space_id FROM execbound.spaces s WHERE s.tenant_id = principals.tenant_id)",
        "UPDATE execbound.tenants SET active = false",
    ],
)
def test_stale_admin_cannot_activate(db, policy_setup, admin_engine, change):
    bundle = validated(db, policy_setup)
    with admin_engine.begin() as conn:
        conn.execute(text(change))
    with pytest.raises(store.PolicyStoreError):
        store.activate_bundle(db, policy_setup["admins"][0], bundle.bundle_id)
    assert states(db, policy_setup)[bundle.bundle_id] == "VALIDATED"


def test_expiry_during_activation_rolls_back(db, policy_setup, monkeypatch):
    bundle = validated(db, policy_setup)
    admin = policy_setup["admins"][0]
    original = store.append_event

    def expire(*args, **kwargs):
        result = original(*args, **kwargs)
        policy_setup["clock"].value = admin.expires_at
        return result

    monkeypatch.setattr(store, "append_event", expire)
    with pytest.raises(store.PolicyStoreError):
        store.activate_bundle(db, admin, bundle.bundle_id, policy_setup["clock"])
    assert states(db, policy_setup)[bundle.bundle_id] == "VALIDATED"


@pytest.mark.parametrize(
    "mutation",
    [
        {"cedar_schema": "invalid schema"},
        {"authorization_policies": "invalid policy"},
        {"approval_policies": "forbid(principal, action, resource);"},
    ],
)
def test_invalid_cedar_cannot_be_validated(db, policy_setup, mutation):
    """Cedar text that does not validate is a defect in the bundle's own component, named by
    its field, not an unavailable store."""
    bundle = draft(db, policy_setup, **mutation)
    with pytest.raises(store.PolicyStoreError) as failure:
        store.validate_bundle(db, policy_setup["admins"][0], bundle.bundle_id)
    assert failure.value.code == "INVALID_COMPONENT"
    assert failure.value.location == next(iter(mutation))
    assert states(db, policy_setup)[bundle.bundle_id] == "DRAFT"


def test_a_cedar_engine_failure_is_still_an_unavailable_store(db, policy_setup, monkeypatch):
    """Only Cedar's refusal of a component is that component's defect: an engine that fails
    outright names no component, and the step reads `POLICY_UNAVAILABLE` as before."""
    bundle = draft(db, policy_setup)

    def unavailable(*args, **kwargs):
        raise RuntimeError("synthetic engine failure")

    monkeypatch.setattr(cedar_engine._internal, "validate_policies", unavailable)
    with pytest.raises(store.PolicyStoreError) as failure:
        store.validate_bundle(db, policy_setup["admins"][0], bundle.bundle_id)
    assert failure.value.code == "POLICY_UNAVAILABLE" and failure.value.location is None
    assert states(db, policy_setup)[bundle.bundle_id] == "DRAFT"


@pytest.mark.parametrize(
    "change",
    [
        "DELETE FROM execbound.operation_mappings",
        "UPDATE execbound.operation_mappings SET active = false",
        "UPDATE execbound.operation_mappings SET mapping_version = 'map-v2'",
        "UPDATE execbound.operation_mappings SET schema_version = 'action.v2'",
        "UPDATE execbound.operation_mappings SET context_contract_version = 'unknown'",
        "UPDATE execbound.operation_mappings SET action = 'generic.http'",
        "UPDATE execbound.operation_mappings SET provider_operation = 'arbitrary'",
        "UPDATE execbound.connector_accounts SET active = false",
    ],
)
def test_activation_rechecks_current_components(db, policy_setup, admin_engine, change):
    bundle = validated(db, policy_setup)
    with admin_engine.begin() as conn:
        conn.execute(text(change))
    with pytest.raises(store.PolicyStoreError):
        store.activate_bundle(db, policy_setup["admins"][0], bundle.bundle_id)
    assert states(db, policy_setup)[bundle.bundle_id] == "VALIDATED"


def test_missing_mapping_prevents_validation(db, policy_setup):
    bundle = draft(
        db,
        policy_setup,
        mappings=(
            MappingRef(
                operation_ref="missing",
                account_id=policy_setup["account"],
                mapping_version="map-v1",
                schema_version="action.v1",
                context_contract_version="endpoint-isolation.v1",
            ),
        ),
    )
    with pytest.raises(store.PolicyStoreError) as failure:
        store.validate_bundle(db, policy_setup["admins"][0], bundle.bundle_id)
    # A bundle component defect, not an unavailable store.
    assert failure.value.code == "INVALID_COMPONENT"


def map_ref(admin_engine, setup, ref, action, *, provider="mock_crowdstrike", account=None):
    """An operation mapping whose ref is not its action (`mapping-create --ref`)."""
    spec = TEST_CATALOG.actions.bound(provider, action)
    tenant = setup["admins"][0].tenant_id
    account = setup["account"] if account is None else account
    with admin_engine.begin() as conn:
        if account != setup["account"]:
            conn.execute(
                text(
                    "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                    "space_id) VALUES (:t, :a, :p, "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                {"t": tenant, "a": account, "p": provider},
            )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, "
                "context_contract_version) VALUES (:t, :r, :a, :p, :rt, :ac, :op, 'map-v1', "
                ":sv, :cv)"
            ),
            {
                "t": tenant,
                "r": ref,
                "a": account,
                "p": provider,
                "rt": spec.resource_type,
                "ac": spec.action,
                "op": spec.provider_operation,
                "sv": spec.schema_version,
                "cv": spec.context_contract_version,
            },
        )
    return MappingRef(
        operation_ref=ref,
        account_id=account,
        mapping_version="map-v1",
        schema_version=spec.schema_version,
        context_contract_version=spec.context_contract_version,
    )


def test_a_mapping_naming_an_action_its_row_does_not_serve_is_refused_at_its_action(
    db, policy_setup, admin_engine
):
    """A bundle that names a mapping's action must name the one its row serves."""
    reference = map_ref(admin_engine, policy_setup, "isolate.corroborated", "endpoint.isolate")
    admin, clock = policy_setup["admins"][0], policy_setup["clock"]
    wrong = draft(
        db,
        policy_setup,
        mappings=(reference.model_copy(update={"action": "endpoint.lift_isolation"}),),
    )
    with pytest.raises(store.PolicyStoreError) as failure:
        store.validate_bundle(db, admin, wrong.bundle_id, clock)
    assert (failure.value.code, failure.value.location) == (
        "INVALID_COMPONENT",
        "mappings.0.action",
    )
    right = validated(
        db, policy_setup, mappings=(reference.model_copy(update={"action": "endpoint.isolate"}),)
    )
    store.activate_bundle(db, admin, right.bundle_id, clock)
    # A hand-written bundle that does not name the action is read exactly as before.
    store.validate_bundle(
        db, admin, draft(db, policy_setup, mappings=(reference,)).bundle_id, clock
    )


def test_a_rules_bundle_is_refused_where_its_ref_names_an_action_its_row_does_not_serve(
    db, policy_setup, admin_engine
):
    """Rules compile about a mapping's action, so that action must be the one its row serves.

    `identity.disable` is a catalog action served by the same contract as the row's action,
    so the rules compile about it, and only the row can say the ref means something else.
    """
    from execbound.policy.rulesets import Rule, Ruleset, ruleset_bundle

    reference = map_ref(
        admin_engine,
        policy_setup,
        "identity.disable",
        "identity.revoke_sessions",
        provider="mock_entra",
        account=uuid4(),
    )
    admin, clock = policy_setup["admins"][0], policy_setup["clock"]

    def rules_over(mapping, action):
        content = ruleset_bundle(
            Ruleset(rules=(Rule(id="allow", action=action, effect="ALLOW"),)),
            tenant_id=admin.tenant_id,
            bundle_id=uuid4(),
            mappings=(mapping,),
        )
        store.create_bundle(db, admin, content, clock)
        return content

    wrong = rules_over(reference, "identity.disable")
    with pytest.raises(store.PolicyStoreError) as failure:
        store.validate_bundle(db, admin, wrong.bundle_id, clock)
    assert (failure.value.code, failure.value.location) == (
        "INVALID_COMPONENT",
        "mappings.0.action",
    )
    named = reference.model_copy(update={"action": "identity.revoke_sessions"})
    right = rules_over(named, "identity.revoke_sessions")
    store.validate_bundle(db, admin, right.bundle_id, clock)
    store.activate_bundle(db, admin, right.bundle_id, clock)


@pytest.mark.parametrize(
    ("changes", "location"),
    [
        pytest.param(
            {"actions": ("endpoint.isolate", "endpoint.unknown")},
            "limits.0.action",
            id="unknown-action-in-list",
        ),
        pytest.param(
            {"scope": "group", "group_id": uuid4()}, "limits.0.group_id", id="unknown-group"
        ),
        pytest.param(
            {"scope": "group", "group_id": FOREIGN_GROUP}, "limits.0.group_id", id="foreign-group"
        ),
        pytest.param(
            {"scope": "account", "account_id": uuid4()}, "limits.0.account_id", id="unknown-account"
        ),
        pytest.param(
            {"scope": "account", "account_id": INACTIVE_ACCOUNT},
            "limits.0.account_id",
            id="inactive-account",
        ),
        pytest.param(
            {"scope": "selector", "selector": LimitSelector(fact="hostname", equals="host-1")},
            "limits.0.selector",
            id="unknown-fact",
        ),
        pytest.param(
            {"scope": "selector", "selector": LimitSelector(fact="environment", equals="prod")},
            "limits.0.selector",
            id="value-outside-domain",
        ),
        pytest.param(
            {
                "action": "endpoint.lift_isolation",
                "scope": "selector",
                "selector": LimitSelector(fact="environment", equals="production"),
            },
            "limits.0.selector",
            id="unserved-actions",
        ),
    ],
)
def test_scoped_rules_fail_validation_with_locations(
    db, policy_setup, admin_engine, changes, location
):
    admin = policy_setup["admins"][0]
    if changes.get("account_id") == INACTIVE_ACCOUNT:
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.connector_accounts"
                    "(tenant_id, account_id, provider, active, "
                    "space_id) VALUES (:t, :a, 'mock_entra', false, "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                {"t": admin.tenant_id, "a": INACTIVE_ACCOUNT},
            )
    if changes.get("group_id") == FOREIGN_GROUP:
        create_group(admin_engine, policy_setup, index=1, group_id=FOREIGN_GROUP)
    bundle = draft(db, policy_setup, limits=(limit(**changes),))
    with pytest.raises(store.PolicyStoreError) as failure:
        store.validate_bundle(db, admin, bundle.bundle_id, policy_setup["clock"])
    assert failure.value.code == "INVALID_COMPONENT"
    assert failure.value.location == location
    assert states(db, policy_setup)[bundle.bundle_id] == "DRAFT"


def test_scoped_rules_validate_and_activate(db, policy_setup, admin_engine):
    setup = policy_setup
    admin, agent = setup["admins"][0], setup["agent"]
    group = create_group(admin_engine, setup)
    rules = (
        limit(rule_id="account-disruption", scope="account", account_id=setup["account"]),
        limit(rule_id="group-triage", scope="group", group_id=group),
        limit(rule_id="pair-isolation", actions=("endpoint.isolate", "endpoint.lift_isolation")),
        limit(
            rule_id="production-isolation",
            scope="selector",
            selector=LimitSelector(fact="environment", equals="production"),
        ),
        limit(rule_id="tenant-total", scope="tenant"),
    )
    bundle = validated(db, setup, limits=rules)
    assert bundle.limits == rules
    result = store.activate_bundle(db, admin, bundle.bundle_id, setup["clock"])
    assert result.content == bundle and result.state == "ACTIVE"
    assert store.load_active_bundle(db, agent, setup["clock"]) == bundle
    # A revalidated load of the active bundle checks owner data again, so a deleted group fails
    # closed here. Admission reads the active bundle without re-running these checks, so it does
    # not refuse a group deleted after activation (docs/POLICY.md).
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.principal_groups WHERE group_id = :g"), {"g": group}
        )
    with pytest.raises(store.PolicyStoreError) as failure:
        store.load_active_bundle(db, agent, setup["clock"])
    assert failure.value.code == "INVALID_COMPONENT"
    assert failure.value.location == "limits.1.group_id"


@pytest.mark.parametrize("keys", ["none", "revoked", "foreign"])
def test_checkpoint_mapping_requires_an_unrevoked_executor_key(
    db, policy_setup, admin_engine, keys
):
    if keys == "revoked":
        register_executor_key(admin_engine, policy_setup, revoked=True)
    if keys == "foreign":
        register_executor_key(admin_engine, policy_setup, index=1)
    bundle = draft(db, policy_setup, mappings=(gate_mapping(policy_setup),))
    with pytest.raises(store.PolicyStoreError) as failure:
        store.validate_bundle(
            db, policy_setup["admins"][0], bundle.bundle_id, policy_setup["clock"]
        )
    assert failure.value.code == "INVALID_COMPONENT"
    assert failure.value.location == "mappings.0.external_executor"
    assert states(db, policy_setup)[bundle.bundle_id] == "DRAFT"


def test_checkpoint_mapping_requires_a_released_provider_binding(db, policy_setup, admin_engine):
    setup = policy_setup
    admin = setup["admins"][0]
    register_executor_key(admin_engine, setup)
    register_unreleased_mapping(admin_engine, setup)
    reference = {"operation_ref": UNRELEASED_REF, "account_id": UNRELEASED_ACCOUNT}
    flagged = draft(db, setup, mappings=(gate_mapping(setup, **reference),))
    with pytest.raises(store.PolicyStoreError) as failure:
        store.validate_bundle(db, admin, flagged.bundle_id, setup["clock"], catalog=TEST_CATALOG)
    assert failure.value.code == "INVALID_COMPONENT"
    assert failure.value.location == "mappings.0.external_executor"
    assert states(db, setup)[flagged.bundle_id] == "DRAFT"
    # The same mapping without the flag is a connector operation the caller's catalog binds,
    # so the refusal above is the checkpoint check and not an unresolvable mapping.
    plain = draft(db, setup, mappings=(gate_mapping(setup, **reference, external_executor=False),))
    result = store.validate_bundle(db, admin, plain.bundle_id, setup["clock"], catalog=TEST_CATALOG)
    assert result.state == "VALIDATED"


def test_checkpoint_mapping_validates_and_activates(db, policy_setup, admin_engine):
    setup = policy_setup
    admin, agent = setup["admins"][0], setup["agent"]
    register_executor_key(admin_engine, setup)
    register_executor_key(admin_engine, setup, key_id="executor-0", revoked=True)
    bundle = validated(db, setup, mappings=(gate_mapping(setup),))
    assert bundle.mappings[0].external_executor is True
    result = store.activate_bundle(db, admin, bundle.bundle_id, setup["clock"])
    assert result.content == bundle and result.state == "ACTIVE"
    assert store.load_active_bundle(db, agent, setup["clock"]) == bundle
    # An active bundle depends on owner data on every admission: revoking the last key
    # fails the checkpoint closed rather than granting an act nobody can attest.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executor_keys SET revoked_at = :now, "
                "revocation_reason = 'RETIRED' WHERE tenant_id = :t AND revoked_at IS NULL"
            ),
            {"now": setup["clock"].now(), "t": admin.tenant_id},
        )
    with pytest.raises(store.PolicyStoreError) as failure:
        store.load_active_bundle(db, agent, setup["clock"])
    assert failure.value.code == "INVALID_COMPONENT"
    assert failure.value.location == "mappings.0.external_executor"


def test_missing_active_bundle_fails_closed(db, policy_setup):
    with pytest.raises(store.PolicyStoreError):
        store.load_active_bundle(db, policy_setup["agent"])


def test_invalid_lifecycle_transitions_fail(db, policy_setup):
    admin = policy_setup["admins"][0]
    bundle = draft(db, policy_setup)
    with pytest.raises(store.PolicyStoreError):
        store.activate_bundle(db, admin, bundle.bundle_id)
    store.validate_bundle(db, admin, bundle.bundle_id)
    with pytest.raises(store.PolicyStoreError):
        store.validate_bundle(db, admin, bundle.bundle_id)
    store.activate_bundle(db, admin, bundle.bundle_id)
    with pytest.raises(store.PolicyStoreError):
        # Already this space's selection: re-selecting it is no transition.
        store.activate_bundle(db, admin, bundle.bundle_id)
    replacement = validated(db, policy_setup)
    store.activate_bundle(db, admin, replacement.bundle_id)
    # The deselected bundle is VALIDATED again, so the space may select it back.
    store.activate_bundle(db, admin, bundle.bundle_id)
    with pytest.raises(store.PolicyStoreError):
        store.activate_bundle(db, admin, bundle.bundle_id)


def test_duplicate_bundle_id_cannot_replace_content(db, policy_setup):
    bundle = draft(db, policy_setup)
    altered = content(policy_setup, bundle_id=bundle.bundle_id, authorization_policies=PERMIT * 2)
    with pytest.raises(store.PolicyStoreError):
        store.create_bundle(db, policy_setup["admins"][0], altered)


def test_tenant_isolation_covers_all_policy_state(db, policy_setup):
    bundle = validated(db, policy_setup)
    first, second = policy_setup["admins"]
    store.activate_bundle(db, first, bundle.bundle_id)
    for method in (store.validate_bundle, store.activate_bundle):
        with pytest.raises(store.PolicyStoreError):
            method(db, second, bundle.bundle_id)
    with pytest.raises(store.PolicyStoreError):
        store.create_bundle(db, second, bundle)
    with pytest.raises(store.PolicyStoreError):
        store.load_active_bundle(db, second)
    with db.transaction(second.tenant_id) as conn:
        for table in ("policy_bundle_contents", "policy_bundle_lifecycle", "tenant_policy_control"):
            assert conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 0
    own = content(policy_setup, index=1, bundle_id=bundle.bundle_id)
    store.create_bundle(db, second, own)
    store.validate_bundle(db, second, own.bundle_id)
    store.activate_bundle(db, second, own.bundle_id)
    assert store.load_active_bundle(db, second) == own
    assert store.load_active_bundle(db, first) == bundle


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE execbound.policy_bundle_contents SET content = '{}'::jsonb",
        "DELETE FROM execbound.policy_bundle_contents",
        "TRUNCATE execbound.policy_bundle_contents",
        "UPDATE execbound.policy_bundle_lifecycle SET content_hash = repeat('0', 64)",
        "UPDATE execbound.tenant_policy_control SET tenant_id = gen_random_uuid()",
    ],
)
def test_runtime_cannot_rewrite_bundle_content_or_scope(db, policy_setup, statement):
    draft(db, policy_setup)
    with pytest.raises(DBAPIError), db.transaction(policy_setup["admins"][0].tenant_id) as conn:
        conn.execute(text(statement))


@pytest.mark.parametrize(
    "grant",
    [
        "UPDATE(content) ON execbound.policy_bundle_contents",
        "UPDATE(content_hash) ON execbound.policy_bundle_lifecycle",
        "UPDATE(tenant_id) ON execbound.tenant_policy_control",
    ],
)
def test_accidental_policy_column_grants_fail_closed(db, policy_setup, admin_engine, grant):
    with admin_engine.begin() as conn:
        conn.execute(text(f"GRANT {grant} TO execbound_app"))
    try:
        with db.engine.connect() as conn, pytest.raises(UnsafeDatabaseRole):
            check_runtime(conn)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f"REVOKE {grant} FROM execbound_app"))


@pytest.mark.parametrize("method", ["create_bundle", "validate_bundle", "activate_bundle"])
def test_audit_failure_rolls_back_every_policy_change(db, policy_setup, monkeypatch, method):
    admin = policy_setup["admins"][0]
    first = validated(db, policy_setup)
    store.activate_bundle(db, admin, first.bundle_id)
    candidate = content(policy_setup)
    if method != "create_bundle":
        store.create_bundle(db, admin, candidate)
    if method == "activate_bundle":
        store.validate_bundle(db, admin, candidate.bundle_id)
    before = states(db, policy_setup)
    with db.transaction(admin.tenant_id) as conn:
        audit_before = read_events(conn, admin.tenant_id)
        content_before = conn.execute(
            text("SELECT count(*) FROM execbound.policy_bundle_contents")
        ).scalar_one()
    original = store.append_event

    def fail_after_append(*args, **kwargs):
        original(*args, **kwargs)
        if method != "activate_bundle" or args[3] == "policy.bundle_activated":
            raise RuntimeError("synthetic audit persistence failure")

    monkeypatch.setattr(store, "append_event", fail_after_append)
    argument = candidate if method == "create_bundle" else candidate.bundle_id
    with pytest.raises((store.PolicyStoreError, RuntimeError)):
        getattr(store, method)(db, admin, argument)
    assert states(db, policy_setup) == before
    assert store.load_active_bundle(db, admin) == first
    with db.transaction(admin.tenant_id) as conn:
        assert read_events(conn, admin.tenant_id) == audit_before
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.policy_bundle_contents")).scalar_one()
            == content_before
        )


def remove_unselected_control(admin_engine, tenant):
    """Restore the missing-row precondition after draft writes acquired the RBAC fence."""
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.space_policy_selection WHERE tenant_id=:t"),
                {"t": tenant},
            ).scalar_one()
            == 0
        )
        assert (
            conn.execute(
                text(
                    "DELETE FROM execbound.tenant_policy_control "
                    "WHERE tenant_id=:t RETURNING tenant_id"
                ),
                {"t": tenant},
            ).scalar_one()
            == tenant
        )


def test_first_activation_race_serializes_and_audits_both(db, policy_setup, admin_engine):
    first, second = validated(db, policy_setup), validated(db, policy_setup)
    remove_unselected_control(admin_engine, policy_setup["admins"][0].tenant_id)
    barrier = Barrier(2)
    aligned = set()

    def align_control_creation(conn, cursor, statement, parameters, context, many):
        if "INSERT INTO execbound.tenant_policy_control" in statement and conn not in aligned:
            # Rechecks may reacquire the fence after this connection already holds it.
            # Only race the first creation attempt, before either worker owns the lock.
            aligned.add(conn)
            barrier.wait(timeout=10)

    event.listen(db.engine, "before_cursor_execute", align_control_creation)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(store.activate_bundle, db, policy_setup["admins"][0], b.bundle_id)
                for b in (first, second)
            ]
            results = [future.result(timeout=20) for future in futures]
    finally:
        event.remove(db.engine, "before_cursor_execute", align_control_creation)
    assert len(aligned) == 2
    assert [result.state for result in results] == ["ACTIVE", "ACTIVE"]
    assert sorted(states(db, policy_setup).values()) == ["ACTIVE", "VALIDATED"]
    admin = policy_setup["admins"][0]
    active = store.load_active_bundle(db, admin)
    assert states(db, policy_setup)[active.bundle_id] == "ACTIVE"
    with db.transaction(admin.tenant_id) as conn:
        events = read_events(conn, admin.tenant_id)
        assert verify_chain(events, admin.tenant_id, len(events), events[-1]["event_hash"])
        assert [e["kind"] for e in events].count("policy.bundle_activated") == 2
        assert [e["kind"] for e in events].count("policy.bundle_deselected") == 1


@pytest.mark.parametrize("phase", ["validate", "activate", "load"])
def test_digest_bound_content_reparsed_on_every_read(db, policy_setup, admin_engine, phase):
    admin = policy_setup["admins"][0]
    bundle = draft(db, policy_setup)
    if phase != "validate":
        store.validate_bundle(db, admin, bundle.bundle_id)
    if phase == "load":
        store.activate_bundle(db, admin, bundle.bundle_id)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.policy_bundle_contents "
                "SET content = jsonb_set(content, '{approval_policies}', "
                "to_jsonb('forbid(principal, action, resource);'::text))"
            )
        )
    with pytest.raises(store.PolicyStoreError):
        if phase == "load":
            store.load_active_bundle(db, admin)
        else:
            getattr(store, f"{phase}_bundle")(db, admin, bundle.bundle_id)


def test_first_activation_audit_failure_removes_new_control_row(
    db, policy_setup, monkeypatch, admin_engine
):
    admin = policy_setup["admins"][0]
    bundle = validated(db, policy_setup)
    remove_unselected_control(admin_engine, admin.tenant_id)
    original = store.append_event

    def fail_after_append(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("synthetic audit failure")

    monkeypatch.setattr(store, "append_event", fail_after_append)
    with pytest.raises(RuntimeError):
        store.activate_bundle(db, admin, bundle.bundle_id)
    assert states(db, policy_setup)[bundle.bundle_id] == "VALIDATED"
    with db.transaction(admin.tenant_id) as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.tenant_policy_control")).scalar_one()
            == 0
        )
        assert len(read_events(conn, admin.tenant_id)) == 2


@pytest.mark.parametrize(
    "policies",
    [
        {"authorization_policies": "invalid policy"},
        {"approval_policies": "forbid(principal, action, resource);"},
    ],
)
def test_activation_revalidates_cedar_even_with_validated_state(
    db, policy_setup, admin_engine, policies
):
    bundle = draft(db, policy_setup, **policies)
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.policy_bundle_lifecycle SET state = 'VALIDATED'"))
    with pytest.raises(store.PolicyStoreError) as failure:
        store.activate_bundle(db, policy_setup["admins"][0], bundle.bundle_id)
    assert failure.value.code == "INVALID_COMPONENT"
    assert failure.value.location == next(iter(policies))


def test_database_constraint_prevents_two_selections_for_one_space(db, policy_setup):
    """ "At most one bundle per space" is the selection table's primary key rather than an
    index over a lifecycle state, so two bundles may be `ACTIVE` in a tenant with two spaces
    and one space still selects exactly one."""
    first, second = validated(db, policy_setup), validated(db, policy_setup)
    admin = policy_setup["admins"][0]
    store.activate_bundle(db, admin, first.bundle_id)
    with pytest.raises(DBAPIError), db.transaction(admin.tenant_id) as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.space_policy_selection"
                "(tenant_id, space_id, bundle_id, changed_at, changed_by) "
                "SELECT :t, s.space_id, :b, now(), :a FROM execbound.spaces s "
                "WHERE s.tenant_id = :t"
            ),
            {"t": admin.tenant_id, "b": second.bundle_id, "a": admin.principal_id},
        )


def test_runtime_policy_rls_denies_cross_tenant_write_and_unscoped_read(db, policy_setup):
    first, second = policy_setup["admins"]
    bundle = validated(db, policy_setup)
    store.activate_bundle(db, first, bundle.bundle_id)
    with db.transaction(second.tenant_id) as conn:
        assert (
            conn.execute(
                text(
                    "UPDATE execbound.policy_bundle_lifecycle SET state = 'RETIRED' "
                    "WHERE tenant_id = :t"
                ),
                {"t": first.tenant_id},
            ).rowcount
            == 0
        )
        assert (
            conn.execute(
                text(
                    "UPDATE execbound.space_policy_selection SET bundle_id = :b "
                    "WHERE tenant_id = :t"
                ),
                {"t": first.tenant_id, "b": bundle.bundle_id},
            ).rowcount
            == 0
        )
    with pytest.raises(DBAPIError), db.transaction(second.tenant_id) as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.tenant_policy_control(tenant_id, changed_at) "
                "VALUES (:t, now())"
            ),
            {"t": first.tenant_id},
        )
    with db.engine.connect() as conn:
        for table in ("policy_bundle_contents", "policy_bundle_lifecycle", "tenant_policy_control"):
            assert conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 0


def test_new_policy_tables_keep_rls_initplans_and_exclude_api_roles(db, policy_setup, admin_engine):
    bundle = validated(db, policy_setup)
    admin = policy_setup["admins"][0]
    store.activate_bundle(db, admin, bundle.bundle_id)
    tables = ("policy_bundle_contents", "policy_bundle_lifecycle", "tenant_policy_control")
    with db.transaction(admin.tenant_id) as conn:
        for table in tables:
            plan = conn.execute(
                text(f"EXPLAIN (ANALYZE, FORMAT JSON) SELECT * FROM execbound.{table}")
            ).scalar_one()[0]["Plan"]
            initplans = [
                child
                for child in plan.get("Plans", [])
                if child.get("Parent Relationship") == "InitPlan"
            ]
            assert len(initplans) == 1
            assert initplans[0]["Actual Loops"] == 1
    with admin_engine.connect() as conn:
        grants = conn.execute(
            text("""
            SELECT c.relname, acl.grantee FROM pg_class c
            CROSS JOIN LATERAL aclexplode(c.relacl) acl
            WHERE c.relnamespace = 'execbound'::regnamespace
              AND c.relname IN ('policy_bundle_contents', 'policy_bundle_lifecycle',
                                'tenant_policy_control')
              AND (acl.grantee = 0 OR acl.grantee IN (
                  SELECT oid FROM pg_roles
                  WHERE rolname IN ('anon', 'authenticated', 'service_role')
              ))
        """)
        ).all()
    assert grants == []


@pytest.mark.parametrize("field", ["principal_id", "credential_id", "tenant_id", "expires_at"])
def test_forged_admin_identity_fields_are_rejected(db, policy_setup, field):
    bundle = validated(db, policy_setup)
    admin = policy_setup["admins"][0]
    changed = admin.expires_at + timedelta(hours=1) if field == "expires_at" else uuid4()
    with pytest.raises(store.PolicyStoreError):
        store.activate_bundle(db, replace(admin, **{field: changed}), bundle.bundle_id)


def test_naive_clock_fails_before_persistence(db, policy_setup):
    policy_setup["clock"].value = datetime(2026, 9, 13)
    with pytest.raises(store.PolicyStoreError):
        draft(db, policy_setup)
    assert states(db, policy_setup) == {}


def test_invalid_content_error_does_not_expose_validation_input(db, policy_setup):
    bundle = content(policy_setup).model_copy(update={"cedar_schema": ""})
    with pytest.raises(store.PolicyStoreError) as error:
        store.create_bundle(db, policy_setup["admins"][0], bundle)
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__


@pytest.mark.parametrize("method", ["create_bundle", "validate_bundle", "activate_bundle"])
def test_administrator_revoked_during_mutation_is_rechecked(
    db, policy_setup, admin_engine, monkeypatch, method
):
    admin = policy_setup["admins"][0]
    bundle = content(policy_setup)
    if method != "create_bundle":
        store.create_bundle(db, admin, bundle)
    if method == "activate_bundle":
        store.validate_bundle(db, admin, bundle.bundle_id)
    before = states(db, policy_setup)
    original = store.append_event

    def revoke_after_append(*args, **kwargs):
        result = original(*args, **kwargs)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.credentials SET revoked_at = now() WHERE credential_id = :c"
                ),
                {"c": admin.credential_id},
            )
        return result

    monkeypatch.setattr(store, "append_event", revoke_after_append)
    argument = bundle if method == "create_bundle" else bundle.bundle_id
    with pytest.raises(store.PolicyStoreError):
        getattr(store, method)(db, admin, argument)
    assert states(db, policy_setup) == before


def latest_payload(db, admin, kind):
    with db.transaction(admin.tenant_id) as conn:
        return [
            row["payload"] for row in read_events(conn, admin.tenant_id) if row["kind"] == kind
        ][-1]


def audit_head(db, admin):
    with db.transaction(admin.tenant_id) as conn:
        return len(read_events(conn, admin.tenant_id))


def test_an_activation_records_its_reason_in_the_event(db, policy_setup):
    """The change note is the `reason` key of the activation event, never part of the bundle,
    so its content hash is the one validation computed (#678)."""
    admin = policy_setup["admins"][0]
    bundle = validated(db, policy_setup)
    reason = "Tighten tier 0 after incident 42"
    store.activate_bundle(db, admin, bundle.bundle_id, policy_setup["clock"], reason=reason)
    payload = latest_payload(db, admin, "policy.bundle_activated")
    assert payload["reason"] == reason
    assert payload["content_hash"] == bundle.content_hash


def test_an_activation_without_a_reason_writes_todays_payload(db, policy_setup):
    """An activation with no reason (the CLI without `--reason`, quickstart, the samples)
    writes exactly the bytes it wrote before the key existed."""
    admin = policy_setup["admins"][0]
    bundle = validated(db, policy_setup)
    store.activate_bundle(db, admin, bundle.bundle_id, policy_setup["clock"])
    payload = latest_payload(db, admin, "policy.bundle_activated")
    assert set(payload) == {"bundle_id", "content_hash", "space_id", "actor_credential_id"}
    by_hand = {
        "bundle_id": str(bundle.bundle_id),
        "content_hash": bundle.content_hash,
        "actor_credential_id": str(admin.credential_id),
        "space_id": payload["space_id"],
    }
    assert canonical_json(payload) == canonical_json(by_hand)


def refused_reason(db, setup, reason):
    admin = setup["admins"][0]
    bundle = validated(db, setup)
    head = audit_head(db, admin)
    with pytest.raises(store.PolicyStoreError) as raised:
        store.activate_bundle(db, admin, bundle.bundle_id, setup["clock"], reason=reason)
    assert (raised.value.code, raised.value.location) == ("INVALID_REASON", "reason")
    assert reason not in str(raised.value) and reason not in repr(raised.value)
    assert audit_head(db, admin) == head
    assert states(db, setup)[bundle.bundle_id] == "VALIDATED"


@pytest.mark.parametrize("reason", secret_shapes.FREE_TEXT, ids=secret_shapes.FREE_TEXT_IDS)
def test_an_activation_reason_shaped_like_a_secret_is_refused_unquoted(db, policy_setup, reason):
    """A person's reason is screened where it is written (THREAT_MODEL.md T7.7), and the
    refusal names the field, never the value."""
    refused_reason(db, policy_setup, reason)


@pytest.mark.parametrize("reason", ["   ", "x" * 501], ids=["blank", "long"])
def test_a_blank_or_long_activation_reason_is_refused(db, policy_setup, reason):
    refused_reason(db, policy_setup, reason)
