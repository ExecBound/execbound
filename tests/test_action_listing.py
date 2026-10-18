# SPDX-License-Identifier: AGPL-3.0-only
"""The actions an agent's own space offers, and admission refusing everything else alike (#545).

An agent lists the operations its space offers: each `operation_ref`, the catalog action and
label, the argument names and domains, the target kinds and whether an incident is required,
and never a target, a rule, a limit or a placement. Admission checks a requested operation
against the same set before arguments or targets, so an operation another space offers, one the
tenant maps but this space's bundle does not, or one the bundle names at a reference the
tenant's mapping no longer matches, is refused exactly as an unknown one is: the same answer,
the same statements, no record (THREAT_MODEL.md T1.17).
"""

import asyncio
import json
from dataclasses import replace
from uuid import uuid4

import httpx
import httpx2
import pytest
from context_fixtures import CATALOG as SYNTHETIC_CATALOG
from context_fixtures import SYNTHETIC_OPERATION, SYNTHETIC_VERSION
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from scope_fixtures import audit_payloads
from space_fixtures import default_space, move_agent_to_a_second_space
from sqlalchemy import event, text
from test_context_bundle_validation import seeded_soc_bundle
from test_denial_categories import UNAVAILABLE, refused_by_admission
from test_denial_notice import domain_controller, mcp_call
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_mcp_surface import gateway as gateway
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import seed_soc_mappings
from test_runtime import api as api
from test_runtime import runtime as runtime
from test_structured_logging import captured as captured
from test_structured_logging import events

from execbound.contracts import PRODUCTION_CATALOG, Catalog
from execbound.domains import IntegerDomain, StringDomain
from execbound.execution import activate_stop, admit, store
from execbound.execution.models import ExecutionError
from execbound.execution.modes import set_enforcement_mode
from execbound.execution.offered import (
    ActionListing,
    OfferedOperation,
    action_listing,
    bundle_operations,
    listing,
)
from execbound.operations import ActionCatalog, ArgumentSpec
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.resolution.registry import ResolutionError
from execbound.spaces import agent_space, archive_space
from execbound.surfaces.agent_api_guide import ERROR_MEANINGS
from execbound.surfaces.agent_openapi import agent_api_document
from execbound.surfaces.mcp import TOOLS

LIFT = "endpoint.lift_isolation"
ISOLATE = "endpoint.isolate"


def reference(world, **changes):
    """The world's own isolation reference, changed in memory."""
    return world["bundle"].mappings[0].model_copy(update=changes)


def bundle_naming(world, *references):
    """The world's bundle naming exactly `references`, in memory only.

    `bundle_operations` reads the bundle it is handed, and the world's Cedar schema declares
    isolation alone, so such a bundle is never validated or activated; admission tests that
    need another operation in the tenant's mappings use `seed_soc_mappings`.
    """
    return world["bundle"].model_copy(update={"mappings": tuple(references)})


def lift_mapping(world):
    """The SOC seed's lift mapping as a bundle reference on the world's own account."""
    return reference(world, operation_ref=LIFT, context_contract_version="endpoint-recovery.v1")


def with_lift(world):
    """The world's bundle naming the lift too, in memory only (see `bundle_naming`)."""
    return bundle_naming(world, *world["bundle"].mappings, lift_mapping(world))


def offered_in(db, world, bundle=None, catalog=PRODUCTION_CATALOG):
    """What the agent's space offers under ``bundle``, or under its active bundle."""
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        space = agent_space(conn, tenant, world["identity"].principal_id)
        if bundle is None:
            bundle = store.active_bundle(conn, tenant, space)
        return bundle_operations(conn, tenant, space, bundle, catalog=catalog)


def refs(operations):
    return [item.operation_ref for item in operations.offered]


def write(admin_engine, world, statement, **params):
    """One owner write in the world's tenant; `:t` is the tenant."""
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(world["identity"].tenant_id)},
        )
        conn.execute(text(statement), {"t": world["identity"].tenant_id, **params})


def map_operation(admin_engine, world, operation_ref, contract="endpoint-isolation.v1"):
    """Another tenant mapping of endpoint isolation on the world's account."""
    write(
        admin_engine,
        world,
        "INSERT INTO execbound.operation_mappings "
        "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
        "provider_operation, mapping_version, schema_version, context_contract_version) "
        "VALUES (:t, :ref, :a, 'mock_crowdstrike', 'endpoint', 'endpoint.isolate', 'contain', "
        "'map-v1', 'action.v1', :contract)",
        ref=operation_ref,
        a=world["account"],
        contract=contract,
    )


def repoint_isolate(admin_engine, world):
    """What a sample removal and reinstall does (`0060_sample_targets.py`): the tenant's
    isolation mapping moves to a new account in the default space, at a new mapping version,
    while the active bundle still names the old reference."""
    account = uuid4()
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) VALUES (:t, :a, 'mock_crowdstrike', :s)"
            ),
            {"t": tenant, "a": account, "s": default_space(conn, tenant)},
        )
        conn.execute(
            text(
                "UPDATE execbound.operation_mappings SET account_id=:a, "
                "mapping_version='sample-v1' WHERE tenant_id=:t AND operation_ref=:r"
            ),
            {"t": tenant, "a": account, "r": ISOLATE},
        )


def test_la1_a_space_offers_what_its_bundle_maps_on_its_own_or_offered_accounts(
    db, world, admin_engine
):
    # The world's bundle maps one operation on the world's account, in the default space.
    operations = offered_in(db, world)
    assert refs(operations) == [ISOLATE]
    [isolate] = operations.offered
    assert (isolate.action, isolate.resource_type, isolate.incident_required) == (
        "endpoint.isolate",
        "endpoint",
        True,
    )
    assert operations.elsewhere == operations.stale == frozenset()
    # A mapping the tenant has but the bundle does not name is not offered.
    seed_soc_mappings(admin_engine, world)
    assert refs(offered_in(db, world)) == [ISOLATE]
    # Named by the bundle, it is offered, in operation_ref order.
    assert refs(offered_in(db, world, with_lift(world))) == [ISOLATE, LIFT]


def test_la1_a_reference_the_tenants_mapping_no_longer_matches_is_stale(db, world, admin_engine):
    """A stale policy: the bundle names an operation the tenant maps, at a reference its
    mapping no longer matches. It is not offered, and is told apart from an unknown one."""
    for changes in (
        {"account_id": uuid4()},
        {"mapping_version": "map-v2"},
        {"schema_version": "action.v2"},
        {"context_contract_version": "endpoint-recovery.v1"},
    ):
        operations = offered_in(db, world, bundle_naming(world, reference(world, **changes)))
        assert (operations.offered, operations.elsewhere, operations.stale) == (
            (),
            frozenset(),
            frozenset({ISOLATE}),
        ), changes
        with pytest.raises(ResolutionError) as stale:
            operations.check(ISOLATE)
        assert stale.value.code == "INVALID_BUNDLE"
    # The mapping inactive, or its account inactive: stale under the world's own bundle.
    for statement, value in (
        (
            "UPDATE execbound.operation_mappings SET active=:on "
            "WHERE tenant_id=:t AND operation_ref=:v",
            ISOLATE,
        ),
        (
            "UPDATE execbound.connector_accounts SET active=:on "
            "WHERE tenant_id=:t AND account_id=:v",
            world["account"],
        ),
    ):
        for active in (False, True):
            write(admin_engine, world, statement, on=active, v=value)
            operations = offered_in(db, world)
            expected = ([ISOLATE], frozenset()) if active else ([], frozenset({ISOLATE}))
            assert (refs(operations), operations.stale) == expected, (statement, active)
    # An operation the tenant does not map at all is unknown, not stale.
    unmapped = offered_in(
        db, world, bundle_naming(world, reference(world, operation_ref="nothing.mapped"))
    )
    assert (unmapped.offered, unmapped.elsewhere, unmapped.stale) == ((), frozenset(), frozenset())
    with pytest.raises(ResolutionError) as unknown:
        unmapped.check("nothing.mapped")
    assert unknown.value.code == "INVALID_OPERATION"


def test_la1_an_action_that_needs_no_incident_says_so(db, world, admin_engine):
    """`incident_required` follows the mapping's context contract. The synthetic contract
    requires none; a catalog that does not hold it offers nothing through it."""
    map_operation(admin_engine, world, SYNTHETIC_OPERATION, SYNTHETIC_VERSION)
    bundle = bundle_naming(
        world,
        *world["bundle"].mappings,
        reference(
            world, operation_ref=SYNTHETIC_OPERATION, context_contract_version=SYNTHETIC_VERSION
        ),
    )
    offered = offered_in(db, world, bundle, catalog=SYNTHETIC_CATALOG).offered
    assert [(item.operation_ref, item.incident_required) for item in offered] == [
        (ISOLATE, True),
        (SYNTHETIC_OPERATION, False),
    ]
    production = offered_in(db, world, bundle)
    assert (refs(production), production.stale) == ([ISOLATE], frozenset())
    with pytest.raises(ResolutionError) as unknown:
        production.check(SYNTHETIC_OPERATION)
    assert unknown.value.code == "INVALID_OPERATION"


def test_la1_the_order_is_the_bundles_whatever_the_database_collation(db, world, admin_engine):
    """`en_US.utf8` orders `_`, `.` and `-` apart from Python and `BundleContent`, which sort
    by code point; the read does too."""
    names = ("endpoint_a", "endpoint-b", ISOLATE)
    for name in names[:2]:
        map_operation(admin_engine, world, name)
    expected = sorted(names)
    assert expected == ["endpoint-b", ISOLATE, "endpoint_a"]
    bundle = bundle_naming(world, *(reference(world, operation_ref=name) for name in names))
    assert refs(offered_in(db, world, bundle)) == expected


def test_la1_another_spaces_account_is_named_elsewhere_until_it_is_offered_tenant_wide(
    db, world, admin_engine
):
    move_agent_to_a_second_space(admin_engine, world)
    operations = offered_in(db, world)
    assert operations.offered == ()
    assert operations.elsewhere == frozenset({ISOLATE})
    assert operations.stale == frozenset()
    with pytest.raises(ResolutionError) as refused:
        operations.check(ISOLATE)
    assert refused.value.code == "INVALID_CONFIGURATION"
    with pytest.raises(ResolutionError) as unknown:
        operations.check("nothing.mapped")
    assert unknown.value.code == "INVALID_OPERATION"
    write(
        admin_engine,
        world,
        "UPDATE execbound.connector_accounts SET offered_tenant_wide = true "
        "WHERE tenant_id=:t AND account_id=:a",
        a=world["account"],
    )
    operations = offered_in(db, world)
    assert refs(operations) == [ISOLATE]
    operations.check(ISOLATE)


def executions(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM execbound.executions WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()


def refused(db, world, wire):
    with pytest.raises(ExecutionError) as failure:
        admit(db, world["identity"], wire, world["clock"])
    return failure.value.code


def test_la2_bad_arguments_answer_400_only_for_an_operation_the_space_offers(
    db, world, admin_engine
):
    tenant = world["identity"].tenant_id
    seed_soc_mappings(admin_engine, world)
    # The space offers endpoint.isolate, which takes no arguments: bad arguments are 400.
    before = len(refused_by_admission(admin_engine, tenant))
    assert refused(db, world, request(world, arguments={"reason": "other"})) == "INVALID_REQUEST"
    assert refused_by_admission(admin_engine, tenant)[before:] == [
        {"operation": "admit", "reason": "INVALID_ARGUMENTS"}
    ]
    # The tenant maps the lift, but this space's bundle does not name it: whatever the
    # arguments, it is refused exactly as an operation nobody maps is.
    for wire, cause in (
        (request(world, operation_ref=LIFT, arguments={"reason": "other"}), "INVALID_OPERATION"),
        (
            request(world, operation_ref=LIFT, arguments={"reason": "remediated"}),
            "INVALID_OPERATION",
        ),
        (
            request(world, operation_ref="nothing.mapped", arguments={"reason": "other"}),
            "INVALID_OPERATION",
        ),
    ):
        before = len(refused_by_admission(admin_engine, tenant))
        assert refused(db, world, wire) == "EXECUTION_UNAVAILABLE"
        assert refused_by_admission(admin_engine, tenant)[before:] == [
            {"operation": "admit", "reason": cause}
        ]
    # Nothing was recorded as an execution: no DENIED INVALID_BUNDLE row says the lift exists.
    assert executions(admin_engine, tenant) == 0
    # A changed request under a known key is checked the same way before it is resolved.
    admitted = admit(db, world["identity"], request(world, idempotency_key="known"), world["clock"])
    assert admitted.view.state == "PENDING_APPROVAL"
    changed = request(
        world, operation_ref=LIFT, arguments={"reason": "other"}, idempotency_key="known"
    )
    before = len(refused_by_admission(admin_engine, tenant))
    assert refused(db, world, changed) == "EXECUTION_UNAVAILABLE"
    assert refused_by_admission(admin_engine, tenant)[before:] == [
        {"operation": "admit", "reason": "INVALID_OPERATION"}
    ]
    assert executions(admin_engine, tenant) == 1


def test_la2_a_stale_policy_is_refused_as_unknown_and_audited_as_itself(db, world, admin_engine):
    """The agent is answered as for an unknown operation. A person reads `INVALID_BUNDLE`, the
    active bundle cannot authorize this request, rather than a missing mapping."""
    tenant = world["identity"].tenant_id
    repoint_isolate(admin_engine, world)
    before = len(refused_by_admission(admin_engine, tenant))
    assert refused(db, world, request(world)) == "EXECUTION_UNAVAILABLE"
    assert refused_by_admission(admin_engine, tenant)[before:] == [
        {"operation": "admit", "reason": "INVALID_BUNDLE"}
    ]
    assert executions(admin_engine, tenant) == 0


def test_la2_an_observing_tenant_is_refused_the_same_way(db, world, admin_engine):
    seed_soc_mappings(admin_engine, world)
    set_enforcement_mode(db, world["admin"], "OBSERVE", "tuning", world["clock"])
    wire = request(world, operation_ref=LIFT, arguments={"reason": "remediated"})
    assert refused(db, world, wire) == "EXECUTION_UNAVAILABLE"
    assert executions(admin_engine, world["identity"].tenant_id) == 0


def test_la3_every_operation_outside_the_space_costs_the_same_statements(db, world, admin_engine):
    """An unknown operation, one the tenant maps but the bundle does not name, one the bundle
    names through another space's account and one it names at a stale reference run the same
    statements in the same order: as a new request, and as a changed request under a known
    key."""
    seed_soc_mappings(admin_engine, world)
    held = admit(db, world["identity"], request(world, idempotency_key="held"), world["clock"])
    assert held.view.state == "PENDING_APPROVAL"
    statements: list[str] = []

    def counted(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    def cost(wire):
        statements.clear()
        event.listen(db.engine, "before_cursor_execute", counted)
        try:
            assert refused(db, world, wire) == "EXECUTION_UNAVAILABLE"
        finally:
            event.remove(db.engine, "before_cursor_execute", counted)
        return tuple(statements)

    new: dict[str, tuple[str, ...]] = {}
    known: dict[str, tuple[str, ...]] = {}

    def measure(kind, **changes):
        new[kind] = cost(request(world, idempotency_key=kind, **changes))
        # Another target selector makes it a changed request under the held key.
        target = {"kind": "canonical", "value": str(uuid4())}
        known[kind] = cost(request(world, idempotency_key="held", target=target, **changes))

    measure("unknown", operation_ref="nothing.mapped")
    measure("unnamed", operation_ref=LIFT, arguments={"reason": "other"})
    move_agent_to_a_second_space(admin_engine, world)
    measure("elsewhere")
    repoint_isolate(admin_engine, world)
    measure("stale")
    assert len(set(new.values())) == 1, sorted(new)
    assert len(set(known.values())) == 1, sorted(known)
    # The known branch reads the held row first, so it is the other path, not this one twice.
    assert new["unknown"] != known["unknown"]


def test_la4_another_spaces_account_is_audited_as_itself_and_answered_as_unavailable(
    api, db, world, admin_engine, live_provider
):
    tenant = world["identity"].tenant_id
    # Held for approval while the account was still the agent's space's.
    held = request(world, idempotency_key="held").model_dump(mode="json")
    assert api.post("/v1/execute", json=held).status_code == 202
    move_agent_to_a_second_space(admin_engine, world)
    # A new request is refused by what the space offers. The held one skips that check, as
    # an unchanged request under a known key does, and meets `_account_in_space`, which is
    # still there as the defence it was: audited as itself, answered as nothing.
    for wire in (request(world).model_dump(mode="json"), held):
        before = len(refused_by_admission(admin_engine, tenant))
        answered = api.post("/v1/execute", json=wire)
        assert answered.status_code == 503 and answered.content == UNAVAILABLE
        assert refused_by_admission(admin_engine, tenant)[before:] == [
            {"operation": "admit", "reason": "INVALID_CONFIGURATION"}
        ]
    # The first request above was a new key for the held intent: refused before resolution,
    # it never attached to the held row, which is untouched and still the only execution.
    with admin_engine.connect() as conn:
        states = conn.execute(
            text("SELECT state FROM execbound.executions WHERE tenant_id=:t"), {"t": tenant}
        ).scalars()
        assert list(states) == ["PENDING_APPROVAL"]


def test_la2_a_changed_request_under_a_known_key_needs_the_spaces_policy(db, world, admin_engine):
    """A changed request under a known key is checked against what the space offers before it
    is resolved, so with no active policy it is refused `NO_ACTIVE_BUNDLE`, even where the
    row it names is already final. The identical request still answers from its own row."""
    first = request(
        world, idempotency_key="final", target={"kind": "canonical", "value": str(world["target"])}
    )
    domain_controller(admin_engine, first)
    assert admit(db, world["identity"], first, world["clock"]).view.state == "DENIED"
    write(admin_engine, world, "DELETE FROM execbound.space_policy_selection WHERE tenant_id=:t")
    # The same intent named another way: the world's hostname for the same target.
    changed = request(world, idempotency_key="final")
    assert refused(db, world, changed) == "NO_ACTIVE_BUNDLE"
    assert admit(db, world["identity"], first, world["clock"]).view.state == "DENIED"


KINDS = ["canonical", "hostname", "provider_id"]
LISTED_ISOLATE = {
    "operation_ref": ISOLATE,
    "action": ISOLATE,
    "label": "Isolate endpoint",
    "arguments": [],
    "target_kinds": KINDS,
    "incident_required": True,
}
LISTED_LIFT = {
    "operation_ref": LIFT,
    "action": LIFT,
    "label": "Lift endpoint isolation",
    "arguments": [{"name": "reason", "type": "string", "values": ["false_positive", "remediated"]}],
    "target_kinds": KINDS,
    "incident_required": True,
}


# Enough values that a set's iteration order is almost never already sorted.
TIERS = ("gold", "Silver", "bronze", "tin", "iron", "Lead", "zinc", "copper")


def listed(db, identity, clock):
    answer = listing(db, identity, clock, catalog=PRODUCTION_CATALOG)
    return answer.model_dump(mode="json", exclude_none=True)


def listing_of(*offered, catalog=PRODUCTION_CATALOG):
    return action_listing(offered, catalog).model_dump(mode="json", exclude_none=True)


def test_la5_the_listing_names_operations_arguments_and_target_kinds_and_nothing_else(
    db, world, admin_engine
):
    assert listed(db, world["identity"], world["clock"]) == {"actions": [LISTED_ISOLATE]}
    # An action with an argument, listed from a bundle that names it (in memory; see with_lift).
    seed_soc_mappings(admin_engine, world)
    answer = listing_of(*offered_in(db, world, with_lift(world)).offered)
    assert answer == {"actions": [LISTED_ISOLATE, LISTED_LIFT]}
    # Never a target, a rule, a limit, a placement, an account or a mapping.
    text_of = json.dumps(answer)
    for absent in (
        str(world["target"]),
        str(world["canonical"]),
        str(world["account"]),
        "mock_crowdstrike",
        "contain",
        "map-v1",
        "ws01",
        "domain_controller",
        "observe",
        "external_executor",
        "budget",
        "policy0",
    ):
        assert absent not in text_of, absent


def test_la5_an_identity_action_takes_no_hostname_and_each_domain_is_listed_as_it_is_checked():
    """An identity action refuses a hostname selector (`registry.resource`), so it lists the
    two kinds it accepts. A boolean argument lists no values, an integer one its range, and a
    string one its values in code point order, whatever order the set iterates in."""
    reset = OfferedOperation("identity.reset", "identity.reset_password", "identity", False)
    assert listing_of(reset) == {
        "actions": [
            {
                "operation_ref": "identity.reset",
                "action": "identity.reset_password",
                "label": "Reset identity password",
                "arguments": [{"name": "require_change_at_next_sign_in", "type": "boolean"}],
                "target_kinds": ["canonical", "provider_id"],
                "incident_required": False,
            }
        ]
    }
    counted = replace(
        PRODUCTION_CATALOG.actions.action(LIFT),
        arguments=(
            ArgumentSpec("count", "Long", IntegerDomain(1, 5)),
            ArgumentSpec("tier", "String", StringDomain(frozenset(TIERS))),
        ),
        reversed_by=None,
    )
    catalog = Catalog((), actions=ActionCatalog((counted,), ()))
    lift = OfferedOperation(LIFT, LIFT, "endpoint", True)
    [action] = listing_of(lift, catalog=catalog)["actions"]
    assert action["arguments"] == [
        {"name": "count", "type": "integer", "minimum": 1, "maximum": 5},
        {"name": "tier", "type": "string", "values": sorted(TIERS)},
    ]


def test_la5_an_observed_or_checkpoint_mapping_is_listed_as_a_connected_one_is(db, world):
    """The agent may send an observe-only or a checkpoint (Gate) operation, so both are listed,
    and exactly as a connected one: the same members, and nothing that says where the
    operation is placed."""
    connected = listing_of(*offered_in(db, world).offered)
    assert connected == {"actions": [LISTED_ISOLATE]}
    for placement in ("observe_only", "external_executor"):
        bundle = bundle_naming(world, reference(world, **{placement: True}))
        assert bundle.mappings[0].model_dump(mode="json")[placement] is True
        answer = listing_of(*offered_in(db, world, bundle).offered)
        assert answer == connected, placement
        text_of = json.dumps(answer)
        for absent in ("observe", "external", "executor", "checkpoint", "gate", "mode"):
            assert absent not in text_of, (placement, absent)


def test_la5_the_runtime_logs_how_many_were_listed_and_never_which(runtime, world, captured):
    answer = runtime.list_actions(world["identity"])
    assert answer.model_dump(mode="json", exclude_none=True) == {"actions": [LISTED_ISOLATE]}
    [logged] = events(captured, "actions.listed")
    assert (logged["principal_id"], logged["count"]) == (str(world["identity"].principal_id), 1)
    assert ISOLATE not in captured.getvalue()


def test_la6_what_a_space_lists_follows_the_space_and_what_it_is_offered(db, world, admin_engine):
    identity, clock = world["identity"], world["clock"]
    # Another space's agent lists nothing while the account is not offered to it: what the
    # bundle names through another space's account is refused as unknown, and not listed.
    move_agent_to_a_second_space(admin_engine, world)
    assert listed(db, identity, clock) == {"actions": []}
    write(
        admin_engine,
        world,
        "UPDATE execbound.connector_accounts SET offered_tenant_wide = true "
        "WHERE tenant_id=:t AND account_id=:a",
        a=world["account"],
    )
    assert listed(db, identity, clock) == {"actions": [LISTED_ISOLATE]}


def test_la6_a_stale_policy_lists_nothing_it_can_no_longer_authorize(db, world, admin_engine):
    repoint_isolate(admin_engine, world)
    assert listed(db, world["identity"], world["clock"]) == {"actions": []}


def test_la6_no_active_policy_lists_nothing_and_an_archived_space_is_refused(
    db, world, admin_engine
):
    identity, clock = world["identity"], world["clock"]
    write(admin_engine, world, "DELETE FROM execbound.space_policy_selection WHERE tenant_id=:t")
    assert listed(db, identity, clock) == {"actions": []}
    second = move_agent_to_a_second_space(admin_engine, world)
    with db.transaction(identity.tenant_id) as conn:
        archive_space(
            conn,
            identity.tenant_id,
            world["admin"].principal_id,
            second,
            "closing",
            credential=None,
        )
    with pytest.raises(ExecutionError) as archived:
        listing(db, identity, clock, catalog=PRODUCTION_CATALOG)
    assert archived.value.code == "SPACE_ARCHIVED"


def test_la6_an_emergency_stop_does_not_stop_a_listing_and_only_an_agent_lists(db, world):
    """A stop halts new executions, not reads: a status read continues during one, and so
    does a listing. A person's identity is refused, as it is by every agent read."""
    activate_stop(db, world["admin"], "Contain agent 7", world["clock"])
    assert listed(db, world["identity"], world["clock"]) == {"actions": [LISTED_ISOLATE]}
    with pytest.raises(ExecutionError) as person:
        listing(db, world["admin"], world["clock"], catalog=PRODUCTION_CATALOG)
    assert person.value.code == "INVALID_IDENTITY"


def test_la7_get_v1_actions_answers_the_listing_and_refuses_a_body_or_a_query(
    api, world, admin_engine
):
    answered = api.get("/v1/actions")
    assert answered.status_code == 200, answered.text
    assert answered.json() == {"actions": [LISTED_ISOLATE]}
    assert answered.headers["cache-control"] == "no-store"
    tenant = world["identity"].tenant_id
    before = len(audit_payloads(admin_engine, tenant, "execution.rejected"))
    assert api.get("/v1/actions?all=1").status_code == 400
    framed = api.request(
        "GET", "/v1/actions", content=b"{}", headers={"Content-Type": "application/json"}
    )
    assert framed.status_code == 400
    assert framed.json() == {"detail": "Execution unavailable", "code": "INVALID_REQUEST"}
    # Each refusal is the surface's, audited as the status route's are.
    assert (
        audit_payloads(admin_engine, tenant, "execution.rejected")[before:]
        == [{"operation": "surface", "reason": "INVALID_REQUEST"}] * 2
    )


def archive_the_agents_space(db, admin_engine, world):
    """The agent moves to a second space, which is then archived."""
    second = move_agent_to_a_second_space(admin_engine, world)
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        admin = world["admin"].principal_id
        archive_space(conn, tenant, admin, second, "closing", credential=None)


ARCHIVED_REFUSAL = {"operation": "surface", "reason": "SPACE_ARCHIVED"}


def test_la7_an_archived_space_is_answered_423_and_audited_once(api, db, world, admin_engine):
    tenant = world["identity"].tenant_id
    archive_the_agents_space(db, admin_engine, world)
    before = len(audit_payloads(admin_engine, tenant, "execution.rejected"))
    answered = api.get("/v1/actions")
    assert answered.status_code == 423
    assert answered.json() == {"detail": "Execution unavailable", "code": "SPACE_ARCHIVED"}
    # Audited by the runtime, as a refused status read is.
    rows = audit_payloads(admin_engine, tenant, "execution.rejected")[before:]
    assert rows == [ARCHIVED_REFUSAL]


def test_la7_the_published_document_describes_the_listing_and_only_what_it_can_answer():
    document = agent_api_document()
    listed = document["paths"]["/v1/actions"]["get"]
    answer = listed["responses"]["200"]["content"]["application/json"]["schema"]
    assert answer == {"$ref": "#/components/schemas/ActionListing"}
    schemas = document["components"]["schemas"]
    assert set(schemas["ActionListing"]["properties"]) == set(ActionListing.model_fields)
    assert set(schemas["ListedAction"]["properties"]) == {
        "operation_ref",
        "action",
        "label",
        "arguments",
        "target_kinds",
        "incident_required",
    }
    # A read is never busy and never stopped by an emergency stop, and a denial's category,
    # an idempotency conflict or a grant's limit cannot arise: none is documented here.
    codes = " ".join(response["description"] for response in listed["responses"].values())
    for absent in ("TENANT_STOPPED", "BUSY", "IDEMPOTENCY_CONFLICT", "TOO_MANY_GRANTS"):
        assert absent not in codes, absent
    assert set(listed["responses"]) == {"200", "400", "401", "403", "409", "423", "429", "503"}
    # A person's credential is refused `{"detail": "Forbidden"}`, with no code; a
    # deactivated agent is a 401. And the listing is never busy.
    assert listed["responses"]["403"]["description"] == "The credential is not an agent's."
    retry = listed["responses"]["429"]["headers"]["Retry-After"]["description"]
    assert retry == "Seconds to wait. Sent with RATE_LIMITED."
    execute = document["paths"]["/v1/execute"]["post"]["responses"]["429"]
    assert "not with BUSY" in execute["headers"]["Retry-After"]["description"]
    # An argument's domain members are absent when the domain has none, never null.
    argument = schemas["ListedArgument"]
    assert argument["required"] == ["name", "type"]
    assert "null" not in json.dumps(argument)
    assert {name: member.get("type") for name, member in argument["properties"].items()} == {
        "name": "string",
        "type": "string",
        "values": "array",
        "minimum": "integer",
        "maximum": "integer",
    }


def mcp_post(gateway, token, method, params):
    """One JSON-RPC message over the real transport; its result, whatever it says."""
    response = httpx.post(
        gateway + "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
            "MCP-Method": method,
            **({"MCP-Name": params["name"]} if "name" in params else {}),
        },
        trust_env=False,
    )
    assert response.status_code == 200, response.text
    return response.json()["result"]


def test_la7_the_guide_tells_an_agent_to_stop_when_a_503_persists():
    """A 503 invites a retry, but stale trusted facts never fix themselves: the sample targets'
    facts go stale after an hour, and every request after that is answered 503 with no record.
    So the guide tells the agent to stop and tell a person when the answer persists."""
    meaning, action = ERROR_MEANINGS["EXECUTION_UNAVAILABLE"]
    assert "GET /v1/actions" in meaning
    assert "if the answer persists, stop and tell a person" in action
    description = agent_api_document()["info"]["description"]
    assert "one that persists needs a person" in description


def test_la8_the_mcp_tool_answers_what_the_route_answers_and_takes_no_arguments(
    gateway, api, seeded, world
):
    token = seeded["tokens"][0]
    listed = mcp_call(gateway, token, "list_actions", {})
    assert listed == api.get("/v1/actions").json() == {"actions": [LISTED_ISOLATE]}
    # Advertised as what it is, beside the other two, and taking nothing.
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    advertised = mcp_post(gateway, token, "tools/list", {"_meta": meta})["tools"]
    assert {tool["name"] for tool in advertised} == {"execute", "execution_status", "list_actions"}
    [tool] = [tool for tool in advertised if tool["name"] == "list_actions"]
    assert tool["inputSchema"] == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }
    assert "not permission" in tool["description"] and "never listed" in tool["description"]
    # Any argument at all is refused, as an unknown argument to another tool is.
    for arguments in ({"x": 1}, {"request": {}}):
        refused = mcp_post(
            gateway,
            token,
            "tools/call",
            {"_meta": meta, "name": "list_actions", "arguments": arguments},
        )
        assert refused["isError"] is True, arguments
        assert refused["structuredContent"] == {
            "detail": "Execution unavailable",
            "code": "INVALID_REQUEST",
        }


def test_la8_a_call_with_no_arguments_member_is_a_call_with_none(gateway, seeded):
    """MCP makes `arguments` optional, and the SDK's own client omits it for a tool called
    with none: that is `list_actions` called properly, and the other two tools' exact key
    checks refuse it. When `arguments` is sent, it is an object or the message is refused."""
    token = seeded["tokens"][0]
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    bare = mcp_post(gateway, token, "tools/call", {"_meta": meta, "name": "list_actions"})
    assert bare["isError"] is False
    assert bare["structuredContent"] == {"actions": [LISTED_ISOLATE]}
    for name in ("execute", "execution_status"):
        refused = mcp_post(gateway, token, "tools/call", {"_meta": meta, "name": name})
        assert refused["isError"] is True, name
        assert refused["structuredContent"]["code"] == "INVALID_REQUEST", name

    async def through_the_sdk():
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + token}, trust_env=False
        ) as http:
            async with Client(
                streamable_http_client(gateway + "/mcp/", http_client=http)
            ) as client:
                return await client.call_tool("list_actions")

    result = asyncio.run(through_the_sdk())
    assert not result.is_error
    assert result.structured_content == {"actions": [LISTED_ISOLATE]}
    for arguments in (None, [], "x", 1):
        response = httpx.post(
            gateway + "/mcp/",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"_meta": meta, "name": "list_actions", "arguments": arguments},
            },
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2026-07-28",
                "MCP-Method": "tools/call",
                "MCP-Name": "list_actions",
            },
            trust_env=False,
        )
        assert response.status_code == 400, arguments
        assert response.json() == {"detail": "Invalid request"}


def test_la8_an_archived_space_is_a_tool_error_audited_as_the_status_tool_is(
    gateway, seeded, db, world, admin_engine
):
    """The runtime audits the refusal and `call_tool` audits it again, as it does a refused
    `execution_status` or `execute`: two surface rows."""
    tenant = world["identity"].tenant_id
    archive_the_agents_space(db, admin_engine, world)
    before = len(audit_payloads(admin_engine, tenant, "execution.rejected"))
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    refused = mcp_post(
        gateway, seeded["tokens"][0], "tools/call", {"_meta": meta, "name": "list_actions"}
    )
    assert refused["isError"] is True
    assert refused["structuredContent"] == {
        "detail": "Execution unavailable",
        "code": "SPACE_ARCHIVED",
    }
    rows = audit_payloads(admin_engine, tenant, "execution.rejected")[before:]
    assert rows == [ARCHIVED_REFUSAL] * 2


def test_la8_a_whole_soc_policy_is_listed_alike_over_both_surfaces(
    gateway, api, seeded, world, db, admin_engine
):
    """The SOC pack active in the space: six operations on two accounts, one with a string
    argument, one with a boolean, four that take no hostname. Both surfaces answer the same
    bytes' worth of JSON, with no member that is null."""
    bundle = seeded_soc_bundle(admin_engine, world)
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    over_http = api.get("/v1/actions").json()
    assert mcp_call(gateway, seeded["tokens"][0], "list_actions", {}) == over_http
    actions = {action["operation_ref"]: action for action in over_http["actions"]}
    assert list(actions) == sorted(PRODUCTION_CATALOG.actions.names)
    assert actions[ISOLATE] == LISTED_ISOLATE and actions[LIFT] == LISTED_LIFT
    assert actions["identity.reset_password"]["arguments"] == [
        {"name": "require_change_at_next_sign_in", "type": "boolean"}
    ]
    for name, action in actions.items():
        assert action["action"] == name and action["incident_required"] is True
        identity = name.startswith("identity.")
        assert action["target_kinds"] == (["canonical", "provider_id"] if identity else KINDS)
    assert "null" not in json.dumps(over_http)


def test_la8_the_execute_tool_sends_the_model_to_the_listing_for_action_names():
    (execute,) = [tool for tool in TOOLS if tool.name == "execute"]
    assert execute.description is not None
    assert (
        "Call list_actions for the operation_ref values your space offers and their arguments."
        in execute.description
    )
    assert "published action catalog" not in execute.description
    assert len(execute.description) < 800, len(execute.description)
