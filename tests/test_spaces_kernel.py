# SPDX-License-Identifier: AGPL-3.0-only
"""Admission, the per-space selection, the space limit scope and the archive race.

SP5 (sharing is opt-in per object), SP6 (per-space policy selection), SP7 (a `space` rule
counts only its own retained rows) and SP9 (the archive race, on real PostgreSQL with two
connections, never sequential mocks).
"""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from scope_fixtures import audit_payloads
from space_fixtures import default_space, make_space, move_agent_to_a_second_space
from sqlalchemy import text
from test_execution import finish, request
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError
from execbound.policy.models import LimitRule
from execbound.policy.store import PolicyStoreError, activate_bundle, create_bundle, validate_bundle
from execbound.spaces import SpaceError, archive_space, is_archived
from execbound.surfaces import space_pages
from execbound.surfaces.human import authority_guard
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration


def session_for(db, identity, clock=None):
    """A session on the test's own clock, so `check_session` reads the same instant the
    surfaces read; a session issued on the wall clock is a second in the future to them."""
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


def agent_space(admin_engine, tenant, principal):
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return conn.execute(
            text(
                "SELECT space_id FROM execbound.principals WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "p": principal},
        ).scalar_one()


def move_agent(admin_engine, tenant, principal, space):
    """Move one agent between spaces on the owner connection.

    Production has no path that moves an agent between spaces; this builds a fixture and
    nothing more, and the retained impact rows deliberately keep the space they were charged
    to.
    """
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "UPDATE execbound.principals SET space_id=:s WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "s": space, "p": principal},
        )


def test_sp6_a_space_with_no_selection_fails_closed(db, admin_engine, world):
    """A space with no selection fails closed exactly as a tenant with none did."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Customer B")
    move_agent(admin_engine, tenant, world["identity"].principal_id, second)
    with pytest.raises(ExecutionError) as refused:
        admit(db, world["identity"], request(world), world["clock"])
    assert refused.value.code == "NO_ACTIVE_BUNDLE"


def test_sp6_each_space_is_admitted_under_its_own_selection(db, admin_engine, world):
    """`ACTIVE` means "selected by at least one space": two spaces may select two
    bundles, and each agent is admitted under its own."""
    tenant = world["identity"].tenant_id
    admin = world["admin"]
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer B")
    # A second bundle, selected by the second space alone.
    replacement = world["bundle"].model_copy(update={"bundle_id": uuid4()})
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "UPDATE execbound.connector_accounts SET offered_tenant_wide = true "
                "WHERE tenant_id=:t AND account_id=:a"
            ),
            {"t": tenant, "a": world["account"]},
        )
    create_bundle(db, admin, replacement, world["clock"], space=second)
    validate_bundle(db, admin, replacement.bundle_id, world["clock"])
    activate_bundle(db, admin, replacement.bundle_id, world["clock"], space=second)
    with db.transaction(tenant) as conn:
        selections = dict(
            conn.execute(
                text(
                    "SELECT space_id, bundle_id FROM execbound.space_policy_selection "
                    "WHERE tenant_id=:t"
                ),
                {"t": tenant},
            ).all()
        )
    assert selections[first] == world["bundle"].bundle_id
    assert selections[second] == replacement.bundle_id
    # Both are ACTIVE, because both are named by a selection row.
    with db.transaction(tenant) as conn:
        states = dict(
            conn.execute(
                text(
                    "SELECT bundle_id, state FROM execbound.policy_bundle_lifecycle "
                    "WHERE tenant_id=:t"
                ),
                {"t": tenant},
            ).all()
        )
    assert states[world["bundle"].bundle_id] == "ACTIVE"
    assert states[replacement.bundle_id] == "ACTIVE"
    # The agent moved to the second space is admitted under the second space's bundle;
    # the account its mapping names is offered tenant-wide, so both spaces may use it.
    move_agent(admin_engine, tenant, world["identity"].principal_id, second)
    admitted = admit(db, world["identity"], request(world), world["clock"])
    with db.transaction(tenant) as conn:
        chosen = conn.execute(
            text(
                "SELECT bundle_id FROM execbound.executions WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": admitted.view.execution_id},
        ).scalar_one()
    assert chosen == replacement.bundle_id


def test_sp6_a_bundle_a_space_selects_cannot_be_retired(db, world):
    from execbound.policy.store import retire_bundle

    with pytest.raises(PolicyStoreError) as refused:
        retire_bundle(db, world["admin"], world["bundle"].bundle_id, world["clock"])
    assert refused.value.code == "INVALID_STATE"


def test_sp5_a_mapping_on_another_spaces_account_is_refused_before_any_provider_contact(
    db, admin_engine, world
):
    """What stops a mapping provisioned for one customer being reachable by another's
    agent: the account must be the agent's space or offered tenant-wide. The agent is
    answered as for an unknown operation; the audit keeps the cause (T1.17)."""
    tenant = world["identity"].tenant_id
    # The agent moves; the account it maps to stays behind and is not offered.
    move_agent_to_a_second_space(admin_engine, world)
    with pytest.raises(ExecutionError) as refused:
        admit(db, world["identity"], request(world), world["clock"])
    assert refused.value.code == "EXECUTION_UNAVAILABLE"
    assert audit_payloads(admin_engine, tenant, "execution.rejected")[-1] == {
        "operation": "admit",
        "reason": "INVALID_CONFIGURATION",
    }
    # Offered tenant-wide, the same account is usable by the second space.
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "UPDATE execbound.connector_accounts SET offered_tenant_wide = true "
                "WHERE tenant_id=:t AND account_id=:a"
            ),
            {"t": tenant, "a": world["account"]},
        )
    assert admit(db, world["identity"], request(world), world["clock"]).view.state in {
        "PENDING_APPROVAL",
        "DISPATCH_COMMITTED",
    }


def test_sp7_a_space_rule_counts_only_its_own_retained_rows(db, admin_engine, world):
    """A `space` rule counts over the retained `execution_impact` row, so moving an agent
    later never rewrites what past impact counted for."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer B")
    admitted = admit(db, world["identity"], request(world), world["clock"])
    assert admitted.view.state == "PENDING_APPROVAL"
    decide_approval(db, world["human"], admitted.view.approval_id, "APPROVE", world["clock"])
    committed = admit(db, world["identity"], request(world), world["clock"])
    assert committed.view.state == "DISPATCH_COMMITTED" and committed.ticket is not None
    finish(db, world, committed)
    with db.transaction(tenant) as conn:
        charged = (
            conn.execute(
                text("SELECT space_id FROM execbound.execution_impact WHERE tenant_id=:t"),
                {"t": tenant},
            )
            .scalars()
            .all()
        )
    assert set(charged) == {first}
    # Moving the agent does not move the charge.
    move_agent(admin_engine, tenant, world["identity"].principal_id, second)
    with db.transaction(tenant) as conn:
        still = (
            conn.execute(
                text("SELECT space_id FROM execbound.execution_impact WHERE tenant_id=:t"),
                {"t": tenant},
            )
            .scalars()
            .all()
        )
    assert set(still) == {first}


def test_sp7_a_space_rule_is_refused_without_its_qualifier_and_with_a_doubled_one():
    """A qualifier without its scope, or a scope without its qualifier, is refused so a
    rule can never silently widen to the tenant."""
    common = {
        "rule_id": "space-cap",
        "action": "endpoint.isolate",
        "window_seconds": 3600,
        "max_targets": 5,
        "budget": "total",
        "on_exceed": "DENY",
    }
    with pytest.raises(ValueError, match="Scope qualifier mismatch"):
        LimitRule(scope="space", **common)
    with pytest.raises(ValueError, match="Scope qualifier mismatch"):
        LimitRule(scope="tenant", space_id=uuid4(), **common)
    rule = LimitRule(scope="space", space_id=uuid4(), **common)
    assert rule.applies_to(
        action="endpoint.isolate", account_id=uuid4(), groups=(), facts={}, space_id=rule.space_id
    )
    # A candidate with no recorded space fails closed out of the scope.
    assert not rule.applies_to(
        action="endpoint.isolate", account_id=uuid4(), groups=(), facts={}, space_id=None
    )


def test_sp7_an_unknown_space_in_a_rule_fails_validation_with_its_field(db, world):
    tenant = world["identity"].tenant_id
    rule = LimitRule(
        rule_id="space-cap",
        action="endpoint.isolate",
        scope="space",
        space_id=uuid4(),
        window_seconds=3600,
        max_targets=5,
        budget="total",
        on_exceed="DENY",
    )
    content = world["bundle"].model_copy(
        update={"bundle_id": uuid4(), "limits": (*world["bundle"].limits, rule)}
    )
    create_bundle(db, world["admin"], content, world["clock"])
    with pytest.raises(PolicyStoreError) as refused:
        validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    assert refused.value.code == "INVALID_COMPONENT"
    assert refused.value.location is not None and refused.value.location.endswith("space_id")
    assert tenant is not None


def test_sp9_an_archived_space_refuses_new_work_at_the_stops_check_point(db, admin_engine, world):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Customer B")
    with db.transaction(tenant) as conn:
        archive_space(
            conn, tenant, world["admin"].principal_id, second, "customer left", credential=None
        )
        assert is_archived(conn, tenant, second)
    move_agent(admin_engine, tenant, world["identity"].principal_id, second)
    with pytest.raises(ExecutionError) as refused:
        admit(db, world["identity"], request(world), world["clock"])
    assert refused.value.code == "SPACE_ARCHIVED"


def test_sp9_a_dispatch_committed_execution_is_not_cancelled_by_an_archive(db, admin_engine, world):
    tenant = world["identity"].tenant_id
    admitted = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], admitted.view.approval_id, "APPROVE", world["clock"])
    committed = admit(db, world["identity"], request(world), world["clock"])
    assert committed.view.state == "DISPATCH_COMMITTED"
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        make_space(conn, tenant, "Customer B")
    with db.transaction(tenant) as conn:
        first = default_space(conn, tenant)
        archive_space(conn, tenant, world["admin"].principal_id, first, "closing", credential=None)
    with db.transaction(tenant) as conn:
        state = conn.execute(
            text("SELECT state FROM execbound.executions WHERE tenant_id=:t AND execution_id=:e"),
            {"t": tenant, "e": committed.view.execution_id},
        ).scalar_one()
    assert state == "DISPATCH_COMMITTED"


def test_sp9_the_archive_and_the_decision_race_has_exactly_one_winner(
    db, runtime, admin_engine, world
):
    """Two connections on real PostgreSQL, never sequential mocks. The archive takes the
    tenant fence and `decide_approval` rechecks the space under that same fence, so the
    two are totally ordered and exactly one of them commits."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        make_space(conn, tenant, "Customer B")
    admitted = admit(db, world["identity"], request(world), world["clock"])
    approval = admitted.view.approval_id
    administrator = session_for(db, world["admin"], world["clock"])
    with db.transaction(tenant) as conn:
        first = default_space(conn, tenant)
    barrier = Barrier(2)

    def archive():
        barrier.wait(timeout=10)
        try:
            space_pages.archive(runtime, administrator, first, "customer left")
            return "archived"
        except SpaceError as exc:
            return exc.code

    def decide():
        barrier.wait(timeout=10)
        try:
            decide_approval(
                db,
                world["human"],
                approval,
                "APPROVE",
                world["clock"],
                authority_check=authority_guard(
                    runtime, session_for(db, world["human"], world["clock"])
                ),
            )
            return "decided"
        except ExecutionError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [
            future.result(timeout=30) for future in (pool.submit(archive), pool.submit(decide))
        ]
    assert outcomes[0] == "archived"
    # The decision either landed before the archive committed or was refused by it; both
    # are one winner, and neither leaves a half-decided approval.
    assert outcomes[1] in {"decided", "SPACE_ARCHIVED"}
    with db.transaction(tenant) as conn:
        state = conn.execute(
            text("SELECT state FROM execbound.approvals WHERE tenant_id=:t AND approval_id=:a"),
            {"t": tenant, "a": approval},
        ).scalar_one()
    assert state == ("APPROVED" if outcomes[1] == "decided" else "PENDING")
