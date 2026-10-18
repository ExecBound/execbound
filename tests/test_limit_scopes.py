# SPDX-License-Identifier: AGPL-3.0-only
"""Shared limit scopes SL1 to SL6, SL8 and SL12 on real PostgreSQL through the live kernel."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from identity_fixtures import ACTIONS, add_target, identity_request
from identity_fixtures import identity_connector as identity_connector
from identity_fixtures import identity_provider as identity_provider
from identity_fixtures import identity_world as identity_world
from scope_fixtures import (
    agent,
    audit_payloads,
    counted,
    group,
    impact_groups,
    rule,
    scoped_bundle,
    transition_payload,
    usage,
)
from scope_fixtures import owner as owner
from sqlalchemy import text
from test_execution import counts, finish, provision_identity, request, retained_attributes, targets
from test_execution import registry as registry
from test_execution import world as world
from test_observe_mode import impacts, observe
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_soc_execution import add_endpoint, impact, isolate, lift, sync_version
from test_soc_execution import soc_runtime as soc_runtime
from test_soc_execution import soc_world as soc_world

from execbound import administration
from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError
from execbound.identity import authenticate
from execbound.policy.models import MAX_GROUPS, LimitSelector
from execbound.replay.export import export_history
from execbound.replay.simulate import simulate
from execbound.replay.verify import verify_export
from execbound_harness.demo import endpoint_bundle


def replayed(db, world):
    """The offline ledger over the tenant's exported history reproduces every live decision.

    Every capture on this database carries the membership, account and facts the kernel
    counted with, so a complete baseline whose decisions all match the recorded ones
    proves the ledger counts under each scope as the store did.
    """
    history = export_history(db, world["admin"], world["clock"])
    report = simulate(verify_export(history, history.head))
    assert report.complete, report.issues
    assert "RECORDED_DECISION_MISMATCH" not in report.issues
    assert report.decisions
    for row in report.decisions:
        assert row.baseline.effect == row.recorded_effect, row
    return report


def baselines(report, admission, stage="ADMISSION"):
    """The replayed baselines of ``admission``'s execution at ``stage``, in history order."""
    return [
        row.baseline
        for row in report.decisions
        if row.execution_id == admission.view.execution_id and row.stage == stage
    ]


def test_sl1_group_ceiling_escalates_the_fourth_isolation_across_members(
    db, world, admin_engine, owner
):
    tenant, clock = world["identity"].tenant_id, world["clock"]
    first, second = world["identity"], agent(admin_engine, db, world)
    outsider = agent(admin_engine, db, world)
    triage = group(owner, world, first, second, name="triage")
    scoped_bundle(db, world, rule(scope="group", group_id=triage))
    requests = targets(admin_engine, world, 6)
    # Three distinct targets between the two members reserve and record the membership.
    for identity, req in zip((first, first, second), requests[:3], strict=True):
        reserved = admit(db, identity, req, clock)
        assert reserved.ticket is not None and reserved.view.state == "DISPATCH_COMMITTED"
        row = retained_attributes(admin_engine, tenant, reserved.view.execution_id)
        assert row["group_ids"] == [str(triage)]
    # The fourth, by either member, escalates on the group rule alone: a development target
    # carries no policy obligation, so the approval names exactly the limit.
    escalated = []
    for identity, req in zip((first, second), requests[3:5], strict=True):
        fourth = admit(db, identity, req, clock)
        escalated.append(fourth)
        assert fourth.ticket is None and fourth.view.state == "PENDING_APPROVAL"
        payload = transition_payload(
            admin_engine, tenant, fourth.view.execution_id, "PENDING_APPROVAL"
        )
        assert payload["obligations"] == ["limit:scoped"]
        snapshot = usage(db, world, identity, fourth.view.execution_id)
        assert snapshot.groups == (triage,) and counted(snapshot) == {"scoped": (0, 3)}
    # An agent outside the group is not in the rule's scope and reserves at once.
    unaffected = admit(db, outsider, requests[5], clock)
    assert unaffected.ticket is not None
    row = retained_attributes(admin_engine, tenant, unaffected.view.execution_id)
    assert row["group_ids"] == []
    outside = usage(db, world, outsider, unaffected.view.execution_id)
    # Not capped, and not charged to the group either: the count is still three.
    assert outside.groups == () and counted(outside) == {"scoped": (0, 3)}
    assert counts(admin_engine, tenant)["execution_impact"] == 4
    # The offline ledger counts the retained membership as the store did: the group's
    # ceiling escalates both members and never reaches the outsider.
    replay = replayed(db, world)
    for admission in escalated:
        [result] = baselines(replay, admission)
        assert result.effect == "REQUIRE_APPROVAL" and result.obligation_ids == ("limit:scoped",)
        assert counted(result) == {"scoped": (0, 3)}
    [result] = baselines(replay, unaffected)
    assert result.effect == "ELIGIBLE" and result.obligation_ids == ()
    assert counted(result) == {"scoped": (0, 3)}


def test_sl2_account_rule_spans_three_identity_actions_and_counts_each_account_apart(
    db, soc_world, admin_engine
):
    world, endpoint = soc_world, soc_world["endpoint"]
    identity, clock, tenant = world["identity"], world["clock"], world["identity"].tenant_id
    # The identity world's two accounts. The SOC bundle is the base because it is the pack that
    # maps both of them (the identity pack maps no endpoint action); its identity policies are
    # the identity pack's, so every development standard identity below is autonomous for
    # disable and revoke_sessions.
    scoped_bundle(
        db,
        world,
        rule(
            rule_id="entra",
            action="identity.disable",
            # The isolation below is in this list too, so only its account keeps it out of
            # the count: the account predicate, not the action filter, is what separates
            # the two accounts.
            actions=(*ACTIONS, "endpoint.isolate"),
            scope="account",
            account_id=world["account"],
            on_exceed="DENY",
        ),
        rule(
            rule_id="crowdstrike", scope="account", account_id=endpoint["account"], on_exceed="DENY"
        ),
        base=world["soc_bundle"],
    )
    actions = (
        "identity.disable",
        "identity.revoke_sessions",
        "identity.disable",
        "identity.revoke_sessions",
    )
    requests = [
        identity_request(add_target(admin_engine, world), action, idempotency_key=str(uuid4()))
        for action in actions
    ]
    reserved = [admit(db, identity, req, clock) for req in requests[:3]]
    assert all(item.ticket is not None for item in reserved)
    # The fourth disruptive action on the account, of any listed action, is a hard denial.
    denied = admit(db, identity, requests[3], clock)
    assert denied.ticket is None and denied.view.state == "DENIED"
    payload = transition_payload(admin_engine, tenant, denied.view.execution_id, "DENIED")
    assert payload["reasons"] == ["HARD_LIMIT:entra"]
    # An isolation on the endpoint account in the same window is neither capped by the
    # identity account's rule nor counted by it; the endpoint account's rule counts it alone.
    [isolation] = targets(admin_engine, endpoint, 1)
    isolated = admit(db, identity, isolation, clock)
    assert isolated.ticket is not None
    snapshot = usage(db, world, identity, reserved[0].view.execution_id)
    assert snapshot.account_id == world["account"]
    assert counted(snapshot) == {"crowdstrike": (0, 1), "entra": (0, 3)}
    for item in reserved:
        row = retained_attributes(admin_engine, tenant, item.view.execution_id)
        assert row["account_id"] == world["account"]
    row = retained_attributes(admin_engine, tenant, isolated.view.execution_id)
    assert row["account_id"] == endpoint["account"]
    still = identity_request(add_target(admin_engine, world), ACTIONS[0], idempotency_key="fifth")
    later = admit(db, identity, still, clock)
    assert later.view.state == "DENIED"
    # The offline ledger counts each account's retained rows apart, whatever the action:
    # the isolation reaches only the endpoint account's rule.
    replay = replayed(db, world)
    [result] = baselines(replay, denied)
    assert result.effect == "DENY" and result.reasons == ("HARD_LIMIT:entra",)
    assert counted(result) == {"crowdstrike": (0, 0), "entra": (0, 3)}
    [result] = baselines(replay, later)
    assert result.reasons == ("HARD_LIMIT:entra",)
    assert counted(result) == {"crowdstrike": (0, 1), "entra": (0, 3)}


def test_sl3_selector_counts_only_production_isolations(db, world, admin_engine):
    """Only production isolations reach the selector rule's count and trigger it.

    Proven with a total budget: the demo pack escalates every production isolation on its
    own policy, and an approved row is exempt from an autonomous budget, so an autonomous
    selector ceiling could never fill here. The autonomous exemption under a selector scope
    is SL8's subject; this scenario proves the scope filter and the trigger.
    """
    tenant, identity, clock = world["identity"].tenant_id, world["identity"], world["clock"]
    scoped_bundle(
        db,
        world,
        rule(
            rule_id="production",
            scope="selector",
            selector=LimitSelector(fact="environment", equals="production"),
            max_targets=2,
        ),
    )
    production = targets(admin_engine, world, 3, production=True)
    development = targets(admin_engine, world, 2)

    def approved(req):
        pending = admit(db, identity, req, clock)
        assert pending.view.state == "PENDING_APPROVAL"
        payload = transition_payload(
            admin_engine, tenant, pending.view.execution_id, "PENDING_APPROVAL"
        )
        assert payload["obligations"] == ["policy:policy0"]
        decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", clock)
        retried = admit(db, identity, req, clock)
        assert retried.ticket is not None
        return retried

    first = approved(production[0])
    between = admit(db, identity, development[0], clock)
    assert between.ticket is not None
    second = approved(production[1])
    # At the ceiling a development isolation is still autonomous: the rule does not apply.
    at_ceiling = admit(db, identity, development[1], clock)
    assert at_ceiling.ticket is not None
    third = admit(db, identity, production[2], clock)
    assert third.ticket is None and third.view.state == "PENDING_APPROVAL"
    payload = transition_payload(admin_engine, tenant, third.view.execution_id, "PENDING_APPROVAL")
    assert payload["obligations"] == ["limit:production", "policy:policy0"]
    # Four rows are retained; the selector counts the two whose retained environment is
    # production and neither development row.
    assert counts(admin_engine, tenant)["execution_impact"] == 4
    assert counted(usage(db, world, identity, third.view.execution_id)) == {"production": (0, 2)}
    for admission, environment in (
        (first, "production"),
        (between, "development"),
        (second, "production"),
        (at_ceiling, "development"),
    ):
        row = retained_attributes(admin_engine, tenant, admission.view.execution_id)
        assert row["facts"]["environment"] == environment
    # The offline ledger matches the retained facts as the store did: the third production
    # isolation escalates on the selector and the development one at the ceiling does not.
    replay = replayed(db, world)
    [result] = baselines(replay, third)
    assert result.obligation_ids == ("limit:production", "policy:policy0")
    assert counted(result) == {"production": (0, 2)}
    [result] = baselines(replay, at_ceiling)
    assert result.effect == "ELIGIBLE" and result.obligation_ids == ()
    assert counted(result) == {"production": (0, 2)}


def test_sl4_multi_action_budget_draws_isolation_and_lift_on_one_counter(
    db, soc_runtime, soc_world, live_provider, admin_engine
):
    world = soc_world
    identity, clock, tenant = world["identity"], world["clock"], world["identity"].tenant_id
    scoped_bundle(
        db,
        world,
        rule(
            rule_id="pair", actions=("endpoint.isolate", "endpoint.lift_isolation"), max_targets=1
        ),
        rule(rule_id="single", max_targets=1),
        base=world["soc_bundle"],
    )
    target = add_endpoint(
        admin_engine, live_provider, world, incident_status="OPEN", contained=False
    )
    isolated = soc_runtime.execute(identity, isolate(target, key="iso-sl4"))
    assert isolated.state == "EXECUTED"
    assert counted(usage(db, world, identity, isolated.execution_id)) == {
        "pair": (1, 0),
        "single": (1, 0),
    }
    sync_version(admin_engine, world, target, live_provider)
    # The settled isolation fills the pair's ceiling, so the lift of the same target
    # escalates on the pair rule alone: the rule without ``actions`` does not cover the lift.
    wire = lift(target, reason="false_positive", key="lift-sl4")
    pending = soc_runtime.execute(identity, wire)
    assert pending.state == "PENDING_APPROVAL"
    payload = transition_payload(admin_engine, tenant, pending.execution_id, "PENDING_APPROVAL")
    assert payload["obligations"] == ["limit:pair"]
    decide_approval(db, world["human"], pending.approval_id, "APPROVE", clock)
    lifted = soc_runtime.execute(identity, wire)
    assert lifted.state == "EXECUTED" and lifted.execution_id == pending.execution_id
    assert impact(admin_engine, world) == 2
    assert live_provider.store.resource(tenant, target["canonical"]).contained is False
    assert counted(usage(db, world, identity, lifted.execution_id)) == {
        "pair": (2, 0),
        "single": (1, 0),
    }


def test_sl5_six_members_on_six_connections_reserve_exactly_the_group_ceiling(
    db, world, admin_engine, owner
):
    tenant, clock = world["identity"].tenant_id, world["clock"]
    members = [agent(admin_engine, db, world) for _ in range(6)]
    squad = group(owner, world, *members, name="squad")
    scoped_bundle(db, world, rule(scope="group", group_id=squad, on_exceed="DENY"))
    requests = targets(admin_engine, world, 6)
    barrier = Barrier(6)

    def submit(index):
        barrier.wait(timeout=10)
        return admit(db, members[index], requests[index], clock)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(submit, range(6)))
    admitted = [item for item in results if item.ticket is not None]
    denied = [item for item in results if item.view.state == "DENIED"]
    assert len(admitted) == 3 and len(denied) == 3
    for item in denied:
        payload = transition_payload(admin_engine, tenant, item.view.execution_id, "DENIED")
        assert payload["reasons"] == ["HARD_LIMIT:scoped"]
    assert counts(admin_engine, tenant)["execution_impact"] == 3
    assert impact_groups(admin_engine, tenant) == {
        item.view.execution_id: [str(squad)] for item in admitted
    }
    # One counter under one fence: settling the three tickets confirms exactly three units,
    # nothing was released twice, and the group is still full for every member.
    for item in admitted:
        assert finish(db, world, item).state == "EXECUTED"
    settled = usage(db, world, members[0], admitted[0].view.execution_id)
    assert counted(settled) == {"scoped": (3, 0)}
    [extra] = targets(admin_engine, world, 1)
    assert admit(db, members[0], extra, clock).view.state == "DENIED"
    assert counts(admin_engine, tenant)["execution_impact"] == 3


def test_sl6_membership_changes_keep_retained_rows_and_move_future_charges(
    db, world, admin_engine, owner
):
    tenant, clock = world["identity"].tenant_id, world["clock"]
    actor = world["admin"].principal_id
    leaver, joiner = agent(admin_engine, db, world), agent(admin_engine, db, world)
    crew = group(owner, world, leaver, name="crew")
    scoped_bundle(db, world, rule(scope="group", group_id=crew))
    requests = targets(admin_engine, world, 5)
    earlier = [admit(db, leaver, req, clock) for req in requests[:2]]
    assert all(item.ticket is not None for item in earlier)
    administration.unassign_group(owner, tenant, crew, leaver.principal_id, actor)
    administration.assign_group(owner, tenant, crew, joiner.principal_id, actor)
    # The newcomer shares the two retained units: its first isolation is the third, and
    # its second escalates.
    before = usage(db, world, joiner, earlier[0].view.execution_id)
    assert before.groups == (crew,) and counted(before) == {"scoped": (0, 2)}
    third = admit(db, joiner, requests[2], clock)
    assert third.ticket is not None
    row = retained_attributes(admin_engine, tenant, third.view.execution_id)
    assert row["group_ids"] == [str(crew)]
    fourth = admit(db, joiner, requests[3], clock)
    assert fourth.ticket is None and fourth.view.state == "PENDING_APPROVAL"
    payload = transition_payload(admin_engine, tenant, fourth.view.execution_id, "PENDING_APPROVAL")
    assert payload["obligations"] == ["limit:scoped"]
    # The removed member is out of scope: its next isolation reserves without the group and
    # is not charged to it, while its earlier rows keep the membership they recorded.
    removed = admit(db, leaver, requests[4], clock)
    assert removed.ticket is not None
    row = retained_attributes(admin_engine, tenant, removed.view.execution_id)
    assert row["group_ids"] == []
    assert usage(db, world, leaver, removed.view.execution_id).groups == ()
    assert counted(usage(db, world, joiner, third.view.execution_id)) == {"scoped": (0, 3)}
    for item in earlier:
        row = retained_attributes(admin_engine, tenant, item.view.execution_id)
        assert row["group_ids"] == [str(crew)]


@pytest.mark.parametrize("fill_before_decision", [False, True])
def test_sl8_approved_candidates_are_exempt_from_autonomous_budgets_in_every_scope(
    db, world, admin_engine, owner, fill_before_decision
):
    tenant, member, clock = world["identity"].tenant_id, world["identity"], world["clock"]
    squad = group(owner, world, member, name="squad")
    # Every scope applies to both the production candidate and the development fill: the
    # same account, the member's group, and both targets are workstations.
    qualifiers = {
        "group": {"group_id": squad},
        "account": {"account_id": world["account"]},
        "selector": {"selector": LimitSelector(fact="role", equals="workstation")},
    }
    scoped_bundle(
        db,
        world,
        *(
            rule(
                rule_id=f"{scope}-{budget}",
                scope=scope,
                budget=budget,
                max_targets=1 if budget == "autonomous" else 10,
                on_exceed="DENY",
                **qualifier,
            )
            for scope, qualifier in qualifiers.items()
            for budget in ("autonomous", "total")
        ),
    )
    autonomous = {f"{scope}-autonomous" for scope in qualifiers}
    total = {f"{scope}-total" for scope in qualifiers}
    pending = admit(db, member, request(world), clock)
    assert pending.view.state == "PENDING_APPROVAL"
    payload = transition_payload(
        admin_engine, tenant, pending.view.execution_id, "PENDING_APPROVAL"
    )
    assert payload["obligations"] == ["policy:policy0"]

    def fill():
        filled = admit(db, member, targets(admin_engine, world, 1)[0], clock)
        assert filled.ticket is not None
        return filled

    if fill_before_decision:
        filled = fill()
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", clock)
    if not fill_before_decision:
        filled = fill()
    before = counted(usage(db, world, member, filled.view.execution_id))
    assert before == dict.fromkeys(autonomous | total, (0, 1))
    # At the hard autonomous threshold of all three scopes the approved retry still executes
    # and adds one unit to each total budget and none to any autonomous budget.
    approved = admit(db, member, request(world), clock)
    assert approved.ticket is not None
    after = counted(usage(db, world, member, approved.view.execution_id))
    assert after == {**dict.fromkeys(autonomous, (0, 1)), **dict.fromkeys(total, (0, 2))}
    # The offline ledger exempts the approved retry from every autonomous budget as the
    # store did: the retried admission saw the fill under all six rules and was eligible.
    # Replayed before settlement: the fixture journal is not a signed provider journal,
    # so a history settled through it cannot pass export verification.
    replay = replayed(db, world)
    escalated, *retried = baselines(replay, approved)
    assert escalated.effect == "REQUIRE_APPROVAL"
    assert escalated.obligation_ids == ("policy:policy0",)
    assert counted(escalated) == dict.fromkeys(autonomous | total, (0, 0))
    # The verified retry records both of its evaluations; each saw the fill under every
    # rule and was eligible with the approval, as the store's snapshot said.
    assert len(retried) == 2
    assert all(result.effect == "ELIGIBLE" for result in retried)
    assert all(counted(result) == before for result in retried)
    for admission in (filled, approved):
        assert finish(db, world, admission).state == "EXECUTED"
    settled = counted(usage(db, world, member, approved.view.execution_id))
    assert settled == {**dict.fromkeys(autonomous, (1, 0)), **dict.fromkeys(total, (2, 0))}
    row = retained_attributes(admin_engine, tenant, approved.view.execution_id)
    assert row["group_ids"] == [str(squad)] and row["facts"]["role"] == "workstation"


def test_sl12_observed_rows_project_group_and_selector_rules_only_in_observe_mode(
    db, world, admin_engine, owner
):
    tenant, member, clock = world["identity"].tenant_id, world["identity"], world["clock"]
    squad = group(owner, world, member, name="squad")
    scoped_bundle(
        db,
        world,
        rule(rule_id="squad", scope="group", group_id=squad, max_targets=2),
        rule(
            rule_id="production",
            scope="selector",
            selector=LimitSelector(fact="environment", equals="production"),
            max_targets=1,
        ),
    )
    observe(db, world)
    development = targets(admin_engine, world, 3)
    production = targets(admin_engine, world, 2, production=True)
    views = [admit(db, member, req, clock).view for req in (*development, *production)]
    assert all(view.state == "OBSERVED" for view in views)
    # The third observed isolation reaches the group ceiling; the second production one
    # reaches the selector ceiling as well, beside the pack's production policy.
    assert [view.observed.effect for view in views] == ["ELIGIBLE"] * 2 + ["REQUIRE_APPROVAL"] * 3
    assert [view.observed.obligation_ids for view in views] == [
        (),
        (),
        ("limit:squad",),
        ("limit:squad", "policy:policy0"),
        ("limit:production", "limit:squad", "policy:policy0"),
    ]
    environments = ["development"] * 3 + ["production"] * 2
    for view, environment in zip(views, environments, strict=True):
        row = retained_attributes(admin_engine, tenant, view.execution_id)
        assert row["account_id"] == world["account"] and row["group_ids"] == [str(squad)]
        assert row["facts"]["environment"] == environment
    assert (
        sorted(impacts(admin_engine, tenant))
        == [("OBSERVED", False)] * 2 + [("OBSERVED", True)] * 3
    )
    projected = usage(db, world, member, views[-1].execution_id, observed=True)
    enforced = usage(db, world, member, views[-1].execution_id)
    assert projected.groups == enforced.groups == (squad,)
    assert counted(projected) == {"production": (2, 0), "squad": (5, 0)}
    assert counted(enforced) == {"production": (0, 0), "squad": (0, 0)}
    # Enforcement ignores the observed rows: the group is not full for the member.
    observe(db, world, "ENFORCE", "Go live")
    [fresh] = targets(admin_engine, world, 1)
    assert admit(db, member, fresh, clock).ticket is not None


def test_membership_beyond_the_bound_fails_admission_closed(db, world, admin_engine):
    tenant, identity, clock = world["identity"].tenant_id, world["identity"], world["clock"]
    with admin_engine.begin() as conn:
        for index in range(MAX_GROUPS + 1):
            params = {
                "t": tenant,
                "g": uuid4(),
                "p": identity.principal_id,
                "n": clock.now(),
                "name": f"group-{index:02d}",
            }
            conn.execute(
                text(
                    "INSERT INTO execbound.principal_groups "
                    "(tenant_id, group_id, name, created_at) VALUES (:t, :g, :name, :n)"
                ),
                params,
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.principal_group_members "
                    "(tenant_id, group_id, principal_id, assigned_at) VALUES (:t, :g, :p, :n)"
                ),
                params,
            )
    [req] = targets(admin_engine, world, 1)
    with pytest.raises(ExecutionError) as caught:
        admit(db, identity, req, clock)
    # Answered as every refusal that names nothing; the audit keeps the cause (T1.17).
    assert caught.value.code == "EXECUTION_UNAVAILABLE"
    rejected = audit_payloads(admin_engine, tenant, "execution.rejected")
    assert rejected[-1]["operation"] == "admit"
    assert rejected[-1]["reason"] == "INVALID_CONFIGURATION"
    # Nothing of the refused admission survives the rollback.
    rows = counts(admin_engine, tenant)
    assert rows["executions"] == 0 and rows["execution_impact"] == 0


# Two tenants against one ceiling each (#155): the two-tenant budget scenario. The `registry`
# fixture seeds both tenants with the same account, sources and mapping; `peer` gives the second
# the people and bundle `world` gives the first, on the account and sources read from the second
# tenant's own rows, and `shared_targets` gives both the very same endpoints, so every
# identifier a request names, its idempotency key included, collides across the two.


def peer(db, admin_engine, seeded, world):
    """The other seeded tenant, set up as `world` sets up its own: an administrator, an
    approver, its seeded agent, and the endpoint bundle `world` starts from, on the account
    and context sources read from that tenant's own rows, and the same mapping version."""
    other = next(tenant for tenant in seeded["tenants"] if tenant != world["identity"].tenant_id)
    now = world["clock"].now()
    with admin_engine.connect() as conn:
        account = conn.execute(
            text(
                "SELECT account_id FROM execbound.connector_accounts "
                "WHERE tenant_id = :t AND provider = 'mock_crowdstrike'"
            ),
            {"t": other},
        ).scalar_one()
        sources = dict(
            conn.execute(
                text(
                    "SELECT kind, source_id FROM execbound.context_sources "
                    "WHERE tenant_id = :t AND account_id = :a"
                ),
                {"t": other, "a": account},
            ).all()
        )
    return {
        **world,
        "identity": authenticate(db, seeded["tokens"][seeded["tenants"].index(other)]),
        "admin": provision_identity(admin_engine, db, other, "ADMIN", now),
        "human": provision_identity(admin_engine, db, other, "HUMAN_APPROVER", now),
        "account": account,
        "inventory": sources["inventory"],
        "incident_source": sources["incident"],
        "bundle": endpoint_bundle(other, account, mapping_version="map-v1"),
        "canonical": None,
    }


def shared_targets(engine, worlds, count):
    """`count` development endpoints every world's tenant holds under the very same ids, on
    the account they share: resource, canonical target, incident and hostname alias. Returns
    the one request for each, which every tenant sends byte for byte."""
    requests = []
    with engine.begin() as conn:
        for index in range(count):
            ids = {"r": uuid4(), "i": uuid4(), "c": uuid4(), "alias": uuid4()}
            host = f"shared-{index:02d}-{ids['r'].hex[:8]}.example"
            for each in worlds:
                p = {
                    **ids,
                    "t": each["identity"].tenant_id,
                    "a": each["account"],
                    "s": each["inventory"],
                    "z": each["incident_source"],
                    "n": each["clock"].now(),
                    "e": each["clock"].now() + timedelta(days=1),
                    "host": host,
                }
                conn.execute(text("INSERT INTO execbound.canonical_targets VALUES (:t,:c,:n)"), p)
                conn.execute(
                    text(
                        "INSERT INTO execbound.resources "
                        "(tenant_id,account_id,provider,resource_type,resource_id,provider_id,"
                        "version,source_id,role,environment,criticality,observed_at) "
                        "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,CAST(:r AS text),"
                        "'v1',:s,'workstation','development',2,:n)"
                    ),
                    p,
                )
                conn.execute(
                    text(
                        "INSERT INTO execbound.resource_identities "
                        "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:c)"
                    ),
                    p,
                )
                conn.execute(
                    text(
                        "INSERT INTO execbound.resource_aliases "
                        "(tenant_id,alias_id,account_id,provider,resource_type,kind,"
                        "normalized_value,resource_id,valid_from,expires_at) "
                        "VALUES (:t,:alias,:a,'mock_crowdstrike','endpoint','hostname',:host,"
                        ":r,:n,:e)"
                    ),
                    p,
                )
                conn.execute(
                    text(
                        "INSERT INTO execbound.incidents "
                        "(tenant_id,account_id,provider,resource_type,incident_id,resource_id,"
                        "source_id,version,status,severity,observed_at) "
                        "VALUES (:t,:a,'mock_crowdstrike','endpoint',:i,:r,:z,'v1',"
                        "'OPEN','CRITICAL',:n)"
                    ),
                    p,
                )
            requests.append(
                request(
                    worlds[0],
                    target={"kind": "hostname", "value": host},
                    claimed_context={"incident_id": str(ids["i"])},
                    idempotency_key=f"shared-{index}",
                )
            )
    return requests


def ceilings():
    """A ceiling of two on the account both tenants name, and one of two on the whole tenant:
    each would be one counter if a tenant boundary failed to divide it."""
    return (
        rule(
            rule_id="account",
            scope="account",
            account_id=UUID(int=10),
            max_targets=2,
            on_exceed="DENY",
        ),
        rule(rule_id="tenant", scope="tenant", max_targets=2, on_exceed="DENY"),
    )


def test_a_tenant_at_its_ceiling_leaves_another_tenants_identical_ceiling_untouched(
    db, world, admin_engine, seeded
):
    other = peer(db, admin_engine, seeded, world)
    first, second, clock = world["identity"], other["identity"], world["clock"]
    # Each tenant's own connector account carries the one id both ceilings name.
    assert world["account"] == other["account"] == UUID(int=10)
    for each in (world, other):
        scoped_bundle(db, each, *ceilings())
    requests = shared_targets(admin_engine, (world, other), 3)
    # The first tenant spends both ceilings, and its third isolation is denied by each.
    spent = [admit(db, first, req, clock) for req in requests[:2]]
    assert all(item.ticket is not None for item in spent)
    refused = admit(db, first, requests[2], clock)
    assert refused.ticket is None and refused.view.state == "DENIED"
    payload = transition_payload(admin_engine, first.tenant_id, refused.view.execution_id, "DENIED")
    assert sorted(payload["reasons"]) == ["HARD_LIMIT:account", "HARD_LIMIT:tenant"]
    full = {"account": (0, 2), "tenant": (0, 2)}
    assert counted(usage(db, world, first, spent[-1].view.execution_id)) == full
    # None of it reached the second tenant: no execution, no impact, no claim.
    untouched = counts(admin_engine, second.tenant_id)
    assert untouched["executions"] == untouched["execution_impact"] == 0
    assert untouched["resource_claims"] == 0
    # The second tenant sends the very same requests, and its projection starts from zero:
    # the first tenant's two reservations count nowhere in it.
    theirs = admit(db, second, requests[0], clock)
    assert theirs.ticket is not None and theirs.view.state == "DISPATCH_COMMITTED"
    projected = counted(usage(db, other, second, theirs.view.execution_id))
    assert projected == {"account": (0, 1), "tenant": (0, 1)}
    assert admit(db, second, requests[1], clock).ticket is not None
    denied = admit(db, second, requests[2], clock)
    assert denied.view.state == "DENIED"
    reasons = transition_payload(admin_engine, second.tenant_id, denied.view.execution_id, "DENIED")
    assert sorted(reasons["reasons"]) == ["HARD_LIMIT:account", "HARD_LIMIT:tenant"]
    # And nothing the second tenant did moved the first's counters.
    assert counted(usage(db, world, first, spent[-1].view.execution_id)) == full
    for tenant in (first.tenant_id, second.tenant_id):
        rows = counts(admin_engine, tenant)
        assert (rows["executions"], rows["execution_impact"], rows["resource_claims"]) == (3, 2, 2)


def test_two_tenants_racing_on_the_same_ids_each_reserve_exactly_their_own_ceiling(
    db, world, admin_engine, seeded
):
    other = peer(db, admin_engine, seeded, world)
    clock = world["clock"]
    assert world["account"] == other["account"] == UUID(int=10)
    for each in (world, other):
        scoped_bundle(db, each, *ceilings())
    requests = shared_targets(admin_engine, (world, other), 3)
    senders = [world["identity"]] * 3 + [other["identity"]] * 3
    barrier = Barrier(6)

    def submit(index):
        barrier.wait(timeout=10)
        return admit(db, senders[index], requests[index % 3], clock)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(submit, range(6)))
    # One counter per tenant: each reserves exactly its own two, where one shared counter
    # would have admitted two in all.
    for each, chunk in ((world, results[:3]), (other, results[3:])):
        tenant = each["identity"].tenant_id
        admitted = [item for item in chunk if item.ticket is not None]
        denied = [item for item in chunk if item.view.state == "DENIED"]
        assert len(admitted) == 2 and len(denied) == 1
        payload = transition_payload(admin_engine, tenant, denied[0].view.execution_id, "DENIED")
        assert sorted(payload["reasons"]) == ["HARD_LIMIT:account", "HARD_LIMIT:tenant"]
        assert counts(admin_engine, tenant)["execution_impact"] == 2
        snapshot = usage(db, each, each["identity"], admitted[0].view.execution_id)
        assert counted(snapshot) == {"account": (0, 2), "tenant": (0, 2)}
