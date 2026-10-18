# SPDX-License-Identifier: AGPL-3.0-only
"""One Space's setup steps, each read from the record that satisfies it (#678).

`getting_started.setup_state` answers five steps for one Space: a selected policy, an agent
holding a live API key, the first request, someone able to review an action the policy maps,
and the first decided approval. Three are current state and un-tick when their record stops
holding; two are the earliest record and stay done. Nothing here is a counter: every value is
read at request time, and another Space's records tick nothing.
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sample_fixtures import agent_identity, empty_workspace, person
from sample_fixtures import sample_key as sample_key
from space_fixtures import make_space, place, unseat
from sqlalchemy import text
from test_console_api_samples import ask, by_effect, fenced

from execbound import administration, samples
from execbound.execution import decide_approval, store
from execbound.execution.modes import set_enforcement_mode
from execbound.getting_started import SETUP_KEYS, setup_state
from execbound.policy.models import MappingRef
from execbound.policy.rulesets import Ruleset, ruleset_bundle
from execbound.policy.store import activate_new_bundle
from execbound.resolution.models import SystemClock

pytestmark = pytest.mark.integration


def read(db, tenant, space, *, now=None, observing=False):
    with db.transaction(tenant) as conn:
        return setup_state(conn, tenant, space, now=now or datetime.now(UTC), observing=observing)


def states(found):
    return {item.key: item.state for item in found.milestones}


def milestone(found, key):
    return next(item for item in found.milestones if item.key == key)


def owner(admin_engine, tenant, statement, params):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(text(statement), {"t": tenant, **params})


def sample_account(admin_engine, tenant) -> UUID:
    return UUID(
        str(
            owner(
                admin_engine,
                tenant,
                "SELECT account_id FROM execbound.connector_accounts "
                "WHERE tenant_id = :t AND sample",
                {},
            ).scalar_one()
        )
    )


def replace_policy(db, admin_engine, workspace, ruleset: Ruleset):
    """Select a new bundle over the sample mapping in the default Space, compiled from
    `ruleset`, in place of the starter."""
    account = sample_account(admin_engine, workspace.tenant_id)
    owner(
        admin_engine,
        workspace.tenant_id,
        "DELETE FROM execbound.space_policy_selection WHERE tenant_id = :t AND space_id = :s",
        {"s": workspace.space_id},
    )
    starter = samples.starter_bundle(workspace.tenant_id, account)
    mapping = MappingRef.model_validate(starter.mappings[0].model_dump())
    content = ruleset_bundle(
        ruleset,
        tenant_id=workspace.tenant_id,
        bundle_id=uuid4(),
        mappings=(mapping,),
        context_settings=ruleset.context,
    )
    clock = SystemClock()
    with db.transaction(workspace.tenant_id) as conn:
        store.fence(conn, workspace.tenant_id, clock)
        activate_new_bundle(conn, workspace.admin, content, clock, space=workspace.space_id)
    return content.bundle_id


def starter_without(*, review_rule: bool, approval_budget: bool) -> Ruleset:
    document = json.loads(samples.starter_ruleset().model_dump_json())
    if not review_rule:
        document["rules"] = [rule for rule in document["rules"] if rule["effect"] != "REVIEW"]
    if not approval_budget:
        for budget in document["budgets"]:
            budget["on_exceed"] = "DENY"
    return Ruleset.model_validate_json(json.dumps(document))


def decide_held(db, admin_engine, workspace, installed, key="sample-prod"):
    agent = agent_identity(admin_engine, db, workspace)
    held = ask(db, agent, by_effect(installed)["require approval"], key)
    assert held.view.state == "PENDING_APPROVAL"
    return held, agent


def test_an_empty_space_has_every_milestone_to_do_and_no_connection(db, admin_engine, seeded):
    workspace = empty_workspace(admin_engine, db)
    found = read(db, workspace.tenant_id, workspace.space_id)
    assert found.connected is False
    assert [item.key for item in found.milestones] == list(SETUP_KEYS)
    assert all(item.state == "todo" and item.record_id is None for item in found.milestones)
    assert found.observed is None and found.observed_since is None


def test_samples_tick_the_policy_and_the_reviewer_from_their_records(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    samples.install(db, workspace.admin, available=True)
    account = sample_account(admin_engine, workspace.tenant_id)
    changed_at = owner(
        admin_engine,
        workspace.tenant_id,
        "SELECT changed_at FROM execbound.space_policy_selection "
        "WHERE tenant_id = :t AND space_id = :s",
        {"s": workspace.space_id},
    ).scalar_one()
    found = read(db, workspace.tenant_id, workspace.space_id)
    assert found.connected is True
    policy = milestone(found, "policy")
    assert (policy.state, policy.record_kind) == ("done", "bundle")
    assert policy.record_id == samples.starter_bundle_id(workspace.tenant_id, account)
    assert policy.at == changed_at
    reviewer = milestone(found, "reviewer")
    assert (reviewer.state, reviewer.record_kind, reviewer.record_id) == (
        "done",
        "approver",
        workspace.admin.principal_id,
    )
    assert reviewer.at is None
    assert states(found) == {
        "policy": "done",
        "agent_key": "todo",
        "first_request": "todo",
        "reviewer": "done",
        "first_decision": "todo",
    }


def test_a_live_agent_key_ticks_and_a_revoked_or_expired_one_does_not(db, admin_engine, seeded):
    workspace = empty_workspace(admin_engine, db)
    agent = agent_identity(admin_engine, db, workspace)
    issued_at = owner(
        admin_engine,
        workspace.tenant_id,
        "SELECT issued_at FROM execbound.credentials WHERE tenant_id = :t AND credential_id = :c",
        {"c": agent.credential_id},
    ).scalar_one()
    key = milestone(read(db, workspace.tenant_id, workspace.space_id), "agent_key")
    assert (key.state, key.record_kind, key.record_id, key.at) == (
        "done",
        "agent",
        agent.principal_id,
        issued_at,
    )
    # The same key, read after it has expired on the clock.
    later = datetime.now(UTC) + timedelta(hours=3)
    assert (
        milestone(read(db, workspace.tenant_id, workspace.space_id, now=later), "agent_key").state
        == "todo"
    )
    # Revoked through the administration function the CLI calls.
    administration.revoke_credential(
        admin_engine, workspace.tenant_id, agent.credential_id, workspace.admin.principal_id
    )
    assert milestone(read(db, workspace.tenant_id, workspace.space_id), "agent_key").state == "todo"
    # A deactivated agent with a live key does not count.
    other = agent_identity(admin_engine, db, workspace)
    assert milestone(read(db, workspace.tenant_id, workspace.space_id), "agent_key").state == "done"
    owner(
        admin_engine,
        workspace.tenant_id,
        "UPDATE execbound.principals SET active = false WHERE tenant_id = :t AND principal_id = :p",
        {"p": other.principal_id},
    )
    assert milestone(read(db, workspace.tenant_id, workspace.space_id), "agent_key").state == "todo"


def test_records_in_another_space_tick_nothing_here(db, admin_engine, seeded, sample_key):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    asked = ask(db, agent, by_effect(installed)["deny"], "sample-dc")
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        second = make_space(conn, workspace.tenant_id, "Customer B")
        place(conn, workspace.tenant_id, "principals", "principal_id", agent.principal_id, second)
        place(
            conn, workspace.tenant_id, "executions", "execution_id", asked.view.execution_id, second
        )
    here = states(read(db, workspace.tenant_id, workspace.space_id))
    there = states(read(db, workspace.tenant_id, second))
    assert (here["agent_key"], here["first_request"]) == ("todo", "todo")
    assert (there["agent_key"], there["first_request"]) == ("done", "done")


def test_the_first_request_is_the_earliest_execution_and_stays_done(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    first = ask(db, agent, by_effect(installed)["deny"], "sample-dc")
    ask(db, agent, by_effect(installed)["allow"], "sample-dev")
    row = owner(
        admin_engine,
        workspace.tenant_id,
        "SELECT created_at, request_number FROM execbound.executions "
        "WHERE tenant_id = :t AND execution_id = :e",
        {"e": first.view.execution_id},
    ).one()
    found = milestone(read(db, workspace.tenant_id, workspace.space_id), "first_request")
    assert (found.state, found.record_kind, found.record_id) == (
        "done",
        "execution",
        first.view.execution_id,
    )
    assert found.request_ref == f"EB-{row.request_number}"
    assert found.at == row.created_at
    owner(
        admin_engine,
        workspace.tenant_id,
        "UPDATE execbound.principals SET active = false WHERE tenant_id = :t AND principal_id = :p",
        {"p": agent.principal_id},
    )
    after = read(db, workspace.tenant_id, workspace.space_id)
    assert milestone(after, "first_request") == found
    assert milestone(after, "agent_key").state == "todo"


def test_a_decided_approval_ticks_the_first_decision_and_a_pending_one_does_not(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    held, _ = decide_held(db, admin_engine, workspace, installed)
    assert (
        milestone(read(db, workspace.tenant_id, workspace.space_id), "first_decision").state
        == "todo"
    )
    decide_approval(db, workspace.admin, held.view.approval_id, "DENY", SystemClock())
    row = owner(
        admin_engine,
        workspace.tenant_id,
        "SELECT a.decided_at, e.request_number FROM execbound.approvals a "
        "JOIN execbound.executions e USING (tenant_id, execution_id) "
        "WHERE a.tenant_id = :t AND a.approval_id = :a",
        {"a": held.view.approval_id},
    ).one()
    decision = milestone(read(db, workspace.tenant_id, workspace.space_id), "first_decision")
    assert (decision.state, decision.record_kind, decision.record_id) == (
        "done",
        "execution",
        held.view.execution_id,
    )
    assert decision.request_ref == f"EB-{row.request_number}"
    assert decision.at == row.decided_at


def test_a_policy_that_holds_nothing_for_review_makes_review_not_applicable(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    samples.install(db, workspace.admin, available=True)
    bundle = replace_policy(
        db, admin_engine, workspace, starter_without(review_rule=False, approval_budget=False)
    )
    found = read(db, workspace.tenant_id, workspace.space_id)
    assert milestone(found, "policy").record_id == bundle
    assert (states(found)["reviewer"], states(found)["first_decision"]) == (
        "not_applicable",
        "not_applicable",
    )


def test_a_limit_that_requires_approval_keeps_review_applicable(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    samples.install(db, workspace.admin, available=True)
    replace_policy(
        db, admin_engine, workspace, starter_without(review_rule=False, approval_budget=True)
    )
    # Nobody may decide the mapped action any more, so the step is owed and not done.
    owner(
        admin_engine,
        workspace.tenant_id,
        "UPDATE execbound.approval_scopes SET active = false WHERE tenant_id = :t",
        {},
    )
    found = read(db, workspace.tenant_id, workspace.space_id)
    assert (states(found)["reviewer"], states(found)["first_decision"]) == ("todo", "todo")
    assert sum(1 for item in found.milestones if item.state != "not_applicable") == 5


def test_samples_tick_nothing_outside_the_default_space(db, admin_engine, seeded, sample_key):
    workspace = empty_workspace(admin_engine, db)
    samples.install(db, workspace.admin, available=True)
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        second = make_space(conn, workspace.tenant_id, "Customer B")
    found = read(db, workspace.tenant_id, second)
    assert found.connected is False
    assert (states(found)["policy"], states(found)["reviewer"]) == ("todo", "todo")


def test_observing_with_no_decision_leaves_the_first_decision_needing_enforcing(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    set_enforcement_mode(db, workspace.admin, "OBSERVE", "Pilot")
    found = read(db, workspace.tenant_id, workspace.space_id, observing=True)
    assert milestone(found, "first_decision").state == "needs_enforcing"
    # Back to Enforcing, a request held and decided, then observing again: it stays done.
    set_enforcement_mode(db, workspace.admin, "ENFORCE", "Pilot over")
    held, _ = decide_held(db, admin_engine, workspace, installed)
    decide_approval(db, workspace.admin, held.view.approval_id, "DENY", SystemClock())
    set_enforcement_mode(db, workspace.admin, "OBSERVE", "Pilot again")
    again = read(db, workspace.tenant_id, workspace.space_id, observing=True)
    assert milestone(again, "first_decision").state == "done"


def test_a_reviewer_must_decide_an_action_the_active_policy_maps(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    host = by_effect(installed)["require approval"]
    tenant, space = workspace.tenant_id, workspace.space_id
    owner(
        admin_engine,
        tenant,
        "UPDATE execbound.approval_scopes SET active = false WHERE tenant_id = :t",
        {},
    )
    assert states(read(db, tenant, space))["reviewer"] == "todo"
    approver = person(admin_engine, db, workspace)
    # A scope on an action the selected bundle does not map.
    owner(
        admin_engine,
        tenant,
        "INSERT INTO execbound.approval_scopes(tenant_id, approver_id, canonical_target_id, "
        "action, space_id) VALUES (:t, :p, :c, 'endpoint.lift_isolation', :s)",
        {"p": approver.principal_id, "c": host.canonical_target_id, "s": space},
    )
    assert states(read(db, tenant, space))["reviewer"] == "todo"
    # A scope on the mapped action, held by someone without `approvals.decide` in this Space.
    outsider = person(admin_engine, db, workspace)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        unseat(conn, tenant, space, outsider.principal_id)
    owner(
        admin_engine,
        tenant,
        "INSERT INTO execbound.approval_scopes(tenant_id, approver_id, canonical_target_id, "
        "action, space_id) VALUES (:t, :p, :c, 'endpoint.isolate', :s)",
        {"p": outsider.principal_id, "c": host.canonical_target_id, "s": space},
    )
    assert states(read(db, tenant, space))["reviewer"] == "todo"
    # Through an approval rule's group, on the mapped action.
    group, rule = uuid4(), uuid4()
    values = {
        "g": group,
        "r": rule,
        "p": approver.principal_id,
        "s": space,
        "c": host.canonical_target_id,
    }
    for statement in (
        "INSERT INTO execbound.access_groups(tenant_id, group_id, name) "
        "VALUES (:t, :g, 'Responders')",
        "INSERT INTO execbound.access_group_members(tenant_id, group_id, principal_id) "
        "VALUES (:t, :g, :p)",
        "INSERT INTO execbound.approval_rules(tenant_id, rule_id, name, space_id, group_id) "
        "VALUES (:t, :r, 'Endpoint response', :s, :g)",
        "INSERT INTO execbound.approval_rule_actions(tenant_id, rule_id, action) "
        "VALUES (:t, :r, 'endpoint.isolate')",
        "INSERT INTO execbound.approval_rule_targets(tenant_id, rule_id, canonical_target_id) "
        "VALUES (:t, :r, :c)",
    ):
        owner(admin_engine, tenant, statement, values)
    reviewer = milestone(read(db, tenant, space), "reviewer")
    assert (reviewer.state, reviewer.record_id) == ("done", approver.principal_id)


def test_observed_decisions_are_counted_by_effect_for_seven_days_in_this_space(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    set_enforcement_mode(db, workspace.admin, "OBSERVE", "Pilot")
    agent = agent_identity(admin_engine, db, workspace)
    hosts = by_effect(installed)
    for effect, key in (("allow", "dev"), ("deny", "dc"), ("require approval", "prod")):
        assert ask(db, agent, hosts[effect], f"observe-{key}").view.state == "OBSERVED"
    moved = ask(db, agent, hosts["deny"], "observe-moved")
    older = ask(db, agent, hosts["allow"], "observe-older")
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        second = make_space(conn, workspace.tenant_id, "Customer B")
        place(
            conn, workspace.tenant_id, "executions", "execution_id", moved.view.execution_id, second
        )
        conn.execute(
            text(
                "UPDATE execbound.executions SET created_at = now() - interval '8 days' "
                "WHERE tenant_id = :t AND execution_id = :e"
            ),
            {"t": workspace.tenant_id, "e": older.view.execution_id},
        )
    now = datetime.now(UTC)
    found = read(db, workspace.tenant_id, workspace.space_id, now=now, observing=True)
    assert found.observed == {"eligible": 1, "held": 1, "denied": 1}
    assert found.observed_since == now - timedelta(days=7)
    assert read(db, workspace.tenant_id, workspace.space_id).observed is None


def test_the_read_writes_nothing(db, admin_engine, seeded, sample_key):
    workspace = empty_workspace(admin_engine, db)
    samples.install(db, workspace.admin, available=True)

    def head():
        return owner(
            admin_engine,
            workspace.tenant_id,
            "SELECT sequence FROM execbound.audit_heads WHERE tenant_id = :t",
            {},
        ).scalar_one()

    before = head()
    read(db, workspace.tenant_id, workspace.space_id, observing=True)
    assert head() == before
