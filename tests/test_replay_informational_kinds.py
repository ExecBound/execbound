# SPDX-License-Identifier: AGPL-3.0-only
"""Audit kinds that decide nothing leave every later decision replayable.

`agent.bound`, `agent.unbound`, `policy.rules_changed` and `tenant.assistant_changed` were
neither informational to replay nor handled by it, so a tenant holding one replayed every
later decision `UNRESOLVED` with `INCOMPLETE_PRIOR_HISTORY`, and kept doing so, because the
chain is append-only. Each test writes its kind through the product's own path, then makes
one decision, exports the history and requires a complete replay that reproduces it.
"""

from console_api_fixtures import API, console_client, console_config
from monitoring_fixtures import collect
from sqlalchemy import text
from test_assistant_loop import answer
from test_console_api_monitoring import seed_tines
from test_console_api_rules import ruleset_draft
from test_emergency_stop import audit
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_scout_run import agent, detailed_scenario

from execbound.assistant.client import ScriptedTransport
from execbound.assistant.config import AssistantConfig
from execbound.assistant.turns import set_tenant_switch
from execbound.execution import admit, decide_approval
from execbound.monitoring import store as monitor_store
from execbound.policy.store import change_draft_rules
from execbound.provider.gateway import dispatch_owned
from execbound.replay.export import export_history
from execbound.replay.simulate import simulate
from execbound.replay.verify import verify_export
from execbound.surfaces.sessions import issue_session, load_session
from execbound_harness.demo import ENDPOINT_RULESET


def decided_and_replayed(db, world, connector) -> None:
    """One executed decision after the event, then a complete replay that reproduces it."""
    body = request(world)
    admission = admit(db, world["identity"], body, world["clock"])
    if admission.view.state == "PENDING_APPROVAL":
        decide_approval(db, world["human"], admission.view.approval_id, "APPROVE", world["clock"])
        admission = admit(db, world["identity"], body, world["clock"])
    assert admission.ticket is not None
    assert dispatch_owned(db, admission.ticket, connector, world["clock"]).state == "EXECUTED"
    history = export_history(db, world["admin"], world["clock"])
    verified = verify_export(history, history.head)
    assert "UNKNOWN_EVENT_SEMANTICS" not in verified.issues
    report = simulate(verified)
    assert report.complete, report.issues
    decision = report.decisions[-1]
    assert decision.execution_id == admission.view.execution_id
    assert decision.baseline.effect == decision.recorded_effect
    assert decision.baseline.outcome == "EXECUTED"


def test_a_bound_and_unbound_agent_leave_every_later_decision_replayable(
    db, world, live_provider, connector, admin_engine
):
    """Binding a discovered agent to a governed principal links Monitoring's record to it.
    Only Monitoring and the Agents pages read a binding; no admission does."""
    tenant, admin = world["identity"].tenant_id, world["admin"]
    connection = collect(db, admin, world["clock"], scenario=detailed_scenario(agents=[agent(1)]))
    with db.transaction(tenant) as conn:
        [platform] = conn.execute(
            text("SELECT platform_ref FROM execbound.monitor_agents")
        ).scalars()
    link = {"connection_id": connection, "platform_ref": platform, "clock": world["clock"]}
    monitor_store.link_agent(db, admin, principal_id=world["identity"].principal_id, **link)
    monitor_store.link_agent(db, admin, principal_id=None, **link)
    assert len(audit(admin_engine, tenant, "agent.bound")) == 1
    assert len(audit(admin_engine, tenant, "agent.unbound")) == 1
    decided_and_replayed(db, world, connector)


def test_a_draft_s_changed_rules_leave_every_later_decision_replayable(
    db, world, live_provider, connector, admin_engine
):
    """A rules change retires one draft and writes its successor; both lifecycle events were
    already informational, and a draft decides nothing until it is validated and selected."""
    draft = ruleset_draft(db, world)
    rules = ENDPOINT_RULESET.model_copy(update={"rules": ENDPOINT_RULESET.rules[:2]})
    change_draft_rules(db, world["admin"], draft, rules, world["clock"])
    [changed] = audit(admin_engine, world["identity"].tenant_id, "policy.rules_changed")
    assert changed["supersedes"] == str(draft)
    decided_and_replayed(db, world, connector)


def test_the_assistant_switch_leaves_every_later_decision_replayable(
    db, world, live_provider, connector, admin_engine
):
    """The assistant reads through the asking person's session and writes nothing, so turning
    it on or off changes only whether a person can ask it something."""
    set_tenant_switch(db, world["admin"], True, "Trying the assistant", world["clock"])
    set_tenant_switch(db, world["admin"], False, "Done trying it", world["clock"])
    assert len(audit(admin_engine, world["identity"].tenant_id, "tenant.assistant_changed")) == 2
    decided_and_replayed(db, world, connector)


def test_the_assistant_s_own_events_leave_every_later_decision_replayable(
    db, runtime, world, live_provider, connector, admin_engine
):
    """A question answered (`assistant.asked`), an explanation opened (`assistant.explained`)
    and a turn the model could not finish (`assistant.refused`). The assistant reads through the
    asking person's session and writes nothing, so none of them decides anything; they were
    written through named constants, which the hosted guard counts rather than reads, and so
    no check noticed that replay knew none of them."""
    tenant = world["identity"].tenant_id
    runtime.assistant = AssistantConfig(api_key="replay-test-key")
    runtime.assistant_transport = ScriptedTransport([answer(("Nothing is waiting.", []))])
    set_tenant_switch(db, world["admin"], True, "Trying the assistant", world["clock"])
    turns = API + "/assistant/turns"
    config = console_config(assistant_enabled=True)
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as console:
        asked = console.post(turns, {"question": "What is waiting for a decision?"})
        assert asked.status_code == 200, asked.text
        turn = asked.json()["turn_id"]
        assert console.get(f"{turns}/{turn}").json()["state"] == "COMPLETED"
        assert console.post(f"{turns}/{turn}/opened").status_code == 200
        # Nothing scripted: the model call fails and the turn ends refused.
        runtime.assistant_transport = ScriptedTransport([])
        refused = console.post(turns, {"question": "And after that?"})
        assert refused.status_code == 200, refused.text
    for kind in ("assistant.asked", "assistant.explained", "assistant.refused"):
        assert audit(admin_engine, tenant, kind), kind
    decided_and_replayed(db, world, connector)


def test_an_acknowledged_finding_leaves_every_later_decision_replayable(
    db, world, live_provider, connector, admin_engine
):
    """Acknowledging a monitoring finding is an administrator's decision about the finding
    (acceptance MQ2). No admission reads it, so it is informational to replay."""
    tenant, clock = world["identity"].tenant_id, world["clock"]
    seed_tines(db, world)
    with db.transaction(tenant) as conn:
        finding = conn.execute(
            text(
                "SELECT finding_id FROM execbound.monitor_findings "
                "WHERE acknowledged_at IS NULL ORDER BY created_at, finding_id LIMIT 1"
            )
        ).scalar_one()
    session = load_session(db, issue_session(db, world["admin"], clock=clock).token, clock=clock)
    monitor_store.acknowledge(db, session, finding, clock=clock)
    assert len(audit(admin_engine, tenant, "monitor.finding_acknowledged")) == 1
    decided_and_replayed(db, world, connector)


def test_monitoring_connection_changes_leave_every_later_decision_replayable(
    db, world, live_provider, connector, admin_engine, tmp_path
):
    """A monitoring connection created, re-keyed, asked for, rescheduled and revoked appends
    one event each (acceptance MC12). No admission reads a connection, so each is
    informational to replay, and the export carrying them passes its secret check."""
    from execbound.monitoring import connect, sealing

    tenant, clock = world["identity"].tenant_id, world["clock"]
    public = sealing.generate(tmp_path / "collector")
    session = load_session(db, issue_session(db, world["admin"], clock=clock).token, clock=clock)
    connection = connect.create_sealed_connection(
        db,
        session,
        label="Synthetic Tines tenant",
        base_url="https://fixture.tines.com",
        team_id=None,
        api_key="SENTINEL-replay-key",
        public=public,
        clock=clock,
    )
    connect.replace_sealed_key(
        db, session, connection, api_key="SENTINEL-replay-key-2", public=public, clock=clock
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET collect_requested_at = NULL, "
                "collect_requested_by = NULL WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": tenant, "c": connection},
        )
    connect.request_collection(db, session, connection, clock=clock)
    connect.set_schedule(db, session, connection, collect=None, activity=600, clock=clock)
    connect.revoke_connection(db, session, connection, clock=clock)
    for kind in (
        "monitor.connection_created",
        "monitor.key_replaced",
        "monitor.collection_requested",
        "monitor.schedule_changed",
        "monitor.connection_revoked",
    ):
        assert len(audit(admin_engine, tenant, kind)) == 1, kind
    decided_and_replayed(db, world, connector)
