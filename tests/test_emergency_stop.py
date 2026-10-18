# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant emergency stop: ES1 to ES14 on real PostgreSQL, a live provider and Chromium."""

import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Lock
from types import MappingProxyType
from uuid import UUID, uuid4

import httpx
import pytest
from alembic import command
from alembic.config import Config
from playwright.sync_api import expect
from replay_fixtures import chain_export, make_capture, replay_case
from sqlalchemy import event, text
from sqlalchemy.exc import IntegrityError
from test_browser_surfaces import agent_http as agent_http
from test_browser_surfaces import browser_gateway as browser_gateway
from test_browser_surfaces import chromium as chromium
from test_browser_surfaces import human_page as human_page
from test_browser_surfaces import pending as pending_over_http
from test_browser_surfaces import sign_in
from test_execution import FixtureJournal, provision_identity, request
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential
from test_mcp_surface import gateway as gateway
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound.cli import main
from execbound.db import (
    EMPTY_CLAIMS,
    UPDATE_COLUMNS,
    check_runtime,
    grant_dormant,
    honour_claims,
)
from execbound.execution import (
    activate_stop,
    admit,
    decide_approval,
    mark_indeterminate,
    reconcile,
    record_outcome,
    release_stop,
    take_dispatch,
)
from execbound.execution.models import ExecutionError
from execbound.plugins import PLUGIN_GRANTS_MISMATCH, PLUGIN_GRANTS_REFUSAL
from execbound.provider.gateway import reconcile_operation
from execbound.replay.export import export_history
from execbound.replay.verify import verify_export
from execbound_harness.demo import endpoint_bundle

REFUSAL = {"detail": "Execution unavailable", "code": "TENANT_STOPPED"}
ROW_TABLES = ("executions", "execution_keys", "resource_claims", "execution_impact")
# A plugin's claim a test grants on the database, the way a plugin's deployment holds it.
PRODUCT_COUNTS = MappingProxyType({"product_counts": frozenset({"SELECT"})})


def scoped(conn, tenant):
    # Limits nothing on an `admin_engine` connection, whose owner bypasses row security
    # (see tenant_fence).
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def control_row(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT stop_id, stopped_at, stopped_by, stop_reason "
                    "FROM execbound.tenant_policy_control WHERE tenant_id=:t"
                ),
                {"t": tenant},
            )
            .mappings()
            .one()
        )


def audit(engine, tenant, kind):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND kind=:k ORDER BY sequence"
                ),
                {"t": tenant, "k": kind},
            )
            .scalars()
            .all()
        )


def audit_count(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text("SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()


def row_counts(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return {
            table: conn.execute(
                text(f"SELECT count(*) FROM execbound.{table} WHERE tenant_id=:t"), {"t": tenant}
            ).scalar_one()
            for table in ROW_TABLES
        }


def execution_row(engine, tenant, execution_id):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT state, dispatch_attempted_at FROM execbound.executions "
                    "WHERE tenant_id=:t AND execution_id=:e"
                ),
                {"t": tenant, "e": execution_id},
            )
            .mappings()
            .one()
        )


def autonomous(engine):
    # A development-environment target needs no approval, so admission commits a dispatch.
    with engine.begin() as conn:
        conn.execute(text("UPDATE execbound.resources SET environment='development'"))


def invocations(live_provider):
    path = live_provider.environment["TEST_PROVIDER_INVOCATIONS"]
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as journal:
        return len(journal.read().splitlines())


def mcp_execute(gateway, token, world):
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "name": "execute",
            "arguments": {"request": request(world).model_dump(mode="json")},
        },
    }
    response = httpx.post(
        gateway + "/mcp/",
        json=rpc,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
            "MCP-Method": "tools/call",
            "MCP-Name": "execute",
        },
        trust_env=False,
    )
    messages = [
        json.loads(line[5:].strip())
        for line in response.text.splitlines()
        if line.startswith("data:")
    ] or [response.json()]
    return response.status_code, messages[-1]


def test_es1_stop_refuses_new_admission_on_http_and_mcp_without_rows(
    api, gateway, world, seeded, db, admin_engine
):
    tenant = world["identity"].tenant_id
    activate_stop(db, world["admin"], "Suspected credential compromise", world["clock"])
    response = api.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert response.status_code == 423 and response.json() == REFUSAL
    status, message = mcp_execute(gateway, seeded["tokens"][0], world)
    assert status == 200 and message["result"]["isError"] is True
    assert message["result"]["structuredContent"] == REFUSAL
    assert set(row_counts(admin_engine, tenant).values()) == {0}
    assert audit(admin_engine, tenant, "execution.evaluated") == []
    # Admission records one rejection per attempt; the MCP adapter also records its own.
    rejected = audit(admin_engine, tenant, "execution.rejected")
    assert [r["reason"] for r in rejected] == ["TENANT_STOPPED"] * 3


def test_es2_es3_pending_approval_waits_out_a_stop_and_executes_once_after_release(
    api, world, db, live_provider
):
    body = request(world).model_dump(mode="json")
    pending = api.post("/v1/execute", json=body)
    assert pending.status_code == 202 and pending.json()["state"] == "PENDING_APPROVAL"
    assert "tenant_stopped" not in pending.json()
    approval_id = UUID(pending.json()["approval_id"])
    activate_stop(db, world["admin"], "Incident 42", world["clock"])
    with pytest.raises(ExecutionError) as refused:
        decide_approval(db, world["human"], approval_id, "APPROVE", world["clock"])
    assert refused.value.code == "TENANT_STOPPED"
    retry = api.post("/v1/execute", json=body)
    assert retry.status_code == 202
    assert retry.json()["state"] == "PENDING_APPROVAL"
    assert retry.json()["approval_state"] == "PENDING"
    assert retry.json()["approval_id"] == str(approval_id)
    assert retry.json()["tenant_stopped"] is True
    release_stop(db, world["admin"], "Incident 42 closed", world["clock"])
    decide_approval(db, world["human"], approval_id, "APPROVE", world["clock"])
    done = api.post("/v1/execute", json=body)
    assert done.status_code == 200 and done.json()["state"] == "EXECUTED"
    assert "tenant_stopped" not in done.json()
    again = api.post("/v1/execute", json=body)
    assert again.json()["state"] == "EXECUTED" and invocations(live_provider) == 1


def test_es4_activation_and_admission_are_totally_ordered_at_the_fence(db, world, admin_engine):
    autonomous(admin_engine)
    tenant = world["identity"].tenant_id
    seen, guard = [], Lock()

    def at_wait(conn, cursor, statement, parameters, context, executemany):
        if "FROM execbound.tenant_policy_control" in statement and "FOR UPDATE" in statement:
            with guard:
                seen.append(statement)

    event.listen(db.engine, "before_cursor_execute", at_wait)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            with admin_engine.begin() as owner:
                owner.execute(
                    text(
                        "SELECT tenant_id FROM execbound.tenant_policy_control "
                        "WHERE tenant_id=:t FOR UPDATE"
                    ),
                    {"t": tenant},
                )
                admission = pool.submit(
                    admit, db, world["identity"], request(world), world["clock"]
                )
                stop = pool.submit(activate_stop, db, world["admin"], "Race", world["clock"])
                deadline = time.monotonic() + 5
                while len(seen) < 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert len(seen) == 2, "both writers must block on the tenant fence"
            stopped = stop.result(timeout=10)
            try:
                admitted = admission.result(timeout=10)
            except ExecutionError as exc:
                assert exc.code == "TENANT_STOPPED"
                admitted = None
    finally:
        event.remove(db.engine, "before_cursor_execute", at_wait)
    activated = audit(admin_engine, tenant, "tenant.stop_activated")
    assert len(activated) == 1 and activated[0]["stop_id"] == str(stopped.stop_id)
    if admitted is None:
        assert set(row_counts(admin_engine, tenant).values()) == {0}
        assert activated[0]["dispatch_committed"] == 0
    else:
        assert admitted.view.state == "DISPATCH_COMMITTED" and admitted.ticket is not None
        assert activated[0]["dispatch_committed"] == 1


def test_es5_committed_dispatch_is_refused_and_settles_as_not_executed(
    db, world, admin_engine, live_provider, connector
):
    autonomous(admin_engine)
    tenant = world["identity"].tenant_id
    admission = admit(db, world["identity"], request(world), world["clock"])
    assert admission.ticket is not None and admission.view.state == "DISPATCH_COMMITTED"
    activate_stop(db, world["admin"], "Halt before send", world["clock"])
    with pytest.raises(ExecutionError) as refused:
        take_dispatch(db, admission.ticket, world["clock"])
    assert refused.value.code == "TENANT_STOPPED"
    row = execution_row(admin_engine, tenant, admission.view.execution_id)
    assert row["state"] == "DISPATCH_COMMITTED" and row["dispatch_attempted_at"] is None
    assert invocations(live_provider) == 0
    # A stop never blocks reconciliation, and the provider proves nothing was sent.
    settled = reconcile_operation(
        db,
        world["admin"],
        admission.view.execution_id,
        connector,
        reason="Stopped before the send attempt",
        cancel_if_missing=True,
        clock=world["clock"],
    )
    assert settled.state == "FAILED_NOT_EXECUTED" and invocations(live_provider) == 0


def test_es6_a_stop_is_scoped_to_its_tenant(db, world, seeded, admin_engine):
    other = seeded["tenants"][1]
    other_admin = provision_identity(admin_engine, db, other, "ADMIN", world["clock"].now())
    activate_stop(db, other_admin, "Other tenant incident", world["clock"])
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    approved = admit(db, world["identity"], request(world), world["clock"])
    assert approved.ticket is not None
    take_dispatch(db, approved.ticket, world["clock"])
    done = record_outcome(
        db, approved.ticket, b"test-journal-proof", FixtureJournal("EXECUTED"), world["clock"]
    )
    assert done.state == "EXECUTED"
    assert control_row(admin_engine, world["identity"].tenant_id)["stop_id"] is None
    assert control_row(admin_engine, other)["stop_id"] is not None


def test_es7_settlement_is_never_blocked_by_a_stop(db, world, admin_engine):
    autonomous(admin_engine)
    admission = admit(db, world["identity"], request(world), world["clock"])
    take_dispatch(db, admission.ticket, world["clock"])
    mark_indeterminate(db, admission.ticket, world["clock"])
    activate_stop(db, world["admin"], "Halt after send", world["clock"])
    settled = reconcile(
        db,
        world["admin"],
        admission.view.execution_id,
        reason="Provider journal located",
        evidence=b"test-journal-proof",
        verifier=FixtureJournal("EXECUTED"),
        clock=world["clock"],
    )
    assert settled.state == "EXECUTED"
    outcome = record_outcome(
        db, admission.ticket, b"test-journal-proof", FixtureJournal("EXECUTED"), world["clock"]
    )
    assert outcome.state == "EXECUTED"


def test_es8_double_activation_release_without_a_stop_and_non_admins_change_nothing(
    db, world, admin_engine
):
    tenant = world["identity"].tenant_id
    with pytest.raises(ExecutionError) as unstopped:
        release_stop(db, world["admin"], "Nothing to release", world["clock"])
    assert unstopped.value.code == "INVALID_STATE"
    for actor in (world["identity"], world["human"]):
        with pytest.raises(ExecutionError) as forbidden:
            activate_stop(db, actor, "Not an administrator", world["clock"])
        assert forbidden.value.code == "INVALID_IDENTITY"
    for reason in ("", " " * 3, "x" * 501):
        with pytest.raises(ExecutionError) as invalid:
            activate_stop(db, world["admin"], reason, world["clock"])
        assert invalid.value.code == "INVALID_REASON"
    assert control_row(admin_engine, tenant)["stop_id"] is None
    assert audit(admin_engine, tenant, "tenant.stop_activated") == []
    first = activate_stop(db, world["admin"], "First", world["clock"])
    with pytest.raises(ExecutionError) as twice:
        activate_stop(db, world["admin"], "Second", world["clock"])
    assert twice.value.code == "INVALID_STATE"
    row = control_row(admin_engine, tenant)
    assert row["stop_id"] == first.stop_id and row["stop_reason"] == "First"
    assert row["stopped_by"] == world["admin"].principal_id
    released = release_stop(db, world["admin"], "Done", world["clock"])
    assert released.stop_id == first.stop_id
    with pytest.raises(ExecutionError) as again:
        release_stop(db, world["admin"], "Done again", world["clock"])
    assert again.value.code == "INVALID_STATE"
    assert dict(control_row(admin_engine, tenant)) == {column: None for column in row}
    assert [p["stop_id"] for p in audit(admin_engine, tenant, "tenant.stop_activated")] == [
        str(first.stop_id)
    ]
    assert [p["stop_id"] for p in audit(admin_engine, tenant, "tenant.stop_released")] == [
        str(first.stop_id)
    ]


def test_es9_human_pages_show_the_stop_and_refuse_a_replayed_decision(
    human_page, browser_gateway, agent_http, admin_engine, world, db
):
    sign_in(human_page, admin_engine, world)
    pending = pending_over_http(agent_http, world)
    # The classic page is where a form still carries the decision, so that is where a
    # replay can be held after a stop has been activated behind it.
    classic = f"/approvals/{pending['approval_id']}/classic"
    human_page.goto(classic)
    form = human_page.locator("form.decision")
    expect(form).to_have_count(1)
    state = form.locator("input[name=state]").input_value()
    csrf = form.locator("input[name=csrf]").input_value()
    reason = "<b>Contain</b> agent 7 & review"
    activate_stop(db, world["admin"], reason, world["clock"])
    human_page.reload()
    banner = human_page.locator(".stop-banner")
    expect(banner).to_be_visible()
    expect(banner).to_contain_text(reason)
    assert banner.locator("b").count() == 0
    expect(human_page.locator("form.decision")).to_have_count(0)
    replayed = human_page.request.post(
        f"/approvals/{pending['approval_id']}/decide",
        form={"csrf": csrf, "state": state, "decision": "APPROVE"},
        headers={"Origin": browser_gateway},
    )
    assert replayed.status >= 400
    with admin_engine.begin() as conn:
        scoped(conn, world["identity"].tenant_id)
        assert (
            conn.execute(
                text("SELECT state FROM execbound.approvals WHERE approval_id=:a"),
                {"a": UUID(pending["approval_id"])},
            ).scalar_one()
            == "PENDING"
        )
    # The console shows the same stop on every route, with the reason as text.
    human_page.goto("/activity")
    stop = human_page.get_by_role("status").filter(has_text="Emergency stop")
    expect(stop).to_be_visible()
    expect(stop).to_contain_text(reason)
    assert stop.locator("b").count() == 0
    human_page.get_by_role("button", name="Sign out").click()
    expect(human_page).to_have_url(re.compile(r"/login$"))


def test_es10_replay_reconstructs_stop_periods_and_rejects_decisions_inside_them(
    db, world, api, admin_engine
):
    activated = activate_stop(db, world["admin"], "Incident 9", world["clock"])
    assert api.post("/v1/execute", json=request(world).model_dump(mode="json")).status_code == 423
    world["clock"].value += timedelta(minutes=2)
    release_stop(db, world["admin"], "Incident 9 closed", world["clock"])
    export = export_history(db, world["admin"], world["clock"])
    history = verify_export(export, export.head)
    assert history.complete
    kinds = [e.event.kind for e in history.events]
    assert kinds.count("tenant.stop_activated") == 1 and kinds.count("tenant.stop_released") == 1
    [period] = history.stop_periods
    assert period.stop_id == activated.stop_id and period.released_at is not None
    assert period.activated_at < period.released_at

    case = replay_case()
    capture = make_capture(case)
    now = capture.semantic_time
    stop_id, identity = uuid4(), capture.identity
    forged = [
        (
            "tenant.stop_activated",
            {
                "stop_id": str(stop_id),
                "reason": "Forged window",
                "principal_id": str(identity.principal_id),
                "credential_id": str(identity.credential_id),
                "dispatch_committed": 0,
                "replay": {"version": 1, "semantic_time": (now - timedelta(minutes=1)).isoformat()},
            },
        ),
        capture,
        (
            "tenant.stop_released",
            {
                "stop_id": str(stop_id),
                "reason": "Forged release",
                "principal_id": str(identity.principal_id),
                "credential_id": str(identity.credential_id),
                "replay": {"version": 1, "semantic_time": (now + timedelta(minutes=1)).isoformat()},
            },
        ),
    ]
    inside = chain_export(forged, [case["bundle"]])
    verified = verify_export(inside, inside.head)
    assert not verified.complete and "DECISION_DURING_STOP" in verified.issues
    assert len(verified.stop_periods) == 1
    still_open = chain_export(forged[:1], tenant_id=identity.tenant_id)
    open_history = verify_export(still_open, still_open.head)
    assert open_history.complete and open_history.stop_periods[0].released_at is None


def test_es11_migration_round_trip_and_runtime_catalog(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    assert {"stop_id", "stopped_at", "stopped_by", "stop_reason"} <= UPDATE_COLUMNS[
        "tenant_policy_control"
    ]
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        scoped(conn, tenant)
        conn.execute(
            text("UPDATE execbound.tenant_policy_control SET stop_id=:s WHERE tenant_id=:t"),
            {"s": uuid4(), "t": tenant},
        )
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    activate_stop(db, world["admin"], "Hold", world["clock"])
    with pytest.raises(RuntimeError):
        command.downgrade(config, "0010_authentication_failures")
    release_stop(db, world["admin"], "Released", world["clock"])
    command.downgrade(config, "0010_authentication_failures")
    command.upgrade(config, "head")
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    assert control_row(admin_engine, tenant)["stop_id"] is None


def test_es12_cli_stop_and_resume_require_an_admin_credential(
    db, world, admin_engine, tmp_path, monkeypatch, capsys
):
    tenant = world["identity"].tenant_id
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])
    admin_file, human_file = tmp_path / "admin.token", tmp_path / "human.token"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    human_file.write_text(credential(admin_engine, world["human"]), encoding="utf-8")

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        main()
        return json.loads(capsys.readouterr().out)

    def refused(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        with pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == 2
        return capsys.readouterr().err

    common = ("--tenant", str(tenant), "--credential-file")
    assert "INVALID_IDENTITY" in refused(
        "tenant-stop", *common, str(human_file), "--reason", "Not allowed"
    )
    assert control_row(admin_engine, tenant)["stop_id"] is None
    stopped = run("tenant-stop", *common, str(admin_file), "--reason", "Incident 7")
    stop_id = UUID(stopped["stop_id"])
    status = run("tenant-status", *common, str(admin_file))
    assert status["stopped"] is True and status["stop_id"] == str(stop_id)
    assert status["reason"] == "Incident 7"
    assert "INVALID_IDENTITY" in refused(
        "tenant-resume", *common, str(human_file), "--reason", "Not allowed"
    )
    resumed = run("tenant-resume", *common, str(admin_file), "--reason", "Resolved")
    assert resumed["stop_id"] == str(stop_id)
    status = run("tenant-status", *common, str(admin_file))
    assert status["stopped"] is False and status["stop_id"] is None
    assert "INVALID_STATE" in refused(
        "tenant-resume", *common, str(admin_file), "--reason", "Nothing active"
    )


def test_es13_the_kill_switch_names_the_fix_for_either_grant_mismatch(
    db, world, admin_engine, tmp_path, monkeypatch, capsys
):
    """`execbound tenant-stop` against a database whose grants are not what this process's
    plugins claim (#496), refused with the sentence for the cause and never a traceback, so
    an operator in an incident is told the fix. A process that loaded no plugin, against a
    plugin's grants, is told to name it in `EXECBOUND_PLUGINS`; one that honours the claim,
    against a database missing the grant, is told to restore it with the plugin's upgrade.
    With the two matching, the same command stops the tenant."""
    tenant = world["identity"].tenant_id
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])
    monkeypatch.delenv("EXECBOUND_PLUGINS", raising=False)
    admin_file = tmp_path / "admin.token"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    argv = ["execbound", "tenant-stop", "--tenant", str(tenant), "--credential-file"]
    argv += [str(admin_file), "--reason", "Incident 8"]
    monkeypatch.setattr(sys, "argv", argv)

    def refused():
        with pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == 2
        err = capsys.readouterr().err
        assert "Traceback" not in err
        assert control_row(admin_engine, tenant)["stop_id"] is None
        return err

    def granted(claims):
        with admin_engine.begin() as conn:
            grant_dormant(conn, claims)

    granted(PRODUCT_COUNTS)
    try:
        assert PLUGIN_GRANTS_REFUSAL in refused()
        # What loading the plugin does; the suite's own fixture resets it after the test.
        honour_claims(PRODUCT_COUNTS)
        granted(EMPTY_CLAIMS)
        assert PLUGIN_GRANTS_MISMATCH in refused()
        granted(PRODUCT_COUNTS)
        main()
        assert json.loads(capsys.readouterr().out)["stop_id"]
    finally:
        with admin_engine.begin() as conn:
            grant_dormant(conn, EMPTY_CLAIMS)


@pytest.mark.parametrize(
    ("granted", "honoured", "sentence"),
    [
        pytest.param(PRODUCT_COUNTS, EMPTY_CLAIMS, PLUGIN_GRANTS_REFUSAL, id="plugin-not-loaded"),
        pytest.param(EMPTY_CLAIMS, PRODUCT_COUNTS, PLUGIN_GRANTS_MISMATCH, id="grants-missing"),
    ],
)
def test_es14_every_command_on_the_runtime_connection_names_the_fix(
    db, world, admin_engine, tmp_path, monkeypatch, capsys, granted, honoured, sentence
):
    """Not only the kill switch (#496): every command on the runtime connection refuses a
    database whose grants are not what this process's plugins claim with the kill switch's
    sentence for the cause, and changes nothing. That is the emergency stop's siblings, a
    policy rollback, the history export, and the runs that read a runtime configuration,
    which names no plugin here. A run over a tenants file, or over every workspace (#503),
    refuses as a whole: the refusal is the process's, and every tenant would meet it, so it
    is not recorded as each tenant's skip."""
    tenant = world["identity"].tenant_id
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.delenv("EXECBOUND_PLUGINS", raising=False)
    token = credential(admin_engine, world["admin"])
    admin_file, tenants_file = tmp_path / "admin.token", tmp_path / "jobs.json"
    admin_file.write_text(token, encoding="utf-8")
    tenants_file.write_text(json.dumps({str(tenant): token}), encoding="utf-8")
    # A connector and a relay that are never reached: every command is refused before either.
    private = tmp_path / "private.json"
    relay = {"host": "127.0.0.1", "port": 2525, "tls": "starttls", "username": "relay"}
    relay |= {"password": "relay-password", "from": "noreply@example.com"}
    unreached = {"tenant_id": str(tenant), "account_id": str(world["account"])}
    unreached |= {"origin": "http://127.0.0.1:9", "dispatch_token": "d" * 32}
    unreached |= {"control_token": "c" * 32, "evidence_keys": {"journal-v1": "22" * 32}}
    private.write_text(
        json.dumps(
            {
                "origin": "http://127.0.0.1:8000",
                "active_key_id": "k1",
                "continuation_keys": {"k1": "11" * 32},
                "connectors": [unreached],
                "mail": relay,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    payload = json.loads(
        endpoint_bundle(tenant, world["account"], mapping_version="map-v1").model_dump_json()
    )
    del payload["tenant_id"], payload["bundle_id"]
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(json.dumps(payload), encoding="utf-8")
    export = tmp_path / "history.json"
    admin = ("--tenant", str(tenant), "--credential-file", str(admin_file))
    bundle = (*admin, "--bundle", str(world["bundle"].bundle_id))
    reason = ("--reason", "Incident 9")
    commands = [
        ("tenant-stop", *admin, *reason),
        ("tenant-resume", *admin, *reason),
        ("tenant-status", *admin),
        ("tenant-mode", *admin, "--set", "OBSERVE", *reason),
        ("tenant-approval-deadline", *admin, "--set", "off", *reason),
        ("tenant-assistant", *admin, "--set", "off", *reason),
        ("observe-report", *admin),
        ("rotation-readiness", *admin),
        ("bundle-create", *admin, "--input", str(bundle_file)),
        ("bundle-validate", *bundle),
        ("bundle-activate", *bundle),
        ("bundle-retire", *bundle),
        ("bundle-list", *admin),
        ("bundle-preview", *bundle),
        ("audit-export", *admin, "--output", str(export)),
        ("recover", *admin),
        ("recover", "--tenants-file", str(tenants_file)),
        # The scheduled pass holds no credential (#503) and refuses before it visits any
        # workspace, so the refusal is the run's and names the fix like every other.
        ("recover", "--all-tenants"),
        ("reconcile", *admin, "--execution", str(uuid4()), *reason),
        ("notify", *admin),
        ("notify", "--tenants-file", str(tenants_file)),
        ("notify", "--all-tenants"),
        ("notifications", *admin),
        ("export-events", *admin),
        ("export-status", *admin),
        ("export-resume", *admin, "--destination", "siem"),
        ("invitations-run",),
    ]
    events = audit_count(admin_engine, tenant)
    # What loading a plugin that claims it does; the suite's own fixture resets it afterwards.
    honour_claims(honoured)
    with admin_engine.begin() as conn:
        grant_dormant(conn, granted)
    try:
        for argv in commands:
            monkeypatch.setattr(sys, "argv", ["execbound", *argv])
            with pytest.raises(SystemExit) as caught:
                main()
            captured = capsys.readouterr()
            assert caught.value.code == 2, argv
            assert sentence in captured.err, argv
            assert "Traceback" not in captured.err and captured.out == "", argv
            # Nothing changed: no stop, no audited event, no export.
            assert control_row(admin_engine, tenant)["stop_id"] is None, argv
            assert audit_count(admin_engine, tenant) == events, argv
            assert not export.exists(), argv
    finally:
        with admin_engine.begin() as conn:
            grant_dormant(conn, EMPTY_CLAIMS)
