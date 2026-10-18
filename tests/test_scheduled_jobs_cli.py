# SPDX-License-Identifier: AGPL-3.0-only
"""The scheduled pass over every workspace (#503): SJ5, SJ11, SJ16, defect 1, the CLI, and the
walk under an owner that does not bypass row security."""

import json
import os
import sys
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sample_fixtures import empty_workspace
from signup_fixtures import stack as stack
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from test_execution import provision_identity, targets
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted
from test_notification_email import ADDRESS, MAIL
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_recovery_run import GRACE, lost_response, state_of

from execbound import administration, jobs, recovery_run
from execbound.assistant import turns
from execbound.assistant.turns import AssistantError
from execbound.cli import main
from execbound.db import UnsafeDatabaseRole
from execbound.execution import admit, mark_indeterminate, take_dispatch
from execbound.execution.models import ExecutionError
from execbound.execution.scheduled import ScheduledActor, enlist
from execbound.identity import authenticate
from execbound.jobs import every_workspace, for_each_tenant
from execbound.plugins import RUNTIME_CHECK_REFUSAL
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.recovery_run import (
    RecoveryCounts,
    RecoveryStopped,
    SweepFailed,
    recover_scheduled,
)
from execbound.resolution.models import SystemClock
from execbound_harness.demo import endpoint_bundle

pytestmark = pytest.mark.integration

# A private configuration must declare a provider (`_Configuration.dispatches_or_governs`), so
# this one names a connector for a tenant no test database holds. A test that needs a real
# connector replaces the list.
PRIVATE = {
    "origin": "http://127.0.0.1:8000",
    "active_key_id": "k1",
    "continuation_keys": {"k1": "11" * 32},
    "connectors": [
        {
            "tenant_id": str(UUID(int=1)),
            "account_id": str(UUID(int=2)),
            "origin": "http://127.0.0.1:8001",
            "dispatch_token": "dispatch-test" * 3,
            "control_token": "control-test" * 3,
            "evidence_keys": {"proof": "31" * 32},
        }
    ],
}


def everyone(db) -> list[UUID]:
    """The whole directory, in order: from the smallest id round to the smallest id."""
    return list(jobs._directory(db, UUID(int=0)))


def mismatch(conn):
    raise UnsafeDatabaseRole("Database revision mismatch")


def second_workspace(db, admin_engine, seeded, world):
    """`world` again, for the second seeded tenant. The registry fixture gave both seeded
    tenants the same account, mapping, sources and resources, so this one needs only its own
    ADMIN, approver and active bundle."""
    identity = authenticate(db, seeded["tokens"][1])
    tenant, now = identity.tenant_id, world["clock"].now()
    admin = provision_identity(admin_engine, db, tenant, "ADMIN", now)
    human = provision_identity(admin_engine, db, tenant, "HUMAN_APPROVER", now)
    bundle = endpoint_bundle(tenant, world["account"], mapping_version="map-v1")
    create_bundle(db, admin, bundle, world["clock"])
    validate_bundle(db, admin, bundle.bundle_id, world["clock"])
    activate_bundle(db, admin, bundle.bundle_id, world["clock"])
    return {**world, "identity": identity, "admin": admin, "human": human, "bundle": bundle}


def response_lost(db, admin_engine, world) -> UUID:
    """An operation sent and its answer lost, with no provider behind it: taken for dispatch,
    then marked INDETERMINATE, as the gateway does when a reply never arrives."""
    admission = admit(db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"])
    assert admission.view.state == "DISPATCH_COMMITTED" and admission.ticket is not None
    take_dispatch(db, admission.ticket, world["clock"])
    assert mark_indeterminate(db, admission.ticket, world["clock"]).state == "INDETERMINATE"
    return admission.view.execution_id


def test_sj5_one_workspace_s_failure_is_its_own_outcome(
    db, world, admin_engine, seeded, live_provider, connector, monkeypatch
):
    """Two workspaces with due work. The first's connection lookup refuses and its retirement
    fails; the second is still recovered, and every transaction either workspace's pass opens
    is fenced to that workspace."""
    refused = second_workspace(db, admin_engine, seeded, world)
    a, b = refused["identity"].tenant_id, world["identity"].tenant_id
    winner = lost_response(db, world, live_provider)
    stuck = response_lost(db, admin_engine, refused)
    world["clock"].value += GRACE + timedelta(seconds=1)

    class Connections:
        """A's lookup refuses, as a sample account's does when its row cannot be read; B's
        answers with the live connector."""

        @contextmanager
        def connection(self, tenant_id, account_id):
            if tenant_id == a:
                raise ExecutionError("EXECUTION_UNAVAILABLE")
            yield connector if (tenant_id, account_id) == (b, world["account"]) else None

        def evidence_verifier(self, tenant_id, account_id):
            return None

    retire = turns.retire_due_turns

    def retire_but_a(db_, actor, clock):
        if actor.tenant_id == a:
            raise AssistantError("ASSISTANT_UNAVAILABLE")
        return retire(db_, actor, clock)

    # `recover_scheduled` imports it from `turns` when it runs, so this is the one it calls.
    monkeypatch.setattr(turns, "retire_due_turns", retire_but_a)
    visiting: list[UUID] = []
    fences: list[tuple[UUID, UUID]] = []
    transaction = db.transaction

    def recorded(tenant_id, **options):
        if visiting:
            fences.append((visiting[-1], tenant_id))
        return transaction(tenant_id, **options)

    monkeypatch.setattr(db, "transaction", recorded)

    def step(tenant):
        visiting.append(tenant)
        try:
            return recover_scheduled(
                db, tenant, Connections(), destinations=[], clock=world["clock"]
            )
        finally:
            visiting.pop()

    report = every_workspace(db, step, command="recover", tenants=[a, b])
    assert (report["visited"], report["failed"]) == (2, 1)
    failed = report["tenants"][str(a)]
    assert (failed["skipped"], failed["examined"], failed["unresolved"]) == (
        "ASSISTANT_UNAVAILABLE",
        1,
        1,
    )
    assert report["tenants"][str(b)]["executed"] == 1
    assert state_of(admin_engine, winner.view.execution_id) == "EXECUTED"
    assert state_of(admin_engine, stuck) == "INDETERMINATE"
    # Both passes opened transactions, and each only under its own workspace's fence.
    assert {visited for visited, _ in fences} == {a, b}
    assert [(v, f) for v, f in fences if v != f] == []


def test_a_step_s_refusal_is_contained_to_its_own_workspace(db, seeded):
    first, second = seeded["tenants"]

    def step(tenant):
        if tenant == first:
            raise AssistantError("ASSISTANT_UNAVAILABLE")
        return {"expired": 1}

    report = every_workspace(db, step, command="recover", tenants=[first, second])
    assert (report["visited"], report["failed"], report["inactive"]) == (2, 1, 0)
    assert report["tenants"] == {
        str(first): {"skipped": "ASSISTANT_UNAVAILABLE"},
        str(second): {"expired": 1},
    }


def test_defect_1_the_token_map_run_contains_an_assistant_failure(db, admin_engine):
    one, two = empty_workspace(admin_engine, db), empty_workspace(admin_engine, db)
    tokens = {w.tenant_id: credential(admin_engine, w.admin) for w in (one, two)}

    def step(identity):
        if identity.tenant_id == one.tenant_id:
            raise AssistantError("ASSISTANT_UNAVAILABLE")
        return {"expired": 0}

    assert for_each_tenant(db, tokens, step, command="recover") == {
        str(one.tenant_id): {"skipped": "ASSISTANT_UNAVAILABLE"},
        str(two.tenant_id): {"expired": 0},
    }


def test_an_inactive_workspace_is_counted_and_a_stopped_one_reports_what_it_did(
    db, admin_engine, seeded
):
    first, second = seeded["tenants"]
    with admin_engine.begin() as conn:
        fenced(conn, first)
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"), {"t": first}
        )

    def step(tenant):
        counts = RecoveryCounts()
        counts.examined = 1
        raise RecoveryStopped("INVALID_IDENTITY", counts)

    report = every_workspace(db, step, command="recover", tenants=[first, second])
    assert (report["inactive"], report["visited"], report["failed"]) == (1, 1, 1)
    assert str(first) not in report["tenants"]
    stopped = report["tenants"][str(second)]
    assert (stopped["skipped"], stopped["examined"]) == ("INVALID_IDENTITY", 1)


def test_a_failed_sweep_reports_what_its_run_had_already_committed(db, seeded):
    first, second = seeded["tenants"]

    def step(tenant):
        if tenant == first:
            raise SweepFailed(
                "ASSISTANT_UNAVAILABLE",
                SimpleNamespace(executed=1, notifications_settled=2),
            )
        return {}

    report = every_workspace(db, step, command="recover", tenants=[first, second])
    assert (report["visited"], report["failed"]) == (2, 1)
    # A workspace with nothing to report is left out; the failed one keeps its partial report.
    assert report["tenants"] == {
        str(first): {"skipped": "ASSISTANT_UNAVAILABLE", "executed": 1, "notifications_settled": 2}
    }


def test_a_workspace_whose_activity_cannot_be_read_is_visited_and_failed(db, seeded, monkeypatch):
    first, second = seeded["tenants"]
    active = jobs.tenant_active

    def unreadable(db_, tenant):
        if tenant == first:
            raise OperationalError("SELECT", {}, Exception("connection lost"))
        return active(db_, tenant)

    monkeypatch.setattr(jobs, "tenant_active", unreadable)
    report = every_workspace(
        db, lambda t: {"expired": 1}, command="recover", tenants=seeded["tenants"]
    )
    assert (report["visited"], report["failed"], report["inactive"]) == (2, 1, 0)
    assert report["tenants"] == {
        str(first): {"skipped": "DEPENDENCY_UNAVAILABLE"},
        str(second): {"expired": 1},
    }


def test_sj16_the_walk_starts_where_it_is_told_wraps_and_counts_what_the_budget_left(
    db, admin_engine, seeded
):
    for index in range(3):
        administration.create_tenant(admin_engine, f"Walk {index}")
    ids = everyone(db)
    assert len(ids) == 5 and ids == sorted(ids)
    start = ids[2]
    seen: list[UUID] = []
    report = every_workspace(db, lambda t: seen.append(t) or {}, command="recover", start=start)
    assert seen == ids[3:] + ids[:3]
    assert report["visited"] == 5
    # A budget spent after the first workspace: the rest are counted, not visited.
    moments = iter([0.0, 0.0] + [100.0] * 5)
    cut: list[UUID] = []
    report = every_workspace(
        db,
        lambda t: cut.append(t) or {},
        command="recover",
        start=start,
        budget_seconds=5,
        monotonic=lambda: next(moments),
    )
    assert cut == [ids[3]]
    assert report["not_reached"] == 4
    # The next run, cut short the same way but from elsewhere, reaches one this one did not.
    moments = iter([0.0, 0.0] + [100.0] * 5)
    later: list[UUID] = []
    report = every_workspace(
        db,
        lambda t: later.append(t) or {},
        command="recover",
        start=ids[0],
        budget_seconds=5,
        monotonic=lambda: next(moments),
    )
    assert later == [ids[1]] and ids[1] not in cut
    assert report["not_reached"] == 4


@pytest.mark.parametrize(
    "change,restore",
    [
        # Wider: more than the listing function could read the directory.
        (
            "ALTER POLICY owner_list ON execbound.job_tenants TO PUBLIC",
            'ALTER POLICY owner_list ON execbound.job_tenants TO "{owner}"',
        ),
        # Narrower, both ways: the listing function would list nothing, and the pass would
        # visit no workspace and say nothing.
        (
            "ALTER POLICY owner_list ON execbound.job_tenants USING (false)",
            "ALTER POLICY owner_list ON execbound.job_tenants USING (true)",
        ),
        (
            "CREATE POLICY hidden ON execbound.job_tenants AS RESTRICTIVE FOR SELECT USING (false)",
            "DROP POLICY hidden ON execbound.job_tenants",
        ),
    ],
    ids=["widened", "using-false", "restrictive"],
)
def test_a_changed_directory_policy_stops_the_pass(db, admin_engine, seeded, change, restore):
    with admin_engine.connect() as conn:
        owner = conn.execute(
            text(
                "SELECT pg_get_userbyid(p.proowner) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = 'job_tenants_page'"
            )
        ).scalar_one()
    with admin_engine.begin() as conn:
        conn.execute(text(change))
    try:
        with pytest.raises(ExecutionError) as refused:
            every_workspace(db, lambda t: {}, command="recover")
        assert refused.value.code == "UNSAFE_JOB_POLICY"
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(restore.format(owner=owner)))
    assert every_workspace(db, lambda t: {}, command="recover")["visited"] == 2


def test_sj11_a_schema_mismatch_stops_the_pass_before_any_workspace(db, seeded, monkeypatch):
    monkeypatch.setattr(jobs, "check_runtime", mismatch)
    visited: list[UUID] = []
    with pytest.raises(UnsafeDatabaseRole):
        every_workspace(db, lambda t: visited.append(t) or {}, command="recover")
    assert visited == []


def test_sj11_the_cli_exits_non_zero_on_a_schema_mismatch(
    db, seeded, tmp_path, monkeypatch, capsys
):
    private = tmp_path / "private.json"
    private.write_text(json.dumps(PRIVATE), encoding="utf-8")
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(jobs, "check_runtime", mismatch)
    for command in (["recover", "--all-tenants"], ["notify", "--all-tenants"]):
        monkeypatch.setattr(sys, "argv", ["execbound", *command])
        with pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == 2
        # The sentence every command on the runtime connection prints for a refusal that is
        # not about a plugin's grants (#496), never a traceback.
        err = capsys.readouterr().err
        assert RUNTIME_CHECK_REFUSAL in err and "Traceback" not in err


MODES = "give --tenants-file, --all-tenants"
TENANT = str(UUID(int=1))


@pytest.mark.parametrize(
    "arguments,message",
    [
        (["recover", "--all-tenants", "--cancel-unattempted"], "needs an administrator"),
        (["recover", "--all-tenants", "--tenants-file", "jobs.json"], MODES),
        (["recover"], MODES),
        (["notify"], MODES),
        (
            ["notify", "--all-tenants", "--tenant", TENANT, "--credential-file", "x"],
            MODES,
        ),
        (["recover", "--all-tenants", "--budget-seconds", "0"], "--budget-seconds must be 1"),
        (["recover", "--all-tenants", "--budget-seconds", "3601"], "--budget-seconds must be 1"),
        # Checked once here, rather than refused by every workspace and exiting 0.
        (["recover", "--all-tenants", "--limit", "0"], "--limit must be 1 to 50"),
        (["recover", "--all-tenants", "--limit", "51"], "--limit must be 1 to 50"),
        (["notify", "--all-tenants", "--limit", "51"], "--limit must be 1 to 50"),
        (["recover", "--all-tenants", "--grace-seconds", "59"], "--grace-seconds must be 60"),
        (["recover", "--all-tenants", "--grace-seconds", "86401"], "--grace-seconds must be 60"),
        # Stray flags another mode would read.
        (["recover", "--all-tenants", "--tenant", TENANT], "takes no --tenant"),
        (["recover", "--all-tenants", "--credential-file", "x"], "takes no --tenant"),
        (["notify", "--all-tenants", "--tenant", TENANT], "takes no --tenant"),
        (["notify", "--all-tenants", "--credential-file", "x"], "takes no --tenant"),
        (
            ["recover", "--tenants-file", "jobs.json", "--budget-seconds", "60"],
            "--budget-seconds needs --all-tenants",
        ),
        (
            ["recover", "--tenant", TENANT, "--credential-file", "x", "--budget-seconds", "60"],
            "--budget-seconds needs --all-tenants",
        ),
    ],
)
def test_the_modes_are_exclusive_and_cancellation_needs_an_administrator(
    arguments, message, monkeypatch, capsys
):
    # With neither set, a run the checks let through fails to start and also exits 2, so only
    # the message shows which check refused.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("EXECBOUND_RUNTIME_CONFIG", raising=False)
    monkeypatch.setattr(sys, "argv", ["execbound", *arguments])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize("command", ["recover", "notify"])
def test_a_database_error_exits_non_zero_without_a_traceback(
    db, seeded, tmp_path, monkeypatch, capsys, command
):
    private = tmp_path / "private.json"
    private.write_text(json.dumps(PRIVATE), encoding="utf-8")
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])

    def lost(conn):
        raise OperationalError("SELECT", {}, Exception("connection lost"))

    monkeypatch.setattr(jobs, "check_runtime", lost)
    monkeypatch.setattr(sys, "argv", ["execbound", command, "--all-tenants"])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    assert "refused: database error" in capsys.readouterr().err


def test_the_scheduled_recovery_is_given_the_runtime_and_its_destinations(
    db, seeded, tmp_path, monkeypatch, capsys
):
    tenant = seeded["tenants"][0]
    destination = {
        "destination_id": "soc-email",
        "tenant_id": str(tenant),
        "kind": "email",
        "to": ADDRESS,
    }
    private = tmp_path / "private.json"
    private.write_text(
        json.dumps({**PRIVATE, "notifications": [destination], "mail": MAIL}), encoding="utf-8"
    )
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    calls = []

    def scheduled(db_, tenant_, connections, *, destinations, **kw):
        calls.append((tenant_, connections, destinations))
        return {}

    monkeypatch.setattr(recovery_run, "recover_scheduled", scheduled)
    monkeypatch.setattr(sys, "argv", ["execbound", "recover", "--all-tenants"])
    main()
    assert json.loads(capsys.readouterr().out)["visited"] == 2
    assert sorted(t for t, _, _ in calls) == sorted(seeded["tenants"])
    for _, connections, destinations in calls:
        # The runtime, which derives a sample account's connection, and its whole
        # configuration of destinations, which settling a gone destination's rows reads.
        assert hasattr(connections, "connection")
        assert [(d.destination_id, d.tenant_id) for d in destinations] == [("soc-email", tenant)]


@pytest.mark.parametrize("mode", ["administrator", "map"])
def test_an_administrator_s_recovery_is_given_the_runtime(
    db, admin_engine, tmp_path, monkeypatch, capsys, mode
):
    workspace = empty_workspace(admin_engine, db)
    token = credential(admin_engine, workspace.admin)
    private = tmp_path / "private.json"
    private.write_text(json.dumps(PRIVATE), encoding="utf-8")
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    if mode == "map":
        tokens = tmp_path / "jobs.json"
        tokens.write_text(json.dumps({str(workspace.tenant_id): token}), encoding="ascii")
        arguments = ["--tenants-file", str(tokens)]
    else:
        secret = tmp_path / "admin.token"
        secret.write_text(token, encoding="ascii")
        arguments = ["--tenant", str(workspace.tenant_id), "--credential-file", str(secret)]
    sources = []

    def recover(db_, identity, connections, **kw):
        sources.append(connections)
        return RecoveryCounts()

    monkeypatch.setattr(recovery_run, "recover", recover)
    monkeypatch.setattr(sys, "argv", ["execbound", "recover", *arguments])
    main()
    capsys.readouterr()
    # The runtime, not its map of configured connectors, so a sample account is reached too.
    assert len(sources) == 1 and hasattr(sources[0], "connection")


def test_an_administrator_s_failed_retirement_exits_non_zero_without_a_traceback(
    db, admin_engine, tmp_path, monkeypatch, capsys
):
    """RC13's command, one workspace as its ADMIN, whose retirement then refuses.

    `AssistantError` is not a `ValueError`, so none of the command's other handlers takes it:
    before its own, the refusal ended the command in a traceback. Recovery has committed its
    own work by then; the exit code and the message are what change.
    """
    from execbound.assistant import turns as assistant_turns

    workspace = empty_workspace(admin_engine, db)
    secret = tmp_path / "admin.token"
    secret.write_text(credential(admin_engine, workspace.admin), encoding="ascii")
    private = tmp_path / "private.json"
    private.write_text(json.dumps(PRIVATE), encoding="utf-8")
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])

    def refuse(*args, **kwargs):
        raise AssistantError("ASSISTANT_UNAVAILABLE")

    # `run_recover_command` imports it from `turns` when it runs, so this is the one it calls.
    monkeypatch.setattr(assistant_turns, "retire_turns", refuse)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "execbound",
            "recover",
            "--tenant",
            str(workspace.tenant_id),
            "--credential-file",
            str(secret),
        ],
    )
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    assert "Recovery refused: ASSISTANT_UNAVAILABLE." in capsys.readouterr().err


def test_the_cli_recovers_every_workspace_with_no_credential(
    db, world, admin_engine, live_provider, tmp_path, monkeypatch, capsys
):
    tenant, account = world["identity"].tenant_id, world["account"]
    winner = lost_response(db, world, live_provider)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET changed_at = changed_at - interval '10 minutes' "
                "WHERE execution_id=:e"
            ),
            {"e": winner.view.execution_id},
        )
    config = live_provider.config
    private = tmp_path / "private.json"
    private.write_text(
        json.dumps(
            {
                **PRIVATE,
                "connectors": [
                    {
                        "tenant_id": str(tenant),
                        "account_id": str(account),
                        "origin": config.origin,
                        "dispatch_token": config.dispatch_token,
                        "control_token": config.control_token,
                        "evidence_keys": {k: v.hex() for k, v in config.evidence_keys.items()},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(sys, "argv", ["execbound", "recover", "--all-tenants"])
    main()
    printed = json.loads(capsys.readouterr().out)
    assert printed["failed"] == 0 and printed["visited"] >= 1
    assert printed["tenants"][str(tenant)]["executed"] == 1
    assert state_of(admin_engine, winner.view.execution_id) == "EXECUTED"


def test_sj3_the_notify_command_drains_every_workspace_a_destination_names(
    tmp_path, db, world, connector, monkeypatch, capsys
):
    from test_notification_email import configuration, email

    from execbound import notifications
    from execbound.execution.scheduled import ScheduledActor as Actor

    config = tmp_path / "private.json"
    config.write_text(json.dumps(configuration(world, connector, [email(world)])), encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(config))
    seen = []
    paths = []

    def fake(db_, actor, destinations, **kw):
        seen.append(actor)
        paths.append(kw["approval_path"])
        return {"delivered": 1, "failed": 0, "closed": 0}

    monkeypatch.setattr(notifications, "deliver_pending", fake)
    monkeypatch.setattr(sys, "argv", ["execbound", "notify", "--all-tenants"])
    main()
    printed = json.loads(capsys.readouterr().out)
    tenant = world["identity"].tenant_id
    assert seen == [Actor(tenant)]
    assert printed["visited"] == 1 and printed["tenants"][str(tenant)]["delivered"] == 1
    # No plugin is loaded, so the drain gets no path builder and links to core's own
    # `/approvals/{id}`; the plugin's own tests hold its half.
    assert paths == [None]


def test_the_walk_and_the_scheduler_work_for_an_owner_without_bypass(stack):
    engine, db = stack
    tenants = [uuid4(), uuid4()]
    for tenant in tenants:
        with engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
                {"t": tenant, "n": f"nobypass-{tenant.hex[:8]}"},
            )
    seen: list[UUID] = []
    report = every_workspace(db, lambda t: seen.append(t) or {}, command="recover")
    assert sorted(seen) == sorted(tenants) and report["visited"] == 2
    actor = enlist(db, ScheduledActor(tenants[0]), SystemClock())
    assert actor.principal_id is not None
    from execbound.assistant.turns import retire_due_turns

    assert retire_due_turns(db, actor, SystemClock()) == 0
    with engine.begin() as conn:
        fenced(conn, tenants[0])
        kind = conn.execute(
            text("SELECT kind FROM execbound.principals WHERE principal_id = :p"),
            {"p": actor.principal_id},
        ).scalar_one()
    assert kind == "SYSTEM"
