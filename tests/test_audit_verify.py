# SPDX-License-Identifier: AGPL-3.0-only
"""The scheduled audit-chain verification (#154, #159): AV1 to AV7.

`audit-verify` reads every workspace's chain on the live database again, as the runtime role,
and places each retained checkpoint on it. These tests alter, reorder, delete, truncate and
re-head a real chain in PostgreSQL with the owner, and hold that the pass names the broken
workspace alone, logs `audit.chain_failed`, writes nothing and exits non-zero.
"""

import json
import os
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from test_jobs_schedule import engine as engine
from test_replay_export import fingerprint
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_structured_logging import captured as captured
from test_structured_logging import events

from execbound import audit_verify, jobs, schedule
from execbound.audit import GENESIS, ChainWalk, _event_hash, append_event
from execbound.audit_verify import AuditVerifyError, check_chain, load_checkpoints, verify_all
from execbound.cli import main
from execbound.db import UnsafeDatabaseRole
from execbound.plugins import RUNTIME_CHECK_REFUSAL
from execbound.replay.models import TrustedHead

pytestmark = pytest.mark.integration


def owner(admin_engine, tenant, statement, **values):
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(text(statement), {"t": tenant, **values})


def head_of(admin_engine, tenant) -> tuple[int, str]:
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        row = conn.execute(
            text("SELECT sequence, event_hash FROM execbound.audit_heads WHERE tenant_id = :t"),
            {"t": tenant},
        ).one()
    return int(row[0]), str(row[1])


def hash_at(admin_engine, tenant, sequence) -> str:
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return str(
            conn.execute(
                text(
                    "SELECT event_hash FROM execbound.audit_events "
                    "WHERE tenant_id = :t AND sequence = :s"
                ),
                {"t": tenant, "s": sequence},
            ).scalar_one()
        )


def history(runtime, world, admin_engine) -> int:
    """The world's workspace with a few events more than its setup left: a held request."""
    runtime.execute(world["identity"], request(world).model_dump_json().encode())
    sequence, _ = head_of(admin_engine, world["identity"].tenant_id)
    assert sequence >= 4
    return sequence


def checkpoint(tmp_path, name, tenant, sequence, event_hash):
    path = tmp_path / name
    head = TrustedHead(tenant_id=tenant, sequence=sequence, event_hash=event_hash)
    path.write_text(head.model_dump_json() + "\n", encoding="utf-8")
    return path


def test_av1_every_intact_chain_verifies_and_the_pass_writes_nothing(
    db, world, runtime, admin_engine, seeded, captured
):
    sequence = history(runtime, world, admin_engine)
    before = fingerprint(admin_engine)
    report = verify_all(db, {})
    assert fingerprint(admin_engine) == before
    assert (report["broken"], report["failed"], report["not_reached"]) == (0, 0, 0)
    assert report["verified"] == report["visited"] == len(seeded["tenants"])
    assert report["events"] >= sequence
    # Only a workspace whose chain failed is named, so an intact run lists none.
    assert report["tenants"] == {}
    assert events(captured, "audit.chain_failed") == []
    assert not audit_verify.failing(report)


def test_av1_a_chain_is_read_a_page_at_a_time_and_a_late_break_is_found_where_it_is(
    db, world, runtime, admin_engine, monkeypatch
):
    sequence = history(runtime, world, admin_engine)
    tenant = world["identity"].tenant_id
    monkeypatch.setattr(audit_verify, "PAGE_SIZE", 2)
    assert check_chain(db, tenant) == audit_verify.ChainCheck(sequence)
    owner(
        admin_engine,
        tenant,
        "UPDATE execbound.audit_events SET payload = payload || '{\"tampered\": true}' "
        "WHERE tenant_id = :t AND sequence = :s",
        s=sequence - 1,
    )
    assert check_chain(db, tenant) == audit_verify.ChainCheck(
        sequence - 2, "CHAIN_BROKEN", sequence - 1
    )


def reorder(admin_engine, tenant):
    """Swap events 2 and 3, through a sequence no chain reaches (the column refuses below 1)."""
    move = (
        "UPDATE execbound.audit_events SET sequence = :to WHERE tenant_id = :t AND sequence = :at"
    )
    for at, to in ((2, 1_000_000), (3, 2), (1_000_000, 3)):
        owner(admin_engine, tenant, move, at=at, to=to)


# Each way a chain can be damaged, and the sequence the pass reports it at.
DAMAGE = {
    "altered": (
        lambda engine, tenant, head: owner(
            engine,
            tenant,
            "UPDATE execbound.audit_events SET payload = payload || '{\"tampered\": true}' "
            "WHERE tenant_id = :t AND sequence = 2",
        ),
        lambda head: 2,
    ),
    "reordered": (lambda engine, tenant, head: reorder(engine, tenant), lambda head: 2),
    "interior deleted": (
        lambda engine, tenant, head: owner(
            engine,
            tenant,
            "DELETE FROM execbound.audit_events WHERE tenant_id = :t AND sequence = 2",
        ),
        lambda head: 2,
    ),
    "tail truncated": (
        lambda engine, tenant, head: owner(
            engine,
            tenant,
            "DELETE FROM execbound.audit_events WHERE tenant_id = :t AND sequence = :s",
            s=head,
        ),
        lambda head: head,
    ),
    "head substituted": (
        lambda engine, tenant, head: owner(
            engine,
            tenant,
            "UPDATE execbound.audit_heads SET event_hash = :h WHERE tenant_id = :t",
            h="f" * 64,
        ),
        lambda head: head,
    ),
}


def rewrite_from(admin_engine, tenant, at, *, relink=False, renumber=False):
    """Rewrite the chain from event `at` as a writer who can hash would: break one link
    (`relink`) or shift every later sequence by one (`renumber`), then re-link and re-hash
    everything after and move the head, so only the one check that change breaks can find it."""
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        rows = [
            dict(row)
            for row in conn.execute(
                text("SELECT * FROM execbound.audit_events WHERE tenant_id = :t ORDER BY sequence"),
                {"t": tenant},
            ).mappings()
        ]
        conn.execute(
            text("DELETE FROM execbound.audit_events WHERE tenant_id = :t AND sequence >= :s"),
            {"t": tenant, "s": at},
        )
        previous = rows[at - 2]["event_hash"] if at > 1 else GENESIS
        for row in rows[at - 1 :]:
            row["previous_hash"] = "a" * 64 if relink and row is rows[at - 1] else previous
            row["sequence"] += 1 if renumber else 0
            row["event_hash"] = previous = _event_hash(row)
            conn.execute(
                text(
                    "INSERT INTO execbound.audit_events (tenant_id, sequence, event_id, actor_id, "
                    "kind, occurred_at, payload, previous_hash, event_hash, space_id) VALUES "
                    "(:tenant_id, :sequence, :event_id, :actor_id, :kind, :occurred_at, "
                    "CAST(:payload AS jsonb), :previous_hash, :event_hash, :space_id)"
                ),
                {**row, "payload": json.dumps(row["payload"])},
            )
        conn.execute(
            text(
                "UPDATE execbound.audit_heads SET sequence = :s, event_hash = :h "
                "WHERE tenant_id = :t"
            ),
            {"t": tenant, "s": rows[-1]["sequence"], "h": previous},
        )


@pytest.mark.parametrize("change", ["relink", "renumber"])
def test_av2_a_rewrite_that_re_hashes_everything_after_still_fails_at_the_change(
    db, world, runtime, admin_engine, change
):
    """Every hash after the change is valid, so a broken link is found only by the link check
    and a shifted sequence only by the sequence check."""
    history(runtime, world, admin_engine)
    tenant = world["identity"].tenant_id
    rewrite_from(admin_engine, tenant, 2, **{change: True})
    check = check_chain(db, tenant)
    assert (check.problem, check.sequence) == ("CHAIN_BROKEN", 2)


@pytest.mark.parametrize("damage", sorted(DAMAGE))
def test_av2_a_damaged_chain_fails_alone_and_is_logged_with_its_code_and_sequence(
    db, world, runtime, admin_engine, seeded, captured, damage
):
    sequence = history(runtime, world, admin_engine)
    tenant = world["identity"].tenant_id
    harm, expected = DAMAGE[damage]
    harm(admin_engine, tenant, sequence)
    report = verify_all(db, {})
    assert report["broken"] == 1 and audit_verify.failing(report)
    # The other workspace still verified: one broken chain hides nobody else's.
    assert report["verified"] == len(seeded["tenants"]) - 1
    assert report["tenants"] == {
        str(tenant): {"broken": 1, "problem": "CHAIN_BROKEN", "sequence": expected(sequence)}
    }
    [logged] = events(captured, "audit.chain_failed")
    assert logged["level"] == "ERROR"
    assert (logged["tenant_id"], logged["code"], logged["sequence"]) == (
        str(tenant),
        "CHAIN_BROKEN",
        expected(sequence),
    )
    assert set(logged) == {"ts", "level", "event", "command", "tenant_id", "code", "sequence"}
    assert logged["code"] in audit_verify.PROBLEMS


def test_av3_retained_checkpoints_are_placed_on_the_chain(
    db, world, runtime, admin_engine, tmp_path
):
    sequence = history(runtime, world, admin_engine)
    tenant = world["identity"].tenant_id
    _, head_hash = head_of(admin_engine, tenant)
    current = checkpoint(tmp_path, "current.head.json", tenant, sequence, head_hash)
    older = checkpoint(tmp_path, "older.head.json", tenant, 1, hash_at(admin_engine, tenant, 1))
    genesis = checkpoint(tmp_path, "genesis.head.json", tenant, 0, GENESIS)
    # A workspace may keep several heads from different times; every one is placed.
    held = load_checkpoints([current, older, genesis])
    assert [head.sequence for head in held[tenant]] == [0, 1, sequence]
    assert check_chain(db, tenant, held[tenant]).problem is None
    report = verify_all(db, held)
    assert report["broken"] == 0 and report["checkpoints"] == 3

    future = checkpoint(tmp_path, "future.head.json", tenant, sequence + 5, head_hash)
    assert check_chain(db, tenant, load_checkpoints([future])[tenant]) == (
        audit_verify.ChainCheck(sequence, "BEHIND_CHECKPOINT", sequence + 1)
    )
    forged = checkpoint(tmp_path, "forged.head.json", tenant, 2, "e" * 64)
    assert check_chain(db, tenant, load_checkpoints([older, forged])[tenant]) == (
        audit_verify.ChainCheck(sequence, "DIVERGES_FROM_CHECKPOINT", 2)
    )


def test_av3_a_consistent_truncation_verifies_alone_and_fails_against_a_retained_head(
    db, world, runtime, admin_engine, tmp_path, captured
):
    """The readiness pack's first gap, shown: a writer who removes the tail and moves the head
    back with it leaves a chain that verifies. Only the head retained before shows the loss."""
    sequence = history(runtime, world, admin_engine)
    tenant = world["identity"].tenant_id
    _, head_hash = head_of(admin_engine, tenant)
    retained = checkpoint(tmp_path, "retained.head.json", tenant, sequence, head_hash)
    earlier = hash_at(admin_engine, tenant, sequence - 1)
    owner(
        admin_engine,
        tenant,
        "DELETE FROM execbound.audit_events WHERE tenant_id = :t AND sequence = :s",
        s=sequence,
    )
    owner(
        admin_engine,
        tenant,
        "UPDATE execbound.audit_heads SET sequence = :s, event_hash = :h WHERE tenant_id = :t",
        s=sequence - 1,
        h=earlier,
    )
    assert check_chain(db, tenant).problem is None
    report = verify_all(db, load_checkpoints([retained]))
    assert report["tenants"][str(tenant)]["problem"] == "BEHIND_CHECKPOINT"
    [logged] = events(captured, "audit.chain_failed")
    assert (logged["code"], logged["sequence"]) == ("BEHIND_CHECKPOINT", sequence)


def test_av2_rows_past_the_stored_head_break_the_chain_at_the_first_of_them(
    db, world, runtime, admin_engine
):
    """A head moved back one with its event left in place: every row still verifies, and the
    chain does not end where the database says it does."""
    sequence = history(runtime, world, admin_engine)
    tenant = world["identity"].tenant_id
    owner(
        admin_engine,
        tenant,
        "UPDATE execbound.audit_heads SET sequence = :s, event_hash = :h WHERE tenant_id = :t",
        s=sequence - 1,
        h=hash_at(admin_engine, tenant, sequence - 1),
    )
    assert check_chain(db, tenant) == audit_verify.ChainCheck(sequence, "CHAIN_BROKEN", sequence)


def test_av1_events_appended_while_a_chain_is_read_do_not_break_it(
    db, world, runtime, admin_engine, monkeypatch
):
    """The head and every page are read in one snapshot: an event a gateway commits half way
    through the walk is not seen, so the chain still ends at the head read first."""
    sequence = history(runtime, world, admin_engine)
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    monkeypatch.setattr(audit_verify, "PAGE_SIZE", 2)

    class Interrupted(ChainWalk):
        def add(self, event):
            if self.count == 1:
                with db.transaction(tenant) as conn:
                    append_event(conn, tenant, actor, "audit.verify_probe", {})
            return super().add(event)

    monkeypatch.setattr(audit_verify, "ChainWalk", Interrupted)
    assert check_chain(db, tenant) == audit_verify.ChainCheck(sequence)
    assert head_of(admin_engine, tenant)[0] == sequence + 1


def test_av3_genesis_divergence_and_a_broken_chain_outrank_the_checkpoints(
    db, world, runtime, admin_engine, tmp_path
):
    history(runtime, world, admin_engine)
    tenant = world["identity"].tenant_id
    wrong_genesis = checkpoint(tmp_path, "g.head.json", tenant, 0, "b" * 64)
    assert check_chain(db, tenant, load_checkpoints([wrong_genesis])[tenant]) == (
        audit_verify.ChainCheck(head_of(admin_engine, tenant)[0], "DIVERGES_FROM_CHECKPOINT", 0)
    )
    first = checkpoint(tmp_path, "1.head.json", tenant, 1, hash_at(admin_engine, tenant, 1))
    owner(
        admin_engine,
        tenant,
        "UPDATE execbound.audit_events SET payload = payload || '{\"tampered\": true}' "
        "WHERE tenant_id = :t AND sequence = 2",
    )
    assert check_chain(db, tenant, load_checkpoints([first])[tenant]).problem == "CHAIN_BROKEN"


def test_av3_a_retained_head_for_a_workspace_the_directory_no_longer_holds_fails(
    db, world, runtime, admin_engine, seeded, tmp_path, captured
):
    """A whole history removed with its workspace leaves nothing to walk; the head retained
    for it is what shows the loss, once the run has reached every workspace."""
    history(runtime, world, admin_engine)
    gone = uuid4()
    held = load_checkpoints([checkpoint(tmp_path, "gone.head.json", gone, 3, "a" * 64)])
    report = verify_all(db, held)
    assert report["broken"] == 1 and report["checkpoints_unplaced"] == 0
    assert report["visited"] == len(seeded["tenants"]) + 1
    assert report["tenants"][str(gone)] == {
        "broken": 1,
        "problem": "BEHIND_CHECKPOINT",
        "sequence": 1,
    }
    [logged] = events(captured, "audit.chain_failed")
    assert (logged["tenant_id"], logged["code"]) == (str(gone), "BEHIND_CHECKPOINT")
    # Named workspaces only: the other heads are counted as not placed, never failed.
    named = verify_all(db, held, tenants=[world["identity"].tenant_id])
    assert (named["broken"], named["checkpoints_unplaced"]) == (0, 1)


def test_av5_a_workspace_the_directory_does_not_hold_is_not_reported_as_verified(db, seeded):
    unknown = uuid4()
    report = verify_all(db, {}, tenants=[unknown])
    assert (report["verified"], report["broken"]) == (0, 1)
    assert report["tenants"][str(unknown)]["problem"] == "UNKNOWN_TENANT"
    assert audit_verify.failing(report)


def test_av4_checkpoint_files_are_strict_and_read_only_from_head_files(tmp_path, seeded):
    tenant = seeded["tenants"][0]
    (tmp_path / "notes.txt").write_text("kept beside the heads", encoding="utf-8")
    first = checkpoint(tmp_path, "a.head.json", tenant, 3, "a" * 64)
    assert audit_verify.checkpoint_files(tmp_path) == [first]
    # The same head twice is one head; two hashes at one sequence cannot both be history.
    checkpoint(tmp_path, "b.head.json", tenant, 3, "a" * 64)
    assert len(load_checkpoints(audit_verify.checkpoint_files(tmp_path))[tenant]) == 1
    checkpoint(tmp_path, "c.head.json", tenant, 3, "b" * 64)
    with pytest.raises(AuditVerifyError) as conflicting:
        load_checkpoints(audit_verify.checkpoint_files(tmp_path))
    assert conflicting.value.code == "CONFLICTING_CHECKPOINTS"
    broken = tmp_path / "broken.head.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(AuditVerifyError) as invalid:
        load_checkpoints([broken])
    assert invalid.value.code == "INVALID_CHECKPOINT"
    with pytest.raises(AuditVerifyError) as unreadable:
        audit_verify.checkpoint_files(tmp_path / "absent")
    assert unreadable.value.code == "CHECKPOINTS_UNREADABLE"
    dangling = tmp_path / "links"
    dangling.mkdir()
    (dangling / "lost.head.json").symlink_to(tmp_path / "nowhere.head.json")
    assert audit_verify.checkpoint_files(dangling) == [dangling / "lost.head.json"]
    with pytest.raises(AuditVerifyError) as lost:
        load_checkpoints(audit_verify.checkpoint_files(dangling))
    assert lost.value.code == "INVALID_CHECKPOINT"


def test_av4_too_many_checkpoint_files_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_verify, "MAX_CHECKPOINT_FILES", 2)
    for name in ("a", "b", "c"):
        checkpoint(tmp_path, f"{name}.head.json", uuid4(), 1, "a" * 64)
    with pytest.raises(AuditVerifyError) as refused:
        audit_verify.checkpoint_files(tmp_path)
    assert refused.value.code == "TOO_MANY_CHECKPOINTS"


def test_av5_an_inactive_workspace_is_verified_and_the_other_passes_still_skip_it(
    db, world, runtime, admin_engine, seeded
):
    history(runtime, world, admin_engine)
    tenant = world["identity"].tenant_id
    owner(admin_engine, tenant, "UPDATE execbound.tenants SET active = false WHERE tenant_id = :t")
    owner(
        admin_engine,
        tenant,
        "UPDATE execbound.audit_events SET payload = payload || '{\"tampered\": true}' "
        "WHERE tenant_id = :t AND sequence = 1",
    )
    report = verify_all(db, {})
    assert report["inactive"] == 0 and report["broken"] == 1
    assert report["tenants"][str(tenant)]["problem"] == "CHAIN_BROKEN"
    # A pass that acts keeps skipping it.
    acting = jobs.every_workspace(db, lambda t: {}, command="recover")
    assert acting["inactive"] == 1


def test_av5_a_workspace_whose_chain_cannot_be_read_fails_the_run(db, seeded, monkeypatch):
    first = seeded["tenants"][0]
    real = audit_verify.check_chain

    def unreadable(database, tenant, checkpoints=()):
        if tenant == first:
            raise ValueError("unreadable")
        return real(database, tenant, checkpoints)

    monkeypatch.setattr(audit_verify, "check_chain", unreadable)
    report = verify_all(db, {})
    assert (report["failed"], report["broken"]) == (1, 0)
    assert report["tenants"][str(first)] == {"skipped": "DEPENDENCY_UNAVAILABLE"}
    assert audit_verify.failing(report)


def run_cli(monkeypatch, *arguments):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(sys, "argv", ["execbound", "audit-verify", *arguments])
    try:
        main()
    except SystemExit as exc:
        return exc.code
    return 0


def test_av6_the_command_exits_0_when_every_chain_verifies_and_1_when_one_does_not(
    db, world, runtime, admin_engine, seeded, monkeypatch, capsys, tmp_path
):
    sequence = history(runtime, world, admin_engine)
    tenant = world["identity"].tenant_id
    _, head_hash = head_of(admin_engine, tenant)
    checkpoint(tmp_path, "t.head.json", tenant, sequence, head_hash)
    assert run_cli(monkeypatch, "--all-tenants", "--checkpoints", str(tmp_path)) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["verified"] == len(seeded["tenants"]) and printed["checkpoints"] == 1

    assert run_cli(monkeypatch, "--tenant", str(tenant)) == 0
    assert json.loads(capsys.readouterr().out)["visited"] == 1

    owner(
        admin_engine,
        tenant,
        "UPDATE execbound.audit_events SET payload = payload || '{\"tampered\": true}' "
        "WHERE tenant_id = :t AND sequence = 1",
    )
    assert run_cli(monkeypatch, "--all-tenants") == 1
    out, err = capsys.readouterr()
    assert json.loads(out)["broken"] == 1
    assert "Audit verification failed: 1 chain(s) did not verify" in err


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ((), "give --all-tenants or --tenant"),
        (("--all-tenants", "--tenant", str(UUID(int=1))), "give --all-tenants or --tenant"),
        (("--all-tenants", "--budget-seconds", "0"), "--budget-seconds must be 1 to 3600"),
    ],
)
def test_av6_the_modes_are_exclusive_and_the_budget_bounded(
    monkeypatch, capsys, arguments, message
):
    assert run_cli(monkeypatch, *arguments) == 2
    assert message in capsys.readouterr().err


def test_av6_a_checkpoint_it_cannot_use_stops_the_run_before_the_database_is_read(
    db, seeded, monkeypatch, capsys, tmp_path
):
    broken = tmp_path / "broken.head.json"
    broken.write_text("{", encoding="utf-8")

    def never(conn):
        raise AssertionError("the database was read")

    monkeypatch.setattr(jobs, "check_runtime", never)
    assert run_cli(monkeypatch, "--all-tenants", "--checkpoint", str(broken)) == 2
    assert "Audit verification refused: INVALID_CHECKPOINT." in capsys.readouterr().err


def test_av6_a_schema_mismatch_or_a_database_error_exits_2_without_a_traceback(
    db, seeded, monkeypatch, capsys
):
    def mismatch(conn):
        raise UnsafeDatabaseRole("Database revision mismatch")

    monkeypatch.setattr(jobs, "check_runtime", mismatch)
    assert run_cli(monkeypatch, "--all-tenants") == 2
    err = capsys.readouterr().err
    assert RUNTIME_CHECK_REFUSAL in err and "Traceback" not in err

    from sqlalchemy.exc import OperationalError

    def lost(conn):
        raise OperationalError("SELECT", {}, Exception("connection lost"))

    monkeypatch.setattr(jobs, "check_runtime", lost)
    assert run_cli(monkeypatch, "--all-tenants") == 2
    assert "Audit verification refused: database error." in capsys.readouterr().err

    from execbound.execution.models import ExecutionError

    def unsafe(conn):
        raise ExecutionError("UNSAFE_JOB_POLICY")

    monkeypatch.setattr(jobs, "check_runtime", lambda conn: None)
    monkeypatch.setattr(jobs, "check_directory_policy", unsafe)
    assert run_cli(monkeypatch, "--all-tenants") == 2
    assert "Audit verification refused: UNSAFE_JOB_POLICY." in capsys.readouterr().err


def test_av7_the_jobs_service_runs_it_hourly_on_its_own_lock_with_the_checkpoints(tmp_path):
    assert schedule.AUDIT_VERIFY in schedule.JOBS
    assert (schedule.AUDIT_VERIFY.interval, schedule.AUDIT_VERIFY.key) == (3600, 9_007)
    every = (*schedule.JOBS, schedule.INVITATIONS, schedule.WEEKLY_SUMMARY, schedule.COLLECT)
    assert len({job.key for job in every}) == len(every)
    # Scheduled whatever else is configured: verification needs no destination, relay or key.
    assert schedule.AUDIT_VERIFY in schedule.jobs_for(False, notify=False)
    absent = schedule.argv(schedule.AUDIT_VERIFY, tmp_path, checkpoints=tmp_path / "absent")
    assert absent == [sys.executable, "-m", "execbound.cli", "audit-verify", "--all-tenants"]
    present = schedule.argv(schedule.AUDIT_VERIFY, tmp_path, checkpoints=tmp_path)
    assert present[-2:] == ["--checkpoints", str(tmp_path)]
    assert Path("/srv/private/checkpoints") == schedule.DEFAULT_CHECKPOINTS
    assert schedule.AUDIT_VERIFY.own_log
    assert not any(job.own_log for job in every if job is not schedule.AUDIT_VERIFY)


def test_av7_the_scheduler_starts_it_with_its_checkpoints_and_its_lines_reach_the_log_whole(
    engine, tmp_path, monkeypatch, capfd
):
    """The job's own lines go straight to the service's log, even when it is stopped at its
    timeout; another job's standard error still reaches the log only as a failure's tail."""
    passed = []
    commands = {
        "audit-verify": "import sys, time; print('chain line', file=sys.stderr, flush=True); "
        "time.sleep(30)",
        "recover": "import sys; print('quiet line', file=sys.stderr)",
    }

    def fake(job, state, *, limit=50, collector=None, checkpoints=None):
        passed.append(checkpoints)
        return [sys.executable, "-c", commands[job.name]]

    monkeypatch.setattr(schedule, "argv", fake)
    state = tmp_path / "state"
    state.mkdir()
    (state / schedule.JOBS_FILE).write_text("{}", encoding="utf-8")
    jobs_run = (
        schedule.Job("audit-verify", 77_031, 900, schedule.JOBS_FILE, own_log=True),
        schedule.Job("recover", 77_032, 900, schedule.JOBS_FILE),
    )
    scheduler = schedule.Scheduler(
        engine, state=state, checkpoints=tmp_path, jobs=jobs_run, timeout=2
    )
    try:
        outcomes = scheduler.cycle(wait=True)
    finally:
        scheduler.close()
    assert passed == [tmp_path, tmp_path]
    assert outcomes == {"audit-verify": 124, "recover": 0}
    err = capfd.readouterr().err
    assert "chain line" in err and "quiet line" not in err
