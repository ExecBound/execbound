# SPDX-License-Identifier: AGPL-3.0-only
"""Restore verification proves chains, checkpoints and stores from reads alone."""

import json
import os
import sqlite3
from contextlib import contextmanager
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.engine import URL
from test_replay_export import fingerprint
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound import recovery
from execbound.audit import GENESIS, append_event
from execbound.replay.models import TrustedHead


def head_of(admin_engine, tenant):
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        row = conn.execute(
            text("SELECT sequence, event_hash FROM execbound.audit_heads WHERE tenant_id=:t"),
            {"t": tenant},
        ).one()
    return int(row[0]), str(row[1])


def checkpoint_file(tmp_path, name, tenant, sequence, event_hash):
    path = tmp_path / name
    path.write_text(
        TrustedHead(tenant_id=tenant, sequence=sequence, event_hash=event_hash).model_dump_json()
        + "\n",
        encoding="utf-8",
    )
    return path


def owner_url():
    return os.environ["TEST_MIGRATION_DATABASE_URL"]


def test_intact_history_matches_checkpoints_and_live_without_writes(
    db, world, runtime, admin_engine, tmp_path
):
    tenant = world["identity"].tenant_id
    pending = runtime.execute(world["identity"], request(world).model_dump_json().encode())
    assert pending.state == "PENDING_APPROVAL"
    sequence, event_hash = head_of(admin_engine, tenant)
    assert sequence > 0
    current = checkpoint_file(tmp_path, "current.head.json", tenant, sequence, event_hash)
    before = fingerprint(admin_engine)

    report = recovery.verify_restore(
        restored_url=owner_url(),
        checkpoint_paths=[current],
        live_url=owner_url(),
    )
    assert report["ok"], report["problems"]
    [check] = report["tenants"]
    assert check["tenant_id"] == str(tenant)
    assert check["events"] == sequence and check["head_sequence"] == sequence
    assert check["chain_ok"] is True and check["unresolved_executions"] == 0
    assert check["checkpoint"] == "MATCHES_CHECKPOINT" and check["live"] == "MATCHES_LIVE"
    assert fingerprint(admin_engine) == before

    # An older checkpoint still sits on the chain; the restore is simply ahead of it.
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first_hash = conn.execute(
            text("SELECT event_hash FROM execbound.audit_events WHERE tenant_id=:t AND sequence=1"),
            {"t": tenant},
        ).scalar_one()
    older = checkpoint_file(tmp_path, "older.head.json", tenant, 1, first_hash)
    genesis = checkpoint_file(tmp_path, "genesis.head.json", tenant, 0, GENESIS)
    for path, expected in ((older, "AHEAD_OF_CHECKPOINT"), (genesis, "AHEAD_OF_CHECKPOINT")):
        report = recovery.verify_restore(restored_url=owner_url(), checkpoint_paths=[path])
        assert report["ok"] and report["tenants"][0]["checkpoint"] == expected


def test_divergent_or_future_checkpoints_and_tampering_fail(
    db, world, runtime, admin_engine, tmp_path
):
    tenant = world["identity"].tenant_id
    runtime.execute(world["identity"], request(world).model_dump_json().encode())
    sequence, event_hash = head_of(admin_engine, tenant)
    future = checkpoint_file(tmp_path, "future.head.json", tenant, sequence + 5, event_hash)
    report = recovery.verify_restore(restored_url=owner_url(), checkpoint_paths=[future])
    assert not report["ok"]
    assert report["tenants"][0]["checkpoint"] == "BEHIND_CHECKPOINT"
    assert f"tenant:{tenant}:BEHIND_CHECKPOINT" in report["problems"]

    forged = checkpoint_file(tmp_path, "forged.head.json", tenant, sequence, "f" * 64)
    report = recovery.verify_restore(restored_url=owner_url(), checkpoint_paths=[forged])
    assert report["tenants"][0]["checkpoint"] == "DIVERGES_FROM_CHECKPOINT"
    assert not report["ok"]

    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "UPDATE execbound.audit_events SET payload = payload || '{\"tampered\": true}' "
                "WHERE tenant_id=:t AND sequence=1"
            ),
            {"t": tenant},
        )
    report = recovery.verify_restore(restored_url=owner_url(), tenants=[tenant])
    assert report["tenants"][0]["chain_ok"] is False
    assert f"tenant:{tenant}:CHAIN_BROKEN" in report["problems"]


def test_checkpoint_files_are_strict_and_consistent(tmp_path, seeded):
    tenant = uuid4()
    bad = tmp_path / "bad.head.json"
    bad.write_text(f'{{"tenant_id": "{tenant}", "sequence": -1, "event_hash": "0"}}')
    with pytest.raises(recovery.RecoveryError) as invalid:
        recovery.load_checkpoints([bad])
    assert invalid.value.code == "INVALID_CHECKPOINT"
    one = checkpoint_file(tmp_path, "one.head.json", tenant, 1, "a" * 64)
    two = checkpoint_file(tmp_path, "two.head.json", tenant, 2, "b" * 64)
    with pytest.raises(recovery.RecoveryError) as conflicting:
        recovery.load_checkpoints([one, two])
    assert conflicting.value.code == "CONFLICTING_CHECKPOINTS"
    assert recovery.load_checkpoints([one, one])[tenant].sequence == 1


def test_provider_store_checks(tmp_path):
    intact = tmp_path / "endpoint.sqlite3"
    with sqlite3.connect(intact) as conn:
        conn.execute("CREATE TABLE journal (command_hash TEXT PRIMARY KEY, record_json TEXT)")
        conn.execute("INSERT INTO journal VALUES ('a', '{}')")
    check = recovery.check_provider_store(intact)
    assert check.integrity == "ok" and check.journal_records == 1 and not check.problems

    without = tmp_path / "other.sqlite3"
    with sqlite3.connect(without) as conn:
        conn.execute("CREATE TABLE resources (id TEXT)")
    assert recovery.check_provider_store(without).problems == ["STORE_WITHOUT_JOURNAL"]

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a database at all" * 100)
    assert "STORE_UNREADABLE" in recovery.check_provider_store(corrupt).problems


def test_main_writes_an_exclusive_report_and_signals_failure(
    db, world, runtime, admin_engine, tmp_path, monkeypatch, capsys
):
    tenant = world["identity"].tenant_id
    runtime.execute(world["identity"], request(world).model_dump_json().encode())
    sequence, event_hash = head_of(admin_engine, tenant)
    checkpoint = checkpoint_file(tmp_path, "head.json", tenant, sequence, event_hash)
    monkeypatch.setenv("MIGRATION_DATABASE_URL", owner_url())
    database = recovery.database_url(owner_url()).database
    output = tmp_path / "report.json"
    code = recovery.main(
        [
            "--restored-database",
            database,
            "--compare-live",
            "--checkpoint",
            str(checkpoint),
            "--output",
            str(output),
        ]
    )
    printed = capsys.readouterr()
    assert code == 0 and "passed" in printed.out
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["ok"] and report["tenants"][0]["live"] == "MATCHES_LIVE"
    assert owner_url() not in output.read_text(encoding="utf-8") + printed.out + printed.err
    if os.name != "nt":
        assert oct(output.stat().st_mode & 0o777) == "0o600"

    assert recovery.main(["--restored-database", database, "--output", str(output)]) == 2
    assert "report file unavailable" in capsys.readouterr().err

    forged = checkpoint_file(tmp_path, "forged.json", tenant, sequence, "e" * 64)
    code = recovery.main(
        [
            "--restored-database",
            database,
            "--checkpoint",
            str(forged),
            "--output",
            str(tmp_path / "r2.json"),
        ]
    )
    assert code == 2 and "DIVERGES_FROM_CHECKPOINT" in capsys.readouterr().out

    with pytest.raises(recovery.RecoveryError) as bad_name:
        recovery.with_database(owner_url(), "a/b")
    assert bad_name.value.code == "INVALID_DATABASE"
    assert UUID(report["tenants"][0]["tenant_id"]) == tenant


def synthetic_url(driver: str, *, host: str = "restore.example.test", **parts) -> str:
    """A connection URL as an operator would type it, password included, built from its parts
    so no connection string is written out in this file."""
    values = {"username": "restorer", "password": "synthetic", "database": "restored"}
    return URL.create(driver, host=host, **{**values, **parts}).render_as_string(
        hide_password=False
    )


# Each carries the same password and host, so one check covers every way a URL can be refused:
# not parsed at all, a port that is not a number, the wrong driver, and a remote server without
# verified TLS.
MALFORMED_URLS = (
    "restorer:synthetic@restore.example.test not a url",
    synthetic_url("postgresql+psycopg", database=None) + ":port/restored",
    synthetic_url("postgresql"),
    synthetic_url("postgresql+psycopg"),
)
# The ids name each case, so no URL is written into a test report either.
MALFORMED_IDS = ("not-a-url", "port-not-a-number", "wrong-driver", "remote-without-tls")


@pytest.mark.parametrize("url", MALFORMED_URLS, ids=MALFORMED_IDS)
def test_a_malformed_restored_url_is_refused_by_code_and_never_echoed(tmp_path, capsys, url):
    """A `--restored-url` the connection rules refuse stops the verifier with a code, before any
    connection, and nothing it prints holds any part of the URL, which can carry a password."""
    output = tmp_path / "report.json"
    assert recovery.main(["--restored-url", url, "--output", str(output)]) == 2
    printed = capsys.readouterr()
    assert printed.err == "Recovery verification stopped: INVALID_RESTORED_URL.\n"
    assert printed.out == ""
    assert not output.exists()


@pytest.mark.parametrize("url", MALFORMED_URLS, ids=MALFORMED_IDS)
def test_a_malformed_live_url_to_compare_with_is_refused_by_code_and_never_echoed(
    tmp_path, capsys, monkeypatch, url
):
    """`--compare-live` reads `MIGRATION_DATABASE_URL`, which the connection rules can refuse
    as well: `INVALID_DATABASE`, which already names that variable, and never the URL."""
    monkeypatch.setenv("MIGRATION_DATABASE_URL", url)
    output = tmp_path / "report.json"
    restored = synthetic_url("postgresql+psycopg", host="127.0.0.1", port=1)
    argv = ["--restored-url", restored, "--compare-live", "--output", str(output)]
    assert recovery.main(argv) == 2
    printed = capsys.readouterr()
    assert printed.err == "Recovery verification stopped: INVALID_DATABASE.\n"
    assert printed.out == ""
    assert not output.exists()


# The restored fence, read as the runtime role (#155). The test database stands in for the
# restored copy, as above, and `TEST_DATABASE_URL` is the runtime role on it.


def runtime_url():
    return os.environ["TEST_DATABASE_URL"]


def both_recorded(db, world, runtime, seeded):
    """Both seeded tenants with history: the world's executes once, and the other records one
    event of its own, so each has rows for the other's fence to keep out."""
    runtime.execute(world["identity"], request(world).model_dump_json().encode())
    tenant = world["identity"].tenant_id
    other = next(candidate for candidate in seeded["tenants"] if candidate != tenant)
    actor = seeded["principals"][seeded["tenants"].index(other)]
    with db.transaction(other) as conn:
        append_event(conn, other, actor, "test.recorded", {"index": 0})
    return tenant, other


@contextmanager
def policy(admin_engine, statement, table):
    """One extra policy on a table of the test database for the length of a block, dropped
    after it whatever happens, so the catalog the other tests read is never left changed."""
    with admin_engine.begin() as conn:
        conn.execute(text(statement))
    try:
        yield
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f"DROP POLICY IF EXISTS restore_probe ON execbound.{table}"))


def fences(report):
    return {UUID(row["tenant_id"]): row["fence"] for row in report["tenants"]}


def test_the_runtime_role_reads_each_restored_tenant_behind_its_own_fence(
    db, world, runtime, admin_engine, seeded
):
    tenant, other = both_recorded(db, world, runtime, seeded)
    before = fingerprint(admin_engine)
    report = recovery.verify_restore(
        restored_url=owner_url(), tenants=[tenant, other], runtime_url=runtime_url()
    )
    assert report["ok"], report["problems"]
    assert fences(report) == {tenant: "HOLDS", other: "HOLDS"}
    assert fingerprint(admin_engine) == before
    # Without the runtime's URL the fence is not read at all, and says so.
    report = recovery.verify_restore(restored_url=owner_url(), tenants=[tenant, other])
    assert fences(report) == {tenant: "NOT_CHECKED", other: "NOT_CHECKED"}


def a_third_tenant(admin_engine):
    """A workspace the copy holds beside the two seeded ones, with no history, so no chain
    head and no checkpoint anyone could have retained for it."""
    third = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, 'Synthetic 2')"),
            {"t": third},
        )
    return third


def test_the_fence_check_reads_every_tenant_the_copy_holds_not_only_the_named_ones(
    db, world, runtime, admin_engine, seeded, tmp_path
):
    """After a restore every tenant's fence is checked (#155). A restore is verified with the
    checkpoints someone retained, and a workspace with no history has none to name; a policy
    that lets that workspace alone read the others is seen only under its own fence. So the
    fence check reads every tenant the copy holds, its workspaces as well as its chains'
    heads, the named ones first, and not only those."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    third = a_third_tenant(admin_engine)
    named = [
        checkpoint_file(tmp_path, f"{index}.head.json", each, *head_of(admin_engine, each))
        for index, each in enumerate((tenant, other))
    ]
    report = recovery.verify_restore(
        restored_url=owner_url(), checkpoint_paths=named, runtime_url=runtime_url()
    )
    assert report["ok"], report["problems"]
    assert [UUID(row["tenant_id"]) for row in report["tenants"]] == [tenant, other, third]
    assert fences(report) == {tenant: "HOLDS", other: "HOLDS", third: "HOLDS"}
    unnamed = report["tenants"][2]
    assert (unnamed["events"], unnamed["checkpoint"]) == (0, "NO_CHECKPOINT")
    only_third = (
        "CREATE POLICY restore_probe ON execbound.resources FOR SELECT "
        f"USING (current_setting('execbound.tenant_id', true) = '{third}')"
    )
    with policy(admin_engine, only_third, "resources"):
        reports = [
            recovery.verify_restore(
                restored_url=owner_url(), checkpoint_paths=named, runtime_url=runtime_url()
            ),
            recovery.verify_restore(restored_url=owner_url(), runtime_url=runtime_url()),
        ]
    for report in reports:
        assert fences(report) == {tenant: "HOLDS", other: "HOLDS", third: "CROSSES"}
        assert report["problems"] == [f"tenant:{third}:CROSSES"] and not report["ok"]
    # Without the fence check the named tenants are all the verifier reads, as before.
    report = recovery.verify_restore(restored_url=owner_url(), checkpoint_paths=named)
    assert fences(report) == {tenant: "NOT_CHECKED", other: "NOT_CHECKED"}


def test_the_owner_lists_every_tenant_under_the_30_second_limit(
    db, world, runtime, admin_engine, seeded, monkeypatch
):
    """The fence check now lists the copy's tenants on every run, as the owner, and that read
    holds to the 30-second limit `DATABASE_UNAVAILABLE` promises for the owner's reads: here
    the list is read only where the limit is set, so without it the third tenant is missed."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    third = a_third_tenant(admin_engine)
    limited = text(
        "SELECT tenant_id FROM execbound.tenants "
        "WHERE current_setting('statement_timeout') = '30s' ORDER BY tenant_id"
    )
    monkeypatch.setattr(recovery, "_EVERY_TENANT", limited)
    report = recovery.verify_restore(
        restored_url=owner_url(), tenants=[tenant, other], runtime_url=runtime_url()
    )
    assert fences(report) == {tenant: "HOLDS", other: "HOLDS", third: "HOLDS"}


def test_a_copy_of_one_tenant_reads_alone_rather_than_holding(db, admin_engine, seeded):
    """With every tenant of the copy read, a fence reads `ALONE` only when no other tenant the
    copy holds has a row the runtime role reads under its own fence, as in a copy of a single
    workspace: the check passes, but nothing shows there was a row to keep out, so it never
    reads as `HOLDS`."""
    tenant, gone = seeded["tenants"]
    with admin_engine.begin() as conn:
        for table in ("job_tenants", "credentials", "principals", "spaces", "tenants"):
            conn.execute(
                text(f"DELETE FROM execbound.{table} WHERE tenant_id = :t"),
                {"t": gone},
            )
    with db.transaction(tenant) as conn:
        append_event(conn, tenant, seeded["principals"][0], "test.recorded", {"index": 0})
    report = recovery.verify_restore(restored_url=owner_url(), runtime_url=runtime_url())
    assert report["ok"], report["problems"]
    assert fences(report) == {tenant: "ALONE"}


def test_a_policy_that_lets_one_tenant_read_another_is_reported_as_crossing(
    db, world, runtime, admin_engine, seeded
):
    """`check_runtime` reads flags and grants, never a policy body, so a restore whose policy
    on one table admits every row passes it; the fence read is what sees the crossing."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    widened = "CREATE POLICY restore_probe ON execbound.resources FOR SELECT USING (true)"
    with policy(admin_engine, widened, "resources"):
        report = recovery.verify_restore(
            restored_url=owner_url(), tenants=[tenant, other], runtime_url=runtime_url()
        )
    assert not report["ok"]
    assert fences(report) == {tenant: "CROSSES", other: "CROSSES"}
    assert report["problems"] == sorted(f"tenant:{t}:CROSSES" for t in (tenant, other))


def test_a_policy_that_hides_a_tenants_own_history_is_reported(
    db, world, runtime, admin_engine, seeded
):
    """The opposite failure: a fence that admits nothing would keep every other tenant out
    too, so the runtime must also read the tenant's own chain exactly as the owner does."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    hidden = (
        "CREATE POLICY restore_probe ON execbound.audit_events AS RESTRICTIVE "
        "FOR SELECT USING (false)"
    )
    with policy(admin_engine, hidden, "audit_events"):
        report = recovery.verify_restore(
            restored_url=owner_url(), tenants=[tenant, other], runtime_url=runtime_url()
        )
    assert fences(report) == {tenant: "HIDES_OWN", other: "HIDES_OWN"}
    assert f"tenant:{tenant}:HIDES_OWN" in report["problems"] and not report["ok"]


def test_a_chain_read_the_copys_privileges_refuse_hides_the_tenants_own(
    db, world, runtime, admin_engine, seeded
):
    """A copy that no longer grants the runtime role its audit head refuses the chain read
    outright, as a restore made without its grants does: that is the fence hiding the
    tenant's own history, not a read that failed."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    role = recovery.database_url(runtime_url()).username
    with admin_engine.begin() as conn:
        conn.execute(text(f"REVOKE SELECT ON execbound.audit_heads FROM {role}"))
    try:
        report = recovery.verify_restore(
            restored_url=owner_url(), tenants=[tenant, other], runtime_url=runtime_url()
        )
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f"GRANT SELECT ON execbound.audit_heads TO {role}"))
    assert fences(report) == {tenant: "HIDES_OWN", other: "HIDES_OWN"}
    assert not report["ok"]


def test_a_copy_that_lost_the_runtime_roles_schema_grant_hides_every_tenants_own(
    db, world, runtime, admin_engine, seeded
):
    """`pg_restore --no-acl` restores no grant at all, the schema's `USAGE` among them. Without
    that one the runtime role can read no table of the copy whatever its table grants say: it
    has no other tenant's row to count, and its chain read is refused, so every tenant's
    fence hides its own history and the report fails, rather than the check stopping on a
    count it could never have made."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    role = recovery.database_url(runtime_url()).username
    with admin_engine.begin() as conn:
        conn.execute(text(f"REVOKE USAGE ON SCHEMA execbound FROM {role}"))
    try:
        report = recovery.verify_restore(
            restored_url=owner_url(), tenants=[tenant, other], runtime_url=runtime_url()
        )
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f"GRANT USAGE ON SCHEMA execbound TO {role}"))
    assert fences(report) == {tenant: "HIDES_OWN", other: "HIDES_OWN"}
    # The startup check's read of the schema revision is refused too, which is the report's
    # `RUNTIME_UNSAFE`, not a stop and not a copy the startup check accepted.
    assert report["problems"] == sorted(
        ["RUNTIME_UNSAFE", *(f"tenant:{t}:HIDES_OWN" for t in (tenant, other))]
    )
    assert not report["ok"]


def test_the_fence_check_stops_when_row_security_applies_to_the_owner(
    db, world, runtime, admin_engine, seeded
):
    """The owner's read of each chain is what the runtime role's is held to, so no policy may
    filter it. An owner without `BYPASSRLS`, on tables that force row security, reads through
    the very policies the check is testing: with the audit chain hidden from every tenant, as
    a policy lost from a forced table hides it, the owner and the runtime role both read an
    empty chain, agree, and the fence would read `HOLDS`. The runtime role, to which row
    security always applies, stands in for such an owner here. The fence check reads the owner
    with row security off, which PostgreSQL refuses outright to a role a policy applies to, so
    it stops as `OWNER_FENCED`; without the fence check that owner's reads stay the
    tenant-scoped ones they were."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    hidden = "CREATE POLICY restore_probe ON execbound.{} AS RESTRICTIVE FOR SELECT USING (false)"
    with (
        policy(admin_engine, hidden.format("audit_heads"), "audit_heads"),
        policy(admin_engine, hidden.format("audit_events"), "audit_events"),
    ):
        with pytest.raises(recovery.RecoveryError) as stopped:
            recovery.verify_restore(
                restored_url=runtime_url(), tenants=[tenant, other], runtime_url=runtime_url()
            )
    assert stopped.value.code == "OWNER_FENCED"
    report = recovery.verify_restore(restored_url=runtime_url(), tenants=[tenant, other])
    assert report["ok"], report["problems"]
    assert fences(report) == {tenant: "NOT_CHECKED", other: "NOT_CHECKED"}


def test_the_fence_is_read_on_the_copy_the_owner_reads(db, world, runtime, admin_engine, seeded):
    """The runtime role's reads count only if they are of the copy the owner read: a runtime URL
    naming another database, or another instance, stops the check as `NO_RUNTIME_DATABASE`
    before either is read. A loopback name and the address the connection rules pin it to
    are one instance."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    parsed = recovery.database_url(runtime_url())
    elsewhere = [parsed.set(database="postgres"), parsed.set(port=1)]
    for url in elsewhere:
        with pytest.raises(recovery.RecoveryError) as stopped:
            recovery.verify_restore(
                restored_url=owner_url(), tenants=[tenant, other], runtime_url=url
            )
        assert stopped.value.code == "NO_RUNTIME_DATABASE"
    other_name = "localhost" if parsed.host == "127.0.0.1" else "127.0.0.1"
    report = recovery.verify_restore(
        restored_url=owner_url(), tenants=[tenant, other], runtime_url=parsed.set(host=other_name)
    )
    assert report["ok"], report["problems"]
    assert fences(report) == {tenant: "HOLDS", other: "HOLDS"}


def test_a_chain_read_that_fails_otherwise_stops_the_check_rather_than_failing_a_fence(
    db, world, runtime, admin_engine, seeded, monkeypatch
):
    """A runtime read that the server cancels, here at its statement timeout, says nothing
    about the copy's fence: the check stops as `RUNTIME_UNAVAILABLE`, as ERROR_CODES.md says,
    rather than reporting the tenant's fence as hiding its own history."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    role = recovery.database_url(runtime_url()).username
    read_events = recovery.read_events

    def cancelled_for_the_runtime(conn, tenant_id):
        if conn.execute(text("SELECT current_user")).scalar_one() == role:
            conn.execute(text("SELECT set_config('statement_timeout', '50', true)"))
            conn.execute(text("SELECT pg_sleep(5)"))
        return read_events(conn, tenant_id)

    monkeypatch.setattr(recovery, "read_events", cancelled_for_the_runtime)
    with pytest.raises(recovery.RecoveryError) as stopped:
        recovery.verify_restore(
            restored_url=owner_url(), tenants=[tenant, other], runtime_url=runtime_url()
        )
    assert stopped.value.code == "RUNTIME_UNAVAILABLE"


def test_the_startup_check_reads_under_the_30_second_limit_and_stops_when_cancelled(
    db, world, runtime, seeded, monkeypatch
):
    """The runtime role's startup check on the copy runs under the 30-second limit every
    other read of the fence check has, so a read blocked there, on a lock another session
    holds for one, stops the check as `RUNTIME_UNAVAILABLE`, as ERROR_CODES.md says, rather
    than waiting for ever; and a startup read the server cancels stops it so."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    role = recovery.database_url(runtime_url()).username
    check_runtime = recovery.check_runtime
    limits = []

    def limited(conn):
        assert conn.execute(text("SELECT current_user")).scalar_one() == role
        limits.append(conn.execute(text("SHOW statement_timeout")).scalar_one())
        return check_runtime(conn)

    monkeypatch.setattr(recovery, "check_runtime", limited)
    report = recovery.verify_restore(
        restored_url=owner_url(), tenants=[tenant, other], runtime_url=runtime_url()
    )
    assert report["ok"], report["problems"]
    assert limits == ["30s"]

    def cancelled(conn):
        conn.execute(text("SELECT set_config('statement_timeout', '50', true)"))
        conn.execute(text("SELECT pg_sleep(5)"))
        return check_runtime(conn)

    monkeypatch.setattr(recovery, "check_runtime", cancelled)
    with pytest.raises(recovery.RecoveryError) as stopped:
        recovery.verify_restore(
            restored_url=owner_url(), tenants=[tenant, other], runtime_url=runtime_url()
        )
    assert stopped.value.code == "RUNTIME_UNAVAILABLE"


def test_a_widened_policy_fails_only_the_tenants_that_see_another_s_rows(
    db, world, runtime, admin_engine, seeded
):
    """The fence is read through the rows the copy holds. Only the world's tenant holds an
    execution, so with `executions` widened the other tenant sees it and `CROSSES`, while the
    tenant whose row is exposed has no other tenant's execution to see and reads `HOLDS`; the
    report fails all the same."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    with admin_engine.connect() as conn:
        held = dict(
            conn.execute(
                text(
                    "SELECT tenant_id, count(*) FROM execbound.executions "
                    "WHERE tenant_id IN (:a, :b) GROUP BY tenant_id"
                ),
                {"a": tenant, "b": other},
            ).all()
        )
    assert held == {tenant: 1}
    widened = "CREATE POLICY restore_probe ON execbound.executions FOR SELECT USING (true)"
    with policy(admin_engine, widened, "executions"):
        report = recovery.verify_restore(
            restored_url=owner_url(), tenants=[tenant, other], runtime_url=runtime_url()
        )
    assert fences(report) == {tenant: "HOLDS", other: "CROSSES"}
    assert report["problems"] == [f"tenant:{other}:CROSSES"] and not report["ok"]


def test_a_runtime_url_that_bypasses_row_security_is_unsafe_and_crosses(
    db, world, runtime, admin_engine, seeded
):
    """The owner in this suite is a superuser that bypasses row security; handed to the check
    as the runtime, it fails `check_runtime` and reads every tenant's rows."""
    tenant, other = both_recorded(db, world, runtime, seeded)
    report = recovery.verify_restore(
        restored_url=owner_url(), tenants=[tenant, other], runtime_url=owner_url()
    )
    assert not report["ok"]
    assert "RUNTIME_UNSAFE" in report["problems"]
    assert fences(report) == {tenant: "CROSSES", other: "CROSSES"}


def test_main_checks_the_fence_on_the_restored_database_and_never_echoes_a_url(
    db, world, runtime, admin_engine, seeded, tmp_path, monkeypatch, capsys
):
    tenant, other = both_recorded(db, world, runtime, seeded)
    monkeypatch.setenv("MIGRATION_DATABASE_URL", owner_url())
    monkeypatch.setenv("DATABASE_URL", runtime_url())
    database = recovery.database_url(owner_url()).database
    output = tmp_path / "report.json"
    argv = ["--restored-database", database, "--tenant", str(tenant), "--tenant", str(other)]
    assert recovery.main([*argv, "--check-fence", "--output", str(output)]) == 0
    printed = capsys.readouterr()
    assert "passed" in printed.out and printed.out.count("fence=HOLDS") == 2
    report = json.loads(output.read_text(encoding="utf-8"))
    assert fences(report) == {tenant: "HOLDS", other: "HOLDS"}
    written = output.read_text(encoding="utf-8") + printed.out + printed.err
    assert owner_url() not in written and runtime_url() not in written
    for secret in (recovery.database_url(url).password for url in (owner_url(), runtime_url())):
        assert secret and secret not in written


def test_main_loads_the_named_plugins_before_the_fence_check_reads_the_copy(
    db, world, runtime, admin_engine, seeded, tmp_path, monkeypatch, capsys
):
    """`--check-fence` runs the gateway's startup check of the runtime role, which compares the
    dormant objects' grants with what the loaded plugins claim. The copy here holds a plugin's
    grant: read without that plugin named, the role is unsafe; with it named in
    `EXECBOUND_PLUGINS`, it is loaded before the check and the copy passes; and a plugin that
    cannot load stops the command before anything is read."""
    from plugin_fixtures import install

    from execbound.db import EMPTY_CLAIMS, grant_dormant

    claims = {"product_counts": frozenset({"SELECT"})}
    install(monkeypatch, register=lambda registry: registry.claim("product_counts", {"SELECT"}))
    tenant, other = both_recorded(db, world, runtime, seeded)
    monkeypatch.setenv("MIGRATION_DATABASE_URL", owner_url())
    monkeypatch.setenv("DATABASE_URL", runtime_url())
    database = recovery.database_url(owner_url()).database
    argv = ["--restored-database", database, "--tenant", str(tenant), "--tenant", str(other)]

    def verify(name):
        output = tmp_path / name
        status = recovery.main([*argv, "--check-fence", "--output", str(output)])
        report = json.loads(output.read_text(encoding="utf-8")) if output.exists() else None
        return status, report, capsys.readouterr()

    monkeypatch.setenv("EXECBOUND_PLUGINS", "no_such_plugin")
    status, report, printed = verify("refused.json")
    assert (status, report) == (2, None)
    # The last line of stderr: a structured log handler another test configured may write there.
    assert printed.err.splitlines()[-1] == "Plugin refused: UNKNOWN_PLUGIN." and printed.out == ""
    with admin_engine.begin() as conn:
        grant_dormant(conn, claims)
    try:
        monkeypatch.delenv("EXECBOUND_PLUGINS")
        status, report, _ = verify("without.json")
        assert status == 2 and report["problems"] == ["RUNTIME_UNSAFE"]
        monkeypatch.setenv("EXECBOUND_PLUGINS", "sample_plugin")
        status, report, _ = verify("with.json")
        assert status == 0 and report["ok"], report["problems"]
        assert fences(report) == {tenant: "HOLDS", other: "HOLDS"}
    finally:
        with admin_engine.begin() as conn:
            grant_dormant(conn, EMPTY_CLAIMS)


@pytest.mark.parametrize(
    ("argv", "environment", "code"),
    [
        (["--restored-url", "{owner}"], {"DATABASE_URL": "{runtime}"}, "NO_RUNTIME_DATABASE"),
        (["--restored-database", "{database}"], {"DATABASE_URL": None}, "NO_RUNTIME_DATABASE"),
        (
            ["--restored-database", "{database}"],
            {"DATABASE_URL": "{elsewhere}"},
            "NO_RUNTIME_DATABASE",
        ),
        (
            ["--restored-database", "{database}"],
            {"DATABASE_URL": "restorer:synthetic@127.0.0.1 not a url"},
            "INVALID_DATABASE",
        ),
    ],
    ids=["another-instance", "no-runtime-url", "runtime-url-elsewhere", "malformed-runtime-url"],
)
def test_the_fence_check_needs_the_runtime_role_on_the_same_instance(
    tmp_path, monkeypatch, capsys, argv, environment, code
):
    """The check substitutes the restored database's name into `DATABASE_URL`, as
    `--restored-database` does into `MIGRATION_DATABASE_URL`; a restore named by URL on
    another instance has no runtime URL to read it with, a `DATABASE_URL` on another instance
    than `MIGRATION_DATABASE_URL` would read the fence of some other database, and nothing is
    guessed or read."""
    values = {
        "owner": owner_url(),
        "runtime": runtime_url(),
        "elsewhere": recovery.database_url(runtime_url())
        .set(port=1)
        .render_as_string(hide_password=False),
        "database": recovery.database_url(owner_url()).database,
    }
    monkeypatch.setenv("MIGRATION_DATABASE_URL", owner_url())
    for name, value in environment.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value.format(**values))
    output = tmp_path / "report.json"
    filled = [arg.format(**values) for arg in argv]
    assert recovery.main([*filled, "--check-fence", "--output", str(output)]) == 2
    printed = capsys.readouterr()
    assert printed.err == f"Recovery verification stopped: {code}.\n"
    assert printed.out == "" and not output.exists()
