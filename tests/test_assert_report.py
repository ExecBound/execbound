# SPDX-License-Identifier: AGPL-3.0-only
"""Named checks over restore and replay reports: a failed check exits 1, a usage error exits 2.

`execbound.reports` replaces the inline `python -c` assertions CI used to read the restore
round trip's reports with, so every check here passes on the report it describes, fails on one
altered for it with an `expected ..., found ...` line, and a typo (an unbound name, a misspelled
status, a malformed report) can never pass. The restore reports below are assembled from
`execbound.recovery`'s own row types, and the last test reads reports the verifier and the
replay wrote for real.
"""

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from test_recovery import checkpoint_file, head_of, owner_url
from test_replay_export import publish
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound import recovery, reports
from execbound.replay.models import TrustedHead
from execbound.replay.report import (
    DecisionComparison,
    EvaluationResult,
    ReplayReport,
    report_json,
)

T0 = UUID("952a77ff-956a-59b4-9680-9d4e4ba01773")
T1 = UUID("f53236f5-bb36-5c2c-87b3-330a53cc4d95")
ENDPOINT = "local-data/validation-private/endpoint.sqlite3"
IDENTITY = "local-data/validation-private/identity.sqlite3"


# Reports, built the way the verifier and the replay build them.


def tenant_row(tenant: UUID, **changes) -> dict:
    """One tenant's row as `recovery.check_tenant` writes it, its problems derived the same
    way from whatever `changes` set."""
    check = recovery.TenantCheck(
        tenant_id=str(tenant),
        events=65,
        head_sequence=65,
        head_hash="a" * 64,
        chain_ok=True,
        unresolved_executions=0,
        checkpoint="MATCHES_CHECKPOINT",
        live="MATCHES_LIVE",
        fence="HOLDS",
    )
    for name, value in changes.items():
        setattr(check, name, value)
    if not check.chain_ok:
        check.problems.append("CHAIN_BROKEN")
    if check.checkpoint in recovery.FAILING_CHECKPOINT_STATUSES:
        check.problems.append(check.checkpoint)
    if check.live in recovery.FAILING_LIVE_STATUSES:
        check.problems.append(check.live)
    if check.fence in recovery.FAILING_FENCE_STATUSES:
        check.problems.append(check.fence)
    return asdict(check)


def store_row(path: str, *problems: str) -> dict:
    integrity = "*** in database main ***" if "STORE_CORRUPT" in problems else "ok"
    check = recovery.StoreCheck(path=path, integrity=integrity, journal_records=6)
    check.problems.extend(problems)
    return asdict(check)


def restore_report(tenants: list[dict], stores: list[dict], *whole: str) -> dict:
    """The report `recovery.verify_restore` returns for these rows, and `whole`, the problems
    of the report itself, such as a runtime role `check_runtime` refused."""
    problems = sorted(
        {f"tenant:{row['tenant_id']}:{problem}" for row in tenants for problem in row["problems"]}
        | {f"store:{row['path']}:{problem}" for row in stores for problem in row["problems"]}
        | set(whole)
    )
    if not tenants:
        problems.append("NO_TENANTS_SELECTED")
    return {
        "version": 1,
        "ok": not problems,
        "tenants": tenants,
        "provider_stores": stores,
        "problems": problems,
    }


def healthy(**tenant_changes) -> dict:
    """Both tenants matching their checkpoints and the live database, both stores intact;
    `t0_...` and `t1_...` keyword arguments change one tenant's row."""
    t0 = {key[3:]: value for key, value in tenant_changes.items() if key.startswith("t0_")}
    t1 = {key[3:]: value for key, value in tenant_changes.items() if key.startswith("t1_")}
    return restore_report(
        [tenant_row(T0, **t0), tenant_row(T1, **t1)], [store_row(ENDPOINT), store_row(IDENTITY)]
    )


def decision(sequence: int) -> DecisionComparison:
    return DecisionComparison(
        sequence=sequence,
        execution_id=uuid4(),
        operation_id=uuid4(),
        canonical_target_id=uuid4(),
        action="endpoint.isolate",
        stage="ADMISSION",
        semantic_time=datetime(2026, 10, 7, tzinfo=UTC),
        recorded_effect="ELIGIBLE",
        baseline=EvaluationResult(effect="ELIGIBLE", reasons=("permitted",)),
    )


def replay_report(*, decisions: int = 1, complete: bool = True, issues: tuple = ()) -> str:
    """A replay's `report.json`, serialized by the replay's own writer."""
    report = ReplayReport(
        tenant_id=T0,
        head_sequence=65,
        head_hash="a" * 64,
        mode="BASELINE",
        complete=complete,
        decisions=tuple(decision(index + 1) for index in range(decisions)),
        issues=issues,
    )
    return report_json(report)


def write(path: Path, value: dict | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = value if isinstance(value, str) else json.dumps(value, indent=2, sort_keys=True)
    path.write_text(text, encoding="utf-8")
    return path


def head(path: Path, tenant: UUID, sequence: int = 65) -> Path:
    return write(
        path,
        TrustedHead(tenant_id=tenant, sequence=sequence, event_hash="a" * 64).model_dump_json(),
    )


@pytest.fixture
def heads(tmp_path) -> list[str]:
    """`--tenant` bindings for t0 and t1, as CI makes them."""
    return [
        "--tenant",
        f"t0={head(tmp_path / 'tenant-0.head.json', T0)}",
        "--tenant",
        f"t1={head(tmp_path / 'tenant-1.head.json', T1)}",
    ]


def run(capsys, *argv: str) -> tuple[int, list[str], str]:
    code = reports.main([str(arg) for arg in argv])
    out, err = capsys.readouterr()
    return code, out.splitlines(), err


def check_restore(capsys, tmp_path, heads, report: dict, *checks: str):
    path = write(tmp_path / f"restore-{uuid4().hex}.json", report)
    return run(capsys, "restore", "--report", path, *heads, *checks)


def check_replay(capsys, tmp_path, report: str, *checks: str):
    path = write(tmp_path / f"replay-{uuid4().hex}.json", report)
    return run(capsys, "replay", "--report", path, *checks)


# Every check passes on the report it describes.


def test_a_healthy_round_trip_passes_every_restore_check(capsys, tmp_path, heads):
    code, lines, err = check_restore(
        capsys,
        tmp_path,
        heads,
        healthy(),
        *("--ok", "--no-problems", "--tenants-exactly", "t1,t0"),
        *("--stores-ok", "--stores-exactly", "2"),
        *("--checkpoint", "t0=MATCHES_CHECKPOINT", "--checkpoint", "t1=MATCHES_CHECKPOINT"),
        *("--live", "t0=MATCHES_LIVE", "--live", "t1=MATCHES_LIVE", "--chain-ok", "t0,t1"),
        *("--fence", "t0=HOLDS", "--fence", "t1=HOLDS"),
        *("--unresolved", "t0=0", "--unresolved", "t1=0"),
        *("--events-min", "t0=65", "--events-min", "t1=1"),
        *("--forbid-problem", "tenant:t0:CHAIN_BROKEN"),
    )
    assert (code, err) == (0, "")
    assert lines == [
        "PASS ok",
        "PASS no-problems",
        "PASS forbid-problem tenant:t0:CHAIN_BROKEN",
        "PASS tenants-exactly t1,t0",
        "PASS stores-ok",
        "PASS stores-exactly 2",
        "PASS checkpoint t0=MATCHES_CHECKPOINT",
        "PASS checkpoint t1=MATCHES_CHECKPOINT",
        "PASS live t0=MATCHES_LIVE",
        "PASS live t1=MATCHES_LIVE",
        "PASS fence t0=HOLDS",
        "PASS fence t1=HOLDS",
        "PASS chain-ok t0",
        "PASS chain-ok t1",
        "PASS unresolved t0=0",
        "PASS unresolved t1=0",
        "PASS events-min t0=65",
        "PASS events-min t1=1",
        "18 checks, 0 failed",
    ]


def test_a_failed_restore_passes_the_checks_that_name_its_failure(capsys, tmp_path, heads):
    """Problem strings name tenants by their bound names and are compared as sets, in any
    order, after the names are expanded to tenant ids."""
    report = restore_report(
        [tenant_row(T0), tenant_row(T1, chain_ok=False, checkpoint="BEHIND_CHECKPOINT")],
        [store_row(ENDPOINT, "STORE_CORRUPT"), store_row(IDENTITY)],
    )
    expected = f"tenant:t1:CHAIN_BROKEN,store:{ENDPOINT}:STORE_CORRUPT,tenant:t1:BEHIND_CHECKPOINT"
    code, lines, _ = check_restore(
        capsys,
        tmp_path,
        heads,
        report,
        *("--not-ok", "--problems-exactly", expected),
        *("--problem", "tenant:t1:CHAIN_BROKEN", "--problem", f"store:{ENDPOINT}:STORE_CORRUPT"),
        *("--checkpoint", "t1=BEHIND_CHECKPOINT", "--checkpoint", "t0=MATCHES_CHECKPOINT"),
    )
    assert code == 0, lines
    assert lines[-1] == "6 checks, 0 failed"


def test_a_restore_whose_fence_failed_passes_the_checks_that_name_it(capsys, tmp_path, heads):
    """The runtime role refused by `check_runtime` is a problem of the whole report, and a
    tenant whose fence crossed carries its own; both are named as the verifier writes them."""
    report = restore_report(
        [tenant_row(T0, fence="CROSSES"), tenant_row(T1)],
        [store_row(ENDPOINT), store_row(IDENTITY)],
        "RUNTIME_UNSAFE",
    )
    code, lines, _ = check_restore(
        capsys,
        tmp_path,
        heads,
        report,
        *("--not-ok", "--problems-exactly", "tenant:t0:CROSSES,RUNTIME_UNSAFE"),
        *("--problem", "RUNTIME_UNSAFE", "--fence", "t0=CROSSES", "--fence", "t1=HOLDS"),
    )
    assert code == 0, lines
    assert lines[-1] == "5 checks, 0 failed"


def test_a_report_with_no_tenants_can_be_named(capsys, tmp_path):
    report = restore_report([], [store_row(ENDPOINT)])
    code, lines, _ = check_restore(
        capsys, tmp_path, [], report, "--not-ok", "--problems-exactly", "NO_TENANTS_SELECTED"
    )
    assert code == 0, lines


# Every check fails on a report altered for it, and says what it expected and found.


def drop_t1(report: dict) -> dict:
    return {**report, "tenants": report["tenants"][:1]}


def drop_t0(report: dict) -> dict:
    return {**report, "tenants": report["tenants"][1:]}


def extra_tenant(report: dict) -> dict:
    stranger = tenant_row(UUID("00000000-0000-4000-8000-000000000001"))
    return {**report, "tenants": [*report["tenants"], stranger]}


def drop_store(report: dict) -> dict:
    return restore_report(report["tenants"], report["provider_stores"][:1])


def no_stores(report: dict) -> dict:
    return restore_report(report["tenants"], [])


def corrupt_store(report: dict) -> dict:
    return restore_report(report["tenants"], [store_row(ENDPOINT, "STORE_CORRUPT")])


def same(report: dict) -> dict:
    return report


RESTORE_FAILURES = [
    (
        ["--ok"],
        healthy(),
        healthy(t1_checkpoint="BEHIND_CHECKPOINT"),
        same,
        "FAIL ok: expected true, found false",
    ),
    (
        ["--not-ok"],
        healthy(t1_checkpoint="BEHIND_CHECKPOINT"),
        healthy(),
        same,
        "FAIL not-ok: expected false, found true",
    ),
    (
        ["--no-problems"],
        healthy(),
        healthy(t1_checkpoint="BEHIND_CHECKPOINT"),
        same,
        "FAIL no-problems: expected none, found tenant:t1:BEHIND_CHECKPOINT",
    ),
    (
        ["--problems-exactly", "tenant:t1:BEHIND_CHECKPOINT"],
        healthy(t1_checkpoint="BEHIND_CHECKPOINT"),
        healthy(t1_checkpoint="BEHIND_CHECKPOINT", t1_chain_ok=False),
        same,
        "FAIL problems-exactly tenant:t1:BEHIND_CHECKPOINT: expected tenant:t1:BEHIND_CHECKPOINT, "
        "found tenant:t1:BEHIND_CHECKPOINT,tenant:t1:CHAIN_BROKEN",
    ),
    (
        ["--problems-exactly", "tenant:t0:CHAIN_BROKEN,tenant:t1:BEHIND_CHECKPOINT"],
        healthy(t0_chain_ok=False, t1_checkpoint="BEHIND_CHECKPOINT"),
        healthy(t1_checkpoint="BEHIND_CHECKPOINT"),
        same,
        "FAIL problems-exactly tenant:t0:CHAIN_BROKEN,tenant:t1:BEHIND_CHECKPOINT: expected "
        "tenant:t0:CHAIN_BROKEN,tenant:t1:BEHIND_CHECKPOINT, found tenant:t1:BEHIND_CHECKPOINT",
    ),
    (
        ["--problem", "tenant:t1:DIVERGES_FROM_LIVE"],
        healthy(t1_live="DIVERGES_FROM_LIVE"),
        healthy(),
        same,
        "FAIL problem tenant:t1:DIVERGES_FROM_LIVE: expected present, found none",
    ),
    (
        ["--forbid-problem", "tenant:t0:CHAIN_BROKEN"],
        healthy(),
        healthy(t0_chain_ok=False),
        same,
        "FAIL forbid-problem tenant:t0:CHAIN_BROKEN: expected absent, found present",
    ),
    (
        ["--tenants-exactly", "t0,t1"],
        healthy(),
        healthy(),
        drop_t1,
        "FAIL tenants-exactly t0,t1: expected t0,t1, found t0",
    ),
    (
        ["--tenants-exactly", "t0,t1"],
        healthy(),
        healthy(),
        extra_tenant,
        "FAIL tenants-exactly t0,t1: expected t0,t1, "
        "found 00000000-0000-4000-8000-000000000001,t0,t1",
    ),
    (
        ["--stores-ok"],
        healthy(),
        healthy(),
        corrupt_store,
        f"FAIL stores-ok: expected every store intact, found store:{ENDPOINT}:STORE_CORRUPT",
    ),
    (
        ["--stores-ok"],
        healthy(),
        healthy(),
        no_stores,
        "FAIL stores-ok: expected every store intact, found no stores",
    ),
    (
        ["--stores-exactly", "2"],
        healthy(),
        healthy(),
        drop_store,
        "FAIL stores-exactly 2: expected 2, found 1",
    ),
    (
        ["--checkpoint", "t0=MATCHES_CHECKPOINT"],
        healthy(),
        healthy(t0_checkpoint="AHEAD_OF_CHECKPOINT"),
        same,
        "FAIL checkpoint t0=MATCHES_CHECKPOINT: expected MATCHES_CHECKPOINT, "
        "found AHEAD_OF_CHECKPOINT",
    ),
    (
        ["--checkpoint", "t0=MATCHES_CHECKPOINT"],
        healthy(),
        healthy(),
        drop_t0,
        "FAIL checkpoint t0=MATCHES_CHECKPOINT: expected MATCHES_CHECKPOINT, "
        "found no tenant t0 in the report",
    ),
    (
        ["--live", "t1=MATCHES_LIVE"],
        healthy(),
        healthy(t1_live="BEHIND_LIVE"),
        same,
        "FAIL live t1=MATCHES_LIVE: expected MATCHES_LIVE, found BEHIND_LIVE",
    ),
    (
        ["--chain-ok", "t0,t1"],
        healthy(),
        healthy(t1_chain_ok=False),
        same,
        "FAIL chain-ok t1: expected true, found false",
    ),
    (
        ["--unresolved", "t0=0"],
        healthy(),
        healthy(t0_unresolved_executions=1),
        same,
        "FAIL unresolved t0=0: expected 0, found 1",
    ),
    (
        ["--events-min", "t0=65"],
        healthy(),
        healthy(t0_events=64),
        same,
        "FAIL events-min t0=65: expected at least 65, found 64",
    ),
    (
        ["--fence", "t0=HOLDS"],
        healthy(),
        healthy(t0_fence="ALONE"),
        same,
        "FAIL fence t0=HOLDS: expected HOLDS, found ALONE",
    ),
    (
        ["--fence", "t1=HOLDS"],
        healthy(),
        healthy(t1_fence="NOT_CHECKED"),
        same,
        "FAIL fence t1=HOLDS: expected HOLDS, found NOT_CHECKED",
    ),
    (
        ["--fence", "t0=HOLDS"],
        healthy(),
        healthy(),
        drop_t0,
        "FAIL fence t0=HOLDS: expected HOLDS, found no tenant t0 in the report",
    ),
    (
        ["--forbid-problem", "RUNTIME_UNSAFE"],
        healthy(),
        restore_report(healthy()["tenants"], healthy()["provider_stores"], "RUNTIME_UNSAFE"),
        same,
        "FAIL forbid-problem RUNTIME_UNSAFE: expected absent, found present",
    ),
    (
        ["--problem", "tenant:t1:HIDES_OWN"],
        healthy(t1_fence="HIDES_OWN"),
        healthy(),
        same,
        "FAIL problem tenant:t1:HIDES_OWN: expected present, found none",
    ),
]


@pytest.mark.parametrize(
    ("checks", "matching", "altered", "alter", "failure"),
    RESTORE_FAILURES,
    ids=[f"{row[0][0][2:]}-{index}" for index, row in enumerate(RESTORE_FAILURES)],
)
def test_each_restore_check_passes_on_its_report_and_fails_on_an_altered_one(
    capsys, tmp_path, heads, checks, matching, altered, alter, failure
):
    code, lines, _ = check_restore(capsys, tmp_path, heads, matching, *checks)
    assert code == 0, lines
    code, lines, err = check_restore(capsys, tmp_path, heads, alter(altered), *checks)
    assert (code, err) == (1, "")
    assert failure in lines
    assert lines[-1].endswith(", 1 failed")


REPLAY_FAILURES = [
    (
        ["--complete"],
        {},
        {"complete": False, "issues": ("INCOMPLETE_HISTORY",)},
        "FAIL complete: expected true, found false",
    ),
    (
        ["--incomplete"],
        {"complete": False, "issues": ("INCOMPLETE_HISTORY",)},
        {},
        "FAIL incomplete: expected false, found true",
    ),
    (
        ["--issues-exactly", "MISSING_SEMANTIC_TIME,INCOMPLETE_HISTORY"],
        {"complete": False, "issues": ("INCOMPLETE_HISTORY", "MISSING_SEMANTIC_TIME")},
        {"complete": False, "issues": ("INCOMPLETE_HISTORY",)},
        "FAIL issues-exactly MISSING_SEMANTIC_TIME,INCOMPLETE_HISTORY: expected "
        "INCOMPLETE_HISTORY,MISSING_SEMANTIC_TIME, found INCOMPLETE_HISTORY",
    ),
    (
        ["--decisions", "2"],
        {"decisions": 2},
        {"decisions": 1},
        "FAIL decisions 2: expected 2, found 1",
    ),
    (
        ["--min-decisions", "2"],
        {"decisions": 3},
        {"decisions": 1},
        "FAIL min-decisions 2: expected at least 2, found 1",
    ),
]


@pytest.mark.parametrize(
    ("checks", "matching", "altered", "failure"),
    REPLAY_FAILURES,
    ids=[row[0][0][2:] for row in REPLAY_FAILURES],
)
def test_each_replay_check_passes_on_its_report_and_fails_on_an_altered_one(
    capsys, tmp_path, checks, matching, altered, failure
):
    code, lines, _ = check_replay(capsys, tmp_path, replay_report(**matching), *checks)
    assert code == 0, lines
    code, lines, err = check_replay(capsys, tmp_path, replay_report(**altered), *checks)
    assert (code, err) == (1, "")
    assert failure in lines
    assert lines[-1] == "1 check, 1 failed"


def test_tenant_id_prints_the_id_alone(capsys, tmp_path):
    code, lines, err = run(capsys, "tenant-id", "--file", head(tmp_path / "h.json", T0))
    assert (code, lines, err) == (0, [str(T0)], "")


# A usage error exits 2, prints nothing on stdout, and so can never pass.


def refused(capsys, *argv: str) -> str:
    code, lines, err = run(capsys, *argv)
    assert code == 2, lines
    assert lines == []
    assert err.startswith("python -m execbound.reports: ")
    return err


@pytest.mark.parametrize(
    "checks",
    [
        ["--checkpoint", "t9=MATCHES_CHECKPOINT"],
        ["--live", "t9=MATCHES_LIVE"],
        ["--chain-ok", "t0,t9"],
        ["--unresolved", "t9=0"],
        ["--events-min", "t9=1"],
        ["--fence", "t9=HOLDS"],
        ["--tenants-exactly", "t0,t9"],
        ["--problem", "tenant:t9:CHAIN_BROKEN"],
        ["--forbid-problem", "tenant:t9:CHAIN_BROKEN"],
        ["--problems-exactly", "tenant:t0:CHAIN_BROKEN,tenant:t9:CHAIN_BROKEN"],
    ],
    ids=lambda checks: checks[0][2:],
)
def test_an_unbound_name_is_refused(capsys, tmp_path, heads, checks):
    report = write(tmp_path / "report.json", healthy())
    err = refused(capsys, "restore", "--report", report, *heads, *checks)
    assert "t9 is not bound" in err


@pytest.mark.parametrize(
    "binding",
    ["T0={head}", "t0", "0t={head}", "abcdefghijklmnopq={head}", "t.0={head}", "={head}"],
    ids=["upper", "no-path", "leading-digit", "seventeen", "dot", "empty"],
)
def test_a_malformed_binding_is_refused(capsys, tmp_path, binding):
    report = write(tmp_path / "report.json", healthy())
    path = head(tmp_path / "h.json", T0)
    refused(capsys, "restore", "--report", report, "--tenant", binding.format(head=path), "--ok")


def test_a_name_binds_one_tenant_and_a_tenant_one_name(capsys, tmp_path):
    report = write(tmp_path / "report.json", healthy())
    zero, one = head(tmp_path / "0.json", T0), head(tmp_path / "1.json", T1)
    err = refused(
        capsys,
        "restore",
        "--report",
        report,
        "--tenant",
        f"t0={zero}",
        "--tenant",
        f"t0={one}",
        "--ok",
    )
    assert "t0 is bound twice" in err
    err = refused(
        capsys,
        "restore",
        "--report",
        report,
        "--tenant",
        f"a={zero}",
        "--tenant",
        f"b={zero}",
        "--ok",
    )
    assert "a and b name the same tenant" in err


@pytest.mark.parametrize("fault", ["oversized", "duplicate", "negative", "missing", "extra"])
def test_a_head_file_is_read_strictly(capsys, tmp_path, fault):
    report = write(tmp_path / "report.json", healthy())
    path = tmp_path / "h.json"
    valid = TrustedHead(tenant_id=T0, sequence=65, event_hash="a" * 64).model_dump_json()
    if fault == "oversized":
        path.write_text(valid + " " * (4097 - len(valid)), encoding="utf-8")
        assert path.stat().st_size == 4097
    elif fault == "duplicate":
        path.write_text(valid[:-1] + ',"sequence":64}', encoding="utf-8")
    elif fault == "negative":
        path.write_text(valid.replace('"sequence":65', '"sequence":-1'), encoding="utf-8")
    elif fault == "extra":
        path.write_text(valid[:-1] + ',"note":"x"}', encoding="utf-8")
    err = refused(capsys, "restore", "--report", report, "--tenant", f"t0={path}", "--ok")
    assert "the head file for t0" in err
    assert refused(capsys, "tenant-id", "--file", path)


def test_a_head_file_of_exactly_four_kibibytes_is_read(capsys, tmp_path):
    path = tmp_path / "h.json"
    valid = TrustedHead(tenant_id=T0, sequence=65, event_hash="a" * 64).model_dump_json()
    path.write_text(valid + " " * (4096 - len(valid)), encoding="utf-8")
    assert run(capsys, "tenant-id", "--file", path)[0] == 0


@pytest.mark.parametrize(
    ("checks", "named"),
    [
        (["--checkpoint", "t0=MATCHES_CHECKPIONT"], "MATCHES_CHECKPOINT"),
        (["--checkpoint", "t0=MATCHES_LIVE"], "AHEAD_OF_CHECKPOINT"),
        (["--live", "t0=MATCHES"], "MATCHES_LIVE"),
        (["--problem", "tenant:t0:CHAIN_BROKE"], "CHAIN_BROKEN"),
        (["--problem", "tenant:t0:STORE_CORRUPT"], "DIVERGES_FROM_LIVE"),
        (["--forbid-problem", f"store:{ENDPOINT}:CHAIN_BROKEN"], "STORE_WITHOUT_JOURNAL"),
        (["--problems-exactly", "NO_TENANT_SELECTED"], "NO_TENANTS_SELECTED"),
        (["--problem", "CHAIN_BROKEN"], "NO_TENANTS_SELECTED"),
        (["--fence", "t0=HOLD"], "HOLDS"),
        (["--fence", "t0=MATCHES_LIVE"], "CROSSES"),
        (["--problem", "tenant:t0:RUNTIME_UNSAFE"], "HIDES_OWN"),
        (["--problem", "RUNTIME_SAFE"], "RUNTIME_UNSAFE"),
    ],
    ids=[
        "checkpoint-typo",
        "checkpoint-from-live",
        "live-typo",
        "tenant-problem-typo",
        "store-problem-on-tenant",
        "tenant-problem-on-store",
        "report-problem-typo",
        "problem-without-kind",
        "fence-typo",
        "fence-from-live",
        "report-problem-on-tenant",
        "report-problem-misspelled",
    ],
)
def test_a_misspelled_status_is_refused_and_the_valid_set_named(
    capsys, tmp_path, heads, checks, named
):
    report = write(tmp_path / "report.json", healthy())
    err = refused(capsys, "restore", "--report", report, *heads, *checks)
    assert named in err


def test_the_accepted_statuses_are_the_verifiers_own():
    """Every status `execbound.recovery` can report, and no other, so an outcome added there is
    accepted here without a second edit and a removed one is refused."""
    tenant = uuid4()
    events = [{"event_hash": "a" * 64}, {"event_hash": "b" * 64}]

    def at(sequence: int, event_hash: str) -> TrustedHead:
        return TrustedHead(tenant_id=tenant, sequence=sequence, event_hash=event_hash)

    checkpoints = {
        recovery._checkpoint_status(events, None),
        recovery._checkpoint_status(events, at(3, "c" * 64)),
        recovery._checkpoint_status(events, at(2, "c" * 64)),
        recovery._checkpoint_status(events, at(2, "b" * 64)),
        recovery._checkpoint_status(events, at(1, "a" * 64)),
    }
    assert checkpoints == recovery.CHECKPOINT_STATUSES
    lives = {
        recovery._live_status(events, None),
        recovery._live_status(events, (3, "c" * 64)),
        recovery._live_status(events, (2, "c" * 64)),
        recovery._live_status(events, (2, "b" * 64)),
        recovery._live_status(events, (1, "a" * 64)),
    }
    assert lives == recovery.LIVE_STATUSES
    chain = "c" * 64
    fences = {
        recovery.fence_status(None, chain, 1),
        recovery.fence_status(recovery.FenceRead(3, 1, chain), chain, 1),
        recovery.fence_status(recovery.FenceRead(3, 0, None), chain, 1),
        recovery.fence_status(recovery.FenceRead(3, 0, "d" * 64), chain, 1),
        recovery.fence_status(recovery.FenceRead(3, 0, chain), chain, 0),
        recovery.fence_status(recovery.FenceRead(3, 0, chain), chain, 1),
    }
    assert fences == recovery.FENCE_STATUSES
    assert recovery.FAILING_CHECKPOINT_STATUSES < recovery.CHECKPOINT_STATUSES
    assert recovery.FAILING_LIVE_STATUSES < recovery.LIVE_STATUSES
    assert recovery.FAILING_FENCE_STATUSES < recovery.FENCE_STATUSES
    assert recovery.TENANT_PROBLEMS == (
        {"CHAIN_BROKEN"}
        | recovery.FAILING_CHECKPOINT_STATUSES
        | recovery.FAILING_LIVE_STATUSES
        | recovery.FAILING_FENCE_STATUSES
    )


def test_the_accepted_store_problems_are_the_verifiers_own(tmp_path):
    import sqlite3

    without = tmp_path / "without.sqlite3"
    with sqlite3.connect(without) as conn:
        conn.execute("CREATE TABLE resources (id TEXT)")
    unreadable = tmp_path / "unreadable.sqlite3"
    unreadable.write_bytes(b"not a database at all" * 100)
    found = {
        problem
        for path in (without, unreadable)
        for problem in recovery.check_provider_store(path).problems
    }
    # STORE_CORRUPT needs a store that opens but fails its integrity check, which SQLite does
    # not let a test write without damaging pages by hand; it is the third the verifier names.
    assert found | {"STORE_CORRUPT"} == recovery.STORE_PROBLEMS


@pytest.mark.parametrize(
    "argv",
    [
        ["restore", "--report", "{report}", "--ok", "--not-ok"],
        ["restore", "--report", "{report}"],
        ["restore", "--report", "{report}", "--tenant", "t0={head}"],
        ["restore", "--report", "{report}", "--stores-exactly", "two"],
        ["restore", "--report", "{report}", "--stores-exactly", "-1"],
        ["restore", "--report", "{report}", "--stores-exactly", "2", "--stores-exactly", "3"],
        ["restore", "--report", "{report}", "--tenant", "t0={head}", "--unresolved", "t0=-1"],
        ["restore", "--report", "{report}", "--tenant", "t0={head}", "--events-min", "t0"],
        ["restore", "--report", "{report}", "--tenant", "t0={head}", "--tenants-exactly", "t0,,t0"],
        ["restore", "--report", "{report}", "--tenant", "t0={head}", "--tenants-exactly", "t0,t0"],
        ["restore", "--report", "{report}", "--frobnicate"],
        ["restore", "--report", "{report}", "--no-prob"],
        ["replay", "--report", "{replay}", "--complete", "--incomplete"],
        ["replay", "--report", "{replay}"],
        ["replay", "--report", "{replay}", "--decisions", "1.0"],
        ["replay", "--report", "{replay}", "--issues-exactly", "incomplete_history"],
        ["replay", "--report", "{replay}", "--issues-exactly", ""],
        ["purge-record", "--record", "{report}"],
        [],
    ],
    ids=[
        "ok-and-not-ok",
        "no-checks",
        "bindings-alone",
        "count-not-a-number",
        "count-negative",
        "once-only-repeated",
        "unresolved-negative",
        "events-without-count",
        "empty-name",
        "name-twice",
        "unknown-flag",
        "abbreviated-flag",
        "complete-and-incomplete",
        "no-replay-checks",
        "decisions-not-an-integer",
        "issue-not-a-code",
        "issues-empty",
        "purge-record-not-yet",
        "no-subcommand",
    ],
)
def test_usage_errors_exit_2_and_never_pass(capsys, tmp_path, argv):
    report = write(tmp_path / "report.json", healthy())
    replay = write(tmp_path / "replay.json", replay_report())
    path = head(tmp_path / "h.json", T0)
    filled = [arg.format(report=report, replay=replay, head=path) for arg in argv]
    refused(capsys, *filled)


# Reports are read strictly: 1 MiB at most, no duplicate key, version 1, the verifier's shape.


def padded(value: dict, size: int) -> str:
    text = json.dumps(value)
    return text + " " * (size - len(text.encode("utf-8")))


@pytest.mark.parametrize(
    "fault",
    [
        "oversized",
        "duplicate",
        "version-2",
        "version-string",
        "version-true",
        "no-version",
        "float",
        "nan",
        "missing-key",
        "extra-key",
        "tenant-missing-field",
        "tenant-extra-field",
        "events-a-string",
        "chain-ok-a-number",
        "unknown-checkpoint",
        "unknown-live",
        "unknown-fence",
        "no-fence",
        "store-extra-field",
        "problems-not-strings",
        "tenant-twice",
        "not-an-object",
        "empty",
        "missing",
        "directory",
    ],
)
def test_a_malformed_restore_report_is_refused(capsys, tmp_path, heads, fault):
    report = healthy()
    path = tmp_path / "report.json"
    text = None
    if fault == "oversized":
        text = padded(report, reports.MAX_REPORT_BYTES + 1)
    elif fault == "duplicate":
        text = json.dumps(report)[:-1] + ', "ok": false}'
    elif fault == "version-2":
        report["version"] = 2
    elif fault == "version-string":
        report["version"] = "1"
    elif fault == "version-true":
        report["version"] = True
    elif fault == "no-version":
        del report["version"]
    elif fault == "float":
        text = json.dumps(report).replace('"events": 65', '"events": 65.0', 1)
    elif fault == "nan":
        text = json.dumps(report).replace('"events": 65', '"events": NaN', 1)
    elif fault == "missing-key":
        del report["provider_stores"]
    elif fault == "extra-key":
        report["secret"] = "do-not-echo-this"
    elif fault == "tenant-missing-field":
        del report["tenants"][0]["live"]
    elif fault == "tenant-extra-field":
        report["tenants"][0]["purged"] = {"purge_id": "x"}
    elif fault == "events-a-string":
        report["tenants"][0]["events"] = "65"
    elif fault == "chain-ok-a-number":
        report["tenants"][0]["chain_ok"] = 1
    elif fault == "unknown-checkpoint":
        report["tenants"][0]["checkpoint"] = "MATCHES"
    elif fault == "unknown-live":
        report["tenants"][0]["live"] = "LIVE"
    elif fault == "unknown-fence":
        report["tenants"][0]["fence"] = "FENCED"
    elif fault == "no-fence":
        # A report written before the verifier read the fence lacks the field.
        del report["tenants"][0]["fence"]
    elif fault == "store-extra-field":
        report["provider_stores"][0]["size"] = 1
    elif fault == "problems-not-strings":
        report["problems"] = [1]
    elif fault == "tenant-twice":
        report["tenants"][1] = report["tenants"][0]
    elif fault == "not-an-object":
        text = json.dumps([report])
    elif fault == "empty":
        text = ""
    elif fault == "directory":
        path.mkdir()
    if fault == "missing":
        pass
    elif fault == "directory":
        pass
    else:
        write(path, report if text is None else text)
    err = refused(capsys, "restore", "--report", path, *heads, "--ok")
    assert "do-not-echo-this" not in err


def test_a_report_of_exactly_one_mebibyte_is_read(capsys, tmp_path, heads):
    path = write(tmp_path / "report.json", padded(healthy(), reports.MAX_REPORT_BYTES))
    assert path.stat().st_size == reports.MAX_REPORT_BYTES
    code, lines, _ = run(capsys, "restore", "--report", path, *heads, "--ok")
    assert (code, lines) == (0, ["PASS ok", "1 check, 0 failed"])


@pytest.mark.parametrize(
    "fault", ["oversized", "duplicate", "version-2", "restore-report", "extra-key", "missing"]
)
def test_a_malformed_replay_report_is_refused(capsys, tmp_path, fault):
    text = replay_report()
    path = tmp_path / "report.json"
    if fault == "oversized":
        text = text + " " * (reports.MAX_REPORT_BYTES + 1 - len(text.encode()))
    elif fault == "duplicate":
        text = text.rstrip("\n")[:-1] + ',"complete":false}'
    elif fault == "version-2":
        text = text.replace('"version":1', '"version":2')
    elif fault == "restore-report":
        text = json.dumps(healthy())
    elif fault == "extra-key":
        text = text.rstrip("\n")[:-1] + ',"secret":"do-not-echo-this"}'
    if fault != "missing":
        write(path, text)
    err = refused(capsys, "replay", "--report", path, "--complete")
    assert "do-not-echo-this" not in err


# The reports the verifier and the replay write for real.


def test_reports_the_verifier_and_the_replay_wrote_pass_their_checks(
    db, world, runtime, admin_engine, tmp_path, capsys, monkeypatch
):
    tenant = world["identity"].tenant_id
    runtime.execute(world["identity"], request(world).model_dump_json().encode())
    sequence, event_hash = head_of(admin_engine, tenant)
    checkpoint = checkpoint_file(tmp_path, "tenant.head.json", tenant, sequence, event_hash)
    monkeypatch.setenv("MIGRATION_DATABASE_URL", owner_url())
    database = recovery.database_url(owner_url()).database
    restored = tmp_path / "restore-report.json"
    verified = recovery.main(
        ["--restored-database", database, "--compare-live", "--checkpoint", str(checkpoint)]
        + ["--output", str(restored)]
    )
    assert verified == 0
    capsys.readouterr()
    code, lines, _ = run(
        capsys,
        *("restore", "--report", restored, "--tenant", f"t0={checkpoint}"),
        *("--ok", "--no-problems", "--tenants-exactly", "t0", "--stores-exactly", "0"),
        *("--checkpoint", "t0=MATCHES_CHECKPOINT", "--live", "t0=MATCHES_LIVE"),
        *("--chain-ok", "t0", "--unresolved", "t0=0", "--events-min", f"t0={sequence}"),
        *("--fence", "t0=NOT_CHECKED"),
    )
    assert code == 0, lines
    beyond = sequence + 1
    code, lines, _ = run(
        capsys,
        "restore",
        "--report",
        restored,
        "--tenant",
        f"t0={checkpoint}",
        "--events-min",
        f"t0={beyond}",
    )
    assert code == 1
    assert f"FAIL events-min t0={beyond}: expected at least {beyond}, found {sequence}" in lines

    from execbound.replay.runner import run_replay

    source, trusted = publish(db, world, tmp_path)
    decisions = len(run_replay(source, trusted, tmp_path / "replay").decisions)
    assert decisions >= 1
    replay = tmp_path / "replay" / "report.json"
    code, lines, _ = run(
        capsys,
        "replay",
        "--report",
        replay,
        "--complete",
        "--decisions",
        str(decisions),
        "--min-decisions",
        "1",
    )
    assert code == 0, lines
    code, lines, _ = run(capsys, "replay", "--report", replay, "--incomplete")
    assert (code, lines) == (
        1,
        ["FAIL incomplete: expected false, found true", "1 check, 1 failed"],
    )
