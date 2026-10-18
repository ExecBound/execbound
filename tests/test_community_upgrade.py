# SPDX-License-Identifier: AGPL-3.0-only
"""`scripts/community_upgrade.py` reads what an upgraded installation says, and refuses on a gap.

The script drives a real installation in `fresh-machine`; these cases feed its readers the
shapes that installation produces, and the ones it must refuse, so each check is shown to bite
without Docker. One case holds the script's two endpoints to the ones quickstart creates.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

from execbound import quickstart

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "community_upgrade", ROOT / "scripts" / "community_upgrade.py"
)
assert _spec is not None and _spec.loader is not None
upgrade = importlib.util.module_from_spec(_spec)
sys.modules["community_upgrade"] = upgrade
_spec.loader.exec_module(upgrade)

ENV = (
    "# written by execbound init\n"
    "POSTGRES_PASSWORD=secret\n"
    "EXECBOUND_IMAGE=execbound:base\n"
    "EXECBOUND_PORT=18090\n"
)


def evaluated(sequence: int, device: str, incident: str | None) -> dict:
    return {
        "kind": "execution.evaluated",
        "sequence": sequence,
        "event_hash": f"hash-{sequence}",
        "payload": {
            "frozen": {
                "request": {"claimed_context": {"incident_id": incident, "role": None}},
                "facts": [
                    {"name": "role", "source_kind": "inventory", "source_object_id": device},
                    {"name": "incident", "source_kind": "incident", "source_object_id": "x"},
                ],
            }
        },
    }


def test_the_endpoints_are_the_ones_quickstart_creates():
    assert upgrade.DEVICES == {device: host for device, host, *_ in quickstart.ENDPOINTS}
    assert set(upgrade.FIRST_RUN) == set(upgrade.AFTER_UPGRADE) == set(upgrade.DEVICES.values())


def test_the_image_line_is_the_only_line_rewritten():
    rewritten = upgrade.rewrite_image(ENV, "execbound:head")
    assert rewritten == ENV.replace(
        "EXECBOUND_IMAGE=execbound:base", "EXECBOUND_IMAGE=execbound:head"
    )


@pytest.mark.parametrize("env", ["POSTGRES_PASSWORD=x\n", ENV + "EXECBOUND_IMAGE=again\n"])
def test_an_env_that_does_not_name_the_image_exactly_once_is_refused(env):
    with pytest.raises(upgrade.UpgradeFailed, match="EXECBOUND_IMAGE"):
        upgrade.rewrite_image(env, "execbound:head")


def test_quickstart_decisions_are_read_from_its_report():
    output = (
        "Quickstart complete.\n"
        "  ws01.example     EXECUTED  INC-1001  execution dc5832ec-717c-4d61-8ae6-5eb717dbf716\n"
        "  ws02.example     DENIED    INC-1002  execution cf9978be-1e92-4515-a90b-c2126a508348\n"
    )
    assert upgrade.first_decisions(output) == upgrade.FIRST_RUN


def test_a_revision_must_be_a_single_head():
    assert upgrade.revision(" Container x Running\n0062_people_numbers (head)\n") == (
        "0062_people_numbers"
    )
    with pytest.raises(upgrade.UpgradeFailed, match="none"):
        upgrade.revision("")
    with pytest.raises(upgrade.UpgradeFailed, match="expected one alembic head"):
        upgrade.revision("0061_a (head)\n0061_b (head)\n")


def test_incidents_are_read_from_the_frozen_requests_by_device():
    export = {
        "events": [
            {"kind": "execution.requested", "sequence": 1},
            evaluated(2, "device-ws-01", "inc-1"),
            evaluated(3, "device-ws-02", "inc-2"),
            evaluated(4, "device-other", "inc-3"),
            evaluated(5, "device-ws-01", None),
        ]
    }
    assert upgrade.incidents(export) == {"ws01.example": "inc-1", "ws02.example": "inc-2"}


def test_the_history_is_kept_only_when_the_old_head_is_at_its_sequence():
    export = {"events": [evaluated(1, "device-ws-01", "a"), evaluated(2, "device-ws-02", "b")]}
    assert upgrade.history_kept({"head_sequence": 2, "head_hash": "hash-2"}, export)
    assert not upgrade.history_kept({"head_sequence": 2, "head_hash": "rewritten"}, export)
    assert not upgrade.history_kept({"head_sequence": 3, "head_hash": "hash-3"}, export)


def test_jobs_are_read_from_their_logs_and_a_failure_is_kept():
    logs = (
        'jobs-1  | {"event":"job.completed","command":"recover","tick":1}\n'
        "jobs-1  | not json\n"
        'jobs-1  | {"event":"job.completed","command":"notify","tick":1}\n'
        'jobs-1  | {"event":"job.failed","command":"monitor-process","tick":1}\n'
    )
    completed, failures = upgrade.job_results(logs)
    assert completed == {"recover", "notify"}
    assert [row["command"] for row in failures] == ["monitor-process"]


def test_a_restore_report_passes_only_when_it_verified_completely():
    tenant = {"chain_ok": True, "live": "MATCHES_LIVE", "unresolved_executions": 0, "events": 3}
    assert upgrade.verified({"ok": True, "tenants": [tenant]}, "before") == tenant
    with pytest.raises(upgrade.UpgradeFailed, match="did not verify"):
        upgrade.verified({"ok": False, "tenants": [tenant], "problems": ["x"]}, "before")
    for broken in ({"chain_ok": False}, {"live": "BEHIND_LIVE"}, {"unresolved_executions": 1}):
        with pytest.raises(upgrade.UpgradeFailed, match="restored incompletely"):
            upgrade.verified({"ok": True, "tenants": [tenant | broken]}, "after")
