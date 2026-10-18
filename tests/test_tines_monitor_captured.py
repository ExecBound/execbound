# SPDX-License-Identifier: AGPL-3.0-only
"""TM5: what the live trial's story built, sent the way it sends it, through the real intake.

The two fixtures are the `Build result` and `Build heartbeat` bodies Tines emitted in the
live trial of 26 September 2026 (`docs/trials/2026-09-26-tines-monitor.md`), captured from
the story's own events. The story sends each as `TO_JSON` text, so that is what is posted
here, to the intake-only origin the trial's tunnel pointed at, on real PostgreSQL.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_execution import provision_identity

from execbound.monitoring import store
from execbound.monitoring.ingress import create_ingress

FIXTURES = Path(__file__).resolve().parent / "fixtures"
RESULT = json.loads((FIXTURES / "tines-monitor-result.json").read_text())
HEARTBEAT = json.loads((FIXTURES / "tines-monitor-heartbeat.json").read_text())


@pytest.fixture
def intake(db, seeded, admin_engine):
    now = datetime.now(UTC)
    admin = provision_identity(admin_engine, db, seeded["tenants"][0], "ADMIN", now)
    source = store.create_source(
        db,
        admin,
        label="Tines lab: Monitor an action",
        story_id=RESULT["story_id"],
        expires_at=now + timedelta(hours=1),
    )
    with TestClient(create_ingress(db)) as client:
        yield client, source


def _post(client, source, body):
    return client.post(
        "/v1/monitor/events",
        content=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {source.token}", "Content-Type": "application/json"},
    )


def test_tm5_the_captured_bodies_are_the_contract_the_story_was_built_to():
    assert RESULT["story_id"] == HEARTBEAT["story_id"] and RESULT["story_id"].isdigit()
    assert set(RESULT) == {
        "version",
        "event_id",
        "story_id",
        "occurred_at",
        "kind",
        "action",
        "target_ref",
        "outcome",
    }
    assert set(HEARTBEAT) == {"version", "event_id", "story_id", "occurred_at", "kind"}


def test_tm5_the_captured_result_is_deduplicated_and_heartbeats_only_refresh(intake):
    client, source = intake
    for body in (RESULT, HEARTBEAT):
        first = _post(client, source, body)
        assert first.status_code == 202, first.text
        again = _post(client, source, body)
        if body["kind"] == "heartbeat":
            assert again.status_code == 202
            assert first.json() == again.json() == {"observation_id": None, "duplicate": False}
        else:
            assert again.status_code == 200
            assert again.json() == {
                "observation_id": first.json()["observation_id"],
                "duplicate": True,
            }


def test_tm5_the_same_result_with_the_story_id_as_a_number_is_refused(intake):
    """What `content_type: json` made of the first body in the live trial."""
    client, source = intake
    answer = _post(client, source, {**RESULT, "story_id": int(RESULT["story_id"])})
    assert answer.status_code == 400
    assert answer.json()["code"] == "INVALID_EVENT"
