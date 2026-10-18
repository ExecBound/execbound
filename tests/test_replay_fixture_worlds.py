# SPDX-License-Identifier: AGPL-3.0-only
"""A regression fixture built from a real PostgreSQL world: the signal-replay world, with a
denial on the recorded budget, a stop, a principal's label and distinctive event ids.

Set `EXECBOUND_REPLAY_FIXTURE_OUT` to a new file's path to keep the fixture this builds, which
is how `tests/fixtures/replay/signal-world-v1.json` was made.
"""

import json
import os
import re
from datetime import timedelta
from pathlib import Path

from conftest import assert_secret_free
from signal_fixtures import post_signal
from signal_fixtures import signal_world as signal_world
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_replay_fixture import values_at
from test_replay_fixture_cli import run
from test_resolution import registry as registry
from test_runtime import api as api
from test_runtime import runtime as runtime
from test_signal_replay import (
    COMPROMISED_CAP,
    MEDIUM_IS_CLEAN,
    MEDIUM_IS_SUSPECT,
    SUSPECT_CAP,
    execute,
    reading,
)

from execbound.audit import append_event
from execbound.execution.stops import activate_stop, release_stop
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.replay.export import export_history

EVENT_IDS = ("ws-lab-7741.corp.example:4f1c", "ws-lab-7741.corp.example:9a2e")
STOP_REASON = "Isolations paused while ws-lab-7741.corp.example is imaged"
PERSON = "Morgan Q. Testperson"
UUID_TEXT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def signal_history(api, db, admin_engine, world, directory):
    """Two isolations on Medium under a cap on compromised hosts: one executed, one denied."""
    recorded = reading(world, rules=COMPROMISED_CAP)
    for step in (create_bundle, validate_bundle, activate_bundle):
        target = recorded if step is create_bundle else recorded.bundle_id
        step(db, world["admin"], target, world["clock"])
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        append_event(
            conn,
            tenant,
            world["admin"].principal_id,
            "principal.labelled",
            {"principal_id": str(world["identity"].principal_id), "label": PERSON},
        )
    post_signal(db, world, "Medium", event_id=EVENT_IDS[0])
    assert execute(api, world)["state"] == "EXECUTED"
    world["clock"].value += timedelta(seconds=5)
    post_signal(db, world, "Medium", event_id=EVENT_IDS[1])
    assert execute(api, world, idempotency_key="second")["state"] == "DENIED"
    activate_stop(db, world["admin"], STOP_REASON, world["clock"])
    world["clock"].value += timedelta(seconds=5)
    release_stop(db, world["admin"], "Imaging finished", world["clock"])
    export = export_history(db, world["admin"], world["clock"])
    candidates = (
        reading(world, thresholds=MEDIUM_IS_SUSPECT),
        reading(world, thresholds=MEDIUM_IS_CLEAN),
        reading(world, thresholds=MEDIUM_IS_SUSPECT, rules=SUSPECT_CAP),
    )
    source, head = directory / "history.json", directory / "history.head.json"
    source.write_text(export.model_dump_json(), encoding="utf-8")
    head.write_text(export.head.model_dump_json(), encoding="utf-8")
    files = []
    for index, candidate in enumerate(candidates):
        path = directory / f"candidate-{index}.json"
        path.write_text(candidate.model_dump_json(), encoding="utf-8")
        files.append(path)
    return export, candidates, source, head, files


def build(monkeypatch, capsys, source, head, candidates, output):
    arguments = ["replay-fixture", "--input", source, "--trusted-head", head]
    for candidate in candidates:
        arguments += ["--candidate", candidate]
    return run(monkeypatch, capsys, *arguments, "--output", output, offline=False)


def test_rf9_a_signal_world_fixture_is_deterministic_sanitized_and_checks(
    api, db, admin_engine, signal_world, live_provider, tmp_path, monkeypatch, capsys
):
    export, candidates, source, head, files = signal_history(
        api, db, admin_engine, signal_world, tmp_path
    )
    first, second = tmp_path / "first.json", tmp_path / "second.json"
    outputs = [build(monkeypatch, capsys, source, head, files, path) for path in (first, second)]
    assert all(code == 0 for code, _, _ in outputs), outputs
    raw = first.read_bytes()
    assert second.read_bytes() == raw

    checks = [
        run(monkeypatch, capsys, "replay-fixture-check", "--fixture", first, offline=False)
        for _ in range(2)
    ]
    # The structured log line on stderr carries its own time; what the check says does not.
    assert checks[0][:2] == checks[1][:2] and checks[0][0] == 0
    for _, out, err in (*outputs, *checks):
        assert_secret_free(out + err)

    text = raw.decode()
    assert_secret_free(json.loads(text))
    source_text = source.read_text() + "".join(path.read_text() for path in files)
    identifiers = set(UUID_TEXT.findall(source_text.lower()))
    assert len(identifiers) > 20
    lowered = text.lower()
    for identifier in identifiers:
        assert identifier not in lowered and identifier.replace("-", "") not in lowered
    for label in (*EVENT_IDS, "ws-lab-7741", STOP_REASON, PERSON, "device-01", "MDE lab"):
        assert label not in text

    fixture = json.loads(text)
    # The caller's own keys never reach an export; the gateway's recorded ones are replaced.
    keys = set(values_at(fixture, "idempotency_key"))
    assert keys and all(re.fullmatch(r"key-\d{6}", key) for key in keys)
    assert not keys & set(values_at(json.loads(source.read_text()), "idempotency_key"))
    versions = {
        version
        for key in ("resource_version", "mapping_version", "expected_version")
        for version in values_at(fixture, key)
    }
    assert versions and all(re.fullmatch(r"version-\d{6}", version) for version in versions)
    facts = [
        fact
        for event in fixture["export"]["events"]
        if isinstance(event["payload"].get("frozen"), dict)
        for fact in event["payload"]["frozen"]["facts"]
    ]
    # A signal fact's source version is its source's registration number, which evaluation
    # compares with its records, so it is kept; every other fact's is a pseudonym.
    assert {fact["source_kind"] for fact in facts} == {"incident", "inventory", "signal"}
    for fact in facts:
        if fact["source_kind"] == "signal":
            assert fact["source_version"].isdigit()
        else:
            assert re.fullmatch(r"version-\d{6}", fact["source_version"])
    baseline = [
        row for row in fixture["expected"]["baseline"]["decisions"] if row["stage"] == "ADMISSION"
    ]
    isolations = [row for row in baseline if row["action"] == "endpoint.isolate"]
    assert [(row["recorded_effect"], row["effect"]) for row in isolations] == [
        ("ELIGIBLE", "ELIGIBLE"),
        ("DENY", "DENY"),
    ]
    assert isolations[1]["reasons"] == ["HARD_LIMIT:compromised-cap"]
    clean = {row["sequence"]: row for row in fixture["expected"]["candidates"][1]["decisions"]}
    for row in isolations:
        assert clean[row["sequence"]]["effect"] == "UNRESOLVED"
        assert "SIGNAL_EVIDENCE_UNAVAILABLE" in clean[row["sequence"]]["reasons"]
    capped = {row["sequence"]: row for row in fixture["expected"]["candidates"][2]["decisions"]}
    assert capped[isolations[1]["sequence"]]["reasons"] == ["HARD_LIMIT:suspect-cap"]
    assert len(fixture["export"]["events"]) == len(export.events)
    kept = os.environ.get("EXECBOUND_REPLAY_FIXTURE_OUT")
    if kept:
        Path(kept).write_bytes(raw)
