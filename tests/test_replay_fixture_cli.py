# SPDX-License-Identifier: AGPL-3.0-only
"""The fixture commands run offline and answer refusals with codes only (docs/REPLAY.md)."""

import json
import os
import stat
import sys

import pytest
from test_replay_fixture import PERSON, STOP_REASON, world


@pytest.fixture
def inputs(tmp_path):
    export, candidate = world()
    source, head = tmp_path / "history.json", tmp_path / "history.head.json"
    candidate_file = tmp_path / "candidate.json"
    source.write_text(export.model_dump_json(), encoding="utf-8")
    head.write_text(export.head.model_dump_json(), encoding="utf-8")
    candidate_file.write_text(candidate.model_dump_json(), encoding="utf-8")
    return source, head, candidate_file


def run(monkeypatch, capsys, *arguments, offline=True):
    from execbound import cli

    if offline:

        def forbidden(*args, **kwargs):
            raise AssertionError("A fixture command touched live initialization")

        monkeypatch.setattr(cli, "load_dotenv", forbidden)
        monkeypatch.setattr(cli, "create_engine", forbidden)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(sys, "argv", ["execbound", *map(str, arguments)])
    try:
        cli.main()
        code = 0
    except SystemExit as exit:
        code = exit.code
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def build(monkeypatch, capsys, inputs, output):
    source, head, candidate = inputs
    return run(
        monkeypatch,
        capsys,
        "replay-fixture",
        "--input",
        source,
        "--trusted-head",
        head,
        "--candidate",
        candidate,
        "--output",
        output,
    )


def test_rf8_both_commands_run_without_an_environment_or_a_database(
    inputs, tmp_path, monkeypatch, capsys
):
    output = tmp_path / "fixture.json"
    code, out, _ = build(monkeypatch, capsys, inputs, output)
    assert code == 0 and "Replay fixture created" in out
    assert json.loads(output.read_text())["format"] == "execbound.replay-fixture"
    code, out, _ = run(monkeypatch, capsys, "replay-fixture-check", "--fixture", output)
    assert code == 0 and "Replay fixture matches" in out
    again = tmp_path / "again.json"
    code, _, _ = run(
        monkeypatch, capsys, "replay-fixture", "--from-fixture", output, "--output", again
    )
    assert code == 0 and again.read_bytes() == output.read_bytes()


def test_rf8_a_fixture_is_written_readable_by_its_owner_only(inputs, tmp_path, monkeypatch, capsys):
    # A fixture of a real tenant is handled like the export it came from, which is private.
    previous = os.umask(0o022)
    try:
        built, again = tmp_path / "fixture.json", tmp_path / "again.json"
        assert build(monkeypatch, capsys, inputs, built)[0] == 0
        code, _, _ = run(
            monkeypatch, capsys, "replay-fixture", "--from-fixture", built, "--output", again
        )
        assert code == 0
    finally:
        os.umask(previous)
    for path in (built, again):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_rf8_a_changed_expectation_exits_one_with_codes_and_numbers_only(
    inputs, tmp_path, monkeypatch, capsys
):
    output = tmp_path / "fixture.json"
    build(monkeypatch, capsys, inputs, output)
    document = json.loads(output.read_text())
    row = document["expected"]["baseline"]["decisions"][0]
    row["effect"] = "DENY"
    output.write_text(json.dumps(document, indent=1, sort_keys=True))
    code, out, err = run(monkeypatch, capsys, "replay-fixture-check", "--fixture", output)
    assert code == 1
    assert f"baseline sequence {row['sequence']} effect" in out + err
    assert "DENY" not in out + err


def test_rf8_an_edited_history_exits_two_with_its_code(inputs, tmp_path, monkeypatch, capsys):
    output = tmp_path / "fixture.json"
    build(monkeypatch, capsys, inputs, output)
    output.write_text(output.read_text().replace('"reason-000001"', '"reason-000009"'))
    code, out, err = run(monkeypatch, capsys, "replay-fixture-check", "--fixture", output)
    assert code == 2 and "INVALID_CHAIN" in err


def test_rf8_refusals_name_a_code_and_never_a_value_or_a_path(
    inputs, tmp_path, monkeypatch, capsys
):
    source, head, candidate = inputs
    document = json.loads(candidate.read_text())
    document["tenant_id"] = "00000000-0000-4000-8000-00000000abcd"
    candidate.write_text(json.dumps(document))
    output = tmp_path / "private-canary-fixture.json"
    code, out, err = build(monkeypatch, capsys, inputs, output)
    assert code == 2
    assert "INVALID_CANDIDATE" in err
    assert "private-canary" not in out + err and str(tmp_path) not in out + err
    assert not output.exists()
    source.write_text(json.dumps({"token": "private-canary", "reason": STOP_REASON}))
    code, out, err = build(monkeypatch, capsys, inputs, output)
    assert code == 2
    for private in ("private-canary", STOP_REASON, PERSON, str(tmp_path)):
        assert private not in out + err
    assert not output.exists()


def test_rf8_an_existing_output_and_an_input_alias_are_refused(
    inputs, tmp_path, monkeypatch, capsys
):
    source, head, _ = inputs
    original = source.read_bytes()
    existing = tmp_path / "existing.json"
    existing.write_text("private-canary")
    for target in (existing, source, head):
        code, out, err = build(monkeypatch, capsys, inputs, target)
        assert code == 2 and "private-canary" not in out + err
    assert existing.read_text() == "private-canary"
    assert source.read_bytes() == original


def test_rf8_the_build_takes_its_inputs_or_a_fixture_never_both(
    inputs, tmp_path, monkeypatch, capsys
):
    source, head, _ = inputs
    output = tmp_path / "fixture.json"
    build(monkeypatch, capsys, inputs, output)
    for arguments in (
        ("--from-fixture", output, "--input", source, "--output", tmp_path / "a.json"),
        ("--input", source, "--output", tmp_path / "b.json"),
        ("--trusted-head", head, "--output", tmp_path / "c.json"),
    ):
        code, _, _ = run(monkeypatch, capsys, "replay-fixture", *arguments)
        assert code == 2
    assert not any((tmp_path / name).exists() for name in ("a.json", "b.json", "c.json"))
