# SPDX-License-Identifier: AGPL-3.0-only
"""Offline file commands validate bounded inputs before creating exclusive outputs."""

import json
import sys
from uuid import uuid4

import pytest

from execbound.audit import GENESIS
from execbound.replay.models import ReplayExport, TrustedHead


@pytest.fixture
def inputs(tmp_path):
    tenant = uuid4()
    head = TrustedHead(tenant_id=tenant, sequence=0, event_hash=GENESIS)
    export = ReplayExport(tenant_id=tenant, events=(), bundles=(), head=head)
    source, checkpoint = tmp_path / "history.json", tmp_path / "head.json"
    source.write_text(export.model_dump_json(), encoding="utf-8")
    checkpoint.write_text(head.model_dump_json(), encoding="utf-8")
    return source, checkpoint


def test_replay_writes_deterministic_new_reports(inputs, tmp_path):
    from execbound.replay.runner import run_replay

    source, checkpoint = inputs
    first, second = tmp_path / "first", tmp_path / "second"
    report = run_replay(source, checkpoint, first)
    run_replay(source, checkpoint, second)
    assert report.complete and report.mode == "BASELINE"
    assert sorted(path.name for path in first.iterdir()) == ["report.json", "report.md"]
    for name in ("report.json", "report.md"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert "internal consistency" in (first / "report.md").read_text()


@pytest.mark.parametrize("bad", ["duplicate", "float", "version", "head", "missing"])
def test_bad_input_leaves_no_report(inputs, tmp_path, bad):
    from execbound.replay.runner import ReplayFileError, run_replay

    source, checkpoint = inputs
    if bad == "duplicate":
        source.write_text('{"version":1,"version":1}', encoding="utf-8")
    elif bad == "float":
        checkpoint.write_text(checkpoint.read_text().replace('"sequence":0', '"sequence":0.0'))
    elif bad == "version":
        checkpoint.write_text(checkpoint.read_text().replace('"version":1', '"version":2'))
    elif bad == "head":
        checkpoint.write_text(checkpoint.read_text().replace(GENESIS, "1" * 64))
    else:
        source.unlink()
    output = tmp_path / "report"
    with pytest.raises(ReplayFileError, match="Replay files unavailable") as failure:
        run_replay(source, checkpoint, output)
    assert failure.value.__context__ is None
    assert not output.exists()


def test_existing_outputs_and_input_aliases_are_preserved(inputs, tmp_path):
    from execbound.replay.runner import ReplayFileError, run_replay

    source, checkpoint = inputs
    output = tmp_path / "report"
    output.mkdir()
    (output / "report.json").write_text("private-canary")
    original = source.read_bytes()
    for target in (output, source, checkpoint):
        with pytest.raises(ReplayFileError):
            run_replay(source, checkpoint, target)
    assert source.read_bytes() == original
    assert (output / "report.json").read_text() == "private-canary"


def test_bounded_read_and_failed_write_clean_only_owned_files(inputs, tmp_path, monkeypatch):
    from execbound.replay import runner

    source, checkpoint = inputs
    monkeypatch.setattr(runner, "MAX_EXPORT_BYTES", 4)
    with pytest.raises(runner.ReplayFileError):
        runner.run_replay(source, checkpoint, tmp_path / "small")
    monkeypatch.undo()
    original = runner.write_new

    def fail(path, data):
        if path.name == "report.md":
            raise OSError("private-canary")
        return original(path, data)

    monkeypatch.setattr(runner, "write_new", fail)
    with pytest.raises(runner.ReplayFileError):
        runner.run_replay(source, checkpoint, tmp_path / "failed")
    assert not (tmp_path / "failed").exists()
    assert source.exists() and checkpoint.exists()


def test_cli_offline_branch_precedes_environment_and_database(
    inputs, tmp_path, monkeypatch, capsys
):
    from execbound import cli

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline replay touched live initialization")

    source, checkpoint = inputs
    monkeypatch.setattr(cli, "load_dotenv", forbidden)
    monkeypatch.setattr(cli, "create_engine", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "execbound",
            "replay",
            "--input",
            str(source),
            "--trusted-head",
            str(checkpoint),
            "--output",
            str(tmp_path / "r"),
        ],
    )
    cli.main()
    assert "Replay reports created" in capsys.readouterr().out


def test_cli_failure_never_prints_private_input(inputs, tmp_path, monkeypatch, capsys):
    from execbound import cli

    source, checkpoint = inputs
    source.write_text(json.dumps({"token": "private-canary"}))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "execbound",
            "replay",
            "--input",
            str(source),
            "--trusted-head",
            str(checkpoint),
            "--output",
            str(tmp_path / "r"),
        ],
    )
    with pytest.raises(SystemExit) as failure:
        cli.main()
    assert failure.value.code == 2
    captured = capsys.readouterr()
    assert "private-canary" not in captured.out + captured.err
    assert "unavailable" in captured.err


def test_failed_publication_preserves_concurrently_created_foreign_file(
    inputs, tmp_path, monkeypatch
):
    from execbound.replay import runner

    source, checkpoint = inputs
    original = runner.write_new
    output = tmp_path / "output"

    def concurrent_file(path, data):
        if path.name == "report.md":
            path.write_text("foreign-content")
        return original(path, data)

    monkeypatch.setattr(runner, "write_new", concurrent_file)
    with pytest.raises(runner.ReplayFileError):
        runner.run_replay(source, checkpoint, output)
    assert (output / "report.md").read_text() == "foreign-content"
    assert not (output / "report.json").exists()


def test_failed_publication_preserves_replacement_of_our_earlier_file(
    inputs, tmp_path, monkeypatch
):
    from execbound.replay import runner

    source, checkpoint = inputs
    output = tmp_path / "output"
    original = runner.write_new

    def replace_earlier(path, data):
        if path.name == "report.md":
            replacement = output / "replacement"
            replacement.write_text("foreign-replacement")
            replacement.replace(output / "report.json")
            raise OSError("Synthetic second write failure")
        return original(path, data)

    monkeypatch.setattr(runner, "write_new", replace_earlier)
    with pytest.raises(runner.ReplayFileError):
        runner.run_replay(source, checkpoint, output)
    assert (output / "report.json").read_text() == "foreign-replacement"
