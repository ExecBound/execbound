# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence refuses incomplete tests and exports only explicit synthetic artifacts."""

import json
import subprocess  # nosec B404
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest

from execbound_harness import validation_evidence as evidence

REPOSITORY = Path(__file__).resolve().parents[1]


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "uv.lock").write_text("locked dependencies")
    (repository / "tests").mkdir()
    (repository / "tests/mcp-legacy.txt").write_text("locked maintained client")
    metadata = repository / ".tools/mcp-legacy/mcp-1.30.0.dist-info"
    metadata.mkdir(parents=True)
    (metadata / "METADATA").write_text("Name: mcp\nVersion: 1.30.0\n")
    artifacts = tmp_path / "evidence"
    artifacts.mkdir()
    for name in evidence.artifact_names():
        path = artifacts / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{}" if path.suffix == ".json" else b"synthetic artifact")
    (artifacts / "validation.json").write_text(
        json.dumps({"providers_stopped_before_replay": True, "live_fingerprints_unchanged": True})
    )
    nodes = sorted(
        {prefix for values in evidence.ACCEPTANCE_PREFIXES.values() for prefix in values}
    )
    suite = ElementTree.Element("testsuite")
    for node in nodes:
        module, name = node.split("::")
        ElementTree.SubElement(
            suite, "testcase", classname=module[:-3].replace("/", "."), name=name
        )
    junit = tmp_path / "results.xml"
    ElementTree.ElementTree(suite).write(junit)
    collected = tmp_path / "collected.txt"
    collected.write_text("\n".join(nodes))
    monkeypatch.setattr(
        evidence.subprocess,
        "check_output",
        lambda command, **kwargs: "a" * 40 if command[-1] == "HEAD" else "",
    )
    return junit, collected, artifacts, repository


def test_manifest_maps_exact_tests_and_excludes_private_files(inputs):
    junit, collected, artifacts, repository = inputs
    (artifacts / "credentials.json").write_text('{"token":"private-canary"}')
    result = evidence.manifest(*inputs)
    assert result["source_commit"] == "a" * 40
    assert result["worktree_dirty"] is False
    assert result["maintained_mcp_version"] == "1.30.0"
    assert set(result["acceptance_evidence"]) == set("ABCDEFGHIJKLMNOPQRSTUVWX") | {
        "SA",
        "SL",
        "GC",
        "AL",
        "SP",
        "SM",
        "DN",
        "LA",
        "EX",
        "SG",
        "PK",
        "CF",
        "AY",
        "MQ",
        "HV",
        "AQ",
        "AK",
        "XW",
        "SN",
        "AR",
        "MC",
        "MI",
        "AV",
        "RF",
    }
    assert result["test_count"] == len(collected.read_text().splitlines())
    assert {item["path"] for item in result["artifacts"]} == set(evidence.artifact_names())
    assert "private-canary" not in json.dumps(result)
    assert result["named_practitioner_host_trial"] == "NOT_PERFORMED"
    before = next(item for item in result["artifacts"] if item["path"] == "tenant-0.json")
    (artifacts / "tenant-0.json").write_text('{"changed":true}')
    after = next(
        item for item in evidence.manifest(*inputs)["artifacts"] if item["path"] == "tenant-0.json"
    )
    assert before["sha256"] != after["sha256"]


@pytest.mark.parametrize("outcome", ["failure", "error", "skipped"])
def test_manifest_rejects_any_nonpassing_test(inputs, outcome):
    tree = ElementTree.parse(inputs[0])
    ElementTree.SubElement(tree.getroot().find("testcase"), outcome)
    tree.write(inputs[0])
    with pytest.raises(ValueError, match="fully passing"):
        evidence.manifest(*inputs)


@pytest.mark.parametrize("change", ["missing", "duplicate", "foreign"])
def test_manifest_rejects_results_not_matching_collection(inputs, change):
    tree = ElementTree.parse(inputs[0])
    root = tree.getroot()
    first = root.find("testcase")
    if change == "missing":
        root.remove(first)
    elif change == "duplicate":
        root.append(first)
    else:
        first.set("name", "uncollected_test")
    tree.write(inputs[0])
    with pytest.raises(ValueError, match="match collection"):
        evidence.manifest(*inputs)


def test_manifest_requires_every_mapped_test_family(inputs):
    tree = ElementTree.parse(inputs[0])
    first = tree.getroot().find("testcase")
    node = first.attrib["classname"].replace(".", "/") + ".py::" + first.attrib["name"]
    tree.getroot().remove(first)
    tree.write(inputs[0])
    inputs[1].write_text("\n".join(n for n in inputs[1].read_text().splitlines() if n != node))
    with pytest.raises(ValueError, match="Acceptance evidence"):
        evidence.manifest(*inputs)


@pytest.mark.parametrize("name", ["providers_stopped_before_replay", "live_fingerprints_unchanged"])
def test_manifest_requires_isolation_evidence(inputs, name):
    path = inputs[2] / "validation.json"
    value = json.loads(path.read_text())
    value[name] = False
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="Isolation evidence"):
        evidence.manifest(*inputs)


def test_manifest_rejects_secret_fields_in_allowlisted_json(inputs):
    (inputs[2] / "tenant-0.json").write_text('{"token":"private-canary"}')
    with pytest.raises(ValueError):
        evidence.manifest(*inputs)


def test_manifest_rejects_xml_entities(inputs):
    inputs[0].write_text('<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///secret">]><testsuite/>')
    with pytest.raises(ValueError, match="XML declaration"):
        evidence.manifest(*inputs)


def test_manifest_requires_all_allowlisted_artifacts(inputs):
    (inputs[2] / "comparison-1/report.json").unlink()
    with pytest.raises(OSError):
        evidence.manifest(*inputs)


def test_manifest_embeds_only_the_bounded_scanned_validation_bytes(inputs, monkeypatch):
    original = evidence.read_bounded
    expected = json.loads((inputs[2] / "validation.json").read_text())

    def replace_after_read(path, limit):
        raw = original(path, limit)
        if path.name == "validation.json":
            path.write_text(json.dumps({**expected, "token": "private-canary"}))
        return raw

    monkeypatch.setattr(evidence, "read_bounded", replace_after_read)
    result = evidence.manifest(*inputs)
    assert result["validation"] == expected
    assert "private-canary" not in json.dumps(result)


def test_every_signal_test_file_is_security_signal_evidence():
    # Group SG names each file, as every group does; a new signal test file must join it.
    files = sorted(path.name for path in (REPOSITORY / "tests").glob("test_signal_*.py"))
    assert files
    missing = [
        name
        for name in files
        if f"tests/{name}::test_" not in evidence.ACCEPTANCE_PREFIXES.get("SG", ())
    ]
    assert missing == []


@pytest.mark.parametrize("selection", [None, *evidence.SELECTIONS])
def test_every_acceptance_prefix_still_matches_a_collected_test(selection):
    # A renamed test must fail here rather than only in the CI evidence step, under the whole
    # suite and under the one selection a run may make (#747).
    # Fixed argv without a shell; collection imports the suite and reads no database.
    chosen = [] if selection is None else ["-m", selection]
    completed = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            *chosen,
        ],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    nodes = [
        line.strip()
        for line in completed.stdout.splitlines()
        if line.startswith("tests/") and "::" in line
    ]
    assert nodes
    missing = sorted(
        f"{letter}: {prefix}"
        for letter, prefixes in evidence.ACCEPTANCE_PREFIXES.items()
        for prefix in prefixes
        if not any(node.startswith(prefix) for node in nodes)
    )
    assert missing == []


def run_main(monkeypatch, capsys, inputs, output, *, evidence_directory=None, extra=()):
    """Drive the command-line entry point and return its status and stderr."""
    junit, collected, artifacts, repository = inputs
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validation-evidence",
            "--junit",
            str(junit),
            "--collected",
            str(collected),
            "--evidence",
            str(artifacts if evidence_directory is None else evidence_directory),
            "--repository",
            str(repository),
            "--output",
            str(output),
            *extra,
        ],
    )
    status = 0
    try:
        evidence.main()
    except SystemExit as exit_signal:
        status = exit_signal.code
    return status, capsys.readouterr().err


def test_the_command_writes_the_manifest_and_reports_nothing_on_stderr(
    inputs, tmp_path, monkeypatch, capsys
):
    output = tmp_path / "manifest.json"
    status, stderr = run_main(monkeypatch, capsys, inputs, output)
    assert status == 0
    assert stderr == ""
    assert json.loads(output.read_text())["test_count"] > 0


def test_a_whole_run_records_no_selection_and_a_selected_run_records_its_own(
    inputs, tmp_path, monkeypatch, capsys
):
    whole = tmp_path / "whole.json"
    assert run_main(monkeypatch, capsys, inputs, whole) == (0, "")
    assert "selection" not in json.loads(whole.read_text())
    selected = tmp_path / "selected.json"
    status = run_main(monkeypatch, capsys, inputs, selected, extra=("--selection", "not timed"))
    assert status == (0, "")
    assert json.loads(selected.read_text())["selection"] == "not timed"


@pytest.mark.parametrize("selection", ["timed", "not integration", "not timed and not slow", ""])
def test_any_other_selection_is_refused(inputs, tmp_path, monkeypatch, capsys, selection):
    with pytest.raises(ValueError, match="Unsupported test selection"):
        evidence.manifest(*inputs, selection=selection)
    output = tmp_path / "manifest.json"
    status, stderr = run_main(monkeypatch, capsys, inputs, output, extra=("--selection", selection))
    assert status == 2 and "invalid choice" in stderr
    assert not output.exists()


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        ("not-passing", "Validation suite is not fully passing"),
        ("secret-field", "PRIVATE_DATA"),
        ("unparsable-artifact", "JSONDecodeError"),
        ("output-exists", "FileExistsError"),
    ],
)
def test_each_failure_class_prints_its_own_reason(
    inputs, tmp_path, monkeypatch, capsys, failure, reason
):
    junit, _collected, artifacts, _repository = inputs
    output = tmp_path / "manifest.json"
    if failure == "not-passing":
        # A strict xfail is a pass to pytest and a <skipped> case here, so this is the
        # condition a green suite still fails on and the one the message must name.
        tree = ElementTree.parse(junit)
        ElementTree.SubElement(tree.getroot().find("testcase"), "skipped")
        tree.write(junit)
    elif failure == "secret-field":
        (artifacts / "tenant-0.json").write_text('{"token":"private-canary"}')
    elif failure == "unparsable-artifact":
        (artifacts / "tenant-0.json").write_text("not json at all")
    else:
        output.write_text("an earlier run's manifest")
    status, stderr = run_main(monkeypatch, capsys, inputs, output)
    assert status == 2
    assert stderr == f"Validation evidence unavailable: {reason}\n"
    assert "private-canary" not in stderr


@pytest.mark.parametrize("carrier", ["workspace-path", "git-argv"])
def test_no_path_or_argv_ever_reaches_the_failure_message(
    inputs, tmp_path, monkeypatch, capsys, carrier
):
    _junit, _collected, _artifacts, repository = inputs
    output = tmp_path / "manifest.json"
    if carrier == "workspace-path":
        # FileNotFoundError's own text carries the path it was given.
        secret_directory = tmp_path / "canary-workspace-6f2a"
        status, stderr = run_main(
            monkeypatch, capsys, inputs, output, evidence_directory=secret_directory
        )
        assert stderr == "Validation evidence unavailable: FileNotFoundError\n"
        assert "canary-workspace-6f2a" not in stderr
    else:
        # CalledProcessError's own text carries the full argv, --repository included.
        command = ["git", "-C", str(repository), "rev-parse", "HEAD"]

        def refuse(*_arguments, **_keywords):
            raise subprocess.CalledProcessError(128, command)

        monkeypatch.setattr(evidence.subprocess, "check_output", refuse)
        status, stderr = run_main(monkeypatch, capsys, inputs, output)
        assert stderr == "Validation evidence unavailable: CalledProcessError\n"
        assert str(repository) not in stderr
    assert status == 2
    assert not output.exists()
