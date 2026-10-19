# SPDX-License-Identifier: AGPL-3.0-only
"""`scripts/check_wheel_licences.py` refuses a wheel that does not carry its license.

The script runs in `verify` against the wheels `uv build` produces; these cases plant the
failures a real build does not have, in wheels assembled here, so each refusal is shown to
fire and a correct wheel is shown to pass.
"""

import importlib.util
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_wheel_licences", ROOT / "scripts" / "check_wheel_licences.py"
)
assert _spec is not None and _spec.loader is not None
check = importlib.util.module_from_spec(_spec)
sys.modules["check_wheel_licences"] = check
_spec.loader.exec_module(check)


def wheel(
    tmp_path,
    name="demo",
    *,
    expression="Apache-2.0",
    files=None,
    extra_info=False,
    metadata=None,
    members=None,
):
    source = tmp_path / "LICENSE-source"
    source.write_bytes(b"the license text\n")
    files = {"LICENSE": source.read_bytes()} if files is None else files
    path = tmp_path / f"{name}-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        fields = "Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n"
        if expression is not None:
            fields += f"License-Expression: {expression}\n"
        body = metadata if metadata is not None else fields + "\nA long description.\n"
        archive.writestr(f"{name}-1.0.dist-info/METADATA", body)
        for file, data in files.items():
            archive.writestr(f"{name}-1.0.dist-info/licenses/{file}", data)
        if extra_info:
            archive.writestr("other-2.0.dist-info/METADATA", "Name: other\n")
        for member, data in (members or {}).items():
            archive.writestr(member, data)
    return path, {name: ("Apache-2.0", {"LICENSE": source})}


def test_a_wheel_that_carries_its_licence_passes(tmp_path):
    path, expected = wheel(tmp_path)
    assert check.problems(path, expected) == []


def test_a_wheel_without_its_licence_file_is_refused(tmp_path):
    path, expected = wheel(tmp_path, files={})
    assert check.problems(path, expected) == [
        f"{path.name}: demo-1.0.dist-info/licenses/LICENSE is missing"
    ]


def test_a_licence_file_that_differs_from_the_repository_copy_is_refused(tmp_path):
    path, expected = wheel(tmp_path, files={"LICENSE": b"another text\n"})
    (problem,) = check.problems(path, expected)
    assert "differs from" in problem


def test_a_wrong_or_absent_expression_is_refused(tmp_path):
    path, expected = wheel(tmp_path, expression="MIT")
    assert check.problems(path, expected) == [
        f"{path.name}: License-Expression is ['MIT'], not Apache-2.0"
    ]
    path, expected = wheel(tmp_path, expression=None)
    assert check.problems(path, expected) == [
        f"{path.name}: License-Expression is absent, not Apache-2.0"
    ]


def test_an_expression_in_the_description_is_not_read_as_the_field(tmp_path):
    """Only the header block is metadata; a body line that looks like a field is prose."""
    metadata = "Metadata-Version: 2.4\nName: demo\n\nLicense-Expression: Apache-2.0\n"
    path, expected = wheel(tmp_path, metadata=metadata)
    assert check.problems(path, expected) == [
        f"{path.name}: License-Expression is absent, not Apache-2.0"
    ]


def test_a_wheel_the_check_does_not_know_is_refused_rather_than_passed(tmp_path):
    path, _ = wheel(tmp_path, name="stranger")
    assert check.problems(path, {}) == [
        f"{path.name}: no license is recorded for the distribution 'stranger'"
    ]


def test_a_wheel_with_two_metadata_directories_is_refused(tmp_path):
    path, expected = wheel(tmp_path, extra_info=True)
    (problem,) = check.problems(path, expected)
    assert "expected one .dist-info directory" in problem


def test_the_command_fails_when_any_wheel_fails_and_needs_a_wheel(tmp_path, capsys):
    assert check.main([str(tmp_path / "not-a-wheel.tar.gz")]) == 2
    stranger, _ = wheel(tmp_path, name="stranger")
    assert check.main([str(stranger)]) == 1
    assert "no license is recorded" in capsys.readouterr().err


def nested(tmp_path):
    """A nested license the demo wheel should carry as package data, and its repository copy."""
    source = tmp_path / "nested-LICENSE"
    source.write_bytes(b"the nested license text\n")
    return {"demo": {"demo/data/LICENSE": source}}


def test_a_wheel_that_carries_its_nested_licence_passes(tmp_path):
    packaged = nested(tmp_path)
    path, expected = wheel(tmp_path, members={"demo/data/LICENSE": b"the nested license text\n"})
    assert check.problems(path, expected, packaged) == []


def test_a_wheel_without_a_nested_licence_it_packages_is_refused(tmp_path):
    packaged = nested(tmp_path)
    path, expected = wheel(tmp_path)
    assert check.problems(path, expected, packaged) == [
        f"{path.name}: demo/data/LICENSE is missing"
    ]


def test_a_nested_licence_that_differs_from_the_repository_copy_is_refused(tmp_path):
    packaged = nested(tmp_path)
    path, expected = wheel(tmp_path, members={"demo/data/LICENSE": b"another text\n"})
    (problem,) = check.problems(path, expected, packaged)
    assert problem.startswith(f"{path.name}: demo/data/LICENSE differs from ")


def test_the_server_wheel_must_carry_the_tines_stories_licence_beside_them():
    """The console build carries the Apache-2.0 Tines stories (#678); their license travels
    with them and is the repository's `integrations/LICENSE`, byte for byte."""
    member = "execbound/surfaces/console_dist/stories/tines/LICENSE"
    assert check.PACKAGED["execbound"][member] == ROOT / "integrations" / "LICENSE"


def test_a_server_wheel_without_or_with_another_tines_stories_licence_is_refused(tmp_path):
    member = "execbound/surfaces/console_dist/stories/tines/LICENSE"
    packaged = {"demo": {member: ROOT / "integrations" / "LICENSE"}}
    path, expected = wheel(tmp_path)
    assert check.problems(path, expected, packaged) == [f"{path.name}: {member} is missing"]
    other = tmp_path / "other"
    other.mkdir()
    path, expected = wheel(other, members={member: b"another text\n"})
    (problem,) = check.problems(path, expected, packaged)
    assert problem == f"{path.name}: {member} differs from integrations/LICENSE"
    good = tmp_path / "good"
    good.mkdir()
    path, expected = wheel(good, members={member: (ROOT / "integrations" / "LICENSE").read_bytes()})
    assert check.problems(path, expected, packaged) == []
