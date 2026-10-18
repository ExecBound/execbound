# SPDX-License-Identifier: AGPL-3.0-only
"""`scripts/check_console_packaged.py` refuses a server distribution without its console.

The script runs in `verify` against the wheel and sdist `uv build` produces, comparing each with
the console build in the workspace. These cases assemble distributions and a build here, so
each refusal is shown to fire and a faithful distribution is shown to pass, and they hold the
two `artifacts` lines to each other, which is what the real build depends on.
"""

import importlib.util
import io
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_console_packaged", ROOT / "scripts" / "check_console_packaged.py"
)
assert _spec is not None and _spec.loader is not None
check = importlib.util.module_from_spec(_spec)
sys.modules["check_console_packaged"] = check
_spec.loader.exec_module(check)

BUILD = {
    "index.html": b"<!doctype html><title>console</title>\n",
    "assets/index-abc123.js": b"console.log(1)\n",
    ".vite/manifest.json": b"{}\n",
}


def build_dir(tmp_path: Path, files: dict[str, bytes] = BUILD) -> Path:
    root = tmp_path / "console_dist"
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    return root


def wheel(tmp_path: Path, files: dict[str, bytes] = BUILD) -> Path:
    path = tmp_path / "execbound-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("execbound/__init__.py", "")
        archive.writestr("execbound-0.1.0.dist-info/METADATA", "Name: execbound\n")
        for name, data in files.items():
            archive.writestr(f"execbound/surfaces/console_dist/{name}", data)
    return path


def sdist(tmp_path: Path, files: dict[str, bytes] = BUILD) -> Path:
    path = tmp_path / "execbound-0.1.0.tar.gz"
    members = {"execbound-0.1.0/pyproject.toml": b"[project]\n"}
    members |= {
        f"execbound-0.1.0/src/execbound/surfaces/console_dist/{name}": data
        for name, data in files.items()
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def test_a_wheel_and_an_sdist_carrying_the_build_pass(tmp_path):
    expected = check.reference(build_dir(tmp_path))
    assert sorted(expected) == sorted(BUILD)
    assert check.problems(wheel(tmp_path), expected) == []
    assert check.problems(sdist(tmp_path), expected) == []


def test_a_distribution_with_no_console_is_refused_by_name(tmp_path):
    """The failure a plain `uv build` produced before the sdist named the build."""
    expected = check.reference(build_dir(tmp_path))
    bare_wheel, bare_sdist = wheel(tmp_path, files={}), sdist(tmp_path, files={})
    assert check.problems(bare_wheel, expected) == [f"{bare_wheel.name}: carries no console at all"]
    assert check.problems(bare_sdist, expected) == [f"{bare_sdist.name}: carries no console at all"]


def test_a_missing_an_extra_and_a_changed_file_are_each_named(tmp_path):
    expected = check.reference(build_dir(tmp_path))
    drifted = {k: v for k, v in BUILD.items() if k != "assets/index-abc123.js"}
    drifted["index.html"] = b"<!doctype html><title>older</title>\n"
    drifted["assets/stale-999.js"] = b"old\n"
    path = wheel(tmp_path, files=drifted)
    assert check.problems(path, expected) == [
        f"{path.name}: assets/index-abc123.js is missing",
        f"{path.name}: assets/stale-999.js is not in the build",
        f"{path.name}: index.html differs from the build",
    ]


def test_only_the_console_directory_is_compared(tmp_path):
    """The rest of the package, and an sdist's other files, are not the console's business."""
    expected = check.reference(build_dir(tmp_path))
    assert check.packaged(wheel(tmp_path)) == expected
    assert check.packaged(sdist(tmp_path)) == expected


def test_a_file_that_is_neither_a_wheel_nor_an_sdist_is_refused(tmp_path):
    other = tmp_path / "execbound-0.1.0.zip"
    other.write_bytes(b"")
    assert check.problems(other, {"index.html": b""}) == [f"{other.name}: not a wheel or an sdist"]


def test_the_command_needs_a_workspace_build_and_fails_when_a_distribution_does(tmp_path, capsys):
    empty = tmp_path / "no-build"
    empty.mkdir()
    good = wheel(tmp_path)
    assert check.main([str(good)], build=empty) == 2
    assert "run `pnpm build` first" in capsys.readouterr().err
    build = build_dir(tmp_path)
    assert check.main([str(good), str(sdist(tmp_path))], build=build) == 0
    bare = tmp_path / "bare"
    bare.mkdir()
    assert check.main([str(wheel(bare, files={}))], build=build) == 1
    assert "carries no console at all" in capsys.readouterr().err


def test_both_distributions_name_the_console_build():
    """A plain `uv build` makes the wheel from the sdist, so the sdist must carry it too."""
    targets = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["hatch"]["build"][
        "targets"
    ]
    console = "src/execbound/surfaces/console_dist/**"
    assert console in targets["wheel"]["artifacts"]
    assert console in targets["sdist"]["artifacts"]
    assert check.WHEEL_PREFIX == "execbound/surfaces/console_dist/"
    assert check.SDIST_PREFIX == console.removesuffix("**")
