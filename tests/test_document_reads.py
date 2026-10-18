# SPDX-License-Identifier: AGPL-3.0-only
"""The `docs` marker's guard (#748): every way a test can read a document is seen.

Each case writes a small suite into a temporary directory and runs it in a fresh process with
the guard loaded, reading this repository's own `README.md`, which `tests/document_paths.py`
counts as a document. A read the guard sees fails the test unless it carries `docs`; a read of
anything else, and a marked reader, pass.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
README = repr(str(ROOT / "README.md"))
READ_README = f"Path({README}).read_text()"
READ_OTHER = f"Path({str(ROOT / 'pyproject.toml')!r}).read_text()"


def run(directory: Path, files: dict[str, str], *extra: str) -> subprocess.CompletedProcess[str]:
    """Run a suite of `files` with the guard, and return what pytest printed."""
    for name, text in files.items():
        (directory / name).write_text(text, encoding="utf-8")
    (directory / "pytest.ini").write_text("[pytest]\nmarkers =\n    docs: reads a document\n")
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join([str(TESTS), str(directory)]))
    # Fixed argv without a shell; the suite is this test's own text.
    return subprocess.run(  # nosec B603
        [
            sys.executable,
            *("-m", "pytest", "-p", "document_reads", "-q", "-p", "no:cacheprovider"),
            *extra,
        ],
        cwd=directory,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.mark.parametrize(
    ("files", "failing"),
    [
        pytest.param(
            {"test_one.py": f"from pathlib import Path\n\ndef test_reads():\n    {READ_README}\n"},
            ["test_one.py::test_reads"],
            id="a-read-in-the-test",
        ),
        pytest.param(
            {
                "test_one.py": (
                    "import pytest\nfrom pathlib import Path\n\n"
                    "@pytest.mark.docs\n"
                    f"def test_reads():\n    Path({README}).read_text()\n"
                )
            },
            [],
            id="a-marked-read",
        ),
        pytest.param(
            {
                "test_one.py": (
                    f"from pathlib import Path\n\nTEXT = Path({README}).read_text()\n\n"
                    "def test_uses():\n    assert TEXT\n"
                )
            },
            ["test_one.py::test_uses"],
            id="a-read-at-import",
        ),
        pytest.param(
            {
                "test_one.py": (
                    "import pytest\nfrom pathlib import Path\n\npytestmark = pytest.mark.docs\n"
                    f"TEXT = Path({README}).read_text()\n\ndef test_uses():\n    assert TEXT\n"
                )
            },
            [],
            id="a-marked-module",
        ),
        pytest.param(
            {
                "conftest.py": (
                    "import pytest\nfrom pathlib import Path\n\n"
                    "@pytest.fixture(scope='session')\n"
                    f"def readme():\n    return Path({README}).read_text()\n"
                ),
                "test_one.py": (
                    "import pytest\n\n"
                    "@pytest.mark.docs\n"
                    "def test_first(readme):\n    assert readme\n"
                ),
                "test_two.py": "def test_second(readme):\n    assert readme\n",
            },
            ["test_two.py::test_second"],
            id="a-fixture-set-up-once-and-reused",
        ),
        pytest.param(
            {
                "helper.py": f"from pathlib import Path\n\nTEXT = Path({README}).read_text()\n",
                "test_one.py": "from helper import TEXT\n\ndef test_uses():\n    assert TEXT\n",
                "test_two.py": "def test_unrelated():\n    pass\n",
            },
            ["test_one.py::test_uses"],
            id="a-helper-that-reads-at-import",
        ),
        pytest.param(
            {
                "loader.py": f"from pathlib import Path\n\ndef read():\n    return {READ_README}\n",
                "test_one.py": (
                    "import importlib.util\nfrom pathlib import Path\n\n"
                    "spec = importlib.util.spec_from_file_location(\n"
                    "    'loader', Path(__file__).with_name('loader.py')\n)\n"
                    "loader = importlib.util.module_from_spec(spec)\n"
                    "spec.loader.exec_module(loader)\nTEXT = loader.read()\n\n"
                    "def test_uses():\n    assert TEXT\n"
                ),
            },
            ["test_one.py::test_uses"],
            id="a-helper-loaded-by-path-and-called-at-import",
        ),
        pytest.param(
            {"test_one.py": f"from pathlib import Path\n\ndef test_reads():\n    {READ_OTHER}\n"},
            [],
            id="a-read-of-something-else",
        ),
    ],
)
def test_the_guard_fails_an_unmarked_reader_and_only_that(tmp_path, files, failing):
    completed = run(tmp_path, files)
    output = completed.stdout + completed.stderr
    errors = sorted(
        line.split(" ", 1)[1].split(" - ", 1)[0]
        for line in output.splitlines()
        if line.startswith("ERROR ")
    )
    assert errors == failing, output
    assert completed.returncode == (1 if failing else 0), output
    if failing:
        assert "without @pytest.mark.docs" in output and "README.md" in output, output


def failures(completed: subprocess.CompletedProcess[str]) -> list[str]:
    output = completed.stdout + completed.stderr
    return sorted(
        line.split(" ", 1)[1].split(" - ", 1)[0]
        for line in output.splitlines()
        if line.startswith("ERROR ")
    )


def test_listing_a_directory_of_documents_is_a_read(tmp_path):
    docs = repr(str(ROOT / "docs"))
    completed = run(
        tmp_path,
        {"test_one.py": f"import os\n\ndef test_lists():\n    assert os.listdir({docs})\n"},
    )
    assert failures(completed) == ["test_one.py::test_lists"], completed.stdout


def test_a_helper_first_imported_inside_a_test_still_marks_a_later_importer(tmp_path):
    completed = run(
        tmp_path,
        {
            "helper.py": f"from pathlib import Path\n\nTEXT = {READ_README}\n",
            "test_one.py": (
                "import pytest\n\n"
                "@pytest.mark.docs\n"
                "def test_first():\n    import helper\n\n    assert helper.TEXT\n"
            ),
            "test_two.py": "def test_second():\n    import helper\n\n    assert helper.TEXT\n",
        },
    )
    assert failures(completed) == ["test_two.py::test_second"], completed.stdout


def test_the_guard_holds_across_xdist_workers(tmp_path):
    completed = run(
        tmp_path,
        {
            "test_one.py": f"from pathlib import Path\n\ndef test_reads():\n    {READ_README}\n",
            "test_two.py": "def test_reads_nothing():\n    pass\n",
        },
        "-n",
        "2",
        "--dist",
        "loadfile",
    )
    assert failures(completed) == ["test_one.py::test_reads"], completed.stdout
    assert completed.returncode == 1


def test_a_fixture_is_its_definition_not_its_name(tmp_path):
    completed = run(
        tmp_path,
        {
            "test_one.py": (
                "import pytest\nfrom pathlib import Path\n\n"
                "@pytest.fixture(scope='session')\n"
                f"def data():\n    return {READ_README}\n\n"
                "@pytest.mark.docs\n"
                "def test_reader(data):\n    assert data\n"
            ),
            "test_two.py": (
                "import pytest\n\n"
                "@pytest.fixture(scope='session')\n"
                "def data():\n    return 'nothing read'\n\n"
                "def test_other(data):\n    assert data\n"
            ),
        },
    )
    assert failures(completed) == [], completed.stdout
    assert completed.returncode == 0
