# SPDX-License-Identifier: AGPL-3.0-only
"""`scripts/release_preflight.py`, which the release workflow runs before it builds anything
and again before it publishes (#124).

The repository is a fixture made with git in a temporary directory, and the GitHub API is a
fake, so nothing here reaches the network or the development repository's own history.
"""

import importlib.util
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "release_preflight", ROOT / "scripts" / "release_preflight.py"
)
assert _spec is not None and _spec.loader is not None
preflight = importlib.util.module_from_spec(_spec)
sys.modules["release_preflight"] = preflight
_spec.loader.exec_module(preflight)

REPOSITORY = "ExecBound/execbound"
IMAGE = "ghcr.io/execbound/execbound"
DIGEST = "sha256:" + "d" * 64
IDENTITY = f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/v0.1.0"
ISSUER = "https://token.actions.githubusercontent.com"
CI_RUN = f"https://github.com/{REPOSITORY}/actions/runs/11"
NOTES = "First release.\n"


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        env={
            "PATH": os.environ["PATH"],
            "HOME": str(root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Release Test",
            "GIT_AUTHOR_EMAIL": "release@example.com",
            "GIT_COMMITTER_NAME": "Release Test",
            "GIT_COMMITTER_EMAIL": "release@example.com",
        },
    ).stdout.strip()


def write_project(root: Path, versions: dict[str, str] | None = None) -> None:
    versions = {name: "0.1.0" for name in preflight.PACKAGES} | (versions or {})
    for name, path in preflight.PACKAGES.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(
            f'[project]\nname = "{name}"\nversion = "{versions[name]}"\n', encoding="utf-8"
        )
    lock = "".join(
        f'[[package]]\nname = "{name}"\nversion = "{versions.get("lock:" + name, "0.1.0")}"\n\n'
        for name in preflight.PACKAGES
    )
    (root / "uv.lock").write_text("version = 1\n\n" + lock, encoding="utf-8")


@pytest.fixture
def repository(tmp_path):
    """A repository whose `main` holds a releasable v0.1.0, tagged, with `origin/main` at it."""
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    write_project(root)
    (root / "releases").mkdir()
    (root / "releases" / "v0.1.0.md").write_text(NOTES, encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "Release 0.1.0")
    git(root, "tag", "v0.1.0")
    git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    return root


def head(root: Path) -> str:
    return git(root, "rev-parse", "HEAD")


def passing(commit: str):
    """The API as it answers for a commit `ci.yml` passed on for a push to `main`."""
    calls: list[str] = []

    def fetch(url: str):
        calls.append(url)
        return {
            "workflow_runs": [
                {
                    "head_sha": commit,
                    "head_branch": "main",
                    "event": "push",
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": CI_RUN,
                }
            ]
        }

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


def checked(root: Path, **changes):
    commit = head(root)
    values = {
        "tag": "v0.1.0",
        "commit": commit,
        "repository": REPOSITORY,
        "image": IMAGE,
        "fetch": passing(commit),
    }
    values.update(changes)
    return preflight.check(root, **values)


def refusal(root: Path, **changes) -> list[str]:
    with pytest.raises(preflight.Refused) as refused:
        checked(root, **changes)
    return refused.value.reasons


def test_a_releasable_tag_passes_with_the_values_the_workflow_reads(repository):
    commit = head(repository)
    fetch = passing(commit)
    assert checked(repository, fetch=fetch) == {
        "version": "0.1.0",
        "minor": "0.1",
        "image": IMAGE,
        "notes": "releases/v0.1.0.md",
        "ci_run": CI_RUN,
    }
    (url,) = fetch.calls
    assert url.startswith(f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/ci.yml/")
    assert f"head_sha={commit}" in url and "event=push" in url and "branch=main" in url


@pytest.mark.parametrize("tag", ["0.1.0", "v0.1", "v01.1.0", "v0.1.0-rc.1", "v0.1.0 ", "v1"])
def test_a_tag_that_is_not_a_release_version_is_refused(repository, tag):
    reasons = refusal(repository, tag=tag)
    assert reasons == [f"{tag!r} is not a release tag: v<major>.<minor>.<patch>, no leading zeros"]


def test_every_package_must_carry_the_tags_version_in_its_project_and_the_lock(repository):
    write_project(
        repository,
        {"execbound-client": "0.1.1", "lock:execbound-protocol": "0.0.9"},
    )
    reasons = refusal(repository)
    assert reasons == [
        "clients/python/pyproject.toml gives execbound-client 0.1.1, not 0.1.0",
        "uv.lock gives execbound-protocol 0.0.9, not 0.1.0",
    ]


def test_a_project_file_that_names_another_package_or_cannot_be_read_is_refused(repository):
    (repository / "protocol" / "pyproject.toml").write_text(
        '[project]\nname = "something-else"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    (repository / "connectors" / "pyproject.toml").unlink()
    (repository / "uv.lock").write_text("not = [toml", encoding="utf-8")
    reasons = refusal(repository)
    assert reasons[0] == "protocol/pyproject.toml declares 'something-else', not execbound-protocol"
    assert reasons[1].startswith("connectors/pyproject.toml cannot be read: ")
    assert reasons[2].startswith("uv.lock cannot be read: ")
    assert len(reasons) == 3


def test_missing_or_empty_release_notes_are_refused(repository):
    notes = repository / "releases" / "v0.1.0.md"
    notes.write_text(" \n", encoding="utf-8")
    assert refusal(repository) == ["releases/v0.1.0.md is empty"]
    notes.unlink()
    assert refusal(repository) == [
        "releases/v0.1.0.md is missing: the release's notes are written before it"
    ]


def test_a_commit_that_is_not_on_main_is_refused(repository):
    git(repository, "switch", "-q", "-c", "side")
    git(repository, "commit", "-q", "--allow-empty", "-m", "Not on main")
    git(repository, "tag", "-f", "v0.1.0")
    commit = head(repository)
    assert refusal(repository, fetch=passing(commit)) == [f"{commit} is not on main"]


def test_a_tag_that_points_at_another_commit_is_refused(repository):
    tagged = head(repository)
    git(repository, "commit", "-q", "--allow-empty", "-m", "After the tag")
    git(repository, "update-ref", "refs/remotes/origin/main", "HEAD")
    commit = head(repository)
    assert commit != tagged
    assert refusal(repository) == [f"the tag v0.1.0 does not point at {commit}"]


@pytest.mark.parametrize(
    "image",
    [
        "",
        "execbound",
        "ghcr.io/execbound/execbound:0.1.0",
        f"ghcr.io/execbound/execbound@{DIGEST}",
        "ghcr.io/ExecBound/execbound",
        "https://ghcr.io/execbound/execbound",
        "docker.io/execbound/execbound",
        "ghcr.io",
    ],
)
def test_an_image_off_ghcr_or_with_a_tag_a_digest_or_capitals_or_none_is_refused(repository, image):
    assert refusal(repository, image=image) == [
        f"the image {image!r} is not a lower-case path on ghcr.io without a tag or a digest;"
        " set the repository variable RELEASE_IMAGE"
    ]


@pytest.mark.parametrize(
    "change",
    [
        {"head_sha": "f" * 40},
        {"head_branch": "release"},
        {"event": "workflow_dispatch"},
        {"status": "in_progress"},
        {"conclusion": "failure"},
        {"html_url": None},
    ],
)
def test_ci_must_have_passed_on_exactly_this_commit_for_a_push_to_main(repository, change):
    """The API is asked for exactly that, and every answer is checked anyway: a filter the API
    ignored must not turn another run into this commit's."""
    commit = head(repository)
    run = passing(commit)("")["workflow_runs"][0] | change

    def fetch(url):
        return {"workflow_runs": [run]}

    assert refusal(repository, fetch=fetch) == [
        f"ci.yml has not passed on {commit} for a push to main"
    ]


@pytest.mark.parametrize("answer", [{}, [], {"workflow_runs": {}}, None])
def test_an_answer_that_is_not_a_list_of_runs_is_refused(repository, answer):
    commit = head(repository)
    assert refusal(repository, fetch=lambda url: answer) == [
        f"the ci.yml runs of {commit} could not be read"
    ]


def test_problems_in_the_repository_refuse_before_the_api_is_read(repository):
    def fetch(url):
        raise AssertionError("the API was read for a release refused on its own files")

    write_project(repository, {"execbound": "0.2.0"})
    assert refusal(repository, fetch=fetch) == ["pyproject.toml gives execbound 0.2.0, not 0.1.0"]


def test_the_token_is_sent_to_the_github_api_and_nowhere_else():
    fetch = preflight.fetcher("token")
    for url in (
        "https://example.com/repos",
        "http://api.github.com/repos",
        "https://api.github.com.example.com/repos",
    ):
        with pytest.raises(preflight.Refused, match="refusing to send the token"):
            fetch(url)


def published(root: Path) -> Path:
    out = root / "local-data" / "release"
    out.mkdir(parents=True)
    for name in preflight.PUBLISHED:
        (out / name).write_text(json.dumps({"file": name}), encoding="utf-8")
    return out


def approvals(*reviews):
    calls: list[str] = []

    def fetch(url):
        calls.append(url)
        return list(reviews)

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


def review(state="approved", environment="release", login="maintainer", comment="Ship it"):
    return {
        "state": state,
        "environments": [{"name": environment}],
        "user": {"login": login},
        "comment": comment,
    }


def recorded(root: Path, fetch, out: Path, **changes):
    values = {
        "tag": "v0.1.0",
        "commit": head(root),
        "repository": REPOSITORY,
        "run": "42",
        "image": IMAGE,
        "digest": DIGEST,
        "identity": IDENTITY,
        "issuer": ISSUER,
        "ci_run": CI_RUN,
        "out_dir": out,
        "fetch": fetch,
        "now": datetime(2026, 10, 1, 20, 0, tzinfo=UTC),
    }
    values.update(changes)
    return preflight.record(root, **values)


def test_the_record_names_the_release_its_checks_its_approval_and_each_files_digest(
    repository,
):
    out = published(repository)
    fetch = approvals(review(), review(state="rejected", login="other"))
    document = recorded(repository, fetch, out)
    assert fetch.calls == [f"https://api.github.com/repos/{REPOSITORY}/actions/runs/42/approvals"]
    assert document == {
        "format": "execbound.release-record.v1",
        "recorded_at": "2026-10-01T20:00:00+00:00",
        "release": {
            "repository": REPOSITORY,
            "tag": "v0.1.0",
            "version": "0.1.0",
            "commit": head(repository),
        },
        "image": {"reference": IMAGE, "tags": ["0.1.0", "0.1"], "digest": DIGEST},
        "signature": {"certificate_identity": IDENTITY, "certificate_oidc_issuer": ISSUER},
        "checks": {"ci_run": CI_RUN},
        "run": f"https://github.com/{REPOSITORY}/actions/runs/42",
        "approval": {
            "environment": "release",
            "approved": [{"by": "maintainer", "comment": "Ship it"}],
        },
        "files": {name: preflight.sha256(out / name) for name in preflight.PUBLISHED},
    }
    assert json.loads((out / "release-record.json").read_text(encoding="utf-8")) == document


def test_the_notes_are_the_reviewed_file_then_how_to_pull_and_verify_the_image(repository):
    out = published(repository)
    recorded(repository, approvals(review()), out)
    notes = (out / "notes.md").read_text(encoding="utf-8")
    assert notes.startswith(NOTES.rstrip() + "\n\n## The image\n")
    assert f"docker pull {IMAGE}@{DIGEST}\n" in notes
    assert (
        f"cosign verify {IMAGE}@{DIGEST} \\\n"
        f"  --certificate-identity {IDENTITY} \\\n"
        f"  --certificate-oidc-issuer {ISSUER}\n"
    ) in notes
    assert f"`{IMAGE}:0.1.0` and `{IMAGE}:0.1`" in notes
    assert f"https://github.com/{REPOSITORY}/blob/v0.1.0/docs/RELEASE.md" in notes
    assert ":latest" not in notes


@pytest.mark.parametrize(
    "reviews",
    [
        [],
        [review(state="rejected")],
        [review(environment="staging")],
        [{"state": "approved", "environments": [{"name": "release"}], "user": None}],
        [{"state": "approved", "user": {"login": "maintainer"}}],
    ],
)
def test_without_an_approval_for_the_release_environment_nothing_is_recorded(repository, reviews):
    out = published(repository)
    with pytest.raises(preflight.Refused) as refused:
        recorded(repository, approvals(*reviews), out)
    assert refused.value.reasons == ["no maintainer approved run 42 for the release environment"]
    assert not (out / "release-record.json").exists()
    assert not (out / "notes.md").exists()


def test_an_approvals_answer_that_is_not_a_list_is_refused(repository):
    out = published(repository)
    with pytest.raises(preflight.Refused, match="approvals of run 42 could not be read"):
        recorded(repository, lambda url: {"message": "Not Found"}, out)


def test_bad_values_and_missing_files_are_refused_before_the_approval_is_read(repository):
    out = published(repository)
    (out / "provenance.json").unlink()

    def fetch(url):
        raise AssertionError("the approvals were read for a record refused on its own values")

    with pytest.raises(preflight.Refused) as refused:
        recorded(
            repository,
            fetch,
            out,
            run="0",
            digest="sha256:short",
            identity="http://github.com/x",
            image=f"{IMAGE}:0.1.0",
        )
    assert refused.value.reasons == [
        "'0' is not a workflow run",
        f"the image '{IMAGE}:0.1.0' is not a lower-case path on ghcr.io without a tag or a digest",
        "'sha256:short' is not a sha256 digest",
        "the identity 'http://github.com/x' is not an https address",
        f"{out / 'provenance.json'} is missing",
    ]


def test_the_command_line_prints_the_values_for_github_output(repository, monkeypatch, capsys):
    monkeypatch.setattr(preflight, "ROOT", repository)
    commit = head(repository)
    code = preflight.main(
        [
            "check",
            "--tag",
            "v0.1.0",
            "--commit",
            commit,
            "--repository",
            REPOSITORY,
            "--image",
            IMAGE,
        ],
        fetch=passing(commit),
    )
    assert code == 0
    assert capsys.readouterr().out.splitlines() == [
        "version=0.1.0",
        "minor=0.1",
        f"image={IMAGE}",
        "notes=releases/v0.1.0.md",
        f"ci_run={CI_RUN}",
    ]


def test_the_command_line_prints_every_reason_and_exits_1(repository, monkeypatch, capsys):
    monkeypatch.setattr(preflight, "ROOT", repository)
    write_project(repository, {"execbound": "0.2.0", "execbound-client": "0.2.0"})
    code = preflight.main(
        ["check", "--tag", "v0.1.0", "--commit", head(repository)]
        + ["--repository", REPOSITORY, "--image", IMAGE],
        fetch=passing(head(repository)),
    )
    assert code == 1
    printed = capsys.readouterr()
    assert printed.out == ""
    assert printed.err.splitlines() == [
        "release refused: pyproject.toml gives execbound 0.2.0, not 0.1.0",
        "release refused: clients/python/pyproject.toml gives execbound-client 0.2.0, not 0.1.0",
    ]


def test_the_command_line_needs_a_token(monkeypatch, capsys):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(SystemExit) as stopped:
        preflight.main(
            ["check", "--tag", "v0.1.0", "--commit", "a" * 40]
            + ["--repository", REPOSITORY, "--image", IMAGE]
        )
    assert stopped.value.code == 2
    assert "GH_TOKEN is not set" in capsys.readouterr().err


def test_the_script_runs_with_the_system_python_alone():
    """Standard library only: the workflow calls it before anything is installed. `-S` keeps
    every installed package out of reach."""
    result = subprocess.run(
        ["python3", "-S", str(ROOT / "scripts" / "release_preflight.py"), "check", "--help"],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": os.environ["PATH"]},
    )
    assert result.returncode == 0, result.stderr
    assert "--tag" in result.stdout


def test_the_publishing_job_starts_only_on_an_approved_run(monkeypatch, capsys):
    fetch = approvals(review(), review(login="second", comment=""))
    assert preflight.main(["approved", "--repository", REPOSITORY, "--run", "42"], fetch=fetch) == 0
    assert capsys.readouterr().out == "approved_by=maintainer,second\n"
    assert fetch.calls == [f"https://api.github.com/repos/{REPOSITORY}/actions/runs/42/approvals"]
    for reviews in ([], [review(state="rejected")], [review(environment="staging")]):
        code = preflight.main(
            ["approved", "--repository", REPOSITORY, "--run", "42"], fetch=approvals(*reviews)
        )
        assert code == 1
        assert capsys.readouterr().err == (
            "release refused: no maintainer approved run 42 for the release environment\n"
        )


@pytest.mark.parametrize(("repository", "run"), [("not a repo", "42"), (REPOSITORY, "4x")])
def test_an_approval_is_read_only_for_a_real_run_of_a_real_repository(repository, run, capsys):
    def fetch(url):
        raise AssertionError(f"read {url}")

    code = preflight.main(["approved", "--repository", repository, "--run", run], fetch=fetch)
    assert code == 1
    assert "is not a run" in capsys.readouterr().err
