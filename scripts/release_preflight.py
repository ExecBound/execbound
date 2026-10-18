#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Refuse a release that is not what it says it is, and record the one that is.

The release workflow (`.github/workflows/release.yml`) runs this three times, on the tag it
was pushed for:

    python3 scripts/release_preflight.py check --tag v0.1.0 --commit <sha> \\
        --repository OWNER/REPO --image ghcr.io/execbound/execbound
    python3 scripts/release_preflight.py approved --repository OWNER/REPO --run <id>
    python3 scripts/release_preflight.py record --tag v0.1.0 --commit <sha> \\
        --repository OWNER/REPO --run <id> --image ghcr.io/execbound/execbound \\
        --digest sha256:<hex> --identity <url> --issuer <url> --ci-run <url> \\
        --out-dir local-data/release

`check` runs before anything is built. It refuses a tag that is not `v<major>.<minor>.<patch>`
or does not point at the commit; a package whose version is not the tag's, in its
`pyproject.toml` or in `uv.lock`; release notes that are missing or empty; a commit that is
not on `main`; an image name off `ghcr.io` or with a tag or a digest; and a commit on which
the CI workflow has not passed for a push to `main`. It prints the values the later steps read as
`name=value` lines, for `$GITHUB_OUTPUT`.

`approved` is the publishing job's first step: it refuses unless a maintainer approved this
run for the `release` environment, so nothing is pushed on a run nobody approved, even where
the environment has lost its protection rule.

`record` runs after the image is pushed and its signature verified. It reads the approval
again and writes `release-record.json` (what was released, from which commit and checks,
signed by whom, on whose approval, and the digest of every file published beside it) and
`notes.md`, the release's description.

Standard library only, so it runs with the system `python3` before anything is installed.
The token comes from `GH_TOKEN` and is sent to `https://api.github.com` and nowhere else.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
API = "https://api.github.com"
ENVIRONMENT = "release"
WORKFLOW = "ci.yml"
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# A path on GitHub's registry with no tag and no digest: the tags are the release's to add, and
# the job's own token can push to no other registry.
IMAGE = re.compile(r"ghcr\.io(?:/[a-z0-9][a-z0-9._-]*)+")
REPOSITORY = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")
RUN = re.compile(r"[1-9][0-9]{0,19}")
# Every package the image ships, by name, and the project file that declares it. One release
# carries one version, so each must carry the tag's.
PACKAGES = {
    "execbound": "pyproject.toml",
    "execbound-client": "clients/python/pyproject.toml",
    "execbound-protocol": "protocol/pyproject.toml",
    "execbound-connectors": "connectors/pyproject.toml",
}
NOTES = "releases"
# Published beside the image, each named with its digest in the record.
PUBLISHED = ("sbom.cdx.json", "provenance.json", "image-distributions.json")

Fetch = Callable[[str], Any]


class Refused(Exception):
    """A release that cannot go ahead, with every reason found."""

    def __init__(self, *reasons: str) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = list(reasons)


def version_of(tag: str) -> str:
    if not TAG.fullmatch(tag):
        raise Refused(f"{tag!r} is not a release tag: v<major>.<minor>.<patch>, no leading zeros")
    return tag[1:]


def version_problems(root: Path, version: str) -> list[str]:
    """Each place a shipped package's version is recorded that does not say `version`: its
    project file, and the lockfile the image is built from."""
    problems = []
    for name, path in PACKAGES.items():
        try:
            project = tomllib.loads((root / path).read_text(encoding="utf-8"))["project"]
        except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
            problems.append(f"{path} cannot be read: {error}")
            continue
        if project.get("name") != name:
            problems.append(f"{path} declares {project.get('name')!r}, not {name}")
        elif project.get("version") != version:
            problems.append(f"{path} gives {name} {project.get('version')}, not {version}")
    try:
        lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
        locked = {entry["name"]: entry.get("version") for entry in lock.get("package", [])}
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        return [*problems, f"uv.lock cannot be read: {error}"]
    for name in PACKAGES:
        if locked.get(name) != version:
            problems.append(f"uv.lock gives {name} {locked.get(name)}, not {version}")
    return problems


def image_problem(image: str) -> str | None:
    if IMAGE.fullmatch(image):
        return None
    return f"the image {image!r} is not a lower-case path on ghcr.io without a tag or a digest"


def notes_path(version: str) -> str:
    return f"{NOTES}/v{version}.md"


def notes_problem(root: Path, version: str) -> str | None:
    path = root / notes_path(version)
    try:
        if path.read_text(encoding="utf-8").strip():
            return None
    except (OSError, UnicodeDecodeError):
        return f"{notes_path(version)} is missing: the release's notes are written before it"
    return f"{notes_path(version)} is empty"


def git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments], cwd=root, capture_output=True, text=True, check=False
    )


def history_problems(root: Path, tag: str, commit: str) -> list[str]:
    """The tag names the commit, and the commit is on `main`."""
    problems = []
    tagged = git(root, "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}")
    if tagged.returncode or tagged.stdout.strip() != commit:
        problems.append(f"the tag {tag} does not point at {commit}")
    on_main = git(root, "merge-base", "--is-ancestor", commit, "origin/main")
    if on_main.returncode == 1:
        problems.append(f"{commit} is not on main")
    elif on_main.returncode:
        problems.append(f"cannot tell whether {commit} is on main: {on_main.stderr.strip()}")
    return problems


def fetcher(token: str) -> Fetch:
    """Reads one GitHub API address with the token, and refuses any other address."""

    def fetch(url: str) -> Any:
        if not url.startswith(API + "/"):
            raise Refused(f"refusing to send the token to {url}")
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "execbound-release-preflight",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            raise Refused(f"cannot read {url}: {error}") from None

    return fetch


def passed_ci(fetch: Fetch, repository: str, commit: str) -> str:
    """The address of a successful CI run for a push to `main` on exactly this commit."""
    query = urllib.parse.urlencode(
        {"head_sha": commit, "event": "push", "branch": "main", "status": "success"}
    )
    found = fetch(f"{API}/repos/{repository}/actions/workflows/{WORKFLOW}/runs?{query}")
    runs = found.get("workflow_runs") if isinstance(found, dict) else None
    if not isinstance(runs, list):
        raise Refused(f"the {WORKFLOW} runs of {commit} could not be read")
    for run in runs:
        if (
            isinstance(run, dict)
            and run.get("head_sha") == commit
            and run.get("head_branch") == "main"
            and run.get("event") == "push"
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and isinstance(run.get("html_url"), str)
        ):
            return str(run["html_url"])
    raise Refused(f"{WORKFLOW} has not passed on {commit} for a push to main")


def check(
    root: Path, *, tag: str, commit: str, repository: str, image: str, fetch: Fetch
) -> dict[str, str]:
    """Every reason this tag cannot be released, or the values the release reads."""
    version = version_of(tag)
    problems = []
    if not COMMIT.fullmatch(commit):
        problems.append(f"{commit!r} is not a full commit")
    if not REPOSITORY.fullmatch(repository):
        problems.append(f"{repository!r} is not OWNER/REPO")
    if (wrong := image_problem(image)) is not None:
        problems.append(wrong + "; set the repository variable RELEASE_IMAGE")
    problems += version_problems(root, version)
    if (missing := notes_problem(root, version)) is not None:
        problems.append(missing)
    if COMMIT.fullmatch(commit):
        problems += history_problems(root, tag, commit)
    if problems:
        raise Refused(*problems)
    major, minor, _ = version.split(".")
    return {
        "version": version,
        "minor": f"{major}.{minor}",
        "image": image,
        "notes": notes_path(version),
        "ci_run": passed_ci(fetch, repository, commit),
    }


def approval(fetch: Fetch, repository: str, run: str) -> dict[str, Any]:
    """Who approved this run for the release environment, or a refusal."""
    reviews = fetch(f"{API}/repos/{repository}/actions/runs/{run}/approvals")
    if not isinstance(reviews, list):
        raise Refused(f"the approvals of run {run} could not be read")
    approved = []
    for review in reviews:
        if not isinstance(review, dict) or review.get("state") != "approved":
            continue
        names = [
            environment.get("name")
            for environment in review.get("environments") or []
            if isinstance(environment, dict)
        ]
        user = review.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        if ENVIRONMENT in names and isinstance(login, str):
            comment = review.get("comment")
            approved.append({"by": login, "comment": comment if isinstance(comment, str) else ""})
    if not approved:
        raise Refused(f"no maintainer approved run {run} for the {ENVIRONMENT} environment")
    return {"environment": ENVIRONMENT, "approved": approved}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(
    root: Path,
    *,
    tag: str,
    commit: str,
    repository: str,
    run: str,
    image: str,
    digest: str,
    identity: str,
    issuer: str,
    ci_run: str,
    out_dir: Path,
    fetch: Fetch,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The release record, written beside the files it names, and the release's notes."""
    version = version_of(tag)
    problems = []
    if not COMMIT.fullmatch(commit):
        problems.append(f"{commit!r} is not a full commit")
    if not REPOSITORY.fullmatch(repository):
        problems.append(f"{repository!r} is not OWNER/REPO")
    if not RUN.fullmatch(run):
        problems.append(f"{run!r} is not a workflow run")
    if (wrong := image_problem(image)) is not None:
        problems.append(wrong)
    if not DIGEST.fullmatch(digest):
        problems.append(f"{digest!r} is not a sha256 digest")
    for name, value in (("identity", identity), ("issuer", issuer), ("CI run", ci_run)):
        if not re.fullmatch(r"https://\S+", value):
            problems.append(f"the {name} {value!r} is not an https address")
    files = {}
    for name in PUBLISHED:
        try:
            files[name] = sha256(out_dir / name)
        except OSError:
            problems.append(f"{out_dir / name} is missing")
    if (missing := notes_problem(root, version)) is not None:
        problems.append(missing)
    if problems:
        raise Refused(*problems)
    gate = approval(fetch, repository, run)
    major, minor, _ = version.split(".")
    document = {
        "format": "execbound.release-record.v1",
        "recorded_at": (now or datetime.now(UTC)).isoformat(),
        "release": {
            "repository": repository,
            "tag": tag,
            "version": version,
            "commit": commit,
        },
        "image": {
            "reference": image,
            "tags": [version, f"{major}.{minor}"],
            "digest": digest,
        },
        "signature": {"certificate_identity": identity, "certificate_oidc_issuer": issuer},
        "checks": {"ci_run": ci_run},
        "run": f"https://github.com/{repository}/actions/runs/{run}",
        "approval": gate,
        "files": files,
    }
    (out_dir / "release-record.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "notes.md").write_text(
        notes(root, version, document, repository=repository), encoding="utf-8"
    )
    return document


def notes(root: Path, version: str, document: dict[str, Any], *, repository: str) -> str:
    """The release's description: the reviewed notes, then how to pull and verify the image."""
    written = (root / notes_path(version)).read_text(encoding="utf-8").rstrip()
    image = document["image"]
    signature = document["signature"]
    guide = f"https://github.com/{repository}/blob/{document['release']['tag']}/docs/RELEASE.md"
    return (
        f"{written}\n\n"
        "## The image\n\n"
        "```sh\n"
        f"docker pull {image['reference']}@{image['digest']}\n"
        "```\n\n"
        f"Tagged `{image['reference']}:{version}` and "
        f"`{image['reference']}:{image['tags'][1]}`. Verify its signature before you run it:\n\n"
        "```sh\n"
        f"cosign verify {image['reference']}@{image['digest']} \\\n"
        f"  --certificate-identity {signature['certificate_identity']} \\\n"
        f"  --certificate-oidc-issuer {signature['certificate_oidc_issuer']}\n"
        "```\n\n"
        "Attached: the SBOM of the image's Python environment (`sbom.cdx.json`), the "
        "provenance document (`provenance.json`), the distributions read out of the image "
        "(`image-distributions.json`) and the release record (`release-record.json`), which "
        "names the digest of each of the other three and the approval this release was "
        f"published on. [Releases]({guide}) says what each one holds.\n"
    )


def main(argv: list[str] | None = None, *, fetch: Fetch | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    approved = commands.add_parser("approved")
    approved.add_argument("--repository", required=True)
    approved.add_argument("--run", required=True)
    for name in ("check", "record"):
        command = commands.add_parser(name)
        command.add_argument("--tag", required=True)
        command.add_argument("--commit", required=True)
        command.add_argument("--repository", required=True)
        command.add_argument("--image", required=True)
        if name == "record":
            for option in ("--run", "--digest", "--identity", "--issuer", "--ci-run"):
                command.add_argument(option, required=True)
            command.add_argument("--out-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if fetch is None:
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            parser.error("GH_TOKEN is not set")
        fetch = fetcher(token)
    try:
        if arguments.command == "approved":
            if not REPOSITORY.fullmatch(arguments.repository) or not RUN.fullmatch(arguments.run):
                raise Refused(f"{arguments.repository!r} run {arguments.run!r} is not a run")
            gate = approval(fetch, arguments.repository, arguments.run)
            names = ",".join(review["by"] for review in gate["approved"])
            print(f"approved_by={names}")
        elif arguments.command == "check":
            values = check(
                ROOT,
                tag=arguments.tag,
                commit=arguments.commit,
                repository=arguments.repository,
                image=arguments.image,
                fetch=fetch,
            )
            for key, value in values.items():
                print(f"{key}={value}")
        else:
            record(
                ROOT,
                tag=arguments.tag,
                commit=arguments.commit,
                repository=arguments.repository,
                run=arguments.run,
                image=arguments.image,
                digest=arguments.digest,
                identity=arguments.identity,
                issuer=arguments.issuer,
                ci_run=arguments.ci_run,
                out_dir=arguments.out_dir,
                fetch=fetch,
            )
            print(f"wrote {arguments.out_dir / 'release-record.json'}")
    except Refused as refused:
        for reason in refused.reasons:
            print(f"release refused: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
