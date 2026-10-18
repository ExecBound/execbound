# SPDX-License-Identifier: AGPL-3.0-only
"""The Community bundle: what an outsider is handed, held to what it claims.

These read the files rather than a comment claiming they agree. The bundle's whole purpose is
that somebody with no repository can run it, so a defect here is not a tidiness problem — it
is an installation that fails on a machine nobody here can see.

The files live **in the wheel**, under `execbound/data/community/`, because the installer has
the image and nothing else: `execbound init` copies them out. Two copies, one in the package
and one in `deploy/`, would be a copy that drifts. That every variable the compose file
interpolates is written into the `.env` beside it is checked in `test_quickstart.py`, against
a directory the command actually wrote.
"""

import json
import re
from pathlib import Path

import pytest

BUNDLE = Path(__file__).resolve().parents[1] / "src" / "execbound" / "data" / "community"
COMPOSE = BUNDLE / "compose.yaml"
INITDB = BUNDLE / "initdb" / "01-runtime-role.sh"

# The ports `scripts/ci.py` binds by default, plus the block a second concurrent run on the
# same machine would take. A bundle that defaulted into them would fail beside a CI run in a
# way that looks like the bundle being wrong.
CI_PORTS = {8100, 8101, 8102, 8120, 8121, 8200, 8201, 8202, 8220, 8221, 55442, 55443}


# Read as text rather than parsed: PyYAML is not a dependency of this project and one
# test is a poor reason to add a package to the image's dependency set. `docker compose
# config` is what establishes the file is valid, and that belongs in the clean-environment
# run rather than in pytest, where Docker may not exist. What is checked here is the
# content the runbook and the security rules depend on.
def compose_text():
    return COMPOSE.read_text(encoding="utf-8")


def service_block(name):
    """The lines of one service, from its key to the next key at the same indent."""
    text = compose_text()
    start = text.index(f"\n  {name}:")
    rest = text[start + 1 :]
    following = re.search(r"\n  [a-z]", rest[len(f"  {name}:") :])
    return rest if following is None else rest[: len(f"  {name}:") + following.start()]


def referenced():
    """Every ${VAR} the compose file interpolates, with or without a default."""
    return {
        match.group(1)
        for match in re.finditer(
            r"\$\{([A-Z_][A-Z0-9_]*)[:?}-]", COMPOSE.read_text(encoding="utf-8")
        )
    }


def test_it_declares_the_five_processes():
    for name in ("db", "gateway", "endpoint", "identity", "jobs"):
        assert f"\n  {name}:" in compose_text(), name


def test_the_gateway_starts_through_boot_and_the_jobs_service_runs_the_jobs():
    """The owner connection reaches the gateway's container and never its server process.

    `boot.py` removes `MIGRATION_DATABASE_URL` before it execs, so a one-off
    `docker compose run` keeps the variable and the long-running process facing the network
    does not. A gateway started with uvicorn directly would keep it, which is the defect this
    reads for.
    """
    gateway = service_block("gateway")
    assert "MIGRATION_DATABASE_URL:" in gateway
    assert "execbound.boot" in gateway, "the gateway must start through boot or it keeps the URL"
    jobs = service_block("jobs")
    assert '["execbound", "jobs"]' in jobs
    assert "MIGRATION_DATABASE_URL" not in jobs, "the jobs service holds no owner connection"
    assert ":/srv/state:ro" in jobs, "it uses the credentials quickstart issued and writes none"


def test_the_collectors_key_is_mounted_into_the_jobs_container_alone():
    """The collector's private key opens every sealed monitoring key (#678). The jobs container
    mounts its directory read-only; the gateway, which seals keys and must never open one, and
    every other process mount nothing of it."""
    assert "${EXECBOUND_COLLECTOR:-./collector}:/srv/collector:ro" in service_block("jobs")
    for name in ("netns", "db", "gateway", "endpoint", "identity"):
        assert "EXECBOUND_COLLECTOR" not in service_block(name), name
        assert "/srv/collector" not in service_block(name), name


def test_nothing_is_mounted_from_outside_the_bundle():
    """A path out of the bundle is a repository dependency wearing a mount."""
    for line in compose_text().splitlines():
        stripped = line.strip()
        if not stripped.startswith("- ") or ":" not in stripped:
            continue
        source = stripped[2:].split(":", 1)[0]
        assert not source.startswith(".."), f"mounts outside the bundle: {stripped}"
        # An absolute host path is either a machine-specific assumption or a clone.
        assert not source.startswith("/"), f"mounts a host path: {stripped}"


def test_the_database_is_a_named_volume_and_the_provider_stores_are_a_directory():
    """Both must survive `docker compose down`.

    The provider store is the one people underestimate: it holds the journals that settle
    retained uncertainty, so losing it leaves an uncertain operation with nothing to be
    reconciled from.
    """
    text = compose_text()
    assert "- execbound-db:/var/lib/postgresql/data" in text
    # The provider stores are a bind mount, not a named volume: Docker creates a named
    # volume root-owned and these processes are not root, so the store could never be
    # written. Running the installation is what found that.
    assert text.count("${EXECBOUND_PROVIDERS:-./providers}:/srv/providers") == 3, (
        "the gateway and both providers share the store directory"
    )
    assert "execbound-providers:" not in text


def test_the_image_is_one_line_and_a_variable():
    """When a registry exists this becomes a pull reference and nothing else changes."""
    text = COMPOSE.read_text(encoding="utf-8")
    images = re.findall(r"^\s*image:\s*(\S+)", text, re.M)
    # PostgreSQL is pinned; ExecBound's own image is the variable.
    assert "${EXECBOUND_IMAGE:-execbound:community}" in images
    assert sum(1 for image in images if "EXECBOUND_IMAGE" in image) == 1


@pytest.mark.parametrize("port", sorted(CI_PORTS))
def test_no_default_port_collides_with_this_project_s_own_runners(port):
    text = COMPOSE.read_text(encoding="utf-8")
    assert f":-{port}}}" not in text and f'"{port}:' not in text


def test_the_runtime_role_cannot_bypass_row_level_security():
    """Readiness refuses a role that can, so this is what makes the gateway start at all."""
    script = INITDB.read_text(encoding="utf-8")
    assert "CREATE ROLE execbound_app" in script
    for clause in ("NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOINHERIT", "NOBYPASSRLS"):
        assert clause in script, clause


def test_every_process_shares_one_namespace_so_that_everything_is_loopback():
    """Two separate rules force this, and running the runbook is what found the second.

    `ConnectionConfig` refuses a cleartext provider origin whose host is not a loopback IP,
    and `connection.py` refuses a PostgreSQL URL whose host is not loopback unless it
    carries sslmode=verify-full and a CA bundle. Over a normal compose network both
    `http://endpoint:8000` and `db:5432` are remote and both are refused — the database one
    only at migration time, which is why reading the file did not catch it.

    `netns` owns the namespace and publishes the gateway's port; the next test says why it is
    not the database.
    """
    for name in ("db", "gateway", "endpoint", "identity", "jobs"):
        block = service_block(name)
        assert 'network_mode: "service:netns"' in block, name
        assert "ports:" not in block, f"{name} must not publish its own port"
    assert "127.0.0.1:5432" in compose_text(), "the gateway reaches the database at loopback"
    assert "@db:5432" not in compose_text(), "a hostname here is refused as remote"


def test_the_namespace_belongs_to_a_container_that_runs_nothing():
    """A container that joined a namespace stays in it when the namespace's owner restarts.

    The namespace is made when its owner starts and goes when its owner stops. While `db`
    owned it, `docker compose stop db` then `start db`, `docker compose restart db`, and
    PostgreSQL exiting and coming back under its restart policy each left the gateway, both
    mocks and the jobs service in the old namespace with only loopback. The published port
    answered nothing, the jobs service could not reach PostgreSQL, `docker compose up -d`
    changed nothing, and Docker reported all four healthy throughout, because each health check
    connects to 127.0.0.1 inside the namespace it was left in. The local recovery exercise found
    it (#130), and all three were reproduced on October 15, 2026. A container that runs nothing
    has no reason to restart, so it holds the namespace and the database joins it like the rest.
    """
    holder = service_block("netns")
    assert "network_mode:" not in holder, "the namespace's owner joins nobody else's"
    assert 'entrypoint: ["sleep", "infinity"]' in holder
    # Process 1 ignores SIGTERM, so without an init Docker waits ten seconds and kills it.
    assert "init: true" in holder
    assert "image: postgres:17.11" in holder, "no image beyond the two the bundle already pins"
    assert '- "127.0.0.1:${EXECBOUND_PORT:-8080}:8000"' in holder
    # It runs nothing, so it is given nothing: no password, no mount, no capability.
    for absent in ("environment:", "volumes:", "PASSWORD", "command:"):
        assert absent not in holder, absent
    assert "cap_drop: [ALL]" in holder
    assert compose_text().count("\n    ports:") == 1, "one published port, and it is the holder's"


RUNBOOK = Path(__file__).resolve().parents[1] / "docs" / "INSTALL.md"


def test_only_the_gateway_listens_beyond_the_namespace():
    """The published port forwards to the namespace's address, never to its loopback.

    A gateway bound to 127.0.0.1 is reachable from every process in the namespace and from
    nobody outside it, so `docker compose ps` shows the port published and the browser gets
    a connection reset. Found by installing. The mocks are the opposite case and must stay
    on loopback: their cleartext origins are accepted only because they are loopback.
    """
    assert '"--host", "0.0.0.0"' in service_block("gateway")
    for name in ("endpoint", "identity"):
        assert '"--host", "127.0.0.1"' in service_block(name), name
        assert "0.0.0.0" not in service_block(name), name


@pytest.mark.docs
def test_the_runbook_leads_with_the_three_commands():
    """Three commands, in order, before anything else the reader could do instead."""
    text = RUNBOOK.read_text(encoding="utf-8")
    first = text.index("execbound init /install")
    second = text.index("docker compose up -d")
    third = text.index("execbound quickstart")
    assert first < second < third
    # The container writes into a directory on the host; as the image's own user it could not.
    assert text.index('-u "$(id -u):$(id -g)"') < second
    # Nobody invents a password any more: `init` generates both.
    assert "openssl rand" not in text
    assert "measured rather than claimed" in text.lower() or "fresh-machine" in text


@pytest.mark.docs
def test_the_runbook_uses_the_port_the_bundle_defaults_to():
    """The runbook curls a port. If the bundle publishes a different one, it is wrong."""
    match = re.search(r"EXECBOUND_PORT:-(\d+)", compose_text())
    assert match, "the bundle declares a default port"
    assert f"127.0.0.1:{match.group(1)}" in RUNBOOK.read_text(encoding="utf-8")


@pytest.mark.docs
def test_the_runbook_does_not_ask_for_anything_but_docker():
    """The whole point of it. A uv or pip step means the developer setup came back."""
    text = RUNBOOK.read_text(encoding="utf-8")
    for forbidden in ("uv sync", "uv run", "pip install", "playwright", "git clone"):
        assert forbidden not in text, f"the runbook asks for {forbidden}"


@pytest.mark.docs
def test_the_runbook_states_what_the_run_established():
    """The claim and the evidence move together.

    It has now been followed end to end, so it says so and says what that run found. What
    the run did not establish is the trial record's to say, and the runbook points at the
    record rather than restating it, so the two cannot drift into disagreeing about what was
    proved.
    """
    assert "## What this run established" in RUNBOOK.read_text(encoding="utf-8")


@pytest.mark.docs
def test_the_runbook_says_why_the_first_command_runs_as_the_installer():
    """Docker creates a missing bind source as root, and the failure surfaces much later.

    Found by running the older runbook: the private directory was created by the first
    `compose run`, root-owned, and the configuration step failed several steps afterwards
    with nothing pointing back to the cause. `execbound init` running as the installer is
    what replaced the `mkdir` that used to come first, so the reason has to be written down
    where somebody tempted to drop the flag will read it.
    """
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "is not optional" in text
    assert "root" in text and "cannot write" in text


@pytest.mark.docs
def test_the_project_name_is_configurable():
    """A fixed project name means a second installation adopts the first one's database.

    The symptom is `password authentication failed` against passwords that are correct,
    several steps after the cause, because the volume outlived a `docker compose down`.
    Found by installing twice on one machine, which is also why the runbook now says how
    to start genuinely fresh.
    """
    assert "name: ${EXECBOUND_PROJECT:-execbound}" in compose_text()
    assert "EXECBOUND_PROJECT" in referenced()
    assert "docker compose down -v" in RUNBOOK.read_text(encoding="utf-8")


STARTER = BUNDLE / "starter-rules.json"


@pytest.mark.docs
def test_the_bundle_ships_a_starter_ruleset_the_runbook_uses():
    """Without it the runbook's policy step has nothing to compile.

    The installation cannot author a bundle document by hand — that is the whole reason
    `ruleset-compile` exists — so the rules have to be in the bundle the installer was
    given, not in a repository they do not have.
    """
    assert STARTER.exists(), "the community bundle ships no starter ruleset"
    text = RUNBOOK.read_text(encoding="utf-8")
    assert STARTER.name in text
    assert "ruleset-compile" in text


@pytest.mark.docs
def test_the_runbook_and_the_starter_ruleset_say_the_same_thing():
    """A table in prose and a file on disk, kept in step.

    The runbook tells the reader what the four rules do and then has them activate the
    file. If an edit moves one and not the other, the reader is told one policy and gets
    another, which is the worst failure a runbook can have.
    """
    ruleset = json.loads(STARTER.read_text(encoding="utf-8"))
    text = RUNBOOK.read_text(encoding="utf-8")
    assert {rule["action"] for rule in ruleset["rules"]} == {"endpoint.isolate"}
    for rule in ruleset["rules"]:
        for condition in rule["when"]:
            assert condition["name"] in text, f"{rule['id']} turns on an unmentioned fact"
            for value in condition["values"]:
                assert str(value).lower() in text.lower(), f"{rule['id']}: {value}"
    # Every rule's effect is named in the table, in the words the compiler's sentences use.
    for effect in {rule["effect"] for rule in ruleset["rules"]}:
        assert effect.capitalize() in text


@pytest.mark.docs
def test_the_runbook_reaches_an_allowed_action_and_a_refused_one():
    """The amended acceptance of the issue this bundle serves, asserted on the text.

    A runbook that stops at a healthy gateway proves an installation runs, not that it
    governs anything, and the two states it has to reach are these.
    """
    text = RUNBOOK.read_text(encoding="utf-8")
    assert '"state":"EXECUTED"' in text and '"state":"DENIED"' in text
    assert "/v1/execute" in text
    assert "audit-export" in text
    # The refusal has to be one an allow rule matched, or it shows nothing about
    # precedence that default deny would not have shown.
    assert "criticality 4" in text and "denial wins over a permit" in text
