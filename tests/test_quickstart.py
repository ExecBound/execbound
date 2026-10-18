# SPDX-License-Identifier: AGPL-3.0-only
"""The three commands, as far as pytest can reach them: `init` and `quickstart`.

The first is a file-writing command with no database and no network, and every claim about
what an installer is handed can be read off the directory it wrote. The second is the whole
sequence against real PostgreSQL, with the two requests answered by a stub transport, because
what those two requests establish is the subject of the fresh-machine job and of a real run on
one host, not of a unit test. What is under test here is that the sequence builds a tenant a
governed request could succeed against: the accounts the configuration names, the mapping, the
facts that differ, the provider's own view of both targets, the active bundle, and the
credential files an installer has to be able to read.
"""

import io
import json
import os
import re
import stat
import sys
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from conftest import local_test_url
from sqlalchemy import text

from execbound import install, quickstart
from execbound.cli import main
from execbound.db import DormantGrantsRefused
from execbound.execution import store
from execbound.execution.models import DEFAULT_APPROVAL_DEADLINE
from execbound.surfaces.configuration import read_configuration

ROOT = Path(__file__).resolve().parents[1]


def written(tmp_path, **changes):
    return install.install(tmp_path / "eb", **{"port": 8601, **changes})


@pytest.fixture
def installed(tmp_path):
    return written(tmp_path)


def test_it_writes_a_whole_installation(installed):
    """Every file the compose stack needs, in a directory the installer owns."""
    for path in install.targets(installed.directory):
        assert path.exists(), path
    for name, mode in install.DIRECTORIES:
        made = installed.directory / name
        assert made.is_dir(), name
        # `initdb/` is read by PostgreSQL's entrypoint, which runs as the database image's
        # own user: created 0700 it cannot be opened at all, and the only symptom is a
        # container that never becomes healthy. Found by installing rather than by reading.
        assert stat.S_IMODE(made.stat().st_mode) == mode, name
    assert dict(install.DIRECTORIES)["initdb"] == 0o755
    assert dict(install.DIRECTORIES)["private"] == 0o700
    # The collector's key pair, mounted into the jobs container alone (#678).
    assert dict(install.DIRECTORIES)["collector"] == 0o700


def test_every_variable_the_compose_file_reads_is_in_the_env_it_wrote(installed):
    """A variable the file interpolates and the `.env` omits is an install that fails later.

    This is the check the old `.env.example` needed a person to keep true. Now one command
    writes both, so it is a property of the command rather than of somebody's diligence.
    """
    compose = (installed.directory / "compose.yaml").read_text(encoding="utf-8")
    used = {match.group(1) for match in re.finditer(r"\$\{([A-Z_][A-Z0-9_]*)[:?}-]", compose)}
    declared = {
        line.split("=", 1)[0].strip()
        for line in (installed.directory / ".env").read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.strip().startswith("#")
    }
    assert used - declared == set(), used - declared


def test_the_secrets_are_generated_private_and_different(installed):
    values = dict(
        line.split("=", 1)
        for line in (installed.directory / ".env").read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.strip().startswith("#")
    )
    owner, runtime = values["POSTGRES_PASSWORD"], values["EXECBOUND_APP_PASSWORD"]
    assert owner != runtime
    for password in (owner, runtime):
        assert len(password) >= 32 and not any(c.isspace() for c in password)
    for path in (
        installed.directory / ".env",
        *[
            installed.directory / "private" / name
            for name in ("gateway.json", "endpoint-accounts.json", "identity-accounts.json")
        ],
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path


def test_it_runs_as_the_installer_so_the_containers_can(installed):
    """The uid and gid in the `.env` are the ones the command ran as, which is the point."""
    values = (installed.directory / ".env").read_text(encoding="utf-8")
    assert f"EXECBOUND_UID={os.getuid()}" in values
    assert f"EXECBOUND_GID={os.getgid()}" in values


def test_the_configuration_it_wrote_is_one_the_gateway_accepts(installed):
    """Written by a command and read by the gateway's own loader, not by a test's idea of it."""
    configured = read_configuration(installed.directory / "private" / "gateway.json")
    assert configured.origin == "http://127.0.0.1:8601"
    assert {connector.provider for connector in configured.connectors} == {
        "mock_crowdstrike",
        "mock_entra",
    }
    assert {connector.tenant_id for connector in configured.connectors} == {installed.tenant_id}
    assert configured.telemetry is not None and configured.telemetry.enabled is False
    # Each provider family gets its own material; startup refuses reuse.
    tokens = {
        connector.dispatch_token.get_secret_value() for connector in configured.connectors
    } | {connector.control_token.get_secret_value() for connector in configured.connectors}
    assert len(tokens) == 4


def test_the_accounts_files_hold_digests_and_the_configuration_holds_the_tokens(installed):
    """The provider never learns a token it was not given, which is why these differ."""
    record = json.loads(
        (installed.directory / "private" / "endpoint-accounts.json").read_text(encoding="utf-8")
    )[0]
    assert set(record) == {
        "tenant_id",
        "account_id",
        "provider",
        "dispatch_token_hash",
        "control_token_hash",
        "signing_key_hex",
        "key_id",
    }
    assert record["account_id"] == str(installed.endpoint_account_id)


def test_telemetry_is_off_unless_it_is_asked_for(tmp_path):
    on = written(tmp_path / "yes", telemetry=True)
    configured = read_configuration(on.directory / "private" / "gateway.json")
    assert configured.telemetry is not None and configured.telemetry.enabled is True


@pytest.mark.parametrize(
    ("answer", "tty", "typed", "expected"),
    [
        (None, False, "", False),
        (None, True, "\n", False),
        (None, True, "y\n", True),
        (None, True, "YES\n", True),
        (None, True, "no\n", False),
        (True, False, "", True),
        (False, True, "y\n", False),
    ],
)
def test_the_question_defaults_to_no_and_silence_is_no(answer, tty, typed, expected):
    """`docker run` without a terminal has nobody to ask, and nobody has opted in."""

    class Stream(io.StringIO):
        def isatty(self):
            return tty

    assert (
        install.ask_telemetry(answer, input_stream=Stream(typed), output=io.StringIO()) is expected
    )


def test_a_second_init_refuses_and_changes_nothing(installed):
    """Overwriting would replace tokens the providers and the database already agree on."""
    before = {path: path.read_bytes() for path in install.targets(installed.directory)}
    with pytest.raises(install.InstallError, match="already holds an installation"):
        install.install(installed.directory)
    assert {path: path.read_bytes() for path in install.targets(installed.directory)} == before


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"port": 80}, "port"),
        ({"project": "two words"}, "project"),
        ({"image": "not an image"}, "image"),
    ],
)
def test_it_refuses_an_argument_that_would_produce_a_broken_stack(tmp_path, changes, message):
    with pytest.raises(install.InstallError, match=message):
        install.install(tmp_path / "eb", **changes)
    assert not (tmp_path / "eb" / ".env").exists()


# --- quickstart -------------------------------------------------------------------------


class Gateway:
    """The running gateway, as far as quickstart is concerned: ready, then two decisions."""

    def __init__(self):
        self.requests = []

    def handle(self, request):
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ready"})
        body = json.loads(request.content)
        self.requests.append((request, body))
        allowed = body["target"]["value"] == "ws01.example"
        return httpx.Response(
            200,
            json={
                "execution_id": str(uuid4()),
                "state": "EXECUTED" if allowed else "DENIED",
                "plan_hash": "0" * 64,
                "approval_id": None,
                "approval_state": None,
            },
        )


@pytest.fixture
def gateway():
    return Gateway()


@pytest.fixture
def urls(seeded):
    """The suite's own databases, as the two roles quickstart is given."""
    owner = local_test_url(os.environ["TEST_MIGRATION_DATABASE_URL"], "execbound_owner")
    runtime = local_test_url(os.environ["TEST_DATABASE_URL"], "execbound_app")
    return (
        owner.render_as_string(hide_password=False),
        runtime.render_as_string(hide_password=False),
    )


def run(installed, urls, gateway, **changes):
    owner, runtime = urls
    with httpx.Client(transport=httpx.MockTransport(gateway.handle)) as client:
        return quickstart.quickstart(
            owner_url=owner,
            runtime_url=runtime,
            private=installed.directory / "private",
            state=installed.directory / "state",
            providers=installed.directory / "providers",
            alembic_config=ROOT / "alembic.ini",
            name=f"Quickstart {uuid4().hex[:8]}",
            client=client,
            output=io.StringIO(),
            **changes,
        )


def rows(engine, tenant, table):
    with engine.connect() as conn:
        return conn.execute(
            text(f"SELECT count(*) FROM execbound.{table} WHERE tenant_id = :t"), {"t": tenant}
        ).scalar_one()


@pytest.mark.integration
def test_it_reaches_a_governed_decision(installed, urls, gateway, admin_engine):
    """The whole sequence, and the two states the amended acceptance of #123 asks for."""
    outcome = run(installed, urls, gateway)
    assert outcome.tenant_id == installed.tenant_id
    assert [(d.hostname, d.state) for d in outcome.decisions] == [
        ("ws01.example", "EXECUTED"),
        ("ws02.example", "DENIED"),
    ]
    tenant = outcome.tenant_id
    # One administrator, one jobs administrator, one agent.
    assert rows(admin_engine, tenant, "principals") == 3
    assert rows(admin_engine, tenant, "connector_accounts") == 2
    assert rows(admin_engine, tenant, "operation_mappings") == 1
    assert rows(admin_engine, tenant, "resources") == 2
    assert rows(admin_engine, tenant, "incidents") == 2
    assert rows(admin_engine, tenant, "context_sources") == 2
    with admin_engine.connect() as conn:
        state = conn.execute(
            text(
                "SELECT state FROM execbound.policy_bundle_lifecycle "
                "WHERE tenant_id = :t AND bundle_id = :b"
            ),
            {"t": tenant, "b": outcome.bundle_id},
        ).scalar_one()
        # The quickstart's workspace keeps core's two-minute approval deadline (#678).
        deadline = store.approval_deadline(conn, tenant)
    assert state == "ACTIVE"
    assert deadline == DEFAULT_APPROVAL_DEADLINE == 120


@pytest.mark.integration
def test_the_rows_carry_the_ids_the_configuration_named(installed, urls, gateway, admin_engine):
    """The file was written before the database existed, so the rows agree with the file."""
    outcome = run(installed, urls, gateway)
    with admin_engine.connect() as conn:
        accounts = set(
            conn.execute(
                text("SELECT account_id FROM execbound.connector_accounts WHERE tenant_id = :t"),
                {"t": outcome.tenant_id},
            ).scalars()
        )
    assert accounts == {installed.endpoint_account_id, installed.identity_account_id}


@pytest.mark.integration
def test_the_two_endpoints_differ_in_one_fact(installed, urls, gateway, admin_engine):
    """The refusal has to be one an allow rule matched, or it shows nothing about precedence."""
    outcome = run(installed, urls, gateway)
    with admin_engine.connect() as conn:
        facts = dict(
            conn.execute(
                text(
                    "SELECT provider_id, criticality FROM execbound.resources WHERE tenant_id = :t"
                ),
                {"t": outcome.tenant_id},
            ).all()
        )
    assert facts == {"device-ws-01": 2, "device-ws-02": 4}
    with admin_engine.connect() as conn:
        roles = set(
            conn.execute(
                text("SELECT DISTINCT role FROM execbound.resources WHERE tenant_id = :t"),
                {"t": outcome.tenant_id},
            ).scalars()
        )
    assert roles == {"workstation"}


@pytest.mark.integration
def test_the_provider_holds_both_targets(installed, urls, gateway, admin_engine):
    """A dispatch whose target the provider never heard of has nothing to act on."""
    from execbound.provider.mock_store import MockStore

    outcome = run(installed, urls, gateway)
    store = MockStore(installed.directory / "providers" / "endpoint.sqlite3")
    with admin_engine.connect() as conn:
        targets = set(
            conn.execute(
                text(
                    "SELECT canonical_target_id FROM execbound.resource_identities "
                    "WHERE tenant_id = :t"
                ),
                {"t": outcome.tenant_id},
            ).scalars()
        )
    assert len(targets) == 2
    for target in targets:
        held = store.resource(outcome.tenant_id, target)
        assert held is not None and held.version == quickstart.RESOURCE_VERSION


@pytest.mark.integration
def test_the_credential_files_are_private_and_the_jobs_map_is_a_map(installed, urls, gateway):
    """An installer has to read the administrator token, and nothing else may."""
    outcome = run(installed, urls, gateway)
    state = installed.directory / "state"
    for name in (quickstart.ADMIN_FILE, quickstart.AGENT_FILE, quickstart.JOBS_FILE):
        path = state / name
        assert path.exists() and stat.S_IMODE(path.stat().st_mode) == 0o600, name
    # The single-token file is a step, not an artifact: one token in one place afterwards.
    assert not (state / quickstart.JOBS_TOKEN_FILE).exists()
    document = json.loads((state / quickstart.JOBS_FILE).read_text(encoding="utf-8"))
    assert list(document) == [str(outcome.tenant_id)]
    monitor = json.loads((state / quickstart.MONITOR_FILE).read_text(encoding="utf-8"))
    assert monitor["admin_token"] == document[str(outcome.tenant_id)]
    assert document[str(outcome.tenant_id)] not in (state / quickstart.ADMIN_FILE).read_text()


@pytest.mark.integration
def test_the_agent_asks_as_an_agent_and_the_host_is_the_configured_origin(installed, urls, gateway):
    """The gateway refuses a Host that is not its origin, and the port inside is not the one
    the host publishes, so this header is what makes the request answerable at all."""
    outcome = run(installed, urls, gateway)
    assert len(gateway.requests) == 2
    for request, body in gateway.requests:
        assert request.headers["host"] == "127.0.0.1:8601"
        assert request.headers["authorization"].startswith("Bearer eb1.")
        assert body["operation_ref"] == "endpoint.isolate"
        assert UUID(body["claimed_context"]["incident_id"])
    assert {body["target"]["value"] for _, body in gateway.requests} == {
        "ws01.example",
        "ws02.example",
    }
    assert outcome.console == "http://127.0.0.1:8601/login?setup=1"


@pytest.mark.integration
def test_a_second_quickstart_refuses_and_says_what_it_found(installed, urls, gateway):
    """Running it twice must not mint a second administrator over a live deployment."""
    run(installed, urls, gateway)
    seen = len(gateway.requests)
    with pytest.raises(quickstart.QuickstartError, match="already holds the tenant"):
        run(installed, urls, gateway)
    assert len(gateway.requests) == seen


@pytest.mark.integration
def test_it_refuses_a_directory_no_init_wrote(tmp_path, urls, gateway):
    with pytest.raises(quickstart.QuickstartError, match="execbound init"):
        owner, runtime = urls
        quickstart.quickstart(
            owner_url=owner,
            runtime_url=runtime,
            private=tmp_path,
            state=tmp_path,
            providers=tmp_path,
            alembic_config=ROOT / "alembic.ini",
            client=httpx.Client(transport=httpx.MockTransport(gateway.handle)),
            output=io.StringIO(),
        )


def test_the_starter_rules_it_activates_come_from_the_image():
    """Not the copy beside the compose file: that one is the installer's to edit."""
    from execbound.policy.models import Ruleset

    ruleset = Ruleset.model_validate_json(quickstart.starter_rules())
    assert {rule.action for rule in ruleset.rules} == {quickstart.ACTION}
    assert {rule.effect for rule in ruleset.rules} == {"ALLOW", "DENY", "REVIEW"}


def test_a_runtime_check_refusal_stops_quickstart_without_advice_to_run_it_again(
    monkeypatch, capsys
):
    """Quickstart has already committed owner work when the runtime check can refuse, so a
    second run would find the tenant there. It keeps its own sentence, the refusal's class
    name, and never the incident commands' advice to run the command again (#496).
    It is also a one-host command that no plugin's deployment runs."""

    def refused(**kwargs):
        raise DormantGrantsRefused("a detail nobody should see")

    monkeypatch.setattr(quickstart, "quickstart", refused)
    monkeypatch.setenv("MIGRATION_DATABASE_URL", "unused")
    monkeypatch.setenv("DATABASE_URL", "unused")
    monkeypatch.delenv("EXECBOUND_PLUGINS", raising=False)
    monkeypatch.setattr(sys, "argv", ["execbound", "quickstart"])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    printed = capsys.readouterr()
    stopped = "Quickstart stopped with DormantGrantsRefused; nothing is printed."
    assert printed.out == "" and stopped in printed.err.splitlines()
    assert "run the command again" not in printed.err and "detail" not in printed.err
