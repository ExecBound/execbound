# SPDX-License-Identifier: AGPL-3.0-only
"""One command from an empty database to a governed decision.

`execbound quickstart` is the third of the three commands an installation runs, and it is the
one that makes the deployment true: migrations, the tenant the private configuration already
names, its first administrator, the two mock connector accounts, the isolation mapping, the
trusted context, two endpoints that differ in one fact, the starter rules compiled and
activated, an agent, and then two requests to the running gateway. One is executed and one is
refused, and both are in the audit chain.

It ends with a decision on purpose. A command that stops at a healthy gateway has shown that
an installation runs; the acceptance on #123
is that it governs, and the only evidence of that is a decision.

Nothing here is a seeder. Every step is an owner command or an ordinary request, the same ones
`docs/INSTALL.md` spells out one at a time, so an installer who wants to know what happened can
read the runbook and find each of them. The development harness, which the image does not
carry, is not involved.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO
from uuid import UUID, uuid4

if TYPE_CHECKING:  # pragma: no cover - imported for types only
    import httpx
    from sqlalchemy.engine import Engine

DEFAULT_PRIVATE = Path("/srv/private")
DEFAULT_STATE = Path("/srv/state")
DEFAULT_PROVIDERS = Path("/srv/providers")
# Inside the shared network namespace the gateway is on its own container port, whatever the
# host publishes. The `Host` header is the configured origin's, because the gateway refuses
# every request whose Host is not the origin it was configured with, and that origin is the
# one a browser on the host will use.
DEFAULT_GATEWAY = "http://127.0.0.1:8000"
DEFAULT_NAME = "ExecBound"
DEFAULT_CREDENTIAL_DAYS = 90
READY_SECONDS = 90
ENDPOINT_PROVIDER = "mock_crowdstrike"
IDENTITY_PROVIDER = "mock_entra"
ACTION = "endpoint.isolate"
RESOURCE_VERSION = "resource-v1"
ADMIN_FILE = "admin.token"  # nosec B105 - a file name, not a secret
AGENT_FILE = "agent.token"  # nosec B105 - a file name, not a secret
JOBS_TOKEN_FILE = "jobs.token"  # nosec B105 - a file name, not a secret
JOBS_FILE = "jobs.json"
MONITOR_FILE = "monitor.json"
STEPS = 9
# The two endpoints. Both are workstations with an open critical incident and they differ in
# one fact, which is the whole demonstration: the second satisfies every condition of the
# allow rule and is refused anyway, because a denial wins over a permit.
ENDPOINTS = (
    ("device-ws-01", "ws01.example", 2, "INC-1001", "ticket-1001"),
    ("device-ws-02", "ws02.example", 4, "INC-1002", "ticket-1002"),
)


class QuickstartError(Exception):
    """A refusal an installer is shown. It names a step, never a token or a password."""


@dataclass(frozen=True)
class Decision:
    reference: str
    hostname: str
    state: str
    execution_id: str


@dataclass(frozen=True)
class Outcome:
    tenant_id: UUID
    admin_principal_id: UUID
    agent_principal_id: UUID
    bundle_id: UUID
    decisions: tuple[Decision, ...]
    admin_token_file: Path
    agent_token_file: Path
    jobs_file: Path
    console: str


def starter_rules() -> bytes:
    """The starter ruleset out of the wheel.

    The image's own copy, not the one `execbound init` wrote beside the compose file: that
    one is the installer's to edit and recompile with `ruleset-compile`, and a first bundle
    has to come from something that cannot have been edited into a shape the compiler
    refuses halfway through the installation.
    """
    return (
        resources.files("execbound.data")
        .joinpath("community")
        .joinpath("starter-rules.json")
        .read_bytes()
    )


def _configuration(private: Path) -> dict[str, Any]:
    """The tenant and both accounts this installation was written for, from its own file.

    The file is the record of what the deployment is: `execbound init` generated these ids
    before any database existed, so the rows are made to agree with the file rather than the
    file rewritten to agree with rows nobody has created yet.
    """
    from execbound.surfaces.configuration import read_configuration

    try:
        configured = read_configuration(private / "gateway.json")
    except (OSError, ValueError) as error:
        raise QuickstartError(
            f"The private configuration at {private / 'gateway.json'} is unreadable or invalid; "
            "run `execbound init` first"
        ) from error
    accounts = {connector.provider: connector for connector in configured.connectors}
    if ENDPOINT_PROVIDER not in accounts or IDENTITY_PROVIDER not in accounts:
        raise QuickstartError(
            "The private configuration must declare both mock connectors; "
            "this one was not written by `execbound init`"
        )
    endpoint, identity = accounts[ENDPOINT_PROVIDER], accounts[IDENTITY_PROVIDER]
    if endpoint.tenant_id != identity.tenant_id:
        raise QuickstartError("The two connectors name different tenants")
    return {
        "origin": configured.origin,
        "tenant_id": endpoint.tenant_id,
        "endpoint_account_id": endpoint.account_id,
        "identity_account_id": identity.account_id,
    }


def _migrate(owner_url: str, config_path: Path) -> None:
    from alembic import command
    from alembic.config import Config

    if not config_path.exists():
        raise QuickstartError(f"{config_path} is missing; run this command from the image")
    config = Config(str(config_path))
    config.attributes["database_url"] = owner_url
    command.upgrade(config, "head")


def _existing(engine: Engine, tenant: UUID) -> tuple[str, int] | None:
    """The tenant's name and principal count if quickstart has already run against this."""
    from sqlalchemy import text

    with engine.connect() as conn:
        name = conn.execute(
            text("SELECT name FROM execbound.tenants WHERE tenant_id = :t"), {"t": tenant}
        ).scalar_one_or_none()
        if name is None:
            return None
        principals = conn.execute(
            text("SELECT count(*) FROM execbound.principals WHERE tenant_id = :t"), {"t": tenant}
        ).scalar_one()
    return str(name), int(principals)


def _manifest(
    tenant: UUID, account: UUID, source: UUID, observed: datetime, incidents: dict[str, str]
) -> bytes:
    return json.dumps(
        {
            "manifest": "execbound.context-manifest.v1",
            "tenant_id": str(tenant),
            "account_id": str(account),
            "source_id": str(source),
            "kind": "incident",
            "writer": "soc_analyst",
            "entries": [
                {
                    "provider": ENDPOINT_PROVIDER,
                    "resource_type": "endpoint",
                    "provider_id": provider_id,
                    "incident_id": incidents[provider_id],
                    "version": version,
                    "observed_at": observed.isoformat(),
                    "facts": {"incident_status": "OPEN", "incident_severity": "CRITICAL"},
                }
                for provider_id, _hostname, _criticality, _reference, version in ENDPOINTS
            ],
        }
    ).encode("utf-8")


def _write_private(path: Path, value: dict[str, str]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")


def _token(path: Path) -> str:
    from execbound.replay.runner import read_bounded

    return read_bounded(path, 162).decode("ascii").rstrip("\r\n")


def _wait_for_gateway(client: httpx.Client, gateway: str, host: str, *, seconds: int) -> None:
    """`docker compose up -d` returns before the gateway answers; wait rather than fail.

    Readiness, not liveness: it is the check that the schema this command just applied is the
    one the running gateway expects, which is the failure worth naming here rather than
    discovering as a strange answer to the first request.
    """
    deadline = time.monotonic() + seconds
    last = "no answer"
    while time.monotonic() < deadline:
        try:
            response = client.get(f"{gateway}/health/ready", headers={"host": host}, timeout=5.0)
        # Any transport failure here means "not yet": the gateway is a few seconds behind
        # `docker compose up -d`, and a refused connection is the ordinary first answer.
        except Exception as error:
            last = type(error).__name__
        else:
            if response.status_code == 200:
                return
            last = f"HTTP {response.status_code}"
        time.sleep(1.0)
    raise QuickstartError(
        f"The gateway at {gateway} did not become ready within {seconds} seconds ({last}). "
        "Check `docker compose ps` and `docker compose logs gateway`."
    )


def _execute(
    client: httpx.Client, gateway: str, host: str, token: str, body: dict[str, Any]
) -> dict[str, Any]:
    response = client.post(
        f"{gateway}/v1/execute",
        json=body,
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "host": host,
        },
    )
    document = (
        response.json()
        if response.headers.get("content-type", "").startswith("application/json")
        else {}
    )
    if not isinstance(document, dict) or "state" not in document:
        raise QuickstartError(
            f"The gateway answered {response.status_code} with no decision. "
            "Check `docker compose logs gateway`."
        )
    return document


def quickstart(
    *,
    owner_url: str,
    runtime_url: str,
    private: Path = DEFAULT_PRIVATE,
    state: Path = DEFAULT_STATE,
    providers: Path = DEFAULT_PROVIDERS,
    gateway: str = DEFAULT_GATEWAY,
    name: str = DEFAULT_NAME,
    credential_days: int = DEFAULT_CREDENTIAL_DAYS,
    alembic_config: Path = Path("alembic.ini"),
    ready_seconds: int = READY_SECONDS,
    client: httpx.Client | None = None,
    output: TextIO,
) -> Outcome:
    """The whole sequence. Each step prints as it completes; no step prints a secret."""
    import httpx

    from execbound import administration as admin
    from execbound import provisioning
    from execbound.db import Database
    from execbound.identity import authenticate
    from execbound.policy.models import MappingRef, Ruleset
    from execbound.policy.rulesets import RulesetError, ruleset_bundle
    from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
    from execbound.provider.mock_store import MockStore

    configured = _configuration(private)
    tenant: UUID = configured["tenant_id"]
    endpoint_account: UUID = configured["endpoint_account_id"]
    identity_account: UUID = configured["identity_account_id"]
    origin: str = configured["origin"]
    host = origin.split("//", 1)[-1]
    ruleset = Ruleset.model_validate_json(starter_rules())

    def say(step: int, line: str) -> None:
        output.write(f"[{step}/{STEPS}] {line}\n")
        output.flush()

    _migrate(owner_url, alembic_config)
    say(1, "Schema applied to head with the owner connection.")

    engine = admin.owner_engine(owner_url)
    owned = client is None
    http = client if client is not None else httpx.Client(trust_env=False, timeout=30.0)
    try:
        found = _existing(engine, tenant)
        if found is not None:
            raise QuickstartError(
                "This database already holds the tenant this installation names "
                f"({found[0]}, {found[1]} principals). Quickstart changed nothing. "
                "Administer it with the commands in docs/INSTALL.md, or start a fresh "
                "database with `docker compose down -v`."
            )
        lifetime = timedelta(days=credential_days)
        admin.create_tenant(engine, name, tenant_id=tenant)
        administrator = admin.create_principal(engine, tenant, "ADMIN")
        issued = admin.issue_credential(
            engine,
            tenant,
            administrator,
            administrator,
            lifetime=lifetime,
            output=state / ADMIN_FILE,
        )
        say(2, f"Tenant created, and its first administrator's credential is {issued.output}.")

        # The scheduled jobs get an administrator of their own, as the hosted deployment's do:
        # the one credential whose job is to run unattended is not the one a person signs in
        # with. The token is moved into the map the jobs service reads and the single-token
        # file removed, so one token is in one place.
        jobs = admin.create_principal(engine, tenant, "ADMIN", administrator)
        admin.issue_credential(
            engine, tenant, jobs, administrator, lifetime=lifetime, output=state / JOBS_TOKEN_FILE
        )
        jobs_token = _token(state / JOBS_TOKEN_FILE)
        _write_private(state / JOBS_FILE, {str(tenant): jobs_token})
        _write_private(state / MONITOR_FILE, {"admin_token": jobs_token})
        (state / JOBS_TOKEN_FILE).unlink()
        say(3, f"The jobs service has an administrator of its own in {state / JOBS_FILE}.")

        for provider, account in (
            (ENDPOINT_PROVIDER, endpoint_account),
            (IDENTITY_PROVIDER, identity_account),
        ):
            admin.create_account(engine, tenant, provider, administrator, account_id=account)
        admin.create_mapping(engine, tenant, endpoint_account, ACTION, administrator)
        say(4, "Both mock providers are connector accounts, and isolation is mapped.")

        inventory = provisioning.create_context_source(
            engine, tenant, endpoint_account, "inventory", ["inventory_sync"], administrator
        )
        incident_source = provisioning.create_context_source(
            engine, tenant, endpoint_account, "incident", ["soc_analyst"], administrator
        )
        targets: dict[str, UUID] = {}
        for provider_id, hostname, criticality, _reference, _version in ENDPOINTS:
            created = admin.create_resource(
                engine,
                tenant,
                endpoint_account,
                "endpoint",
                provider_id,
                inventory,
                administrator,
                version=RESOURCE_VERSION,
                hostname=hostname,
                facts={
                    "role": "workstation",
                    "environment": "development",
                    "criticality": criticality,
                },
            )
            targets[provider_id] = created.canonical_target_id
        say(5, "Two endpoints registered: " + ", ".join(item[1] for item in ENDPOINTS) + ".")

        # The provider holds its own view of a target, as a vendor would, and a dispatch
        # whose target the provider never heard of has nothing to act on. This is the same
        # provisioning `boot.py` performs from a variable at a mock's start.
        store = MockStore(providers / "endpoint.sqlite3")
        for provider_id, _hostname, _criticality, _reference, _version in ENDPOINTS:
            store.provision_resource(tenant, targets[provider_id], RESOURCE_VERSION)
            store.provision_representation(
                tenant, endpoint_account, provider_id, targets[provider_id]
            )
        incidents = {item[0]: str(uuid4()) for item in ENDPOINTS}
        parsed = provisioning.parse_manifest(
            _manifest(tenant, endpoint_account, incident_source, datetime.now(UTC), incidents)
        )
        provisioning.import_manifest(engine, tenant, parsed, administrator, strict=True)
        say(6, "The provider holds both targets, and each has an open critical incident.")

        mappings = tuple(
            MappingRef(
                operation_ref=summary.operation_ref,
                account_id=summary.account_id,
                mapping_version=summary.mapping_version,
                schema_version="action.v1",
                context_contract_version=summary.context_contract_version,
            )
            for summary in admin.list_mappings(engine, tenant)
            if summary.active
        )
        bundle_id = uuid4()
        try:
            content = ruleset_bundle(
                ruleset,
                tenant_id=tenant,
                bundle_id=bundle_id,
                mappings=mappings,
                context_settings=ruleset.context,
            )
        except RulesetError as error:
            raise QuickstartError(f"The starter rules are invalid: {error}") from None
        # The bundle lifecycle belongs to an administrator over the restricted runtime
        # connection, never to the owner, and quickstart takes the same path a person would.
        db = Database(runtime_url, pool_size=1, max_overflow=0)
        try:
            identity = authenticate(db, _token(issued.output))
            create_bundle(db, identity, content)
            validate_bundle(db, identity, bundle_id)
            activate_bundle(db, identity, bundle_id)
        finally:
            db.close()
        say(
            7,
            f"The starter policy is active: {len(ruleset.rules)} rules over {ACTION}, "
            f"{len(ruleset.budgets)} budgets.",
        )

        agent = admin.create_principal(engine, tenant, "AGENT", administrator)
        agent_issued = admin.issue_credential(
            engine, tenant, agent, administrator, lifetime=lifetime, output=state / AGENT_FILE
        )
        say(8, f"An agent has a credential of its own in {agent_issued.output}.")

        _wait_for_gateway(http, gateway, host, seconds=ready_seconds)
        agent_token = _token(agent_issued.output)
        decisions = []
        for provider_id, hostname, _criticality, reference, _version in ENDPOINTS:
            answer = _execute(
                http,
                gateway,
                host,
                agent_token,
                {
                    "operation_ref": ACTION,
                    "target": {"kind": "hostname", "value": hostname},
                    "arguments": {},
                    "reference": reference,
                    "claimed_context": {"incident_id": incidents[provider_id]},
                },
            )
            decisions.append(
                Decision(reference, hostname, str(answer["state"]), str(answer["execution_id"]))
            )
        say(9, "Two requests governed.")
        outcome = Outcome(
            tenant_id=tenant,
            admin_principal_id=administrator,
            agent_principal_id=agent,
            bundle_id=bundle_id,
            decisions=tuple(decisions),
            admin_token_file=issued.output,
            agent_token_file=agent_issued.output,
            jobs_file=state / JOBS_FILE,
            # The administrator's token is a setup credential, and the sign-in page offers a field
            # for one only when it is asked for: plain `/login` shows an address and a password.
            console=f"{origin}/login?setup=1",
        )
        report(outcome, output=output)
        return outcome
    finally:
        engine.dispose()
        if owned:
            http.close()


def report(outcome: Outcome, *, output: TextIO) -> None:
    """What was decided, where the credential is, and where to sign in. Never a token."""
    output.write("\nThe installation has governed its first actions.\n\n")
    for decision in outcome.decisions:
        output.write(
            f"  {decision.hostname:<16} {decision.state:<9} {decision.reference}  "
            f"execution {decision.execution_id}\n"
        )
    # The paths are this container's. The directory they are in is mounted from the host, so
    # say both: an installer who is told `/srv/state/admin.token` and has no container open
    # cannot find the file they have to sign in with.
    state = outcome.admin_token_file.parent.name
    output.write(
        "\nThe second is refused although it satisfies every condition of the allow rule: it\n"
        "is criticality 4, and a denial wins over a permit. Both are in the audit chain.\n\n"
        f"Sign in at {outcome.console} with the contents of "
        f"{state}/{outcome.admin_token_file.name},\n"
        f"in the directory you installed into. The agent's credential is "
        f"{state}/{outcome.agent_token_file.name}\n"
        f"and the scheduled jobs use {state}/{outcome.jobs_file.name}. All of them expire;\n"
        "docs/INSTALL.md says how to issue another.\n"
    )
