# SPDX-License-Identifier: AGPL-3.0-only
"""Private, explicit file configuration; never inferred from an agent request."""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import Field, SecretStr, model_validator

from execbound import microsoft
from execbound.arcade.map import ArcadeBlock
from execbound.assistant.config import DEFAULT_BASE_URL, DEFAULT_MODEL, AssistantConfig
from execbound.db import Database
from execbound.directory import DirectoryConfig
from execbound.envelope import ring_from
from execbound.execution.models import PreconditionClass, PreconditionConfig
from execbound.github import GitHubProvider
from execbound.logging_schema import log_event
from execbound.monitoring.sealing import CollectorPublicKey, read_public_key
from execbound.notifications import Destination
from execbound.oidc import GoogleProvider, JwksCache
from execbound.operations import ProviderName, ProviderOperation
from execbound.plugins import load_plugins
from execbound.provider.checkpoint_evidence import CheckpointProvider
from execbound.provider.connector import ConnectionConfig, Connector, MockConnector
from execbound.provider.graph import GraphCredential
from execbound.provider.graph_connector import GraphConnectionConfig, GraphConnector
from execbound.provider.models import GRAPH_PROVIDER
from execbound.provider.sample_accounts import SampleProvider, parse_sample_key
from execbound.requests import StrictModel, _unique_object
from execbound.runtime import Runtime
from execbound.service_links import SOURCE_URL, ServiceLinks
from execbound.signin import ProviderConfig, SignInProvider
from execbound.surfaces.human import HumanConfig, ScoutConfig, ScoutEntra
from execbound.surfaces.limits import RequestLimits
from execbound.surfaces.tokens import TokenKeys
from execbound.transports import MailConfig


class _Connector(StrictModel):
    tenant_id: UUID
    account_id: UUID
    provider: ProviderName = "mock_crowdstrike"
    origin: str
    dispatch_token: SecretStr
    control_token: SecretStr
    evidence_keys: dict[str, SecretStr]
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)


class _GraphConnector(StrictModel):
    """A Microsoft Graph connection, which shares no shape with the one above.

    There is no origin and no bearer token: the origin is pinned in source so no operator
    can move it, and the credential is one app registration that may disable a user. The
    key ring signs and verifies ExecBound's own record of the exchange, and never
    authenticates anything to Microsoft.
    """

    tenant_id: UUID
    account_id: UUID
    provider: Literal["graph"] = "graph"
    directory: str = Field(min_length=1, max_length=64)
    client_id: str = Field(min_length=1, max_length=64)
    client_secret: SecretStr
    signing_key_id: str = Field(min_length=1, max_length=64)
    evidence_keys: dict[str, SecretStr]


class _CheckpointProvider(StrictModel):
    """A Gate account's provider journal key: verification only, no URL and no token."""

    tenant_id: UUID
    account_id: UUID
    provider: Literal["mock_crowdstrike", "mock_entra"] = "mock_crowdstrike"
    evidence_keys: dict[str, SecretStr]


class _SampleProvider(StrictModel):
    """A mock that accepts derived sample accounts (#420).

    The origin is the only destination any sample connection of this provider may reach, and
    the key derives every sample account's tokens and journal key; nothing per workspace is
    configured. The key is 32 to 128 bytes of lower-case hex, the same value the endpoint mock
    reads from `EXECBOUND_MOCK_SAMPLE_KEY`.
    """

    origin: str
    sample_key: SecretStr
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)


class _Notification(StrictModel):
    destination_id: str
    tenant_id: UUID
    kind: Literal["webhook", "security-events", "email", "slack", "teams"] = "webhook"
    # A signed endpoint's or a chat webhook's URL; `Destination` validates it. A chat URL
    # is itself the secret, so none is ever logged or rendered.
    url: SecretStr | None = None
    secret: SecretStr | None = None
    # An email destination's one bare address; operator configuration, never tenant data.
    to: str | None = None
    approvers: tuple[UUID, ...] | None = None
    # Which approval messages the destination receives (#678): `pending` announces a held
    # request, `reminder` reminds once before it lapses, `closed` reports how it ended. Absent
    # means `["pending"]`, what every destination always received, so an existing file's
    # behaviour and shape are unchanged.
    messages: tuple[Literal["pending", "reminder", "closed"], ...] | None = None

    @model_validator(mode="after")
    def fields_for_kind(self) -> Self:
        """Each kind carries exactly its own fields, so a file cannot half-describe one."""
        signed = self.kind in {"webhook", "security-events"}
        posted = signed or self.kind in {"slack", "teams"}
        if posted != (self.url is not None) or signed != (self.secret is not None):
            raise ValueError("Invalid notification destination")
        if (self.kind == "email") != (self.to is not None):
            raise ValueError("Invalid notification destination")
        return self

    @model_validator(mode="after")
    def messages_listed_once(self) -> Self:
        """A non-empty list without repeats, where a close-out follows a message received.

        The audit export announces no approval, so it takes no list at all.
        """
        if self.messages is None:
            return self
        chosen = set(self.messages)
        if (
            self.kind == "security-events"
            or not self.messages
            or len(chosen) != len(self.messages)
            or ("closed" in chosen and not chosen & {"pending", "reminder"})
        ):
            raise ValueError("Invalid notification destination")
        return self


class _Mail(StrictModel):
    """The deployment's SMTP relay; `MailConfig` validates the values."""

    host: str
    port: int
    tls: Literal["tls", "starttls"]
    username: str
    password: SecretStr
    sender: str = Field(alias="from")
    daily_limit: int = Field(default=500, ge=1, le=100_000)
    # The weekly summary (#678): offered only where it is on, and a deployment-wide daily
    # ceiling so a Monday cannot spend the relay's whole day.
    weekly_summary: bool = False
    weekly_summary_daily_cap: int = Field(default=200, ge=1, le=100_000)


class _Precondition(StrictModel):
    """One operator declaration of a binding's class; see ``PreconditionConfig`` for why."""

    provider: ProviderName
    provider_operation: ProviderOperation
    precondition_class: PreconditionClass


class _Limits(StrictModel):
    agent_requests: int = 300
    agent_window_seconds: int = 60
    login_attempts: int = 10
    login_window_seconds: int = 60
    client_requests: int = 1000
    client_window_seconds: int = 60
    token_requests: int = 300
    token_window_seconds: int = 60
    max_tracked_keys: int = 10000


class _Telemetry(StrictModel):
    """Whether this deployment would send ExecBound one weekly usage report.

    Off unless an operator turns it on (#411),
    and deployment-wide rather than per tenant, which is why it lives here beside the
    connectors. `execbound init` asks the question once and writes the answer.

    **Nothing in this repository reads it yet.** No report is composed, no schedule exists and
    no endpoint receives one. The block exists so that the answer an installer gave is
    recorded where the decision lives rather than lost, and so a file carrying it is accepted
    rather than refused at start.
    """

    enabled: bool = False


class _Console(StrictModel):
    """What the console's flag used to be (#333).

    The console is the console now: it answers the product's own paths, is not optional, and
    has no flag. The block is still accepted, and ignored, because a deployment's private
    configuration file is edited by a person on a different schedule from a deploy: refusing
    it would mean a gateway that will not start until someone edits the file, in the middle
    of the release that makes the console the only console there is. `read_configuration`
    says so in a structured event, so the block can be removed at leisure and its removal is
    the only thing that stops the line appearing.
    """

    enabled: bool = False


class _Assistant(StrictModel):
    """The console assistant (#330).

    Present, the feature exists and each tenant's ADMIN turns it on; absent, it does not
    exist. The key arrives as `EXECBOUND_ASSISTANT_API_KEY`, merged in by `boot.py` the way
    the mail password is, never written in the file beside the caps.
    """

    api_key: SecretStr
    model: str = Field(default=DEFAULT_MODEL, min_length=1, max_length=80)
    base_url: str = Field(default=DEFAULT_BASE_URL, max_length=200)
    tenant_daily_tokens: int = Field(default=200_000, ge=1_000, le=50_000_000)
    person_hourly_turns: int = Field(default=20, ge=1, le=1_000)
    effort: Literal["low", "medium", "high"] = "low"


class _Provider(StrictModel):
    """The three values a deployment supplies for one sign-in provider.

    Everything that chooses a host is pinned in that provider's own module, so nothing in a
    file can move a flow. The secret arrives as `EXECBOUND_GOOGLE_CLIENT_SECRET`,
    `EXECBOUND_GITHUB_CLIENT_SECRET` or `EXECBOUND_MICROSOFT_CLIENT_SECRET`, merged in by
    `boot.py` the way the mail password is: in the environment or in the file, never both.
    """

    client_id: str = Field(min_length=1, max_length=256)
    client_secret: SecretStr
    redirect_uri: str = Field(min_length=1, max_length=512)


class _DirectoryKeys(StrictModel):
    """The ring a customer's own identity provider's client secret is sealed under (#177).

    A tenant's provider is a row, registered from the console by that tenant's administrator,
    so its client secret cannot be an environment variable the way Google's is: there is no
    restart to put one in and no operator in the loop. It is a column, sealed with AES-256-GCM
    under one of these keys, and a deployment given no ring can hold no tenant's secret at all,
    registers no provider and says so on the page rather than offering a form that cannot work.

    Rotation is a restart, not a reload: these keys open data at rest rather than signing a
    token, so `shape()` names them and a file that changes one is refused as a configuration
    change. A retired key stays in the ring and every row it sealed keeps opening; a row is
    rewritten under the active key the next time it is written.
    """

    active_key_id: str = Field(min_length=1, max_length=64)
    keys: dict[str, SecretStr]


class _SignIn(StrictModel):
    """Sign-in methods beyond the credential form. A provider with no block here serves no
    route and shows no button, so a deployment offers exactly what it was given."""

    google: _Provider | None = None
    github: _Provider | None = None
    # Microsoft work accounts through the multi-tenant `organizations` authority: a sign-in
    # method like Google, never a workspace's own directory (`execbound.microsoft`).
    microsoft: _Provider | None = None
    directory: _DirectoryKeys | None = None

    def blocks(self) -> tuple[tuple[str, "_Provider"], ...]:
        return tuple(
            (name, block)
            for name, block in (
                ("google", self.google),
                ("github", self.github),
                ("microsoft", self.microsoft),
            )
            if block is not None
        )


class _Service(StrictModel):
    """Where this deployment sends people for help (`execbound.service_links`).

    Each field is optional, and a link with no address is not shown: the footers' Help,
    Privacy and Terms (and Status in the console), "Forgot your password or lost access?" on
    the sign-in page, "Get account help" on the MFA pages, the console's Help page and My
    account, and the guidance link on Workspace settings' requests card. A loaded plugin may
    register these instead; both at once refuses start (`LoadedPlugins.service`).

    `source_url`, the footers' Source link, is the one with a default: the public repository,
    kept when the block leaves it out. A deployment running changed code names its own copy,
    and `null` turns the link off. `operator` names who runs the deployment, the footers'
    copyright holder; left out, the footers read "Powered by ExecBound".
    """

    support_email: str | None = None
    help_url: str | None = None
    status_url: str | None = None
    privacy_url: str | None = None
    terms_url: str | None = None
    plans_url: str | None = None
    security_url: str | None = None
    privacy_requests_url: str | None = None
    source_url: str | None = SOURCE_URL
    operator: str | None = None

    @model_validator(mode="after")
    def links_are_valid(self) -> Self:
        self.links()
        return self

    def links(self) -> ServiceLinks:
        return ServiceLinks(**self.model_dump())


class _ScoutCollector(StrictModel):
    """The monitoring collector's public key and its id, as `collector-keygen` writes them to
    `collector-public.json` (#678).

    With it, an administrator may connect Tines from the console: the gateway seals the pasted
    key to this public key and only the collector's private key, which never comes near this
    file, opens it. The id is the public key's own digest, so a block whose id does not match
    its key is refused here, naming the field and never the value.
    """

    key_id: str = Field(min_length=1, max_length=40)
    public_key: str = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def a_collector_key(self) -> Self:
        self.public()
        return self

    def public(self) -> CollectorPublicKey:
        return read_public_key({"key_id": self.key_id, "public_key": self.public_key})


# A directory or app id as Microsoft writes one, in one spelling.
_GUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
# Characters a page could read as markup; a name that holds one is refused, not escaped.
_MARKUP = frozenset("<>&")


class _ScoutEntra(StrictModel):
    """The platform app a directory administrator consents to, so Microsoft Entra can be
    connected from the console (#678): its client id, the authority its sign-in uses, and the
    name an administrator sees for it under Enterprise applications, which the console names
    when it tells them how to withdraw consent. `authority` is `organizations` for an app any
    directory may consent to, or one directory's id for a single-tenant registration; the
    personal-account authorities cannot consent for a directory. Every value is public: the
    app's certificate lives in the collector's environment alone.
    """

    client_id: str = Field(pattern=f"^{_GUID}$")
    authority: str = Field(pattern=f"^(organizations|{_GUID})$")
    display_name: str = Field(min_length=1, max_length=96)

    @model_validator(mode="after")
    def a_plain_name(self) -> Self:
        name = self.display_name
        if not name.strip() or not name.isprintable() or _MARKUP & set(name):
            raise ValueError("display_name must be plain printable text")
        return self

    def public(self) -> ScoutEntra:
        return ScoutEntra(self.client_id.lower(), self.authority.lower(), self.display_name)


class _Scout(StrictModel):
    """Monitoring connected from the console (#678). Every value is public; absent, console
    connect is not configured and the console says so, which is never an error. `entra` is
    accepted only beside `collector`, because a consented directory is read by the collector
    alone."""

    collector: _ScoutCollector | None = None
    entra: _ScoutEntra | None = None

    @model_validator(mode="after")
    def entra_beside_the_collector(self) -> Self:
        if self.entra is not None and self.collector is None:
            raise ValueError("entra needs collector")
        return self


class _Configuration(StrictModel):
    origin: str
    active_key_id: str
    continuation_keys: dict[str, SecretStr]
    connectors: tuple[_Connector, ...] = Field(default=(), max_length=64)
    graph_connectors: tuple[_GraphConnector, ...] = Field(default=(), max_length=64)
    # The journal keys Gate accounts' providers sign with. Never a connector: the gateway
    # holds no URL or token for these and calls none of them.
    checkpoint_providers: tuple[_CheckpointProvider, ...] = Field(default=(), max_length=64)
    # Sample targets (#420): keyed by provider, and only the endpoint mock in this unit.
    sample_providers: dict[Literal["mock_crowdstrike"], _SampleProvider] = Field(
        default_factory=dict, max_length=1
    )
    limits: _Limits | None = None
    notifications: tuple[_Notification, ...] = Field(default=(), max_length=64)
    mail: _Mail | None = None
    preconditions: tuple[_Precondition, ...] = Field(default=(), max_length=64)
    # Accepted and ignored since the switch; see `_Console`.
    console: _Console | None = None
    # Recorded and not yet read; see `_Telemetry`.
    telemetry: _Telemetry | None = None
    assistant: _Assistant | None = None
    sign_in: _SignIn | None = None
    mfa: _DirectoryKeys | None = None
    arcade: ArcadeBlock | None = None
    # The deployment's support address and public pages; see `_Service`.
    service: _Service | None = None
    # Monitoring connected from the console: the collector's public key; see `_Scout`.
    scout: _Scout | None = None
    # First-party plugins this gateway loads, each with its own section, which the plugin
    # validates with its own strict model (#238, #496). Absent, none loads.
    plugins: dict[str, dict[str, Any]] = Field(default_factory=dict, max_length=8)
    # Seconds between checks of this file for rotated keys; 0 disables the reload.
    key_reload_seconds: int = Field(default=0, ge=0, le=3600)

    @model_validator(mode="after")
    def dispatches_or_governs(self) -> Self:
        """A deployment declares a connector unless it is one that dispatches nothing.

        The minimum of one connector is what says a gateway was configured to reach a
        provider rather than left half-written. An Arcade deployment executes through the
        control point and holds no connector account of its own, so it has none to declare;
        nor does a Gate deployment whose providers' journal keys are its whole provider
        configuration. A file carrying none of the three is still refused here.
        """
        # A deployment whose only providers are sample mocks dispatches to them, so its sample
        # block is a provider configuration too (#420).
        if (
            not self.connectors
            and not self.graph_connectors
            and not self.checkpoint_providers
            and not self.sample_providers
            and self.arcade is None
        ):
            raise ValueError(
                "A deployment with no connectors declares an arcade or checkpoint providers"
            )
        return self

    @model_validator(mode="after")
    def journal_keys_name_gate_accounts(self) -> Self:
        """A journal key names an account the deployment does not dispatch through."""
        gate = [(p.tenant_id, p.account_id) for p in self.checkpoint_providers]
        dispatch = {(c.tenant_id, c.account_id) for c in self.connectors} | {
            (g.tenant_id, g.account_id) for g in self.graph_connectors
        }
        if len(set(gate)) != len(gate) or set(gate) & dispatch:
            raise ValueError("A checkpoint provider names one Gate account")
        return self

    @model_validator(mode="after")
    def graph_is_declared_for_what_it_proves(self) -> Self:
        """A Graph connection's binding must be declared CHECKED_BY_CONNECTOR.

        Not a matter of taste. The connector always measures a window, and migration
        `0032`'s CHECK admits one only on a row whose class is CHECKED_BY_CONNECTOR, so a
        deployment that declared anything else — or, just as easily, declared nothing and
        took the UNAVAILABLE default — would perform the vendor write and then fail to
        settle it, leaving every Graph execution uncertain after the mutation had already
        landed. Refusing the file is the only place that can be caught before a write.

        It is also true on its own terms: Graph offers no conditional write for a user
        object, so ENFORCED_BY_PROVIDER for one of its bindings is a claim the vendor does
        not support, whoever writes it in.
        """
        if self.graph_connectors:
            checked = {
                (p.provider, p.provider_operation)
                for p in self.preconditions
                if p.precondition_class == "CHECKED_BY_CONNECTOR"
            }
            if (GRAPH_PROVIDER, "disable") not in checked:
                raise ValueError("A Graph connection declares its binding CHECKED_BY_CONNECTOR")
        return self

    @model_validator(mode="after")
    def a_provider_redirects_to_this_deployment(self) -> Self:
        """A provider block may only send a browser back to this deployment's own callback.

        The redirect URI is the one value in a block a person could point somewhere else,
        and an authorization code delivered to somebody else's server is the whole of the
        attack. Refusing the file is the only place that can be caught before a sign-in.
        """
        for name, block in self.sign_in.blocks() if self.sign_in is not None else ():
            configured = ProviderConfig(
                block.client_id, block.client_secret.get_secret_value(), block.redirect_uri
            )
            configured.check(name)
            if not configured.belongs_to(self.origin, name):
                raise ValueError("A sign-in redirect URI belongs to this deployment's origin")
        return self

    @model_validator(mode="after")
    def mail_for_email(self) -> Self:
        """An email destination with nowhere to send from is a half-written file."""
        if self.mail is None and any(n.kind == "email" for n in self.notifications):
            raise ValueError("An email destination needs the mail block")
        return self

    def shape(self) -> tuple[object, ...]:
        """Everything a reload may not change; only the key rings rotate at runtime."""
        return (
            self.origin,
            self.limits,
            self.key_reload_seconds,
            tuple(
                (
                    str(n.tenant_id),
                    n.destination_id,
                    n.kind,
                    n.url.get_secret_value() if n.url is not None else None,
                    n.secret.get_secret_value() if n.secret is not None else None,
                    n.to,
                    n.approvers,
                    n.messages,
                )
                for n in self.notifications
            ),
            (
                None
                if self.mail is None
                else (
                    self.mail.host,
                    self.mail.port,
                    self.mail.tls,
                    self.mail.username,
                    self.mail.password.get_secret_value(),
                    self.mail.sender,
                    self.mail.daily_limit,
                )
            ),
            tuple(
                sorted(
                    (p.provider, p.provider_operation, p.precondition_class)
                    for p in self.preconditions
                )
            ),
            tuple(
                sorted(
                    (
                        str(c.tenant_id),
                        str(c.account_id),
                        c.provider,
                        c.origin,
                        c.dispatch_token.get_secret_value(),
                        c.control_token.get_secret_value(),
                        c.timeout_seconds,
                    )
                    for c in self.connectors
                )
            ),
            tuple(
                sorted(
                    (
                        str(c.tenant_id),
                        str(c.account_id),
                        c.provider,
                        c.directory,
                        c.client_id,
                        c.client_secret.get_secret_value(),
                        c.signing_key_id,
                    )
                    for c in self.graph_connectors
                )
            ),
            # The checkpoint journal keys are read once, when the runtime is built, and no
            # rotation carries them, so a file that changes them is a restart rather than a
            # reload that would report a rotation nothing applied.
            tuple(
                sorted(
                    (
                        str(p.tenant_id),
                        str(p.account_id),
                        p.provider,
                        tuple(
                            sorted((k, v.get_secret_value()) for k, v in p.evidence_keys.items())
                        ),
                    )
                    for p in self.checkpoint_providers
                )
            ),
            # A sample key derives every workspace's sample connection, so changing one is a
            # restart that cuts every sample connection at once, never a reload (#420).
            tuple(
                sorted(
                    (
                        name,
                        entry.origin,
                        entry.sample_key.get_secret_value(),
                        entry.timeout_seconds,
                    )
                    for name, entry in self.sample_providers.items()
                )
            ),
            # The tool map governs like the precondition classes above it, and a deployment
            # reads it once when it loads this file, so a file that changes it is not a key
            # rotation: the running deployment would either change its map under itself or
            # be told a change took effect that nothing read. A restart beats both.
            self.arcade,
            # The sign-in blocks choose who may sign in and where a browser comes back
            # to. A reload that changed one would change a flow under a browser mid-way, so
            # they belong with the shape a restart is the path for.
            tuple(
                (
                    name,
                    block.client_id,
                    block.client_secret.get_secret_value(),
                    block.redirect_uri,
                )
                for name, block in (self.sign_in.blocks() if self.sign_in is not None else ())
            ),
            # The directory ring opens data at rest rather than signing a token, so changing
            # it is not a rotation a running deployment can absorb: rows sealed under a key
            # that left the ring would stop opening with nothing to say why. A restart is the
            # path, and naming it here is what makes a reload refuse instead of reporting a
            # rotation nothing read.
            None
            if self.sign_in is None or self.sign_in.directory is None
            else (
                self.sign_in.directory.active_key_id,
                tuple(
                    sorted(
                        (name, value.get_secret_value())
                        for name, value in self.sign_in.directory.keys.items()
                    )
                ),
            ),
            None
            if self.mfa is None
            else (
                self.mfa.active_key_id,
                tuple(
                    sorted(
                        (name, value.get_secret_value()) for name, value in self.mfa.keys.items()
                    )
                ),
            ),
            # The pages read the links once, when the human surface is built, so a changed
            # block is a restart rather than a reload that reports a change nothing applied.
            self.service,
            # The collector key the console seals to is read once, too; a new one is a restart
            # beside `collector-reseal`, never a reload.
            self.scout,
            json.dumps(self.plugins, sort_keys=True),
        )

    def rings(self) -> tuple[TokenKeys, dict[tuple[UUID, UUID], dict[str, bytes]]]:
        keys = TokenKeys(
            self.active_key_id,
            {
                name: bytes.fromhex(value.get_secret_value())
                for name, value in self.continuation_keys.items()
            },
        )
        evidence = {
            (c.tenant_id, c.account_id): {
                name: bytes.fromhex(value.get_secret_value())
                for name, value in c.evidence_keys.items()
            }
            for c in self.connectors
        }
        evidence.update(
            {
                (c.tenant_id, c.account_id): {
                    name: bytes.fromhex(value.get_secret_value())
                    for name, value in c.evidence_keys.items()
                }
                for c in self.graph_connectors
            }
        )
        return keys, evidence


@dataclass(frozen=True)
class KeyReload:
    """Outcome of the last reload check; never carries a key or a diagnostic string."""

    state: Literal["current", "refused", "failed", "disabled"]
    code: str | None = None
    rotated: bool = False
    configuration: "_Configuration | None" = field(default=None, repr=False)


def _assistant_config(block: _Assistant) -> AssistantConfig:
    return AssistantConfig(
        api_key=block.api_key.get_secret_value(),
        model=block.model,
        base_url=block.base_url,
        tenant_daily_tokens=block.tenant_daily_tokens,
        person_hourly_turns=block.person_hourly_turns,
        effort=block.effort,
    )


def _mail_config(block: _Mail) -> MailConfig:
    return MailConfig(
        host=block.host,
        port=block.port,
        tls=block.tls,
        username=block.username,
        password=block.password.get_secret_value(),
        sender=block.sender,
        daily_limit=block.daily_limit,
        weekly_summary=block.weekly_summary,
        weekly_summary_daily_cap=block.weekly_summary_daily_cap,
    )


MAX_MAIL_FILE_BYTES = 16384


def load_mail(path: Path, environment: Mapping[str, str]) -> MailConfig:
    """A `mail` block from its own file, for owner tooling that sends from a workstation.

    The password sits in the file or arrives as `EXECBOUND_MAIL_PASSWORD`, never both, the
    same rule `boot.py` applies to the gateway's configuration. Every refusal is the same
    opaque error, quoting nothing from the file.
    """
    raw = path.read_bytes()
    if not 0 < len(raw) <= MAX_MAIL_FILE_BYTES:
        raise ValueError("Invalid mail configuration")
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(document, dict):
        raise ValueError("Invalid mail configuration")
    password = environment.get("EXECBOUND_MAIL_PASSWORD") or None
    if password is not None:
        if "password" in document:
            raise ValueError("Invalid mail configuration")
        document = document | {"password": password}
    return _mail_config(_Mail.model_validate_json(json.dumps(document)))


def sign_in_providers(block: "_SignIn | None") -> tuple[SignInProvider, ...]:
    """One provider per configured block, in a fixed order, and none at all without one.

    A provider absent from the file serves no route and shows no button; there is nothing to
    switch on at runtime, because the absence is the switch.
    """
    built: list[SignInProvider] = []
    for name, entry in block.blocks() if block is not None else ():
        configured = ProviderConfig(
            entry.client_id, entry.client_secret.get_secret_value(), entry.redirect_uri
        )
        configured.check(name)
        if name == "google":
            built.append(GoogleProvider(configured, JwksCache()))
        elif name == "github":
            built.append(GitHubProvider(configured))
        else:
            built.append(microsoft.MicrosoftProvider(configured, microsoft.keys()))
    return tuple(built)


def directory_config(block: "_SignIn | None", origin: str) -> DirectoryConfig | None:
    """The deployment's directory settings, or None when it was given no key ring.

    The redirect URI is derived from this deployment's own origin and is the same string for
    every tenant, which is what lets a runbook print it and a customer paste it once.
    """
    if block is None or block.directory is None:
        return None
    return DirectoryConfig(ring_from(block.directory), origin)


def read_configuration(path: Path) -> _Configuration:
    raw = path.read_bytes()
    if not 0 < len(raw) <= 65536:
        raise ValueError
    json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    config = _Configuration.model_validate_json(raw)
    if config.console is not None:
        # Tolerated, not honoured: the console is served whatever this says (#333).
        log_event("configuration.ignored_block", block="console")
    return config


def reload_keys(
    path: Path, runtime: Runtime, human: HumanConfig, baseline: _Configuration
) -> KeyReload:
    """Rotate the key rings from the private file when only they changed.

    A file that changes anything else, or that cannot be read or validated, leaves the
    running keys untouched and reports why; a restart is the path for those changes.
    """
    try:
        config = read_configuration(path)
    except (OSError, ValueError, RecursionError):
        log_event("keys.reloaded", level="ERROR", key_state="failed", code="INVALID_CONFIGURATION")
        return KeyReload("failed", "INVALID_CONFIGURATION", configuration=baseline)
    if config == baseline:
        return KeyReload("current", configuration=baseline)
    if config.shape() != baseline.shape():
        return KeyReload("refused", "CONFIGURATION_CHANGED", configuration=baseline)
    try:
        keys, evidence = config.rings()
        runtime.rotate(keys, evidence)
    except ValueError:
        return KeyReload("refused", "INVALID_KEYS", configuration=baseline)
    human.rotate(keys)
    log_event("keys.reloaded", key_state="current")
    return KeyReload("current", rotated=True, configuration=config)


def load_runtime(path: Path, db: Database) -> tuple[Runtime, HumanConfig]:
    connectors: list[Connector] = []
    try:
        config = read_configuration(path)
        keys, _ = config.rings()
        for item in config.connectors:
            connection = ConnectionConfig(
                item.tenant_id,
                item.account_id,
                item.origin,
                item.dispatch_token.get_secret_value(),
                item.control_token.get_secret_value(),
                {
                    name: bytes.fromhex(value.get_secret_value())
                    for name, value in item.evidence_keys.items()
                },
                item.timeout_seconds,
                provider=item.provider,
            )
            connectors.append(MockConnector(connection))
        for graph in config.graph_connectors:
            connectors.append(
                GraphConnector(
                    GraphConnectionConfig(
                        graph.tenant_id,
                        graph.account_id,
                        GraphCredential(
                            graph.directory,
                            graph.client_id,
                            graph.client_secret.get_secret_value(),
                        ),
                        {
                            name: bytes.fromhex(value.get_secret_value())
                            for name, value in graph.evidence_keys.items()
                        },
                        graph.signing_key_id,
                    )
                )
            )
        limits = RequestLimits(**config.limits.model_dump()) if config.limits else None
        destinations = [
            Destination(
                n.destination_id,
                n.tenant_id,
                n.url.get_secret_value() if n.url is not None else "",
                n.secret.get_secret_value() if n.secret is not None else "",
                frozenset(n.approvers) if n.approvers is not None else None,
                kind=n.kind,
                to=n.to,
                messages=frozenset(n.messages or ("pending",)),
            )
            for n in config.notifications
        ]
        mail = _mail_config(config.mail) if config.mail is not None else None
        assistant = _assistant_config(config.assistant) if config.assistant is not None else None
        if len({(d.tenant_id, d.destination_id) for d in destinations}) != len(destinations):
            raise ValueError
        preconditions = PreconditionConfig(
            {(p.provider, p.provider_operation): p.precondition_class for p in config.preconditions}
        )
        # A declaration naming a binding the catalog does not bind is refused by Runtime
        # construction below, the one place that holds the catalog; both arrive as the
        # same opaque failure, with no diagnostic quoting the file.
        if len(preconditions.classes) != len(config.preconditions):
            raise ValueError
        checkpoint_providers = [
            CheckpointProvider(
                p.tenant_id,
                p.account_id,
                p.provider,
                {k: bytes.fromhex(v.get_secret_value()) for k, v in p.evidence_keys.items()},
            )
            for p in config.checkpoint_providers
        ]
        # Refused as a whole file like any other invalid block; the refusal's code is logged
        # by the loader as `plugins.refused`, never a value from the file.
        plugins = load_plugins(config.plugins)
        # Built once the plugins have loaded, because a plugin may give the service links;
        # a `service` block beside a plugin's links refuses the whole file.
        human = HumanConfig(
            config.origin,
            keys,
            assistant_enabled=config.assistant is not None,
            providers=sign_in_providers(config.sign_in),
            directory=directory_config(config.sign_in, config.origin),
            mfa=ring_from(config.mfa) if config.mfa is not None else None,
            service=plugins.service(config.service.links() if config.service is not None else None),
            scout=(
                ScoutConfig(
                    collector=config.scout.collector.public(),
                    entra=config.scout.entra.public() if config.scout.entra is not None else None,
                )
                if config.scout is not None and config.scout.collector is not None
                else None
            ),
        )
        samples = [
            SampleProvider(
                name,
                entry.origin,
                parse_sample_key(entry.sample_key.get_secret_value()),
                entry.timeout_seconds,
            )
            for name, entry in config.sample_providers.items()
        ]
        runtime = Runtime(
            db,
            connectors,
            keys=keys,
            approval_url=config.origin + "/approvals",
            limits=limits,
            notifications=destinations,
            mail=mail,
            preconditions=preconditions,
            assistant=assistant,
            checkpoint_providers=checkpoint_providers,
            plugins=plugins,
            sample_providers=samples,
        )
        return runtime, human
    except (OSError, ValueError, RecursionError):
        for connector in connectors:
            connector.close()
    raise ValueError("Invalid runtime configuration")
