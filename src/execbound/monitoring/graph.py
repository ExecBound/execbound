# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit, bounded, read-only collection from Microsoft Graph.

One ``POST`` per run acquires a token from the pinned login origin; every other request is a
``GET`` to the pinned Graph origin, with redirects, ambient proxies and in-run retries
disabled and the body and time bounded. The token is a local value for the run and is never
persisted, logged or rendered.

An operator's own registration authenticates with its client secret, from the key file the
operator keeps. A directory an administrator consented to is read with the deployment's own app
(`PlatformApp`), which authenticates with a certificate instead: an RFC 7523 client assertion
signed RS256 with the certificate's key, naming the certificate by its SHA-256 thumbprint
(`x5t#S256`), for the token endpoint of the directory being read, living five minutes with a
fresh `jti`. Only the collector holds that credential.

Every response passes a field allowlist before anything is retained. ``agentIdentity`` is an
*open type* — the vendor may add properties at any time — so each parser is written as "take
these fields", never as "take the object minus these", and what it drops is counted. No human
display name, mail address, principal name, credential value or hint reaches memory beyond
the response buffer. Collection produces evidence: nothing here admits, approves, settles,
reserves or refunds, and no execution privilege is used.
"""

import base64
import hashlib
import ipaddress
import json
import re
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dotenv import dotenv_values
from execbound_connectors.graph import GRAPH_ORIGIN as GRAPH_ORIGIN
from execbound_connectors.graph import LOGIN_ORIGIN as LOGIN_ORIGIN

from execbound.db import Database
from execbound.execution.scheduled import ScheduledActor
from execbound.identity import Identity
from execbound.monitoring import activity_map, ai_publishers, drivers, egress, store
from execbound.monitoring.models import MonitorError
from execbound.resolution.models import Clock, SystemClock
from execbound.secrets import secret_shaped

MAX_BODY = 4 * 1024 * 1024
TIMEOUT = 10.0
PAGE_SIZE = 100
MAX_AGENTS = 1000
MAX_BLUEPRINTS = 200
MAX_GRANTS = 200
MAX_SPONSORS = 100
SYSTEM_CLOCK = SystemClock()

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
# A certificate credential's client assertion (RFC 7523), and how long one lives.
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ASSERTION_SECONDS = 300
MAX_APP_FILE = 16384
APP_FIELDS = frozenset({"client_id", "certificate_pem", "private_key_pem"})

AGENTS_PATH = "/v1.0/servicePrincipals/microsoft.graph.agentIdentity"
PRINCIPALS_PATH = "/v1.0/servicePrincipals"
# Changes to the directory's service principals between full collections (#355). A delta link is
# stored as the pinned origin, this path and the query Graph gave, and nothing else.
DELTA_LINK_PREFIX = store.DELTA_PREFIX
DELTA_PATH = urlsplit(DELTA_LINK_PREFIX).path
# One round's bounds: past either, the round is abandoned and the link dropped, and the next full
# collection reconciles the directory and takes a fresh link.
MAX_DELTA_PAGES = 20
MAX_DELTA_ENTRIES = 1000
# What a delta pass asks Graph to track and return: the allowlisted fields `servicePrincipal`
# itself defines. `createdDateTime` and `agentIdentityBlueprintId` belong to the `agentIdentity`
# type; naming a property the base type lacks risks a refusal that would end every delta pass,
# so those two are left to the full collection.
DELTA_FIELDS = (
    "id",
    "displayName",
    "accountEnabled",
    "servicePrincipalType",
    "appRoleAssignmentRequired",
    "disabledByMicrosoftStatus",
    "tags",
    "appOwnerOrganizationId",
    "appId",
    "verifiedPublisher",
)
DELTA_SELECT = ",".join(DELTA_FIELDS)
# Graph's "sync from now" keyword for `$deltatoken`, not a token of anyone's.
LATEST = "latest"  # nosec B105 - a query keyword, authenticates nothing
# What ends a delta round with its link dropped rather than kept: Graph asking for a resync and
# a round past its bounds, and a next link or delta link off the pinned read (`LinkRefused`). A
# page that cannot be read is `MALFORMED` like any other and keeps the link.
RESYNC = frozenset({"RESYNC_REQUIRED", "DELTA_OVERFLOW"})
APPLICATIONS_PATH = "/v1.0/applications"
# The directory's audit log (#355): what an application did, read after the principals.
AUDIT_PATH = "/v1.0/auditLogs/directoryAudits"
# Entries a read takes per page, and the pages one run reads. The reports API allows five
# requests per 10 seconds per app per tenant, and a full collection's probe is the fifth.
AUDIT_PAGE_SIZE = 100
MAX_AUDIT_PAGES = 4
# How far back a connection's first read looks. Graph answers it with what its seven-day (Entra
# ID Free) or thirty-day (P1 and P2) retention still holds, so a cursor further back than this
# is one whose next entries Graph no longer holds on any plan.
AUDIT_LOOKBACK = timedelta(days=30)
# How far behind a read's moment the cursor is left once the read has caught up, so the next
# read sees an entry Graph makes available a while after it happened. A read that reads past this
# far behind its moment has caught up, because the next read starts there anyway.
AUDIT_OVERLAP = timedelta(minutes=30)
# How far after a read's own moment an entry may be stamped and still be kept by that read: a
# directory's clock a day fast is kept, and the clock-skew rule flags it as ahead of its receipt.
# An entry stamped later has not happened by any clock the read trusts, and no evaluation could
# date the evidence it would be, so the read keeps nothing of it. Nothing is lost: the cursor
# never passes the read's moment less the overlap, so every later read meets the entry again,
# and the first it is no more than this far ahead of keeps it.
AUDIT_AHEAD = timedelta(days=1)
# What a read asks for: every mapped activity is a Core Directory one.
AUDIT_FILTER = "activityDateTime ge {start} and loggedByService eq '" + activity_map.SERVICE + "'"
AUDIT_ORDER = "activityDateTime asc"
# An audit entry's own id, as Microsoft writes one ("Directory_<guid>_<code>_<number>"), read
# with `fullmatch` like every pattern here (see `GUID`).
AUDIT_REF = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
# What an observation's change and event identifier are derived under: one actor's action on one
# target with one outcome under one correlation id, logged within `store.AUDIT_SAME_CHANGE`, is
# one observation, however many entries the directory logs for it.
AUDIT_NAMESPACE = uuid5(NAMESPACE_URL, GRAPH_ORIGIN + AUDIT_PATH)
# Where the windows of `store.AUDIT_SAME_CHANGE` an audit observation's identifier names start.
AUDIT_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
AUDIT_OUTCOMES = {"success": "success", "failure": "error"}
# What a read counts besides the entries it maps.
AUDIT_COUNTS = ("read", "mapped", "unmapped", "user", "unattributed", "dropped")
# Service principal sign-ins (#355), documented on beta only: what network a principal signs in
# from, read after the audit log. Losing the read degrades driver evidence and nothing else.
SIGN_INS_PATH = "/beta/auditLogs/signIns"
SIGN_IN_FILTER = "createdDateTime ge {start} and signInEventTypes/any(t: t eq 'servicePrincipal')"
# The fields asked for. The parser still takes only what it reads, whatever Graph sends.
SIGN_IN_SELECT = "id,createdDateTime,servicePrincipalId,ipAddress,userAgent,status"
SIGN_IN_PAGE_SIZE = 500
MAX_SIGN_IN_PAGES = 4
# How far back a connection's first read looks, and how far behind its moment a read leaves the
# cursor for sign-ins Graph makes available late, as for the audit log.
SIGN_IN_LOOKBACK = timedelta(days=30)
SIGN_IN_OVERLAP = timedelta(minutes=30)
# How far ahead of the read a sign-in may be stamped and still be kept, at the read's moment.
SIGN_IN_AHEAD = timedelta(minutes=5)
# How far back the capability probe asks: a sign-in read without a time range may time out.
SIGN_IN_PROBE = timedelta(days=1)
SIGN_IN_COUNTS = ("read", "matched", "unmatched", "failed", "unattributed", "dropped")
# Capability states for which no read is made: the registration is refused the log, the beta
# endpoint is gone, or the directory has no Microsoft Entra ID P1 or P2.
NO_SIGN_INS = frozenset({"forbidden", "unsupported", "unlicensed"})
# A user agent's leading product token, the only part of it kept: a name and an optional version.
PRODUCT = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,47}(/[A-Za-z0-9._-]{1,32})?")
# The identity and access reports, which share one budget per app per tenant: five requests in
# any ten seconds. A run waits for the window rather than be throttled, at most this long in all.
REPORTS_PREFIXES = ("/v1.0/auditLogs/", "/beta/auditLogs/")
REPORTS_LIMIT = 5
REPORTS_WINDOW = 10.0
REPORTS_WAIT = 12.0
GRANTS_PATH = "/v1.0/oauth2PermissionGrants"
BLUEPRINTS_PATH = "/v1.0/applications/microsoft.graph.agentIdentityBlueprint"
AGENT_CAST = "/microsoft.graph.agentIdentity"
ROLES_PATH = "/v1.0/directoryRoles"
# Resources that refuse a page size outright: "This resource does not support custom page
# sizes", verified against a live tenant on 18 September 2026. Sending one is a 400, which
# a probe would read as "we could not tell" and a walk would read as a failed collection.
NO_PAGE_SIZE = frozenset({ROLES_PATH})
AGENT_TYPE = "#microsoft.graph.agentIdentity"
# "Set to ServiceIdentity for all agent identities", and present where @odata.type is not.
AGENT_PRINCIPAL_TYPE = "ServiceIdentity"
DIRECTORY_ROLE_TYPE = "#microsoft.graph.directoryRole"
CAPABILITIES = (
    "agent_identities",
    "service_principals",
    "applications",
    "grants",
    "directory_roles",
    # The directory's audit log (#355), which `AuditLog.Read.All` grants.
    "audit_log",
    # Service principal sign-ins (#355), beta: driver evidence only, never a run's outcome.
    "sign_ins",
)
# The two collections that list principals, read in this order: a collection takes a baseline
# only when it read both.
PRINCIPAL_COLLECTIONS = ("agent_identities", "service_principals")

# Every pattern here is read with `fullmatch`: with `match`, Python's `$` also matches before a
# final newline, so a value ending in one would pass here and fail the column's check, whose `$`
# in PostgreSQL is the end of the value, and roll the whole write back.
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SCOPE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)?(\.[A-Za-z0-9]+)+$")
TAG = re.compile(r"^[A-Za-z0-9._:\-]{1,64}$")
# The fields each parser keeps. Anything else in an open type is dropped and counted.
AGENT_FIELDS = frozenset(
    {
        "@odata.type",
        "id",
        "displayName",
        "accountEnabled",
        "createdDateTime",
        "agentIdentityBlueprintId",
        "servicePrincipalType",
        "appRoleAssignmentRequired",
        "disabledByMicrosoftStatus",
        "tags",
        "appOwnerOrganizationId",
        # Read only to look the application up in the AI publisher catalog; neither is stored.
        "appId",
        "verifiedPublisher",
    }
)


class GraphError(MonitorError):
    """A stable code and nothing from the response body."""

    def __init__(self, code: str, *, retry_after: int | None = None) -> None:
        self.retry_after = retry_after
        super().__init__(code)


class LinkRefused(GraphError):
    """A delta round's next link or delta link that is not the pinned read, `MALFORMED`.

    A page that does not parse says nothing about the link a delta pass started from, so the
    pass keeps that link and the next one reads the same round; a link off the pinned read is
    one the round cannot be followed by, so the pass drops its link for the next full
    collection to replace.
    """

    def __init__(self) -> None:
        super().__init__("MALFORMED")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError
    return dict(pairs)


def _constant(value: str) -> Any:
    raise ValueError


class Pace:
    """One run's share of the identity and access reports budget (#355).

    Graph allows five reports requests in any ten seconds per app per tenant, across the audit log
    and sign-ins. A sixth inside the window waits until the oldest leaves it, so the run is paced
    rather than throttled; the waits a run makes are at most `REPORTS_WAIT` in all, and a request
    that would need more is refused `PACED` without being sent, which ends only the read it was
    part of.
    """

    def __init__(
        self,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._monotonic = monotonic
        self._sleep = sleep
        self._sent: list[float] = []
        self.waited = 0.0

    def _window(self) -> float:
        now = self._monotonic()
        self._sent = [moment for moment in self._sent if now - moment < REPORTS_WINDOW]
        return now

    def before(self) -> None:
        now = self._window()
        if len(self._sent) >= REPORTS_LIMIT:
            wait = self._sent[0] + REPORTS_WINDOW - now
            if self.waited + wait > REPORTS_WAIT:
                raise GraphError("PACED")
            self._sleep(wait)
            self.waited += wait
            now = self._window()
        self._sent.append(now)


# What makes each run's pacer; the tests give every run a clock of its own that never sleeps.
PACER: Callable[[], Pace] = Pace


def _guid(value: object) -> str | None:
    return value if type(value) is str and GUID.fullmatch(value) else None


def _label(value: object) -> tuple[str, bool]:
    """A display name with control characters removed, bounded and marked when truncated."""
    if type(value) is not str:
        return "Unnamed", False
    cleaned = "".join(char for char in value if char.isprintable()).strip()
    if not cleaned:
        return "Unnamed", False
    return (cleaned[:96], True) if len(cleaned) > 96 else (cleaned, False)


# The moments a response may name: a day short of either end of the calendar, so that no
# arithmetic the collector does on one, such as a window either side of it, runs off the end.
MOMENTS = (
    datetime.min.replace(tzinfo=UTC) + timedelta(days=1),
    datetime.max.replace(tzinfo=UTC) - timedelta(days=1),
)


def _moment(value: object) -> datetime | None:
    """A moment Graph wrote, in UTC; None for one that is not a moment, or that UTC cannot hold
    once its offset is taken off, or that lies within a day of either end of the calendar."""
    if type(value) is not str or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        moment = parsed.astimezone(UTC) if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    except (ValueError, OverflowError):
        return None
    return moment if MOMENTS[0] <= moment <= MOMENTS[1] else None


def _flag(value: object) -> bool | None:
    return value if type(value) is bool else None


@dataclass(frozen=True)
class AgentRecord:
    """One allowlisted directory principal; nothing else from the record is retained."""

    platform_ref: str
    identity_class: str
    display_name: str
    display_name_truncated: bool
    enabled: bool | None
    blueprint_ref: str | None
    tags: tuple[str, ...]
    created_at: datetime | None
    # The organization whose application this principal represents. Null means it was
    # registered in this directory; another organization's identifier means the customer
    # did not create it and cannot assign accountability for it.
    owner_org_ref: str | None = None
    dropped: int = 0
    # The AI publisher catalog's key for this principal's application, if it names one.
    ai_publisher: str | None = None
    # Whether the record said what it is: it came from the agent identity cast collection, or
    # carried the agent identity `@odata.type` or a `servicePrincipalType`. A delta entry with
    # neither is a partial representation that does not say, and its class above is only the
    # default (#355).
    class_stated: bool = True


@dataclass(frozen=True)
class GrantRecord:
    grant_kind: str
    resource_ref: str
    value: str
    inherited: bool
    path_ref: str


@dataclass(frozen=True)
class SponsorRecord:
    kind: str
    ref: str


@dataclass(frozen=True)
class BlueprintRecord:
    object_ref: str
    app_ref: str
    credential_kinds: tuple[str, ...] = ()
    inherited: tuple[GrantRecord, ...] = field(default_factory=tuple)


def _verified_publisher(value: object) -> str | None:
    """A verified publisher's partner number, the one field of the object the catalog reads."""
    if not isinstance(value, dict):
        return None
    number = value.get("verifiedPublisherId")
    return (
        number if type(number) is str and ai_publishers.PUBLISHER_NUMBER.fullmatch(number) else None
    )


def parse_agent(
    record: object,
    *,
    cast_collection: bool = False,
    catalog: ai_publishers.Catalog = ai_publishers.PRODUCTION,
) -> AgentRecord | None:
    """An agent identity or a classic service principal, by what the directory says it is.

    Three signals, in order of strength, because a live tenant showed the first design
    relied on a field the vendor does not send. ``cast_collection`` says the record came
    from ``/servicePrincipals/microsoft.graph.agentIdentity``, whose every member is an
    agent identity by construction — the URL is the type assertion. ``@odata.type`` is
    accepted where an endpoint does send it. ``servicePrincipalType`` is the documented
    discriminator, "set to ServiceIdentity for all agent identities".

    A tag is still only evidence: it is kept and shown, and never promotes a service
    principal to an agent. The difference is that these three are the platform stating a
    type, where a tag is a label anyone can write.
    """
    if not isinstance(record, dict):
        return None
    platform_ref = _guid(record.get("id"))
    if platform_ref is None:
        return None
    agent = (
        cast_collection
        or record.get("@odata.type") == AGENT_TYPE
        or record.get("servicePrincipalType") == AGENT_PRINCIPAL_TYPE
    )
    stated = (
        cast_collection
        or record.get("@odata.type") == AGENT_TYPE
        or type(record.get("servicePrincipalType")) is str
    )
    name, truncated = _label(record.get("displayName"))
    kept = (tag for tag in record.get("tags", []) if type(tag) is str and TAG.fullmatch(tag))
    tags = tuple(kept)[:32]
    blueprint = _guid(record.get("agentIdentityBlueprintId")) if agent else None
    owner = _guid(record.get("appOwnerOrganizationId"))
    return AgentRecord(
        platform_ref=platform_ref,
        identity_class="agent_identity" if agent else "service_principal",
        display_name=name,
        display_name_truncated=truncated,
        enabled=_flag(record.get("accountEnabled")),
        blueprint_ref=blueprint,
        tags=tags,
        created_at=_moment(record.get("createdDateTime")),
        owner_org_ref=owner,
        dropped=len(set(record) - AGENT_FIELDS),
        ai_publisher=catalog.match(
            app_ref=_guid(record.get("appId")),
            owner_ref=owner,
            publisher_ref=_verified_publisher(record.get("verifiedPublisher")),
        ),
        class_stated=stated,
    )


def parse_removed(record: object) -> str | None:
    """The object identifier of a delta entry that says its principal was removed.

    Graph writes a removed instance as its `id` and an `@removed` object whose reason is
    `changed` (restorable) or `deleted`; either way it is no longer in the directory.
    """
    if not isinstance(record, dict) or not isinstance(record.get("@removed"), dict):
        return None
    return _guid(record.get("id"))


def parse_app_role_assignment(record: object) -> tuple[str, str] | None:
    """The resource principal and the app role identifier, both as opaque identifiers.

    The identifier is resolved to a permission name against the resource application's own
    ``appRoles`` collection; an assignment the tenant will not resolve stays unresolved.
    """
    if not isinstance(record, dict):
        return None
    resource = _guid(record.get("resourceId"))
    role = _guid(record.get("appRoleId"))
    return None if resource is None or role is None else (resource, role)


def parse_delegated_grant(record: object) -> tuple[str, tuple[str, ...]] | None:
    """The resource principal and the delegated scope names, which arrive as text."""
    if not isinstance(record, dict):
        return None
    resource = _guid(record.get("resourceId"))
    scope = record.get("scope")
    if resource is None or type(scope) is not str or len(scope) > 4096:
        return None
    names = tuple(name for name in scope.split() if SCOPE_NAME.fullmatch(name))[:MAX_GRANTS]
    return (resource, names)


def parse_directory_role(record: object) -> str | None:
    """A role template identifier, and only from an object that says it is a directory role.

    A group membership is not a directory role. A group can carry one, which is a reach path
    of its own; this slice does not follow it and the page says so.
    """
    if not isinstance(record, dict) or record.get("@odata.type") != DIRECTORY_ROLE_TYPE:
        return None
    return _guid(record.get("roleTemplateId"))


def parse_sponsor(record: object) -> SponsorRecord | None:
    """An object identifier and whether it is a person or a group. Never a name or address."""
    if not isinstance(record, dict):
        return None
    ref = _guid(record.get("id"))
    if ref is None:
        return None
    declared = record.get("@odata.type")
    kind = {"#microsoft.graph.user": "user", "#microsoft.graph.group": "group"}.get(
        declared if type(declared) is str else "", "other"
    )
    return SponsorRecord(kind=kind, ref=ref)


def parse_blueprint(record: object) -> BlueprintRecord | None:
    """Which *kinds* of credential the blueprint holds, never a credential or a hint."""
    if not isinstance(record, dict):
        return None
    object_ref = _guid(record.get("id"))
    app_ref = _guid(record.get("appId"))
    if object_ref is None or app_ref is None:
        return None
    kinds = []
    if isinstance(record.get("keyCredentials"), list) and record["keyCredentials"]:
        kinds.append("certificate")
    if isinstance(record.get("passwordCredentials"), list) and record["passwordCredentials"]:
        kinds.append("secret")
    return BlueprintRecord(object_ref=object_ref, app_ref=app_ref, credential_kinds=tuple(kinds))


def parse_inheritable(record: object, blueprint: str) -> tuple[GrantRecord, ...]:
    """An ``allAllowed`` declaration is a grant, held on the blueprint rather than the agent.

    Enumerating only an agent's own assignments would miss it entirely, and missing reach is
    the one failure this product cannot afford. ``none`` declares the absence of one.
    """
    if not isinstance(record, dict):
        return ()
    resource = _guid(record.get("resourceAppId"))
    if resource is None:
        return ()
    grants = []
    for key, kind in (
        ("inheritableRoles", "inherited_roles"),
        ("inheritableScopes", "inherited_scopes"),
    ):
        declared = record.get(key)
        if isinstance(declared, dict) and declared.get("kind") == "allAllowed":
            grants.append(
                GrantRecord(
                    grant_kind=kind,
                    resource_ref=resource,
                    # The set is whatever the blueprint principal holds, which is why the
                    # value says so rather than naming a permission that was never listed.
                    value="allAllowed",
                    inherited=True,
                    path_ref=blueprint,
                )
            )
    return tuple(grants)


def parse_app_roles(record: object) -> dict[str, str]:
    """A resource application's published app roles, as identifier to permission name."""
    if not isinstance(record, dict) or not isinstance(record.get("appRoles"), list):
        return {}
    resolved = {}
    for role in record["appRoles"][:2000]:
        if not isinstance(role, dict):
            continue
        identifier = _guid(role.get("id"))
        value = role.get("value")
        if identifier is not None and type(value) is str and SCOPE_NAME.fullmatch(value):
            resolved[identifier] = value
    return resolved


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _app_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError
    return dict(pairs)


@dataclass(frozen=True)
class PlatformApp:
    """The deployment's own app registration, which reads every directory that consented to it.

    Read from the collector's private file (`scout-app.json`): exactly a client id, a PEM
    certificate and the PEM private key of that certificate, an RSA key of at least 2048 bits.
    It is checked whole when it is read, so an assertion it signs is one the token endpoint can
    verify, and no part of it is ever printed. Only the collector holds it; the gateway names
    the same client id in its configuration and holds nothing that signs for it.
    """

    client_id: str
    certificate: x509.Certificate = field(repr=False)
    private_key: rsa.RSAPrivateKey = field(repr=False)

    @classmethod
    def from_text(cls, raw: str) -> "PlatformApp":
        try:
            if len(raw) > MAX_APP_FILE:
                raise ValueError
            document = json.loads(raw, object_pairs_hook=_app_object, parse_constant=_constant)
            if type(document) is not dict or set(document) != APP_FIELDS:
                raise ValueError
            client_id, certificate_pem, key_pem = (
                document["client_id"],
                document["certificate_pem"],
                document["private_key_pem"],
            )
            if not all(type(value) is str for value in (client_id, certificate_pem, key_pem)):
                raise ValueError
            if GUID.fullmatch(client_id) is None:
                raise ValueError
            certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
            key = serialization.load_pem_private_key(key_pem.encode("ascii"), password=None)
            if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
                raise ValueError
            public = certificate.public_key()
            # The certificate the directory registered must be this key's, or every assertion
            # would be refused, run after run.
            if not isinstance(public, rsa.RSAPublicKey) or (
                public.public_numbers() != key.public_key().public_numbers()
            ):
                raise ValueError
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise GraphError("INVALID_INPUT") from None
        return cls(client_id.lower(), certificate, key)

    @classmethod
    def from_file(cls, path: Path) -> "PlatformApp":
        try:
            if path.stat().st_size > MAX_APP_FILE:
                raise ValueError
            raw = path.read_text(encoding="utf-8")
        except (OSError, ValueError):
            raise GraphError("INVALID_INPUT") from None
        return cls.from_text(raw)

    @property
    def thumbprint(self) -> str:
        """The certificate's SHA-256 thumbprint, as a client assertion names it (`x5t#S256`)."""
        return _base64url(
            hashlib.sha256(self.certificate.public_bytes(serialization.Encoding.DER)).digest()
        )

    def assertion(self, audience: str, now: datetime) -> str:
        """One client assertion for `audience`, a directory's token endpoint: valid from `now`
        for five minutes, with a `jti` of its own."""
        moment = int(now.timestamp())
        header = {"alg": "RS256", "typ": "JWT", "x5t#S256": self.thumbprint}
        payload = {
            "aud": audience,
            "iss": self.client_id,
            "sub": self.client_id,
            "jti": str(uuid4()),
            "nbf": moment,
            "iat": moment,
            "exp": moment + ASSERTION_SECONDS,
        }
        signing_input = ".".join(
            _base64url(json.dumps(part, separators=(",", ":")).encode("utf-8"))
            for part in (header, payload)
        )
        signature = self.private_key.sign(
            signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{signing_input}.{_base64url(signature)}"


class Reader:
    """Bounded access to one pinned Graph origin under one app registration.

    It authenticates with exactly one credential: an operator's client `secret`, or the
    deployment's platform `app`, whose certificate signs a client assertion.
    """

    def __init__(
        self,
        directory: str,
        client_id: str,
        secret: str | None,
        client: httpx.Client,
        *,
        app: PlatformApp | None = None,
        clock: Clock = SYSTEM_CLOCK,
        pace: Pace | None = None,
    ) -> None:
        if (secret is None) == (app is None):
            raise GraphError("INVALID_INPUT")
        self.directory = directory
        self._client_id = client_id
        self._secret = secret
        self._app = app
        self._clock = clock
        self._client = client
        self._token: str | None = None
        self._pace = pace if pace is not None else PACER()

    def _credential(self, endpoint: str) -> dict[str, str]:
        if self._app is not None:
            return {
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": self._app.assertion(endpoint, self._clock.now()),
            }
        return {"client_secret": str(self._secret)}

    def authenticate(self) -> None:
        """The one ``POST`` of a run. The token stays in this object and goes nowhere else."""
        endpoint = f"{LOGIN_ORIGIN}/{self.directory}/oauth2/v2.0/token"
        try:
            response = self._client.post(
                endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    **self._credential(endpoint),
                    "scope": GRAPH_SCOPE,
                },
                headers={"Accept": "application/json"},
                follow_redirects=False,
                timeout=TIMEOUT,
            )
        except httpx.HTTPError:
            raise GraphError("UNAVAILABLE") from None
        if response.status_code in {400, 401, 403}:
            # The body names the client and sometimes the secret's state; none is read.
            raise GraphError("AUTH_LOST")
        if response.status_code == 429:
            raise GraphError("RATE_LIMITED", retry_after=_retry_after(response.headers))
        if response.status_code != 200 or len(response.content) > MAX_BODY:
            raise GraphError("UNAVAILABLE")
        try:
            body = json.loads(response.content, object_pairs_hook=_object, parse_constant=_constant)
        except (ValueError, RecursionError):
            raise GraphError("MALFORMED") from None
        token = body.get("access_token") if isinstance(body, dict) else None
        if type(token) is not str or not token:
            raise GraphError("MALFORMED")
        self._token = token

    def get(
        self, path: str, params: dict[str, Any] | None = None, *, delta: bool = False
    ) -> dict[str, Any]:
        """One bounded read. On the delta path a 400 or a 410 is `RESYNC_REQUIRED`: Graph
        refusing a delta link, as it does an expired token, which only a new link answers."""
        if self._token is None:
            raise GraphError("AUTH_LOST")
        if path.startswith(REPORTS_PREFIXES):
            # Before the request, so a refused one is never sent.
            self._pace.before()
        try:
            with self._client.stream(
                "GET",
                GRAPH_ORIGIN + path,
                params=params or {},
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Accept": "application/json",
                    # Without it the newer agent enumeration members are withheld.
                    "Prefer": "include-unknown-enum-members",
                },
                follow_redirects=False,
                timeout=TIMEOUT,
            ) as response:
                if response.status_code in {401, 403}:
                    raise GraphError("FORBIDDEN")
                if response.status_code in {404, 501}:
                    raise GraphError("UNSUPPORTED")
                if response.status_code == 429:
                    raise GraphError("RATE_LIMITED", retry_after=_retry_after(response.headers))
                if delta and response.status_code in {400, 410}:
                    raise GraphError("RESYNC_REQUIRED")
                if response.status_code != 200:
                    raise GraphError("UNAVAILABLE")
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_BODY:
                        raise GraphError("OVERSIZE")
                    raw.extend(chunk)
        except httpx.HTTPError:
            raise GraphError("UNAVAILABLE") from None
        try:
            body = json.loads(bytes(raw), object_pairs_hook=_object, parse_constant=_constant)
        except (ValueError, RecursionError):
            raise GraphError("MALFORMED") from None
        if not isinstance(body, dict):
            raise GraphError("MALFORMED")
        return body

    def walk(
        self,
        path: str,
        *,
        limit: int,
        params: dict[str, Any] | None = None,
        whole: str | None = None,
    ) -> Iterator[Any]:
        """Page a collection, following only a continuation that stays on the same read.

        Graph hands the next page back as a URL inside the response, which is the one place
        a request could be built from a response field. It is accepted only when it is the
        pinned origin and the very same path, so a response can redirect the collector's
        query but never its destination.

        The read stops at `limit` records or after the pages that many full pages need. Graph
        may serve shorter pages than the `$top` asked for, so the page bound can come first,
        with a continuation still on offer. A read that must be whole names `whole`, and is
        then refused with that code rather than ended short; any other read ends there.
        """
        query: dict[str, Any] = {**(params or {})}
        if path not in NO_PAGE_SIZE:
            query = {"$top": PAGE_SIZE, **query}
        seen = 0
        for _ in range(limit // PAGE_SIZE + 2):
            body = self.get(path, query)
            records = body.get("value")
            if not isinstance(records, list):
                raise GraphError("MALFORMED")
            for record in records:
                if seen >= limit:
                    return
                seen += 1
                yield record
            link = body.get("@odata.nextLink")
            if link is None:
                return
            query = _continuation(link, path)
        if whole is not None:
            raise GraphError(whole)

    def resource_app_roles(self, resource_ref: str) -> tuple[str | None, dict[str, str]]:
        """The resource application's identifier and its published app roles, from the tenant.

        This is what turns an app role identifier into the permission name the grant catalog
        is keyed by, without a vendor identifier being copied into this project.
        """
        body = self.get(f"{PRINCIPALS_PATH}/{resource_ref}", {"$select": "appId,appRoles"})
        return _guid(body.get("appId")), parse_app_roles(body)


def _continuation(link: object, path: str, *, fold: bool = False) -> dict[str, Any]:
    """The query of a next link that stays on the pinned origin and `path`. Only the query is
    ever used: the request that follows goes to the pinned origin and `path` with it. `fold`
    compares the path without regard to case, for a resource whose own links Graph spells
    either way."""
    if type(link) is not str or len(link) > 4096:
        raise GraphError("MALFORMED")
    origin = urlsplit(GRAPH_ORIGIN)
    try:
        # A port out of range or a host that is not one is refused as any link off the read.
        parsed = urlsplit(link)
        port = parsed.port
    except ValueError:
        raise GraphError("MALFORMED") from None
    if (
        parsed.scheme != origin.scheme
        or parsed.hostname != origin.hostname
        or port != origin.port
        or (parsed.path.lower() != path.lower() if fold else parsed.path != path)
    ):
        raise GraphError("MALFORMED")
    return dict(parse_qsl(parsed.query, keep_blank_values=False)[:16])


def delta_query(link: object) -> dict[str, Any]:
    """The query of a delta link, if the link is the pinned read and carries a delta token.

    A link Graph returns and a link read back from the database pass this same check, so a
    stored link is trusted no more than a fresh one. Only the query is ever used: the request
    a delta pass sends is the pinned origin and `DELTA_PATH` with it.
    """
    query = _continuation(link, DELTA_PATH)
    token = query.get("$deltatoken")
    if type(token) is not str or not token or token == LATEST:
        raise GraphError("MALFORMED")
    return query


def stored_link(query: dict[str, Any]) -> str:
    """The link a connection keeps: the pinned origin and path with the validated query."""
    link = DELTA_LINK_PREFIX + urlencode(query)
    if len(link) > 4096:
        raise GraphError("MALFORMED")
    return link


@dataclass(frozen=True)
class DeltaRound:
    """One delta round to its delta link: who it listed, who it says was removed, the link."""

    listed: tuple[AgentRecord, ...]
    removed: tuple[str, ...]
    link: str
    dropped: int = 0


def read_delta(reader: Reader, query: dict[str, Any], *, keep: bool = True) -> DeltaRound:
    """Follow one delta round from `query` to its delta link, within its bounds.

    Every page must carry a next link or a delta link and never both, and each is accepted only
    on the pinned origin and `DELTA_PATH`; one that is not is refused as `LinkRefused`. Graph
    may list one entity more than once, a later entry carrying only the properties that
    changed, and a restored one is listed with only some of its properties: a principal is its
    entries laid one over the other, the later's properties over the earlier's, a removal
    between them included, so a property a later entry leaves out keeps what an earlier one
    said rather than reading as cleared. Whether it is listed or removed is its last entry's.
    `keep=False` walks a round for its link alone, as a full collection does when Graph will
    not give the latest link directly.
    """
    # Every entry for a principal as Graph sent it, merged; parsed once the round is whole.
    said: dict[str, dict[str, Any]] = {}
    listed: dict[str, None] = {}
    removed: dict[str, None] = {}
    dropped = entries = 0
    for _ in range(MAX_DELTA_PAGES):
        body = reader.get(DELTA_PATH, query, delta=True)
        records = body.get("value")
        if not isinstance(records, list):
            raise GraphError("MALFORMED")
        for record in records if keep else ():
            entries += 1
            if entries > MAX_DELTA_ENTRIES:
                raise GraphError("DELTA_OVERFLOW")
            gone = parse_removed(record)
            if gone is not None:
                listed.pop(gone, None)
                removed[gone] = None
                continue
            ref = _guid(record.get("id")) if isinstance(record, dict) else None
            if ref is None:
                dropped += 1
                continue
            removed.pop(ref, None)
            listed[ref] = None
            # Listed again with only what changed: what an earlier entry said and this one
            # does not still holds, its class among it.
            said[ref] = {**said.get(ref, {}), **record}
        following, final = body.get("@odata.nextLink"), body.get("@odata.deltaLink")
        if (following is None) == (final is None):
            raise GraphError("MALFORMED")
        try:
            if final is not None:
                link = stored_link(delta_query(final))
            else:
                query = _continuation(following, DELTA_PATH)
        except GraphError:
            raise LinkRefused() from None
        if final is not None:
            parsed = (parse_agent(said[ref]) for ref in listed)
            return DeltaRound(
                listed=tuple(record for record in parsed if record is not None),
                removed=tuple(removed),
                link=link,
                dropped=dropped,
            )
    raise GraphError("DELTA_OVERFLOW")


def take_link(reader: Reader) -> str | None:
    """A delta link for the directory as it stands, taken before a full read; None if Graph
    gives none this collection can trust. It never fails the collection that asks.

    `$deltatoken=latest` first, which answers a link and no principals. Graph documents it for
    directory resources "such as users and groups"; where service principals refuse it, an
    initial round is walked for its link and nothing it lists is kept.
    """
    try:
        try:
            return read_delta(
                reader, {"$select": DELTA_SELECT, "$deltatoken": LATEST}, keep=False
            ).link
        except GraphError as error:
            if error.code not in {"RESYNC_REQUIRED", "UNSUPPORTED"}:
                raise
        return read_delta(reader, {"$select": DELTA_SELECT}, keep=False).link
    except GraphError:
        return None


def audit_flag(value: object) -> bool | None:
    """A modified property's value as a boolean, as an audit entry writes one: `true`, the
    string `"true"` or a one-element JSON array of either, in any case. None for anything else,
    which no map entry matches."""
    if type(value) is bool:
        return value
    if type(value) is not str or len(value) > 64:
        return None
    try:
        parsed: object = json.loads(value, parse_constant=_constant)
    except (ValueError, RecursionError):
        parsed = value
    if isinstance(parsed, list):
        if len(parsed) != 1:
            return None
        parsed = parsed[0]
    if type(parsed) is bool:
        return parsed
    if type(parsed) is str and parsed.strip().lower() in {"true", "false"}:
        return parsed.strip().lower() == "true"
    return None


@dataclass(frozen=True)
class AuditEntry:
    """One directory audit entry an application initiated that the activity map covers, as
    much of it as is kept: who, what, to whom by object id, how it ended and when."""

    entry_ref: str
    occurred_at: datetime
    activity: activity_map.Activity
    actor_ref: str
    target_ref: str
    outcome: str
    correlation_ref: str | None

    @property
    def action(self) -> str:
        return self.activity.action

    @property
    def operation_name(self) -> str:
        return self.activity.operation

    @property
    def change_ref(self) -> str:
        """The change the entry logs: one actor's action on one target with one outcome under
        one correlation id (the entry's own id where it has none). Everything the observation
        asserts is in it, so two entries under one correlation id that assert different things,
        such as a refused attempt and the retry that succeeded, or two actors' entries, are two
        observations rather than one dropped as a conflicting copy of the other."""
        under = self.correlation_ref or f"entry:{self.entry_ref}"
        asserted = f"{under}|{self.actor_ref}|{self.action}|{self.target_ref}|{self.outcome}"
        return str(uuid5(AUDIT_NAMESPACE, asserted))

    @property
    def window(self) -> int:
        """The window of `store.AUDIT_SAME_CHANGE` the entry's moment falls in."""
        return (self.occurred_at - AUDIT_EPOCH) // store.AUDIT_SAME_CHANGE

    def _event(self, window: int) -> str:
        return f"audit:{uuid5(AUDIT_NAMESPACE, f'{self.change_ref}|{window}')}"

    @property
    def event_id(self) -> str:
        """The observation's identifier: its change, in the window its moment falls in. A
        caller chooses its own correlation id and may use it again, so the change alone would
        make a later action a copy of the first, dropped unseen; the moment is what tells them
        apart. One change logged twice, as one request's entries are, is one observation however
        its moments fall about a window's edge, because the store looks in both neighbours
        (`nearby_event_ids`)."""
        return self._event(self.window)

    @property
    def nearby_event_ids(self) -> tuple[str, ...]:
        """Every identifier an observation of this change logged within `AUDIT_SAME_CHANGE` of
        this entry can hold: its own window's and either neighbour's."""
        return tuple(self._event(self.window + offset) for offset in (-1, 0, 1))

    @property
    def content_hash(self) -> str:
        """What the observation asserts: the same change logged twice hashes the same, in
        whichever window either entry falls."""
        asserted = {
            "change": self.change_ref,
            "actor": self.actor_ref,
            "action": self.action,
            "target": self.target_ref,
            "outcome": self.outcome,
        }
        return hashlib.sha256(json.dumps(asserted, sort_keys=True).encode()).hexdigest()


def _target_type(target: dict[str, Any]) -> object:
    # Graph's own examples write the property both ways.
    return target.get("type", target.get("Type"))


def parse_directory_audit(
    record: object, *, catalog: activity_map.ActivityMap = activity_map.PRODUCTION
) -> tuple[str, AuditEntry | None, datetime | None]:
    """What one audit entry is: `mapped` (with the entry), `user` (no application initiated it,
    a person's or the directory's own), `unattributed` (an application with no service
    principal id), `unmapped` (an application's activity the map does not cover) or `dropped`
    (not an entry this collector can read), with its moment where it has one.

    The entry is read by allowlist: its id, moment, activity, service, result and correlation
    id, the initiating application's service principal id, and from its one `User` target the
    object id and the modified properties the map inspects. Names, principal names, addresses,
    reasons, additional details, the application's own id and name, and every other property
    value are never taken.
    """
    if not isinstance(record, dict):
        return "dropped", None, None
    occurred = _moment(record.get("activityDateTime"))
    if occurred is None:
        return "dropped", None, None
    initiated = record.get("initiatedBy")
    app = initiated.get("app") if isinstance(initiated, dict) else None
    user = initiated.get("user") if isinstance(initiated, dict) else None
    if not isinstance(app, dict) or isinstance(user, dict):
        # A person's own change, or an application acting for a signed-in person: the actor is
        # the person, not the application's own identity.
        return "user", None, occurred
    actor = _guid(app.get("servicePrincipalId"))
    if actor is None:
        return "unattributed", None, occurred
    service, name = record.get("loggedByService"), record.get("activityDisplayName")
    targets = record.get("targetResources")
    users = (
        [
            target
            for target in targets
            if isinstance(target, dict) and _target_type(target) == activity_map.USER
        ]
        if isinstance(targets, list)
        else []
    )
    target_ref = _guid(users[0].get("id")) if len(users) == 1 else None
    if type(service) is not str or type(name) is not str or target_ref is None:
        return "unmapped", None, occurred
    changes: dict[str, tuple[bool | None, bool | None]] = {}
    modified = users[0].get("modifiedProperties")
    for item in modified if isinstance(modified, list) else ():
        # A name that is not a string is no property the map inspects, and may not be hashable.
        if (
            isinstance(item, dict)
            and type(item.get("displayName")) is str
            and item["displayName"] in activity_map.INSPECTED
        ):
            changes[item["displayName"]] = (
                audit_flag(item.get("oldValue")),
                audit_flag(item.get("newValue")),
            )
    found = catalog.match(service, name, changes)
    if found is None:
        return "unmapped", None, occurred
    entry_ref = record.get("id")
    if type(entry_ref) is not str or AUDIT_REF.fullmatch(entry_ref) is None:
        return "dropped", None, occurred
    correlation = _guid(record.get("correlationId"))
    return (
        "mapped",
        AuditEntry(
            entry_ref=entry_ref,
            occurred_at=occurred,
            activity=found,
            actor_ref=actor,
            target_ref=target_ref.lower(),
            outcome=AUDIT_OUTCOMES.get(str(record.get("result")), "unknown"),
            correlation_ref=correlation.lower() if correlation else None,
        ),
        occurred,
    )


@dataclass
class AuditRead:
    """One bounded read of the audit log: the entries it mapped, its counts, the moment of the
    last entry it read, whether it reached the log's end, and the refusal that stopped it."""

    entries: list[AuditEntry] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(AUDIT_COUNTS, 0))
    last: datetime | None = None
    complete: bool = False
    error: str | None = None


def _filter_moment(value: datetime) -> str:
    """A filter's moment, exactly `value`: to the second, unless `value` carries a fraction of
    one, which only `_resume` leaves, for a read that never left the second it started in."""
    value = value.astimezone(UTC)
    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _second(value: datetime) -> datetime:
    """`value`'s whole second: a cursor the next read names to the second, never later."""
    return value.replace(microsecond=0)


def _resume(start: datetime, last: datetime) -> datetime:
    """Where the next read starts after one from `start` that stopped short of the log's end at
    the entry it read last, `last`: that entry's whole second, so it and any beside it are read
    again and recognised. A read that never left the second it started in would then read the
    same entries again, as when a bulk change logs more entries inside one second than a run
    reads, so the next starts at `last` itself, to the microsecond, and reads on."""
    return last if _second(last) <= _second(start) else _second(last)


def read_audit(reader: Reader, start: datetime, *, now: datetime) -> AuditRead:
    """Core Directory entries from `start`, oldest first, in at most `MAX_AUDIT_PAGES` pages,
    read at `now`.

    A page is taken whole or not at all: one whose entries are out of time order is refused
    (`MALFORMED`), because the cursor stands on the read's order. A next link is followed only on
    the pinned origin and the audit path; one that is not stops the read after the page it came
    with (`MALFORMED`). Any other refusal from Graph stops it before the page it refused. A read
    that reaches a page with no next link is complete; one stopped by its bound is not, and the
    next run continues from where it stopped. An entry stamped more than `AUDIT_AHEAD` after
    `now` is counted as dropped and not kept; its moment still orders the page.
    """
    latest = now + AUDIT_AHEAD
    found = AuditRead()
    query: dict[str, Any] = {
        "$filter": AUDIT_FILTER.format(start=_filter_moment(start)),
        "$orderby": AUDIT_ORDER,
        "$top": AUDIT_PAGE_SIZE,
    }
    for _ in range(MAX_AUDIT_PAGES):
        try:
            body = reader.get(AUDIT_PATH, query)
            records = body.get("value")
            if not isinstance(records, list):
                raise GraphError("MALFORMED")
            parsed = [parse_directory_audit(record) for record in records]
            last = found.last
            for _, _, occurred in parsed:
                if occurred is None:
                    continue
                if last is not None and occurred < last:
                    raise GraphError("MALFORMED")
                last = occurred
        except GraphError as error:
            found.error = error.code
            return found
        for kind, entry, _ in parsed:
            if entry is not None and entry.occurred_at > latest:
                # Not yet happened by the read's clock: a later read keeps it (`AUDIT_AHEAD`).
                kind, entry = "dropped", None
            found.counts["read"] += 1
            found.counts[kind] += 1
            if entry is not None:
                found.entries.append(entry)
        found.last = last
        link = body.get("@odata.nextLink")
        if link is None:
            found.complete = True
            return found
        try:
            query = _continuation(link, AUDIT_PATH, fold=True)
        except GraphError as error:
            found.error = error.code
            return found
    return found


def collect_audit(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    reader: Reader,
    row: dict[str, Any],
    capability: str | None,
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, Any]:
    """Read the directory's audit log from the connection's cursor and keep what it maps (#355).

    Counts and codes only. A capability the probe found `forbidden` or `unsupported` is not
    asked, its state is the read's, and any episode of reads behind ends. A read has caught up
    (`complete`) when it reaches the log's end or reads an entry at or after its moment less
    `AUDIT_OVERLAP`, where the next read starts anyway, so a directory busy around the clock
    catches up as long as each run reads further than the time since the last. The cursor is
    where the next read starts: after a read that caught up, that moment less the overlap, so an
    entry Graph makes available late is read next time; after one that did not (`backlog`) or
    that Graph refused (`failed`), where it stopped (`_resume`), never later than that moment.
    It never moves back, and a read that read nothing leaves it. The connection's first read
    that catches up sets its activity baseline: what it and the reads before it stored is the
    actors' habit, and what a later read stores is news, however early Graph stamped it, since
    an entry Graph publishes late is found only by a later read. A refusal
    changes nothing about the run: what was read before it is kept, and the next run reads on
    from the cursor. The store dates how long the reads have not caught up, and raises the
    health finding when that runs long or when the cursor is further back than any retention
    Graph offers (`gap`). A read that meets the connection's observation bound is no refusal:
    it moves on like any read, keeping of each new entry only what the rules would miss without
    it (`bounded`, with what it kept and dropped there, as `store._AtBound` decides), and the
    store raises its own health finding once an episode.
    """
    result: dict[str, Any] = {
        "state": "not_read",
        "error_code": None,
        **dict.fromkeys(AUDIT_COUNTS, 0),
        "accepted": 0,
        "duplicates": 0,
        "bounded": 0,
        "kept_at_bound": 0,
        "dropped_at_bound": 0,
    }
    if capability in {"forbidden", "unsupported"}:
        result["state"] = capability
        if row.get("audit_behind_since") is not None:
            # No read, so none behind: a refused read's episode ends here (`end_audit_episode`).
            store.end_audit_episode(db, actor, connection_id, clock=clock, lease=lease)
        return result
    now = clock.now()
    cursor = row.get("audit_cursor")
    floor = now - AUDIT_LOOKBACK
    start = cursor if cursor is not None else _second(floor)
    found = read_audit(reader, start, now=now)
    result.update(found.counts)
    result["mapped"] = len(found.entries)
    caught = now - AUDIT_OVERLAP
    caught_up = found.error is None and (
        found.complete or (found.last is not None and found.last >= caught)
    )
    moved: datetime | None = _second(caught)
    if not caught_up:
        moved = None if found.last is None else min(_resume(start, found.last), _second(caught))
    if cursor is not None and moved is not None:
        moved = max(cursor, moved)
    kept = store.apply_directory_audit(
        db,
        actor,
        connection_id,
        found.entries,
        cursor=moved,
        caught_up=caught_up,
        # Graph keeps no entry this far back on any plan, so what lay past the cursor is gone.
        gap=cursor is not None and cursor < floor,
        clock=clock,
        lease=lease,
    )
    result.update(
        {
            key: kept[key]
            for key in ("accepted", "duplicates", "bounded", "kept_at_bound", "dropped_at_bound")
        }
    )
    result["error_code"] = found.error
    result["state"] = "failed" if found.error else "complete" if caught_up else "backlog"
    return result


def user_agent_hint(value: object) -> str | None:
    """A sign-in's user agent as Scout keeps it: its leading product token alone, such as
    `python-requests/2.31.0`, and nothing after it. A client chooses its own user agent, so this is
    a hint shown beside the actor and never evidence of anything. None for a value that does not
    begin with a product token, or whose token is shaped like a secret, an address or a mailbox:
    what follows a token, where a host, a version string or an address may sit, is never kept.
    """
    if type(value) is not str or len(value) > 512:
        return None
    text = value.strip()
    found = PRODUCT.match(text)
    if found is None:
        return None
    token = found.group(0)
    if len(text) > len(token) and text[len(token)] not in " (;":
        return None
    name = token.split("/", 1)[0]
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    if "@" in token or secret_shaped(token):
        return None
    return token


def _address(value: object) -> str | None:
    """A sign-in's address in canonical form, an IPv4 address mapped into IPv6 as the IPv4 one, or
    None. It lives only as long as the match it is read for."""
    if type(value) is not str or len(value) > 64:
        return None
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    mapped = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
    return str(mapped or parsed)


@dataclass
class SignInRead:
    """One bounded read of service principal sign-ins: for each principal and platform its sign-
    ins matched, the first and last moment; each principal's newest user agent hint; the counts;
    whether the read reached its window's end; and the refusal that stopped it. No address is
    held: each is matched and dropped as it is read."""

    matches: dict[tuple[str, str], tuple[datetime, datetime]] = field(default_factory=dict)
    hints: dict[str, tuple[datetime, str]] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(SIGN_IN_COUNTS, 0))
    complete: bool = False
    pages: int = 0
    error: str | None = None


def _seen(found: SignInRead, key: tuple[str, str], moment: datetime) -> None:
    first, last = found.matches.get(key, (moment, moment))
    found.matches[key] = (min(first, moment), max(last, moment))


def read_sign_ins(
    reader: Reader,
    start: datetime,
    *,
    now: datetime,
    tines: dict[str, tuple[str, ...]],
    catalog: egress.Catalog = egress.PRODUCTION,
) -> SignInRead:
    """Service principal sign-ins from `start`, newest first as Graph serves them, in at most
    `MAX_SIGN_IN_PAGES` pages, read at `now`.

    Each successful sign-in by a service principal is matched in memory: its address against the
    egress catalog's stable platforms (`egress:<key>`) and against the Space's recorded Tines
    egress addresses (`tines`, an address to the Tines connections that recorded it). Only the
    match is kept. A failed sign-in, one with no principal and one stamped more than
    `SIGN_IN_AHEAD` after `now` are counted and matched to nothing, and a moment after `now` is
    kept as `now`. A next link is followed only on the pinned origin and the sign-ins path, in
    either case; one that is not stops the read after the page it came with (`MALFORMED`), and any
    other refusal, the pacer's included, stops it before the page it refused, keeping what the
    pages before it matched.
    """
    found = SignInRead()
    query: dict[str, Any] = {
        "$filter": SIGN_IN_FILTER.format(start=_filter_moment(_second(start))),
        "$select": SIGN_IN_SELECT,
        "$top": SIGN_IN_PAGE_SIZE,
    }
    for _ in range(MAX_SIGN_IN_PAGES):
        try:
            body = reader.get(SIGN_INS_PATH, query)
            records = body.get("value")
            if not isinstance(records, list):
                raise GraphError("MALFORMED")
        except GraphError as error:
            found.error = error.code
            return found
        found.pages += 1
        for record in records:
            found.counts["read"] += 1
            moment = _moment(record.get("createdDateTime")) if isinstance(record, dict) else None
            if moment is None or moment > now + SIGN_IN_AHEAD:
                found.counts["dropped"] += 1
                continue
            moment = min(moment, now)
            actor = _guid(record.get("servicePrincipalId"))
            if actor is None:
                found.counts["unattributed"] += 1
                continue
            actor = actor.lower()
            status = record.get("status")
            code = status.get("errorCode") if isinstance(status, dict) else None
            if type(code) is not int or code != 0:
                found.counts["failed"] += 1
                continue
            hint = user_agent_hint(record.get("userAgent"))
            if hint is not None and moment >= found.hints.get(actor, (moment, ""))[0]:
                found.hints[actor] = (moment, hint)
            address = _address(record.get("ipAddress"))
            refs = []
            if address is not None:
                platform = catalog.match(address)
                if platform is not None:
                    refs.append(f"egress:{platform.key}")
                refs += [f"tines:{connection}" for connection in tines.get(address, ())]
            if not refs:
                found.counts["unmatched"] += 1
                continue
            found.counts["matched"] += 1
            for ref in refs:
                _seen(found, (actor, ref), moment)
        link = body.get("@odata.nextLink")
        if link is None:
            found.complete = True
            return found
        try:
            query = _continuation(link, SIGN_INS_PATH, fold=True)
        except GraphError as error:
            found.error = error.code
            return found
    return found


def collect_sign_ins(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    reader: Reader,
    capability: str | None,
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, Any]:
    """Read the directory's service principal sign-ins from the connection's cursor and keep what
    they establish about who drives its actors (#355). Counts and codes only.

    A capability the probe found `forbidden`, `unsupported` or `unlicensed` is not asked, and its
    state is the read's. The cursor is read beside the Space's recorded Tines egress, and a read
    from no cursor, the first or the one after egress is recorded, looks back `SIGN_IN_LOOKBACK`.
    A read that reached its window's end (`complete`) or its bound (`sampled`, since Graph serves
    the newest first and the rest of the window is not read, or by the run's reports budget after
    its first page) leaves the cursor at its moment less `SIGN_IN_OVERLAP`, or at the earliest
    match for a principal the inventory does not hold yet, no further back than
    `SIGN_IN_LOOKBACK`; one Graph refused, or the pacer before its first page (`failed`), leaves
    it where it was, keeping what it matched. It never moves back. The read is matched against
    the Tines egress the Space recorded when it began; if that has changed by the time it is
    written, its Tines matches are dropped and the cursor is left, so the next read matches what
    is recorded now. Nothing here changes the run's outcome, schedule or health.
    """
    result: dict[str, Any] = {
        "state": "not_read",
        "error_code": None,
        **dict.fromkeys(SIGN_IN_COUNTS, 0),
        "pages": 0,
        "network": 0,
        "joined": 0,
        "unknown_actor": 0,
        "stale": 0,
    }
    if capability in NO_SIGN_INS:
        result["state"] = capability
        return result
    now = clock.now()
    # The cursor as it stands beside the recorded egress, not as the run found it when it
    # began: egress recorded since has cleared it, and the read then looks back again.
    recorded = drivers.space_egress(db, actor, connection_id, clock=clock, lease=lease)
    start = recorded.cursor if recorded.cursor is not None else now - SIGN_IN_LOOKBACK
    found = read_sign_ins(reader, start, now=now, tines=recorded.addresses)
    result.update(found.counts)
    result["pages"] = found.pages
    # The run's own reports budget stopping a read that had begun is its bound, not a refusal:
    # what it read is the newest, so the cursor moves on as for a read stopped by its pages.
    sampled = found.error == "PACED" and found.pages > 0
    moved = None if found.error and not sampled else _second(now - SIGN_IN_OVERLAP)
    kept = drivers.apply_sign_ins(
        db,
        actor,
        connection_id,
        found.matches,
        found.hints,
        recorded=recorded,
        cursor=moved,
        oldest=_second(now - SIGN_IN_LOOKBACK),
        clock=clock,
        lease=lease,
    )
    result.update(kept)
    result["error_code"] = found.error
    if found.error and not sampled:
        result["state"] = "failed"
    else:
        result["state"] = "complete" if found.complete else "sampled"
    return result


def _retry_after(headers: httpx.Headers) -> int | None:
    value = headers.get("Retry-After")
    if value is None or not value.strip().isdigit():
        return None
    return min(int(value.strip()), 86400)


def probe(reader: Reader, now: datetime) -> dict[str, dict[str, Any]]:
    """One bounded request per capability. A probe classifies and retains nothing else.

    The shape is the monitoring store's: a state and the moment it was established. Being
    throttled classifies that one capability ``unknown`` and decides nothing about the rest,
    because a platform's answer to this run is not a statement about what exists.
    """
    probes: dict[str, Any] = {
        "agent_identities": lambda: reader.get(AGENTS_PATH, {"$top": 1}),
        "service_principals": lambda: reader.get(PRINCIPALS_PATH, {"$top": 1}),
        "applications": lambda: reader.get(APPLICATIONS_PATH, {"$top": 1}),
        "grants": lambda: reader.get(GRANTS_PATH, {"$top": 1}),
        "directory_roles": lambda: reader.get(ROLES_PATH, {}),
        "audit_log": lambda: reader.get(AUDIT_PATH, {"$top": 1}),
        # The read's own filter over the last day: a probe without a time range may time out.
        "sign_ins": lambda: reader.get(
            SIGN_INS_PATH,
            {
                "$filter": SIGN_IN_FILTER.format(
                    start=_filter_moment(_second(now - SIGN_IN_PROBE))
                ),
                "$select": SIGN_IN_SELECT,
                "$top": 1,
            },
        ),
    }
    result: dict[str, dict[str, Any]] = {}
    for name, call in probes.items():
        try:
            call()
            state = "available"
        except GraphError as error:
            state = {"FORBIDDEN": "forbidden", "UNSUPPORTED": "unsupported"}.get(
                error.code, "unknown"
            )
        if name == "sign_ins" and state == "forbidden":
            state = sign_ins_refused(result["audit_log"]["state"])
        result[name] = {"state": state, "at": now.isoformat()}
    return result


def sign_ins_refused(audit_log: str) -> str:
    """What a sign-in read Graph refuses outright says, by what the audit log's probe said.

    Both need `AuditLog.Read.All`, and sign-ins also Microsoft Entra ID P1 or P2. So a refusal
    while the audit log is available is the directory's licence (`unlicensed`), one while the
    audit log is refused too is the registration's (`forbidden`), and one while the audit log could
    not be told is `unknown`. The response body, which names the reason, is never read. A beta
    capability is therefore never `forbidden` unless the audit log is, and losing it never makes
    a connection read as incomplete.
    """
    return {"available": "unlicensed", "forbidden": "forbidden"}.get(audit_log, "unknown")


def verify_directory(reader: Reader) -> str | None:
    """The directory the token was actually issued for, as the directory itself reports it.

    The connection names a directory at registration; this is the only check that the app
    registration behind the secret speaks for that same directory. A refused read leaves it
    unestablished rather than assumed.
    """
    try:
        body = reader.get("/v1.0/organization", {"$top": 1, "$select": "id"})
    except GraphError as error:
        if error.code in {"FORBIDDEN", "UNSUPPORTED"}:
            return None
        raise
    records = body.get("value")
    if not isinstance(records, list) or not records or not isinstance(records[0], dict):
        return None
    return _guid(records[0].get("id"))


@dataclass(frozen=True)
class AgentDetail:
    """Everything a second pass established about one agent, and what it could not read."""

    platform_ref: str
    grants: tuple[GrantRecord, ...] = ()
    sponsors: tuple[SponsorRecord, ...] = ()
    sponsor_state: str = "not_read"
    owner_count: int | None = None
    blueprint_object_ref: str | None = None
    credential_kinds: tuple[str, ...] = ()


class _Resources:
    """Resolves a resource principal to its application and its published app roles, once."""

    def __init__(self, reader: Reader) -> None:
        self._reader = reader
        self._cache: dict[str, tuple[str | None, dict[str, str]]] = {}

    def resolve(self, resource_ref: str) -> tuple[str | None, dict[str, str]]:
        if resource_ref not in self._cache:
            try:
                self._cache[resource_ref] = self._reader.resource_app_roles(resource_ref)
            except GraphError as error:
                if error.code in {"FORBIDDEN", "UNSUPPORTED"}:
                    # Unresolved, which makes the grant unknown rather than absent.
                    self._cache[resource_ref] = (None, {})
                else:
                    raise
        return self._cache[resource_ref]


def _optional(call: Any) -> tuple[Any, bool]:
    """Run a read whose refusal is a fact about one agent, not a failure of the run."""
    try:
        return call(), True
    except GraphError as error:
        if error.code in {"FORBIDDEN", "UNSUPPORTED"}:
            return None, False
        raise


def blueprints(reader: Reader) -> dict[str, BlueprintRecord]:
    """Every agent identity blueprint in the directory, indexed by its application id.

    One bounded walk rather than a lookup per agent: many agents share a blueprint, and the
    blueprint is where their credentials and inherited permissions actually sit.
    """
    found: dict[str, BlueprintRecord] = {}
    records, readable = _optional(lambda: list(reader.walk(BLUEPRINTS_PATH, limit=MAX_BLUEPRINTS)))
    if not readable or records is None:
        return found
    for record in records:
        parsed = parse_blueprint(record)
        if parsed is None:
            continue
        inherited: tuple[GrantRecord, ...] = ()
        entries, _ = _optional(
            lambda ref=parsed.object_ref: list(
                reader.walk(f"{BLUEPRINTS_PATH}/{ref}/inheritablePermissions", limit=MAX_GRANTS)
            )
        )
        for entry in entries or []:
            inherited += parse_inheritable(entry, parsed.app_ref)
        found[parsed.app_ref] = BlueprintRecord(
            object_ref=parsed.object_ref,
            app_ref=parsed.app_ref,
            credential_kinds=parsed.credential_kinds,
            inherited=inherited,
        )
    return found


def detail(
    reader: Reader,
    agents: Sequence[AgentRecord],
    capabilities: dict[str, dict[str, Any]],
    *,
    read_blueprints: bool = True,
) -> list[AgentDetail]:
    """Read each agent's grants, roles, sponsors and blueprint, within the run's bounds.

    `read_blueprints=False` skips the blueprint collection, for a delta pass none of whose
    principals is an agent identity with a blueprint the store knows.
    """
    resources = _Resources(reader)
    index = (
        blueprints(reader)
        if read_blueprints and capabilities["applications"]["state"] == "available"
        else {}
    )
    results = []
    for agent in agents:
        grants: tuple[GrantRecord, ...] = ()
        if capabilities["grants"]["state"] == "available":
            grants += _assignments(reader, resources, agent.platform_ref)
            grants += _delegated(reader, resources, agent.platform_ref)
        if capabilities["directory_roles"]["state"] == "available":
            grants += _roles(reader, agent.platform_ref)
        blueprint = index.get(agent.blueprint_ref or "")
        if blueprint is not None:
            # An inherited permission sits on the blueprint, and so does the way to remove it.
            grants += blueprint.inherited
        sponsors, state, owners = _accountability(reader, agent)
        results.append(
            AgentDetail(
                platform_ref=agent.platform_ref,
                grants=grants[:MAX_GRANTS],
                sponsors=sponsors,
                sponsor_state=state,
                owner_count=owners,
                blueprint_object_ref=blueprint.object_ref if blueprint else None,
                credential_kinds=blueprint.credential_kinds if blueprint else (),
            )
        )
    return results


def _assignments(reader: Reader, resources: _Resources, ref: str) -> tuple[GrantRecord, ...]:
    records, readable = _optional(
        lambda: list(reader.walk(f"{PRINCIPALS_PATH}/{ref}/appRoleAssignments", limit=MAX_GRANTS))
    )
    if not readable:
        return ()
    grants = []
    for record in records or []:
        parsed = parse_app_role_assignment(record)
        if parsed is None:
            continue
        resource, role_id = parsed
        app_ref, roles = resources.resolve(resource)
        # An identifier the tenant will not resolve stays the identifier, which the catalog
        # does not name, so the reach it produces is unknown rather than absent.
        grants.append(
            GrantRecord(
                grant_kind="graph_role",
                resource_ref=app_ref or resource,
                value=roles.get(role_id, role_id),
                inherited=False,
                path_ref=ref,
            )
        )
    return tuple(grants)


def _delegated(reader: Reader, resources: _Resources, ref: str) -> tuple[GrantRecord, ...]:
    records, readable = _optional(
        lambda: list(
            reader.walk(f"{PRINCIPALS_PATH}/{ref}/oauth2PermissionGrants", limit=MAX_GRANTS)
        )
    )
    if not readable:
        return ()
    grants = []
    for record in records or []:
        parsed = parse_delegated_grant(record)
        if parsed is None:
            continue
        resource, names = parsed
        app_ref, _ = resources.resolve(resource)
        grants += [
            GrantRecord(
                grant_kind="graph_scope",
                resource_ref=app_ref or resource,
                value=name,
                inherited=False,
                path_ref=ref,
            )
            for name in names
        ]
    return tuple(grants)


def _roles(reader: Reader, ref: str) -> tuple[GrantRecord, ...]:
    records, readable = _optional(
        lambda: list(reader.walk(f"{PRINCIPALS_PATH}/{ref}/memberOf", limit=MAX_GRANTS))
    )
    if not readable:
        return ()
    return tuple(
        GrantRecord(
            grant_kind="directory_role",
            resource_ref="",
            value=template,
            inherited=False,
            path_ref=ref,
        )
        for template in (parse_directory_role(record) for record in records or [])
        if template is not None
    )


def _accountability(
    reader: Reader, agent: AgentRecord
) -> tuple[tuple[SponsorRecord, ...], str, int | None]:
    """Sponsors and owners, keeping "none" and "could not read" as different answers."""
    if agent.identity_class != "agent_identity":
        # A classic service principal has owners but no sponsor relationship at all.
        owners, readable = _optional(
            lambda: list(
                reader.walk(f"{PRINCIPALS_PATH}/{agent.platform_ref}/owners", limit=MAX_SPONSORS)
            )
        )
        return (), "absent", len(owners or []) if readable else None
    records, readable = _optional(
        lambda: list(
            reader.walk(
                f"{PRINCIPALS_PATH}/{agent.platform_ref}{AGENT_CAST}/sponsors", limit=MAX_SPONSORS
            )
        )
    )
    if not readable:
        return (), "unreadable", None
    sponsors = tuple(
        parsed
        for parsed in (parse_sponsor(record) for record in records or [])
        if parsed is not None
    )
    owners, owners_readable = _optional(
        lambda: list(
            reader.walk(
                f"{PRINCIPALS_PATH}/{agent.platform_ref}{AGENT_CAST}/owners", limit=MAX_SPONSORS
            )
        )
    )
    return (
        sponsors,
        "present" if sponsors else "absent",
        len(owners or []) if owners_readable else None,
    )


@dataclass(frozen=True)
class EntraConfig:
    """The collection app registration, read from the operator's private file."""

    directory_id: str
    client_id: str
    client_secret: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            GUID.fullmatch(self.directory_id) is None
            or GUID.fullmatch(self.client_id) is None
            or not 1 <= len(self.client_secret) <= 4096
            or not self.client_secret.isascii()
            or any(
                char.isspace() or ord(char) < 33 or ord(char) == 127 for char in self.client_secret
            )
        ):
            raise GraphError("INVALID_INPUT")

    @classmethod
    def from_file(cls, path: Path) -> "EntraConfig":
        try:
            if path.stat().st_size > 16384:
                raise ValueError
            # No ambient override or interpolation can silently change the registration.
            values = dotenv_values(path, interpolate=False)
            return cls(
                values.get("ENTRA_DIRECTORY_ID") or "",
                values.get("ENTRA_CLIENT_ID") or "",
                values.get("ENTRA_CLIENT_SECRET") or "",
            )
        except (OSError, ValueError):
            raise GraphError("INVALID_INPUT") from None


def fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _principals(reader: Reader, capabilities: dict[str, dict[str, Any]]) -> tuple[list[Any], int]:
    """Agent identities first, then classic principals; the authoritative class wins.

    ``/servicePrincipals`` lists agent identities too. Reading the agent collection first and
    keeping its answer means a principal the directory calls an agent is never downgraded to
    a classic one by the order of the walk.

    A directory with more principals than one run reads is refused whole (`AGENT_CAPACITY`),
    never read in part: a principal past a silent cut would be marked gone, then stored for
    the first time by a later read or a delta pass and reported as new (#355). That includes a
    directory under the bound that Graph serves in pages too short for the run's pages to reach
    the end of either collection.
    """
    seen: dict[str, Any] = {}
    dropped = 0
    for capability, path in zip(PRINCIPAL_COLLECTIONS, (AGENTS_PATH, PRINCIPALS_PATH), strict=True):
        if capabilities[capability]["state"] != "available":
            continue
        # One past the bound, so a collection that holds more is seen to, not cut short; and
        # whole, so one whose pages run out before it does is refused, not cut short either.
        records = list(reader.walk(path, limit=MAX_AGENTS + 1, whole="AGENT_CAPACITY"))
        if len(records) > MAX_AGENTS:
            raise GraphError("AGENT_CAPACITY")
        for record in records:
            parsed = parse_agent(record, cast_collection=capability == "agent_identities")
            if parsed is None:
                dropped += 1
                continue
            seen.setdefault(parsed.platform_ref, parsed)
    if len(seen) > MAX_AGENTS:
        raise GraphError("AGENT_CAPACITY")
    return list(seen.values()), dropped


def _as_held(record: AgentRecord, held: tuple[str, str | None] | None) -> AgentRecord:
    """A full collection's record of a principal the store holds, in the class the store holds.

    An object's type does not change in a directory, and the store's class came from a record
    that stated it. Should the directory ever contradict it, the stored class stands rather than
    the run failing the blueprint check, which only an agent identity may carry, on every
    collection after (#355). A blueprint is read only for an agent identity.
    """
    if held is None or held[0] == record.identity_class:
        return record
    return replace(
        record,
        identity_class=held[0],
        blueprint_ref=record.blueprint_ref if held[0] == "agent_identity" else None,
    )


def coverage(capabilities: dict[str, dict[str, Any]]) -> store.Coverage:
    """What this collection read of the directory's principals, for the baseline (#355).

    "whole" when both principal collections were read. "refused" when the registration is
    refused one of them outright, so no baseline can be taken until an administrator grants the
    permission. "partial" otherwise: Graph would not answer this time, and the next collection
    will most likely read both.
    """
    states = {capabilities[name]["state"] for name in PRINCIPAL_COLLECTIONS}
    if states == {"available"}:
        return "whole"
    return "refused" if states & {"forbidden", "unsupported"} else "partial"


def _reader(
    row: dict[str, Any],
    client: httpx.Client,
    client_secret: str | None,
    app: PlatformApp | None,
    clock: Clock,
) -> Reader:
    """The reader for one connection's credential, refused before anything reaches Graph when
    the credential is not the one the connection registered."""
    if row["credential_mode"] == "platform_app":
        if app is None:
            raise GraphError("COLLECTOR_KEY_UNAVAILABLE")
        if app.client_id != str(row["client_ref"]).lower():
            # Consent was given to another app; this one would be refused, or worse, read a
            # directory that never consented to it. Nothing reaches the platform.
            raise GraphError("CLIENT_MISMATCH")
        return Reader(row["directory_ref"], app.client_id, None, client, app=app, clock=clock)
    if client_secret is None or fingerprint(client_secret) != row["key_fingerprint"]:
        # A secret that is not the registered one never reaches the platform.
        raise GraphError("KEY_MISMATCH")
    return Reader(row["directory_ref"], row["client_ref"], client_secret, client)


def run(
    db: Database,
    actor: Identity | ScheduledActor,
    *,
    connection_id: UUID,
    client: httpx.Client,
    client_secret: str | None = None,
    app: PlatformApp | None = None,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, Any]:
    """One collection run; counts and codes only, never response content.

    An operator's connection is read with its own `client_secret`; a consented one with the
    platform `app`, and only when the row names that app's client id. `lease` is the
    connection's lease, which every write of the run proves (`due.claim`); a run whose lease is
    gone, or whose connection was revoked, stops at its next write. Once the directory's
    principals are written and its agent rules run, the run records who the directory declares
    drives each actor (`drivers.derive_declared`), then reads its audit log (`collect_audit`) and
    its service principal sign-ins (`collect_sign_ins`), neither of whose refusals changes the
    run's outcome.
    """
    run_id = uuid4()
    row = store.load_connection(db, actor, connection_id, lease=lease)
    if row["kind"] != "entra_agent_id":
        raise GraphError("INVALID_STATE")
    reader = _reader(row, client, client_secret, app, clock)
    now = clock.now()
    result: dict[str, Any] = {
        "run_id": str(run_id),
        "capabilities": {},
        "agents": {"agents": 0, "agent_identities": 0, "service_principals": 0, "gone": 0},
        "detail": {
            "grants": 0,
            "inherited": 0,
            "gone": 0,
            "sponsored": 0,
            "unreadable": 0,
            "reach": 0,
            "unresolved": 0,
            "reach_gone": 0,
        },
        "findings": dict.fromkeys(store.AGENT_FINDING_COUNTS, 0),
        "dropped": 0,
        "directory": "unverified",
        "delta": "unavailable",
        "audit": {"state": "not_read"},
        "sign_ins": {"state": "not_read"},
        "drivers": {"declared": 0, "gone": 0},
        "outcome": "COMPLETE",
    }
    outcome = "COMPLETE"
    error_code: str | None = None
    retry_after: int | None = None
    try:
        reader.authenticate()
        reported = verify_directory(reader)
        if reported is not None and reported.lower() != str(row["directory_ref"]).lower():
            # The registration speaks for a different directory than the row claims. Nothing
            # it returns can be attributed to this tenant's connection.
            raise GraphError("DIRECTORY_MISMATCH")
        result["directory"] = "verified" if reported is not None else "unverified"
        capabilities = probe(reader, now)
        store.record_capabilities(db, actor, connection_id, capabilities, clock=clock, lease=lease)
        result["capabilities"] = {name: value["state"] for name, value in capabilities.items()}
        if capabilities["agent_identities"]["state"] == "forbidden":
            # Reading agent identities is this run's own authority, not merely coverage.
            raise GraphError("AUTH_LOST")
        # Taken before the read, so a change made while it reads is reported again by the next
        # delta pass rather than missed, and kept only if this collection completes. Only a
        # collection that reads both principal collections takes one, as only it can be the
        # baseline a link needs. Any other takes none and leaves the stored link where the delta
        # passes left it: a link taken now would skip what changed in what it did not read.
        read = coverage(capabilities)
        link = take_link(reader) if read == "whole" else None
        records, dropped = _principals(reader, capabilities)
        result["dropped"] = dropped
        # A class is written once, from a record that states it, and is the store's after that,
        # in a full collection as in a delta pass: the detail read and every write follow it.
        held = store.held_agents(
            db,
            actor,
            connection_id,
            [record.platform_ref for record in records],
            clock=clock,
            lease=lease,
        )
        records = [_as_held(record, held.get(record.platform_ref)) for record in records]
        result["agents"] = store.apply_agents(
            db, actor, connection_id, records, clock=clock, lease=lease
        )
        result["detail"] = store.apply_agent_detail(
            db,
            actor,
            connection_id,
            detail(reader, records, capabilities),
            clock=clock,
            lease=lease,
        )
        result["findings"] = store.evaluate_agents(
            db,
            actor,
            connection_id,
            full=True,
            coverage=read,
            clock=clock,
            lease=lease,
        )
        # Who the directory itself says drives each actor, from what the store now holds.
        result["drivers"] = drivers.derive_declared(
            db, actor, connection_id, clock=clock, lease=lease
        )
        if link is not None:
            store.record_delta(db, actor, connection_id, link, clock=clock, lease=lease)
            result["delta"] = "taken"
        # What the directory's own log says its actors did. It never changes this run's outcome:
        # the run's subject is the inventory, and a refused read is retried by the next run.
        result["audit"] = collect_audit(
            db,
            actor,
            connection_id,
            reader,
            row,
            capabilities["audit_log"]["state"],
            clock=clock,
            lease=lease,
        )
        # Then the network its principals sign in from, which never changes the outcome either.
        result["sign_ins"] = collect_sign_ins(
            db,
            actor,
            connection_id,
            reader,
            capabilities["sign_ins"]["state"],
            clock=clock,
            lease=lease,
        )
    except GraphError as error:
        error_code = error.code
        retry_after = error.retry_after
        outcome = {"AUTH_LOST": "AUTH_LOST", "RATE_LIMITED": "RATE_LIMITED"}.get(
            error.code, "ERROR"
        )
    result["outcome"] = outcome
    store.record_run_outcome(
        db,
        actor,
        connection_id,
        outcome=outcome,
        run_id=run_id,
        error_code=error_code,
        retry_after=retry_after,
        synced=outcome == "COMPLETE",
        clock=clock,
        lease=lease,
    )
    return result


def run_delta(
    db: Database,
    actor: Identity | ScheduledActor,
    *,
    connection_id: UUID,
    client: httpx.Client,
    client_secret: str | None = None,
    app: PlatformApp | None = None,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, Any]:
    """One delta pass between full collections (#355); counts and codes only.

    It reads everything it needs from the directory first: the round from the connection's
    stored link, then the grants, roles and accountability of every principal the round lists.
    Only then does it write, in order: the principals it listed and removed, their grants and
    accountability, the agent rules, and last the new link, so a pass that stops part way
    leaves the old link and the next pass reads the same changes again. It never writes the
    run's outcome, `last_run_at` or `last_sync_at`, so it never moves the schedule and never
    changes the connection's health. A resync, a link that is not the pinned read and a round
    past its bounds drop the link for the next full collection to replace; any other refusal
    from Graph, a page that cannot be read among them, keeps it and, arriving before the first
    write, writes nothing. A pass that completes then reads the directory's audit log and its
    sign-ins as a full collection does, unless the last probe found either refused.
    """
    row = store.load_connection(db, actor, connection_id, lease=lease)
    if row["kind"] != "entra_agent_id" or row["delta_link"] is None or row["baseline_at"] is None:
        raise GraphError("INVALID_STATE")
    reader = _reader(row, client, client_secret, app, clock)
    result: dict[str, Any] = {
        "outcome": "COMPLETE",
        "error_code": None,
        "link": "kept",
        "changes": {"listed": 0, "new": 0, "restored": 0, "gone": 0},
        "detail": {},
        "findings": dict.fromkeys(store.AGENT_FINDING_COUNTS, 0),
        "dropped": 0,
        "deferred": 0,
        "audit": {"state": "not_read"},
        "sign_ins": {"state": "not_read"},
        "drivers": {"declared": 0, "gone": 0},
    }

    def resync(code: str) -> dict[str, Any]:
        store.record_delta(db, actor, connection_id, None, clock=clock, lease=lease)
        result.update(outcome="RESYNC", error_code=code, link="dropped")
        return result

    try:
        query = delta_query(row["delta_link"])
    except GraphError as error:
        # Stored, and still not a link this collector would have stored: never sent.
        return resync(error.code)
    try:
        reader.authenticate()
        reported = verify_directory(reader)
        if reported is not None and reported.lower() != str(row["directory_ref"]).lower():
            raise GraphError("DIRECTORY_MISMATCH")
        try:
            found = read_delta(reader, query)
        except GraphError as error:
            if error.code in RESYNC or isinstance(error, LinkRefused):
                return resync(error.code)
            raise
        held = store.held_agents(
            db,
            actor,
            connection_id,
            [record.platform_ref for record in found.listed],
            clock=clock,
            lease=lease,
        )
        # The class and blueprint of a principal the store holds are the store's: an updated
        # instance carries only some of its properties, and which collection reads sponsors
        # rather than owners follows them. One the store does not hold is stored with the class
        # its entry states; an entry that states none is left for the full collection, whose
        # cast collection says whether it is an agent identity, rather than stored as a classic
        # principal for good.
        listed = [
            replace(
                record,
                identity_class=held[record.platform_ref][0],
                blueprint_ref=held[record.platform_ref][1],
            )
            if record.platform_ref in held
            else record
            for record in found.listed
            if record.platform_ref in held or record.class_stated
        ]
        result["deferred"] = len(found.listed) - len(listed)
        # What the last probe established; a delta pass does not probe again.
        stored = row["capabilities"] if isinstance(row["capabilities"], dict) else {}
        capabilities: dict[str, dict[str, Any]] = {}
        for name in CAPABILITIES:
            recorded = stored.get(name)
            capabilities[name] = recorded if isinstance(recorded, dict) else {"state": "unknown"}
        details = detail(
            reader,
            listed,
            capabilities,
            read_blueprints=any(record.blueprint_ref for record in listed),
        )
        # Everything this pass reads from the directory is read; from here on it writes.
        result["dropped"] = found.dropped
        try:
            result["changes"] = store.apply_agent_changes(
                db, actor, connection_id, listed, found.removed, clock=clock, lease=lease
            )
        except MonitorError as error:
            # The round would take the directory past what a full collection reads: nothing of
            # it was written, and the next full collection refuses the directory where the
            # Connections view shows it.
            if error.code != "AGENT_CAPACITY":
                raise
            return resync(error.code)
        result["detail"] = store.apply_agent_detail(
            db, actor, connection_id, details, only_listed=True, clock=clock, lease=lease
        )
        result["findings"] = store.evaluate_agents(
            db, actor, connection_id, full=False, clock=clock, lease=lease
        )
        result["drivers"] = drivers.derive_declared(
            db, actor, connection_id, clock=clock, lease=lease
        )
        store.record_delta(db, actor, connection_id, found.link, clock=clock, lease=lease)
        result["link"] = "advanced"
        # Then the audit log, under what the last probe established, and never changing the
        # pass's own outcome, as in a full collection.
        audit = capabilities.get("audit_log") or {}
        result["audit"] = collect_audit(
            db, actor, connection_id, reader, row, audit.get("state"), clock=clock, lease=lease
        )
        sign_ins = capabilities.get("sign_ins") or {}
        result["sign_ins"] = collect_sign_ins(
            db, actor, connection_id, reader, sign_ins.get("state"), clock=clock, lease=lease
        )
    except GraphError as error:
        result["outcome"] = {"AUTH_LOST": "AUTH_LOST", "RATE_LIMITED": "RATE_LIMITED"}.get(
            error.code, "ERROR"
        )
        result["error_code"] = error.code
    return result
