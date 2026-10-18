# SPDX-License-Identifier: AGPL-3.0-only
"""Owner-connection administration of tenants, principals, credentials, approvers, groups,
executor keys and the connector registry (accounts, mappings, canonical targets and resources).

These operations run with the database owner role that provisions authority data.
They never sit behind an HTTP route, never print a secret, and audit every change
under an ADMIN principal of the tenant. The first ADMIN principal of a tenant is
audited as its own actor because no other principal exists yet.
"""

import os
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, get_args
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from execbound.audit import append_event
from execbound.connection import connect_args, database_url
from execbound.contracts import PRODUCTION_CATALOG, Column, ContractError, FactSpec
from execbound.domains import IntegerDomain, StringDomain
from execbound.identity import new_token
from execbound.operations import PRODUCTION_ACTIONS, CatalogError, ResourceType
from execbound.passwords import (
    DEFAULT_RESET_LIFETIME,
    MAX_RESET_LIFETIME,
    MIN_RESET_LIFETIME,
    normalize_email,
    reset_code,
)
from execbound.policy.models import MAX_GROUPS
from execbound.policy.store import LIVE_EXECUTOR_KEY
from execbound.provider.executor import (
    ALGORITHMS,
    COMPROMISED,
    ED25519,
    ES256,
    RETIRED,
    es256_public_key,
    forgeable_public_key,
)
from execbound.provider.published_keys import published_executor_key
from execbound.requests import ResourceSelector
from execbound.secrets import secret_shaped
from execbound.spaces import MAX_NAME_LENGTH as MAX_SPACE_NAME_LENGTH
from execbound.spaces import provision_default_space

PrincipalKind = Literal["AGENT", "HUMAN_APPROVER", "ADMIN"]
PRINCIPAL_KINDS: frozenset[str] = frozenset(get_args(PrincipalKind))
ACTIONS: frozenset[str] = PRODUCTION_ACTIONS.names
MIN_CREDENTIAL_LIFETIME = timedelta(minutes=1)
MAX_CREDENTIAL_LIFETIME = timedelta(days=90)
MAX_NAME_LENGTH = 120
MAX_GROUP_NAME_LENGTH = 80
# One bound for provisioning and the capture model, so a capture never exceeds the payload limit.
MAX_GROUP_MEMBERSHIPS = MAX_GROUPS
# The CHECK constraints of migration 0025, restated so a malformed value is refused here
# rather than by a constraint violation whose error text would quote the offending row.
# A key id names one key for its lifetime; a public key is the executor's raw 32-byte
# Ed25519 key in hex, stored lowercase, and uppercase input is normalized rather than refused.
# The shape is all a pattern can say: `forgeable_public_key` is what refuses a small-order
# or non-canonical point, which no pattern and no CHECK constraint can express.
_KEY_ID = re.compile(r"[a-zA-Z0-9_.-]{1,64}")
_PUBLIC_KEY = re.compile(r"[0-9a-fA-F]{64}")
# Whether any space's selected bundle declares an operation an external executor
# performs. A tenant's key ring is one ring, never one per space, so a checkpoint in any
# space keeps the last key attestable.
# One literal with the tenant bound as a parameter; the flag is serialized only when true,
# so its presence is the declaration.
_ACTIVE_CHECKPOINT = (
    "SELECT 1 FROM execbound.space_policy_selection c "
    "JOIN execbound.policy_bundle_contents b "
    "ON b.tenant_id = c.tenant_id AND b.bundle_id = c.bundle_id "
    "WHERE c.tenant_id = :t AND jsonb_path_exists(b.content, "
    "'$.mappings[*] ? (@.external_executor == true)') LIMIT 1"
)


class AdministrationError(ValueError):
    """Safe code only; owner-connection diagnostics never escape."""

    def __init__(self, code: str = "ADMINISTRATION_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Administration unavailable")


@dataclass(frozen=True)
class CredentialSummary:
    credential_id: UUID
    principal_id: UUID
    kind: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    failures_24h: int


@dataclass(frozen=True)
class FailureSummary:
    surface: str
    reason: str
    window_start: datetime
    subject_kind: str | None
    subject_id: UUID | None
    count: int
    first_at: datetime
    last_at: datetime


@dataclass(frozen=True)
class GroupSummary:
    group_id: UUID
    name: str
    created_at: datetime
    members: tuple[UUID, ...]


@dataclass(frozen=True)
class ExecutorKeySummary:
    """One registered key. The public key is listed because nothing here is secret, and
    the revocation reason because a retired key and a compromised one differ in exactly
    what an operator needs to know: the first still attests the grants it covered.
    `published` marks one of the executor protocol's published test keys, which a ring can
    hold only from before registration refused them and which attests nothing, so an
    operator can tell which row to revoke."""

    key_id: str
    algorithm: str
    public_key: str
    created_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None
    published: bool = False


# Tenant context for reading unattributed rows; matches identity.UNATTRIBUTED_CONTEXT.
_UNATTRIBUTED_CONTEXT = UUID("00000000-0000-4000-8000-000000000000")
_FAILURE_COLUMNS = (
    "SELECT surface, reason, window_start, subject_kind, subject_id, count, first_at, last_at "
    "FROM execbound.authentication_failures WHERE window_start >= :start AND "
)
_FAILURE_ORDER = " ORDER BY window_start DESC, surface, reason, subject_id"
_TENANT_FAILURES = _FAILURE_COLUMNS + "tenant_id = :tenant" + _FAILURE_ORDER
_UNATTRIBUTED_FAILURES = _FAILURE_COLUMNS + "tenant_id IS NULL" + _FAILURE_ORDER


@dataclass(frozen=True)
class IssuedCredential:
    """What the operator may see; the token itself lives only in the output file."""

    credential_id: UUID
    principal_id: UUID
    kind: str
    expires_at: datetime
    output: Path


def owner_engine(url: str) -> Engine:
    """An engine for the owner role; ownership is verified inside every transaction."""
    parsed = database_url(url)
    return create_engine(parsed, hide_parameters=True, connect_args=connect_args(parsed))


@contextmanager
def _tenant_transaction(engine: Engine, tenant: UUID) -> Iterator[Connection]:
    try:
        with engine.begin() as conn:
            conn.execute(text("SELECT set_config('statement_timeout', '10000', true)"))
            conn.execute(text("SELECT set_config('lock_timeout', '5000', true)"))
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :tenant, true)"),
                {"tenant": str(tenant)},
            )
            owner = conn.execute(
                text(
                    "SELECT current_user = (SELECT tableowner FROM pg_tables "
                    "WHERE schemaname = 'execbound' AND tablename = 'tenants')"
                )
            ).scalar_one()
            if owner is not True:
                raise AdministrationError("INVALID_CONNECTION")
            yield conn
    except AdministrationError:
        raise
    except (SQLAlchemyError, ValueError):
        raise AdministrationError() from None


def _tenant(conn: Connection, tenant: UUID) -> None:
    active = conn.execute(
        text("SELECT active FROM execbound.tenants WHERE tenant_id = :tenant"),
        {"tenant": tenant},
    ).scalar_one_or_none()
    if active is not True:
        raise AdministrationError("INVALID_TENANT")


def _principal(conn: Connection, tenant: UUID, principal: UUID) -> str:
    kind = conn.execute(
        text(
            "SELECT kind FROM execbound.principals "
            "WHERE tenant_id = :tenant AND principal_id = :principal AND active "
            # A workspace's scheduler principal (#503) is nobody the owner CLI acts on or for.
            "AND kind <> 'SYSTEM'"
        ),
        {"tenant": tenant, "principal": principal},
    ).scalar_one_or_none()
    if kind is None:
        raise AdministrationError("INVALID_PRINCIPAL")
    return str(kind)


def _actor(conn: Connection, tenant: UUID, actor: UUID) -> None:
    from execbound.access_control import has_permission

    _fence(conn, tenant)
    if not has_permission(conn, tenant, actor, "workspace.manage", any_scope=True):
        raise AdministrationError("INVALID_ACTOR")


def _fence(conn: Connection, tenant: UUID) -> None:
    """Hold the tenant fence store.fence takes, so a membership change is ordered against
    every decision that reads memberships under it."""
    conn.execute(
        text(
            "INSERT INTO execbound.tenant_policy_control(tenant_id, changed_at) "
            "VALUES (:t, :now) ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"t": tenant, "now": datetime.now(UTC)},
    )
    conn.execute(
        text("SELECT tenant_id FROM execbound.tenant_policy_control WHERE tenant_id=:t FOR UPDATE"),
        {"t": tenant},
    ).one()


def _space_for(conn: Connection, tenant: UUID, space: UUID | None) -> UUID:
    """One space of this tenant: the one named, or its only one when none was named."""
    if space is None:
        spaces = (
            conn.execute(
                text(
                    "SELECT space_id FROM execbound.spaces WHERE tenant_id=:t "
                    "ORDER BY created_at, space_id"
                ),
                {"t": tenant},
            )
            .scalars()
            .all()
        )
        if len(spaces) != 1:
            raise AdministrationError("INVALID_SPACE")
        return UUID(str(spaces[0]))
    known = conn.execute(
        text("SELECT 1 FROM execbound.spaces WHERE tenant_id=:t AND space_id=:s"),
        {"t": tenant, "s": space},
    ).scalar_one_or_none()
    if known is None:
        raise AdministrationError("INVALID_SPACE")
    return space


def _instant(value: datetime | None) -> datetime:
    now = value or datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise AdministrationError("INVALID_CLOCK")
    return now.astimezone(UTC)


def create_tenant(engine: Engine, name: str, *, tenant_id: UUID | None = None) -> UUID:
    """Create an active tenant. Nothing can be audited before its first principal exists.

    `tenant_id` lets a caller that already named this tenant create it: `execbound init`
    writes a private configuration naming one tenant before any database exists, and
    `quickstart` makes the rows agree with the file rather than the other way round. An id
    already taken is the database's own refusal, not a check here, so two callers racing on
    one id cannot both succeed.
    """
    if type(name) is not str or not 1 <= len(name.strip()) <= MAX_NAME_LENGTH:
        raise AdministrationError("INVALID_NAME")
    tenant = uuid4() if tenant_id is None else tenant_id
    with _tenant_transaction(engine, tenant) as conn:
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:tenant, :name)"),
            {"tenant": tenant, "name": name.strip()},
        )
        # Every tenant has exactly one space from the moment it exists, so every column
        # that carries one has an unambiguous value. Its creator is the zero principal
        # because nothing can be audited before the tenant's first ADMIN exists.
        provision_default_space(conn, tenant, UUID(int=0))
    return tenant


def create_principal(
    engine: Engine,
    tenant: UUID,
    kind: str,
    actor: UUID | None = None,
    *,
    space: UUID | None = None,
) -> UUID:
    """Create a principal. Only a tenant's first ADMIN may be created without an actor.

    An agent is owned by one space and a person is a member of spaces, so ``space`` is
    required exactly when the kind is `AGENT`; a caller that names none gets the tenant's
    only space, which is what every tenant has until it makes a second.
    """
    if kind not in PRINCIPAL_KINDS:
        raise AdministrationError("INVALID_KIND")
    principal = uuid4()
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        if actor is None:
            existing = conn.execute(
                text(
                    "SELECT count(*) FROM execbound.principals "
                    "WHERE tenant_id = :tenant AND kind = 'ADMIN' AND active"
                ),
                {"tenant": tenant},
            ).scalar_one()
            if kind != "ADMIN" or existing:
                raise AdministrationError("INVALID_ACTOR")
        else:
            _actor(conn, tenant, actor)
        placed = _space_for(conn, tenant, space) if kind != "ADMIN" else None
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, space_id) "
                "VALUES (:tenant, :principal, :kind, :space)"
            ),
            {
                "tenant": tenant,
                "principal": principal,
                "kind": kind,
                "space": placed if kind == "AGENT" else None,
            },
        )
        if kind == "HUMAN_APPROVER":
            # A person is a member of spaces rather than owned by one; an administrator
            # gets no membership at all, which is what makes them a tenant administrator.
            conn.execute(
                text(
                    "INSERT INTO execbound.space_members"
                    "(tenant_id, space_id, principal_id, role, assigned_at) "
                    "VALUES (:tenant, :space, :principal, 'HUMAN_APPROVER', now())"
                ),
                {"tenant": tenant, "space": placed, "principal": principal},
            )
        append_event(
            conn,
            tenant,
            actor or principal,
            "principal.created",
            {"principal_id": str(principal), "kind": kind},
            space=placed,
        )
    return principal


def issue_credential(
    engine: Engine,
    tenant: UUID,
    principal: UUID,
    actor: UUID,
    *,
    lifetime: timedelta,
    output: Path,
    now: datetime | None = None,
) -> IssuedCredential:
    """Issue a credential and write its token once to a new private file.

    The file is created exclusively with owner-only permissions before the row is
    committed; any failure removes the file again, so a token never outlives a
    credential that was not created.
    """
    if not MIN_CREDENTIAL_LIFETIME <= lifetime <= MAX_CREDENTIAL_LIFETIME:
        raise AdministrationError("INVALID_LIFETIME")
    issued_at = _instant(now)
    expires_at = issued_at + lifetime
    credential = uuid4()
    token, digest = new_token(tenant, credential)
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        raise AdministrationError("OUTPUT_UNAVAILABLE") from None
    closed = False
    try:
        with _tenant_transaction(engine, tenant) as conn:
            _tenant(conn, tenant)
            _actor(conn, tenant, actor)
            kind = _principal(conn, tenant, principal)
            conn.execute(
                text(
                    "INSERT INTO execbound.credentials "
                    "(tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at) "
                    "VALUES (:tenant, :credential, :principal, :digest, :issued, :expires)"
                ),
                {
                    "tenant": tenant,
                    "credential": credential,
                    "principal": principal,
                    "digest": digest,
                    "issued": issued_at,
                    "expires": expires_at,
                },
            )
            append_event(
                conn,
                tenant,
                actor,
                "credential.issued",
                {
                    "credential_id": str(credential),
                    "principal_id": str(principal),
                    "kind": kind,
                    "expires_at": expires_at.isoformat(),
                },
            )
            pending = (token + "\n").encode("ascii")
            while pending:
                pending = pending[os.write(descriptor, pending) :]
            os.fsync(descriptor)
            os.close(descriptor)
            closed = True
    except BaseException:
        if not closed:
            os.close(descriptor)
        output.unlink(missing_ok=True)
        raise
    return IssuedCredential(credential, principal, kind, expires_at, output)


def list_credentials(engine: Engine, tenant: UUID) -> tuple[CredentialSummary, ...]:
    """Every credential of the tenant with its principal kind; digests are never read."""
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        rows = (
            conn.execute(
                text(
                    "SELECT c.credential_id, c.principal_id, p.kind, c.issued_at, "
                    "c.expires_at, c.revoked_at, COALESCE((SELECT sum(f.count) "
                    "FROM execbound.authentication_failures f "
                    "WHERE f.tenant_id = c.tenant_id AND f.subject_kind = 'credential' "
                    "AND f.subject_id = c.credential_id AND f.window_start >= :since), 0) "
                    "AS failures_24h FROM execbound.credentials c "
                    "JOIN execbound.principals p USING (tenant_id, principal_id) "
                    "WHERE c.tenant_id = :tenant ORDER BY c.issued_at DESC, c.credential_id"
                ),
                {"tenant": tenant, "since": datetime.now(UTC) - timedelta(hours=24)},
            )
            .mappings()
            .all()
        )
    return tuple(
        CredentialSummary(
            row["credential_id"],
            row["principal_id"],
            row["kind"],
            row["issued_at"],
            row["expires_at"],
            row["revoked_at"],
            int(row["failures_24h"]),
        )
        for row in rows
    )


def list_failures(
    engine: Engine, tenant: UUID | None, *, since: timedelta
) -> tuple[FailureSummary, ...]:
    """A tenant's attributed failure windows, or the unattributed ones when tenant is None."""
    if not timedelta(0) < since <= timedelta(days=90):
        raise AdministrationError("INVALID_WINDOW")
    start = datetime.now(UTC) - since
    with _tenant_transaction(engine, tenant or _UNATTRIBUTED_CONTEXT) as conn:
        if tenant is not None:
            _tenant(conn, tenant)
        query = _UNATTRIBUTED_FAILURES if tenant is None else _TENANT_FAILURES
        parameters = {"start": start} if tenant is None else {"start": start, "tenant": tenant}
        rows = conn.execute(text(query), parameters).mappings().all()
    return tuple(
        FailureSummary(
            row["surface"],
            row["reason"],
            row["window_start"],
            row["subject_kind"],
            row["subject_id"],
            int(row["count"]),
            row["first_at"],
            row["last_at"],
        )
        for row in rows
    )


def screened_label(label: str | None) -> str | None:
    """A principal's label as `principal.labelled` will carry it: refused, unquoted, where it
    is shaped like a secret, because the event export would refuse that event for good. `None`
    passes through untouched, so an optional label's caller need not guard the call itself."""
    if label is not None and secret_shaped(label):
        raise AdministrationError("INVALID_LABEL")
    return label


@dataclass(frozen=True)
class InvitedPerson:
    """What the operator may see; the code itself lives only in the output file."""

    principal_id: UUID
    kind: str
    email: str
    created: bool
    reset_id: UUID
    expires_at: datetime
    address: str
    output: Path


def invite_person(
    engine: Engine,
    tenant: UUID,
    email: str,
    kind: str,
    *,
    label: str | None = None,
    actor: UUID | None = None,
    lifetime: timedelta = DEFAULT_RESET_LIFETIME,
    origin: str,
    output: Path,
    now: datetime | None = None,
) -> InvitedPerson:
    """Find or create a person by address, and write one set-password code to a new file.

    This is the bootstrap: an operator holding the owner connection and no credential can
    give themselves an ADMIN person and a code, then sign in with a password like anybody
    else. `--actor` is required exactly where `principal-create` requires it, so a tenant
    that already has an administrator cannot gain another without one auditing the change.

    The file is created exclusively with owner-only permissions before the rows are
    committed, and any failure removes it, so a code never outlives the row it belongs to.
    The code is written to the file and never printed, exactly as `credential-issue` does
    with a token; the address to open is printed instead, because a code in a link is a
    code in a log.
    """
    if kind not in {"ADMIN", "HUMAN_APPROVER"}:
        raise AdministrationError("INVALID_KIND")
    if not MIN_RESET_LIFETIME <= lifetime <= MAX_RESET_LIFETIME:
        raise AdministrationError("INVALID_LIFETIME")
    normalized = normalize_email(email)
    if normalized is None:
        raise AdministrationError("INVALID_EMAIL")
    # Only the domain reaches `person.email_set`, so only the domain is screened, and the
    # value screened here is the exact value the event below carries.
    domain = normalized.rsplit("@", 1)[1]
    if secret_shaped(domain):
        raise AdministrationError("INVALID_EMAIL")
    if label is not None and not 1 <= len(label.strip()) <= MAX_GROUP_NAME_LENGTH:
        raise AdministrationError("INVALID_LABEL")
    screened_label(label)
    issued_at = _instant(now)
    expires_at = issued_at + lifetime
    reset_id = uuid4()
    code, digest = reset_code(tenant, reset_id)
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        raise AdministrationError("OUTPUT_UNAVAILABLE") from None
    closed = False
    try:
        with _tenant_transaction(engine, tenant) as conn:
            _tenant(conn, tenant)
            principal, created = _person_for(conn, tenant, normalized, kind, actor)
            if actor is not None:
                _actor(conn, tenant, actor)
            attribution = actor or principal
            if created:
                append_event(
                    conn,
                    tenant,
                    attribution,
                    "principal.created",
                    {"principal_id": str(principal), "kind": kind},
                )
                append_event(
                    conn,
                    tenant,
                    attribution,
                    "person.email_set",
                    {
                        "principal_id": str(principal),
                        "domain": domain,
                    },
                )
            if label is not None:
                conn.execute(
                    text(
                        "UPDATE execbound.principals SET label = :label "
                        "WHERE tenant_id = :tenant AND principal_id = :principal"
                    ),
                    {"tenant": tenant, "principal": principal, "label": label.strip()},
                )
                append_event(
                    conn,
                    tenant,
                    attribution,
                    "principal.labelled",
                    {"principal_id": str(principal), "label": label.strip()},
                )
            # At most one live code per person, as the console's action also leaves it.
            conn.execute(
                text(
                    "UPDATE execbound.password_resets SET revoked_at = :now "
                    "WHERE tenant_id = :tenant AND principal_id = :principal "
                    "AND redeemed_at IS NULL AND revoked_at IS NULL"
                ),
                {"tenant": tenant, "principal": principal, "now": issued_at},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.password_resets (tenant_id, reset_id, principal_id, "
                    "token_hash, created_by, created_at, expires_at) "
                    "VALUES (:tenant, :reset, :principal, :digest, :actor, :issued, :expires)"
                ),
                {
                    "tenant": tenant,
                    "reset": reset_id,
                    "principal": principal,
                    "digest": digest,
                    "actor": attribution,
                    "issued": issued_at,
                    "expires": expires_at,
                },
            )
            append_event(
                conn,
                tenant,
                attribution,
                "password.reset_issued",
                {
                    "principal_id": str(principal),
                    "reset_id": str(reset_id),
                    "expires_at": expires_at.isoformat(),
                },
            )
            pending = (code + "\n").encode("ascii")
            while pending:
                pending = pending[os.write(descriptor, pending) :]
            os.fsync(descriptor)
            os.close(descriptor)
            closed = True
    except BaseException:
        if not closed:
            os.close(descriptor)
        output.unlink(missing_ok=True)
        raise
    return InvitedPerson(
        principal,
        kind,
        normalized,
        created,
        reset_id,
        expires_at,
        origin.rstrip("/") + "/set-password",
        output,
    )


def _person_for(
    conn: Connection, tenant: UUID, email: str, kind: str, actor: UUID | None
) -> tuple[UUID, bool]:
    """The active person holding this address in this tenant, or a new one of that kind.

    An address another tenant holds is refused rather than reused: the sign-in index is
    global, so one address is one person, and quietly taking somebody else's would be the
    one way an owner command could give a stranger a code for a live account.
    """
    existing = (
        conn.execute(
            text(
                "SELECT principal_id, kind, active FROM execbound.principals "
                "WHERE tenant_id = :tenant AND email = :email"
            ),
            {"tenant": tenant, "email": email},
        )
        .mappings()
        .one_or_none()
    )
    if existing is not None:
        if existing["kind"] != kind or not existing["active"]:
            raise AdministrationError("INVALID_PRINCIPAL")
        return UUID(str(existing["principal_id"])), False
    if actor is None:
        held = conn.execute(
            text(
                "SELECT count(*) FROM execbound.principals "
                "WHERE tenant_id = :tenant AND kind = 'ADMIN' AND active"
            ),
            {"tenant": tenant},
        ).scalar_one()
        if kind != "ADMIN" or held:
            raise AdministrationError("INVALID_ACTOR")
    principal = uuid4()
    conn.execute(
        text(
            "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
            "VALUES (:tenant, :principal, :kind)"
        ),
        {"tenant": tenant, "principal": principal, "kind": kind},
    )
    if kind == "HUMAN_APPROVER":
        # An invited approver is seated in the tenant's space, as migration 0041 seats
        # every approver that already existed; an invited administrator gets no
        # membership, which is what makes them a tenant administrator.
        conn.execute(
            text(
                "INSERT INTO execbound.space_members"
                "(tenant_id, space_id, principal_id, role, assigned_at) "
                "VALUES (:tenant, :space, :principal, 'HUMAN_APPROVER', now())"
            ),
            {"tenant": tenant, "space": _space_for(conn, tenant, None), "principal": principal},
        )
    # The sign-in index is global, so the one way this can fail is an address another
    # tenant's person already holds. Naming that is the whole point of the refusal.
    with conn.begin_nested():
        try:
            conn.execute(
                text(
                    "UPDATE execbound.principals SET email = :email "
                    "WHERE tenant_id = :tenant AND principal_id = :principal"
                ),
                {"tenant": tenant, "principal": principal, "email": email},
            )
        except IntegrityError:
            raise AdministrationError("EMAIL_TAKEN") from None
    return principal, True


def revoke_credential(
    engine: Engine, tenant: UUID, credential: UUID, actor: UUID, *, now: datetime | None = None
) -> None:
    """Revoke a live credential; sessions and continuations backed by it stop verifying."""
    revoked_at = _instant(now)
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        updated = conn.execute(
            text(
                "UPDATE execbound.credentials SET revoked_at = :now "
                "WHERE tenant_id = :tenant AND credential_id = :credential "
                "AND revoked_at IS NULL"
            ),
            {"now": revoked_at, "tenant": tenant, "credential": credential},
        ).rowcount
        if updated != 1:
            raise AdministrationError("INVALID_CREDENTIAL")
        append_event(conn, tenant, actor, "credential.revoked", {"credential_id": str(credential)})


def assign_approver(
    engine: Engine,
    tenant: UUID,
    approver: UUID,
    canonical_target: UUID,
    action: str,
    actor: UUID,
    *,
    space: UUID | None = None,
) -> None:
    """Assign, or reactivate, one approver for one canonical target and action.

    A scope belongs to one space: an approver may hold it in one and not another. A
    caller that names no space gets the tenant's only one.
    """
    if action not in ACTIONS:
        raise AdministrationError("INVALID_ACTION")
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        if _principal(conn, tenant, approver) not in {"HUMAN_APPROVER", "ADMIN"}:
            raise AdministrationError("INVALID_PRINCIPAL")
        known = conn.execute(
            text(
                "SELECT 1 FROM execbound.canonical_targets "
                "WHERE tenant_id = :tenant AND canonical_target_id = :target"
            ),
            {"tenant": tenant, "target": canonical_target},
        ).scalar_one_or_none()
        if known is None:
            raise AdministrationError("INVALID_TARGET")
        placed = _space_for(conn, tenant, space)
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes "
                "(tenant_id, approver_id, canonical_target_id, action, active, space_id) "
                "VALUES (:tenant, :approver, :target, :action, true, :space) "
                "ON CONFLICT (tenant_id, approver_id, canonical_target_id, action) "
                "DO UPDATE SET active = true, space_id = excluded.space_id"
            ),
            {
                "tenant": tenant,
                "approver": approver,
                "target": canonical_target,
                "action": action,
                "space": placed,
            },
        )
        append_event(
            conn,
            tenant,
            actor,
            "approval_scope.assigned",
            {
                "approver_id": str(approver),
                "canonical_target_id": str(canonical_target),
                "action": action,
            },
            space=placed,
        )


def unassign_approver(
    engine: Engine, tenant: UUID, approver: UUID, canonical_target: UUID, action: str, actor: UUID
) -> None:
    """Deactivate one assignment; pending decisions under it fail their scope check."""
    if action not in ACTIONS:
        raise AdministrationError("INVALID_ACTION")
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        updated = conn.execute(
            text(
                "UPDATE execbound.approval_scopes SET active = false "
                "WHERE tenant_id = :tenant AND approver_id = :approver "
                "AND canonical_target_id = :target AND action = :action AND active"
            ),
            {"tenant": tenant, "approver": approver, "target": canonical_target, "action": action},
        ).rowcount
        if updated != 1:
            raise AdministrationError("INVALID_SCOPE")
        append_event(
            conn,
            tenant,
            actor,
            "approval_scope.revoked",
            {
                "approver_id": str(approver),
                "canonical_target_id": str(canonical_target),
                "action": action,
            },
        )


def create_group(engine: Engine, tenant: UUID, name: str, actor: UUID) -> UUID:
    """Create an empty group; names are unique within the tenant."""
    # Names are stored trimmed, like tenant names, so padding cannot mint a lookalike.
    if type(name) is not str or not 1 <= len(name.strip()) <= MAX_GROUP_NAME_LENGTH:
        raise AdministrationError("INVALID_NAME")
    name = name.strip()
    if secret_shaped(name):
        raise AdministrationError("INVALID_NAME")
    group = uuid4()
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        taken = conn.execute(
            text("SELECT 1 FROM execbound.principal_groups WHERE tenant_id=:t AND name=:n"),
            {"t": tenant, "n": name},
        ).scalar_one_or_none()
        if taken is not None:
            raise AdministrationError("INVALID_NAME")
        conn.execute(
            text(
                "INSERT INTO execbound.principal_groups (tenant_id, group_id, name, created_at) "
                "VALUES (:t, :g, :n, :now)"
            ),
            {"t": tenant, "g": group, "n": name, "now": datetime.now(UTC)},
        )
        append_event(conn, tenant, actor, "group.created", {"group_id": str(group), "name": name})
    return group


def assign_group(engine: Engine, tenant: UUID, group: UUID, principal: UUID, actor: UUID) -> None:
    """Add one active AGENT to a group; a principal holds at most MAX_GROUP_MEMBERSHIPS."""
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        _fence(conn, tenant)
        if _principal(conn, tenant, principal) != "AGENT":
            raise AdministrationError("INVALID_PRINCIPAL")
        known = conn.execute(
            text("SELECT 1 FROM execbound.principal_groups WHERE tenant_id=:t AND group_id=:g"),
            {"t": tenant, "g": group},
        ).scalar_one_or_none()
        if known is None:
            raise AdministrationError("INVALID_GROUP")
        memberships = (
            conn.execute(
                text(
                    "SELECT group_id FROM execbound.principal_group_members "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": tenant, "p": principal},
            )
            .scalars()
            .all()
        )
        if group in memberships or len(memberships) >= MAX_GROUP_MEMBERSHIPS:
            raise AdministrationError("INVALID_MEMBERSHIP")
        conn.execute(
            text(
                "INSERT INTO execbound.principal_group_members "
                "(tenant_id, group_id, principal_id, assigned_at) VALUES (:t, :g, :p, :now)"
            ),
            {"t": tenant, "g": group, "p": principal, "now": datetime.now(UTC)},
        )
        append_event(
            conn,
            tenant,
            actor,
            "group.assigned",
            {"group_id": str(group), "principal_id": str(principal)},
        )


def unassign_group(engine: Engine, tenant: UUID, group: UUID, principal: UUID, actor: UUID) -> None:
    """Delete one membership; the audit chain and retained impact rows keep its history."""
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        _fence(conn, tenant)
        deleted = conn.execute(
            text(
                "DELETE FROM execbound.principal_group_members "
                "WHERE tenant_id=:t AND group_id=:g AND principal_id=:p"
            ),
            {"t": tenant, "g": group, "p": principal},
        ).rowcount
        if deleted != 1:
            raise AdministrationError("INVALID_MEMBERSHIP")
        append_event(
            conn,
            tenant,
            actor,
            "group.revoked",
            {"group_id": str(group), "principal_id": str(principal)},
        )


@dataclass(frozen=True)
class SpaceSummary:
    """One space of a tenant, with how many people are seated in it."""

    space_id: UUID
    name: str
    detail: str | None
    created_at: datetime
    archived_at: datetime | None
    members: tuple[UUID, ...]


def _space_actor(conn: Connection, tenant: UUID, actor: UUID) -> None:
    """A **tenant** administrator: an active ADMIN principal with no membership at all.

    The definer functions decide this too; the owner path states it for itself so an
    operator gets the same refusal as the console rather than a constraint violation.
    """
    _actor(conn, tenant, actor)
    seated = conn.execute(
        text(
            "SELECT 1 FROM execbound.space_members WHERE tenant_id=:t AND principal_id=:p LIMIT 1"
        ),
        {"t": tenant, "p": actor},
    ).scalar_one_or_none()
    if seated is not None:
        raise AdministrationError("INVALID_ACTOR")


def create_space(
    engine: Engine, tenant: UUID, name: str, actor: UUID, *, detail: str | None = None
) -> UUID:
    """Create a space. Owner commands write the same events the console writes (SP14), with
    `credential=None`: the owner connection acts with no credential, so none is named."""
    from execbound.spaces import SpaceError
    from execbound.spaces import create_space as _create

    if type(name) is not str or not 1 <= len(name.strip()) <= MAX_SPACE_NAME_LENGTH:
        raise AdministrationError("INVALID_NAME")
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _space_actor(conn, tenant, actor)
        _fence(conn, tenant)
        try:
            return _create(conn, tenant, actor, name.strip(), detail, credential=None)
        except SpaceError as exc:
            raise AdministrationError(exc.code) from None


def _space_change(engine: Engine, tenant: UUID, actor: UUID, action: Any) -> None:
    from execbound.spaces import SpaceError

    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _space_actor(conn, tenant, actor)
        _fence(conn, tenant)
        try:
            action(conn)
        except SpaceError as exc:
            raise AdministrationError(exc.code) from None


def rename_space(
    engine: Engine,
    tenant: UUID,
    space: UUID,
    name: str,
    actor: UUID,
    *,
    detail: str | None = None,
) -> None:
    from execbound.spaces import rename_space as _rename

    if type(name) is not str or not 1 <= len(name.strip()) <= MAX_SPACE_NAME_LENGTH:
        raise AdministrationError("INVALID_NAME")
    _space_change(
        engine,
        tenant,
        actor,
        lambda conn: _rename(conn, tenant, actor, space, name.strip(), detail, credential=None),
    )


def archive_space(engine: Engine, tenant: UUID, space: UUID, actor: UUID, reason: str) -> None:
    from execbound.spaces import archive_space as _archive

    _space_change(
        engine,
        tenant,
        actor,
        lambda conn: _archive(conn, tenant, actor, space, reason, credential=None),
    )


def unarchive_space(engine: Engine, tenant: UUID, space: UUID, actor: UUID, reason: str) -> None:
    from execbound.spaces import unarchive_space as _unarchive

    _space_change(
        engine,
        tenant,
        actor,
        lambda conn: _unarchive(conn, tenant, actor, space, reason, credential=None),
    )


def assign_space(
    engine: Engine, tenant: UUID, space: UUID, principal: UUID, role: str, actor: UUID
) -> None:
    from execbound.spaces import assign_member

    _space_change(
        engine,
        tenant,
        actor,
        lambda conn: assign_member(conn, tenant, actor, space, principal, role, credential=None),
    )


def unassign_space(engine: Engine, tenant: UUID, space: UUID, principal: UUID, actor: UUID) -> None:
    from execbound.spaces import unassign_member

    _space_change(
        engine,
        tenant,
        actor,
        lambda conn: unassign_member(conn, tenant, actor, space, principal, credential=None),
    )


def list_spaces(engine: Engine, tenant: UUID) -> tuple[SpaceSummary, ...]:
    """Every space of the tenant by name with its seated people; nothing is audited."""
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        rows = (
            conn.execute(
                text(
                    "SELECT s.space_id, s.name, s.detail, s.created_at, s.archived_at, "
                    "array_remove(array_agg(m.principal_id), NULL) AS members "
                    "FROM execbound.spaces s "
                    "LEFT JOIN execbound.space_members m USING (tenant_id, space_id) "
                    "WHERE s.tenant_id = :t GROUP BY s.tenant_id, s.space_id ORDER BY s.name"
                ),
                {"t": tenant},
            )
            .mappings()
            .all()
        )
    return tuple(
        SpaceSummary(
            row["space_id"],
            row["name"],
            row["detail"],
            row["created_at"],
            row["archived_at"],
            tuple(sorted(row["members"])),
        )
        for row in rows
    )


def list_groups(engine: Engine, tenant: UUID) -> tuple[GroupSummary, ...]:
    """Every group of the tenant by name with its sorted member ids; nothing is audited."""
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        rows = (
            conn.execute(
                text(
                    "SELECT g.group_id, g.name, g.created_at, "
                    "array_remove(array_agg(m.principal_id), NULL) AS members "
                    "FROM execbound.principal_groups g "
                    "LEFT JOIN execbound.principal_group_members m USING (tenant_id, group_id) "
                    "WHERE g.tenant_id = :t GROUP BY g.tenant_id, g.group_id ORDER BY g.name"
                ),
                {"t": tenant},
            )
            .mappings()
            .all()
        )
    return tuple(
        GroupSummary(row["group_id"], row["name"], row["created_at"], tuple(sorted(row["members"])))
        for row in rows
    )


def _key_id(value: str) -> str:
    if type(value) is not str or not _KEY_ID.fullmatch(value):
        raise AdministrationError("INVALID_KEY")
    return value


def _public_key(value: str, algorithm: str) -> str:
    """Normalize and refuse anything the key ring must never hold, per algorithm.

    Ed25519 keeps its shape check and the small-order blocklist. ES256 accepts a PEM, a JWK
    or compressed hex, stores compressed hex, and refuses anything that is not a point on
    P-256 held by nobody but its owner.

    Either scheme then refuses the executor protocol's published test keys, whose private
    halves the vector file publishes (`provider.published_keys`). Asked of the normalized
    key, so a PEM, a JWK or uppercase hex of one is refused as surely as its stored form.
    """
    if algorithm not in ALGORITHMS:
        raise AdministrationError("INVALID_KEY")
    if algorithm == ES256:
        try:
            key = es256_public_key(value)
        except ValueError:
            raise AdministrationError("INVALID_KEY") from None
    else:
        if type(value) is not str or not _PUBLIC_KEY.fullmatch(value):
            raise AdministrationError("INVALID_KEY")
        key = value.lower()
        if forgeable_public_key(key):
            raise AdministrationError("INVALID_KEY")
    if published_executor_key(key):
        raise AdministrationError("INVALID_KEY")
    return key


def _add_key(
    conn: Connection, tenant: UUID, key_id: str, algorithm: str, public_key: str, now: datetime
) -> None:
    """Insert one unused key id carrying material the tenant may still hold.

    A taken id is refused, never rewritten, so the key a settled or outstanding grant was
    verified against stays the key that id names. Material the tenant may not hold is
    refused too, under the fence every caller holds, and it is of two kinds. Material that
    is already live would let a rotation paste back the key it revokes, or a second id
    carry a registered key, leaving one private key minting attested evidence while the
    audit chain showed a key ring change. Material recorded as compromised is barred
    permanently: the private half is in someone else's hands, so re-registering it under a
    fresh id would hand the thief the attested tier again through a ring the chain showed
    being repaired. A retirement bars nothing, which is what a rotation back to a key the
    operator still holds needs. The public key reaching here is already lowercase, so case
    cannot evade the comparison.
    """
    held = conn.execute(
        text(
            "SELECT 1 FROM execbound.executor_keys WHERE tenant_id = :t AND public_key = :key "
            "AND (revoked_at IS NULL OR revocation_reason = :compromised) LIMIT 1"
        ),
        {"t": tenant, "key": public_key, "compromised": COMPROMISED},
    ).scalar_one_or_none()
    if held is not None:
        raise AdministrationError("INVALID_KEY")
    inserted = conn.execute(
        text(
            "INSERT INTO execbound.executor_keys "
            "(tenant_id, key_id, algorithm, public_key, created_at) "
            "VALUES (:t, :k, :a, :key, :now) ON CONFLICT (tenant_id, key_id) DO NOTHING"
        ),
        {"t": tenant, "k": key_id, "a": algorithm, "key": public_key, "now": now},
    ).rowcount
    if inserted != 1:
        raise AdministrationError("INVALID_KEY")


def _retire_key(conn: Connection, tenant: UUID, key_id: str, now: datetime) -> None:
    """Stamp a revocation time on one live key, as the ordinary retirement it is.

    The statement names no other column beside the reason, so a revocation cannot rewrite
    the public key an outstanding proof is checked against. The reason is written here
    because migration 0026's CHECK constraint holds one exactly when the row is revoked,
    and it is the literal RETIRED rather than an argument: both callers are ordinary
    retirements, and a reason a caller passes is how an operator reaching for a retirement
    reaches a cut-off by omission, or the reverse. Recording a compromise is
    ``_cut_off_key``, which is a different statement about a different set of rows.
    """
    updated = conn.execute(
        text(
            "UPDATE execbound.executor_keys SET revoked_at = :now, revocation_reason = :reason "
            "WHERE tenant_id = :t AND key_id = :k AND revoked_at IS NULL"
        ),
        {"now": now, "reason": RETIRED, "t": tenant, "k": key_id},
    ).rowcount
    if updated != 1:
        raise AdministrationError("INVALID_KEY")


def _cut_off_key(conn: Connection, tenant: UUID, key_id: str, now: datetime) -> None:
    """Record that this key's private half is in someone else's hands, live or retired.

    A revocation already stamped is not in the way, which is the whole of why this is its
    own statement. Standard incident response is rotate-first: the key is revoked the
    moment it is suspected and the theft confirmed afterwards, so by the time a compromise
    can be recorded the row usually carries RETIRED — and a retirement is deliberately
    backward-permissive, so that key goes on attesting every grant it was holding for the
    rest of each report window, with a signed non-execution refunding the reservation and
    releasing the canonical claim. Refusing the report there left that operator with no
    remedy at all.

    What the verifier reads is the reason, and it refuses a compromise whatever the grant
    instant, so a compromise recorded over a retired row is identical in effect to one
    recorded at revocation time. ``revoked_at`` therefore keeps the instant the key
    actually left the ring rather than being moved forward: it no longer decides anything,
    and when the compromise was reported is what the audit chain carries.

    The statement is by material and not by id. Registration bars compromised material
    from coming back, and this is the same rule read backwards: a key already registered
    under a second id spelling the same public key would otherwise stay live and attest
    with the stolen private half, so cutting off one row and not the other would cut off
    nothing. The id the operator named is one of the rows it reaches, which is why a row
    already recorded as compromised is refused here — the act is total and permanent, so a
    repeat would change no state while appending an audit event saying it did, and one
    grep of the chain for `executor_key.compromised` is why that kind exists.
    """
    material = conn.execute(
        text(
            "SELECT public_key FROM execbound.executor_keys WHERE tenant_id = :t AND key_id = :k "
            "AND revocation_reason IS DISTINCT FROM :compromised"
        ),
        {"t": tenant, "k": key_id, "compromised": COMPROMISED},
    ).scalar_one_or_none()
    if material is None:
        raise AdministrationError("INVALID_KEY")
    conn.execute(
        text(
            "UPDATE execbound.executor_keys "
            "SET revoked_at = COALESCE(revoked_at, :now), revocation_reason = :compromised "
            "WHERE tenant_id = :t AND public_key = :key "
            "AND revocation_reason IS DISTINCT FROM :compromised"
        ),
        {"now": now, "t": tenant, "key": material, "compromised": COMPROMISED},
    )


def _keep_attestable(conn: Connection, tenant: UUID) -> None:
    """Refuse a revocation that would leave an active checkpoint bundle with no live key.

    Admission reads the active bundle without re-running component validation, so a tenant
    whose last key is revoked would keep issuing grants nothing can attest and no
    administrator could settle. The two reads run under the fence this transaction already
    holds, which is the same row the activation path locks, so the active selection cannot
    change under them. Rotation is unaffected: it inserts its replacement in this same
    transaction, so a live key always remains.

    ``revoke_executor_key`` is its only caller. ``report_executor_key_compromise``
    deliberately does not call it, because refusing to cut off a stolen last key is a
    refusal to perform the security action; its docstring argues that and states what the
    tenant is left with.

    The lookup is ``policy.store.LIVE_EXECUTOR_KEY``, the one bundle validation makes,
    because this guard exists to keep that validation's premise true and two spellings of
    one question are how the two come to disagree.
    """
    live = conn.execute(text(LIVE_EXECUTOR_KEY), {"tenant": tenant}).scalar_one_or_none()
    if live is not None:
        return
    declared = conn.execute(text(_ACTIVE_CHECKPOINT), {"t": tenant}).scalar_one_or_none()
    if declared is not None:
        raise AdministrationError("INVALID_STATE")


def register_executor_key(
    engine: Engine,
    tenant: UUID,
    key_id: str,
    public_key: str,
    actor: UUID,
    *,
    algorithm: str = ED25519,
    now: datetime | None = None,
) -> None:
    """Register an executor's public key, Ed25519 or ES256, supplied by the operator, under a
    new id.

    ExecBound generates nothing and returns nothing: the executor keeps the private key,
    so read access to this table cannot forge the attested tier that replay treats as
    verified. The key is validated before any statement runs.
    """
    key_id, public_key = _key_id(key_id), _public_key(public_key, algorithm)
    # Screened here and in the rotation's new id only: the shared `_key_id` above also
    # validates the id a revocation or a compromise report names, and neither may be
    # refused for a key that already exists.
    if secret_shaped(key_id):
        raise AdministrationError("INVALID_KEY")
    registered_at = _instant(now)
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        # A key ring change is ordered against every decision that reads it, as a
        # membership change is: a bundle declaring an external executor needs a live key.
        _fence(conn, tenant)
        _add_key(conn, tenant, key_id, algorithm, public_key, registered_at)
        append_event(
            conn,
            tenant,
            actor,
            "executor_key.registered",
            {"key_id": key_id, "algorithm": algorithm},
        )


def rotate_executor_key(
    engine: Engine,
    tenant: UUID,
    old_key_id: str,
    new_key_id: str,
    public_key: str,
    actor: UUID,
    *,
    algorithm: str = ED25519,
    now: datetime | None = None,
) -> None:
    """Add a key and retire the previous one in one transaction.

    Rotation never rewrites a registered key. The old row keeps the public key it was
    registered with and only gains a revocation time and the reason RETIRED, so a proof
    for a grant issued while that key was current still verifies afterwards. The
    revocation and the new row are stamped from one instant, which the caller may supply.

    A rotation is an ordinary retirement and never a compromise, however it is being used:
    ExecBound cannot tell why an operator is swapping a key, and reading a rotation as a
    cut-off would silently invalidate every outstanding proof of every tenant that merely
    rotates on a schedule. An operator whose key was stolen calls
    ``report_executor_key_compromise``, which is one audited statement about that key and
    takes effect whether or not a replacement is registered.
    """
    old_key_id, new_key_id = _key_id(old_key_id), _key_id(new_key_id)
    public_key = _public_key(public_key, algorithm)
    # The new id only: the old id names a key that already exists, exactly like a
    # revocation's or a compromise report's, and must never be refused on that account.
    if secret_shaped(new_key_id):
        raise AdministrationError("INVALID_KEY")
    if old_key_id == new_key_id:
        raise AdministrationError("INVALID_KEY")
    handover = _instant(now)
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        _fence(conn, tenant)
        # The replacement is inserted before the old row is retired, so the material check
        # still sees the key being revoked as live: a rotation onto the key it is replacing
        # is refused and, sharing this transaction, revokes nothing.
        _add_key(conn, tenant, new_key_id, algorithm, public_key, handover)
        _retire_key(conn, tenant, old_key_id, handover)
        append_event(
            conn,
            tenant,
            actor,
            "executor_key.rotated",
            {"key_id": new_key_id, "previous_key_id": old_key_id, "algorithm": algorithm},
        )


def revoke_executor_key(
    engine: Engine, tenant: UUID, key_id: str, actor: UUID, *, now: datetime | None = None
) -> None:
    """Retire one live key; an already revoked or unknown id is refused.

    The row stays and the revocation is recorded as RETIRED, so an outstanding grant
    issued while the key was current remains verifiable against a revocation that
    postdates it. The tenant's last live key cannot be retired while its active bundle
    declares an external executor; retire or replace that bundle first, or — if the key
    is in someone else's hands — report the compromise, which is the one revocation that
    is allowed to leave the ring empty.
    """
    key_id = _key_id(key_id)
    revoked_at = _instant(now)
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        _fence(conn, tenant)
        _retire_key(conn, tenant, key_id, revoked_at)
        _keep_attestable(conn, tenant)
        append_event(conn, tenant, actor, "executor_key.revoked", {"key_id": key_id})


def report_executor_key_compromise(
    engine: Engine, tenant: UUID, key_id: str, actor: UUID, *, now: datetime | None = None
) -> None:
    """Cut one key off retroactively: it attests nothing, whatever the grant instant.

    A separate function rather than a mode of ``revoke_executor_key``, because it is not
    the same act with a different label. It is the only revocation the verifier reads
    backwards, the only one that may leave the tenant with no live key while an active
    bundle declares an external executor, the only one that may be recorded over a
    revocation already stamped, and it is audited as its own kind so an incident is one
    grep and never a payload comparison. The other three key-ring writers already share
    ``_add_key`` and ``_retire_key`` rather than taking flags, and an operator reaching
    for a retirement must not be able to reach this by omitting an argument, nor the
    reverse.

    The key does not have to be live. Incident response rotates or revokes first and
    confirms afterwards, so the row is usually already stamped RETIRED by the time the
    theft is known, and a retirement keeps attesting the grants it covered by design;
    refusing the report over such a row left the operator no remedy at all.
    ``_cut_off_key`` argues the shape of the statement, which reaches every id of the
    tenant carrying the stolen material and refuses only a key already cut off.

    ``_keep_attestable`` is deliberately not called. It refuses to retire a tenant's last
    live key while its active bundle declares an external executor, which is right for an
    ordinary retirement and would be a refusal to perform the security action itself here:
    an operator who cannot cut off a stolen key because it is the last one is worse off
    than before. The consequence is stated rather than hidden. The tenant fails closed on
    new grants either way, because a bundle declaring an external executor does not load
    while the tenant has no unrevoked key and admission refuses it; grants already
    outstanding keep their reservation and their canonical claim, and any that only this
    key could have attested now have no settlement at all, which is retained uncertainty
    rather than a release on a stolen key's word. Registering a replacement restores new
    grants immediately, and it confers no authority over grants issued before it.

    Outstanding grants are not swept. A sweep here would close nothing on its own:
    INDETERMINATE is inside UNSETTLED, the report route accepts a report in either unsettled
    state, and the cut-off above is what ends the key's authority. It would also be a claim
    about the wrong set — a grant issued while a second, uncompromised key was also current
    is still perfectly attestable by that key — and the execution state machine is not the
    owner connection's to drive. What an unreportable grant already has is the recovery
    sweep at its report window, the uncertain queue and the administrator exit.
    """
    key_id = _key_id(key_id)
    compromised_at = _instant(now)
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        _fence(conn, tenant)
        _cut_off_key(conn, tenant, key_id, compromised_at)
        append_event(conn, tenant, actor, "executor_key.compromised", {"key_id": key_id})


def list_executor_keys(engine: Engine, tenant: UUID) -> tuple[ExecutorKeySummary, ...]:
    """Every key of the tenant oldest first; reading a key ring changes and audits nothing."""
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        rows = (
            conn.execute(
                text(
                    "SELECT key_id, algorithm, public_key, created_at, revoked_at, "
                    "revocation_reason FROM execbound.executor_keys WHERE tenant_id = :t "
                    "ORDER BY created_at, key_id"
                ),
                {"t": tenant},
            )
            .mappings()
            .all()
        )
    return tuple(
        ExecutorKeySummary(
            row["key_id"],
            row["algorithm"],
            row["public_key"],
            row["created_at"],
            row["revoked_at"],
            row["revocation_reason"],
            published_executor_key(row["public_key"]),
        )
        for row in rows
    )


# --- Registry provisioning: connector accounts, mappings, canonical targets and resources ---
# Until these commands existed, only the loopback-only validation seeder wrote these rows, so
# a tenant on any other database could not admit an action (issue #182).

PROVIDERS: frozenset[str] = frozenset(binding.provider for binding in PRODUCTION_ACTIONS.bindings)
RESOURCE_TYPES: frozenset[str] = frozenset(get_args(ResourceType))
DEFAULT_MAPPING_VERSION = "map-v1"
DEFAULT_RESOURCE_VERSION = "resource-v1"
MAX_VERSION_LENGTH = 80
DEFAULT_ALIAS_DAYS = 365
MAX_ALIAS_DAYS = 3660
_OPERATION_REF = re.compile(r"[a-z][a-z0-9_.-]{0,79}")


@dataclass(frozen=True)
class AccountSummary:
    account_id: UUID
    provider: str
    active: bool


@dataclass(frozen=True)
class MappingSummary:
    operation_ref: str
    account_id: UUID
    provider: str
    resource_type: str
    action: str
    provider_operation: str
    mapping_version: str
    schema_version: str
    context_contract_version: str
    active: bool


@dataclass(frozen=True)
class CreatedResource:
    resource_id: UUID
    canonical_target_id: UUID
    aliases: tuple[str, ...]


@dataclass(frozen=True)
class ResourceSummary:
    resource_id: UUID
    account_id: UUID
    provider: str
    resource_type: str
    provider_id: str
    version: str
    canonical_target_id: UUID | None
    active: bool
    aliases: tuple[str, ...]


def _version(value: object, code: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= MAX_VERSION_LENGTH:
        raise AdministrationError(code)
    return value


def _account(conn: Connection, tenant: UUID, account: UUID) -> str:
    provider = conn.execute(
        text(
            "SELECT provider FROM execbound.connector_accounts "
            "WHERE tenant_id = :t AND account_id = :a AND active"
        ),
        {"t": tenant, "a": account},
    ).scalar_one_or_none()
    if provider is None:
        raise AdministrationError("INVALID_ACCOUNT")
    return str(provider)


def create_account(
    engine: Engine,
    tenant: UUID,
    provider: str,
    actor: UUID,
    *,
    space: UUID | None = None,
    account_id: UUID | None = None,
) -> UUID:
    """Create an active connector account; the gateway configuration names it by id.

    An account belongs to one space and may later be offered tenant-wide; a caller that
    names no space gets the tenant's only one. `account_id` is for the case the
    configuration was written first and names the account, as `create_tenant` explains.
    """
    if provider not in PROVIDERS:
        raise AdministrationError("INVALID_PROVIDER")
    account = uuid4() if account_id is None else account_id
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        placed = _space_for(conn, tenant, space)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts "
                "(tenant_id, account_id, provider, space_id) VALUES (:t, :a, :p, :s)"
            ),
            {"t": tenant, "a": account, "p": provider, "s": placed},
        )
        append_event(
            conn,
            tenant,
            actor,
            "account.created",
            {"account_id": str(account), "provider": provider},
            space=placed,
        )
    return account


def list_accounts(engine: Engine, tenant: UUID) -> tuple[AccountSummary, ...]:
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        rows = conn.execute(
            text(
                "SELECT account_id, provider, active FROM execbound.connector_accounts "
                "WHERE tenant_id = :t ORDER BY provider, account_id"
            ),
            {"t": tenant},
        ).all()
    return tuple(AccountSummary(row[0], row[1], row[2]) for row in rows)


def create_mapping(
    engine: Engine,
    tenant: UUID,
    account: UUID,
    action: str,
    actor: UUID,
    *,
    operation_ref: str | None = None,
    mapping_version: str = DEFAULT_MAPPING_VERSION,
    context_contract_version: str | None = None,
) -> MappingSummary:
    """Bind a catalog action to the account's provider operation under one operation ref.

    The provider operation and schema version come from the action catalog, never from the
    caller; the context contract is the catalog's default for the action unless the caller
    names another version the catalog says serves it (endpoint-isolation.v2, #478)."""
    ref = action if operation_ref is None else operation_ref
    if type(ref) is not str or not _OPERATION_REF.fullmatch(ref):
        raise AdministrationError("INVALID_REFERENCE")
    version = _version(mapping_version, "INVALID_VERSION")
    if secret_shaped(ref):
        raise AdministrationError("INVALID_REFERENCE")
    if secret_shaped(version):
        raise AdministrationError("INVALID_VERSION")
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        _fence(conn, tenant)
        provider = _account(conn, tenant, account)
        try:
            spec = PRODUCTION_ACTIONS.bound(provider, action)
        except CatalogError:
            raise AdministrationError("INVALID_ACTION") from None
        contract_version = (
            spec.context_contract_version
            if context_contract_version is None
            else context_contract_version
        )
        try:
            PRODUCTION_CATALOG.for_operation(contract_version, spec.action, spec.resource_type)
        except ContractError:
            raise AdministrationError("INVALID_CONTRACT") from None
        taken = conn.execute(
            text(
                "SELECT 1 FROM execbound.operation_mappings "
                "WHERE tenant_id = :t AND operation_ref = :r"
            ),
            {"t": tenant, "r": ref},
        ).scalar_one_or_none()
        if taken is not None:
            raise AdministrationError("INVALID_REFERENCE")
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings (tenant_id, operation_ref, account_id, "
                "provider, resource_type, action, provider_operation, mapping_version, "
                "schema_version, context_contract_version) VALUES (:t, :r, :a, :p, :rt, :ac, "
                ":op, :mv, :sv, :cv)"
            ),
            {
                "t": tenant,
                "r": ref,
                "a": account,
                "p": provider,
                "rt": spec.resource_type,
                "ac": spec.action,
                "op": spec.provider_operation,
                "mv": version,
                "sv": spec.schema_version,
                "cv": contract_version,
            },
        )
        append_event(
            conn,
            tenant,
            actor,
            "mapping.created",
            {
                "operation_ref": ref,
                "account_id": str(account),
                "provider": provider,
                "action": spec.action,
                "mapping_version": version,
                "context_contract_version": contract_version,
            },
        )
    return MappingSummary(
        ref,
        account,
        provider,
        spec.resource_type,
        spec.action,
        spec.provider_operation,
        version,
        spec.schema_version,
        contract_version,
        True,
    )


def list_mappings(engine: Engine, tenant: UUID) -> tuple[MappingSummary, ...]:
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        rows = (
            conn.execute(
                text(
                    "SELECT operation_ref, account_id, provider, resource_type, action, "
                    "provider_operation, mapping_version, schema_version, "
                    "context_contract_version, active FROM execbound.operation_mappings "
                    "WHERE tenant_id = :t ORDER BY operation_ref"
                ),
                {"t": tenant},
            )
            .mappings()
            .all()
        )
    return tuple(MappingSummary(**row) for row in rows)


def create_target(engine: Engine, tenant: UUID, actor: UUID) -> UUID:
    """Create a canonical target that resources can be bound to and approvers assigned to."""
    target = uuid4()
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        conn.execute(
            text(
                "INSERT INTO execbound.canonical_targets (tenant_id, canonical_target_id, "
                "created_at) VALUES (:t, :c, :now)"
            ),
            {"t": tenant, "c": target, "now": datetime.now(UTC)},
        )
        append_event(conn, tenant, actor, "target.created", {"canonical_target_id": str(target)})
    return target


def _facts(resource_type: str, facts: Mapping[str, object] | None) -> dict[str, object]:
    """Column-backed inventory facts of the resource type, checked against their domains.

    Every contract of one resource type declares the same inventory columns (endpoint v1
    and v2 do; `tests/test_signal_contract.py` holds them to it), so the first is as good
    as any.
    """
    contract = next(
        spec
        for spec in (PRODUCTION_CATALOG.contract(v) for v in PRODUCTION_CATALOG.versions)
        if spec.resource_type == resource_type
    )
    columns: dict[str, tuple[FactSpec, str]] = {}
    for spec in contract.facts:
        if spec.source_kind == "inventory" and isinstance(spec.storage, Column):
            columns[spec.name] = (spec, spec.storage.column)
    values: dict[str, object] = {}
    for name, value in (facts or {}).items():
        found = columns.get(name) if type(name) is str else None
        if found is None:
            raise AdministrationError("INVALID_FACT")
        fact, column = found
        domain = fact.domain
        valid = (
            (type(value) is str and value in domain.values)
            if isinstance(domain, StringDomain)
            else (type(value) is int and domain.minimum <= value <= domain.maximum)
            if isinstance(domain, IntegerDomain)
            else type(value) is bool
        )
        if not valid:
            raise AdministrationError("INVALID_FACT")
        values[column] = value
    return values


def _selector(kind: str, value: object, code: str) -> str:
    try:
        return ResourceSelector(kind=kind, value=value).value  # type: ignore[arg-type]
    except (ValidationError, ValueError):
        raise AdministrationError(code) from None


def create_resource(
    engine: Engine,
    tenant: UUID,
    account: UUID,
    resource_type: str,
    provider_id: str,
    source: UUID,
    actor: UUID,
    *,
    version: str = DEFAULT_RESOURCE_VERSION,
    target: UUID | None = None,
    hostname: str | None = None,
    alias_days: int = DEFAULT_ALIAS_DAYS,
    facts: Mapping[str, object] | None = None,
    observed_at: datetime | None = None,
) -> CreatedResource:
    """Register one provider resource as a resolvable target.

    Writes the resource attested by an active inventory source of the account, binds it to a
    canonical target (a new one unless `target` names an existing one), and gives it a
    `provider_id` alias plus an optional hostname alias valid for `alias_days`. Facts are
    optional here and normally arrive through `context-import`; the ones given are checked
    against the contract domains for the resource type."""
    if resource_type not in RESOURCE_TYPES:
        raise AdministrationError("INVALID_RESOURCE_TYPE")
    provider_id = _selector("provider_id", provider_id, "INVALID_PROVIDER_ID")
    version = _version(version, "INVALID_VERSION")
    if type(alias_days) is not int or not 1 <= alias_days <= MAX_ALIAS_DAYS:
        raise AdministrationError("INVALID_ALIAS")
    host = None
    if hostname is not None:
        if resource_type != "endpoint":
            raise AdministrationError("INVALID_ALIAS")
        host = _selector("hostname", hostname, "INVALID_ALIAS")
    # Each field keeps the code it already has for every other shape of refusal: a
    # secret-shaped provider id reads as a bad provider id, a secret-shaped version as a
    # bad version, and a secret-shaped hostname alias as a bad alias, never lumped under
    # one code a caller cannot otherwise tell apart.
    if secret_shaped(provider_id):
        raise AdministrationError("INVALID_PROVIDER_ID")
    if secret_shaped(version):
        raise AdministrationError("INVALID_VERSION")
    if host is not None and secret_shaped(host):
        raise AdministrationError("INVALID_ALIAS")
    columns = _facts(resource_type, facts)
    now = _instant(observed_at)
    resource = uuid4()
    aliases = {"provider_id": provider_id, **({"hostname": host} if host else {})}
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        _fence(conn, tenant)
        provider = _account(conn, tenant, account)
        attesting = conn.execute(
            text(
                "SELECT kind FROM execbound.context_sources "
                "WHERE tenant_id = :t AND account_id = :a AND source_id = :s AND active"
            ),
            {"t": tenant, "a": account, "s": source},
        ).scalar_one_or_none()
        if attesting != "inventory":
            raise AdministrationError("INVALID_SOURCE")
        duplicate = conn.execute(
            text(
                "SELECT 1 FROM execbound.resources WHERE tenant_id = :t AND account_id = :a "
                "AND provider = :p AND resource_type = :rt AND provider_id = :pid"
            ),
            {"t": tenant, "a": account, "p": provider, "rt": resource_type, "pid": provider_id},
        ).scalar_one_or_none()
        if duplicate is not None:
            raise AdministrationError("INVALID_PROVIDER_ID")
        canonical = target
        if canonical is None:
            canonical = uuid4()
            conn.execute(
                text(
                    "INSERT INTO execbound.canonical_targets (tenant_id, canonical_target_id, "
                    "created_at) VALUES (:t, :c, :now)"
                ),
                {"t": tenant, "c": canonical, "now": datetime.now(UTC)},
            )
        else:
            known = conn.execute(
                text(
                    "SELECT 1 FROM execbound.canonical_targets "
                    "WHERE tenant_id = :t AND canonical_target_id = :c"
                ),
                {"t": tenant, "c": canonical},
            ).scalar_one_or_none()
            if known is None:
                raise AdministrationError("INVALID_TARGET")
        for kind, value in aliases.items():
            clash = conn.execute(
                text(
                    "SELECT 1 FROM execbound.resource_aliases WHERE tenant_id = :t "
                    "AND account_id = :a AND provider = :p AND resource_type = :rt "
                    "AND kind = :k AND normalized_value = :v AND expires_at > :now"
                ),
                {
                    "t": tenant,
                    "a": account,
                    "p": provider,
                    "rt": resource_type,
                    "k": kind,
                    "v": value,
                    "now": now,
                },
            ).scalar_one_or_none()
            if clash is not None:
                raise AdministrationError("INVALID_ALIAS")
        fact_columns = "".join(f", {name}" for name in columns)
        fact_params = "".join(f", :{name}" for name in columns)
        # Column names come from the contract catalog, never from the caller.
        conn.execute(
            text(
                "INSERT INTO execbound.resources (tenant_id, account_id, provider, "  # nosec B608 - catalog
                f"resource_type, resource_id, provider_id, version, source_id, observed_at"
                f"{fact_columns}) VALUES (:t, :a, :p, :rt, :r, :pid, :v, :s, :now{fact_params})"
            ),
            {
                "t": tenant,
                "a": account,
                "p": provider,
                "rt": resource_type,
                "r": resource,
                "pid": provider_id,
                "v": version,
                "s": source,
                "now": now,
                **columns,
            },
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resource_identities (tenant_id, account_id, provider, "
                "resource_type, resource_id, canonical_target_id) "
                "VALUES (:t, :a, :p, :rt, :r, :c)"
            ),
            {
                "t": tenant,
                "a": account,
                "p": provider,
                "rt": resource_type,
                "r": resource,
                "c": canonical,
            },
        )
        for kind, value in aliases.items():
            conn.execute(
                text(
                    "INSERT INTO execbound.resource_aliases (tenant_id, alias_id, account_id, "
                    "provider, resource_type, kind, normalized_value, resource_id, valid_from, "
                    "expires_at) VALUES (:t, :alias, :a, :p, :rt, :k, :v, :r, :now, :expires)"
                ),
                {
                    "t": tenant,
                    "alias": uuid4(),
                    "a": account,
                    "p": provider,
                    "rt": resource_type,
                    "k": kind,
                    "v": value,
                    "r": resource,
                    "now": now,
                    "expires": now + timedelta(days=alias_days),
                },
            )
        labels = tuple(sorted(f"{kind}:{value}" for kind, value in aliases.items()))
        append_event(
            conn,
            tenant,
            actor,
            "resource.created",
            {
                "resource_id": str(resource),
                "account_id": str(account),
                "provider": provider,
                "resource_type": resource_type,
                "provider_id": provider_id,
                "version": version,
                "canonical_target_id": str(canonical),
                "aliases": list(labels),
            },
        )
    return CreatedResource(resource, canonical, labels)


def list_resources(engine: Engine, tenant: UUID) -> tuple[ResourceSummary, ...]:
    """Every resource with its canonical target and unexpired aliases; nothing is audited."""
    now = datetime.now(UTC)
    with _tenant_transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        rows = (
            conn.execute(
                text(
                    "SELECT r.resource_id, r.account_id, r.provider, r.resource_type, "
                    "r.provider_id, r.version, i.canonical_target_id, r.active, "
                    "array_remove(array_agg(a.kind || ':' || a.normalized_value "
                    "ORDER BY a.kind, a.normalized_value), NULL) AS aliases "
                    "FROM execbound.resources r "
                    "LEFT JOIN execbound.resource_identities i USING (tenant_id, account_id, "
                    "provider, resource_type, resource_id) "
                    "LEFT JOIN execbound.resource_aliases a ON a.tenant_id = r.tenant_id "
                    "AND a.account_id = r.account_id AND a.provider = r.provider "
                    "AND a.resource_type = r.resource_type AND a.resource_id = r.resource_id "
                    "AND a.valid_from <= :now AND a.expires_at > :now "
                    "WHERE r.tenant_id = :t GROUP BY r.tenant_id, r.account_id, r.provider, "
                    "r.resource_type, r.resource_id, i.canonical_target_id "
                    "ORDER BY r.provider, r.resource_type, r.provider_id"
                ),
                {"t": tenant, "now": now},
            )
            .mappings()
            .all()
        )
    return tuple(
        ResourceSummary(
            row["resource_id"],
            row["account_id"],
            row["provider"],
            row["resource_type"],
            row["provider_id"],
            row["version"],
            row["canonical_target_id"],
            row["active"],
            tuple(row["aliases"]),
        )
        for row in rows
    )
