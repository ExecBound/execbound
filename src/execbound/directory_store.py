# SPDX-License-Identifier: AGPL-3.0-only
"""Every database call the customer's own identity provider makes, and nothing else.

The shape is `passwords.py`'s: one function per store function, each opening its own fenced
transaction, calling `check_runtime`, calling the definer function, appending the audit events
in that same transaction so there is no moment where the rows and the chain disagree, and
mapping a database refusal to a code a page may act on. Nothing here talks to a directory; that
is `directory.py`, and it is deliberately on the other side of this line.

Two reads happen before a tenant is known, because one redirect URI serves every tenant and the
two public halves of a flow hold a provider id and no tenant at all. Each sets a marker and
reads the one row the matching single-row policy of migration 0042 then permits: the provider
whose id the caller already holds, and the link for the account the caller already holds a
verified assertion for. Neither can list anything and neither can see another tenant's row.

A subject is the directory's own claim, not a person's free text, so an event carries it
through `withheld` rather than refusing it: refusing would lock out a person the directory
has already proved signed in. The link row keeps the real value either way, so the digest
beside `WITHHELD` only has to correlate events about the same person, never stand in for it.
"""

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database, UnsafeDatabaseRole, check_runtime
from execbound.directory import (
    SUBJECT_CLAIMS,
    DirectoryAccount,
    DirectoryConfig,
    Discovery,
    ProviderRow,
)
from execbound.envelope import EnvelopeError, seal, unseal
from execbound.execution import store
from execbound.identity import UNATTRIBUTED_CONTEXT, Identity, PrincipalKind
from execbound.logging_schema import log_event
from execbound.passwords import SIGN_IN_LIFETIME
from execbound.resolution.models import Clock, SystemClock
from execbound.runtime import Runtime
from execbound.secrets import withheld
from execbound.surfaces.sessions import Session, SessionError, check_session

CODE_PREFIX = "ebv1"
DEFAULT_INVITATION_LIFETIME = timedelta(days=7)
MIN_INVITATION_LIFETIME = timedelta(hours=1)
MAX_INVITATION_LIFETIME = timedelta(days=14)
# How stale a directory session's last verification may be before the next renewal rechecks it,
# and how long an unreachable directory is tolerated. A session renews once half of its fifteen
# minutes has passed, so a person using the console is rechecked about every seven and a half
# minutes; the grace is one session lifetime, which is also how long a person who walked away
# would have kept the session anyway.
RECHECK_INTERVAL = timedelta(minutes=5)
RECHECK_GRACE = timedelta(minutes=15)
STATES = ("draft", "verified", "enabled", "disabled")
REQUESTABLE = ("enabled", "disabled")

_SECRET = re.compile(r"[A-Za-z0-9_-]{43}")
# What a database refusal may say. Anything else is the store being unavailable, which is the
# one refusal a caller should retry.
_KNOWN = frozenset(
    {
        "INVALID_TENANT",
        "INVALID_ACTOR",
        "INVALID_PRINCIPAL",
        "INVALID_PROVIDER",
        "INVALID_STATE",
        "INVALID_SUBJECT",
        "INVALID_LINK",
        "INVALID_INVITATION",
        "INVALID_DIGEST",
        "INVALID_LIFETIME",
        "INVALID_CLOCK",
        "INVALID_REASON",
        "INVALID_CREDENTIAL",
        "PROVIDER_EXISTS",
        "ALREADY_LINKED",
    }
)

_PROVIDER_COLUMNS = (
    "tenant_id, provider_id, name, issuer, client_id, secret_ciphertext, secret_key_id, "
    "subject_claim, issuer_tenant, authorization_endpoint, token_endpoint, jwks_uri, state, "
    "created_at, verified_at, enabled_at, disabled_at"
)


class DirectoryError(ValueError):
    """A safe code only; no code, no client secret and no refresh token reaches a message."""

    def __init__(self, code: str = "DIRECTORY_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Directory unavailable")


@dataclass(frozen=True)
class Invitation:
    """A minted invitation. The code exists for one response and is stored hashed."""

    code: str
    invitation_id: UUID
    principal_id: UUID
    provider_id: UUID
    expires_at: datetime


def _now(clock: Clock) -> datetime:
    value = clock.now()
    if value.tzinfo is None or value.utcoffset() is None:
        raise DirectoryError("INVALID_CLOCK")
    return value.astimezone(UTC)


def _refusal(exc: DBAPIError) -> DirectoryError:
    diagnostic = getattr(exc.orig, "diag", None)
    message = getattr(diagnostic, "message_primary", None)
    return DirectoryError(message if message in _KNOWN else "DIRECTORY_UNAVAILABLE")


def invitation_code(tenant_id: UUID, invitation_id: UUID) -> tuple[str, str]:
    code = f"{CODE_PREFIX}.{tenant_id}.{invitation_id}.{secrets.token_urlsafe(32)}"
    return code, hashlib.sha256(code.encode("ascii")).hexdigest()


def invitation_selectors(code: object) -> tuple[UUID, UUID]:
    """The tenant and invitation a string names, read without any lookup or comparison."""
    try:
        if type(code) is not str or len(code) > 160:
            raise ValueError
        version, tenant_text, invitation_text, secret = code.split(".")
        tenant_id, invitation_id = UUID(tenant_text), UUID(invitation_text)
        if (
            version != CODE_PREFIX
            or str(tenant_id) != tenant_text
            or str(invitation_id) != invitation_text
            or _SECRET.fullmatch(secret) is None
        ):
            raise ValueError
        return tenant_id, invitation_id
    except ValueError:
        raise DirectoryError("INVALID_INVITATION") from None


def code_digest(code: str) -> str:
    return hashlib.sha256(code.encode("ascii")).hexdigest()


def _row(mapping: Any) -> ProviderRow:
    return ProviderRow(**dict(mapping))


def provider_in(conn: Connection, tenant_id: UUID, provider_id: UUID | None = None) -> Any:
    """The tenant's provider under a fence the caller already holds, or None.

    Without a provider id this answers the one that is not disabled, which is what every page
    means by "the tenant's provider"; with one it answers that row whatever its state, which is
    what a state change and a self-link mean.
    """
    clause = "AND p.provider_id = :p" if provider_id is not None else "AND p.state <> 'disabled'"
    return (
        conn.execute(
            text(
                f"SELECT {_PROVIDER_COLUMNS} FROM execbound.identity_providers p "  # nosec B608 - a fixed column list and one of two fixed predicates
                f"WHERE p.tenant_id = :t {clause}"
            ),
            {"t": tenant_id, "p": provider_id},
        )
        .mappings()
        .one_or_none()
    )


def locate_provider(db: Database, provider_id: UUID) -> ProviderRow | None:
    """The provider a sign-in link names, across tenants, or None.

    The marker below is what the `directory_provider` policy compares each row's own id
    against, so this read sees the row for the provider the caller already holds the id of and
    no other row in any tenant. It is not authority: the state, the tenant and the link are all
    read again inside that tenant's fence.
    """
    try:
        with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
            check_runtime(conn)
            conn.execute(
                text("SELECT set_config('execbound.directory_provider', :p, true)"),
                {"p": str(provider_id)},
            )
            found = (
                conn.execute(
                    text(
                        f"SELECT {_PROVIDER_COLUMNS} FROM execbound.identity_providers p "  # nosec B608 - a fixed column list
                        "WHERE p.provider_id = :p"
                    ),
                    {"p": provider_id},
                )
                .mappings()
                .one_or_none()
            )
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None
    return _row(found) if found is not None else None


def locate_link(db: Database, provider_id: UUID, subject: str) -> tuple[UUID, UUID] | None:
    """The one person a directory account is bound to, across tenants, or None."""
    marker = f"{provider_id}:{subject}"
    try:
        with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
            check_runtime(conn)
            conn.execute(
                text("SELECT set_config('execbound.directory_subject', :s, true)"),
                {"s": marker},
            )
            row = (
                conn.execute(
                    text(
                        "SELECT tenant_id, principal_id FROM execbound.identity_links "
                        "WHERE provider_id = :p AND subject = :s AND revoked_at IS NULL"
                    ),
                    {"p": provider_id, "s": subject},
                )
                .mappings()
                .one_or_none()
            )
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None
    return (row["tenant_id"], row["principal_id"]) if row is not None else None


def register(
    db: Database,
    directory: DirectoryConfig,
    tenant_id: UUID,
    actor_id: UUID,
    *,
    name: str,
    client_id: str,
    client_secret: str,
    subject_claim: str,
    discovery: Discovery,
    clock: Clock | None = None,
) -> UUID:
    """Write a validated registration as a draft. The secret is sealed before it is sent."""
    clock = clock or SystemClock()
    provider_id = uuid4()
    try:
        ciphertext, key_id = seal(
            directory.ring, client_secret, tenant_id, provider_id, "client_secret"
        )
    except EnvelopeError:
        raise DirectoryError("INVALID_SECRET") from None
    now = _now(clock)
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            conn.execute(
                text(
                    "SELECT execbound.directory_register(:a,:p,:n,:i,:c,:x,:k,:s,:it,:ae,:te,"
                    ":j,:now)"
                ),
                {
                    "a": actor_id,
                    "p": provider_id,
                    "n": name,
                    "i": discovery.issuer,
                    "c": client_id,
                    "x": ciphertext,
                    "k": key_id,
                    "s": subject_claim,
                    "it": discovery.issuer_tenant,
                    "ae": discovery.authorization_endpoint,
                    "te": discovery.token_endpoint,
                    "j": discovery.jwks_uri,
                    "now": now,
                },
            )
            append_event(
                conn,
                tenant_id,
                actor_id,
                "identity_provider.registered",
                {
                    "provider_id": str(provider_id),
                    # The administrator types the issuer, but it must equal what the
                    # directory's own discovery document says, so they cannot rephrase it:
                    # refusing would make that directory impossible to register.
                    **withheld("issuer", discovery.issuer),
                    "subject_claim": subject_claim,
                },
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None
    return provider_id


def _ended(
    conn: Connection,
    tenant_id: UUID,
    actor_id: UUID,
    ended: dict[str, Any],
    reason: str,
) -> None:
    """One audit event per credential and session an end revoked, in its own transaction."""
    for credential in ended.get("credentials", ()):
        append_event(
            conn,
            tenant_id,
            actor_id,
            "credential.revoked",
            {"credential_id": credential, "reason": reason},
        )
    for session_id in ended.get("sessions", ()):
        append_event(
            conn,
            tenant_id,
            actor_id,
            "human_session.revoked",
            {"session_id": session_id, "reason": reason},
        )


def set_state(
    db: Database,
    tenant_id: UUID,
    actor_id: UUID,
    provider_id: UUID,
    state: str,
    *,
    clock: Clock | None = None,
) -> None:
    """Enable or disable a provider. Disabling ends every directory session under it."""
    clock = clock or SystemClock()
    if state not in REQUESTABLE:
        raise DirectoryError("INVALID_STATE")
    now = _now(clock)
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            result = conn.execute(
                text("SELECT execbound.directory_set_state(:a,:p,:s,:now)"),
                {"a": actor_id, "p": provider_id, "s": state, "now": now},
            ).scalar_one()
            append_event(
                conn,
                tenant_id,
                actor_id,
                f"identity_provider.{state}",
                {"provider_id": str(provider_id), "previous": result["previous"]},
            )
            _ended(conn, tenant_id, actor_id, result, "PROVIDER_DISABLED")
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None


def _configures(conn: Connection, tenant_id: UUID, actor_id: UUID) -> bool:
    """A workspace administrator: an effective administrator who is not narrowed to spaces.

    The effective kind, as a session's identity carries it: an administrator role granted on
    the access page leaves the principal row's own kind unchanged.
    """
    from execbound.access_control import effective_kind
    from execbound.spaces import narrowed

    return effective_kind(conn, tenant_id, actor_id) == "ADMIN" and not narrowed(
        conn, tenant_id, actor_id
    )


def configures(db: Database, tenant_id: UUID, actor_id: UUID) -> bool:
    """Whether this person may configure the tenant's provider: register, test, enable, disable.

    A provider signs people in to the whole tenant, so since 0073 only a workspace
    administrator configures it; an administrator narrowed to spaces is refused as anybody
    who is not an administrator is. A route asks this before it writes or reaches a
    directory, and the definer functions refuse the same again in their own statements.
    """
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            return _configures(conn, tenant_id, actor_id)
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None


def link_self(
    db: Database,
    tenant_id: UUID,
    actor_id: UUID,
    provider_id: UUID,
    account: DirectoryAccount,
    *,
    clock: Clock | None = None,
) -> dict[str, Any]:
    """Bind the acting person's own directory account, and say what that did.

    The answer carries the link, whether this was the sign-in that verified a draft provider,
    and the person's effective kind, which is what the callback lands them by: it cannot read
    their session, because the directory's redirect back is cross-site.

    Only a workspace administrator links through a provider that is not enabled. The first
    sign-in through a draft is the evidence a provider is enabled on, and that evidence is the
    registering administrator's to produce, so anybody else, an approver or an administrator
    narrowed to spaces, is refused here, in the same transaction and before the definer
    function runs. Since 0073 `directory_link_self` refuses them again itself; before it, the
    function accepted an approver's sign-in and marked the draft verified. A provider never
    returns to `draft`, so a state read without a lock can only be staler in the refusing
    direction.
    """
    from execbound.access_control import effective_kind

    clock = clock or SystemClock()
    now = _now(clock)
    answer: dict[str, Any] = {"link_id": None, "verified": False, "kind": "HUMAN_APPROVER"}
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            state = conn.execute(
                text(
                    "SELECT state FROM execbound.identity_providers "
                    "WHERE tenant_id = :t AND provider_id = :p"
                ),
                {"t": tenant_id, "p": provider_id},
            ).scalar_one_or_none()
            if state != "enabled" and not _configures(conn, tenant_id, actor_id):
                raise DirectoryError("INVALID_PROVIDER")
            result = conn.execute(
                text("SELECT execbound.directory_link_self(:a,:p,:s,:d,:u,:now)"),
                {
                    "a": actor_id,
                    "p": provider_id,
                    "s": account.subject,
                    "d": account.display_name,
                    "u": account.display_username,
                    "now": now,
                },
            ).scalar_one()
            append_event(
                conn,
                tenant_id,
                actor_id,
                "identity.linked",
                {
                    "principal_id": str(actor_id),
                    "provider_id": str(provider_id),
                    **withheld("subject", account.subject),
                    "via": "self",
                },
            )
            answer = dict(result)
            # The function answers the principal row's own kind, which a role granted on the
            # access page leaves unchanged; the landing follows the effective kind, as the
            # person's session and a directory sign-in (`sign_in`) do.
            answer["kind"] = (
                "ADMIN"
                if effective_kind(conn, tenant_id, actor_id) == "ADMIN"
                else "HUMAN_APPROVER"
            )
            if answer["verified"]:
                append_event(
                    conn,
                    tenant_id,
                    actor_id,
                    "identity_provider.verified",
                    {"provider_id": str(provider_id)},
                )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None
    return answer


def link_person(
    db: Database,
    tenant_id: UUID,
    actor_id: UUID,
    principal_id: UUID,
    provider_id: UUID,
    subject: str,
    *,
    clock: Clock | None = None,
) -> None:
    """An administrator binds an existing person to a directory account they already know."""
    clock = clock or SystemClock()
    now = _now(clock)
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            conn.execute(
                text("SELECT execbound.directory_link(:a,:p,:v,:s,:now)"),
                {"a": actor_id, "p": principal_id, "v": provider_id, "s": subject, "now": now},
            )
            append_event(
                conn,
                tenant_id,
                actor_id,
                "identity.linked",
                {
                    "principal_id": str(principal_id),
                    "provider_id": str(provider_id),
                    **withheld("subject", subject),
                    "via": "admin",
                },
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None


def unlink_person(
    db: Database,
    tenant_id: UUID,
    actor_id: UUID,
    principal_id: UUID,
    *,
    clock: Clock | None = None,
) -> None:
    """Revoke a person's directory account and end every session standing on it."""
    clock = clock or SystemClock()
    now = _now(clock)
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            result = conn.execute(
                text("SELECT execbound.directory_unlink(:a,:p,:now)"),
                {"a": actor_id, "p": principal_id, "now": now},
            ).scalar_one()
            append_event(
                conn,
                tenant_id,
                actor_id,
                "identity.unlinked",
                {"principal_id": str(principal_id), "link_id": result["link_id"]},
            )
            _ended(conn, tenant_id, actor_id, result, "LINK_REVOKED")
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None


def invite(
    db: Database,
    tenant_id: UUID,
    actor_id: UUID,
    principal_id: UUID,
    provider_id: UUID,
    *,
    lifetime: timedelta = DEFAULT_INVITATION_LIFETIME,
    clock: Clock | None = None,
) -> Invitation:
    """Mint one invitation code for a person; whatever was pending is revoked first."""
    clock = clock or SystemClock()
    if not MIN_INVITATION_LIFETIME <= lifetime <= MAX_INVITATION_LIFETIME:
        raise DirectoryError("INVALID_LIFETIME")
    invitation_id = uuid4()
    code, digest = invitation_code(tenant_id, invitation_id)
    expires_at = _now(clock) + lifetime
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            conn.execute(
                text("SELECT execbound.directory_invite(:a,:p,:v,:i,:h,:e)"),
                {
                    "a": actor_id,
                    "p": principal_id,
                    "v": provider_id,
                    "i": invitation_id,
                    "h": digest,
                    "e": expires_at,
                },
            )
            append_event(
                conn,
                tenant_id,
                actor_id,
                "identity.invited",
                {
                    "principal_id": str(principal_id),
                    "provider_id": str(provider_id),
                    "invitation_id": str(invitation_id),
                    "expires_at": expires_at.isoformat(),
                },
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None
    return Invitation(code, invitation_id, principal_id, provider_id, expires_at)


def revoke_invitation(
    db: Database,
    tenant_id: UUID,
    actor_id: UUID,
    invitation_id: UUID,
    *,
    clock: Clock | None = None,
) -> None:
    clock = clock or SystemClock()
    now = _now(clock)
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            principal = conn.execute(
                text("SELECT execbound.directory_invitation_revoke(:a,:i,:now)"),
                {"a": actor_id, "i": invitation_id, "now": now},
            ).scalar_one()
            append_event(
                conn,
                tenant_id,
                actor_id,
                "identity.invitation_revoked",
                {"invitation_id": str(invitation_id), "principal_id": str(principal)},
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None


def check_invitation(db: Database, code: object) -> tuple[UUID, UUID]:
    """The invitation and provider a code names, or the one refusal every failure gets.

    The counter the function keeps is why a wrong secret answers NULL rather than raising: a
    refusal that rolled the count back would make five wrong attempts a suggestion rather than
    a limit. The refusal is raised here, after that transaction commits.
    """
    tenant_id, invitation_id = invitation_selectors(code)
    if type(code) is not str:
        raise DirectoryError("INVALID_INVITATION")
    try:
        with db.transaction(tenant_id) as conn:
            check_runtime(conn)
            provider = conn.execute(
                text("SELECT execbound.directory_invitation_check(:i,:h)"),
                {"i": invitation_id, "h": code_digest(code)},
            ).scalar_one_or_none()
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None
    if provider is None:
        raise DirectoryError("INVALID_INVITATION")
    return invitation_id, UUID(str(provider))


def sign_in(
    db: Database,
    directory: DirectoryConfig,
    row: ProviderRow,
    account: DirectoryAccount,
    *,
    invitation_id: UUID | None = None,
    clock: Clock | None = None,
) -> Identity:
    """Mint the credential a directory session stands on, binding an invitation when there is one.

    The credential's digest is of thirty-two random bytes that are discarded here, so the row
    authenticates nobody and exists only to give `issue_session` the credential every session is
    already bound to. That is why revocation, capacity, renewal and the recheck cover a
    directory session with no new session code.
    """
    clock = clock or SystemClock()
    credential_id = uuid4()
    kind: PrincipalKind = "HUMAN_APPROVER"
    principal_id = UUID(int=0)
    digest = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    issued_at = _now(clock)
    expires_at = issued_at + SIGN_IN_LIFETIME
    ciphertext: str | None = None
    key_id: str | None = None
    if account.refresh_token is not None:
        try:
            ciphertext, key_id = seal(
                directory.ring,
                account.refresh_token,
                row.tenant_id,
                row.provider_id,
                "refresh_token",
            )
        except EnvelopeError:
            ciphertext, key_id = None, None
    try:
        with db.transaction(row.tenant_id) as conn:
            check_runtime(conn)
            result = conn.execute(
                text("SELECT execbound.directory_sign_in(:v,:s,:i,:c,:h,:x,:k,:d,:u,:issued,:exp)"),
                {
                    "v": row.provider_id,
                    "s": account.subject,
                    "i": invitation_id,
                    "c": credential_id,
                    "h": digest,
                    "x": ciphertext,
                    "k": key_id,
                    "d": account.display_name,
                    "u": account.display_username,
                    "issued": issued_at,
                    "exp": expires_at,
                },
            ).scalar_one()
            principal_id = UUID(result["principal_id"])
            from execbound.access_control import effective_kind

            kind = (
                "ADMIN"
                if effective_kind(conn, row.tenant_id, principal_id) == "ADMIN"
                else "HUMAN_APPROVER"
            )
            if invitation_id is not None:
                append_event(
                    conn,
                    row.tenant_id,
                    principal_id,
                    "identity.linked",
                    {
                        "principal_id": str(principal_id),
                        "provider_id": str(row.provider_id),
                        **withheld("subject", account.subject),
                        "via": "invitation",
                    },
                )
            append_event(
                conn,
                row.tenant_id,
                principal_id,
                "human_sign_in.directory",
                {
                    "credential_id": str(credential_id),
                    "kind": result["kind"],
                    "provider_id": str(row.provider_id),
                    **withheld("subject", account.subject),
                    "expires_at": expires_at.isoformat(),
                },
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None
    return Identity(row.tenant_id, principal_id, credential_id, kind, expires_at)


# The provider's own columns, named one by one rather than reused from the list above: a join
# that merges `tenant_id` and `provider_id` would otherwise return each of them twice and the
# row would not map onto `ProviderRow` at all.
_SESSION_ROW = """
SELECT f.subject, f.refresh_ciphertext, f.refresh_key_id, f.verified_at,
       p.tenant_id, p.provider_id, p.name, p.issuer, p.client_id, p.secret_ciphertext,
       p.secret_key_id, p.subject_claim, p.issuer_tenant, p.authorization_endpoint,
       p.token_endpoint, p.jwks_uri, p.state, p.created_at, p.verified_at AS provider_verified_at,
       p.enabled_at, p.disabled_at
FROM execbound.federated_sign_ins f
JOIN execbound.identity_providers p
  ON p.tenant_id = f.tenant_id AND p.provider_id = f.provider_id
WHERE f.tenant_id = :t AND f.credential_id = :c AND f.revoked_reason IS NULL
"""


def recheck_session(runtime: Runtime, directory: DirectoryConfig, session: Session) -> None:
    """Ask the directory whether a renewing session's account still exists, and act on the answer.

    Called from the one place both the pages and the console API load a session, and only when
    that session was just renewed, so the cost is one directory call about every seven and a
    half minutes of continuous use and nothing at all for a password or credential session.

    A refusal revokes the credential and every session under it, so the session is gone on this
    request. An unreachable directory is tolerated while the last verification is inside the
    grace and refuses the session after it, revoking nothing: an outage that resolves lets
    people carry on rather than forcing a tenant-wide sign-in.
    """
    identity = session.identity
    try:
        with runtime.db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            found = (
                conn.execute(
                    text(_SESSION_ROW), {"t": identity.tenant_id, "c": identity.credential_id}
                )
                .mappings()
                .one_or_none()
            )
    except (SQLAlchemyError, UnsafeDatabaseRole):
        # A read that failed says nothing about the account, and a session already proven by
        # `load_session` is not ended because this could not run.
        return
    if found is None:
        return
    now = _now(runtime.clock)
    verified_at = found["verified_at"].astimezone(UTC)
    if now - verified_at < RECHECK_INTERVAL:
        return
    row = _session_provider(found)
    stale = now - verified_at > RECHECK_GRACE
    if found["refresh_ciphertext"] is None:
        # The directory issued no refresh token, so there is nothing to redeem and nothing this
        # server can learn. It is unavailability, not a refusal.
        _unavailable(row, identity, "NO_REFRESH_TOKEN", stale=stale)
        return
    try:
        provider = directory.provider(row)
        token = unseal(
            directory.ring,
            found["refresh_ciphertext"],
            found["refresh_key_id"],
            row.tenant_id,
            row.provider_id,
            "refresh_token",
        )
    except EnvelopeError as exc:
        _unavailable(row, identity, exc.code, stale=stale)
        return
    answer = provider.recheck(token, found["subject"], now=now.timestamp())
    log_event(
        "directory.recheck",
        level="WARNING" if answer.state != "VERIFIED" else "INFO",
        state=answer.state,
        code=answer.code,
        tenant_id=identity.tenant_id,
        credential_id=identity.credential_id,
        provider_id=row.provider_id,
    )
    if answer.state == "REFUSED":
        revoke(runtime, row, identity, answer.code)
        raise SessionError("PROVIDER_REFUSED")
    if answer.state == "UNAVAILABLE":
        _unavailable(row, identity, answer.code, stale=stale)
        return
    _verified(runtime, directory, row, identity, answer.refresh_token)


def _session_provider(found: Any) -> ProviderRow:
    """The provider half of a directory session's row, as the relying party wants it."""
    return ProviderRow(
        tenant_id=found["tenant_id"],
        provider_id=found["provider_id"],
        name=found["name"],
        issuer=found["issuer"],
        client_id=found["client_id"],
        secret_ciphertext=found["secret_ciphertext"],
        secret_key_id=found["secret_key_id"],
        subject_claim=found["subject_claim"],
        issuer_tenant=found["issuer_tenant"],
        authorization_endpoint=found["authorization_endpoint"],
        token_endpoint=found["token_endpoint"],
        jwks_uri=found["jwks_uri"],
        state=found["state"],
        created_at=found["created_at"],
        verified_at=found["provider_verified_at"],
        enabled_at=found["enabled_at"],
        disabled_at=found["disabled_at"],
    )


def _unavailable(row: ProviderRow, identity: Identity, code: str, *, stale: bool) -> None:
    if not stale:
        return
    log_event(
        "directory.recheck",
        level="WARNING",
        state="STALE",
        code=code,
        tenant_id=identity.tenant_id,
        credential_id=identity.credential_id,
        provider_id=row.provider_id,
    )
    raise SessionError("PROVIDER_UNAVAILABLE")


def _verified(
    runtime: Runtime,
    directory: DirectoryConfig,
    row: ProviderRow,
    identity: Identity,
    refresh_token: str | None,
) -> None:
    ciphertext: str | None = None
    key_id: str | None = None
    if refresh_token is not None:
        try:
            ciphertext, key_id = seal(
                directory.ring, refresh_token, row.tenant_id, row.provider_id, "refresh_token"
            )
        except EnvelopeError:
            ciphertext, key_id = None, None
    try:
        with runtime.db.transaction(row.tenant_id) as conn:
            check_runtime(conn)
            conn.execute(
                text("SELECT execbound.directory_recheck(:c,:x,:k,:now)"),
                {
                    "c": identity.credential_id,
                    "x": ciphertext,
                    "k": key_id,
                    "now": _now(runtime.clock),
                },
            )
    except (DBAPIError, SQLAlchemyError, UnsafeDatabaseRole):
        # The directory said yes; failing to record that is not a reason to end the session.
        return


def revoke(runtime: Runtime, row: ProviderRow, identity: Identity, reason: str) -> None:
    """End a directory credential the provider refused, with one event per row it ended."""
    try:
        with runtime.db.transaction(row.tenant_id) as conn:
            check_runtime(conn)
            ended = conn.execute(
                text("SELECT execbound.directory_revoke(:c,:r,:now)"),
                {
                    "c": identity.credential_id,
                    "r": "PROVIDER_REFUSED",
                    "now": _now(runtime.clock),
                },
            ).scalar_one()
            append_event(
                conn,
                row.tenant_id,
                identity.principal_id,
                "identity.recheck_refused",
                {
                    "credential_id": str(identity.credential_id),
                    "provider_id": str(row.provider_id),
                    "reason": reason,
                },
            )
            _ended(conn, row.tenant_id, identity.principal_id, ended, "PROVIDER_REFUSED")
    except (DBAPIError, SQLAlchemyError, UnsafeDatabaseRole):
        raise DirectoryError("DIRECTORY_UNAVAILABLE") from None


def _link_of(conn: Connection, tenant_id: UUID, principal_id: UUID) -> Any:
    """One person's active link with its provider's name, or None; the subject and the two
    display hints are the directory's text and every reader renders them as text."""
    return (
        conn.execute(
            text(
                "SELECT l.provider_id, v.name AS provider_name, l.subject, l.via, "
                "l.display_name, l.display_username, l.created_at, l.last_sign_in_at "
                "FROM execbound.identity_links l "
                "JOIN execbound.identity_providers v USING (tenant_id, provider_id) "
                "WHERE l.tenant_id = :t AND l.principal_id = :p AND l.revoked_at IS NULL"
            ),
            {"t": tenant_id, "p": principal_id},
        )
        .mappings()
        .one_or_none()
    )


def directory_of(conn: Connection, tenant_id: UUID, principal_id: UUID, now: datetime) -> Any:
    """One person's directory account and pending invitation, under a fence the caller holds."""
    params = {"t": tenant_id, "p": principal_id, "now": now}
    link = _link_of(conn, tenant_id, principal_id)
    invitation = (
        conn.execute(
            text(
                "SELECT invitation_id, provider_id, expires_at FROM execbound.identity_invitations"
                " WHERE tenant_id = :t AND principal_id = :p AND redeemed_at IS NULL "
                "AND revoked_at IS NULL AND expires_at > :now"
            ),
            params,
        )
        .mappings()
        .one_or_none()
    )
    return {
        "link": dict(link) if link is not None else None,
        "invitation": dict(invitation) if invitation is not None else None,
    }


def own_directory(conn: Connection, tenant_id: UUID, principal_id: UUID) -> dict[str, Any]:
    """What My account says about the acting person's directory, under a fence they hold.

    The tenant's enabled provider, the only one a person who is not an administrator may link
    their own account through (`link_self`), and that person's own active link. The caller
    passes the session's own principal and nothing else, so there is no argument here that
    could name somebody else; a draft, a provider verified but not yet enabled and a disabled
    one are not offered, and the fence keeps every other tenant's rows out of both reads.
    """
    # Three columns, so neither the client secret's ciphertext nor anything else about the
    # registration is read for a person who is not its administrator.
    provider = (
        conn.execute(
            text(
                "SELECT provider_id, name, state FROM execbound.identity_providers "
                "WHERE tenant_id = :t AND state = 'enabled'"
            ),
            {"t": tenant_id},
        )
        .mappings()
        .one_or_none()
    )
    link = _link_of(conn, tenant_id, principal_id)
    return {
        "provider": dict(provider) if provider is not None else None,
        "link": dict(link) if link is not None else None,
    }


def provider_overview(
    runtime: Runtime, directory: DirectoryConfig | None, session: Session
) -> dict[str, Any]:
    """What the tenant settings page says about this tenant's provider, for an administrator."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        store.identity_check(conn, identity, runtime.clock, "ADMIN")
        check_session(conn, session, runtime.clock)
        found = provider_in(conn, identity.tenant_id)
        linked = 0
        last_sign_in = None
        self_linked = False
        if found is not None:
            counts = (
                conn.execute(
                    text(
                        "SELECT count(*) AS linked, max(last_sign_in_at) AS last_sign_in, "
                        "count(*) FILTER (WHERE principal_id = :me) AS mine "
                        "FROM execbound.identity_links "
                        "WHERE tenant_id = :t AND provider_id = :v AND revoked_at IS NULL"
                    ),
                    {
                        "t": identity.tenant_id,
                        "v": found["provider_id"],
                        "me": identity.principal_id,
                    },
                )
                .mappings()
                .one()
            )
            linked = int(counts["linked"])
            last_sign_in = counts["last_sign_in"]
            self_linked = bool(counts["mine"])
        store.identity_check(conn, identity, runtime.clock, "ADMIN")
        check_session(conn, session, runtime.clock)
    provider = None
    if found is not None:
        provider = {
            "provider_id": found["provider_id"],
            "name": found["name"],
            "issuer": found["issuer"],
            "client_id": found["client_id"],
            "subject_claim": found["subject_claim"],
            "state": found["state"],
            "created_at": found["created_at"],
            "verified_at": found["verified_at"],
            "enabled_at": found["enabled_at"],
            "linked": linked,
            "last_sign_in_at": last_sign_in,
            "self_linked": self_linked,
        }
    return {
        "configured": directory is not None,
        "redirect_uri": directory.redirect_uri if directory is not None else None,
        "sign_in_url": (
            f"{directory.origin.rstrip('/')}/login/directory/{found['provider_id']}"
            if directory is not None and found is not None and found["state"] == "enabled"
            else None
        ),
        "invite_url": (f"{directory.origin.rstrip('/')}/invite" if directory is not None else None),
        "subject_claims": list(SUBJECT_CLAIMS),
        "provider": provider,
    }
