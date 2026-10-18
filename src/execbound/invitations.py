# SPDX-License-Identifier: AGPL-3.0-only
"""Teammate invitations (#487): create, resend, revoke, list, deliver, drain and accept.

Migration 0059 holds the tables and the `SECURITY DEFINER` functions this module calls over
the runtime role; read their bodies in `migrations/versions/0059_workspace_invitations.py`
before changing a caller here. `inspect_invitation` and `accept_invitation` are the
recipient's own path: they need no workspace session, only the link, and for an address that
already has an account, that account signed in.

The link is `<origin>/join#ebt1.<tenant>.<invitation>.<secret>`, minted fresh inside every
send exactly as a sandbox invitation's is (`onboarding.py`'s `ebi1`): only the latest
delivered link ever works. Delivery is tenant-agnostic: `workspace_invitation_due` lists due
messages across every tenant through a definer function granted to the runtime role, so
`deliver_invitations` needs no identity, and its own transactions are per-message, fenced to
that message's own tenant.

The page is `/join`, not `/invite`: `directory_pages.py` already serves `GET/POST /invite` for
the customer-directory one-time invitation code (#241), registered ahead of this feature's own
router, and Starlette hands a request to the first route that matches path and method: a
second `/invite` route added here would never be reached. `/join` is free.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, NoReturn, cast
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database, UnsafeDatabaseRole, check_runtime
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.logging_schema import log_event
from execbound.resolution.models import Clock, SystemClock
from execbound.secrets import secret_shaped
from execbound.transports import MailConfig, SendResult, is_address, send_teammate_invitation

if TYPE_CHECKING:
    from execbound.identity import Identity
    from execbound.runtime import Runtime
    from execbound.surfaces.sessions import Session

TOKEN_PREFIX = "ebt1"  # nosec B105 - a link-token prefix, not a secret
_SECRET = re.compile(r"[A-Za-z0-9_-]{43}")
MAX_GRANTS = 20
MAX_ATTEMPTS = 5
BACKOFF = (300, 900, 3600, 10800, 43200)
MAX_DRAIN = 50
# `list_invitations`'s own bound (#487): a row older than `LIST_RECENT` drops off the list,
# filtered in the SQL itself rather than in Python so the read stays bounded. Filtering on
# `created_at` alone is enough to keep every still-pending row: resend never extends
# `expires_at`, so an unexpired PENDING row is already under 7 days old, well inside this
# 30-day window. A row this old and still PENDING is simply expired, Postgres never states
# that as a fourth `state` value, only a comparison against `expires_at` does, and an
# administrator does not need it dredged back up any more than a 30-day-old ACCEPTED or
# REVOKED one. `LIST_LIMIT` is a second, independent bound against the query growing without
# end even inside the window.
LIST_RECENT = timedelta(days=30)
LIST_LIMIT = 500
# Terminal `SendResult` codes: no retry ever resolves either one, so `_settle` fails the
# message on the first attempt rather than spending its five leases on a row that can never
# succeed. `INVALID_STATE` is the invitation moving out from under an in-flight send;
# `INVALID_ADDRESS` is a stored address `transports.is_address` refuses (#487):
# `create_invitation` refuses one before it is ever stored, so this is legacy or directly
# written data only.
_TERMINAL_CODES = frozenset({"INVALID_STATE", "INVALID_ADDRESS"})

# Every code the definer functions or this module itself may raise. A diagnostic never
# travels: a database message could quote a value, and the values here are addresses.
_CODES = frozenset(
    {
        "FORBIDDEN",
        "INVALID_EMAIL",
        "INVALID_ROLES",
        "INVALID_ROLE",
        "INVALID_ROLE_SCOPE",
        "INVALID_SPACE",
        "INVITATION_PENDING",
        "ALREADY_MEMBER",
        "INVALID_CLOCK",
        "INVALID_REQUEST",
        "NOT_FOUND",
        "INVALID_STATE",
        "RESEND_LIMIT",
        "INVALID_DIGEST",
        # Acceptance: `workspace_invitation_accept` itself, and the `access_change` it makes
        # as the inviter inside the same transaction.
        "INVALID_TOKEN",
        "INVITATION_REVOKED",
        "INVALID_TENANT",
        "ACCOUNT_EXISTS",
        "ACCOUNT_MISMATCH",
        "INVALID_PRINCIPAL",
        "LAST_ADMINISTRATOR",
        "CONFLICT",
        # `workspace_invitation_set_group`: the reviewer group grants more than the invitation
        # shows, belongs to no group of this workspace, or the invitation grants no Approver.
        "INVALID_GROUP",
    }
)


class InvitationError(ValueError):
    """Safe errors carry a code and never an address, token or database diagnostic."""

    def __init__(self, code: str = "INVITATION_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Invitation unavailable")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def new_invitation_token(tenant: UUID, invitation: UUID) -> tuple[str, str]:
    token = f"{TOKEN_PREFIX}.{tenant}.{invitation}.{secrets.token_urlsafe(32)}"
    return token, _hash(token)


def invitation_selectors(token: object) -> tuple[UUID, UUID]:
    """The tenant and invitation a code names; untrusted until the database matched its hash."""
    try:
        if type(token) is not str or len(token) > 160 or not token.isascii():
            raise ValueError
        version, tenant_text, invitation_text, secret = token.split(".")
        tenant, invitation = UUID(tenant_text), UUID(invitation_text)
        if (
            version != TOKEN_PREFIX
            or str(tenant) != tenant_text
            or str(invitation) != invitation_text
            or _SECRET.fullmatch(secret) is None
        ):
            raise ValueError
        return tenant, invitation
    except ValueError:
        raise InvitationError("INVALID_TOKEN") from None


def invite_link(origin: str) -> str:
    """The page a link opens. The origin is the configured public one, never a Host header."""
    return f"{origin.rstrip('/')}/join"


def _call(conn: Connection, statement: str, params: dict[str, Any]) -> Any:
    """Run one definer function; a refusal surfaces as its code, nothing else."""
    try:
        return conn.execute(text(statement), params).scalar_one()
    except DBAPIError as exc:
        diagnostic = getattr(exc.orig, "diag", None)
        message = getattr(diagnostic, "message_primary", None)
        raise InvitationError(message if message in _CODES else "INVITATION_UNAVAILABLE") from None


# --- Grant validation --------------------------------------------------------------------------


def _validate_grants(grants: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """The same shape SQL's own `GRANT_CHECK` enforces, applied here so a malformed grant is
    refused without a database round trip. SQL checks again; this never replaces it.

    `space_id` absent, `None`, or a UUID string in any form Python's own `UUID` accepts is
    normalized to `str(UUID(value))`, the canonical lowercase 8-4-4-4-12 form; the same
    form SQL itself stores. Anything else is `INVALID_ROLES` (the grant's shape) or
    `INVALID_SPACE` (the identifier itself).
    """
    if grants is None:
        return [{"role": "viewer", "space_id": None}]
    if type(grants) is not list or not 1 <= len(grants) <= MAX_GRANTS:
        raise InvitationError("INVALID_ROLES")
    normalized = []
    for item in grants:
        if type(item) is not dict or set(item) - {"role", "space_id"}:
            raise InvitationError("INVALID_ROLES")
        space_id = item.get("space_id")
        if space_id is not None:
            if type(space_id) is not str:
                raise InvitationError("INVALID_SPACE")
            try:
                space_id = str(UUID(space_id))
            except (ValueError, AttributeError, TypeError):
                raise InvitationError("INVALID_SPACE") from None
        normalized.append({"role": item.get("role"), "space_id": space_id})
    return normalized


# --- The console's own calls -------------------------------------------------------------------


def _create_once(
    conn: Connection,
    actor: UUID,
    invitation_id: UUID,
    message_id: UUID,
    email: str,
    grants: list[dict[str, Any]],
    now: datetime,
) -> datetime:
    """One `workspace_invitation_create` attempt, in its own savepoint.

    The function's own `EXCEPTION WHEN unique_violation` block catches the insert, but its
    `RAISE EXCEPTION 'INVITATION_PENDING'` afterward is uncaught inside the function and
    aborts the calling transaction at the Postgres level unless a savepoint bounds it. The
    expired-invitation retry needs the outer transaction to survive that refusal so it can
    revoke the expired row and try again in the same transaction; the savepoint is what
    makes that possible.
    """
    with conn.begin_nested():
        return cast(
            datetime,
            _call(
                conn,
                "SELECT execbound.workspace_invitation_create"
                "(:a, :i, :e, CAST(:g AS jsonb), :m, :n)",
                {
                    "a": actor,
                    "i": invitation_id,
                    "e": email,
                    "g": json.dumps(grants),
                    "m": message_id,
                    "n": now,
                },
            ),
        )


def _name_group(
    conn: Connection, actor: UUID, invitation_id: UUID, group: UUID, now: datetime
) -> None:
    """The reviewer group the invitation's Approver joins on acceptance, set once, in the
    creating transaction. `workspace_invitation_set_group` refuses a group that grants more
    than the invitation shows; the refusal rolls the whole creation back."""
    _call(
        conn,
        "SELECT execbound.workspace_invitation_set_group(:a, :i, :g, :n)",
        {"a": actor, "i": invitation_id, "g": group, "n": now},
    )


def create_invitation(
    runtime: Runtime,
    session: Session,
    email: str,
    grants: list[dict[str, Any]] | None,
    *,
    reviewer_group: UUID | None = None,
) -> dict[str, Any]:
    """An administrator's own invitation. `grants=None` is one workspace-scope viewer grant.

    `reviewer_group` names the group the invited person joins when they accept. It is checked
    here, through `workspace_invitation_set_group`, and again at acceptance, and the membership
    exists only once they accept.

    An expired pending invitation for the same address does not block a new one: on
    `INVITATION_PENDING`, the existing row is read back, and only when it is actually
    expired is it revoked, through `workspace_invitation_revoke`, as this same actor, with
    its own `invitation.revoked` audit event (`reason: EXPIRED`), before the create is
    retried, all inside this one transaction. An unexpired pending invitation still refuses
    `INVITATION_PENDING`.

    The address is normalized (stripped, lowercased) and checked with `transports.is_address`
    before anything else, the same shape `signups.py`'s own `normalized_address` uses for the
    open waitlist. SQL's own regex (`^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$`) is looser than
    `is_address` and would accept something a real address never is, such as
    `o'brien@example.org`, and a row that shape can reach `render_teammate_invitation`
    inside the drain, which refuses it with a bare `ValueError` that must never reach here.
    """
    if type(email) is not str:
        raise InvitationError("INVALID_EMAIL")
    email = email.strip().lower()
    if not is_address(email):
        raise InvitationError("INVALID_EMAIL")
    # Only the domain reaches `invitation.created`, so only the domain is screened, and the
    # value screened here is the exact value the event below carries: `is_address` has
    # already guaranteed exactly one `@`, so the split below always has a second element.
    domain = email.rsplit("@", 1)[1]
    if secret_shaped(domain):
        raise InvitationError("INVALID_EMAIL")
    normalized_grants = _validate_grants(grants)
    invitation_id, message_id = uuid4(), uuid4()
    tenant, actor = session.identity.tenant_id, session.identity.principal_id
    from execbound.surfaces.sessions import check_session

    try:
        with runtime.db.transaction(tenant) as conn:
            check_runtime(conn)
            store.fence(conn, tenant, runtime.clock)
            check_session(conn, session, runtime.clock)
            now = store.now(runtime.clock)
            try:
                expires_at = _create_once(
                    conn, actor, invitation_id, message_id, email, normalized_grants, now
                )
            except InvitationError as exc:
                if exc.code != "INVITATION_PENDING":
                    raise
                existing = (
                    conn.execute(
                        text(
                            "SELECT invitation_id, expires_at "
                            "FROM execbound.workspace_invitations "
                            "WHERE tenant_id = :t AND email = :e AND state = 'PENDING'"
                        ),
                        {"t": tenant, "e": email},
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is None or existing["expires_at"] > now:
                    raise
                existing_id = UUID(str(existing["invitation_id"]))
                _call(
                    conn,
                    "SELECT execbound.workspace_invitation_revoke(:a, :i, :n)",
                    {"a": actor, "i": existing_id, "n": now},
                )
                append_event(
                    conn,
                    tenant,
                    actor,
                    "invitation.revoked",
                    {"invitation_id": str(existing_id), "reason": "EXPIRED"},
                )
                expires_at = _create_once(
                    conn, actor, invitation_id, message_id, email, normalized_grants, now
                )
            created: dict[str, Any] = {
                "invitation_id": str(invitation_id),
                "email_domain": domain,
                "grants": normalized_grants,
                "expires_at": expires_at.isoformat(),
            }
            if reviewer_group is not None:
                _name_group(conn, actor, invitation_id, reviewer_group, now)
                created["reviewer_group_id"] = str(reviewer_group)
            append_event(conn, tenant, actor, "invitation.created", created)
    except InvitationError as exc:
        log_event(
            "invitation.refused",
            level="WARNING",
            code=exc.code,
            tenant_id=tenant,
            principal_id=actor,
        )
        raise
    except SQLAlchemyError:
        raise InvitationError() from None
    log_event(
        "invitation.created", tenant_id=tenant, principal_id=actor, invitation_id=invitation_id
    )
    return {
        "invitation_id": invitation_id,
        "email": email,
        "grants": normalized_grants,
        "expires_at": expires_at,
        # The console's create route uses this to schedule the fast first send
        # (`deliver_one`) without a second read; `create_invitation` mints it locally (see
        # `invitation_id, message_id = uuid4(), uuid4()` above).
        "message_id": message_id,
    }


def resend_invitation(runtime: Runtime, session: Session, invitation_id: UUID) -> UUID:
    """Return the message to the outbox, and hand back its message id.

    One row per invitation, so the id is a plain read inside the same transaction: the
    console's resend route uses it to schedule the same fast first send `create_invitation`
    gets (#487), rather than leaving the administrator's retry to wait for the scheduled
    drain.
    """
    from execbound.surfaces.sessions import check_session

    tenant, actor = session.identity.tenant_id, session.identity.principal_id
    try:
        with runtime.db.transaction(tenant) as conn:
            check_runtime(conn)
            store.fence(conn, tenant, runtime.clock)
            check_session(conn, session, runtime.clock)
            now = store.now(runtime.clock)
            _call(
                conn,
                "SELECT execbound.workspace_invitation_resend(:a, :i, :n)",
                {"a": actor, "i": invitation_id, "n": now},
            )
            message_id = conn.execute(
                text(
                    "SELECT message_id FROM execbound.workspace_invitation_messages "
                    "WHERE tenant_id = :t AND invitation_id = :i"
                ),
                {"t": tenant, "i": invitation_id},
            ).scalar_one()
            append_event(
                conn, tenant, actor, "invitation.resent", {"invitation_id": str(invitation_id)}
            )
    except InvitationError as exc:
        log_event(
            "invitation.refused",
            level="WARNING",
            code=exc.code,
            tenant_id=tenant,
            principal_id=actor,
        )
        raise
    except SQLAlchemyError:
        raise InvitationError() from None
    return UUID(str(message_id))


def revoke_invitation(runtime: Runtime, session: Session, invitation_id: UUID) -> None:
    from execbound.surfaces.sessions import check_session

    tenant, actor = session.identity.tenant_id, session.identity.principal_id
    try:
        with runtime.db.transaction(tenant) as conn:
            check_runtime(conn)
            store.fence(conn, tenant, runtime.clock)
            check_session(conn, session, runtime.clock)
            now = store.now(runtime.clock)
            _call(
                conn,
                "SELECT execbound.workspace_invitation_revoke(:a, :i, :n)",
                {"a": actor, "i": invitation_id, "n": now},
            )
            append_event(
                conn, tenant, actor, "invitation.revoked", {"invitation_id": str(invitation_id)}
            )
    except InvitationError as exc:
        log_event(
            "invitation.refused",
            level="WARNING",
            code=exc.code,
            tenant_id=tenant,
            principal_id=actor,
        )
        raise
    except SQLAlchemyError:
        raise InvitationError() from None


def list_invitations(runtime: Runtime, session: Session) -> list[dict[str, Any]]:
    """Every invitation this workspace made in the last `LIST_RECENT`, newest first, bounded
    at `LIST_LIMIT`. Requires `access.manage`.

    An administrator of this workspace may see the address they invited: unlike a log line,
    this listing is the operator's own read of their own workspace, and nothing here reaches
    a chain, a log or another tenant. The cutoff and the limit are both applied in the SQL
    itself (#487), not filtered afterward in Python, so the read stays bounded regardless of
    how many invitations a long-lived tenant has ever made.
    """
    from execbound.access_control import has_permission
    from execbound.surfaces.sessions import check_session

    tenant, actor = session.identity.tenant_id, session.identity.principal_id
    try:
        with runtime.db.transaction(tenant) as conn:
            check_runtime(conn)
            store.fence(conn, tenant, runtime.clock)
            check_session(conn, session, runtime.clock)
            if not has_permission(conn, tenant, actor, "access.manage"):
                raise InvitationError("FORBIDDEN")
            cutoff = store.now(runtime.clock) - LIST_RECENT
            rows = (
                conn.execute(
                    text(
                        "SELECT i.invitation_id, i.email, i.grants, i.state, i.created_at, "
                        "i.expires_at, i.sends, m.last_error, m.delivered_at, "
                        "i.reviewer_group_id, g.name AS reviewer_group_name "
                        "FROM execbound.workspace_invitations i "
                        "JOIN execbound.workspace_invitation_messages m "
                        "  ON m.tenant_id = i.tenant_id AND m.invitation_id = i.invitation_id "
                        "LEFT JOIN execbound.access_groups g "
                        "  ON g.tenant_id = i.tenant_id AND g.group_id = i.reviewer_group_id "
                        "WHERE i.tenant_id = :t AND i.created_at >= :cutoff "
                        "ORDER BY i.created_at DESC, i.invitation_id "
                        "LIMIT :limit"
                    ),
                    {"t": tenant, "cutoff": cutoff, "limit": LIST_LIMIT},
                )
                .mappings()
                .all()
            )
            return [dict(row) for row in rows]
    except InvitationError as exc:
        log_event(
            "invitation.refused",
            level="WARNING",
            code=exc.code,
            tenant_id=tenant,
            principal_id=actor,
        )
        raise
    except SQLAlchemyError:
        raise InvitationError() from None


# --- The tenant-agnostic drain -------------------------------------------------------------------


def _check_drain_policy(conn: Connection) -> None:
    """The `owner_drain` policy is what lets `workspace_invitation_due` see every tenant's
    due messages under an owner that does not bypass RLS (#487): a later migration that
    recreated the messages table without it, or a migration applied under a role other than
    the function owner, would leave a local superuser owner still seeing every row while a
    deployment's drain silently delivered nothing. `check_runtime` covers tables, grants,
    columns and functions but not policies, so this reads `pg_policy` itself, the same shape
    TI1 already proves once at migration time, every time the batch drain runs: the policy
    must exist, must be a `SELECT` policy, and must name exactly one role, the owner of
    `workspace_invitation_due`. `pg_policy` and `pg_proc` are ordinary system catalogs the
    runtime role can read without any extra grant.
    """
    row = (
        conn.execute(
            text("""
        SELECT pol.polcmd, pol.polpermissive,
               ARRAY(SELECT pg_get_userbyid(r) FROM unnest(pol.polroles) r) AS roles,
               (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'execbound'
                  AND p.proname = 'workspace_invitation_due') AS owner
        FROM pg_policy pol
        WHERE pol.polrelid = 'execbound.workspace_invitation_messages'::regclass
          AND pol.polname = 'owner_drain'
    """)
        )
        .mappings()
        .one_or_none()
    )
    if (
        row is None
        or row["polcmd"] != "r"
        or not row["polpermissive"]
        or list(row["roles"]) != [row["owner"]]
    ):
        raise InvitationError("UNSAFE_DRAIN_POLICY")


def _due(db: Database, clock: Clock, limit: int) -> list[tuple[UUID, UUID]]:
    """Due (tenant, message) pairs across every tenant, through the owner-only cross-tenant
    read `workspace_invitation_due` grants. No tenant fence decides what this call sees; the
    transaction it runs in exists only to hold a connection, so any tenant id opens one."""
    with db.transaction(uuid4()) as conn:
        check_runtime(conn)
        _check_drain_policy(conn)
        rows = conn.execute(
            text(
                "SELECT tenant_id, message_id FROM execbound.workspace_invitation_due(:n, :limit)"
            ),
            {"n": store.now(clock), "limit": limit},
        ).all()
    return [(UUID(str(tenant)), UUID(str(message))) for tenant, message in rows]


def _lease(
    db: Database, tenant: UUID, message_id: UUID, clock: Clock, lease: UUID
) -> dict[str, Any] | None:
    """Take one already-selected message under its own tenant's fence, in its own
    transaction: a second drain racing the same due list finds the row locked and
    `SKIP LOCKED` returns nothing here, rather than blocking or double-sending."""
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            now = store.now(clock)
            row = (
                conn.execute(
                    text("""
                SELECT m.message_id, m.invitation_id, m.attempts
                  FROM execbound.workspace_invitation_messages m
                 WHERE m.tenant_id = :t AND m.message_id = :m AND (
                   (m.state = 'PENDING' AND m.next_attempt_at <= :now)
                   OR (m.state = 'IN_FLIGHT' AND m.lease_until <= :now))
                 FOR UPDATE OF m SKIP LOCKED
                """),
                    {"t": tenant, "m": message_id, "now": now},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            message = dict(row)
            if int(message["attempts"]) >= MAX_ATTEMPTS:
                conn.execute(
                    text(
                        "UPDATE execbound.workspace_invitation_messages SET state='FAILED', "
                        "last_error='DELIVERY_UNCERTAIN', lease_until=NULL, lease_token=NULL "
                        "WHERE tenant_id=:t AND message_id=:m"
                    ),
                    {"t": tenant, "m": message_id},
                )
                return {**message, "spent": True}
            conn.execute(
                text(
                    "UPDATE execbound.workspace_invitation_messages SET state='IN_FLIGHT', "
                    "attempts=attempts+1, lease_token=:lease, lease_until=:until "
                    "WHERE tenant_id=:t AND message_id=:m"
                ),
                {
                    "t": tenant,
                    "m": message_id,
                    "lease": lease,
                    "until": now + timedelta(seconds=60),
                },
            )
            return {**message, "spent": False}
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        return None


def _send(
    db: Database,
    tenant: UUID,
    message: dict[str, Any],
    mail: MailConfig,
    link: str,
    clock: Clock,
    tls_context: ssl.SSLContext | None,
) -> SendResult | None:
    """The rekey, in its own transaction, then the send outside any transaction."""
    if message["spent"]:
        return None
    invitation_id = UUID(str(message["invitation_id"]))
    token, digest = new_invitation_token(tenant, invitation_id)
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            expires_at = _call(
                conn,
                "SELECT execbound.workspace_invitation_rekey(:i, :h, :n)",
                {"i": invitation_id, "h": digest, "n": store.now(clock)},
            )
            row = (
                conn.execute(
                    text(
                        "SELECT inv.email, t.name AS workspace, "
                        "coalesce(p.label, p.email) AS inviter "
                        "FROM execbound.workspace_invitations inv "
                        "JOIN execbound.tenants t ON t.tenant_id = inv.tenant_id "
                        "LEFT JOIN execbound.principals p "
                        "  ON p.tenant_id = inv.tenant_id AND p.principal_id = inv.inviter_id "
                        "WHERE inv.tenant_id = :t AND inv.invitation_id = :i"
                    ),
                    {"t": tenant, "i": invitation_id},
                )
                .mappings()
                .one()
            )
    except InvitationError as exc:
        # Only a real `INVALID_STATE` from the rekey itself (accepted or revoked out from
        # under this attempt) is terminal. Everything else (a clock skew, a dropped
        # connection, `_call`'s own fallback for a code-less database error) is transient
        # and must retry.
        code = "INVALID_STATE" if exc.code == "INVALID_STATE" else "RECEIVER_UNAVAILABLE"
        return SendResult(False, code)
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        return SendResult(False, "RECEIVER_UNAVAILABLE")
    try:
        return send_teammate_invitation(
            mail,
            str(row["email"]),
            invitation_id,
            str(row["workspace"]),
            row["inviter"],
            link,
            token,
            expires_at.astimezone(UTC),
            context=tls_context,
        )
    except ValueError:
        # `create_invitation` refuses an address `is_address` would refuse, but a row from
        # before that check existed, or written directly, can still hold one. Terminal, like
        # `INVALID_STATE`: no retry will ever make a stored address valid, and one such row
        # must never stall every other tenant's due message behind it (#487).
        return SendResult(False, "INVALID_ADDRESS")


def _settle(
    db: Database,
    tenant: UUID,
    clock: Clock,
    message: dict[str, Any],
    lease: UUID,
    result: SendResult | None,
    counts: dict[str, int],
) -> None:
    """Settle one attempt, in its own transaction.

    Guarded the same way `_lease` and `_send` are (`SQLAlchemyError`, `UnsafeDatabaseRole`,
    `ValueError`, #487): a fault opening or running this transaction counts the message as
    failed and returns rather than ending the run for every other due message. The row
    itself is untouched by a fault here, so it stays `IN_FLIGHT` with the lease `_lease`
    already set, and is retried once that lease expires; nothing is lost.
    """
    if result is None:
        counts["failed"] += 1
        return
    attempts = int(message["attempts"]) + 1
    invitation_id = UUID(str(message["invitation_id"]))
    state: str
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            params = {"t": tenant, "m": message["message_id"], "lease": lease}
            if result.delivered:
                conn.execute(
                    text(
                        "UPDATE execbound.workspace_invitation_messages SET state='DELIVERED', "
                        "delivered_at=:now, lease_until=NULL, lease_token=NULL, last_error=NULL "
                        "WHERE tenant_id=:t AND message_id=:m AND lease_token=:lease"
                    ),
                    {**params, "now": store.now(clock)},
                )
                state = "DELIVERED"
            elif attempts >= MAX_ATTEMPTS or result.code in _TERMINAL_CODES:
                conn.execute(
                    text(
                        "UPDATE execbound.workspace_invitation_messages SET state='FAILED', "
                        "last_error=:code, lease_until=NULL, lease_token=NULL "
                        "WHERE tenant_id=:t AND message_id=:m AND lease_token=:lease"
                    ),
                    {**params, "code": result.code},
                )
                state = "FAILED"
            else:
                delay = result.retry_after or BACKOFF[min(attempts, MAX_ATTEMPTS) - 1]
                conn.execute(
                    text(
                        "UPDATE execbound.workspace_invitation_messages SET state='PENDING', "
                        "next_attempt_at=:next, last_error=:code, lease_until=NULL, "
                        "lease_token=NULL "
                        "WHERE tenant_id=:t AND message_id=:m AND lease_token=:lease"
                    ),
                    {
                        **params,
                        "code": result.code,
                        "next": store.now(clock) + timedelta(seconds=delay),
                    },
                )
                state = "PENDING"
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        counts["failed"] += 1
        return
    # Counted only once the settle has committed, so a fault at commit counts it failed once.
    counts[{"DELIVERED": "delivered", "FAILED": "failed", "PENDING": "deferred"}[state]] += 1
    log_event(
        "invitation.sent",
        level="INFO" if result.delivered else "WARNING",
        tenant_id=tenant,
        invitation_id=invitation_id,
        state=state,
        code=result.code,
    )


def deliver_invitations(
    db: Database,
    *,
    mail: MailConfig,
    origin: str,
    limit: int = MAX_DRAIN,
    clock: Clock | None = None,
    tls_context: ssl.SSLContext | None = None,
) -> dict[str, int]:
    """Send every due teammate invitation, minting a fresh link inside each attempt.

    Needs no identity: `workspace_invitation_due` reaches every tenant on its own, including
    one that no jobs token names, a tenant `community_provision` made. Lease, rekey and settle
    each run in their own transaction, one pair at a time.
    """
    clock = clock or SystemClock()
    if type(limit) is not int or not 1 <= limit <= MAX_DRAIN:
        raise InvitationError("INVALID_LIMIT")
    if type(mail) is not MailConfig:
        raise InvitationError("INVALID_CONFIGURATION")
    link = invite_link(origin)
    counts = {"delivered": 0, "failed": 0, "deferred": 0}
    for tenant, message_id in _due(db, clock, limit):
        lease = uuid4()
        leased = _lease(db, tenant, message_id, clock, lease)
        if leased is None:
            continue
        result = _send(db, tenant, leased, mail, link, clock, tls_context)
        _settle(db, tenant, clock, leased, lease, result, counts)
    return counts


def deliver_one(
    db: Database,
    tenant: UUID,
    message_id: UUID,
    *,
    mail: MailConfig,
    origin: str,
    clock: Clock | None = None,
    tls_context: ssl.SSLContext | None = None,
) -> bool:
    """The gateway's best-effort first send, right after `create_invitation`.

    Never raises: a failure here just leaves the message for the next scheduled drain, so
    the console request that created the invitation is never made to wait on mail delivery.
    """
    clock = clock or SystemClock()
    try:
        if type(mail) is not MailConfig:
            return False
        link = invite_link(origin)
        lease = uuid4()
        leased = _lease(db, tenant, message_id, clock, lease)
        if leased is None:
            return False
        result = _send(db, tenant, leased, mail, link, clock, tls_context)
        counts = {"delivered": 0, "failed": 0, "deferred": 0}
        _settle(db, tenant, clock, leased, lease, result, counts)
        return counts["delivered"] == 1
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        # Never a diagnostic: a database message could quote the address this call is about.
        # Traceable only as a line naming the tenant, not silent (#487).
        log_event(
            "invitation.refused",
            level="WARNING",
            tenant_id=tenant,
            code="INVITATION_UNAVAILABLE",
        )
        return False


# --- The recipient's own path: inspection and acceptance -----------------------------------


@dataclass(frozen=True)
class Inspected:
    """What a link is for, as `workspace_invitation_check` tells whoever holds it.

    `state` is `PENDING`, `ACCEPTED`, `REVOKED` or `EXPIRED`. `account` is `new` when nobody
    signs in with the address yet, `existing` when an account holds it, and `legacy` when an
    active ADMIN or HUMAN_APPROVER set up before accounts existed holds it and no account
    does, the same meaning `community_signup.inspect` gives it: both of the last two sign in
    before they accept.
    """

    invitation_id: UUID
    tenant_id: UUID
    email: str
    state: str
    workspace: str
    grants: list[dict[str, Any]]
    space_names: dict[str, str]
    inviter: str | None
    account: str


@dataclass(frozen=True)
class Accepted:
    """One acceptance's committed outcome, `ACCEPTED` or `ALREADY`.

    Only an acceptance that created its account carries `account_version`, which is what
    `sign_in_invited_account` needs; a signed-in account already has its session.
    `reviewer_group` is what became of the group the invitation named: `None` when it named
    none, else its `group_id`, whether it was `applied`, and the `reason` it was not.
    """

    outcome: str
    tenant_id: UUID
    principal_id: UUID | None = None
    account_id: UUID | None = None
    account_version: int | None = None
    reviewer_group: dict[str, Any] | None = None


def _refuse(code: str, tenant: UUID, invitation: UUID) -> NoReturn:
    """Log one refusal by its code and the ids the link named, then raise it.

    Never the address, the token or its digest, and never a database diagnostic.
    """
    log_event(
        "invitation.refused",
        level="ERROR" if code == "INVITATION_UNAVAILABLE" else "WARNING",
        code=code,
        tenant_id=tenant,
        invitation_id=invitation,
    )
    # Called from inside `except` blocks too: the error it replaces, and any diagnostic that
    # error carried, never travels with it.
    raise InvitationError(code) from None


def inspect_invitation(db: Database, token: object, *, clock: Clock | None = None) -> Inspected:
    """What a link is for, told only to whoever holds it. Changes nothing but a miss count."""
    clock = clock or SystemClock()
    tenant, invitation = invitation_selectors(token)
    assert isinstance(token, str)
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            found = conn.execute(
                text("SELECT execbound.workspace_invitation_check(:i, :h, :n)"),
                {"i": invitation, "h": _hash(token), "n": store.now(clock)},
            ).scalar_one()
    except (SQLAlchemyError, UnsafeDatabaseRole, ExecutionError, ValueError):
        _refuse("INVITATION_UNAVAILABLE", tenant, invitation)
    # A miss was counted in the transaction above, which committed; only now is it a refusal.
    if found is None:
        _refuse("INVALID_TOKEN", tenant, invitation)
    email = str(found["email"])
    from execbound.user_accounts import legacy_holder, locate_account

    try:
        if locate_account(db, email) is not None:
            account = "existing"
        elif legacy_holder(db, email):
            account = "legacy"
        else:
            account = "new"
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        _refuse("INVITATION_UNAVAILABLE", tenant, invitation)
    return Inspected(
        invitation,
        tenant,
        email,
        str(found["state"]),
        str(found["workspace"]),
        list(found["grants"]),
        dict(found["space_names"]),
        found["inviter_label"],
        account,
    )


def accept_invitation(
    db: Database,
    token: object,
    *,
    password: object = None,
    session: Session | None = None,
    account_token: str | None = None,
    clock: Clock | None = None,
) -> Accepted:
    """Join the workspace a link names, as a new account or as the signed-in one.

    Exactly one proof of the person: a new password for an address nobody signs in with yet,
    or a signed-in account session with its account cookie. Everything else, including the
    inviter's authority as it stands now, is checked again inside one transaction.
    """
    clock = clock or SystemClock()
    tenant, invitation = invitation_selectors(token)
    assert isinstance(token, str)
    if (password is None) == (session is None):
        _refuse("INVALID_REQUEST", tenant, invitation)
    record: dict[str, Any] | None = None
    if password is not None:
        from execbound.passwords import PasswordError, check_password, hash_password

        seen = inspect_invitation(db, token, clock=clock)
        if seen.state == "ACCEPTED":
            return Accepted("ALREADY", tenant)
        # A link that will only ever be refused is refused before `hash_password`, whose
        # deliberate cost must not be handed to whoever holds a dead link for free.
        if seen.state == "EXPIRED":
            _refuse("INVALID_TOKEN", tenant, invitation)
        if seen.state == "REVOKED":
            _refuse("INVITATION_REVOKED", tenant, invitation)
        if seen.account != "new":
            # An address with an account, or held by an active legacy person whose first
            # password sign-in adopts theirs, signs in first. This answer can be stale by the
            # time the account is made, so `workspace_invitation_accept` applies the same
            # predicate again, in its own transaction, before it creates one.
            _refuse("ACCOUNT_EXISTS", tenant, invitation)
        try:
            record = hash_password(check_password(password, seen.email)).parameters()
        except PasswordError:
            _refuse("INVALID_PASSWORD", tenant, invitation)
    return _accept_once(db, tenant, invitation, token, record, session, account_token, clock)


def _prove_account(
    conn: Connection,
    tenant: UUID,
    session: Session,
    account_token: str | None,
    clock: Clock,
) -> UUID:
    """The signed-in account, proven in the accepting transaction and before any lock.

    `community_signup._prove_account`'s own recipe: the account cookie and the workspace
    session it stands in are both rechecked here, reading under the session's own tenant, and
    then the account becomes this transaction's `execbound.account_id`, which is how
    `workspace_invitation_accept` learns who is signed in. A session still waiting for its MFA
    fails `check_session`. A stale or forged proof is the same refusal as a different
    account's: sign in again.
    """
    from execbound.surfaces.sessions import SessionError, check_session
    from execbound.user_accounts import account_context, check_account_cookie

    try:
        if account_token is None or session.account_id is None:
            raise SessionError("ACCOUNT_SIGN_IN_REQUIRED")
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(session.identity.tenant_id)},
        )
        check_account_cookie(conn, session, account_token, clock.now())
        check_session(conn, session, clock)
    except SessionError:
        raise InvitationError("ACCOUNT_MISMATCH") from None
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
    account_context(conn, session.account_id)
    return session.account_id


def _accept_once(
    db: Database,
    tenant: UUID,
    invitation: UUID,
    token: str,
    record: dict[str, Any] | None,
    session: Session | None,
    account_token: str | None,
    clock: Clock,
) -> Accepted:
    # The principal id, then the account id: tests predict both in this order.
    principal = uuid4()
    account = uuid4() if record is not None else None
    result: dict[str, Any] | None
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            if session is not None:
                from execbound.user_accounts import lock_account

                # Lock order (migration 0059, `workspace_invitation_accept`'s first comment):
                # the account, then the tenant fence, then the function. A new address has no
                # account to lock yet and takes the fence first.
                lock_account(conn, _prove_account(conn, tenant, session, account_token, clock))
            store.fence(conn, tenant, clock)
            result = _call(
                conn,
                "SELECT execbound.workspace_invitation_accept("
                ":i, :h, :p, CAST(:a AS uuid), CAST(:pw AS jsonb), :n)",
                {
                    "i": invitation,
                    "h": _hash(token),
                    "p": principal,
                    "a": account,
                    "pw": json.dumps(record) if record is not None else None,
                    "n": store.now(clock),
                },
            )
            if result is not None and result["outcome"] == "ACCEPTED":
                _record_acceptance(conn, tenant, invitation, principal, result)
    except InvitationError as exc:
        # Raised inside the transaction, so it rolled back: nothing was made or counted.
        _refuse(exc.code, tenant, invitation)
    except (SQLAlchemyError, UnsafeDatabaseRole, ExecutionError, ValueError):
        _refuse("INVITATION_UNAVAILABLE", tenant, invitation)
    # Only now, after commit, is a mismatch a refusal: its count is written.
    if result is None:
        _refuse("INVALID_TOKEN", tenant, invitation)
    if result["outcome"] == "ALREADY":
        return Accepted("ALREADY", tenant)
    log_event(
        "invitation.accepted", tenant_id=tenant, principal_id=principal, invitation_id=invitation
    )
    return Accepted(
        "ACCEPTED",
        tenant,
        principal,
        UUID(str(result["account_id"])),
        int(result["account_version"]) if record is not None else None,
        result.get("reviewer_group"),
    )


def _record_acceptance(
    conn: Connection,
    tenant: UUID,
    invitation: UUID,
    principal: UUID,
    result: dict[str, Any],
) -> None:
    """The acceptance's own evidence, in the tenant's chain and the same transaction.

    The grant decision is the inviter's, made through `access_change`, so it is recorded
    exactly as `access_control` records every other one, promotion revocations included. No
    address and no token: the principal id, the invitation id and the grants say who joined.

    A reviewer group the invitation named was applied, or skipped, by the acceptance itself,
    under the inviter's re-checked authority. An applied one is the inviter's group change too,
    recorded as `access.group_member_added` between the grants and the acceptance; either way
    `invitation.accepted` says what became of it.
    """
    from execbound.access_control import record_change

    append_event(
        conn,
        tenant,
        principal,
        "principal.created",
        {"principal_id": str(principal), "kind": "HUMAN_APPROVER"},
    )
    record_change(
        conn,
        tenant,
        UUID(str(result["inviter_id"])),
        "set_user_roles",
        result["changed"],
        {"grants": result["grants"]},
        f"invitation {invitation} accepted",
    )
    accepted: dict[str, Any] = {"invitation_id": str(invitation), "principal_id": str(principal)}
    group = result.get("reviewer_group")
    if group is not None:
        if group["applied"]:
            append_event(
                conn,
                tenant,
                UUID(str(result["inviter_id"])),
                "access.group_member_added",
                {
                    "subject_id": str(group["group_id"]),
                    "principal_id": str(principal),
                    "invitation_id": str(invitation),
                    "reason": f"invitation {invitation} accepted",
                },
            )
        accepted["reviewer_group_id"] = str(group["group_id"])
        accepted["reviewer_group_applied"] = bool(group["applied"])
        accepted["reviewer_group_refusal"] = group["reason"]
    append_event(conn, tenant, principal, "invitation.accepted", accepted)


def sign_in_invited_account(
    db: Database, accepted: Accepted, *, clock: Clock | None = None
) -> Identity:
    """The session credential for the account this acceptance just created, and only that."""
    from execbound.passwords import mint_session_credential

    if (
        accepted.outcome != "ACCEPTED"
        or accepted.principal_id is None
        or accepted.account_id is None
        or accepted.account_version is None
    ):
        raise InvitationError("INVALID_REQUEST")
    return mint_session_credential(
        db,
        accepted.tenant_id,
        accepted.principal_id,
        "password",
        clock=clock or SystemClock(),
        account=(accepted.account_id, accepted.account_version),
    )
