# SPDX-License-Identifier: AGPL-3.0-only
"""Opaque, short-lived human sessions; stored selectors never establish identity."""

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database, UnsafeDatabaseRole, check_runtime
from execbound.execution.store import fence
from execbound.identity import Identity
from execbound.policy.store import PolicyStoreError, _identity
from execbound.resolution.models import Clock, SystemClock

MAX_ACTIVE_SESSIONS = 5
SESSION_LIFETIME = timedelta(hours=12)
# A session is renewed on activity this long after it was last extended, never past the
# credential's expiry or `SESSION_ABSOLUTE` after sign-in. The cadence is its own constant, no
# longer half the lifetime: a directory session is rechecked each time it renews, and that stays
# about every seven and a half minutes. Walking away ends the session after twelve hours;
# reading and navigating keep it alive.
RENEW_AFTER = timedelta(minutes=7, seconds=30)
# A session that still owes its second factor stands this long, as every session once did, and a
# session a workspace switch opens starts at it too. Once nothing is owed (the factor was
# verified, or the switch carried the source's verification), the next load of any kind extends
# it to the full lifetime; a session that still owes the factor is never extended.
PENDING_LIFETIME = timedelta(minutes=15)
SESSION_ABSOLUTE = timedelta(days=2)
# Every sign-in credential is minted for two days a few milliseconds before its session row,
# so its expiry falls just short of the row's own two days. A session whose credential ends
# more than this much sooner ends on that credential, which in practice is a setup credential
# exchanged at `POST /session` (#678).
CREDENTIAL_END_TOLERANCE = timedelta(minutes=1)


class SessionError(ValueError):
    """Safe errors contain no supplied credentials, digests or database diagnostics."""

    def __init__(self, code: str = "INVALID_SESSION") -> None:
        self.code = code
        super().__init__("Session unavailable")


class DirectoryStale(SessionError):
    """`DIRECTORY_REQUIRED`, for a session whose only fault is that its directory sign-in was
    last verified longer ago than `directory_store.RECHECK_GRACE` (#859).

    Raised by `_validated` only once every other check of the session has passed, carrying the
    session's identity, so `directory_store.load_rechecked` can ask the directory and load the
    session again. Every other handler treats it as the `DIRECTORY_REQUIRED` it is."""

    def __init__(self, identity: Identity | None = None) -> None:
        super().__init__("DIRECTORY_REQUIRED")
        self.identity = identity


@dataclass(frozen=True)
class Session:
    identity: Identity
    session_id: UUID
    expires_at: datetime
    csrf_hash: str = field(repr=False)
    # Set on the object this request loaded when the row was just extended, so the
    # response can re-issue the cookies with the new age. Never persisted.
    renewed: bool = False
    # Set on the object this request loaded when `RENEW_AFTER` had passed since the session was
    # last extended, whether or not the row could move: a session already at its two-day end
    # cannot be extended, and a directory session is still rechecked on this cadence.
    renewal_due: bool = False
    mfa_required: bool = False
    account_id: UUID | None = None
    account_session_id: UUID | None = None
    # The hard end no renewal passes: two days after sign-in or the credential's expiry,
    # whichever is sooner, and why it falls then. `None` only for a token session, which has
    # no row to read it from.
    ends_at: datetime | None = None
    end_reason: str = "sign_in"


@dataclass(frozen=True)
class SessionGrant:
    identity: Identity
    session_id: UUID
    expires_at: datetime
    token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    mfa_required: bool = False
    account_token: str | None = field(default=None, repr=False)
    account_bound: bool = False
    # Where a workspace switch lands: a console section root the new session may open.
    place: str | None = None


def _now(clock: Clock) -> datetime:
    value = clock.now()
    if value.tzinfo is None or value.utcoffset() is None:
        raise SessionError()
    return value.astimezone(UTC)


def _secret(value: str) -> bool:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is None:
        return False
    decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    return len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode().rstrip("=") == value


def _selectors(token: str) -> tuple[UUID, UUID]:
    try:
        if type(token) is not str or len(token) > 160:
            raise ValueError
        version, tenant_text, session_text, secret = token.split(".")
        tenant, session = UUID(tenant_text), UUID(session_text)
        if (
            version != "hs1"
            or str(tenant) != tenant_text
            or str(session) != session_text
            or not _secret(secret)
        ):
            raise ValueError
        return tenant, session
    except ValueError:
        raise SessionError() from None


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _human(conn: Connection, identity: Identity, clock: Clock) -> None:
    if identity.kind not in {"HUMAN_APPROVER", "ADMIN"}:
        raise SessionError()
    try:
        _identity(conn, identity, clock, admin=False)
    except PolicyStoreError:
        raise SessionError() from None


def _read(conn: Connection, tenant: UUID, session_id: UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text("SELECT * FROM execbound.human_sessions WHERE tenant_id=:t AND session_id=:s"),
            {"t": tenant, "s": session_id},
        )
        .mappings()
        .one_or_none()
    )
    return dict(row) if row is not None else None


def _validated(
    conn: Connection, row: dict[str, Any] | None, clock: Clock, *, allow_pending_mfa: bool = False
) -> Session:
    if row is None or row["revoked_at"] is not None:
        raise SessionError()
    from execbound.user_accounts import validate_workspace_session

    stale = False
    try:
        factor_account = validate_workspace_session(conn, row, _now(clock))
    except DirectoryStale:
        # Raised below, once the rest of the session is known to be valid: only a session that
        # would load but for its directory verification's age is offered a recheck.
        factor_account, stale = None, True
    identity = Identity(
        row["tenant_id"],
        row["principal_id"],
        row["credential_id"],
        row["kind"],
        row["credential_expires_at"],
    )
    _human(conn, identity, clock)
    if not row["created_at"] <= _now(clock) < row["expires_at"]:
        raise SessionError()
    if stale:
        raise DirectoryStale(identity)
    from execbound.mfa import requires_mfa

    pending = requires_mfa(conn, {**row, "factor_account_id": factor_account}, _now(clock))
    if pending and not allow_pending_mfa:
        raise SessionError("MFA_REQUIRED")
    ends_at, end_reason = _hard_end(row)
    return Session(
        identity,
        row["session_id"],
        row["expires_at"],
        row["csrf_hash"],
        mfa_required=pending,
        account_id=row.get("account_id"),
        account_session_id=row.get("account_session_id"),
        ends_at=ends_at,
        end_reason=end_reason,
    )


def _hard_end(row: dict[str, Any]) -> tuple[datetime, str]:
    """When a session must end whatever renews it, and why: `setup_credential` when a session
    with no account ends on its credential more than the tolerance before its two days,
    `sign_in` otherwise. An account-bound session's credential is the account sign-in's own
    two days, a switched-to session's included, so it always reads `sign_in`."""
    absolute = row["created_at"] + SESSION_ABSOLUTE
    credential = row["credential_expires_at"]
    early = credential < absolute - CREDENTIAL_END_TOLERANCE
    reason = "setup_credential" if row.get("account_id") is None and early else "sign_in"
    return min(absolute, credential), reason


def check_session(
    conn: Connection, session: Session, clock: Clock, *, allow_pending_mfa: bool = False
) -> None:
    """Recheck a trusted session inside the caller's fenced tenant transaction.

    Human mutations can use this check after acquiring the same tenant fence as
    revocation. This internal binding is never accepted as an external credential.
    """
    from execbound.personal_tokens import TokenSession, check_token_session

    if isinstance(session, TokenSession):
        check_token_session(conn, session, clock)
        return
    current = _validated(
        conn,
        _read(conn, session.identity.tenant_id, session.session_id),
        clock,
        allow_pending_mfa=allow_pending_mfa,
    )
    # A renewal by another request of the same session only ever extends the row; a
    # shorter row means it was rebound or replaced underneath the caller.
    if (
        current.identity != session.identity
        or current.expires_at < session.expires_at
        or not hmac.compare_digest(current.csrf_hash, session.csrf_hash)
    ):
        raise SessionError()


def verify_csrf(session: Session, token: str) -> bool:
    """Only a previously loaded current session supplies the trusted digest."""
    return _secret(token) and hmac.compare_digest(_hash(token), session.csrf_hash)


def issue_session(
    db: Database, identity: Identity, *, clock: Clock | None = None, label: str | None = None
) -> SessionGrant:
    clock = clock or SystemClock()
    # The label is one of device_label's fixed strings, never the header; anything else is
    # dropped rather than stored.
    label = label if label in LABELS else None
    session_id = uuid4()
    token = f"hs1.{identity.tenant_id}.{session_id}.{secrets.token_urlsafe(32)}"
    csrf_token = secrets.token_urlsafe(32)
    try:
        with db.transaction(identity.tenant_id) as conn:
            from execbound.user_accounts import open_account_session

            check_runtime(conn)
            account, account_token, membership_version = open_account_session(
                conn, identity, session_id, _now(clock)
            )
            account_version = None
            member = (
                conn.execute(
                    text(
                        "SELECT account_id,version FROM execbound.workspace_memberships "
                        "WHERE tenant_id=:t AND principal_id=:p"
                    ),
                    {"t": identity.tenant_id, "p": identity.principal_id},
                )
                .mappings()
                .one_or_none()
            )
            if member:
                from execbound.user_accounts import account_context

                account_context(conn, member["account_id"])
                account_version = conn.execute(
                    text("SELECT version FROM execbound.user_accounts WHERE account_id=:a"),
                    {"a": member["account_id"]},
                ).scalar_one()
                membership_version = member["version"]
            _human(conn, identity, clock)
            fence(conn, identity.tenant_id, clock)
            _human(conn, identity, clock)
            created_at = _now(clock)
            # Whether the second factor is still owed is known only once the row exists, so the
            # row starts at the pending bound and a session that owes nothing is extended to
            # its full idle lifetime below.
            expires_at = min(
                created_at + min(PENDING_LIFETIME, SESSION_LIFETIME), identity.expires_at
            )
            # At the bound the oldest live sessions of this credential are ended to admit the
            # new one, under the tenant fence taken above, so there are never more than
            # `MAX_ACTIVE_SESSIONS` live after this one. A setup credential exchanged again and
            # again, with the old sessions never signed out, would otherwise be refused for the
            # twelve hours they stand.
            live = (
                conn.execute(
                    text(
                        "SELECT session_id FROM execbound.human_sessions WHERE tenant_id=:t "
                        "AND credential_id=:c AND revoked_at IS NULL AND expires_at>:n "
                        "ORDER BY created_at, session_id"
                    ),
                    {"t": identity.tenant_id, "c": identity.credential_id, "n": created_at},
                )
                .scalars()
                .all()
            )
            for evicted in live[: max(0, len(live) - MAX_ACTIVE_SESSIONS + 1)]:
                conn.execute(
                    text(
                        "UPDATE execbound.human_sessions SET revoked_at=:n "
                        "WHERE tenant_id=:t AND session_id=:s AND revoked_at IS NULL"
                    ),
                    {"t": identity.tenant_id, "s": evicted, "n": created_at},
                )
                append_event(
                    conn,
                    identity.tenant_id,
                    identity.principal_id,
                    "human_session.revoked",
                    {
                        "session_id": str(evicted),
                        "credential_id": str(identity.credential_id),
                        "principal_id": str(identity.principal_id),
                        "reason": "SESSION_CAPACITY",
                    },
                )
            conn.execute(
                text("""
                    INSERT INTO execbound.human_sessions
                        (tenant_id,session_id,principal_id,credential_id,kind,
                         credential_expires_at,token_hash,csrf_hash,created_at,expires_at,
                         label,account_id,account_session_id,membership_version,account_version)
                    VALUES (:t,:s,:p,:c,:k,:ce,:th,:ch,:n,:e,:l,:a,:as,:mv,:av)
                """),
                {
                    "t": identity.tenant_id,
                    "s": session_id,
                    "p": identity.principal_id,
                    "c": identity.credential_id,
                    "k": identity.kind,
                    "ce": identity.expires_at,
                    "th": _hash(token),
                    "ch": _hash(csrf_token),
                    "n": created_at,
                    "e": expires_at,
                    "l": label,
                    "a": account,
                    "as": session_id if account else None,
                    "mv": membership_version,
                    "av": account_version,
                },
            )
            pending = _validated(
                conn, _read(conn, identity.tenant_id, session_id), clock, allow_pending_mfa=True
            ).mfa_required
            if not pending:
                extended = conn.execute(
                    text("SELECT execbound.renew_human_session(:s, :h, :n, :l, :a)"),
                    {
                        "s": session_id,
                        "h": _hash(token),
                        "n": created_at,
                        "l": SESSION_LIFETIME,
                        "a": SESSION_ABSOLUTE,
                    },
                ).scalar_one_or_none()
                if extended is not None:
                    expires_at = extended.astimezone(UTC)
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "human_session.issued",
                {
                    "session_id": str(session_id),
                    "credential_id": str(identity.credential_id),
                    "kind": identity.kind,
                    "expires_at": expires_at.isoformat(),
                },
            )
            # Recheck after the audit write, as before: a credential revoked while it waited
            # fails the session here, inside the transaction, rather than committing.
            pending = _validated(
                conn, _read(conn, identity.tenant_id, session_id), clock, allow_pending_mfa=True
            ).mfa_required
        return SessionGrant(
            identity,
            session_id,
            expires_at,
            token,
            csrf_token,
            pending,
            account_token,
            account_bound=account is not None,
        )
    except SessionError:
        raise
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        raise SessionError("SESSION_UNAVAILABLE") from None


def load_session(
    db: Database, token: str, *, clock: Clock | None = None, allow_pending_mfa: bool = False
) -> Session:
    clock = clock or SystemClock()
    tenant, session_id = _selectors(token)
    digest = _hash(token)
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            row = _read(conn, tenant, session_id)
            matches = hmac.compare_digest(digest, row["token_hash"] if row else "0" * 64)
            if row is None or not matches:
                raise SessionError()
            if row.get("account_id") is not None:
                from execbound.user_accounts import lock_account

                lock_account(conn, row["account_id"])
            # Authenticate the retained token before deriving a human identity or
            # waiting on the shared fence. Recheck both state and identity after it.
            _validated(conn, row, clock, allow_pending_mfa=allow_pending_mfa)
            fence(conn, tenant, clock)
            session = _validated(
                conn, _read(conn, tenant, session_id), clock, allow_pending_mfa=allow_pending_mfa
            )
            if not session.mfa_required:
                session = _renewed(conn, session, digest, clock)
                if session.account_session_id is not None:
                    conn.execute(
                        text("SELECT execbound.account_session_touch(:s,:n)"),
                        {"s": session.account_session_id, "n": _now(clock)},
                    )
        return session
    except SessionError:
        raise
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        raise SessionError("SESSION_UNAVAILABLE") from None


def _renewed(conn: Connection, session: Session, digest: str, clock: Clock) -> Session:
    """Extend a live session once `RENEW_AFTER` has passed since it was last extended; the
    database enforces the caps and answers NULL when nothing may change."""
    now = _now(clock)
    if now < session.expires_at - SESSION_LIFETIME + RENEW_AFTER:
        return session
    due = replace(session, renewal_due=True)
    if session.ends_at is not None and session.expires_at >= session.ends_at:
        # Already at the hard end, which only a new sign-in moves: no statement can change the
        # row, so none is sent.
        return due
    extended = conn.execute(
        text("SELECT execbound.renew_human_session(:s, :h, :n, :l, :a)"),
        {
            "s": session.session_id,
            "h": digest,
            "n": now,
            "l": SESSION_LIFETIME,
            "a": SESSION_ABSOLUTE,
        },
    ).scalar_one_or_none()
    if extended is None or extended <= session.expires_at:
        return due
    return replace(due, expires_at=extended.astimezone(UTC), renewed=True)


def revoke_session(db: Database, session: Session, *, clock: Clock | None = None) -> None:
    from execbound.personal_tokens import TokenSession

    if isinstance(session, TokenSession):
        raise SessionError()
    clock = clock or SystemClock()
    if session.account_id is not None:
        from execbound.user_accounts import end_account_sessions

        end_account_sessions(db, session, others=False, clock=clock)
        return
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            _human(conn, identity, clock)
            fence(conn, identity.tenant_id, clock)
            check_session(conn, session, clock)
            conn.execute(
                text(
                    "UPDATE execbound.human_sessions SET revoked_at=:n "
                    "WHERE tenant_id=:t AND session_id=:s AND revoked_at IS NULL"
                ),
                {"t": identity.tenant_id, "s": session.session_id, "n": _now(clock)},
            )
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "human_session.revoked",
                {
                    "session_id": str(session.session_id),
                    "credential_id": str(identity.credential_id),
                },
            )
            _human(conn, identity, clock)
            if _now(clock) >= session.expires_at:
                raise SessionError()
    except SessionError:
        raise
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        raise SessionError("SESSION_UNAVAILABLE") from None


# Browser and system families, each in the order that disambiguates: an Edge or Chrome
# string also says Safari, an Android string also says Linux. The label a session carries
# is always one of LABELS or None, so the page renders a known string and never the header.
_BROWSERS = (
    ("Edg/", "Edge"),
    ("EdgiOS/", "Edge"),
    ("OPR/", "Opera"),
    ("CriOS/", "Chrome"),
    ("FxiOS/", "Firefox"),
    ("Firefox/", "Firefox"),
    ("Chrome/", "Chrome"),
    ("Safari/", "Safari"),
)
_SYSTEMS = (
    ("iPhone", "iPhone"),
    ("iPad", "iPad"),
    ("Android", "Android"),
    ("Windows", "Windows"),
    ("Mac OS X", "Mac"),
    ("CrOS", "ChromeOS"),
    ("Linux", "Linux"),
)
LABELS = frozenset(
    {f"{browser} on {system}" for _, browser in _BROWSERS for _, system in _SYSTEMS} | {"Other"}
)


def device_label(user_agent: str | None) -> str:
    """The fixed device label for a User-Agent header, and "Other" for anything unrecognized."""
    if not user_agent or len(user_agent) > 1024:
        return "Other"
    browser = next((name for marker, name in _BROWSERS if marker in user_agent), None)
    system = next((name for marker, name in _SYSTEMS if marker in user_agent), None)
    if browser is None or system is None:
        return "Other"
    return f"{browser} on {system}"


def revoke_other_sessions(db: Database, session: Session, *, clock: Clock | None = None) -> int:
    """End every other live session of this principal, inside the fence; this one stays.

    One audit event per ended session, with the reason ``OTHER_DEVICES``, so the chain says
    which sessions a person ended from the console and which ended by sign-out or expiry.

    A session with no account sign-in (a setup credential's, say) whose membership links an
    account also moves that account's version, as the account path does
    (`account_sign_out_others`, migration `0101_trusted_browsers`): every trusted browser of
    the account ends and every account sign-in of it is signed out, so "Sign out other
    devices" means the same from either kind of session (#859).
    """
    from execbound.personal_tokens import TokenSession

    if isinstance(session, TokenSession):
        raise SessionError()
    clock = clock or SystemClock()
    if session.account_id is not None:
        from execbound.user_accounts import end_account_sessions

        return end_account_sessions(db, session, others=True, clock=clock)
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            from execbound.user_accounts import lock_account

            _human(conn, identity, clock)
            linked = conn.execute(
                text(
                    "SELECT account_id FROM execbound.workspace_memberships "
                    "WHERE tenant_id=:t AND principal_id=:p AND active"
                ),
                {"t": identity.tenant_id, "p": identity.principal_id},
            ).scalar_one_or_none()
            if linked is not None:
                # The account's lock comes before the tenant fence, as everywhere else.
                lock_account(conn, linked)
            fence(conn, identity.tenant_id, clock)
            check_session(conn, session, clock)
            ended = (
                conn.execute(
                    text(
                        "UPDATE execbound.human_sessions SET revoked_at=:n "
                        "WHERE tenant_id=:t AND principal_id=:p AND session_id<>:s "
                        "AND revoked_at IS NULL RETURNING session_id, credential_id"
                    ),
                    {
                        "t": identity.tenant_id,
                        "p": identity.principal_id,
                        "s": session.session_id,
                        "n": _now(clock),
                    },
                )
                .mappings()
                .all()
            )
            for row in ended:
                append_event(
                    conn,
                    identity.tenant_id,
                    identity.principal_id,
                    "human_session.revoked",
                    {
                        "session_id": str(row["session_id"]),
                        "credential_id": str(row["credential_id"]),
                        "reason": "OTHER_DEVICES",
                    },
                )
            if linked is not None:
                conn.execute(
                    text("SELECT execbound.account_sign_out_others(:t,:s,:n)"),
                    {"t": identity.tenant_id, "s": session.session_id, "n": _now(clock)},
                )
            check_session(conn, session, clock)
            return len(ended)
    except SessionError:
        raise
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        raise SessionError("SESSION_UNAVAILABLE") from None


def revoke_sessions_of(
    db: Database, session: Session, principal_id: UUID, *, reason: str, clock: Clock | None = None
) -> int:
    """End every live session of one principal from an administrator's session.

    The acting session is rechecked inside the same transaction; the page refuses the case
    where the target is the actor, whose own sessions belong on the personal page. One audit
    event per ended session carries the given reason and the acting principal as actor.

    The statement carries the rule the definer functions apply since 0072: an administrator
    narrowed to spaces ends the sessions only of a person whose every seat is in one of
    their `ADMIN` spaces, and anyone else's are left alone, so the count is zero.
    """
    from execbound.spaces import administered_clause

    clock = clock or SystemClock()
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            _human(conn, identity, clock)
            fence(conn, identity.tenant_id, clock)
            check_session(conn, session, clock)
            people = administered_clause(conn, session, "holder")
            ended = (
                conn.execute(
                    text(
                        "UPDATE execbound.human_sessions SET revoked_at=:n "
                        "WHERE tenant_id=:t AND principal_id=:p AND revoked_at IS NULL "
                        "AND EXISTS (SELECT 1 FROM execbound.principals holder "
                        "WHERE holder.tenant_id = human_sessions.tenant_id "
                        "AND holder.principal_id = human_sessions.principal_id"
                        + people.sql  # nosec B608 - one helper's predicate; values are bound
                        + ") RETURNING session_id, credential_id"
                    ),
                    {"t": identity.tenant_id, "p": principal_id, "n": _now(clock), **people.params},
                )
                .mappings()
                .all()
            )
            for row in ended:
                append_event(
                    conn,
                    identity.tenant_id,
                    identity.principal_id,
                    "human_session.revoked",
                    {
                        "session_id": str(row["session_id"]),
                        "credential_id": str(row["credential_id"]),
                        "principal_id": str(principal_id),
                        "reason": reason,
                    },
                )
            check_session(conn, session, clock)
            return len(ended)
    except SessionError:
        raise
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        raise SessionError("SESSION_UNAVAILABLE") from None
