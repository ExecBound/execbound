# SPDX-License-Identifier: AGPL-3.0-only
"""Trusted browsers: a sign-in on a browser the person trusted skips the second factor (#859).

A person who verifies their factor at sign-in may trust that browser for thirty days. The
browser keeps a cookie `tb1.<browser_id>.<secret>`; the database keeps the SHA-256 of the
secret, the account and factor versions it was granted at, and the time and method of the
verification behind it (migration `0101_trusted_browsers`). A later sign-in on that browser that
owes the factor is given a `session_assurance` row with method `trusted` and that original
time, never now: the sign-in factor is satisfied, while the step-up (`mfa.STEP_UP_WINDOW`), the
database's own `fresh` and the switch carry still read how old the real verification is.

Trust ends when the account or the factor version moves (a password change, a factor change,
a passkey, a provider link, "Sign out other devices"), after thirty days, on removal, and in
a workspace whose administrator forbids it. An account holds at most ten live trusts.

Every write goes through a definer function; the runtime only reads its own account's rows.
"""

import hashlib
import hmac
import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database
from execbound.execution.store import fence
from execbound.mfa import MfaError, _factor, _recent, _sets_requirement, _transaction
from execbound.resolution.models import Clock
from execbound.user_accounts import (
    account_context,
    factor_account,
    fence_account_workspaces,
    lock_account,
)

if TYPE_CHECKING:
    from execbound.surfaces.sessions import Session, SessionGrant

# The database holds the same thirty days and ten in `trusted_browser_add` and the table's
# check; a test holds these to them.
TRUST_LIFETIME = timedelta(days=30)
MAX_TRUSTED = 10
COOKIE_PREFIX = "tb1"

# The factors that can stand behind a trust: never `trusted` itself.
_METHODS = frozenset({"totp", "recovery", "passkey"})
# `secrets.token_urlsafe(32)`: 43 characters of the URL-safe alphabet.
_SECRET = re.compile(r"[A-Za-z0-9_-]{43}")
_COOKIE_MAX = 128
# The refusals the definer functions raise by name, answered as themselves; anything else the
# database raises is `MFA_UNAVAILABLE`.
_REFUSALS = frozenset(
    {
        "RECENT_AUTH_REQUIRED",
        "TRUST_NOT_ALLOWED",
        "INVALID_IDENTITY",
        "INVALID_ACCOUNT",
        "INVALID_SESSION",
        "INVALID_TENANT",
        "ACCOUNT_SIGN_IN_REQUIRED",
    }
)


@dataclass(frozen=True)
class Trust:
    """One live trust of the account, as My account lists it."""

    browser_id: UUID
    label: str | None
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


def _parse(cookie: object) -> tuple[UUID, str] | None:
    """The browser and secret of a well-formed cookie, or None for anything else."""
    if type(cookie) is not str or len(cookie) > _COOKIE_MAX:
        return None
    parts = cookie.split(".")
    if len(parts) != 3 or parts[0] != COOKIE_PREFIX or _SECRET.fullmatch(parts[2]) is None:
        return None
    try:
        browser = UUID(parts[1])
    except ValueError:
        return None
    # Only the canonical form, so one trust has exactly one cookie spelling.
    if str(browser) != parts[1]:
        return None
    return browser, parts[2]


def browser_of(cookie: object) -> UUID | None:
    """The browser a well-formed trust cookie names, or None: for My account to mark the
    trust this browser holds. It proves nothing, since the secret is not compared, and is
    never used to grant or apply a trust."""
    parsed = _parse(cookie)
    return parsed[0] if parsed is not None else None


@contextmanager
def _refused() -> Iterator[None]:
    """Answer a definer function's named refusal as an `MfaError` with that code."""
    try:
        yield
    except DBAPIError as exc:
        message = getattr(getattr(exc.orig, "diag", None), "message_primary", None)
        if message in _REFUSALS:
            raise MfaError(str(message)) from None
        raise


def _now(clock: Clock) -> datetime:
    value = clock.now()
    if value.tzinfo is None or value.utcoffset() is None:
        raise MfaError()
    return value.astimezone(UTC)


def grant(
    db: Database,
    session: "Session",
    *,
    method: str,
    verified_at: datetime,
    label: str | None,
    clock: Clock,
) -> tuple[str, datetime]:
    """Trust this session's browser, and answer the cookie value and when it expires.

    The session must hold its own recent verification of the account's enabled factor, by
    `method`, at `verified_at` or just before it; the database records that verification's own
    time and refuses `RECENT_AUTH_REQUIRED` otherwise, and `TRUST_NOT_ALLOWED` in a workspace
    that forbids trust. `label` is kept only when it is one of `sessions.device_label`'s fixed
    strings."""
    from execbound.surfaces.sessions import LABELS

    if method not in _METHODS:
        raise MfaError("INVALID_FACTOR")
    label = label if label in LABELS else None
    browser = uuid4()
    secret = secrets.token_urlsafe(32)
    with _transaction(db, session, clock) as conn, _refused():
        expires = conn.execute(
            text("SELECT execbound.trusted_browser_add(:t,:s,:b,:h,:l,:m,:v,:n)"),
            {
                "t": session.identity.tenant_id,
                "s": session.session_id,
                "b": browser,
                "h": _digest(secret),
                "l": label,
                "m": method,
                "v": verified_at,
                "n": _now(clock),
            },
        ).scalar_one()
    return f"{COOKIE_PREFIX}.{browser}.{secret}", expires.astimezone(UTC)


def verification(db: Database, session: "Session") -> tuple[str, datetime] | None:
    """The method and time of the verification this session holds, as `grant` takes them:
    read from the session's own `session_assurance` row just after a sign-in verified it, so
    a trust records the verification behind it and never one the caller supplies. None for a
    session that holds none; `grant` checks what it answers against the same row again."""
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            row = (
                conn.execute(
                    text(
                        "SELECT method, verified_at FROM execbound.session_assurance "
                        "WHERE tenant_id=:t AND session_id=:s"
                    ),
                    {"t": session.identity.tenant_id, "s": session.session_id},
                )
                .mappings()
                .one_or_none()
            )
    except SQLAlchemyError:
        raise MfaError() from None
    if row is None:
        return None
    return str(row["method"]), row["verified_at"].astimezone(UTC)


def apply(
    db: Database, session: "Session", cookie: str | None, *, clock: Clock
) -> "SessionGrant | None":
    """The rotated session, when trust satisfied this sign-in's second factor; None when it did
    not, with nothing written.

    When it does, the session's assurance is written with the trust's original verification
    time, the trust's `last_used_at` moves, and the session's token and CSRF token are replaced
    in the same statement, as `mfa.rotate_verified_session` replaces them after a code: the
    token issued before the factor was satisfied no longer loads. The grant carries the new
    ones for the caller to set as `signed_in` does. A missing or malformed cookie, or a
    session that owes no factor, answers None without reaching the database. A session that is
    no longer valid raises, as every other change to it does."""
    from execbound.surfaces.sessions import SessionGrant, check_session

    parsed = _parse(cookie)
    if parsed is None or not session.mfa_required:
        return None
    browser, secret = parsed
    tenant = session.identity.tenant_id
    token = f"hs1.{tenant}.{session.session_id}.{secrets.token_urlsafe(32)}"
    csrf = secrets.token_urlsafe(32)
    try:
        # The session is checked here, before the write, and not after it as
        # `rotate_verified_session` checks it, because the write replaces the session's token
        # and CSRF digests. The definer rechecks that the session is live and belongs to its
        # account, but never compares the old token or CSRF digest: this check is the only one.
        with db.transaction(tenant) as conn:
            account = factor_account(conn, session)
            if session.account_id is not None:
                fence_account_workspaces(conn, session.account_id, tenant, clock)
            elif account is not None:
                lock_account(conn, account)
            fence(conn, tenant, clock)
            check_session(conn, session, clock, allow_pending_mfa=True)
            with _refused():
                used = conn.execute(
                    text("SELECT execbound.trusted_browser_use(:t,:s,:b,:h,:th,:ch,:n)"),
                    {
                        "t": tenant,
                        "s": session.session_id,
                        "b": browser,
                        "h": _digest(secret),
                        "th": hashlib.sha256(token.encode("ascii")).hexdigest(),
                        "ch": hashlib.sha256(csrf.encode("ascii")).hexdigest(),
                        "n": _now(clock),
                    },
                ).scalar_one()
            if used:
                _record_use(conn, session, account, browser)
    except SQLAlchemyError:
        raise MfaError() from None
    if not used:
        return None
    return SessionGrant(
        session.identity,
        session.session_id,
        session.expires_at,
        token,
        csrf,
        account_bound=session.account_id is not None,
    )


def _record_use(conn: Connection, session: "Session", account: UUID | None, browser: UUID) -> None:
    """Append `account_security.trusted_sign_in` to the workspace's chain, in the transaction
    that wrote the trusted assurance: the session, the trust, and when and how the factor
    behind it was really verified, read from the trust's own row. A trusted sign-in thus
    leaves the record a code leaves (`account_security.verified`) and a carry leaves
    (`account_security.assurance_carried`); the account's own record is in
    `user_security_events` for a grant and a removal, never for a use."""
    if account is None:  # pragma: no cover - the definer refused before a use could happen
        raise MfaError()
    account_context(conn, account)
    row = (
        conn.execute(
            text(
                "SELECT verified_at, method FROM execbound.trusted_browsers "
                "WHERE account_id=:a AND browser_id=:b"
            ),
            {"a": account, "b": browser},
        )
        .mappings()
        .one()
    )
    append_event(
        conn,
        session.identity.tenant_id,
        session.identity.principal_id,
        "account_security.trusted_sign_in",
        {
            "session_id": str(session.session_id),
            "browser_id": str(browser),
            "method": str(row["method"]),
            "verified_at": row["verified_at"].astimezone(UTC).isoformat(timespec="microseconds"),
        },
    )


def applies(
    conn: Connection, account_id: UUID, tenant_id: UUID, cookie: str | None, now: datetime
) -> bool:
    """Whether this cookie would satisfy the account's factor in `tenant_id`, read inside the
    caller's transaction and writing nothing: the same checks as `trusted_browser_use`, for
    the workspace-entry interstitial. The account's row security is entered for the read and
    the caller's setting put back."""
    parsed = _parse(cookie)
    if parsed is None:
        return False
    browser, secret = parsed
    original = conn.execute(
        text("SELECT current_setting('execbound.account_id',true)")
    ).scalar_one()
    conn.execute(text("SELECT set_config('execbound.account_id',:a,true)"), {"a": str(account_id)})
    row = (
        conn.execute(
            text(
                "SELECT b.token_hash FROM execbound.trusted_browsers b "
                "JOIN execbound.user_accounts u ON u.account_id=b.account_id "
                "JOIN execbound.user_factors f ON f.account_id=b.account_id "
                "WHERE b.account_id=:a AND b.browser_id=:b AND u.active "
                "AND b.revoked_at IS NULL AND b.created_at<=:n AND b.expires_at>:n "
                "AND b.account_version=u.version AND f.enabled_at IS NOT NULL "
                "AND b.factor_version=f.version"
            ),
            {"a": account_id, "b": browser, "n": now},
        )
        .mappings()
        .one_or_none()
    )
    conn.execute(text("SELECT set_config('execbound.account_id',:a,true)"), {"a": original or ""})
    return (
        row is not None
        # Both are hex digests, ASCII by the table's check and by `hexdigest`.
        and hmac.compare_digest(row["token_hash"].encode("ascii"), _digest(secret).encode("ascii"))
        and allowed(conn, tenant_id)
    )


def listed(db: Database, session: "Session", *, clock: Clock) -> list[Trust]:
    """The account's live trusts, newest first: not removed, not expired, and granted at the
    account's current version and its enabled factor's current version."""
    with _transaction(db, session, clock) as conn:
        account = factor_account(conn, session)
        if account is None:
            return []
        rows = conn.execute(
            text(
                "SELECT b.browser_id,b.label,b.created_at,b.expires_at,b.last_used_at "
                "FROM execbound.trusted_browsers b "
                "JOIN execbound.user_accounts u ON u.account_id=b.account_id "
                "JOIN execbound.user_factors f ON f.account_id=b.account_id "
                "WHERE b.account_id=:a AND b.revoked_at IS NULL AND b.created_at<=:n "
                "AND b.expires_at>:n AND b.account_version=u.version "
                "AND f.enabled_at IS NOT NULL AND b.factor_version=f.version "
                "ORDER BY b.created_at DESC, b.browser_id"
            ),
            {"a": account, "n": _now(clock)},
        ).mappings()
        return [
            Trust(
                browser_id=row["browser_id"],
                label=row["label"],
                created_at=row["created_at"].astimezone(UTC),
                expires_at=row["expires_at"].astimezone(UTC),
                last_used_at=(
                    row["last_used_at"].astimezone(UTC) if row["last_used_at"] is not None else None
                ),
            )
            for row in rows
        ]


def _account(conn: Connection, session: "Session") -> UUID:
    account = factor_account(conn, session)
    if account is None:
        raise MfaError("ACCOUNT_SIGN_IN_REQUIRED")
    return account


def remove(db: Database, session: "Session", browser_id: UUID, *, clock: Clock) -> None:
    """Remove one of the account's live trusts. Removing only tightens, so no step-up is
    asked; removing one that is gone or was never the account's changes nothing."""
    with _transaction(db, session, clock) as conn, _refused():
        conn.execute(
            text("SELECT execbound.trusted_browser_remove(:a,:b,:n)"),
            {"a": _account(conn, session), "b": browser_id, "n": _now(clock)},
        )


def remove_all(db: Database, session: "Session", *, clock: Clock) -> int:
    """Remove every live trust of the account, and answer how many there were."""
    with _transaction(db, session, clock) as conn, _refused():
        return int(
            conn.execute(
                text("SELECT execbound.trusted_browser_remove_all(:a,:n)"),
                {"a": _account(conn, session), "n": _now(clock)},
            ).scalar_one()
        )


def allowed(conn: Connection, tenant_id: UUID) -> bool:
    """Whether `tenant_id` allows trusted browsers, true unless its administrator turned it
    off. Read inside that workspace's row security, the caller's setting put back after, so a
    caller in another workspace (a switch's source) reads the destination's own answer."""
    original = conn.execute(text("SELECT current_setting('execbound.tenant_id',true)")).scalar_one()
    conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant_id)})
    value = conn.execute(
        text(
            "SELECT allow_trusted_browsers FROM execbound.account_security_policy "
            "WHERE tenant_id=:t"
        ),
        {"t": tenant_id},
    ).scalar_one_or_none()
    conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": original or ""})
    return value is None or bool(value)


def set_allowed(db: Database, session: "Session", allow: bool, *, clock: Clock) -> None:
    """Allow or forbid trusted browsers in the session's workspace: a workspace
    administrator's alone, refused `INVALID_IDENTITY` here and by the definer function.

    Allowing trust loosens every sign-in to the workspace, so an administrator with a factor
    must have verified it within the step-up window (`mfa.require_recent_factor`'s rule,
    `RECENT_AUTH_REQUIRED` otherwise). The change is appended to the workspace's audit chain
    in the same transaction, as the requirement's own writer appends `requirement_changed`."""
    with _transaction(db, session, clock) as conn:
        if not _sets_requirement(conn, session):
            raise MfaError("INVALID_IDENTITY")
        factor = _factor(conn, session)
        if factor is not None and factor["enabled_at"] is not None:
            _recent(conn, session, _now(clock))
        with _refused():
            conn.execute(
                text("SELECT execbound.trusted_browser_policy(:t,:p,:a,:n)"),
                {
                    "t": session.identity.tenant_id,
                    "p": session.identity.principal_id,
                    "a": bool(allow),
                    "n": _now(clock),
                },
            )
        append_event(
            conn,
            session.identity.tenant_id,
            session.identity.principal_id,
            "account_security.trusted_browsers_changed",
            {"session_id": str(session.session_id), "allowed": bool(allow)},
        )
