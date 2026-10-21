# SPDX-License-Identifier: AGPL-3.0-only
"""Human authentication factors, separate from agent execution authority.

Authenticator seeds are sealed at rest. Recovery codes retain only a domain-separated
digest of 96 random bits. All state transitions serialize on the existing tenant fence.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database
from execbound.envelope import KeyRing, seal, unseal
from execbound.execution.store import fence
from execbound.resolution.models import Clock, SystemClock
from execbound.spaces import narrowed

if TYPE_CHECKING:
    from execbound.surfaces.sessions import Session, SessionGrant

_CODE = re.compile(r"[0-9]{6}")
_RECOVERY = re.compile(r"[0-9a-f]{4}(?:-[0-9a-f]{4}){5}")

# How long a verified factor steps a session up: every change that asks for a recent factor
# (the console API's step-up, the account security page's own changes, passkeys, provider
# links) reads this one value, and migration `0067_step_up_window` holds the definer
# functions' own check to the same thirty minutes. It was lengthened from five on 28 September
# 2026, when the console began asking for the factor in place. A workspace switch carries a
# verification into the new session within the same thirty minutes, a literal in
# `account_switch` since migration `0089_assurance_carry`: a change to this window patches it
# too.
STEP_UP_WINDOW = timedelta(minutes=30)
# How new a session must be to enrol a first factor, or to link a provider: the age of the
# sign-in itself, not of a factor, so a different window, and deliberately still five minutes.
ENROLLMENT_WINDOW = timedelta(minutes=5)


class MfaError(ValueError):
    """A safe refusal; factor values must never reach exception strings."""

    def __init__(self, code: str = "MFA_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Account security unavailable")


def totp(secret: str, step: int) -> str:
    """RFC 6238: HMAC-SHA1, six digits, a caller-supplied 30-second step."""
    key = base64.b32decode(secret, casefold=False)
    digest = hmac.digest(key, struct.pack(">Q", step), "sha1")
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(secret: str, code: object, timestamp: float, last_step: int) -> int | None:
    """Return the unused matching step, allowing one adjacent step for clock skew."""
    if not isinstance(code, str) or _CODE.fullmatch(code) is None:
        return None
    current = int(timestamp // 30)
    match = None
    for step in (current - 1, current, current + 1):
        if step >= 0 and step > last_step and hmac.compare_digest(totp(secret, step), code):
            match = step
    return match


def used_step(secret: str, code: object, timestamp: float, last_step: int) -> bool:
    """Whether `code` is this factor's code for a step in the current window that has already
    been used: the code a person still sees after it opened another session. Every step of the
    window is compared, in constant time, whatever matches."""
    if not isinstance(code, str) or _CODE.fullmatch(code) is None:
        return False
    current = int(timestamp // 30)
    found = False
    for step in (current - 1, current, current + 1):
        if 0 <= step <= last_step and hmac.compare_digest(totp(secret, step), code):
            found = True
    return found


def recovery_digest(principal: UUID, value: object) -> str | None:
    if not isinstance(value, str) or _RECOVERY.fullmatch(value) is None:
        return None
    return hashlib.sha256(f"execbound-recovery-v1|{principal}|{value}".encode("ascii")).hexdigest()


def new_recovery_codes(principal: UUID) -> tuple[list[str], list[str]]:
    shown: list[str] = []
    retained: list[str] = []
    for _ in range(10):
        raw = secrets.token_hex(12)
        code = "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))
        digest = recovery_digest(principal, code)
        assert digest is not None
        shown.append(code)
        retained.append(digest)
    return shown, retained


def requires_mfa(conn: Connection, row: dict[str, Any], now: datetime) -> bool:
    """Called by every session load and in-transaction authority recheck."""
    account = row.get("factor_account_id", row.get("account_id"))
    factors = (
        "execbound.account_factors f ON f.tenant_id=:t AND f.principal_id=:p"
        if account is None
        else "execbound.user_factors f ON f.account_id=:account"
    )
    state = (
        conn.execute(
            text(f"""
        SELECT f.enabled_at,f.version,a.version AS assured_version,a.verified_at,
            coalesce(p.requirement,'optional') AS requirement
        FROM (SELECT 1) one
        LEFT JOIN {factors}
        LEFT JOIN execbound.account_security_policy p ON p.tenant_id=:t
        LEFT JOIN execbound.session_assurance a ON a.tenant_id=:t AND a.session_id=:s
    """),  # nosec B608 - Only the two fixed joins above; all values are bound parameters.
            {
                "t": row["tenant_id"],
                "p": row["principal_id"],
                "s": row["session_id"],
                "account": account,
            },
        )
        .mappings()
        .one()
    )
    required = (
        state["enabled_at"] is not None
        or state["requirement"] == "all"
        or (state["requirement"] == "admins" and row["kind"] == "ADMIN")
    )
    verified = (
        state["enabled_at"] is not None
        and state["assured_version"] == state["version"]
        and state["verified_at"] is not None
        and state["verified_at"] <= now
    )
    return bool(required and not verified)


@contextmanager
def _transaction(db: Database, session: "Session", clock: Clock) -> Iterator[Connection]:
    from execbound.surfaces.sessions import check_session

    try:
        with db.transaction(session.identity.tenant_id) as conn:
            from execbound.user_accounts import (
                factor_account,
                fence_account_workspaces,
                lock_account,
            )

            account = factor_account(conn, session)
            if session.account_id is not None:
                fence_account_workspaces(
                    conn, session.account_id, session.identity.tenant_id, clock
                )
            elif account is not None:
                lock_account(conn, account)
            fence(conn, session.identity.tenant_id, clock)
            check_session(conn, session, clock, allow_pending_mfa=True)
            yield conn
            check_session(conn, session, clock, allow_pending_mfa=True)
    except SQLAlchemyError:
        raise MfaError() from None


def _factor(conn: Connection, session: "Session") -> dict[str, Any] | None:
    from execbound.user_accounts import factor_account

    account = factor_account(conn, session)
    query = (
        "SELECT * FROM execbound.account_factors WHERE tenant_id=:t AND principal_id=:p"
        if account is None
        else "SELECT * FROM execbound.user_factors WHERE account_id=:a"
    )
    row = (
        conn.execute(
            text(query),
            {
                "t": session.identity.tenant_id,
                "p": session.identity.principal_id,
                "a": account,
            },
        )
        .mappings()
        .one_or_none()
    )
    return dict(row) if row is not None else None


def _change(
    conn: Connection, session: "Session", now: datetime, operation: str, data: dict[str, Any]
) -> None:
    from execbound.user_accounts import factor_account

    account = factor_account(conn, session)
    if (
        session.account_id is None
        and account is not None
        and operation
        not in {
            "verify",
            "fail",
            "passkey_begin",
            "passkey_consume",
            "passkey_verify",
            "rotate_session",
            "policy",
        }
    ):
        raise MfaError("ACCOUNT_SIGN_IN_REQUIRED")
    function = "user_security_change" if account else "account_security_change"
    conn.execute(
        text(f"SELECT execbound.{function}(:s,:n,:o,CAST(:d AS jsonb))"),
        {"s": session.session_id, "n": now, "o": operation, "d": json.dumps(data)},
    )


def _event(
    conn: Connection, session: "Session", kind: str, data: dict[str, Any] | None = None
) -> None:
    append_event(
        conn,
        session.identity.tenant_id,
        session.identity.principal_id,
        "account_security." + kind,
        {"session_id": str(session.session_id), **(data or {})},
    )


def _recent(
    conn: Connection, session: "Session", now: datetime, *, enrollment: bool = False
) -> None:
    """Refuse `RECENT_AUTH_REQUIRED` unless this session's enabled factor was verified within
    `STEP_UP_WINDOW`, by a factor entered on it or carried into it: a `trusted` assurance, a
    sign-in a trusted browser let through, is never fresh, however recent the verification
    behind the trust (`0101_trusted_browsers`). With `enrollment` and no enabled factor there
    is no factor to have verified, so what is read instead is the sign-in's own age, within
    `ENROLLMENT_WINDOW`."""
    factor = _factor(conn, session)
    from execbound.user_accounts import factor_account

    account = factor_account(conn, session)
    params = {"t": session.identity.tenant_id, "s": session.session_id, "now": now}
    if enrollment and (factor is None or factor["enabled_at"] is None):
        query = (
            "SELECT 1 FROM execbound.human_sessions WHERE tenant_id=:t AND "
            "session_id=:s AND created_at>:n AND created_at<=:now"
            if account is None
            else "SELECT 1 FROM execbound.account_sessions WHERE account_id=:a AND "
            "session_id=:account_session AND created_at>:n AND created_at<=:now"
        )
        fresh = conn.execute(
            text(query),
            {
                **params,
                "n": now - ENROLLMENT_WINDOW,
                "a": session.account_id,
                "account_session": session.account_session_id,
            },
        ).scalar_one_or_none()
    else:
        factors = (
            "execbound.account_factors f ON f.tenant_id=a.tenant_id AND f.principal_id=:p"
            if account is None
            else "execbound.user_factors f ON f.account_id=:account"
        )
        fresh = conn.execute(
            text(f"""SELECT 1 FROM execbound.session_assurance a JOIN {factors}
          WHERE a.tenant_id=:t AND a.session_id=:s
          AND a.version=f.version AND a.verified_at>:n AND a.verified_at<=:now
          AND f.enabled_at IS NOT NULL AND a.method<>'trusted'"""),  # nosec B608 - Only fixed joins; values are bound.
            {
                **params,
                "n": now - STEP_UP_WINDOW,
                "p": session.identity.principal_id,
                "account": account,
            },
        ).scalar_one_or_none()
    if fresh is None:
        raise MfaError("RECENT_AUTH_REQUIRED")


def begin_enrollment(
    db: Database, session: "Session", ring: KeyRing, *, clock: Clock | None = None
) -> str:
    clock = clock or SystemClock()
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    sealed, key = seal(
        ring,
        secret,
        session.account_id or session.identity.tenant_id,
        session.account_id or session.identity.principal_id,
        "authenticator_seed",
    )
    with _transaction(db, session, clock) as conn:
        _recent(conn, session, clock.now(), enrollment=True)
        _change(conn, session, clock.now(), "stage", {"sealed": sealed, "key": key})
        _event(conn, session, "enrollment_started")
    return secret


def confirm_enrollment(
    db: Database, session: "Session", ring: KeyRing, code: str, *, clock: Clock | None = None
) -> list[str]:
    clock = clock or SystemClock()
    shown, retained = new_recovery_codes(session.account_id or session.identity.principal_id)
    accepted = False
    with _transaction(db, session, clock) as conn:
        row = _factor(conn, session)
        now = clock.now()
        if (
            row is None
            or row["pending_session"] != session.session_id
            or row["pending_expires"] is None
            or row["pending_expires"] <= now
            or (row["locked_until"] is not None and row["locked_until"] > now)
        ):
            raise MfaError("INVALID_ENROLLMENT")
        _recent(conn, session, now, enrollment=True)
        secret = unseal(
            ring,
            row["pending_sealed"],
            row["pending_key"],
            session.account_id or session.identity.tenant_id,
            session.account_id or session.identity.principal_id,
            "authenticator_seed",
        )
        step = verify_totp(secret, code, now.timestamp(), -1)
        if step is None:
            _change(conn, session, now, "fail", {})
            _event(conn, session, "verification_failed")
        else:
            _change(conn, session, now, "enable", {"step": step, "recovery": retained})
            _event(conn, session, "factor_enabled")
            accepted = True
    if not accepted:
        raise MfaError("INVALID_FACTOR")
    return shown


class FactorCheck(StrEnum):
    """What a code presented for a second factor turned out to be."""

    VERIFIED = "verified"
    # The code for a step already used, still inside the window: the code a person still has
    # on screen after it opened another session. Never accepted, never counted as a failure.
    REUSED = "reused"
    REFUSED = "refused"


@dataclass(frozen=True)
class FactorMatch:
    """What a code is for one factor row, decided without writing anything."""

    result: FactorCheck
    method: str | None = None
    step: int | None = None
    digest: str | None = field(default=None, repr=False)


def match_factor(row: dict[str, Any], ring: KeyRing, code: object, now: datetime) -> FactorMatch:
    """Unseal the authenticator secret and compare the code in constant time, writing nothing.

    A fresh step is `VERIFIED("totp", step)`, a held recovery code `VERIFIED("recovery",
    digest=...)`, the code for a step already used within the window `REUSED`, and anything
    else `REFUSED`. The caller decides what a lock means and records the outcome; a caller with
    no session (a password reset from an emailed link) passes the answer to its own definer
    function instead of `user_security_change`.
    """
    secret = unseal(
        ring,
        row["sealed"],
        row["key_id"],
        row["tenant_id"],
        row["principal_id"],
        "authenticator_seed",
    )
    step = verify_totp(secret, code, now.timestamp(), row["last_step"])
    digest = recovery_digest(row["principal_id"], code)
    recovery = digest is not None and any(
        hmac.compare_digest(digest, item) for item in row["recovery_hashes"]
    )
    if recovery:
        return FactorMatch(FactorCheck.VERIFIED, "recovery", None, digest)
    if step is not None:
        return FactorMatch(FactorCheck.VERIFIED, "totp", step, None)
    if used_step(secret, code, now.timestamp(), row["last_step"]):
        return FactorMatch(FactorCheck.REUSED)
    return FactorMatch(FactorCheck.REFUSED)


def check_factor(
    db: Database, session: "Session", ring: KeyRing, code: str, *, clock: Clock | None = None
) -> FactorCheck:
    """Verify a code, telling a code just used from a wrong one (#678).

    A fresh step or an unused recovery code verifies the session. A code for a step already
    used within the current window records `account_security.code_reused` and nothing else:
    no failure is counted, so it never moves the five-attempt lock. Any other code is a failure,
    recorded and counted. A locked factor refuses every code without reading it.
    """
    clock = clock or SystemClock()
    with _transaction(db, session, clock) as conn:
        row = _factor(conn, session)
        now = clock.now()
        if row is None or row["enabled_at"] is None:
            raise MfaError("NOT_ENROLLED")
        if row["locked_until"] is not None and row["locked_until"] > now:
            return FactorCheck.REFUSED
        match = match_factor(row, ring, code, now)
        if match.result is FactorCheck.VERIFIED:
            method = match.method
            _change(
                conn,
                session,
                now,
                "verify",
                {"method": method, "step": match.step, "digest": match.digest},
            )
            _event(
                conn,
                session,
                "recovery_used" if method == "recovery" else "verified",
                {"method": method},
            )
        elif match.result is FactorCheck.REUSED:
            _event(conn, session, "code_reused")
        else:
            _change(conn, session, now, "fail", {})
            _event(conn, session, "verification_failed")
    return match.result


def verify_factor(
    db: Database, session: "Session", ring: KeyRing, code: str, *, clock: Clock | None = None
) -> bool:
    """Whether the code verified the session: `check_factor`'s answer as a yes or no."""
    return check_factor(db, session, ring, code, clock=clock) is FactorCheck.VERIFIED


def _sets_requirement(conn: Connection, session: "Session") -> bool:
    """An administrator who holds the whole workspace: the organization's requirement is one
    value for every person of the tenant, so since `0074_workspace_settings_admin` an
    administrator narrowed to spaces sets none of it. `spaces.narrowed` is the definer
    functions' own predicate, asked here in the same words."""
    identity = session.identity
    return identity.kind == "ADMIN" and not narrowed(
        conn, identity.tenant_id, identity.principal_id
    )


def sets_requirement(db: Database, session: "Session", *, clock: Clock | None = None) -> bool:
    """Whether this person may set the organization's MFA requirement. The page asks before
    the write; `account_security_change` and `user_security_change` refuse the same again."""
    with _transaction(db, session, clock or SystemClock()) as conn:
        return _sets_requirement(conn, session)


def security_overview(
    db: Database, session: "Session", *, clock: Clock | None = None
) -> dict[str, Any]:
    from execbound import trusted_browsers

    clock = clock or SystemClock()
    with _transaction(db, session, clock) as conn:
        row = _factor(conn, session)
        policy = (
            conn.execute(
                text(
                    "SELECT requirement FROM execbound.account_security_policy WHERE tenant_id=:t"
                ),
                {"t": session.identity.tenant_id},
            )
            .mappings()
            .one_or_none()
        )
        requirement = policy["requirement"] if policy is not None else "optional"
        keys = [
            {"credential_id": item["credential_id"], "created_at": item["created_at"]}
            for item in saved_passkeys(conn, session)
        ]
        # A session a workspace switch created belongs to an account sign-in with another
        # session id; one issued at sign-in shares its id. Only the first is opening a
        # workspace, and its challenge names the one it opens.
        entering = (
            conn.execute(
                text("SELECT name FROM execbound.tenants WHERE tenant_id=:t"),
                {"t": session.identity.tenant_id},
            ).scalar_one_or_none()
            if session.account_session_id is not None
            and session.account_session_id != session.session_id
            else None
        )
        return {
            "enabled": row is not None and row["enabled_at"] is not None,
            "recovery_remaining": len(row["recovery_hashes"]) if row else 0,
            "requirement": requirement,
            "required": session.mfa_required,
            "locked_until": row["locked_until"] if row else None,
            "passkeys": keys,
            "sets_requirement": _sets_requirement(conn, session),
            # Whether a sign-in here may skip the factor on a trusted browser (#859): true
            # unless the workspace's administrator turned it off. The challenge offers the
            # "Trust this browser" box only where it is.
            "trust_allowed": trusted_browsers.allowed(conn, session.identity.tenant_id),
            "entering": entering,
        }


def factor_summary(conn: Connection, session: "Session") -> dict[str, Any]:
    """A person's own second-factor status for My account (#678), read inside the caller's
    transaction: whether an authenticator is enabled, how many passkeys are saved, how many
    recovery codes are left and the workspace's requirement. It reads the factor exactly as
    the step-up does and returns counts and flags only, never a seed, digest or passkey id;
    whether the deployment has account security at all is the route's to say."""
    row = _factor(conn, session)
    enabled = row is not None and row["enabled_at"] is not None
    requirement = (
        conn.execute(
            text("SELECT requirement FROM execbound.account_security_policy WHERE tenant_id=:t"),
            {"t": session.identity.tenant_id},
        ).scalar_one_or_none()
        or "optional"
    )
    return {
        "authenticator": enabled,
        "passkeys": len(saved_passkeys(conn, session)),
        "recovery_remaining": len(row["recovery_hashes"]) if row is not None and enabled else 0,
        "requirement": str(requirement),
    }


def saved_passkeys(conn: Connection, session: "Session") -> list[dict[str, Any]]:
    from execbound.user_accounts import factor_account

    account = factor_account(conn, session)
    query = (
        "SELECT * FROM execbound.account_passkeys WHERE tenant_id=:t AND principal_id=:p "
        "ORDER BY created_at"
        if account is None
        else "SELECT * FROM execbound.user_passkeys WHERE account_id=:a ORDER BY created_at"
    )
    return [
        dict(row)
        for row in conn.execute(
            text(query),
            {"t": session.identity.tenant_id, "p": session.identity.principal_id, "a": account},
        ).mappings()
    ]


def manage_security(
    db: Database,
    session: "Session",
    operation: str,
    requirement: str = "optional",
    *,
    clock: Clock | None = None,
) -> list[str]:
    if operation not in {"disable", "recovery", "policy"} or requirement not in {
        "optional",
        "admins",
        "all",
    }:
        raise MfaError("INVALID_OPERATION")
    clock = clock or SystemClock()
    with _transaction(db, session, clock) as conn:
        factor = _factor(conn, session)
        shown, retained = new_recovery_codes(
            factor["principal_id"]
            if factor
            else (session.account_id or session.identity.principal_id)
        )
        _recent(conn, session, clock.now())
        _change(
            conn,
            session,
            clock.now(),
            operation,
            {"requirement": requirement, "recovery": retained},
        )
        _event(
            conn,
            session,
            {
                "disable": "factor_disabled",
                "recovery": "recovery_replaced",
                "policy": "requirement_changed",
            }[operation],
            {"requirement": requirement} if operation == "policy" else {},
        )
    return shown if operation == "recovery" else []


def require_recent_factor(db: Database, session: "Session", *, clock: Clock | None = None) -> None:
    """Step up an enrolled account before account/authority changes: its factor must have been
    verified on this session within `STEP_UP_WINDOW`. The console asks for one in place
    (`surfaces/console_api/step_up.py`) when this refuses."""
    clock = clock or SystemClock()
    with _transaction(db, session, clock) as conn:
        factor = _factor(conn, session)
        if factor is not None and factor["enabled_at"] is not None:
            _recent(conn, session, clock.now())


def rotate_verified_session(
    db: Database, session: "Session", *, clock: Clock | None = None
) -> "SessionGrant":
    from execbound.surfaces.sessions import SessionGrant

    clock = clock or SystemClock()
    token = f"hs1.{session.identity.tenant_id}.{session.session_id}.{secrets.token_urlsafe(32)}"
    csrf = secrets.token_urlsafe(32)
    # The old CSRF binding deliberately changes: validate before the write, not afterwards.
    from execbound.surfaces.sessions import check_session

    try:
        with db.transaction(session.identity.tenant_id) as conn:
            from execbound.user_accounts import factor_account, lock_account

            account = factor_account(conn, session)
            if account is not None:
                lock_account(conn, account)
            fence(conn, session.identity.tenant_id, clock)
            check_session(conn, session, clock)
            _recent(conn, session, clock.now())
            _change(
                conn,
                session,
                clock.now(),
                "rotate_session",
                {
                    "token_hash": hashlib.sha256(token.encode("ascii")).hexdigest(),
                    "csrf_hash": hashlib.sha256(csrf.encode("ascii")).hexdigest(),
                },
            )
        return SessionGrant(
            session.identity,
            session.session_id,
            session.expires_at,
            token,
            csrf,
            account_bound=session.account_id is not None,
        )
    except SQLAlchemyError:
        raise MfaError() from None
