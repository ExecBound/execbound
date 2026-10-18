# SPDX-License-Identifier: AGPL-3.0-only
"""Personal authentication and its workspace memberships; no execution authority here."""

import hashlib
import hmac
import secrets
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.db import Database, check_runtime
from execbound.identity import UNATTRIBUTED_CONTEXT, AuthenticationFailed, Identity
from execbound.resolution.models import Clock
from execbound.secrets import withheld

if TYPE_CHECKING:
    from execbound.passwords import PasswordRecord
    from execbound.signin import ExternalAccount
    from execbound.surfaces.sessions import Session


def account_context(conn: Connection, account_id: UUID) -> None:
    conn.execute(text("SELECT set_config('execbound.account_id',:a,true)"), {"a": str(account_id)})


def adopt_personal_identity(db: Database, tenant: UUID, principal: UUID) -> UUID:
    """Adopt an enrolled legacy identity without joining accounts by matching email."""
    with db.transaction(tenant) as conn:
        check_runtime(conn)
        account = conn.execute(
            text("SELECT execbound.account_adopt(:p)"), {"p": principal}
        ).scalar_one()
        if account is None:
            raise AuthenticationFailed(reason="UNKNOWN")
        return UUID(str(account))


def _binding(db: Database, provider: str, subject: str) -> dict[str, Any] | None:
    """The `user_identities` row for this provider subject, revoked or not, or None."""
    with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
        check_runtime(conn)
        conn.execute(
            text(
                "SELECT set_config('execbound.sign_in_provider',:p,true), "
                "set_config('execbound.sign_in_subject',:s,true)"
            ),
            {"p": provider, "s": subject},
        )
        row = (
            conn.execute(
                text(
                    "SELECT account_id,revoked_at FROM execbound.user_identities "
                    "WHERE provider=:p AND subject=:s"
                ),
                {"p": provider, "s": subject},
            )
            .mappings()
            .one_or_none()
        )
        return dict(row) if row else None


def subject_known(db: Database, provider: str, subject: str) -> bool:
    """Whether this provider subject already identifies someone: a binding, revoked or not,
    or a legacy binding a first sign-in would adopt. Reveals nothing beyond that one pair.

    A database fault on either half is `PasswordError("PASSWORD_UNAVAILABLE")`, the one
    outcome `locate_subject` already gives for its own half's fault: a caller sees a single
    failure shape for this question, never two, and never the generic `SignInRefused` a
    missing answer gets."""
    from execbound.passwords import PasswordError, locate_subject

    try:
        return _binding(db, provider, subject) is not None or (
            locate_subject(db, provider, subject) is not None
        )
    except (SQLAlchemyError, PasswordError):
        raise PasswordError("PASSWORD_UNAVAILABLE") from None


def provider_sign_in(
    db: Database, proof: "ExternalAccount", *, clock: Clock, prefer: UUID | None = None
) -> Identity:
    """Only an existing subject binding identifies a personal account at anonymous sign-in.

    The session opens `prefer` when it is one of the account's usable workspaces."""
    from execbound.passwords import locate_subject, mint_session_credential
    from execbound.signin import SignInRefused

    try:
        found = _binding(db, proof.provider, proof.subject)
        if found is None:
            legacy = locate_subject(db, proof.provider, proof.subject)
            if legacy is None:
                raise SignInRefused("NO_ACCOUNT")
            adopt_personal_identity(db, *legacy)
            found = _binding(db, proof.provider, proof.subject)
        if found is None or found["revoked_at"] is not None:
            raise SignInRefused("NO_ACCOUNT")
        account_id = found["account_id"]
        with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
            account_context(conn, account_id)
            account = (
                conn.execute(
                    text("SELECT active,version FROM execbound.user_accounts WHERE account_id=:a"),
                    {"a": account_id},
                )
                .mappings()
                .one()
            )
        if not account["active"]:
            raise SignInRefused("NO_ACCOUNT")
        member = first_membership(db, account_id, prefer=prefer)
        return mint_session_credential(
            db,
            member["tenant_id"],
            member["principal_id"],
            proof.provider,
            clock=clock,
            account=(account_id, account["version"]),
            # The provider's own subject, withheld rather than refused: refusing it would
            # lock out a person this provider already proved signed in.
            detail=withheld("subject", proof.subject),
        )
    except (AuthenticationFailed, SQLAlchemyError):
        raise SignInRefused("NO_ACCOUNT") from None


def locate_account(db: Database, email: str) -> dict[str, Any] | None:
    with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
        check_runtime(conn)
        conn.execute(text("SELECT set_config('execbound.sign_in_email',:e,true)"), {"e": email})
        row = (
            conn.execute(text("SELECT * FROM execbound.user_accounts WHERE email=:e"), {"e": email})
            .mappings()
            .one_or_none()
        )
        return dict(row) if row else None


def password_record(db: Database, account_id: UUID) -> "PasswordRecord | None":
    from execbound.passwords import _record

    with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
        check_runtime(conn)
        account_context(conn, account_id)
        row = (
            conn.execute(
                text("SELECT * FROM execbound.user_passwords WHERE account_id=:a"),
                {"a": account_id},
            )
            .mappings()
            .one_or_none()
        )
        return _record(row)


def memberships(conn: Connection, account_id: UUID) -> list[dict[str, Any]]:
    """List only this account's current usable memberships, without a tenant directory."""
    account_context(conn, account_id)
    account = (
        conn.execute(
            text(
                "SELECT active,email_verified_at FROM execbound.user_accounts WHERE account_id=:a"
            ),
            {"a": account_id},
        )
        .mappings()
        .one_or_none()
    )
    if not account or not account["active"]:
        return []
    candidates = (
        conn.execute(
            text(
                "SELECT * FROM execbound.workspace_memberships "
                "WHERE account_id=:a AND active ORDER BY created_at,tenant_id"
            ),
            {"a": account_id},
        )
        .mappings()
        .all()
    )
    original = conn.execute(text("SELECT current_setting('execbound.tenant_id',true)")).scalar_one()
    available = []
    try:
        for item in candidates:
            if account["email_verified_at"] is None and not item["legacy_access"]:
                continue
            conn.execute(
                text("SELECT set_config('execbound.tenant_id',:t,true)"),
                {"t": str(item["tenant_id"])},
            )
            row = (
                conn.execute(
                    text(
                        "SELECT t.name,p.kind,EXISTS(SELECT 1 FROM execbound.identity_providers i "
                        "WHERE i.tenant_id=t.tenant_id AND i.require_sign_in) "
                        "AS requires_directory "
                        "FROM execbound.tenants t "
                        "JOIN execbound.principals p USING(tenant_id) WHERE "
                        "t.tenant_id=:t AND p.principal_id=:p AND t.active AND p.active "
                        "AND p.kind IN ('ADMIN','HUMAN_APPROVER')"
                    ),
                    {"t": item["tenant_id"], "p": item["principal_id"]},
                )
                .mappings()
                .one_or_none()
            )
            if row:
                available.append({**dict(item), **dict(row)})
    finally:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": original or ""}
        )
    return available


def first_membership(
    db: Database, account_id: UUID, *, prefer: UUID | None = None
) -> dict[str, Any]:
    """The workspace an account's sign-in opens, among those it may open without a directory.

    `prefer` (the workspace a signed navigation hint names) wins only when it is one of them:
    it chooses among the account's own usable memberships and never widens them. Otherwise the
    workspace entered most recently, then the oldest membership, as before any was entered.
    """
    with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
        check_runtime(conn)
        available = [
            item for item in memberships(conn, account_id) if not item["requires_directory"]
        ]
    if not available:
        raise AuthenticationFailed(reason="INACTIVE")
    for item in available:
        if prefer is not None and item["tenant_id"] == prefer:
            return item
    # `memberships()` lists by `created_at, tenant_id`, and the sort is stable, so ordering by
    # the entry alone, newest first with never-entered last, keeps that order beneath it.
    entered = sorted(
        (item for item in available if item.get("last_entered_at") is not None),
        key=lambda item: item["last_entered_at"],
        reverse=True,
    )
    return entered[0] if entered else available[0]


def validate_workspace_session(conn: Connection, row: dict[str, Any], now: datetime) -> UUID | None:
    """A tenant session is valid only while its independently authenticated account is."""
    # A configured IdP is optional until the operator explicitly requires it. A
    # personal account session is never evidence of authentication at that directory.
    from execbound.directory_store import RECHECK_GRACE
    from execbound.surfaces.sessions import SessionError

    unavailable_directory = conn.execute(
        text("""
        SELECT 1 FROM execbound.identity_providers p WHERE p.tenant_id=:t AND p.require_sign_in
        AND (p.state<>'enabled' OR NOT EXISTS(
            SELECT 1 FROM execbound.federated_sign_ins f
            JOIN execbound.identity_links l ON l.tenant_id=f.tenant_id
                AND l.provider_id=f.provider_id AND l.subject=f.subject
            WHERE f.tenant_id=p.tenant_id AND f.provider_id=p.provider_id
                AND f.credential_id=:c AND f.revoked_reason IS NULL
                AND l.principal_id=:person AND l.revoked_at IS NULL
                AND f.verified_at<=:now AND f.verified_at>:earliest)) LIMIT 1
    """),
        {
            "t": row["tenant_id"],
            "c": row["credential_id"],
            "person": row["principal_id"],
            "now": now,
            "earliest": now - RECHECK_GRACE,
        },
    ).scalar_one_or_none()
    if unavailable_directory:
        raise SessionError("DIRECTORY_REQUIRED")

    if row.get("account_id") is None:
        member = (
            conn.execute(
                text(
                    "SELECT * FROM execbound.workspace_memberships "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": row["tenant_id"], "p": row["principal_id"]},
            )
            .mappings()
            .one_or_none()
        )
        if member is None:
            return None
        account_context(conn, member["account_id"])
        account = (
            conn.execute(
                text("SELECT active,version FROM execbound.user_accounts WHERE account_id=:a"),
                {"a": member["account_id"]},
            )
            .mappings()
            .one()
        )
        if (
            not account["active"]
            or not member["active"]
            or row.get("account_version") != account["version"]
            or row.get("membership_version") != member["version"]
        ):
            raise SessionError()
        return UUID(str(member["account_id"]))
    account_context(conn, row["account_id"])
    valid = conn.execute(
        text("""
        SELECT 1 FROM execbound.account_sessions s
        JOIN execbound.user_accounts a USING(account_id)
        JOIN execbound.workspace_memberships m USING(account_id)
        WHERE s.account_id=:a AND s.session_id=:s AND s.revoked_at IS NULL
          AND s.created_at<=:n AND s.expires_at>:n AND a.active AND a.version=s.version
          AND s.current_tenant=:t AND s.current_session=:ws
          AND m.tenant_id=:t AND m.principal_id=:p AND m.active AND m.version=:mv
          AND (m.legacy_access OR a.email_verified_at IS NOT NULL)
    """),
        {
            "a": row["account_id"],
            "s": row["account_session_id"],
            "n": now,
            "t": row["tenant_id"],
            "ws": row["session_id"],
            "p": row["principal_id"],
            "mv": row["membership_version"],
        },
    ).scalar_one_or_none()
    if valid is None:
        raise SessionError()
    return UUID(str(row["account_id"]))


def lock_account(conn: Connection, account_id: UUID) -> None:
    """Always before the first tenant fence; tenant-only checks never acquire this lock."""
    account_context(conn, account_id)
    conn.execute(text("SELECT execbound.account_lock(:a)"), {"a": account_id})


def factor_account(conn: Connection, session: "Session") -> UUID | None:
    """Local authentication can prove MFA, but cannot administer the shared account."""
    account = (
        session.account_id
        or conn.execute(
            text(
                "SELECT account_id FROM execbound.workspace_memberships "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": session.identity.tenant_id, "p": session.identity.principal_id},
        ).scalar_one_or_none()
    )
    if account is not None:
        account_context(conn, account)
    return account


def fence_account_workspaces(conn: Connection, account: UUID, tenant: UUID, clock: Clock) -> None:
    """Global revocation serializes with in-flight tenant mutations, in sorted lock order."""
    from execbound.execution.store import fence

    lock_account(conn, account)
    tenants = set(
        conn.execute(
            text("SELECT tenant_id FROM execbound.workspace_memberships WHERE account_id=:a"),
            {"a": account},
        ).scalars()
    ) | {tenant}
    for selected in sorted(tenants):
        conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(selected)})
        fence(conn, selected, clock)
    conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})


def end_account_sessions(db: Database, session: "Session", *, others: bool, clock: Clock) -> int:
    from execbound.audit import append_event
    from execbound.surfaces.sessions import SessionError, check_session

    if session.account_id is None:
        raise SessionError("ACCOUNT_SIGN_IN_REQUIRED")
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            fence_account_workspaces(conn, session.account_id, session.identity.tenant_id, clock)
            check_session(conn, session, clock)
            count = conn.execute(
                text("SELECT execbound.account_session_revoke(:s,:n,:o)"),
                {"s": session.session_id, "n": clock.now(), "o": others},
            ).scalar_one()
            append_event(
                conn,
                session.identity.tenant_id,
                session.identity.principal_id,
                "account_security.other_devices_signed_out"
                if others
                else "account_security.signed_out",
                {"session_id": str(session.session_id), "sessions": count},
            )
            return int(count)
    except SQLAlchemyError:
        raise SessionError("SESSION_UNAVAILABLE") from None


def open_account_session(
    conn: Connection, identity: Identity, session_id: UUID, now: datetime
) -> tuple[UUID | None, str | None, int | None]:
    """Only credentials minted by personal authentication may establish an account session."""
    account = conn.execute(
        text(
            "SELECT account_id FROM execbound.account_login_proofs "
            "WHERE tenant_id=:t AND credential_id=:c"
        ),
        {"t": identity.tenant_id, "c": identity.credential_id},
    ).scalar_one_or_none()
    if account is None:
        return None, None, None
    token = f"as1.{account}.{session_id}.{secrets.token_urlsafe(32)}"
    conn.execute(
        text("SELECT execbound.account_session_open(:c,:s,:h,:n)"),
        {
            "c": identity.credential_id,
            "s": session_id,
            "n": now,
            "h": hashlib.sha256(token.encode("ascii")).hexdigest(),
        },
    )
    version = conn.execute(
        text(
            "SELECT version FROM execbound.workspace_memberships "
            "WHERE account_id=:a AND tenant_id=:t AND principal_id=:p AND active"
        ),
        {"a": account, "t": identity.tenant_id, "p": identity.principal_id},
    ).scalar_one()
    return account, token, version


def check_account_cookie(conn: Connection, session: "Session", token: str, now: datetime) -> None:
    from execbound.surfaces.sessions import SessionError, _secret

    if session.account_id is None or session.account_session_id is None:
        raise SessionError("ACCOUNT_SIGN_IN_REQUIRED")
    try:
        version, account, identifier, secret = token.split(".")
        if (
            version != "as1"
            or account != str(session.account_id)
            or identifier != str(session.account_session_id)
            or not _secret(secret)
        ):
            raise ValueError
    except (ValueError, AttributeError):
        raise SessionError() from None
    account_context(conn, session.account_id)
    stored = conn.execute(
        text(
            "SELECT token_hash FROM execbound.account_sessions "
            "WHERE account_id=:a AND session_id=:s AND revoked_at IS NULL "
            "AND expires_at>:n AND created_at<=:n"
        ),
        {"a": session.account_id, "s": session.account_session_id, "n": now},
    ).scalar_one_or_none()
    if not hmac.compare_digest(
        stored or "0" * 64, hashlib.sha256(token.encode("ascii")).hexdigest()
    ):
        raise SessionError()


def legacy_holder(db: Database, email: str) -> bool:
    """Whether an active person, set up before accounts existed, holds this address.

    The same predicate `community_provision` applies before it creates an account: an
    `ADMIN` or `HUMAN_APPROVER` principal that is active. An inactive holder cannot sign in to
    adopt anything, so it does not make the address theirs. The principal is read inside its
    own tenant, the way `sign_in_with_password` reads it.
    """
    from execbound.passwords import _PERSON, locate_email

    found = locate_email(db, email)
    if found is None:
        return False
    tenant_id, principal_id = found
    with db.transaction(tenant_id) as conn:
        check_runtime(conn)
        row = (
            conn.execute(text(_PERSON), {"t": tenant_id, "p": principal_id})
            .mappings()
            .one_or_none()
        )
    return (
        row is not None
        and bool(row["principal_active"])
        and row["kind"] in {"ADMIN", "HUMAN_APPROVER"}
    )
