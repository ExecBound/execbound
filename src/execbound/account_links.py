# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit, short-lived provider linking from a recently authenticated account."""

import hashlib
import hmac
import secrets
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound import mfa
from execbound.db import Database, check_runtime
from execbound.identity import UNATTRIBUTED_CONTEXT
from execbound.passwords import normalize_email
from execbound.resolution.models import Clock, SystemClock
from execbound.signin import ExternalAccount, FlowState, SignInRefused
from execbound.surfaces.sessions import Session, SessionError, _read, _secret, _validated
from execbound.user_accounts import account_context, fence_account_workspaces, lock_account


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def begin_link(
    db: Database, session: Session, provider: str, flow: FlowState, *, clock: Clock | None = None
) -> str:
    clock = clock or SystemClock()
    if session.account_id is None or provider not in {"google", "github", "microsoft"}:
        raise SignInRefused("ACCOUNT_SIGN_IN_REQUIRED")
    link = uuid4()
    token = f"al1.{session.account_id}.{link}.{secrets.token_urlsafe(32)}"
    try:
        with mfa._transaction(db, session, clock) as conn:
            mfa._recent(conn, session, clock.now(), enrollment=True)
            mfa._change(
                conn,
                session,
                clock.now(),
                "link_begin",
                {
                    "link": str(link),
                    "provider": provider,
                    "state_hash": digest(flow.state),
                    "token_hash": digest(token),
                },
            )
            mfa._event(conn, session, "provider_link_started", {"provider": provider})
    except (mfa.MfaError, SessionError, SQLAlchemyError):
        raise SignInRefused("LINK_REFUSED") from None
    return token


def finish_link(
    db: Database, token: str, flow: FlowState, proof: ExternalAccount, *, clock: Clock | None = None
) -> None:
    """A callback holds only the scoped linking capability, never a global login grant.

    The originating account session, workspace generation and recent MFA are rechecked.
    The one-use capability binds the callback's state, provider and short expiry to that
    session. A revoked session or an intervening workspace switch invalidates it.
    """
    clock = clock or SystemClock()
    try:
        if len(token) > 160:
            raise ValueError
        prefix, account_text, link_text, secret = token.split(".")
        account, link = UUID(account_text), UUID(link_text)
        if (
            prefix != "al1"
            or str(account) != account_text
            or str(link) != link_text
            or not _secret(secret)
        ):
            raise ValueError
        with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
            check_runtime(conn)
            account_context(conn, account)
            lock_account(conn, account)
            row = (
                conn.execute(
                    text(
                        "SELECT * FROM execbound.account_provider_links "
                        "WHERE account_id=:a AND link_id=:l"
                    ),
                    {"a": account, "l": link},
                )
                .mappings()
                .one_or_none()
            )
            if (
                row is None
                or row["consumed_at"] is not None
                or not row["created_at"] <= clock.now() < row["expires_at"]
                or row["provider"] != proof.provider
                or not hmac.compare_digest(row["token_hash"], digest(token))
                or not hmac.compare_digest(row["state_hash"], digest(flow.state))
            ):
                raise ValueError
            tenant = row["tenant_id"]
            conn.execute(
                text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)}
            )
            fence_account_workspaces(conn, account, tenant, clock)
            session = _validated(conn, _read(conn, tenant, row["session_id"]), clock)
            if session.account_id != account:
                raise ValueError
            mfa._recent(conn, session, clock.now(), enrollment=True)
            mfa._change(
                conn,
                session,
                clock.now(),
                "link_finish",
                {
                    "link": str(link),
                    "provider": proof.provider,
                    "subject": proof.subject,
                    "email": normalize_email(proof.email),
                    "display_name": proof.display_name,
                    "state_hash": digest(flow.state),
                    "token_hash": digest(token),
                },
            )
            mfa._event(conn, session, "provider_linked", {"provider": proof.provider})
    except (ValueError, SessionError, SQLAlchemyError):
        raise SignInRefused("LINK_REFUSED") from None
