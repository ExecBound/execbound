# SPDX-License-Identifier: AGPL-3.0-only
"""User-owned preferences and an administrator's privacy-request queue."""

import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database
from execbound.execution.store import fence
from execbound.resolution.models import Clock, SystemClock
from execbound.spaces import narrowed
from execbound.surfaces.sessions import Session, check_session

NOTICES = {
    "account_security.factor_enabled": "Authenticator enabled or replaced",
    "account_security.factor_disabled": "Multi-factor authentication disabled",
    "account_security.recovery_used": "A recovery code was used",
    "account_security.recovery_replaced": "Recovery codes replaced",
    "account_security.requirement_changed": "Workspace MFA requirement changed",
    "account_security.passkey_added": "A passkey was added",
    "account_security.passkey_removed": "A passkey was removed",
    "password.changed": "Password changed",
}
ACCOUNT_NOTICES = {
    "enable": "Authenticator enabled or replaced",
    "disable": "Multi-factor authentication disabled",
    "recovery": "Recovery codes replaced",
    "passkey_register": "A passkey was added",
    "passkey_remove": "A passkey was removed",
    "password": "Password changed",  # nosec B105 - Event label, not a credential.
    "link_finish": "A sign-in provider was linked",
    # A hosted password reset from an emailed link (#678); self-hosted never writes the kind.
    "password_reset": "Password reset from an emailed link",  # nosec B105 - Event label.
    "other_devices_signed_out": "Other devices signed out",
    "signed_out": "Signed out",
}
REQUEST_KINDS = {"data_access", "close_account", "close_workspace"}


class AccountError(ValueError):
    def __init__(self, code: str = "UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Account request refused")


@contextmanager
def transaction(db: Database, session: Session, clock: Clock) -> Iterator[Connection]:
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            fence(conn, session.identity.tenant_id, clock)
            check_session(conn, session, clock)
            yield conn
            check_session(conn, session, clock)
    except SQLAlchemyError:
        raise AccountError() from None


def overview(db: Database, session: Session, *, clock: Clock | None = None) -> dict[str, Any]:
    with transaction(db, session, clock or SystemClock()) as conn:
        params = {"t": session.identity.tenant_id, "p": session.identity.principal_id}
        profile = (
            conn.execute(
                text(
                    "SELECT p.label AS name FROM execbound.principals p "
                    "WHERE p.tenant_id=:t AND p.principal_id=:p"
                ),
                params,
            )
            .mappings()
            .one()
        )
        requests = (
            conn.execute(
                text("""
          SELECT request_id,kind,state,requested_at,closed_at,response FROM
              execbound.account_requests
          WHERE tenant_id=:t AND principal_id=:p
          ORDER BY (state='pending') DESC,requested_at DESC LIMIT 50
        """),
                params,
            )
            .mappings()
            .all()
        )
        notices = (
            conn.execute(
                text("""
          SELECT sequence,kind,occurred_at FROM execbound.audit_events
          WHERE tenant_id=:t AND actor_id=:p AND kind=ANY(:kinds)
            AND occurred_at>clock_timestamp()-interval '90 days'
          ORDER BY sequence DESC LIMIT 30
        """),
                {**params, "kinds": list(NOTICES)},
            )
            .mappings()
            .all()
        )
        notice_names = NOTICES
        if session.account_id is not None:
            notices = (
                conn.execute(
                    text(
                        "SELECT event_id AS sequence,kind,occurred_at "
                        "FROM execbound.user_security_events "
                        "WHERE account_id=:a AND kind=ANY(:kinds) "
                        "AND occurred_at>clock_timestamp()-interval '90 days' "
                        "ORDER BY occurred_at DESC,event_id DESC LIMIT 30"
                    ),
                    {"a": session.account_id, "kinds": list(ACCOUNT_NOTICES)},
                )
                .mappings()
                .all()
            )
            notice_names = ACCOUNT_NOTICES
        return {
            **profile,
            "requests": [dict(row) for row in requests],
            "notifications": [
                {
                    "sequence": row["sequence"],
                    "at": row["occurred_at"],
                    "message": notice_names[row["kind"]],
                }
                for row in notices
            ],
        }


def _holds_the_workspace(conn: Connection, session: Session) -> bool:
    """An administrator who holds the whole workspace, not one narrowed to spaces.

    The requests queue holds every person's requests, from every space, with each requester's
    name and id, and a response recorded there closes a request whoever filed it, a workspace
    closure included. So since 8 October 2026 only a workspace administrator reads or answers
    it. `spaces.narrowed` is the definer functions' own predicate, asked in the same words, and
    `account_change` asks it again before it records a response.
    """
    identity = session.identity
    return identity.kind == "ADMIN" and not narrowed(
        conn, identity.tenant_id, identity.principal_id
    )


def request_queue(
    db: Database, session: Session, *, clock: Clock | None = None
) -> list[dict[str, Any]]:
    with transaction(db, session, clock or SystemClock()) as conn:
        # Refused before any request is read: an administrator narrowed to spaces would
        # otherwise read the names and ids of people outside them.
        if not _holds_the_workspace(conn, session):
            raise AccountError("FORBIDDEN")
        return [
            dict(row)
            for row in conn.execute(
                text("""
          SELECT r.request_id,r.kind,r.state,r.requested_at,r.closed_at,r.response,
            p.label AS name,r.principal_id,p.number,p.kind AS principal_kind
          FROM execbound.account_requests r
          JOIN execbound.principals p USING(tenant_id,principal_id)
          WHERE r.tenant_id=:t
          ORDER BY (r.state='pending') DESC,
            CASE WHEN r.state='pending' THEN r.requested_at END ASC,
            r.requested_at DESC LIMIT 100
        """),
                {"t": session.identity.tenant_id},
            ).mappings()
        ]


def change(
    db: Database,
    session: Session,
    operation: str,
    data: dict[str, Any],
    *,
    clock: Clock | None = None,
) -> None:
    data = dict(data)
    if operation == "profile":
        valid = (
            set(data) == {"name"}
            and isinstance(data["name"], str)
            and 1 <= len(data["name"].strip()) <= 80
            and not any(ord(c) < 32 for c in data["name"])
        )
    elif operation == "request":
        valid = set(data) == {"kind"} and data["kind"] in REQUEST_KINDS
        if data.get("kind") == "close_workspace" and session.identity.kind != "ADMIN":
            raise AccountError("FORBIDDEN")
        data["request_id"] = str(uuid4())
    elif operation == "resolve":
        valid = (
            set(data) == {"request_id", "state", "response"}
            and data["state"] in {"completed", "declined"}
            and isinstance(data["response"], str)
            and 1 <= len(data["response"].strip()) <= 1000
        )
        if session.identity.kind != "ADMIN":
            raise AccountError("FORBIDDEN")
        try:
            data["request_id"] = str(UUID(str(data.get("request_id"))))
        except ValueError:
            valid = False
    else:
        valid = False
    if not valid:
        raise AccountError("INVALID_BODY")
    clock = clock or SystemClock()
    with transaction(db, session, clock) as conn:
        if operation == "resolve" and not _holds_the_workspace(conn, session):
            raise AccountError("FORBIDDEN")
        conn.execute(
            text("SELECT execbound.account_change(:s,:n,:o,CAST(:d AS jsonb))"),
            {"s": session.session_id, "n": clock.now(), "o": operation, "d": json.dumps(data)},
        )
        # Neither the name nor the request response is duplicated into the audit chain.
        append_event(
            conn,
            session.identity.tenant_id,
            session.identity.principal_id,
            "account." + operation,
            {"operation": operation},
        )
