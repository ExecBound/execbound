# SPDX-License-Identifier: AGPL-3.0-only
"""Opaque credentials: token selectors are untrusted until the digest matches."""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound.db import Database, check_runtime
from execbound.logging_schema import log_event

PrincipalKind = Literal["AGENT", "HUMAN_APPROVER", "ADMIN"]


Reason = Literal["MALFORMED", "UNKNOWN", "MISMATCH", "EXPIRED", "REVOKED", "INACTIVE"]
Surface = Literal["http", "mcp", "human", "monitor", "token", "signal"]
SubjectKind = Literal["credential", "source", "principal"]
# Tenant context used to record an unattributed failure; the row itself carries no tenant.
UNATTRIBUTED_CONTEXT = UUID("00000000-0000-4000-8000-000000000000")


class AuthenticationFailed(ValueError):
    """One message for every caller; the reason and attribution stay private to the recorder."""

    def __init__(
        self,
        message: str = "Invalid credentials",
        *,
        reason: Reason = "MALFORMED",
        tenant_id: UUID | None = None,
        subject_kind: SubjectKind | None = None,
        subject_id: UUID | None = None,
        context_tenant: UUID | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.tenant_id = tenant_id
        self.subject_kind = subject_kind
        self.subject_id = subject_id
        self.context_tenant = context_tenant


# The expiry of an agent's API key issued to never expire (0057). It is a real instant rather
# than a missing one, so everything that compares an identity's expiry or takes the least of
# several reads it unchanged; `admin_issue_credential` lets exactly this instant past the
# 90-day cap, for an agent's key and nothing else, and the console shows it as "Never".
NEVER = datetime(9999, 12, 31, tzinfo=UTC)


@dataclass(frozen=True)
class Identity:
    tenant_id: UUID
    principal_id: UUID
    credential_id: UUID
    kind: PrincipalKind
    expires_at: datetime


# An agent key's last use, for display only (0079): a person's or an owner tool's credential is
# not stamped, so an administrator's read-only command writes nothing. Stamped at most once a
# minute, after every check
# below has passed and never on a refusal (every refusal raises inside this transaction, which
# then rolls back), in authentication's own transaction and never in a decision's. It runs
# inside a savepoint whose failure is deliberately ignored, so the stamp can never change
# authentication's outcome: the function skips a row another transaction holds rather than
# waiting for it, and stamps nothing when the application's clock that issued the key is ahead
# of the database's. A module constant so a test can replace it.
_STAMP = text("SELECT execbound.credential_used(:c, :n)")
_STAMP_INTERVAL = timedelta(minutes=1)


def new_token(tenant_id: UUID, credential_id: UUID) -> tuple[str, str]:
    token = f"eb1.{tenant_id}.{credential_id}.{secrets.token_urlsafe(32)}"
    return token, hashlib.sha256(token.encode("ascii")).hexdigest()


def authenticate(db: Database, token: str) -> Identity:
    try:
        if len(token) > 160:
            raise ValueError
        version, tenant_text, credential_text, secret = token.split(".")
        tenant_id, credential_id = UUID(tenant_text), UUID(credential_text)
        if (
            version != "eb1"
            or str(tenant_id) != tenant_text
            or str(credential_id) != credential_text
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", secret)
        ):
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise AuthenticationFailed("Invalid credentials") from exc
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    with db.transaction(tenant_id) as conn:
        check_runtime(conn)
        # One unfiltered lookup so every well-formed token costs the same work; the
        # conditions below classify the failure privately without changing the message.
        row = (
            conn.execute(
                text("""
            SELECT c.tenant_id, c.principal_id, c.credential_id,
                   execbound.access_effective_kind(p.principal_id) AS kind, c.expires_at,
                   c.token_hash, c.revoked_at, p.active AS principal_active,
                   t.active AS tenant_active, c.last_used_at, statement_timestamp() AS now
            FROM execbound.credentials c
            JOIN execbound.principals p USING (tenant_id, principal_id)
            JOIN execbound.tenants t USING (tenant_id)
            WHERE c.tenant_id = :tenant AND c.credential_id = :credential
        """),
                {"tenant": tenant_id, "credential": credential_id},
            )
            .mappings()
            .one_or_none()
        )
        matches = hmac.compare_digest(digest, row["token_hash"] if row else "0" * 64)
        if row is None:
            raise AuthenticationFailed(reason="UNKNOWN", context_tenant=tenant_id)
        attributed: dict[str, Any] = {
            "tenant_id": tenant_id,
            "subject_kind": "credential",
            "subject_id": credential_id,
        }
        if not matches:
            raise AuthenticationFailed(reason="MISMATCH", **attributed)
        if row["revoked_at"] is not None:
            raise AuthenticationFailed(reason="REVOKED", **attributed)
        if row["expires_at"] <= row["now"]:
            raise AuthenticationFailed(reason="EXPIRED", **attributed)
        if not row["principal_active"] or not row["tenant_active"]:
            raise AuthenticationFailed(reason="INACTIVE", **attributed)
        last_used = row["last_used_at"]
        if row["kind"] == "AGENT" and (
            last_used is None or row["now"] - last_used >= _STAMP_INTERVAL
        ):
            try:
                with conn.begin_nested():
                    conn.execute(_STAMP, {"c": row["credential_id"], "n": row["now"]})
            except SQLAlchemyError:
                pass  # Display only: a refused, timed-out or skipped stamp changes nothing.
        return Identity(
            row["tenant_id"],
            row["principal_id"],
            row["credential_id"],
            row["kind"],
            row["expires_at"],
        )


def record_failure(
    db: Database, surface: Surface, failure: AuthenticationFailed, now: datetime | None = None
) -> None:
    """Best-effort bounded counter: never raises and never changes what the caller sees."""
    log_event(
        "authentication.refused",
        level="WARNING",
        surface=surface,
        reason=failure.reason,
        tenant_id=failure.tenant_id,
        credential_id=failure.subject_id if failure.subject_kind == "credential" else None,
        source_id=failure.subject_id if failure.subject_kind == "source" else None,
    )
    try:
        _write_failure(db, surface, failure, now or datetime.now(UTC))
    except Exception:
        return


def _write_failure(
    db: Database, surface: Surface, failure: AuthenticationFailed, now: datetime
) -> None:
    now = now.astimezone(UTC)
    window = now.replace(second=0, microsecond=0)
    context = failure.tenant_id or failure.context_tenant or UNATTRIBUTED_CONTEXT
    with db.transaction(context) as conn:
        conn.execute(
            text("""
            INSERT INTO execbound.authentication_failures
              (failure_id, surface, reason, window_start, tenant_id, subject_kind, subject_id,
               count, first_at, last_at)
            VALUES (:failure, :surface, :reason, :window, :tenant, :kind, :subject, 1, :now, :now)
            ON CONFLICT (surface, reason, window_start, tenant_id, subject_kind, subject_id)
            DO UPDATE SET count = execbound.authentication_failures.count + 1,
                          last_at = excluded.last_at
        """),
            {
                "failure": uuid4(),
                "surface": surface,
                "reason": failure.reason,
                "window": window,
                "tenant": failure.tenant_id,
                "kind": failure.subject_kind,
                "subject": failure.subject_id,
                "now": now,
            },
        )
