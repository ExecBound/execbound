# SPDX-License-Identifier: AGPL-3.0-only
"""Personal access tokens: an administrator's own bearer token for the console API.

A token is `ebp1.<tenant>.<token>.<secret>`, stored as the SHA-256 digest of the whole string
beside a backing credential that migration 0063's function mints with a discarded secret. The
identity a token acts as is that credential-backed ADMIN identity, so every check the console
makes of a session's identity applies to it unchanged. A `TokenSession` carries it; the
console's `check_session` hands one to `check_token_session`, which reads the token and its
owner instead of a `human_sessions` row. A token session can never manage tokens.
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from execbound import access_control as access
from execbound.audit import acted_with, append_event
from execbound.db import Database, UnsafeDatabaseRole, check_runtime
from execbound.execution.store import fence
from execbound.identity import NEVER, AuthenticationFailed, Identity, Reason
from execbound.resolution.models import Clock, SystemClock
from execbound.secrets import secret_shaped
from execbound.spaces import NO_SPACE_FILTER, SpaceFilter, administered_clause
from execbound.surfaces.sessions import Session, SessionError, _human, check_session

TOKEN_PREFIX = "ebp1"  # nosec B105 - The token format's public prefix, not a credential.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
TOKEN = re.compile(rf"^ebp1\.({_UUID})\.({_UUID})\.([A-Za-z0-9_-]{{43}})$")
# Every code the three admin functions in migration 0063 can raise: the ACTOR check shared
# by all three (INVALID_TENANT, INVALID_ACTOR), the clock guard shared by all three
# (INVALID_CLOCK), and admin_issue_personal_token's own INVALID_LIFETIME, INVALID_NAME,
# INVALID_DIGEST and TOO_MANY_TOKENS, and admin_revoke_personal_token's/
# admin_delete_personal_token's own INVALID_TOKEN.
_REFUSALS = (
    "INVALID_ACTOR",
    "INVALID_LIFETIME",
    "INVALID_NAME",
    "INVALID_TOKEN",
    "TOO_MANY_TOKENS",
    "INVALID_CLOCK",
    "INVALID_TENANT",
    "INVALID_DIGEST",
)


class TokenError(ValueError):
    """A refusal the console API maps to a typed code; never carries the token."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TokenRefused(SessionError):
    """A token that did not authenticate, with the failure class `record_failure` keeps.

    Answered exactly as any other refused session; the class is private to the recorder, as
    `identity.authenticate`'s is for an `eb1` credential.
    """

    def __init__(self, failure: AuthenticationFailed) -> None:
        super().__init__()
        self.failure = failure


@dataclass(frozen=True)
class TokenSession(Session):
    """The console's session shape, standing for one personal access token.

    `space_id` is the space one request named in `X-ExecBound-Space`, the token's stand-in for
    the current space a browser session keeps in its row; `visible_spaces` holds it to the
    owner's membership inside every read, and a space not theirs is refused, never widened.
    """

    token_id: UUID | None = None
    space_id: UUID | None = None


def _now(clock: Clock) -> datetime:
    return clock.now().astimezone(UTC)


def _read(conn: Connection, tenant: UUID, token_id: UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(
                "SELECT * FROM execbound.personal_access_tokens WHERE tenant_id=:t AND token_id=:k"
            ),
            {"t": tenant, "k": token_id},
        )
        .mappings()
        .one_or_none()
    )
    return dict(row) if row is not None else None


def _owner_active(conn: Connection, tenant: UUID, principal: UUID) -> None:
    """A member of the workspace with an active membership and an active account."""
    from execbound.user_accounts import account_context

    member = (
        conn.execute(
            text(
                "SELECT account_id, active FROM execbound.workspace_memberships "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "p": principal},
        )
        .mappings()
        .one_or_none()
    )
    if member is None:
        return
    if not member["active"]:
        raise SessionError()
    account_context(conn, member["account_id"])
    active = conn.execute(
        text("SELECT active FROM execbound.user_accounts WHERE account_id=:a"),
        {"a": member["account_id"]},
    ).scalar_one_or_none()
    if not active:
        raise SessionError()


def _directory_required(conn: Connection, tenant: UUID) -> bool:
    """True while any identity provider for the tenant requires sign-in, in any state.

    `validate_workspace_session` (0043) only refuses a browser session when its own credential
    lacks a federated sign-in verified in the last 15 minutes, because a browser can go sign in
    at the directory and come back with one. A token cannot: nothing ever mints a
    `federated_sign_ins` row for a personal access token's credential. So unlike that check,
    this one never looks for a recent sign-in and never looks at the provider's `state` — any
    tenant row with `require_sign_in` true refuses every token outright.
    """
    return bool(
        conn.execute(
            text(
                "SELECT 1 FROM execbound.identity_providers "
                "WHERE tenant_id=:t AND require_sign_in LIMIT 1"
            ),
            {"t": tenant},
        ).scalar_one_or_none()
    )


def check_token_session(conn: Connection, session: TokenSession, clock: Clock) -> None:
    """Recheck a token inside the caller's tenant transaction, as `check_session` does a row.

    `_human` below already refuses when the backing credential is revoked: it derives the
    identity's authority through `policy.store._identity`, whose query requires
    `c.revoked_at IS NULL` for that credential row. No separate credential check is added
    here for that reason alone.
    """
    if session.token_id is None:
        raise SessionError()
    row = _read(conn, session.identity.tenant_id, session.token_id)
    now = _now(clock)
    if (
        row is None
        or row["revoked_at"] is not None
        or row["deleted_at"] is not None
        or not row["created_at"] <= now < row["expires_at"]
        or row["credential_id"] != session.identity.credential_id
        or row["principal_id"] != session.identity.principal_id
        or session.identity.kind != "ADMIN"
    ):
        raise SessionError()
    if _directory_required(conn, session.identity.tenant_id):
        raise SessionError("DIRECTORY_REQUIRED")
    _owner_active(conn, session.identity.tenant_id, session.identity.principal_id)
    _human(conn, session.identity, clock)


def load_token_session(db: Database, token: str, *, clock: Clock | None = None) -> TokenSession:
    """The token's session, or `TokenRefused` classed the way `identity.authenticate` classes
    an `eb1` credential: malformed and unknown name no tenant or subject, so a guessed id adds
    no row to a workspace's failure counters; a mismatch or a refused token is attributed to
    its backing credential, the credential it authenticates as, since the counters' subject
    kinds name no token. `DIRECTORY_REQUIRED` and `SESSION_UNAVAILABLE` are not failed
    sign-ins and stay plain `SessionError`s, as they are for a browser session."""
    clock = clock or SystemClock()
    match = TOKEN.fullmatch(token or "")
    if match is None:
        raise TokenRefused(AuthenticationFailed())
    tenant, token_id = UUID(match[1]), UUID(match[2])
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            row = _read(conn, tenant, token_id)
            stored = row["token_hash"] if row is not None else "0" * 64
            matches = hmac.compare_digest(digest, stored)
            if row is None:
                raise TokenRefused(AuthenticationFailed(reason="UNKNOWN", context_tenant=tenant))
            attributed: dict[str, Any] = {
                "tenant_id": tenant,
                "subject_kind": "credential",
                "subject_id": row["credential_id"],
            }
            if not matches:
                raise TokenRefused(AuthenticationFailed(reason="MISMATCH", **attributed))
            expires_at = conn.execute(
                text(
                    "SELECT expires_at FROM execbound.credentials "
                    "WHERE tenant_id=:t AND credential_id=:c"
                ),
                {"t": tenant, "c": row["credential_id"]},
            ).scalar_one()
            identity = Identity(
                tenant, row["principal_id"], row["credential_id"], "ADMIN", expires_at
            )
            session = TokenSession(identity, token_id, expires_at, "", token_id=token_id)
            now = _now(clock)
            try:
                check_token_session(conn, session, clock)
            except SessionError as exc:
                if exc.code != "INVALID_SESSION":
                    raise
                reason: Reason
                if row["revoked_at"] is not None or row["deleted_at"] is not None:
                    reason = "REVOKED"
                elif not row["created_at"] <= now < row["expires_at"]:
                    reason = "EXPIRED"
                else:
                    # The token stands; its owner lost the membership, the account, the
                    # administrator role or the backing credential.
                    reason = "INACTIVE"
                raise TokenRefused(AuthenticationFailed(reason=reason, **attributed)) from None
            if row["last_used_at"] is None or now - row["last_used_at"] >= timedelta(minutes=1):
                conn.execute(
                    text("SELECT execbound.personal_token_used(:k, :n)"),
                    {"k": token_id, "n": now},
                )
        return session
    except SessionError:
        raise
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        raise SessionError("SESSION_UNAVAILABLE") from None


def _person_only(session: Session) -> None:
    if isinstance(session, TokenSession):
        raise TokenError("TOKEN_NOT_ALLOWED")


def _refusal(exc: DBAPIError) -> TokenError:
    message = str(exc.orig) if exc.orig is not None else ""
    for code in _REFUSALS:
        if code in message:
            return TokenError(code)
    return TokenError("UNAVAILABLE")


def issue_token(
    db: Database,
    session: Session,
    name: str,
    lifetime: timedelta | None,
    *,
    clock: Clock | None = None,
) -> tuple[str, dict[str, Any]]:
    """Mint a token for the signed-in administrator; the token string is returned once.

    `lifetime` is the token's own lifetime measured from its own `issued_at`, both read from
    the one clock call below; `None` mints a token that never expires (`NEVER`). A caller must
    not compute `expires_at` itself from a separate clock read: the definer function refuses a
    lifetime under an hour, and two reads a few milliseconds apart (one for `issued_at` here,
    one for a route's own `expires_at`) can fall a hair under a whole-hour request.
    """
    _person_only(session)
    if secret_shaped(name):
        raise TokenError("INVALID_NAME")
    clock = clock or SystemClock()
    identity = session.identity
    token_id, credential_id = uuid4(), uuid4()
    token = f"{TOKEN_PREFIX}.{identity.tenant_id}.{token_id}.{secrets.token_urlsafe(32)}"
    issued_at = _now(clock)
    expires_at = NEVER if lifetime is None else issued_at + lifetime
    stored_name: str | None = None
    owner_label: str | None = None
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            fence(conn, identity.tenant_id, clock)
            # Checked before the acting session is even rechecked: a tenant that requires
            # directory sign-in refuses every new token outright, regardless of whether the
            # browser session asking for one currently still passes its own check (it can go
            # sign in again at the directory; a token it mints never could).
            if _directory_required(conn, identity.tenant_id):
                raise TokenError("DIRECTORY_REQUIRED")
            check_session(conn, session, clock)
            conn.execute(
                text("SELECT execbound.admin_issue_personal_token(:a,:k,:c,:n,:h,:ch,:i,:e)"),
                {
                    "a": identity.principal_id,
                    "k": token_id,
                    "c": credential_id,
                    "n": name,
                    "h": hashlib.sha256(token.encode("ascii")).hexdigest(),
                    "ch": hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
                    "i": issued_at,
                    "e": expires_at,
                },
            )
            # The definer stores `btrim(p_name)`, which strips only whitespace; read the
            # stored value back rather than assume `.strip()` matches it exactly.
            stored_name = conn.execute(
                text(
                    "SELECT name FROM execbound.personal_access_tokens "
                    "WHERE tenant_id=:t AND token_id=:k"
                ),
                {"t": identity.tenant_id, "k": token_id},
            ).scalar_one()
            owner_label = conn.execute(
                text(
                    "SELECT label FROM execbound.principals WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": identity.tenant_id, "p": identity.principal_id},
            ).scalar_one()
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "personal_token.issued",
                {
                    "token_id": str(token_id),
                    # The backing credential and the name together: every event the token
                    # causes names this credential, and this event still maps it to the
                    # token's name after the token is deleted and leaves every list.
                    "credential_id": str(credential_id),
                    "name": stored_name,
                    **acted_with(identity.credential_id),
                    "expires_at": expires_at.isoformat(),
                },
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise TokenError("UNAVAILABLE") from None
    view = {
        "token_id": str(token_id),
        "credential_id": str(credential_id),
        "name": stored_name,
        "owner_id": str(identity.principal_id),
        "owner_label": owner_label,
        "created_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "last_used_at": None,
        "state": "live",
    }
    return token, view


def _change(
    db: Database, session: Session, token_id: UUID, function: str, kind: str, clock: Clock | None
) -> None:
    _person_only(session)
    clock = clock or SystemClock()
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            fence(conn, identity.tenant_id, clock)
            check_session(conn, session, clock)
            conn.execute(
                text(f"SELECT execbound.{function}(:a, :k, :n)"),
                {"a": identity.principal_id, "k": token_id, "n": _now(clock)},
            )
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                kind,
                {"token_id": str(token_id), **acted_with(identity.credential_id)},
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise TokenError("UNAVAILABLE") from None


def revoke_token(
    db: Database, session: Session, token_id: UUID, *, clock: Clock | None = None
) -> None:
    _change(db, session, token_id, "admin_revoke_personal_token", "personal_token.revoked", clock)


def delete_token(
    db: Database, session: Session, token_id: UUID, *, clock: Clock | None = None
) -> None:
    _change(db, session, token_id, "admin_delete_personal_token", "personal_token.deleted", clock)


def _owners(conn: Connection, session: Session, alias: str, everyone: bool) -> SpaceFilter:
    """Whose tokens the workspace's list reaches: the reader's own, and since 0072, for an
    administrator narrowed to spaces, those of the people they may administer, as the
    functions that revoke and delete a token ask it. ``alias`` is the owner's principal row."""
    if not everyone:
        return NO_SPACE_FILTER
    people = administered_clause(conn, session, alias)
    if not people.sql:
        return people
    return SpaceFilter(f" AND ({alias}.principal_id = :p OR (true{people.sql}))", people.params)


def list_tokens(
    db: Database, session: Session, *, everyone: bool, clock: Clock | None = None
) -> list[dict[str, Any]]:
    """The owner's tokens, or every token in the workspace; never a digest or a secret.

    Each row names its backing credential, the `actor_credential_id` every event the token
    caused carries, so the list is how an event maps to the token's name. At most 200 rows.

    Deactivation, a password reset and a promotion revoke every credential a principal
    holds without touching `personal_access_tokens` (0036, 0040, 0047), so a token row can
    stay live here while its backing credential is dead. `execbound.credentials` is joined
    so a token is reported `revoked` when either its own `revoked_at` or its backing
    credential's `revoked_at` is set.
    """
    _person_only(session)
    clock = clock or SystemClock()
    identity = session.identity
    now = _now(clock)
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            check_session(conn, session, clock)
            if (
                everyone
                and access.effective_kind(conn, identity.tenant_id, identity.principal_id)
                != "ADMIN"
            ):
                raise TokenError("INVALID_ACTOR")
            owners = _owners(conn, session, "p", everyone)
            rows = conn.execute(
                text(
                    "SELECT k.token_id, k.credential_id, k.name, k.principal_id, p.label, "
                    "k.created_at, "
                    "k.expires_at, k.revoked_at, k.last_used_at, "
                    "c.revoked_at AS credential_revoked_at "
                    "FROM execbound.personal_access_tokens k "
                    "JOIN execbound.principals p USING (tenant_id, principal_id) "
                    "JOIN execbound.credentials c "
                    "ON c.tenant_id = k.tenant_id AND c.credential_id = k.credential_id "
                    "WHERE k.tenant_id = :t AND k.deleted_at IS NULL "
                    "AND (CAST(:everyone AS boolean) OR k.principal_id = :p) "
                    + owners.sql  # nosec B608 - one helper's predicate; values are bound
                    + " ORDER BY k.created_at DESC, k.token_id LIMIT 200"
                ),
                {
                    "t": identity.tenant_id,
                    "p": identity.principal_id,
                    "everyone": everyone,
                    **owners.params,
                },
            ).mappings()
            result = []
            for row in rows:
                if row["revoked_at"] is not None or row["credential_revoked_at"] is not None:
                    state = "revoked"
                elif row["expires_at"] <= now:
                    state = "expired"
                else:
                    state = "live"
                result.append(
                    {
                        "token_id": str(row["token_id"]),
                        "credential_id": str(row["credential_id"]),
                        "name": row["name"],
                        "owner_id": str(row["principal_id"]),
                        "owner_label": row["label"],
                        "created_at": row["created_at"].isoformat(),
                        "expires_at": row["expires_at"].isoformat(),
                        "last_used_at": row["last_used_at"].isoformat()
                        if row["last_used_at"]
                        else None,
                        "state": state,
                    }
                )
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise TokenError("UNAVAILABLE") from None
    return result


def token_exists(
    db: Database, session: Session, token_id: UUID, *, everyone: bool, clock: Clock | None = None
) -> bool:
    """Whether an undeleted token with this id exists: the caller's own unless `everyone`.

    A targeted single-row lookup, not a scan of `list_tokens`'s (bounded, but larger) result:
    the console API's own-token routes use it before `revoke_token`/`delete_token`, which
    accept any token of the tenant, to answer `NOT_FOUND` for an id that is not the caller's
    (or does not exist at all) before ever calling the store, so a wrong-state refusal from the
    definer function (`CONFLICT`) is never confused with a missing or foreign one.
    """
    _person_only(session)
    clock = clock or SystemClock()
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            check_session(conn, session, clock)
            if (
                everyone
                and access.effective_kind(conn, identity.tenant_id, identity.principal_id)
                != "ADMIN"
            ):
                raise TokenError("INVALID_ACTOR")
            owners = _owners(conn, session, "p", everyone)
            found = conn.execute(
                text(
                    "SELECT 1 FROM execbound.personal_access_tokens k "
                    "JOIN execbound.principals p USING (tenant_id, principal_id) "
                    "WHERE k.tenant_id = :t AND k.token_id = :k AND k.deleted_at IS NULL "
                    "AND (CAST(:everyone AS boolean) OR k.principal_id = :p)" + owners.sql  # nosec B608 - one helper's predicate; values are bound
                ),
                {
                    "t": identity.tenant_id,
                    "k": token_id,
                    "p": identity.principal_id,
                    "everyone": everyone,
                    **owners.params,
                },
            ).scalar_one_or_none()
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise TokenError("UNAVAILABLE") from None
    return found is not None
