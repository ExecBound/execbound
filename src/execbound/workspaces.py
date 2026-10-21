# SPDX-License-Identifier: AGPL-3.0-only
"""Switching an account's session between the workspaces it belongs to."""

import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.db import Database, check_runtime
from execbound.resolution.models import Clock, SystemClock
from execbound.surfaces.sections import place
from execbound.user_accounts import check_account_cookie, lock_account, memberships

if TYPE_CHECKING:
    from execbound.surfaces.sessions import Session, SessionGrant


# At most this many of an account's own waiting approvals are counted per workspace, and at
# most this many workspaces are counted per read; the rest answer `not_counted`.
WAITING_CAP = 100
COUNTED_WORKSPACES = 25

Entry = Literal["open", "factor", "enrol", "directory"]


@contextmanager
def _inside(conn: Connection, tenant: UUID) -> Iterator[None]:
    """Enter one listed tenant's row security for the block, then set the caller's back.

    There is deliberately no `finally`: the setting is transaction-local, an exception fails
    the whole call and rolls its transaction back, and a `set_config` after an SQL error would
    itself raise `InFailedSqlTransaction` and mask the original error.
    """
    original = conn.execute(text("SELECT current_setting('execbound.tenant_id',true)")).scalar_one()
    conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})
    yield
    conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": original or ""})


def carries(conn: Connection, session: "Session", now: datetime) -> bool:
    """Whether a switch from this session now would carry its verification into the
    destination: the session's own `session_assurance` row is for the account's enabled factor
    at its current version and was verified within `mfa.STEP_UP_WINDOW`, by a factor rather
    than a trusted browser (`0101_trusted_browsers`: the destination may forbid trust). The
    same conditions as `account_switch`'s carry read (migrations `0089_assurance_carry` and
    `0101_trusted_browsers`), which a test holds to this. Called under the session's own
    tenant setting: inside another workspace's row security the row is invisible."""
    from execbound.mfa import STEP_UP_WINDOW

    return (
        conn.execute(
            text(
                "SELECT 1 FROM execbound.session_assurance sa "
                "JOIN execbound.user_factors f ON f.account_id=:a "
                "WHERE sa.tenant_id=:t AND sa.session_id=:s AND f.enabled_at IS NOT NULL "
                "AND sa.version=f.version AND sa.verified_at<=:now AND sa.verified_at>:since "
                "AND sa.method<>'trusted'"
            ),
            {
                "a": session.account_id,
                "t": session.identity.tenant_id,
                "s": session.session_id,
                "now": now,
                "since": now - STEP_UP_WINDOW,
            },
        ).first()
        is not None
    )


def entry_proof(
    conn: Connection,
    account: UUID,
    item: dict[str, Any],
    kind: str,
    now: datetime,
    carried: bool = False,
    trusted: bool = False,
) -> Entry:
    """What entering this membership asks beyond the current sign-in.

    It mirrors the session `account_switch` would create there. That session carries the
    current session's verification when `carried` (see `carries`), and so asks for nothing
    more; otherwise it starts without assurance, and a workspace whose second-factor rule
    applies asks for the account's factor, or for one to be set up where the account has none.
    `trusted` is whether this browser's trust applies there (`trusted_browsers.applies`, which
    reads the destination's own allowance): the switch then satisfies the factor with it
    (`trusted_entry`), and entering asks for nothing more, exactly as a carry. A directory
    requirement is never carried or trusted. Any change to what a switch carries or trusts
    must change this function in step. Called inside the tenant.
    """
    from execbound.mfa import requires_mfa

    if item["requires_directory"]:
        return "directory"
    session = {
        "tenant_id": item["tenant_id"],
        "principal_id": item["principal_id"],
        "session_id": None,
        "kind": kind,
        "factor_account_id": account,
    }
    if not requires_mfa(conn, session, now):
        return "open"
    enabled = conn.execute(
        text("SELECT enabled_at IS NOT NULL FROM execbound.user_factors WHERE account_id=:a"),
        {"a": account},
    ).scalar_one_or_none()
    # A carry is honoured only for an account that holds an enabled factor now, as the switch's
    # own read requires: an account without one is sent to set one up whatever `carried` says.
    if (carried or trusted) and enabled:
        return "open"
    return "factor" if enabled else "enrol"


def _waiting(
    conn: Connection, tenant: UUID, principal: UUID, now: datetime
) -> tuple[int, datetime | None]:
    """How many approvals this principal could decide now in this tenant, and the earliest
    deadline floored to the minute: the pending queue's predicate for a fresh session there,
    capped, and nothing else. An execution holds at most one approval, so the read starts from
    the pending approvals' own partial index rather than every execution of the tenant.
    Called inside the tenant."""
    from execbound.access_control import access_visibility
    from execbound.spaces import Visibility, space_clause

    everything, spaces, roles = access_visibility(conn, tenant, principal)
    space = space_clause(Visibility(everything, spaces, None, roles), "e")
    row = (
        conn.execute(
            text(
                "SELECT count(*) AS waiting, date_trunc('minute', min(w.lapse)) AS next_lapse "
                "FROM (SELECT a.expires_at AS lapse FROM execbound.approvals a "
                "JOIN execbound.executions e ON e.tenant_id=a.tenant_id "
                "AND e.execution_id=a.execution_id "
                "WHERE a.tenant_id=:t AND a.state='PENDING' AND a.expires_at > :now "
                "AND e.state='PENDING_APPROVAL' "
                "AND EXISTS (SELECT 1 FROM execbound.effective_approval_scopes s "
                "WHERE s.tenant_id=e.tenant_id AND s.approver_id=:p AND s.active "
                "AND s.canonical_target_id=e.canonical_target_id AND s.space_id=e.space_id "
                "AND s.action=e.frozen -> 'intent' ->> 'action')"
                + space.sql  # nosec B608 - a literal from space_clause; values are bound
                + " ORDER BY a.expires_at LIMIT :cap) w"
            ),
            {**space.params, "t": tenant, "p": principal, "now": now, "cap": WAITING_CAP},
        )
        .mappings()
        .one()
    )
    return int(row["waiting"]), row["next_lapse"]


def list_workspaces(
    db: Database,
    session: "Session",
    token: str,
    *,
    clock: Clock | None = None,
    waiting: bool = False,
    trust: str | None = None,
) -> list[dict[str, Any]]:
    """This account's own workspaces, each with what a session there would be and what
    entering it asks.

    ``trust`` is the browser's trust cookie, when it holds one: a workspace whose factor that
    trust satisfies, in a workspace that allows it, asks for nothing more, since the switch
    applies it (`trusted_entry`).

    With ``waiting``, a workspace other than the current one that asks nothing more to enter
    also carries the number of approvals waiting for this account there and the earliest of
    their deadlines, floored to the minute: a count, never a record. Each is read under that
    tenant's own row security, entered only for a tenant `memberships()` listed; a workspace
    that would ask for more proof is withheld with no count read at all (#678). A workspace a
    switch would enter carrying this session's recent verification asks for no more proof.
    """
    from execbound import trusted_browsers
    from execbound.access_control import workspace_role_ids
    from execbound.surfaces.sessions import check_session

    clock = clock or SystemClock()
    with db.transaction(session.identity.tenant_id) as conn:
        now = clock.now()
        check_account_cookie(conn, session, token, now)
        check_session(conn, session, clock)
        account = session.account_id
        assert account is not None
        # Read once, under this session's own tenant setting, before the loop enters others.
        carried = carries(conn, session, now)
        answer = []
        for index, item in enumerate(memberships(conn, account)):
            tenant, principal = item["tenant_id"], item["principal_id"]
            current = tenant == session.identity.tenant_id
            with _inside(conn, tenant):
                kind = conn.execute(
                    text("SELECT execbound.access_effective_kind(:p)"), {"p": principal}
                ).scalar_one()
                roles = workspace_role_ids(conn, tenant, principal)
                # Read only where it could matter: no cookie, or a carry, needs no read.
                trusted = (
                    bool(trust)
                    and not carried
                    and trusted_browsers.applies(conn, account, tenant, trust, now)
                )
                entry = entry_proof(conn, account, item, kind, now, carried, trusted)
                state, count, lapse = "current" if current else "withheld", None, None
                if not current and entry == "open":
                    if waiting and index < COUNTED_WORKSPACES:
                        state = "counted"
                        count, lapse = _waiting(conn, tenant, principal, now)
                    else:
                        state = "not_counted"
            answer.append(
                {
                    "tenant_id": tenant,
                    "name": item["name"],
                    "current": current,
                    "kind": kind,
                    "roles": roles,
                    "entry": entry,
                    "waiting_state": state,
                    "waiting": count,
                    "next_lapse": lapse if count else None,
                    # The account's own record of when it last entered this workspace, read
                    # from its membership outside the workspace's row security.
                    "last_entered_at": item["last_entered_at"],
                }
            )
        return answer


def switch_workspace(
    db: Database,
    session: "Session",
    token: str,
    destination: UUID,
    *,
    section: str | None = None,
    clock: Clock | None = None,
) -> "SessionGrant":
    """Rotate this account's session into another of its workspaces.

    ``section`` is the console section the person was on; the grant's ``place`` is that
    section when the new session may open it, and the session's own start otherwise, read
    with the destination's permissions inside the same transaction.
    """
    from execbound.access_control import capabilities
    from execbound.audit import append_event
    from execbound.execution.store import fence
    from execbound.surfaces.sessions import (
        SessionError,
        SessionGrant,
        _hash,
        _read,
        _validated,
        check_session,
    )

    clock = clock or SystemClock()
    next_id, credential = uuid4(), uuid4()
    next_token = f"hs1.{destination}.{next_id}.{secrets.token_urlsafe(32)}"
    csrf = secrets.token_urlsafe(32)
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            check_runtime(conn)
            check_account_cookie(conn, session, token, clock.now())
            assert session.account_id is not None
            lock_account(conn, session.account_id)
            check_session(conn, session, clock)
            available = memberships(conn, session.account_id)
            if destination not in {item["tenant_id"] for item in available}:
                raise SessionError()
            for tenant in sorted({session.identity.tenant_id, destination}):
                conn.execute(
                    text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)}
                )
                fence(conn, tenant, clock)
            conn.execute(
                text("SELECT set_config('execbound.tenant_id',:t,true)"),
                {"t": str(session.identity.tenant_id)},
            )
            check_session(conn, session, clock)
            switched = conn.execute(
                text(
                    "SELECT execbound.account_switch(:previous,:destination,:next,"
                    ":credential,:token,:csrf,:credential_hash,:now)"
                ),
                {
                    "previous": session.session_id,
                    "destination": destination,
                    "next": next_id,
                    "credential": credential,
                    "token": _hash(next_token),
                    "csrf": _hash(csrf),
                    "credential_hash": _hash(secrets.token_urlsafe(32)),
                    "now": clock.now(),
                },
            ).scalar_one()
            selected = _validated(
                conn, _read(conn, destination, next_id), clock, allow_pending_mfa=True
            )
            append_event(
                conn,
                destination,
                selected.identity.principal_id,
                "workspace.entered",
                {"session_id": str(next_id)},
            )
            if switched["assurance_carried"]:
                # The destination's own record of the carry: this session, the account sign-in
                # it belongs to (already on this session's row), and when and how the factor
                # was verified. The workspace it came from is recorded for the account alone,
                # in `user_security_events`, never in this chain.
                verified_at = datetime.fromisoformat(switched["carried_verified_at"])
                append_event(
                    conn,
                    destination,
                    selected.identity.principal_id,
                    "account_security.assurance_carried",
                    {
                        "session_id": str(next_id),
                        "account_session_id": str(session.account_session_id),
                        "method": switched["carried_method"],
                        "verified_at": verified_at.astimezone(UTC).isoformat(
                            timespec="microseconds"
                        ),
                    },
                )
            permissions = capabilities(conn, destination, selected.identity.principal_id)[
                "permissions"
            ]
            return SessionGrant(
                selected.identity,
                next_id,
                selected.expires_at,
                next_token,
                csrf,
                selected.mfa_required,
                account_bound=True,
                place=place(selected.identity.kind, permissions, section),
            )
    except SQLAlchemyError:
        raise SessionError("SESSION_UNAVAILABLE") from None


def trusted_entry(
    db: Database, grant: "SessionGrant", cookie: str | None, *, clock: Clock | None = None
) -> "SessionGrant":
    """A switch's grant with the destination's factor satisfied by this browser's trust (#859).

    A switch whose new session still owes the factor, on a browser holding a trust the
    destination honours, goes straight on, as `GET /mfa` would take it there:
    `trusted_browsers.apply` writes the session's assurance with method `trusted` and the
    trust's own verification time, never now, and rotates its token and CSRF. The answer keeps
    the switch's `place`. A missing cookie, one that does not apply there, or a refusal leaves
    the grant as it was, and the person is asked for the code at `/mfa` as before; a step-up in
    the destination still asks, since a trusted assurance is never fresh. The trust is applied
    in a transaction of its own after the switch has committed, so a failure here fails safe:
    the new session simply still owes its factor and the answer is `/mfa`."""
    from dataclasses import replace

    from execbound import trusted_browsers
    from execbound.logging_schema import log_event
    from execbound.mfa import MfaError
    from execbound.surfaces.sessions import SessionError, load_session

    if not cookie or not grant.mfa_required:
        return grant
    clock = clock or SystemClock()
    try:
        pending = load_session(db, grant.token, clock=clock, allow_pending_mfa=True)
        applied = trusted_browsers.apply(db, pending, cookie, clock=clock)
    except (MfaError, SessionError) as exc:
        log_event("trusted_browser.refused", level="WARNING", code=exc.code, method="trusted")
        return grant
    if applied is None:
        return grant
    return replace(applied, place=grant.place)
