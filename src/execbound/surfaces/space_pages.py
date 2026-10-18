# SPDX-License-Identifier: AGPL-3.0-only
"""The reads and the changes the Spaces area is built on.

Every function here opens the same fenced tenant transaction every other surface opens,
rechecks the identity and the session inside it, and computes the visible set from
`space_members` and `principals.kind` (`spaces.visible_spaces`) rather than trusting the
session's column. Nothing here is a new authority: a change is one definer function's
refusal or its audit event, and a read is one bounded statement over rows the visible set
already allows.

Archiving takes the tenant fence before it calls the definer function, so an archive and a
decision on an approval of the same space are totally ordered on the row they already
serialize on and exactly one of the two commits.
"""

from collections.abc import Callable
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.execution import store
from execbound.runtime import Runtime
from execbound.spaces import (
    MAX_DETAIL_LENGTH,
    MAX_NAME_LENGTH,
    SpaceError,
    Visibility,
    archive_space,
    assign_member,
    create_space,
    rename_space,
    unarchive_space,
    unassign_member,
    visible_spaces,
)
from execbound.surfaces.sessions import Session, check_session

PAGE_SIZE = 50
MAX_QUERY_LENGTH = 80
STATES = ("active", "archived", "all")

# One bounded statement for the list, with the visible set as a bound array and the state
# and the search as bound parameters. `all_spaces` is workspace-wide read access, which sees
# every space of the tenant; anyone else sees the spaces they may read and nothing else.
_LIST = """
SELECT s.space_id, s.name, s.detail, s.created_at, s.archived_at,
       (SELECT count(*) FROM execbound.space_members m
         WHERE m.tenant_id = s.tenant_id AND m.space_id = s.space_id) AS members,
       (SELECT count(*) FROM execbound.principals p
         WHERE p.tenant_id = s.tenant_id AND p.space_id = s.space_id
           AND p.kind = 'AGENT' AND p.active) AS agents,
       (SELECT count(*) FROM execbound.approvals a
         WHERE a.tenant_id = s.tenant_id AND a.space_id = s.space_id
           AND a.state = 'PENDING') AS pending,
       (SELECT count(*) FROM execbound.monitor_findings f
         WHERE f.tenant_id = s.tenant_id AND f.space_id = s.space_id
           AND f.acknowledged_at IS NULL) AS findings
  FROM execbound.spaces s
 WHERE s.tenant_id = :t
   AND (CAST(:only AS uuid) IS NULL OR s.space_id = :only)
   AND (:all_spaces OR s.space_id = ANY(CAST(:visible AS uuid[])))
   AND (:state = 'all'
        OR (:state = 'active' AND s.archived_at IS NULL)
        OR (:state = 'archived' AND s.archived_at IS NOT NULL))
   AND (CAST(:q AS text) IS NULL OR s.name ILIKE '%%' || :q || '%%')
   AND (CAST(:cursor_name AS text) IS NULL
        OR (lower(s.name), s.space_id) > (CAST(:cursor_name AS text), CAST(:cursor_id AS uuid)))
 ORDER BY lower(s.name), s.space_id
 LIMIT :limit
"""


def _guard(conn: Connection, runtime: Runtime, session: Session, *, admin: bool = False) -> None:
    kind = session.identity.kind
    if admin and kind != "ADMIN":
        raise SpaceError("INVALID_ACTOR")
    store.identity_check(conn, session.identity, runtime.clock, kind)
    check_session(conn, session, runtime.clock)


def _bounded(value: str | None, limit: int, code: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not 1 <= len(value.strip()) <= limit:
        raise SpaceError(code)
    return value.strip()


def spaces_overview(
    runtime: Runtime,
    session: Session,
    *,
    query: str | None = None,
    state: str = "active",
    cursor: tuple[str, UUID] | None = None,
    limit: int = PAGE_SIZE,
) -> dict[str, Any]:
    """The person's visible spaces with the counts the switcher shows, one page at a time."""
    if state not in STATES:
        raise SpaceError("INVALID_SPACE")
    query = _bounded(query, MAX_QUERY_LENGTH, "INVALID_NAME")
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _guard(conn, runtime, session)
        visibility = visible_spaces(conn, session)
        rows = (
            conn.execute(
                text(_LIST),
                {
                    "t": identity.tenant_id,
                    "all_spaces": visibility.everything,
                    "visible": [str(space) for space in visibility.spaces],
                    "state": state,
                    "q": query,
                    "only": None,
                    "cursor_name": cursor[0] if cursor else None,
                    "cursor_id": cursor[1] if cursor else None,
                    "limit": min(max(int(limit), 1), PAGE_SIZE + 1),
                },
            )
            .mappings()
            .all()
        )
        visible = (
            conn.execute(
                text("SELECT count(*) FROM execbound.spaces WHERE tenant_id=:t"),
                {"t": identity.tenant_id},
            ).scalar_one()
            if visibility.everything
            else len(visibility.spaces)
        )
        _guard(conn, runtime, session)
    return {
        "spaces": [dict(row) for row in rows],
        "visibility": visibility,
        "visible": int(visible),
        "administrator": visibility.everything and identity.kind == "ADMIN",
    }


def space_overview(runtime: Runtime, session: Session, space: UUID) -> dict[str, Any]:
    """One space with its members, its selection, its counts and its offered objects.

    A space outside the reader's visible set is `NOT_FOUND` alike, whether it is unknown,
    another tenant's or one they do not belong to.
    """
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _guard(conn, runtime, session)
        visibility = visible_spaces(conn, session)
        if not visibility.allows(space):
            raise SpaceError("INVALID_SPACE")
        found = (
            conn.execute(
                text(_LIST),
                {
                    "t": identity.tenant_id,
                    "all_spaces": visibility.everything,
                    "visible": [str(item) for item in visibility.spaces],
                    "state": "all",
                    "q": None,
                    "only": space,
                    "cursor_name": None,
                    "cursor_id": None,
                    "limit": 1,
                },
            )
            .mappings()
            .one_or_none()
        )
        if found is None:
            raise SpaceError("INVALID_SPACE")
        # A member is named by their label, else their email, else their number (0062). The
        # email reaches only an administrator, the person People already shows it to: the
        # identity's kind is its effective kind, which `_guard` has just proven inside this
        # transaction, the same check People makes. It is never `visibility.everything`,
        # which is workspace-wide read access and which a Viewer, Approver or Policy manager
        # granted at Workspace scope holds too. Anyone else gets the number instead.
        shows_email = identity.kind == "ADMIN"
        members = [
            dict(item)
            for item in conn.execute(
                text(
                    "SELECT m.principal_id, m.role, m.assigned_at, p.label, "
                    "CASE WHEN CAST(:administrator AS boolean) THEN p.email END AS email, "
                    "p.number, p.kind "
                    "FROM execbound.space_members m "
                    "JOIN execbound.principals p USING (tenant_id, principal_id) "
                    "WHERE m.tenant_id=:t AND m.space_id=:s "
                    "ORDER BY p.label NULLS LAST, m.principal_id LIMIT 500"
                ),
                {"t": identity.tenant_id, "s": space, "administrator": shows_email},
            ).mappings()
        ]
        selection = (
            conn.execute(
                text(
                    "SELECT bundle_id, changed_at FROM execbound.space_policy_selection "
                    "WHERE tenant_id=:t AND space_id=:s"
                ),
                {"t": identity.tenant_id, "s": space},
            )
            .mappings()
            .one_or_none()
        )
        offered = [
            dict(item)
            for item in conn.execute(
                text(
                    "SELECT 'connector_account' AS kind, account_id AS object_id, "
                    "provider AS label "
                    "FROM execbound.connector_accounts "
                    "WHERE tenant_id=:t AND space_id=:s AND offered_tenant_wide "
                    "UNION ALL "
                    "SELECT 'policy_bundle', bundle_id, content_hash "
                    "FROM execbound.policy_bundle_contents "
                    "WHERE tenant_id=:t AND space_id=:s AND offered_tenant_wide "
                    "ORDER BY 1, 2 LIMIT 200"
                ),
                {"t": identity.tenant_id, "s": space},
            ).mappings()
        ]
        _guard(conn, runtime, session)
    return {
        "space": dict(found),
        "members": members,
        "selection": dict(selection) if selection is not None else None,
        "offered": offered,
        "administrator": visibility.everything,
    }


# One space change: the connection, the tenant, the acting principal and the credential it
# acted with, which the change's event names.
SpaceChange = Callable[[Connection, UUID, UUID, UUID], None]


def _change(runtime: Runtime, session: Session, action: SpaceChange) -> None:
    """One space administration act, fenced and audited in the caller's transaction.

    The act is handed the session's credential as well as its principal, so its event names
    the credential that acted: a browser session's own, or a personal access token's backing
    credential, which is how the token list attributes the event to the token."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _guard(conn, runtime, session, admin=True)
        # The tenant fence, so an archive is ordered against every decision that reads a
        # space under it. The lock order is unchanged: tenant control, then audit head.
        store.fence(conn, identity.tenant_id, runtime.clock)
        _guard(conn, runtime, session, admin=True)
        action(conn, identity.tenant_id, identity.principal_id, identity.credential_id)
        _guard(conn, runtime, session, admin=True)


def create(runtime: Runtime, session: Session, name: str, detail: str | None) -> UUID:
    name = _bounded(name, MAX_NAME_LENGTH, "INVALID_NAME") or ""
    detail = _bounded(detail, MAX_DETAIL_LENGTH, "INVALID_NAME") if detail else None
    created: dict[str, UUID] = {}

    def action(conn: Connection, tenant: UUID, actor: UUID, credential: UUID) -> None:
        created["space"] = create_space(conn, tenant, actor, name, detail, credential=credential)

    _change(runtime, session, action)
    return created["space"]


def rename(runtime: Runtime, session: Session, space: UUID, name: str, detail: str | None) -> None:
    name = _bounded(name, MAX_NAME_LENGTH, "INVALID_NAME") or ""
    detail = _bounded(detail, MAX_DETAIL_LENGTH, "INVALID_NAME") if detail else None
    _change(
        runtime,
        session,
        lambda conn, tenant, actor, credential: rename_space(
            conn, tenant, actor, space, name, detail, credential=credential
        ),
    )


def archive(runtime: Runtime, session: Session, space: UUID, reason: str) -> None:
    _change(
        runtime,
        session,
        lambda conn, tenant, actor, credential: archive_space(
            conn, tenant, actor, space, reason, credential=credential
        ),
    )


def unarchive(runtime: Runtime, session: Session, space: UUID, reason: str) -> None:
    _change(
        runtime,
        session,
        lambda conn, tenant, actor, credential: unarchive_space(
            conn, tenant, actor, space, reason, credential=credential
        ),
    )


def assign(runtime: Runtime, session: Session, space: UUID, principal: UUID, role: str) -> None:
    _change(
        runtime,
        session,
        lambda conn, tenant, actor, credential: assign_member(
            conn, tenant, actor, space, principal, role, credential=credential
        ),
    )


def unassign(runtime: Runtime, session: Session, space: UUID, principal: UUID) -> None:
    _change(
        runtime,
        session,
        lambda conn, tenant, actor, credential: unassign_member(
            conn, tenant, actor, space, principal, credential=credential
        ),
    )


def current_visibility(runtime: Runtime, session: Session) -> Visibility:
    """The visible set for a surface that only needs to know what the person may see."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _guard(conn, runtime, session)
        return visible_spaces(conn, session)
