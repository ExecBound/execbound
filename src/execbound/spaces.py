# SPDX-License-Identifier: AGPL-3.0-only
"""Spaces: ownership and view inside one tenant, and the one place a filter is built.

A space is **a column plus a membership check**, never a second fence. Forced row-level
security is a second line of defence for tenants and there is **no second line for spaces**:
a store function that forgets its tenant predicate returns nothing because the database
refuses it, and one that forgets its **space** predicate returns another customer's rows.
That asymmetry is why every space-filtered read takes its predicate from `space_clause` over
one visible set computed by `visible_spaces`, and why no store function writes its own.

Membership is the authority and the current space is a view: every read recomputes the
visible set inside the already-open fenced transaction, from `space_members` and
`principals.kind`, so a person removed from a space between two page loads loses it at once
and a stale session column grants nothing.

Nothing a caller sends names a space. An agent's space is read from its own principal row; a
person's is read from their memberships; the one console mutation that names one verifies it
against membership inside the database, and so does every read made with a personal access
token whose request names one (`X-ExecBound-Space`).

Every space change takes `credential`, keyword-only and with no default, and its event names
it (`audit.acted_with`): the console passes its session's credential, and an owner command,
which acts with none, passes `None` in so many words. A caller cannot leave attribution out
by forgetting an argument.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from execbound.audit import acted_with, append_event
from execbound.secrets import secret_shaped

DEFAULT_SPACE_NAME = "Default"
MAX_NAME_LENGTH = 80
MAX_DETAIL_LENGTH = 160
MAX_REASON_LENGTH = 500
SPACE_ROLES = frozenset({"ADMIN", "HUMAN_APPROVER"})
# Every code the six definer functions raise. Anything else is an unavailable store, so a
# database diagnostic never reaches a page or a client.
CODES = frozenset(
    {
        "INVALID_TENANT",
        "INVALID_ACTOR",
        "INVALID_NAME",
        "NAME_TAKEN",
        "INVALID_SPACE",
        "INVALID_PRINCIPAL",
        "INVALID_ROLE",
        "LAST_TENANT_ADMIN",
        "SPACE_ARCHIVED",
        "INVALID_SESSION",
        "CONFLICT",
    }
)


class SpaceError(ValueError):
    """Safe code only; a definer function's diagnostics never escape."""

    def __init__(self, code: str = "SPACE_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Space unavailable")


@dataclass(frozen=True)
class Visibility:
    """What one person may see, and which part of it they are looking at.

    ``everything`` is workspace-wide read access, ``console.read`` with no Space scope
    (`access_visibility`). A tenant administrator holds it (an active ``ADMIN`` principal
    with no row in ``space_members``), and since 0047 so does any managed person granted a
    role at Workspace scope: a Viewer, an Approver or a Policy manager as much as an
    Administrator. It is read access and never administration; whether a person is an
    administrator is their identity's effective kind, which is what People checks. Anyone
    else sees the spaces they may read and nothing else, whatever their kind. ``current`` is
    the session's chosen space narrowed to that set, so a space the person has been removed
    from falls back to "All spaces" on the next read rather than granting one.
    """

    everything: bool
    spaces: tuple[UUID, ...]
    current: UUID | None
    roles: dict[UUID, str]

    @property
    def unfiltered(self) -> bool:
        """A workspace-wide reader looking at every space contributes no predicate at all.

        A tenant that never made a second space therefore runs exactly the query plans it
        ran before spaces existed.
        """
        return self.everything and self.current is None

    def allows_many(self, tenant_spaces: int) -> bool:
        """Whether this person's visible set holds more than one space.

        A workspace-wide reader's set is the tenant's, so it takes the tenant's count;
        anyone else's is the spaces they may read. "All spaces" is offered to anyone whose set has
        more than one, and a search row names its space on the same condition.
        """
        return tenant_spaces > 1 if self.everything else len(self.spaces) > 1

    def allows(self, space: UUID | None) -> bool:
        """Whether this person may read a row owned by that space at all.

        Membership is the authority and the current space is only a view, so a record in
        another of the person's own spaces is allowed here and a record in a space they do
        not belong to never is.
        """
        if space is None:
            return True
        return self.everything or space in self.spaces

    def whole(self) -> "Visibility":
        """The same visible set with no current space; what one named record is read under.

        A list is filtered by the space the person is looking at; a **single record named
        by its own identifier** is authorised by membership and answered whatever the
        session holds, so an approval link opens the approval and the shell follows it into
        the space that owns it. The bound is unchanged: a record in a space the person does
        not belong to is still not in this set.
        """
        if self.current is None:
            return self
        return Visibility(
            everything=self.everything, spaces=self.spaces, current=None, roles=self.roles
        )


@dataclass(frozen=True)
class SpaceFilter:
    """One `AND` and its bound parameters; a caller adds both and builds nothing itself."""

    sql: str
    params: dict[str, Any]


def space_clause(
    visibility: Visibility,
    alias: str,
    *,
    offered: bool = False,
    unowned: bool = False,
    column: str = "space_id",
) -> SpaceFilter:
    """The predicate for one alias of one space-carrying table.

    A workspace-wide reader looking at every space gets no predicate; a chosen space gets
    equality; a member's "All spaces" gets membership of their own set. ``offered`` adds
    the tenant-wide offer of a table that carries one, which is usable by every space of
    the tenant and owned, still, by one. ``unowned`` adds the rows no space owns, for the
    one table whose space is optional: a principal's is null for a person, who is a member
    of spaces and owned by none, so every view lists people and only an agent is filtered.

    The alias and the column are the caller's own literals and never a request value; the
    space and the set are bound parameters.
    """
    if visibility.unfiltered:
        return SpaceFilter("", {})
    offer = f" OR {alias}.offered_tenant_wide" if offered else ""
    if unowned:
        offer += f" OR {alias}.{column} IS NULL"
    if visibility.current is not None:
        return SpaceFilter(
            f" AND ({alias}.{column} = :space_filter{offer})",
            {"space_filter": visibility.current},
        )
    return SpaceFilter(
        f" AND ({alias}.{column} = ANY(CAST(:space_set AS uuid[])){offer})",
        {"space_set": [str(space) for space in visibility.spaces]},
    )


# A workspace-wide reader looking at every space contributes no predicate at all, so a
# caller that has not computed a visible set yet uses this and runs the plans it always ran.
NO_SPACE_FILTER = SpaceFilter("", {})

# Whom an administrator narrowed to spaces administers, as the definer functions ask it since
# `0072_space_principal_scope`. `{a}` is the caller's alias of `principals`; the administrator
# is bound. An agent is theirs when its space is one where their membership is `ADMIN`. A
# person is theirs when they are seated in at least one space, every space they are seated in
# is one of those, and no role from the access model reaches them: a managed person's reach is
# their roles rather than their seats, and a group's grants reach its members, and only a
# workspace administrator changes either. Every membership is read in the statement itself.
_ADMINISTERED_AGENT = (
    "EXISTS (SELECT 1 FROM execbound.space_members am "
    "WHERE am.tenant_id = {a}.tenant_id AND am.principal_id = :space_administrator "
    "AND am.space_id = {a}.space_id AND am.role = 'ADMIN')"
)
_ADMINISTERED_PERSON = (
    "EXISTS (SELECT 1 FROM execbound.space_members ts "
    "WHERE ts.tenant_id = {a}.tenant_id AND ts.principal_id = {a}.principal_id) "
    "AND NOT EXISTS (SELECT 1 FROM execbound.space_members ts "
    "WHERE ts.tenant_id = {a}.tenant_id AND ts.principal_id = {a}.principal_id "
    "AND NOT EXISTS (SELECT 1 FROM execbound.space_members am "
    "WHERE am.tenant_id = ts.tenant_id AND am.principal_id = :space_administrator "
    "AND am.space_id = ts.space_id AND am.role = 'ADMIN')) "
    "AND NOT EXISTS (SELECT 1 FROM execbound.access_principals ap "
    "WHERE ap.tenant_id = {a}.tenant_id AND ap.principal_id = {a}.principal_id) "
    "AND NOT EXISTS (SELECT 1 FROM execbound.access_group_members gm "
    "WHERE gm.tenant_id = {a}.tenant_id AND gm.principal_id = {a}.principal_id)"
)


def administered_clause(
    conn: Connection, session: Any, alias: str, *, agents: bool = True
) -> SpaceFilter:
    """The principals this administrator may administer, as one predicate on ``alias``.

    The visible set answers what a person may read; this answers what an administrator may
    change, and the two differ: an administrator seated as an approver in another space reads
    that space's agents and administers none of them, and a person is read in every view and
    administered only inside the administrator's spaces. It is the rule the definer functions
    apply since `0072_space_principal_scope`, so a page never offers a change the database
    refuses, and it stays here, beside `space_clause`, so no store function writes its own.

    A workspace administrator (workspace-wide ``access.manage``) contributes no predicate.
    ``agents=False`` leaves agents to the caller's own `space_clause`, which lists them by
    the visible set, and narrows only the people.
    """
    from execbound.access_control import has_permission

    identity = session.identity
    if has_permission(conn, identity.tenant_id, identity.principal_id, "access.manage"):
        return NO_SPACE_FILTER
    agent = _ADMINISTERED_AGENT if agents else "{a}.space_id IS NOT NULL"
    predicate = f" AND (({agent}) OR ({{a}}.space_id IS NULL AND {_ADMINISTERED_PERSON}))"
    return SpaceFilter(predicate.format(a=alias), {"space_administrator": identity.principal_id})


# An administrator narrowed to spaces, in the definer functions' own words since
# `0047_access_control`: no workspace-wide `access.manage`, and a membership of any space.
_NARROWED = (
    "SELECT NOT execbound.access_has_permission(:p, 'access.manage', NULL, false) "
    "AND EXISTS (SELECT 1 FROM execbound.space_members m "
    "WHERE m.tenant_id = :t AND m.principal_id = :p)"
)


def narrowed(conn: Connection, tenant: UUID, principal: UUID) -> bool:
    """Whether this person is narrowed to their spaces rather than holding the workspace.

    It is the question `space_create` and the other workspace-wide definer functions ask
    before a change that is the whole workspace's rather than one space's, read in the same
    words, so a page asks it before a write and the function asks it again in its own
    statement. A workspace administrator, or an administrator who holds no membership, is not.
    """
    return bool(conn.execute(text(_NARROWED), {"t": tenant, "p": principal}).scalar_one())


def visible_spaces(conn: Connection, session: Any) -> Visibility:
    """Every space of the tenant for a workspace-wide reader, else the spaces they may read.

    Read inside the already-open fenced transaction, beside `identity_check`, `fence` and
    `check_session`. The current space comes from the session's own row rather than from
    the object the request loaded, so a switch takes effect for every later read and a
    membership removed since the object was loaded drops the space here.

    A personal access token has no session row. Its current space is the one its request
    named, if any, held to the same visibility `session_set_space` holds a browser's choice
    to, here, inside every read: a named space that is not the tenant's or not visible to
    the token's owner is refused as `INVALID_SPACE` rather than widened to "All spaces", so a
    script never writes somewhere it did not name.
    """
    from execbound.access_control import access_visibility
    from execbound.personal_tokens import TokenSession

    identity = session.identity
    if isinstance(session, TokenSession):
        everything, spaces, roles = access_visibility(
            conn, identity.tenant_id, identity.principal_id
        )
        named = session.space_id
        if named is not None and not (
            (everything or named in spaces) and named in tenant_spaces(conn, identity.tenant_id)
        ):
            raise SpaceError("INVALID_SPACE")
        return Visibility(everything=everything, spaces=spaces, current=named, roles=roles)
    params = {"t": identity.tenant_id, "p": identity.principal_id, "s": session.session_id}
    current = conn.execute(
        text(
            "SELECT current_space_id FROM execbound.human_sessions "
            "WHERE tenant_id=:t AND session_id=:s"
        ),
        params,
    ).scalar_one_or_none()
    everything, spaces, roles = access_visibility(conn, identity.tenant_id, identity.principal_id)
    if current is not None and not (everything or current in spaces):
        # A person removed from the space their session holds falls back to "All spaces".
        current = None
    return Visibility(everything=everything, spaces=spaces, current=current, roles=roles)


def tenant_spaces(conn: Connection, tenant: UUID) -> tuple[UUID, ...]:
    """Every space of the tenant, ordered; the whole visible set of a workspace-wide reader."""
    return tuple(
        conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id=:t ORDER BY space_id"),
            {"t": tenant},
        ).scalars()
    )


def agent_space(conn: Connection, tenant: UUID, principal: UUID) -> UUID:
    """The space of an agent principal, read inside the fence from its own row.

    No request field, header or credential attribute names a space; this is the only way an
    agent's space is ever decided.
    """
    space = conn.execute(
        text(
            "SELECT space_id FROM execbound.principals "
            "WHERE tenant_id=:t AND principal_id=:p AND kind='AGENT'"
        ),
        {"t": tenant, "p": principal},
    ).scalar_one_or_none()
    if space is None:
        raise SpaceError("INVALID_SPACE")
    return UUID(str(space))


def principal_allows(conn: Connection, tenant: UUID, principal: UUID, space: UUID) -> bool:
    """Whether one person may act on a row owned by that space, by membership alone.

    The authority is the membership, recomputed inside the fence, not the session's
    column: a person removed from a space between reading a queue and deciding on it is
    refused by this and not by the page. A workspace-wide reader passes for every space: a
    tenant administrator, an active `ADMIN` principal with no membership at all, or since
    0047 a managed person granted any role at Workspace scope.
    """
    from execbound.access_control import has_permission

    return has_permission(conn, tenant, principal, "console.read", space)


def is_archived(conn: Connection, tenant: UUID, space: UUID) -> bool:
    """Whether a space takes no new work. An archived space is still fully readable."""
    return (
        conn.execute(
            text(
                "SELECT archived_at IS NOT NULL FROM execbound.spaces "
                "WHERE tenant_id=:t AND space_id=:s"
            ),
            {"t": tenant, "s": space},
        ).scalar_one_or_none()
        is True
    )


def write_space(conn: Connection, tenant: UUID, visibility: Visibility) -> UUID:
    """The one space a write lands in, or a refusal saying the person has to choose.

    A chosen space is that space. A person whose visible set is exactly one space writes
    there. A workspace-wide reader looking at "All spaces" in a tenant that has exactly one
    writes there, which is what keeps every tenant that never made a second space working
    exactly as it did. Anything else is ambiguous and is refused rather than guessed.
    """
    if visibility.current is not None:
        return visibility.current
    if not visibility.everything:
        if len(visibility.spaces) == 1:
            return visibility.spaces[0]
        raise SpaceError("INVALID_SPACE")
    spaces = tenant_spaces(conn, tenant)
    if len(spaces) == 1:
        return spaces[0]
    raise SpaceError("INVALID_SPACE")


def _call(conn: Connection, statement: str, params: dict[str, Any]) -> Any:
    """Run one space function; a refusal surfaces as its code and nothing else."""
    try:
        return conn.execute(text(statement), params).scalar_one()
    except DBAPIError as exc:
        diagnostic = getattr(exc.orig, "diag", None)
        message = getattr(diagnostic, "message_primary", None)
        raise SpaceError(message if message in CODES else "SPACE_UNAVAILABLE") from None


def _reason(value: str | None) -> str:
    if type(value) is not str or not 1 <= len(value.strip()) <= MAX_REASON_LENGTH:
        raise SpaceError("INVALID_NAME")
    if secret_shaped(value):
        raise SpaceError("INVALID_NAME")
    return value.strip()


def create_space(
    conn: Connection,
    tenant: UUID,
    actor: UUID,
    name: str,
    detail: str | None,
    *,
    credential: UUID | None,
) -> UUID:
    """Create a space and audit it in the caller's transaction, under the tenant's chain."""
    if secret_shaped(name):
        raise SpaceError("INVALID_NAME")
    space = UUID(
        str(
            _call(
                conn,
                "SELECT execbound.space_create(:name, :detail, :actor)",
                {"name": name, "detail": detail, "actor": actor},
            )
        )
    )
    append_event(
        conn,
        tenant,
        actor,
        "space.created",
        {
            "space_id": str(space),
            "name": name.strip(),
            "detail": bool(detail and detail.strip()),
            **acted_with(credential),
        },
        space=space,
    )
    return space


def rename_space(
    conn: Connection,
    tenant: UUID,
    actor: UUID,
    space: UUID,
    name: str,
    detail: str | None,
    *,
    credential: UUID | None,
) -> None:
    if secret_shaped(name):
        raise SpaceError("INVALID_NAME")
    _call(
        conn,
        "SELECT execbound.space_rename(:space, :name, :detail, :actor)",
        {"space": space, "name": name, "detail": detail, "actor": actor},
    )
    append_event(
        conn,
        tenant,
        actor,
        "space.renamed",
        {"space_id": str(space), "name": name.strip(), **acted_with(credential)},
        space=space,
    )


def archive_space(
    conn: Connection,
    tenant: UUID,
    actor: UUID,
    space: UUID,
    reason: str,
    *,
    credential: UUID | None,
) -> None:
    """Stop new work in one space. Nothing is deleted and every row stays readable."""
    reason = _reason(reason)
    _call(
        conn,
        "SELECT execbound.space_archive(:space, :actor)",
        {"space": space, "actor": actor},
    )
    append_event(
        conn,
        tenant,
        actor,
        "space.archived",
        {"space_id": str(space), "reason": reason, **acted_with(credential)},
        space=space,
    )


def unarchive_space(
    conn: Connection,
    tenant: UUID,
    actor: UUID,
    space: UUID,
    reason: str,
    *,
    credential: UUID | None,
) -> None:
    reason = _reason(reason)
    _call(
        conn,
        "SELECT execbound.space_unarchive(:space, :actor)",
        {"space": space, "actor": actor},
    )
    append_event(
        conn,
        tenant,
        actor,
        "space.unarchived",
        {"space_id": str(space), "reason": reason, **acted_with(credential)},
        space=space,
    )


def assign_member(
    conn: Connection,
    tenant: UUID,
    actor: UUID,
    space: UUID,
    principal: UUID,
    role: str,
    *,
    credential: UUID | None,
) -> None:
    """Give one person a role in one space; the role narrows and never raises."""
    if role not in SPACE_ROLES:
        raise SpaceError("INVALID_ROLE")
    _call(
        conn,
        "SELECT execbound.space_assign(:space, :principal, :role, :actor)",
        {"space": space, "principal": principal, "role": role, "actor": actor},
    )
    append_event(
        conn,
        tenant,
        actor,
        "space.member_assigned",
        {
            "space_id": str(space),
            "principal_id": str(principal),
            "role": role,
            **acted_with(credential),
        },
        space=space,
    )


def unassign_member(
    conn: Connection,
    tenant: UUID,
    actor: UUID,
    space: UUID,
    principal: UUID,
    *,
    credential: UUID | None,
) -> None:
    """Remove one membership. The rows it governed keep their space."""
    _call(
        conn,
        "SELECT execbound.space_unassign(:space, :principal, :actor)",
        {"space": space, "principal": principal, "actor": actor},
    )
    append_event(
        conn,
        tenant,
        actor,
        "space.member_unassigned",
        {"space_id": str(space), "principal_id": str(principal), **acted_with(credential)},
        space=space,
    )


def set_current_space(conn: Connection, session: Any, space: UUID | None) -> None:
    """Change the session's current space. Not audited: a view change grants nothing.

    Every read it enables is already bounded by membership and already covered by that
    surface's own events, and one event per switch would flood a chain that has to stay
    small enough to walk backwards.
    """
    _call(
        conn,
        "SELECT execbound.session_set_space(:session, :space)",
        {"session": session.session_id, "space": space},
    )


def provision_default_space(conn: Connection, tenant: UUID, actor: UUID) -> UUID:
    """Give a newly created tenant its one `Default` space, on an owner connection.

    Every tenant has exactly one space from the moment it exists, so every column that
    carries a space has an unambiguous value and the switcher shows one space and stays as
    quiet as the tenant block was before spaces. It is renameable from day one.
    """
    existing = conn.execute(
        text(
            "SELECT space_id FROM execbound.spaces WHERE tenant_id=:t "
            "ORDER BY created_at, space_id LIMIT 1"
        ),
        {"t": tenant},
    ).scalar_one_or_none()
    if existing is not None:
        return UUID(str(existing))
    space = UUID(int=0)
    row = conn.execute(
        text(
            "INSERT INTO execbound.spaces "
            "(tenant_id, space_id, name, detail, created_at, created_by) "
            "VALUES (:t, gen_random_uuid(), :n, NULL, now(), :a) RETURNING space_id"
        ),
        {"t": tenant, "n": DEFAULT_SPACE_NAME, "a": actor},
    ).scalar_one()
    space = UUID(str(row))
    return space


def default_space(conn: Connection, tenant: UUID) -> UUID:
    """The tenant's first space, for a caller that has not been given one to write in.

    Ordered by creation, so a tenant that made a second space still resolves to the one
    every backfilled column names rather than to whichever identifier sorts lower.
    """
    space = conn.execute(
        text(
            "SELECT space_id FROM execbound.spaces WHERE tenant_id=:t "
            "ORDER BY created_at, space_id LIMIT 1"
        ),
        {"t": tenant},
    ).scalar_one_or_none()
    if space is None:
        raise SpaceError("INVALID_SPACE")
    return UUID(str(space))


def space_names(conn: Connection, tenant: UUID) -> dict[UUID, str]:
    """Every space of the tenant by name, as inert text for a page that labels a row."""
    return {
        row[0]: row[1]
        for row in conn.execute(
            text("SELECT space_id, name FROM execbound.spaces WHERE tenant_id=:t"),
            {"t": tenant},
        )
    }


@dataclass(frozen=True)
class SpaceRow:
    space_id: UUID
    name: str
    detail: str | None
    created_at: datetime
    archived_at: datetime | None
    members: int
