# SPDX-License-Identifier: AGPL-3.0-only
"""Current human authorization; roles never grant an agent action or a review scope.

An explicit user-role replacement takes the person out of legacy compatibility. Group
membership is additive: an existing account keeps its legacy access until that deliberate
replacement. A managed account with no remaining grants never falls back to its old kind.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from execbound.audit import append_event
from execbound.secrets import secret_shaped

if TYPE_CHECKING:
    from execbound.runtime import Runtime
    from execbound.surfaces.sessions import Session

PERMISSIONS = (
    "console.read",
    "policy.manage",
    "approvals.decide",
    "access.manage",
    "workspace.manage",
)
ROLES: tuple[dict[str, Any], ...] = (
    {
        "id": "administrator",
        "name": "Administrator",
        "description": "Manage users, groups, credentials, workspace settings and policy.",
        "permissions": ["console.read", "policy.manage", "access.manage", "workspace.manage"],
        "scopes": ["WORKSPACE"],
    },
    {
        "id": "policy_manager",
        "name": "Policy manager",
        "description": "Create, validate, preview and activate policy in assigned Spaces.",
        "permissions": ["console.read", "policy.manage"],
        "scopes": ["WORKSPACE", "SPACE"],
    },
    {
        "id": "approver",
        "name": "Approver",
        "description": "Review requests covered by a separate approval assignment.",
        "permissions": ["console.read", "approvals.decide"],
        "scopes": ["WORKSPACE", "SPACE"],
    },
    {
        "id": "viewer",
        "name": "Viewer",
        "description": "Read activity in assigned Spaces.",
        "permissions": ["console.read"],
        "scopes": ["WORKSPACE", "SPACE"],
    },
)
CODES = frozenset(
    {
        "FORBIDDEN",
        "INVALID_TENANT",
        "NOT_FOUND",
        "INVALID_PRINCIPAL",
        "INVALID_NAME",
        "INVALID_MEMBERS",
        "INVALID_ROLES",
        "INVALID_ROLE",
        "INVALID_ROLE_SCOPE",
        "INVALID_SPACE",
        "LAST_ADMINISTRATOR",
        "CONFLICT",
        "GROUP_IN_USE",
        "INVALID_OPERATION",
        "INVALID_REASON",
    }
)


class AccessError(ValueError):
    def __init__(self, code: str = "ACCESS_UNAVAILABLE") -> None:
        self.code = code
        super().__init__(code)


def is_managed(conn: Connection, tenant: UUID, principal: UUID) -> bool:
    return (
        conn.execute(
            text(
                "SELECT 1 FROM execbound.access_principals WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "p": principal},
        ).scalar_one_or_none()
        is not None
    )


def has_permission(
    conn: Connection,
    tenant: UUID,
    principal: UUID,
    permission: str,
    space: UUID | None = None,
    *,
    any_scope: bool = False,
) -> bool:
    if permission not in PERMISSIONS:
        return False
    return (
        conn.execute(
            text(
                "SELECT execbound.access_has_permission(:p,:permission,:s,:a) "
                "AND current_setting('execbound.tenant_id',true)=:t"
            ),
            {
                "p": principal,
                "permission": permission,
                "s": space,
                "a": any_scope,
                "t": str(tenant),
            },
        ).scalar_one()
        is True
    )


def effective_kind(conn: Connection, tenant: UUID, principal: UUID) -> str:
    value = conn.execute(
        text(
            "SELECT execbound.access_effective_kind(:p) "
            "WHERE current_setting('execbound.tenant_id',true)=:t"
        ),
        {"p": principal, "t": str(tenant)},
    ).scalar_one_or_none()
    return str(value) if value is not None else ""


def review_scoped(conn: Connection, identity: Any) -> bool:
    """Legacy reviewers retain their narrow queue; managed people read allowed Spaces."""
    if identity.kind != "HUMAN_APPROVER" or is_managed(
        conn, identity.tenant_id, identity.principal_id
    ):
        return False
    return not any(
        grant["space_id"] is None
        for grant in _grants(conn, identity.tenant_id, identity.principal_id)
    )


def review_read_spaces(conn: Connection, identity: Any) -> tuple[UUID, ...]:
    """Spaces explicitly granted broad reads, without widening legacy memberships."""
    return tuple(
        sorted(
            {
                grant["space_id"]
                for grant in _grants(conn, identity.tenant_id, identity.principal_id)
                if grant["space_id"] is not None
            }
        )
    )


def owner_authority_fence(conn: Connection, tenant: UUID) -> None:
    """Order recovery changes with role changes, without creating a missing tenant."""
    conn.execute(
        text(
            "INSERT INTO execbound.tenant_policy_control(tenant_id,changed_at) "
            "SELECT tenant_id,now() FROM execbound.tenants WHERE tenant_id=:t "
            "ON CONFLICT(tenant_id) DO NOTHING"
        ),
        {"t": tenant},
    )
    conn.execute(
        text("SELECT 1 FROM execbound.tenant_policy_control WHERE tenant_id=:t FOR UPDATE"),
        {"t": tenant},
    )


def owner_administrator(conn: Connection, tenant: UUID, principal: UUID) -> bool:
    """Current owner-operation actor, including an inactive tenant being restored.

    This helper is restricted to the table owner. Runtime authorization always uses
    access_has_permission, which also requires the tenant itself to be active.
    """
    return (
        conn.execute(
            text("""
            SELECT EXISTS(SELECT 1 FROM execbound.principals p
                WHERE p.tenant_id=:t AND p.principal_id=:p AND p.active
                AND p.kind IN ('ADMIN','HUMAN_APPROVER')
                AND current_user=(SELECT tableowner FROM pg_tables
                    WHERE schemaname='execbound' AND tablename='tenants')
                AND ((p.kind='ADMIN' AND NOT EXISTS(
                    SELECT 1 FROM execbound.access_principals a
                    WHERE a.tenant_id=p.tenant_id AND a.principal_id=p.principal_id)
                    AND NOT EXISTS(SELECT 1 FROM execbound.space_members s
                        WHERE s.tenant_id=p.tenant_id AND s.principal_id=p.principal_id))
                OR EXISTS(SELECT 1 FROM execbound.access_role_grants g
                    WHERE g.tenant_id=p.tenant_id AND g.role='administrator'
                    AND (g.principal_id=p.principal_id OR EXISTS(
                        SELECT 1 FROM execbound.access_group_members m
                        WHERE m.tenant_id=g.tenant_id AND m.group_id=g.group_id
                        AND m.principal_id=p.principal_id)))))
        """),
            {"t": tenant, "p": principal},
        ).scalar_one()
        is True
    )


def capabilities(conn: Connection, tenant: UUID, principal: UUID) -> dict[str, Any]:
    params = {"t": tenant, "p": principal, "permissions": list(PERMISSIONS)}
    permissions = conn.execute(
        text("""
        SELECT permission,
            execbound.access_has_permission(:p,permission,NULL,false) AS workspace,
            execbound.access_has_permission(:p,permission,NULL,true) AS anywhere
        FROM unnest(CAST(:permissions AS text[])) AS names(permission)
    """),
        params,
    ).all()
    scoped: dict[str, list[str]] = {}
    for row in conn.execute(
        text("""
        SELECT s.space_id,n.permission,
            execbound.access_has_permission(:p,n.permission,s.space_id,false) AS allowed
        FROM execbound.spaces s CROSS JOIN
            unnest(CAST(:permissions AS text[])) AS n(permission)
        WHERE s.tenant_id=:t
          AND execbound.access_has_permission(:p,'console.read',s.space_id,false)
        ORDER BY s.space_id,n.permission
    """),
        params,
    ):
        values = scoped.setdefault(str(row.space_id), [])
        if row.allowed:
            values.append(row.permission)
    grants = _grants(conn, tenant, principal)
    role_ids = {g["role"] for g in grants}
    managed = is_managed(conn, tenant, principal)
    if not managed:
        role_ids.update(g["role"] for g in _legacy_roles(conn, tenant, principal))
    return {
        "managed": managed,
        "roles": sorted(role_ids),
        "permissions": [
            row.permission
            for row in permissions
            if (
                row.workspace
                if row.permission in {"access.manage", "workspace.manage"}
                else row.anywhere
            )
        ],
        "workspace_permissions": [row.permission for row in permissions if row.workspace],
        "space_permissions": scoped,
    }


def workspace_role_ids(conn: Connection, tenant: UUID, principal: UUID) -> list[str]:
    """The roles this principal holds across the whole workspace: grants with no space, and
    for an unmanaged principal its legacy roles with no space.

    Unlike `capabilities()["roles"]`, a role granted in one space is left out, so a person who
    approves in one space is never labelled an approver of the whole workspace.
    """
    roles = {g["role"] for g in _grants(conn, tenant, principal) if g["space_id"] is None}
    if not is_managed(conn, tenant, principal):
        roles.update(
            g["role"] for g in _legacy_roles(conn, tenant, principal) if g["space_id"] is None
        )
    return sorted(roles)


def access_visibility(
    conn: Connection, tenant: UUID, principal: UUID
) -> tuple[bool, tuple[UUID, ...], dict[UUID, str]]:
    all_spaces = has_permission(conn, tenant, principal, "console.read")
    if all_spaces:
        return True, (), {}
    spaces = tuple(
        conn.execute(
            text(
                "SELECT space_id FROM execbound.spaces WHERE tenant_id=:t "
                "AND execbound.access_has_permission(:p,'console.read',space_id,false) "
                "ORDER BY space_id"
            ),
            {"t": tenant, "p": principal},
        ).scalars()
    )
    roles = {
        s: "ADMIN"
        if has_permission(conn, tenant, principal, "policy.manage", s)
        else "HUMAN_APPROVER"
        for s in spaces
    }
    return all_spaces, spaces, roles


def _grants(conn: Connection, tenant: UUID, principal: UUID) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            text("""
        SELECT g.role,g.space_id,g.group_id,h.name AS group_name
        FROM execbound.access_role_grants g
        LEFT JOIN execbound.access_groups h ON h.tenant_id=g.tenant_id AND h.group_id=g.group_id
        WHERE g.tenant_id=:t AND (g.principal_id=:p OR EXISTS (
            SELECT 1 FROM execbound.access_group_members m WHERE m.tenant_id=g.tenant_id
            AND m.group_id=g.group_id AND m.principal_id=:p)) ORDER BY g.role,g.space_id
    """),
            {"t": tenant, "p": principal},
        ).mappings()
    ]


def _legacy_roles(conn: Connection, tenant: UUID, principal: UUID) -> list[dict[str, Any]]:
    row = conn.execute(
        text("SELECT kind FROM execbound.principals WHERE tenant_id=:t AND principal_id=:p"),
        {"t": tenant, "p": principal},
    ).scalar_one_or_none()
    spaces = conn.execute(
        text(
            "SELECT space_id,role FROM execbound.space_members "
            "WHERE tenant_id=:t AND principal_id=:p"
        ),
        {"t": tenant, "p": principal},
    ).all()
    if row == "ADMIN" and not spaces:
        return [{"role": "administrator", "space_id": None}, {"role": "approver", "space_id": None}]
    result = [{"role": "approver", "space_id": s.space_id} for s in spaces]
    if row == "ADMIN":
        result.extend(
            {"role": "policy_manager", "space_id": s.space_id} for s in spaces if s.role == "ADMIN"
        )
    return result


def _reason(reason: str) -> str:
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
        raise AccessError("INVALID_REASON")
    if secret_shaped(reason):
        raise AccessError("INVALID_REASON")
    return reason.strip()


def _change(
    conn: Connection,
    tenant: UUID,
    actor: UUID,
    operation: str,
    subject: UUID | None,
    body: dict[str, Any],
    reason: str,
) -> UUID:
    reason = _reason(reason)
    if secret_shaped(body.get("name"), body.get("description")):
        raise AccessError("INVALID_NAME")
    if str(
        conn.execute(text("SELECT current_setting('execbound.tenant_id',true)")).scalar_one()
    ) != str(tenant):
        raise AccessError("FORBIDDEN")
    try:
        changed = conn.execute(
            text("SELECT execbound.access_change(:a,:op,:s,CAST(:b AS jsonb))"),
            {"a": actor, "op": operation, "s": subject, "b": json.dumps(body, default=str)},
        ).scalar_one()
        identifier = UUID(changed["subject_id"])
    except DBAPIError as exc:
        message = getattr(getattr(exc.orig, "diag", None), "message_primary", None)
        raise AccessError(message if message in CODES else "ACCESS_UNAVAILABLE") from None
    record_change(conn, tenant, actor, operation, changed, body, reason)
    return identifier


def record_change(
    conn: Connection,
    tenant: UUID,
    actor: UUID,
    operation: str,
    changed: dict[str, Any],
    body: dict[str, Any],
    reason: str,
) -> None:
    """The audit events for one `access_change` result, in the transaction that made it.

    `_change` calls this after its own call to the function. Teammate acceptance (#487)
    calls it for the `access_change` that `workspace_invitation_accept` makes inside its own
    transaction, so a grant decision reads the same on the chain whichever path made it.
    """
    identifier = UUID(str(changed["subject_id"]))
    append_event(
        conn,
        tenant,
        actor,
        "access." + operation,
        {
            "subject_id": str(identifier),
            "reason": reason,
            "change": json.loads(json.dumps(body, default=str)),
            "revoked_password_resets": [row["reset_id"] for row in changed["resets"]],
        },
    )
    for collection, kind in (
        ("credentials", "credential.revoked"),
        ("sessions", "human_session.revoked"),
        ("invitations", "identity.invitation_revoked"),
    ):
        for revoked in changed[collection]:
            append_event(conn, tenant, actor, kind, {**revoked, "reason": "ROLE_PROMOTION"})


def set_roles_in(
    conn: Connection,
    tenant: UUID,
    actor: UUID,
    subject_kind: str,
    subject: UUID,
    grants: list[dict[str, Any]],
    reason: str,
) -> None:
    if subject_kind not in {"user", "group"}:
        raise AccessError("INVALID_OPERATION")
    if (
        not isinstance(grants, list)
        or len(grants) > 100
        or any(not isinstance(g, dict) or set(g) - {"role", "space_id"} for g in grants)
    ):
        raise AccessError("INVALID_ROLES")
    _change(
        conn, tenant, actor, "set_" + subject_kind + "_roles", subject, {"grants": grants}, reason
    )


def _authorized(conn: Connection, runtime: Runtime, session: Session) -> None:
    from execbound.execution import store
    from execbound.surfaces.sessions import check_session

    store.fence(conn, session.identity.tenant_id, runtime.clock)
    check_session(conn, session, runtime.clock)
    if not has_permission(
        conn, session.identity.tenant_id, session.identity.principal_id, "access.manage"
    ):
        raise AccessError("FORBIDDEN")


def read_access(runtime: Runtime, session: Session) -> dict[str, Any]:
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _authorized(conn, runtime, session)
        tenant = identity.tenant_id
        users = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT principal_id,label,email,number,kind,active "
                    "FROM execbound.principals WHERE tenant_id=:t "
                    "AND kind IN ('ADMIN','HUMAN_APPROVER') "
                    "ORDER BY lower(coalesce(label,email,'')),principal_id"
                ),
                {"t": tenant},
            ).mappings()
        ]
        for user in users:
            principal = user["principal_id"]
            grants = _grants(conn, tenant, principal)
            user["managed"] = is_managed(conn, tenant, principal)
            user["direct_roles"] = [
                {"role": g["role"], "space_id": g["space_id"]}
                for g in grants
                if g["group_id"] is None
            ]
            if not user["managed"]:
                user["direct_roles"] = _legacy_roles(conn, tenant, principal)
            user["inherited_roles"] = [g for g in grants if g["group_id"] is not None]
        groups = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT group_id,name,description FROM execbound.access_groups "
                    "WHERE tenant_id=:t ORDER BY lower(name),group_id"
                ),
                {"t": tenant},
            ).mappings()
        ]
        for group in groups:
            group["members"] = list(
                conn.execute(
                    text(
                        "SELECT principal_id FROM execbound.access_group_members "
                        "WHERE tenant_id=:t AND group_id=:g ORDER BY principal_id"
                    ),
                    {"t": tenant, "g": group["group_id"]},
                ).scalars()
            )
            group["roles"] = [
                dict(row)
                for row in conn.execute(
                    text(
                        "SELECT role,space_id FROM execbound.access_role_grants "
                        "WHERE tenant_id=:t AND group_id=:g ORDER BY role,space_id"
                    ),
                    {"t": tenant, "g": group["group_id"]},
                ).mappings()
            ]
        spaces = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT space_id,name FROM execbound.spaces "
                    "WHERE tenant_id=:t AND archived_at IS NULL ORDER BY lower(name),space_id"
                ),
                {"t": tenant},
            ).mappings()
        ]
    return {"roles": list(ROLES), "users": users, "groups": groups, "spaces": spaces}


list_access = read_access


def _mutation(
    runtime: Runtime,
    session: Session,
    operation: str,
    subject: UUID | None,
    body: dict[str, Any],
    reason: str,
) -> UUID:
    try:
        with runtime.db.transaction(session.identity.tenant_id) as conn:
            _authorized(conn, runtime, session)
            return _change(
                conn,
                session.identity.tenant_id,
                session.identity.principal_id,
                operation,
                subject,
                body,
                reason,
            )
    except AccessError:
        raise
    except SQLAlchemyError:
        raise AccessError() from None


def set_user_roles(
    runtime: Runtime,
    session: Session,
    principal_id: UUID,
    grants: list[dict[str, Any]],
    reason: str,
) -> None:
    _mutation(runtime, session, "set_user_roles", principal_id, {"grants": grants}, reason)


def create_group(
    runtime: Runtime, session: Session, name: str, description: str | None, reason: str
) -> UUID:
    return _mutation(
        runtime, session, "create_group", None, {"name": name, "description": description}, reason
    )


def update_group(
    runtime: Runtime,
    session: Session,
    group_id: UUID,
    name: str,
    description: str | None,
    reason: str,
) -> None:
    _mutation(
        runtime,
        session,
        "update_group",
        group_id,
        {"name": name, "description": description},
        reason,
    )


def set_group_members(
    runtime: Runtime, session: Session, group_id: UUID, members: list[UUID], reason: str
) -> None:
    _mutation(runtime, session, "set_members", group_id, {"members": members}, reason)


def delete_group(runtime: Runtime, session: Session, group_id: UUID, reason: str) -> None:
    _mutation(runtime, session, "delete_group", group_id, {}, reason)


def set_group_roles(
    runtime: Runtime, session: Session, group_id: UUID, grants: list[dict[str, Any]], reason: str
) -> None:
    _mutation(runtime, session, "set_group_roles", group_id, {"grants": grants}, reason)
