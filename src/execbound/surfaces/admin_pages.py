# SPDX-License-Identifier: AGPL-3.0-only
"""ADMIN administration pages: issue and revoke agent and approver credentials, assign approvers.

Every write goes through a SECURITY DEFINER database function that rechecks the tenant and
the acting ADMIN inside the database; the runtime role holds no table write privilege on
principals, credentials or approval scopes. A new secret is rendered once and is never
stored, logged or shown again.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from execbound.administration import AdministrationError, screened_label
from execbound.audit import acted_with, append_event
from execbound.execution import store
from execbound.identity import NEVER, new_token
from execbound.operations import PRODUCTION_ACTIONS
from execbound.runtime import Runtime
from execbound.spaces import (
    SpaceError,
    administered_clause,
    space_clause,
    visible_spaces,
    write_space,
)
from execbound.surfaces.sessions import Session, check_session

LIFETIMES: dict[str, tuple[timedelta, str]] = {
    "1": (timedelta(hours=1), "1 hour"),
    "8": (timedelta(hours=8), "8 hours"),
    "24": (timedelta(hours=24), "1 day"),
    "168": (timedelta(days=7), "7 days"),
    "720": (timedelta(days=30), "30 days"),
    "2160": (timedelta(days=90), "90 days"),
}
NEW_PRINCIPALS = {"new:AGENT": "AGENT", "new:HUMAN_APPROVER": "HUMAN_APPROVER"}
LIST_LIMIT = 500
FAILURE_WINDOW = timedelta(hours=24)
# How far ahead a used agent key's expiry is announced, and how many agents Home lists.
EXPIRY_NOTICE = timedelta(days=7)
EXPIRING_LIMIT = 5
# Codes the database functions raise, mapped to page copy; never a value from the form.
_PROBLEMS: dict[str, tuple[str, int]] = {
    "INVALID_KIND": ("Only agent and approver principals can be created here.", 400),
    "INVALID_PRINCIPAL": ("That principal cannot be used here.", 400),
    "INVALID_LIFETIME": ("The lifetime is outside the allowed range.", 400),
    "INVALID_LABEL": ("Only a new agent is named here.", 400),
    "INVALID_DIGEST": ("The credential could not be prepared.", 503),
    "INVALID_CLOCK": ("The service clock and the database clock disagree.", 503),
    "INVALID_CREDENTIAL": ("That credential is not live, or belongs to an administrator.", 409),
    "INVALID_REPLACEMENT": (
        "That key cannot be replaced: it is not a live key of this agent, "
        "or another key already replaces it.",
        409,
    ),
    "INVALID_TARGET": ("That canonical target is not in this tenant.", 400),
    "INVALID_ACTION": ("That action is not in the catalog.", 400),
    "INVALID_SCOPE": ("That assignment is not active.", 409),
    "INVALID_ACTOR": ("Administrator session required.", 403),
    "INVALID_TENANT": ("This tenant is not active.", 403),
    "PLAN_LIMIT": (
        "This workspace has reached its agent limit. Every agent you have keeps running.",
        409,
    ),
    # A tenant with several spaces and an administrator looking at all of them: the
    # space a new object belongs to has to be chosen rather than guessed.
    "INVALID_SPACE": ("Choose a space before creating this.", 409),
    "SPACE_ARCHIVED": ("This space takes no new work.", 409),
}


@dataclass(frozen=True)
class IssuedSecret:
    """The one-time secret with its identifiers; the token never reaches the audit chain."""

    token: str = field(repr=False)
    credential_id: UUID
    principal_id: UUID
    kind: str
    expires_at: datetime
    # The key's counting number in its workspace (0058); `None` for a person's credential.
    number: int | None = None


def _call(conn: Connection, statement: str, params: dict[str, Any]) -> Any:
    """Run one administration function; a refusal surfaces as its code, nothing else."""
    try:
        return conn.execute(text(statement), params).scalar_one()
    except DBAPIError as exc:
        diagnostic = getattr(exc.orig, "diag", None)
        message = getattr(diagnostic, "message_primary", None)
        # The scheduler principal's guard (#503) is the same refusal as any principal the
        # page may not act on.
        if message == "SYSTEM_PRINCIPAL":
            message = "INVALID_PRINCIPAL"
        code = message if message in _PROBLEMS else "ADMINISTRATION_UNAVAILABLE"
        raise AdministrationError(code) from None


def _space_to_write(conn: Connection, session: Session) -> UUID:
    """The one space an administrator's write lands in, as this surface's own refusal.

    Nothing the request carries names it: it is the space the administrator is looking at,
    or the tenant's only one. A tenant with several spaces and an administrator looking at
    all of them is ambiguous and refused rather than guessed.
    """
    try:
        return write_space(conn, session.identity.tenant_id, visible_spaces(conn, session))
    except SpaceError:
        raise AdministrationError("INVALID_SPACE") from None


def _admin(conn: Connection, runtime: Runtime, session: Session) -> None:
    store.fence(conn, session.identity.tenant_id, runtime.clock)
    store.identity_check(conn, session.identity, runtime.clock, "ADMIN")
    check_session(conn, session, runtime.clock)


def credentials_overview(runtime: Runtime, session: Session) -> dict[str, Any]:
    """Principals and credentials of the tenant with live counts and 24-hour failures.

    An agent and its keys belong to the agent's space, so they are listed in the spaces the
    reader may see and filtered by the one they are looking at, as the Agents page lists
    them. A person belongs to no space and is listed in every view, to the administrators who
    may administer them: since 0072 an administrator narrowed to spaces sees only the people
    whose every seat is in one of their `ADMIN` spaces (`spaces.administered_clause`).
    """
    identity = session.identity
    now = store.now(runtime.clock)
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        space = space_clause(visible_spaces(conn, session), "p", unowned=True)
        people = administered_clause(conn, session, "p", agents=False)
        params = {
            "t": identity.tenant_id,
            "now": now,
            "since": now - FAILURE_WINDOW,
            **space.params,
            **people.params,
        }
        principals = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT p.principal_id, p.kind, p.active, p.label, p.number, "
                    "count(c.credential_id) "
                    "FILTER (WHERE c.revoked_at IS NULL AND c.expires_at > :now "
                    "AND NOT EXISTS (SELECT 1 FROM execbound.personal_access_tokens k "
                    "WHERE k.tenant_id = c.tenant_id AND k.credential_id = c.credential_id)) "
                    "AS live "
                    "FROM execbound.principals p LEFT JOIN execbound.credentials c "
                    "USING (tenant_id, principal_id) WHERE p.tenant_id = :t "
                    # A workspace's scheduler principal (#503) is no one a key is issued
                    # to, and the page's model accepts only the person and agent kinds.
                    "AND p.kind <> 'SYSTEM'"
                    + space.sql  # nosec B608 - one helper's predicate; values are bound
                    + people.sql  # nosec B608 - one helper's predicate; values are bound
                    + " GROUP BY p.principal_id, p.kind, p.active, p.label, p.number "
                    "ORDER BY p.kind, p.principal_id LIMIT :limit"
                ),
                {**params, "limit": LIST_LIMIT},
            ).mappings()
        ]
        credentials = []
        for row in conn.execute(
            text(
                "SELECT c.credential_id, c.principal_id, p.kind, p.label, p.email, "
                "c.number, p.number AS principal_number, c.issued_at, c.expires_at, "
                "c.revoked_at, c.last_used_at, "
                # Replaced only when a live key names this one, through Rotate (0079).
                "EXISTS (SELECT 1 FROM execbound.credentials n "
                "WHERE n.tenant_id = c.tenant_id AND n.replaces_credential_id = c.credential_id "
                "AND n.revoked_at IS NULL AND n.deleted_at IS NULL AND n.expires_at > :now) "
                "AS replaced, "
                "COALESCE((SELECT sum(f.count) "
                "FROM execbound.authentication_failures f WHERE f.tenant_id = c.tenant_id "
                "AND f.subject_kind = 'credential' AND f.subject_id = c.credential_id "
                "AND f.window_start >= :since), 0) AS failures_24h "
                "FROM execbound.credentials c "
                "JOIN execbound.principals p USING (tenant_id, principal_id) "
                "WHERE c.tenant_id = :t AND c.deleted_at IS NULL "
                "AND NOT EXISTS (SELECT 1 FROM execbound.personal_access_tokens k "
                "WHERE k.tenant_id = c.tenant_id AND k.credential_id = c.credential_id)"
                + space.sql  # nosec B608 - one helper's predicate; values are bound
                + people.sql  # nosec B608 - one helper's predicate; values are bound
                + " ORDER BY p.kind, c.principal_id, c.issued_at DESC, c.credential_id "
                "LIMIT :limit"
            ),
            {**params, "limit": LIST_LIMIT},
        ).mappings():
            if row["revoked_at"] is not None:
                state = "revoked"
            elif row["expires_at"] <= now:
                state = "expired"
            else:
                state = "live"
            credentials.append({**row, "state": state, "failures_24h": int(row["failures_24h"])})
        _admin(conn, runtime, session)
    return {
        "principals": principals,
        "credentials": credentials,
        "live": sum(1 for item in credentials if item["state"] == "live"),
    }


def expiring_rows(
    conn: Connection,
    session: Session,
    now: datetime,
    *,
    principal: UUID | None = None,
    limit: int = EXPIRING_LIMIT,
) -> tuple[list[dict[str, Any]], int]:
    """Used agent keys that expire soon: one per agent, its soonest, and how many agents.

    A key needs a notice when its agent is an active, awake agent, the key is live, it expires
    within `EXPIRY_NOTICE` of the server's clock, it has been used, and no live key names it as
    the key it replaces. Nothing else retires a notice: a key issued without Rotate replaces
    nothing, because an agent often holds several live keys for different integrations. The
    reader's visible spaces filter it, as the credentials page's list is filtered.
    """
    space = space_clause(visible_spaces(conn, session), "p")
    rows = [
        dict(row)
        for row in conn.execute(
            text(
                "WITH due AS (SELECT DISTINCT ON (c.principal_id) c.credential_id, c.number, "
                "c.principal_id, p.number AS principal_number, p.label AS principal_label, "
                "c.expires_at, c.last_used_at "
                "FROM execbound.credentials c JOIN execbound.principals p "
                "ON p.tenant_id = c.tenant_id AND p.principal_id = c.principal_id "
                "WHERE c.tenant_id = :t AND p.kind = 'AGENT' AND p.active "
                "AND p.dormant_at IS NULL "
                "AND c.revoked_at IS NULL AND c.deleted_at IS NULL "
                "AND c.expires_at > :now AND c.expires_at <= :horizon "
                "AND c.last_used_at IS NOT NULL "
                "AND (CAST(:principal AS uuid) IS NULL "
                "OR c.principal_id = CAST(:principal AS uuid)) "
                "AND NOT EXISTS (SELECT 1 FROM execbound.credentials n "
                "WHERE n.tenant_id = c.tenant_id AND n.replaces_credential_id = c.credential_id "
                "AND n.revoked_at IS NULL AND n.deleted_at IS NULL AND n.expires_at > :now)"
                + space.sql  # nosec B608 - one helper's predicate; values are bound
                + " ORDER BY c.principal_id, c.expires_at, c.credential_id) "
                "SELECT *, count(*) OVER () AS total FROM due "
                "ORDER BY expires_at, credential_id LIMIT :limit"
            ),
            {
                "t": session.identity.tenant_id,
                "now": now,
                "horizon": now + EXPIRY_NOTICE,
                "principal": principal,
                "limit": limit,
                **space.params,
            },
        ).mappings()
    ]
    total = int(rows[0]["total"]) if rows else 0
    return [{k: v for k, v in row.items() if k != "total"} for row in rows], total


def expiring_keys(
    runtime: Runtime, session: Session, *, limit: int = EXPIRING_LIMIT
) -> dict[str, Any]:
    """Home's "API keys expiring soon": at most `limit` agents, and how many more there are."""
    identity = session.identity
    now = store.now(runtime.clock)
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        keys, total = expiring_rows(conn, session, now, limit=limit)
        _admin(conn, runtime, session)
    return {"keys": keys, "more": max(total - len(keys), 0)}


def approvers_overview(runtime: Runtime, session: Session) -> dict[str, Any]:
    """Active assignments plus the approvers and canonical targets the assign form offers."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        # An approver may hold a scope in one space and not another, so the matrix shows
        # the scopes of the spaces the reader can see.
        space = space_clause(visible_spaces(conn, session), "e")
        params = {"t": identity.tenant_id, "limit": LIST_LIMIT, **space.params}
        assignments = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT e.approver_id, e.canonical_target_id, e.action "
                    "FROM execbound.approval_scopes e WHERE e.tenant_id = :t AND e.active"
                    + space.sql  # nosec B608 - one helper's predicate; values are bound
                    + " ORDER BY e.approver_id, e.canonical_target_id, e.action LIMIT :limit"
                ),
                params,
            ).mappings()
        ]
        approvers = [
            row["principal_id"]
            for row in conn.execute(
                text(
                    "SELECT principal_id FROM execbound.principals WHERE tenant_id = :t "
                    "AND kind IN ('HUMAN_APPROVER', 'ADMIN') AND active "
                    "ORDER BY principal_id LIMIT :limit"
                ),
                params,
            ).mappings()
        ]
        # Provider identifiers label targets for the operator; they render as escaped text.
        targets = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT ct.canonical_target_id, "
                    "string_agg(r.provider_id, ', ' ORDER BY r.provider_id) AS labels "
                    "FROM execbound.canonical_targets ct "
                    "LEFT JOIN execbound.resource_identities ri "
                    "ON ri.tenant_id = ct.tenant_id "
                    "AND ri.canonical_target_id = ct.canonical_target_id "
                    "LEFT JOIN execbound.resources r ON r.tenant_id = ri.tenant_id "
                    "AND r.account_id = ri.account_id AND r.provider = ri.provider "
                    "AND r.resource_type = ri.resource_type AND r.resource_id = ri.resource_id "
                    "WHERE ct.tenant_id = :t GROUP BY ct.canonical_target_id "
                    "ORDER BY ct.canonical_target_id LIMIT :limit"
                ),
                params,
            ).mappings()
        ]
        # What names each person the page lists: the label, else the email, else the number,
        # "User 3" (0062). Read for exactly the people above, so no bound can drop one.
        listed = {row["approver_id"] for row in assignments} | set(approvers)
        names = {
            row["principal_id"]: dict(row)
            for row in conn.execute(
                text(
                    "SELECT principal_id, label, email, number FROM execbound.principals "
                    "WHERE tenant_id = :t AND principal_id = ANY(CAST(:ids AS uuid[]))"
                ),
                {"t": identity.tenant_id, "ids": [str(principal) for principal in listed]},
            ).mappings()
        }
        _admin(conn, runtime, session)
    return {
        "assignments": assignments,
        "approvers": approvers,
        "targets": targets,
        "names": names,
    }


def issue(
    runtime: Runtime,
    session: Session,
    *,
    principal: UUID | None,
    kind: str | None,
    lifetime: timedelta | None,
    label: str | None = None,
    replaces: UUID | None = None,
) -> IssuedSecret:
    """Create a principal when asked, then issue one credential; the token exists in memory only.

    A `lifetime` of `None` is an agent's API key that never expires: it is issued with the
    expiry `NEVER`, which `admin_issue_credential` refuses for anything but an agent.

    `replaces` names a live key of the same agent that the new key replaces (Rotate). It is
    recorded in the same transaction by `admin_credential_replaces`, whose refusal rolls the
    whole issue back, so no key is issued without the link it was asked for.
    """
    identity = session.identity
    if lifetime is None:
        if kind not in (None, "AGENT"):
            raise AdministrationError("INVALID_LIFETIME")
    elif lifetime not in {value for value, _ in LIFETIMES.values()}:
        raise AdministrationError("INVALID_LIFETIME")
    if (principal is None) == (kind is None):
        raise AdministrationError("INVALID_PRINCIPAL")
    # A name is given only to an agent created for its first key, "Coding agent on my laptop".
    if label is not None and kind != "AGENT":
        raise AdministrationError("INVALID_LABEL")
    screened_label(label)
    now = store.now(runtime.clock)
    expires_at = NEVER if lifetime is None else now + lifetime
    credential = uuid4()
    token, digest = new_token(identity.tenant_id, credential)
    actor = {"actor": identity.principal_id}
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        if principal is None:
            # An agent is owned by the space the administrator is looking at; a person
            # is seated as a member of it. Nothing the request carries names it.
            space = _space_to_write(conn, session)
            principal = _call(
                conn,
                "SELECT execbound.admin_create_principal(:actor, :kind, :space)",
                {**actor, "kind": kind, "space": space},
            )
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "principal.created",
                {
                    "principal_id": str(principal),
                    "kind": kind,
                    **acted_with(identity.credential_id),
                },
            )
            if label is not None:
                stored = _call(
                    conn,
                    "SELECT execbound.admin_label_principal(:actor, :principal, :label)",
                    {**actor, "principal": principal, "label": label},
                )
                append_event(
                    conn,
                    identity.tenant_id,
                    identity.principal_id,
                    "principal.labelled",
                    {
                        "principal_id": str(principal),
                        "label": str(stored),
                        **acted_with(identity.credential_id),
                    },
                )
        issued_kind = _call(
            conn,
            "SELECT execbound.admin_issue_credential("
            ":actor, :principal, :credential, :digest, :issued, :expires)",
            {
                **actor,
                "principal": principal,
                "credential": credential,
                "digest": digest,
                "issued": now,
                "expires": expires_at,
            },
        )
        if replaces is not None:
            _call(
                conn,
                "SELECT execbound.admin_credential_replaces(:actor, :credential, :replaces)",
                {**actor, "credential": credential, "replaces": replaces},
            )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "credential.issued",
            {
                "credential_id": str(credential),
                "principal_id": str(principal),
                "kind": issued_kind,
                "expires_at": expires_at.isoformat(),
                # Written only for a rotation, so an ordinary issue writes the bytes it did.
                **({"replaces": str(replaces)} if replaces is not None else {}),
                **acted_with(identity.credential_id),
            },
        )
        number = key_number(conn, identity.tenant_id, credential)
        _admin(conn, runtime, session)
    return IssuedSecret(token, credential, principal, str(issued_kind), expires_at, number)


def key_number(conn: Connection, tenant: UUID, credential: UUID) -> int | None:
    """The number the database gave a key as it was written; `None` for a person's."""
    number = conn.execute(
        text(
            "SELECT number FROM execbound.credentials WHERE tenant_id = :t AND credential_id = :c"
        ),
        {"t": tenant, "c": credential},
    ).scalar_one()
    return None if number is None else int(number)


def delete(runtime: Runtime, session: Session, credential: UUID) -> None:
    """Take a revoked or expired API key out of every list; the chain keeps its history."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        _call(
            conn,
            "SELECT execbound.admin_delete_credential(:actor, :credential, :now)",
            {
                "actor": identity.principal_id,
                "credential": credential,
                "now": store.now(runtime.clock),
            },
        )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "credential.deleted",
            {
                "credential_id": str(credential),
                **acted_with(identity.credential_id),
            },
        )
        _admin(conn, runtime, session)


def revoke(runtime: Runtime, session: Session, credential: UUID) -> None:
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        _call(
            conn,
            "SELECT execbound.admin_revoke_credential(:actor, :credential, :now)",
            {
                "actor": identity.principal_id,
                "credential": credential,
                "now": store.now(runtime.clock),
            },
        )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "credential.revoked",
            {
                "credential_id": str(credential),
                **acted_with(identity.credential_id),
            },
        )
        _admin(conn, runtime, session)


def assign(
    runtime: Runtime, session: Session, approver: UUID, target: UUID, action: str, *, active: bool
) -> None:
    """Assign (active) or unassign one approver for one canonical target and action."""
    identity = session.identity
    if action not in PRODUCTION_ACTIONS.names:
        raise AdministrationError("INVALID_ACTION")
    function = "admin_assign_approver" if active else "admin_unassign_approver"
    space_argument = ", :space" if active else ""
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        # An approver may hold a scope in one space and not another, so an assignment
        # lands in the space the administrator is looking at; withdrawing one names the
        # row by approver, target and action and leaves its space alone.
        space = _space_to_write(conn, session) if active else None
        _call(
            conn,
            # function is one of the two literals chosen above; every value is bound.
            f"SELECT execbound.{function}(:actor, :approver, :target, :action{space_argument})",  # nosec B608 - a literal
            {
                "actor": identity.principal_id,
                "approver": approver,
                "target": target,
                "action": action,
                **({"space": space} if active else {}),
            },
        )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "approval_scope.assigned" if active else "approval_scope.revoked",
            {
                "approver_id": str(approver),
                "canonical_target_id": str(target),
                "action": action,
                **acted_with(identity.credential_id),
            },
        )
        _admin(conn, runtime, session)


def _uuid(value: str, status: int) -> UUID:
    try:
        identifier = UUID(value)
    except ValueError:
        raise HTTPException(status, "Invalid request") from None
    if str(identifier) != value:
        raise HTTPException(status, "Invalid request")
    return identifier
