# SPDX-License-Identifier: AGPL-3.0-only
"""Agents: the tenant's agents, governed and discovered, one list and one page per agent.

Step 1 of #228 is the governed half: AGENT principals with their credentials, activity,
limits and deactivation. Every number is read from the rows the kernel itself counts:
requests from ``executions``, limits from the retained impact ledger with the same sum
admission makes, and reach through ExecBound from the active bundle as Monitoring derives it.

Step 2 adds the agents a monitoring connection discovered and the explicit binding between
one of them and one AGENT principal. A binding is written only by the two definer functions
of migration 0037, through ``execbound.bindings``, and ``Govern this agent`` composes the
principal, its label, the binding and a credential in one transaction. Every other write
reuses the functions the credentials and People pages already call, so each fact keeps one
write path.
"""

import base64
import binascii
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from execbound import bindings
from execbound.administration import AdministrationError, screened_label
from execbound.audit import acted_with, append_event, canonical_json
from execbound.capacity import agent_capacity
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.execution.offered import bundle_operations
from execbound.identity import NEVER, new_token
from execbound.monitoring import reach
from execbound.monitoring import store as monitor_store
from execbound.monitoring.grant_catalog import ENTRA, PRODUCTION_GRANTS
from execbound.monitoring.models import MonitorError
from execbound.operations import CatalogError
from execbound.policy.models import BundleContent, LimitRule
from execbound.policy.reading import document_reading
from execbound.policy.rulesets import rules_for, sentence
from execbound.runtime import Runtime
from execbound.secrets import secret_shaped
from execbound.spaces import (
    NO_SPACE_FILTER,
    SpaceFilter,
    administered_clause,
    space_clause,
    visible_spaces,
)
from execbound.surfaces.admin_pages import (
    LIFETIMES,
    IssuedSecret,
    _admin,
    _space_to_write,
    expiring_rows,
    key_number,
)
from execbound.surfaces.human import (
    limit_label,
)
from execbound.surfaces.names import principal_facts
from execbound.surfaces.sessions import Session

PAGE_SIZE = 50
RECENT = 20
LIST_LIMIT = 500
OPTIONS_LIMIT = 200
STATES = ("active", "deactivated", "gone", "all")
ACTIVE = ("any", "yes", "no")
POPULATIONS = ("all", "registered", "bound", "governed", "discovered")
SOURCES = ("all", "entra_agent_id", "tines")
UNGOVERNED = ("any", "yes")
FAILURE_WINDOW = timedelta(hours=24)
MAX_CURSOR = 512
LABEL_LIMIT = 80
# Codes the functions raise, mapped to page copy; never a value from the form.
_PROBLEMS: dict[str, tuple[str, int]] = {
    "INVALID_LABEL": ("A label of 1 to 80 characters is required.", 400),
    "INVALID_REASON": ("A reason of 1 to 500 characters is required.", 400),
    "INVALID_PRINCIPAL": ("That agent principal cannot be used here.", 400),
    "INVALID_AGENT": ("That discovered agent is gone from its source or not in this tenant.", 409),
    "INVALID_STATE": ("That agent is already in that state, or already bound.", 409),
    "SYNTHETIC_ACTOR": ("A synthetic directory's actor cannot be governed or bound.", 409),
    "INVALID_KIND": ("Only agents can be created here.", 400),
    "INVALID_LIFETIME": ("The lifetime is outside the allowed range.", 400),
    "INVALID_DIGEST": ("The credential could not be prepared.", 503),
    "INVALID_CLOCK": ("The service clock and the database clock disagree.", 503),
    "INVALID_CREDENTIAL": ("That credential is not live.", 409),
    "INVALID_ACTOR": ("Administrator session required.", 403),
    "INVALID_TENANT": ("This tenant is not active.", 403),
    "PLAN_LIMIT": (
        "This workspace has reached its agent limit. Every agent you have keeps running.",
        409,
    ),
}
_UNAVAILABLE = ("Administration is unavailable.", 503)

# The one definition of "active this month" (#233): AGENT principals with at least one
# request created in the current UTC calendar month. The list, the tenant figure and the
# agent page all read it, so they cannot disagree; #257's tally replaces this query. The
# list query repeats it as its first common table expression rather than formatting it in,
# so every statement here stays a literal, and a test holds the two texts identical.
_MONTH = """
SELECT e.principal_id, count(*) AS requests
FROM execbound.executions e
JOIN execbound.principals p
  ON p.tenant_id = e.tenant_id AND p.principal_id = e.principal_id AND p.kind = 'AGENT'
WHERE e.tenant_id = :t AND e.created_at >= :month_start AND e.created_at < :month_end
  AND (CAST(:only AS uuid) IS NULL OR e.principal_id = CAST(:only AS uuid))/*space*/
GROUP BY e.principal_id
"""

# One row per bound pair or governed-only principal (addressed by the principal) and per
# discovered agent no active binding claims (addressed by the agent). Reach counts are
# Monitoring's own, over the active profile's sensitive actions.
_AGENTS = """
WITH month AS (
SELECT e.principal_id, count(*) AS requests
FROM execbound.executions e
JOIN execbound.principals p
  ON p.tenant_id = e.tenant_id AND p.principal_id = e.principal_id AND p.kind = 'AGENT'
WHERE e.tenant_id = :t AND e.created_at >= :month_start AND e.created_at < :month_end
  AND (CAST(:only AS uuid) IS NULL OR e.principal_id = CAST(:only AS uuid))/*space*/
GROUP BY e.principal_id
),
reached AS (
    SELECT r.agent_id,
           count(*) FILTER (
               WHERE r.path_kind IN ('grant', 'role', 'inherited')
                 AND r.action = ANY(CAST(:consequential AS text[])) AND r.valid_until > :now
           ) AS consequential,
           count(*) FILTER (WHERE r.path_kind = 'execbound') AS governed_paths,
           count(*) FILTER (WHERE r.valid_until <= :now) AS lapsed
    FROM execbound.monitor_agent_reach r
    WHERE r.tenant_id = :t AND r.gone_at IS NULL
    GROUP BY r.agent_id
),
open_findings AS (
    SELECT f.agent_id, count(*) AS findings
    FROM execbound.monitor_findings f
    WHERE f.tenant_id = :t AND f.agent_id IS NOT NULL AND f.acknowledged_at IS NULL/*fspace*/
    GROUP BY f.agent_id
),
bound AS (
    SELECT b.agent_id, b.principal_id FROM execbound.agent_bindings b
    WHERE b.tenant_id = :t AND b.unbound_at IS NULL
),
listed AS (
    SELECT p.principal_id AS row_id,
           CASE WHEN b.agent_id IS NULL THEN 'governed' ELSE 'bound' END AS population,
           p.principal_id, b.agent_id, COALESCE(p.label, a.display_name) AS name, p.active,
           p.dormant_at IS NOT NULL AS dormant, p.number
    FROM execbound.principals p
    LEFT JOIN bound b ON b.principal_id = p.principal_id
    LEFT JOIN execbound.monitor_agents a
      ON a.tenant_id = p.tenant_id AND a.agent_id = b.agent_id
    WHERE p.tenant_id = :t AND p.kind = 'AGENT'/*pspace*/
    UNION ALL
    SELECT a.agent_id, 'discovered', NULL, a.agent_id, a.display_name, NULL, NULL, NULL
    FROM execbound.monitor_agents a
    WHERE a.tenant_id = :t
      AND NOT EXISTS (SELECT 1 FROM bound b WHERE b.agent_id = a.agent_id)
)
SELECT x.row_id, x.population, x.principal_id, x.agent_id, x.name, x.active, x.dormant,
       x.number, a.identity_class, a.enabled, a.gone_at, a.observed_at AS last_seen,
       a.sponsors, a.sponsor_state, c.kind AS source,
       (SELECT count(*) FROM execbound.credentials cr
         WHERE cr.tenant_id = :t AND cr.principal_id = x.principal_id
           AND cr.revoked_at IS NULL AND cr.expires_at > :now) AS live,
       COALESCE(m.requests, 0) AS requests,
       (SELECT max(e.created_at) FROM execbound.executions e
         WHERE e.tenant_id = :t AND e.principal_id = x.principal_id/*space*/) AS last_request,
       (SELECT e.execution_id FROM execbound.executions e
         WHERE e.tenant_id = :t AND e.principal_id = x.principal_id/*space*/
         ORDER BY e.created_at DESC, e.execution_id DESC LIMIT 1) AS last_execution_id,
       (SELECT 'EB-' || e.request_number FROM execbound.executions e
         WHERE e.tenant_id = :t AND e.principal_id = x.principal_id/*space*/
         ORDER BY e.created_at DESC, e.execution_id DESC LIMIT 1) AS last_request_ref,
       COALESCE(r.consequential, 0) AS consequential,
       COALESCE(r.governed_paths, 0) AS governed_paths,
       COALESCE(r.lapsed, 0) AS lapsed,
       COALESCE(o.findings, 0) AS findings
FROM listed x
LEFT JOIN execbound.monitor_agents a ON a.tenant_id = :t AND a.agent_id = x.agent_id
LEFT JOIN execbound.monitor_connections c
  ON c.tenant_id = :t AND c.connection_id = a.connection_id
LEFT JOIN month m ON m.principal_id = x.principal_id
LEFT JOIN reached r ON r.agent_id = x.agent_id
LEFT JOIN open_findings o ON o.agent_id = x.agent_id
WHERE (CAST(:population AS text) = 'all' OR x.population = CAST(:population AS text)
       OR (CAST(:population AS text) = 'registered' AND x.principal_id IS NOT NULL))
  AND (CAST(:source AS text) = 'all' OR c.kind = CAST(:source AS text))
  AND (CAST(:state AS text) = 'all'
       OR (CAST(:state AS text) = 'active'
           AND ((x.principal_id IS NOT NULL AND x.active)
                OR (x.principal_id IS NULL AND a.gone_at IS NULL)))
       OR (CAST(:state AS text) = 'deactivated'
           AND x.principal_id IS NOT NULL AND NOT x.active)
       OR (CAST(:state AS text) = 'gone' AND a.gone_at IS NOT NULL))
  AND (CAST(:active AS text) = 'any'
       OR (CAST(:active AS text) = 'yes' AND m.requests IS NOT NULL)
       OR (CAST(:active AS text) = 'no' AND m.requests IS NULL))
  AND (CAST(:ungoverned AS text) = 'any'
       OR (COALESCE(r.consequential, 0) > 0 AND COALESCE(r.governed_paths, 0) = 0))
  AND (NOT CAST(:after AS boolean)
       OR (x.name IS NULL, COALESCE(x.name, ''), x.row_id)
          > (CAST(:after_unnamed AS boolean), CAST(:after_name AS text),
             CAST(:after_id AS uuid)))
ORDER BY (x.name IS NULL), COALESCE(x.name, ''), x.row_id
LIMIT :limit
"""

# The asleep AGENT principals of the Space the list is read under, whatever its filters: the
# console's empty-Space test asks it, because the default State hides an asleep agent and the
# tenant line's count is the whole workspace's (#439).
_ASLEEP = """
SELECT count(*) FROM execbound.principals p
WHERE p.tenant_id = :t AND p.kind = 'AGENT' AND p.dormant_at IS NOT NULL/*pspace*/
"""

_CREDENTIALS = """
SELECT c.credential_id, c.number, c.issued_at, c.expires_at, c.revoked_at, c.last_used_at,
       -- Replaced only when a live key names this one, through Rotate (0079).
       EXISTS (SELECT 1 FROM execbound.credentials n
                WHERE n.tenant_id = c.tenant_id AND n.replaces_credential_id = c.credential_id
                  AND n.revoked_at IS NULL AND n.deleted_at IS NULL AND n.expires_at > :now)
           AS replaced,
       COALESCE((SELECT sum(f.count) FROM execbound.authentication_failures f
                  WHERE f.tenant_id = c.tenant_id AND f.subject_kind = 'credential'
                    AND f.subject_id = c.credential_id AND f.window_start >= :since), 0)
           AS failures
FROM execbound.credentials c
WHERE c.tenant_id = :t AND c.principal_id = :p AND c.deleted_at IS NULL
ORDER BY c.issued_at DESC, c.credential_id LIMIT :limit
"""

# The target's provider identifier as the board reads it, the first by name when a canonical
# target has several, so a row is never repeated; agent text, rendered as text.
_RECENT = """
SELECT e.execution_id, e.state, e.created_at, e.canonical_target_id,
       e.frozen -> 'intent' ->> 'action' AS action, 'EB-' || e.request_number AS request_ref,
       (SELECT r.provider_id FROM execbound.resource_identities i
          JOIN execbound.resources r
            ON r.tenant_id = i.tenant_id AND r.account_id = i.account_id
           AND r.provider = i.provider AND r.resource_type = i.resource_type
           AND r.resource_id = i.resource_id
         WHERE i.tenant_id = e.tenant_id AND i.canonical_target_id = e.canonical_target_id
         ORDER BY r.provider_id LIMIT 1) AS target_label
FROM execbound.executions e
WHERE e.tenant_id = :t AND e.principal_id = :p
ORDER BY e.created_at DESC, e.execution_id DESC LIMIT :limit
"""

# The same rows ``derive_reach`` reads for a linked agent: settled executions of this
# principal inside the evidence window, by action.
_EXECUTED = """
SELECT e.frozen -> 'intent' ->> 'action' AS action, max(e.changed_at) AS at
FROM execbound.executions e
WHERE e.tenant_id = :t AND e.principal_id = :p AND e.state = 'EXECUTED'
  AND e.changed_at > :horizon
GROUP BY e.frozen -> 'intent' ->> 'action'
"""

# The sum ``store.usage`` makes for one rule, without a candidate request.
_USAGE = """
SELECT count(*) FILTER (WHERE state = 'CONFIRMED' AND confirmed_at > :start
                               AND confirmed_at <= :now) AS confirmed,
       count(*) FILTER (WHERE state = 'UNRESOLVED') AS unresolved,
       count(*) FILTER (WHERE state = 'OBSERVED' AND created_at > :start
                               AND created_at <= :now) AS projected
FROM execbound.execution_impact WHERE tenant_id = :t
  AND action = ANY(CAST(:actions AS text[]))
  AND (:scope <> 'principal' OR principal_id = :p)
  AND (:scope <> 'group' OR group_ids @> CAST(:group AS jsonb))
  AND (:budget = 'total' OR NOT approved)
"""

_BINDING_OF_PRINCIPAL = """
SELECT b.binding_id, b.agent_id, b.principal_id, b.bound_by, b.bound_at
FROM execbound.agent_bindings b
WHERE b.tenant_id = :t AND b.principal_id = :p AND b.unbound_at IS NULL
"""

# The discovered agents a governed agent may be bound to. Never the synthetic directory's
# (#355): binding one is refused (`SYNTHETIC_ACTOR`), so the picker never offers it.
_UNBOUND_AGENTS = """
SELECT a.agent_id, a.display_name, a.identity_class, c.kind AS source
FROM execbound.monitor_agents a
JOIN execbound.monitor_connections c
  ON c.tenant_id = a.tenant_id AND c.connection_id = a.connection_id
WHERE a.tenant_id = :t AND a.gone_at IS NULL AND c.kind <> 'fixture'
  AND NOT EXISTS (SELECT 1 FROM execbound.agent_bindings b
                   WHERE b.tenant_id = a.tenant_id AND b.agent_id = a.agent_id
                     AND b.unbound_at IS NULL)
ORDER BY a.display_name, a.agent_id LIMIT :limit
"""

_UNBOUND_PRINCIPALS = """
SELECT p.principal_id, p.label
FROM execbound.principals p
WHERE p.tenant_id = :t AND p.kind = 'AGENT' AND p.active
  AND NOT EXISTS (SELECT 1 FROM execbound.agent_bindings b
                   WHERE b.tenant_id = p.tenant_id AND b.principal_id = p.principal_id
                     AND b.unbound_at IS NULL)
ORDER BY (p.label IS NULL), p.label, p.principal_id LIMIT :limit
"""

SOURCE_LABELS = {"entra_agent_id": "Entra", "tines": "Tines", "fixture": "Synthetic directory"}
CLASS_LABELS = {
    "agent_identity": "agent identity",
    "service_principal": "classic service principal",
    "managed_identity": "managed identity",
    "consented_app": "consented app",
    "tines_story": "Tines story",
}


def _call(conn: Connection, statement: str, params: dict[str, Any]) -> Any:
    """Run one definer function; a refusal surfaces as its code and nothing else."""
    try:
        return conn.execute(text(statement), params).scalar_one()
    except DBAPIError as exc:
        diagnostic = getattr(exc.orig, "diag", None)
        message = getattr(diagnostic, "message_primary", None)
        code = message if message in _PROBLEMS else "ADMINISTRATION_UNAVAILABLE"
        raise AdministrationError(code) from None


def month_bounds(now: datetime) -> tuple[datetime, datetime]:
    """The current UTC calendar month as a half-open interval."""
    now = now.astimezone(UTC)
    start = datetime(now.year, now.month, 1, tzinfo=UTC)
    end = datetime(now.year + now.month // 12, now.month % 12 + 1, 1, tzinfo=UTC)
    return start, end


def spaced(statement: str, space: SpaceFilter) -> str:
    """One statement with the one helper's predicate at each alias it was written for.

    The markers are this module's own literals and the predicate comes from
    `space_clause`; every value in it is a bound parameter.
    """
    return (  # nosec B608 - literals only
        statement.replace("/*space*/", space.sql)
        .replace("/*pspace*/", space.sql.replace("e.", "p."))
        .replace("/*fspace*/", space.sql.replace("e.", "f."))
    )


def active_this_month(
    conn: Connection,
    tenant: UUID,
    now: datetime,
    *,
    only: UUID | None = None,
    space: SpaceFilter = NO_SPACE_FILTER,
) -> dict[UUID, int]:
    """Requests this UTC month per AGENT principal that made at least one."""
    start, end = month_bounds(now)
    rows = conn.execute(
        text(spaced(_MONTH, space)),
        {"t": tenant, "month_start": start, "month_end": end, "only": only, **space.params},
    )
    return {row.principal_id: int(row.requests) for row in rows}


def encode_cursor(row: dict[str, Any]) -> str:
    raw = json.dumps([row["name"] is None, row["name"] or "", str(row["row_id"])])
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(value: str) -> tuple[bool, str, UUID]:
    """The last row of the previous page; anything else is a 400, never a guess."""
    if not value or len(value) > MAX_CURSOR:
        raise HTTPException(400, "Invalid request")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        decoded = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise HTTPException(400, "Invalid request") from None
    if type(decoded) is not list or len(decoded) != 3:
        raise HTTPException(400, "Invalid request")
    unnamed, name, row = decoded
    if type(unnamed) is not bool or type(name) is not str or type(row) is not str:
        raise HTTPException(400, "Invalid request")
    try:
        parsed = UUID(row)
    except ValueError:
        raise HTTPException(400, "Invalid request") from None
    if str(parsed) != row:
        raise HTTPException(400, "Invalid request")
    return unnamed, name, parsed


_CONNECTIONS = """
SELECT c.connection_id, c.label, c.kind, c.active, c.last_sync_at, c.health_state
FROM execbound.monitor_connections c
WHERE c.tenant_id = :t
  AND (c.active OR EXISTS (SELECT 1 FROM execbound.monitor_agents a
                            WHERE a.tenant_id = c.tenant_id AND a.connection_id = c.connection_id
                              AND a.gone_at IS NULL))
ORDER BY c.created_at, c.connection_id
"""


def tenant_line(conn: Connection, tenant: UUID, now: datetime) -> dict[str, Any]:
    """Per source: agents listed, with consequential reach, bound, and not established.

    Counted with Monitoring's own definitions over the same rows, so this line and
    Monitoring's Agents view cannot disagree: consequential reach is a current grant, role or
    inherited path to a sensitive action of the active profile; not established is a grant the
    catalog cannot explain, a lapsed claim, or accountability the directory would not let us
    read. Every count is of agents a connection could enumerate, never of agents that exist.
    """
    consequential = _consequential(conn, tenant)
    counts = monitor_store._agent_counts(conn, tenant, consequential, now)
    unresolved: dict[UUID, int] = {}
    for grant in conn.execute(
        text(
            "SELECT agent_id, grant_kind, resource_ref, value FROM "
            "execbound.monitor_agent_grants WHERE tenant_id = :t AND gone_at IS NULL"
        ),
        {"t": tenant},
    ).mappings():
        if not PRODUCTION_GRANTS.lookup(
            ENTRA, grant["grant_kind"], grant["resource_ref"], grant["value"]
        ):
            unresolved[grant["agent_id"]] = unresolved.get(grant["agent_id"], 0) + 1
    bound = set(
        conn.execute(
            text(
                "SELECT agent_id FROM execbound.agent_bindings "
                "WHERE tenant_id = :t AND unbound_at IS NULL"
            ),
            {"t": tenant},
        ).scalars()
    )
    sources: dict[UUID, dict[str, Any]] = {
        row["connection_id"]: {
            **row,
            "source_label": SOURCE_LABELS.get(row["kind"], row["kind"]),
            "listed": 0,
            "consequential": 0,
            "bound": 0,
            "unestablished": 0,
        }
        for row in conn.execute(text(_CONNECTIONS), {"t": tenant}).mappings()
    }
    for agent in conn.execute(
        text(
            "SELECT agent_id, connection_id, sponsor_state FROM execbound.monitor_agents "
            "WHERE tenant_id = :t AND gone_at IS NULL"
        ),
        {"t": tenant},
    ).mappings():
        row = sources.get(agent["connection_id"])
        if row is None:
            continue
        found = counts.get(agent["agent_id"], {})
        row["listed"] += 1
        row["consequential"] += bool(found.get("consequential", 0))
        row["bound"] += agent["agent_id"] in bound
        row["unestablished"] += bool(
            unresolved.get(agent["agent_id"])
            or found.get("lapsed", 0)
            or agent["sponsor_state"] in {"unreadable", "not_read"}
        )
    lines = list(sources.values())
    totals = {
        key: sum(row[key] for row in lines)
        for key in ("listed", "consequential", "bound", "unestablished")
    }
    principals = (
        conn.execute(
            text("""
                SELECT count(p.principal_id) FILTER (WHERE p.active) AS active,
                       count(p.principal_id) AS total
                FROM execbound.principals p
                WHERE p.tenant_id = :t AND p.kind = 'AGENT'
            """),
            {"t": tenant},
        )
        .mappings()
        .one()
    )
    # The limit and the count the cap itself makes (#257), inside the request's own fence.
    capacity = agent_capacity(conn, tenant)
    return {
        "sources": lines,
        "totals": totals,
        "profiled": bool(consequential),
        "principals": int(principals["active"]),
        "principals_total": int(principals["total"]),
        "bound": len(bound),
        "agent_limit": capacity.agent_limit,
        "agents_held": capacity.agents_held,
        "agents_dormant": capacity.agents_dormant,
    }


def _consequential(conn: Connection, tenant: UUID) -> list[str]:
    """What Monitoring counts as consequential: the active detection profile's sensitive
    actions, or the built-in set for a synthetic directory with none (#355, step 4)."""
    return monitor_store.consequential_actions(
        conn, tenant, monitor_store._active_profile(conn, tenant)
    )


def agents_overview(
    runtime: Runtime,
    session: Session,
    *,
    state: str = "active",
    active: str = "any",
    population: str = "all",
    source: str = "all",
    ungoverned: str = "any",
    cursor: tuple[bool, str, UUID] | None = None,
) -> dict[str, Any]:
    """One page of agents across the three populations, and the month figure."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        now = store.now(runtime.clock)
        start, end = month_bounds(now)
        space = space_clause(visible_spaces(conn, session), "e")
        rows = [
            dict(row)
            for row in conn.execute(
                text(spaced(_AGENTS, space)),
                {
                    **space.params,
                    "t": identity.tenant_id,
                    "now": now,
                    "month_start": start,
                    "month_end": end,
                    "only": None,
                    "consequential": _consequential(conn, identity.tenant_id),
                    "state": state,
                    "active": active,
                    "population": population,
                    "source": source,
                    "ungoverned": ungoverned,
                    "after": cursor is not None,
                    "after_unnamed": cursor[0] if cursor else None,
                    "after_name": cursor[1] if cursor else None,
                    "after_id": cursor[2] if cursor else None,
                    "limit": PAGE_SIZE + 1,
                },
            ).mappings()
        ]
        figure = len(active_this_month(conn, identity.tenant_id, now))
        line = tenant_line(conn, identity.tenant_id, now)
        asleep = conn.execute(
            text(spaced(_ASLEEP, space)), {**space.params, "t": identity.tenant_id}
        ).scalar_one()
        _admin(conn, runtime, session)
    following = encode_cursor(rows[PAGE_SIZE - 1]) if len(rows) > PAGE_SIZE else None
    for row in rows:
        row["source_label"] = SOURCE_LABELS.get(row["source"] or "", "")
        row["class_label"] = CLASS_LABELS.get(row["identity_class"] or "", "")
    return {
        "agents": rows[:PAGE_SIZE],
        "state": state,
        "active": active,
        "population": population,
        "source": source,
        "ungoverned": ungoverned,
        "next": following,
        "active_month": figure,
        "month": start,
        "line": line,
        "space_dormant": int(asleep),
    }


def action_label(runtime: Runtime, action: str | None) -> str:
    """Catalog label; an action this runtime's catalog lacks reads the way Activity reads it."""
    try:
        return str(runtime.catalog.actions.action(str(action)).label)
    except CatalogError:
        return "unknown action " + str(action)


def reach_rows(
    runtime: Runtime,
    conn: Connection,
    tenant: UUID,
    principal: UUID,
    now: datetime,
    *,
    bundle: BundleContent | None,
    space: UUID,
) -> list[dict[str, Any]]:
    """Configured paths from this agent's selected bundle, plus its historical execution.

    A tenant-wide union of selected bundles would incorrectly lend another Space's
    mappings to this agent. Match the bundle's exact account and mapping versions too.
    This is configuration evidence, not authorization for a particular target.
    """
    modes: dict[str, str] = {}
    scopes: dict[str, list[str]] = {}
    if bundle is not None:
        for mapping in conn.execute(
            text(
                "SELECT om.action, om.resource_type, om.provider, om.account_id, "
                "COALESCE((m->>'external_executor')::boolean, false) AS external_executor "
                "FROM execbound.policy_bundle_contents b "
                "CROSS JOIN LATERAL jsonb_array_elements(b.content->'mappings') AS m "
                "JOIN execbound.operation_mappings om ON om.tenant_id=b.tenant_id "
                "AND om.operation_ref=m->>'operation_ref' "
                "AND om.account_id=(m->>'account_id')::uuid "
                "AND om.mapping_version=m->>'mapping_version' "
                "AND om.schema_version=m->>'schema_version' "
                "AND om.context_contract_version=m->>'context_contract_version' AND om.active "
                "JOIN execbound.connector_accounts ca ON ca.tenant_id=om.tenant_id "
                "AND ca.account_id=om.account_id AND ca.provider=om.provider AND ca.active "
                "WHERE b.tenant_id=:t AND b.bundle_id=:b "
                "AND (ca.space_id=:s OR ca.offered_tenant_wide) "
                "AND NOT COALESCE((m->>'observe_only')::boolean, false) "
                "ORDER BY om.action, om.account_id"
            ),
            {"t": tenant, "b": bundle.bundle_id, "s": space},
        ).mappings():
            action = str(mapping["action"])
            modes[action] = "integrated" if mapping["external_executor"] else "native"
            scopes.setdefault(action, []).append(
                f"{mapping['resource_type']} · {mapping['provider']} · "
                f"account {mapping['account_id']}"
            )
    executed = {
        row.action: row.at
        for row in conn.execute(
            text(_EXECUTED),
            {"t": tenant, "p": principal, "horizon": now - reach.EVIDENCE_VALIDITY},
        )
    }
    rows = []
    for action in sorted(set(modes) | set(executed)):
        at = executed.get(action)
        rows.append(
            {
                "action": action,
                "label": action_label(runtime, action),
                "certainty": "verified" if at is not None else "inferred",
                "mode": modes.get(action, "native"),
                "governed": action in modes,
                "last": at,
                "until": at + reach.EVIDENCE_VALIDITY if at is not None else None,
                "resource_scope": scopes.get(action, []),
            }
        )
    return rows


def window_label(seconds: int) -> str:
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= size and seconds % size == 0:
            count = seconds // size
            return f"{count} {unit}" if count == 1 else f"{count} {unit}s"
    return f"{seconds} second" if seconds == 1 else f"{seconds} seconds"


def limit_rows(
    runtime: Runtime,
    conn: Connection,
    tenant: UUID,
    principal: UUID,
    bundle: BundleContent,
    *,
    space: UUID,
    observe: bool,
    now: datetime,
) -> list[dict[str, Any]]:
    """The rules that bear on this agent, each counted the way admission counts it."""
    groups = {
        row.group_id: row.name
        for row in conn.execute(
            text(
                "SELECT g.group_id, g.name FROM execbound.principal_groups g WHERE g.tenant_id = :t"
            ),
            {"t": tenant},
        )
    }
    member = set(
        conn.execute(
            text(
                "SELECT group_id FROM execbound.principal_group_members "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": principal},
        ).scalars()
    )
    # What the agent's own space is offered, read as admission reads it before any limit
    # (`execution.offered`). Each operation's action is its mapping row's, so a ref written by
    # hand as another name for its action, without saying which, still bears that action's
    # rules; an operation the space cannot use (another space's account, a reference the
    # tenant's mapping no longer matches) bears none, because admission refuses it first. A
    # current operation's account is its row's, which is the reference's.
    accounts = {mapping.operation_ref: mapping.account_id for mapping in bundle.mappings}
    served = [
        (item.action, accounts[item.operation_ref])
        for item in bundle_operations(conn, tenant, space, bundle, catalog=runtime.catalog).offered
    ]
    available = {action for action, _ in served} | set(
        conn.execute(
            text(
                "SELECT DISTINCT action FROM execbound.execution_impact "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": principal},
        ).scalars()
    )
    rows = []
    for rule in bundle.limits:
        if not _bears_on(rule, member, available):
            continue
        if rule.scope == "space" and rule.space_id != space:
            continue
        if rule.scope == "account" and not any(
            account == rule.account_id and action in rule.action_names for action, account in served
        ):
            continue
        counted = rule.scope in ("principal", "tenant", "group")
        row: dict[str, Any] = {
            "rule": rule,
            "scope": limit_label(rule, groups),
            "actions": ", ".join(rule.action_names),
            "labels": ", ".join(action_label(runtime, name) for name in rule.action_names),
            "window": window_label(rule.window_seconds),
            "count": None,
        }
        if counted:
            row["count"] = limit_usage(conn, tenant, principal, rule, observe=observe, now=now)
        rows.append(row)
    return rows


def _bears_on(rule: LimitRule, member: set[UUID], available: set[str]) -> bool:
    if not available & set(rule.action_names):
        return False
    return rule.scope != "group" or rule.group_id in member


def limit_usage(
    conn: Connection,
    tenant: UUID,
    principal: UUID | None,
    rule: LimitRule,
    *,
    observe: bool,
    now: datetime,
) -> int:
    """Retained impact for one rule, counted the way admission counts it.

    The one statement any page's meter reads, so the Agents page and the Policy page can never
    come to disagree about the same rule. ``principal`` is what a `principal`-scoped rule is
    measured for and is ignored by every other scope, so a caller counting tenant-wide passes
    ``None`` and must not ask about a `principal` rule: the statement narrows on no other
    qualifier, which is why `account` and `selector` rules are not counted here either.
    """
    try:
        start = now - timedelta(seconds=rule.window_seconds)
    except OverflowError:
        start = datetime.min.replace(tzinfo=UTC)
    row = (
        conn.execute(
            text(_USAGE),
            {
                "t": tenant,
                "p": principal,
                "actions": list(rule.action_names),
                "scope": rule.scope,
                "group": canonical_json([str(rule.group_id)]) if rule.group_id else None,
                "budget": rule.budget,
                "start": start,
                "now": now,
            },
        )
        .mappings()
        .one()
    )
    return (
        int(row["confirmed"]) + int(row["unresolved"]) + (int(row["projected"]) if observe else 0)
    )


def resolve(runtime: Runtime, session: Session, row_id: UUID) -> tuple[str, UUID]:
    """What an Agents id names: ``("principal", id)``, ``("discovered", id)`` or a
    ``("bound", principal)`` redirect for an agent an active binding already claims."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        is_agent = conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.principals "
                "WHERE tenant_id = :t AND principal_id = :p AND kind = 'AGENT')"
            ),
            {"t": identity.tenant_id, "p": row_id},
        ).scalar_one()
        if is_agent:
            return "principal", row_id
        discovered = conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_agents "
                "WHERE tenant_id = :t AND agent_id = :a)"
            ),
            {"t": identity.tenant_id, "a": row_id},
        ).scalar_one()
        if not discovered:
            raise HTTPException(404, "Not found")
        claimed = bindings.active_binding(conn, identity.tenant_id, agent=row_id)
    if claimed is not None:
        return "bound", claimed["principal_id"]
    return "discovered", row_id


def _discovered(runtime: Runtime, session: Session, agent: UUID) -> dict[str, Any]:
    """Monitoring's own view of a discovered agent, labelled for this page."""
    try:
        detail = monitor_store.agent_detail(runtime.db, session, agent, clock=runtime.clock)
    except MonitorError as exc:
        if exc.code == "AGENT_UNAVAILABLE":
            raise HTTPException(404, "Not found") from None
        raise HTTPException(503, "Monitoring unavailable") from None
    facts = detail["agent"]
    facts["class_label"] = CLASS_LABELS.get(facts["identity_class"], facts["identity_class"])
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        kind = conn.execute(
            text(
                "SELECT kind FROM execbound.monitor_connections "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": identity.tenant_id, "c": facts["connection_id"]},
        ).scalar_one_or_none()
    facts["source_label"] = SOURCE_LABELS.get(kind or "", "")
    for row in detail["reach"]:
        row["label"] = action_label(runtime, row["action"])
    return detail


def _combined_reach(
    discovered: dict[str, Any] | None,
    governed: list[dict[str, Any]],
    binding: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Monitoring's grant, role, inherited and observation rows beside the live ExecBound
    rows, so a bound agent's governed path is never shown twice or out of date."""
    rows: list[dict[str, Any]] = []
    for row in governed:
        rows.append(
            {
                "action": row["action"],
                "label": row["label"],
                "path_kind": "execbound",
                "path": (
                    f"ExecBound, binding {str(binding['binding_id'])[:8]}"
                    if binding
                    else "ExecBound, this agent's credentials"
                ),
                "certainty": row["certainty"],
                "mode": row["mode"] + ("" if row["governed"] else " · no longer mapped"),
                "freshness": (
                    f"last executed {row['last'].isoformat()}, "
                    f"evidence until {row['until'].isoformat()}"
                    if row["until"]
                    else "from the active bundle"
                ),
                "govern": False,
                "rules": row.get("rules", []),
                "resource_scope": row.get("resource_scope", []),
            }
        )
    governed_actions = {row["action"] for row in governed}
    for row in (discovered or {}).get("reach", []):
        if row["path_kind"] == "execbound" or row["gone_at"] is not None:
            continue
        rows.append(
            {
                "action": row["action"],
                "label": row["label"],
                "path_kind": row["path_kind"],
                "path": f"{row['path_kind']} {row['path_ref']}",
                "certainty": row["effective"],
                "mode": row["enforcement_mode"],
                "freshness": f"valid until {row['valid_until'].isoformat()}",
                "govern": row["path_kind"] in ("grant", "role", "inherited")
                and row["action"] not in governed_actions,
                "rules": [],
            }
        )
    return sorted(rows, key=lambda row: (row["action"], row["path_kind"], row["path"]))


def agent_overview(runtime: Runtime, session: Session, principal: UUID) -> dict[str, Any]:
    """One governed agent: identity, binding, credentials, reach, activity and limits."""
    identity = session.identity
    tenant = identity.tenant_id
    with runtime.db.transaction(tenant) as conn:
        _admin(conn, runtime, session)
        now = store.now(runtime.clock)
        params: dict[str, Any] = {"t": tenant, "p": principal, "limit": LIST_LIMIT}
        agent = (
            conn.execute(
                text(
                    "SELECT principal_id, number, active, label, created_at, deactivated_at, "
                    "dormant_at IS NOT NULL AS dormant, "
                    "space_id FROM execbound.principals "
                    "WHERE tenant_id = :t AND principal_id = :p AND kind = 'AGENT'"
                ),
                params,
            )
            .mappings()
            .one_or_none()
        )
        # Membership is the authority and the current space is only a view: an agent in another
        # of the person's own spaces is answered, and one in a space they do not belong to is 404
        # whatever the session holds.
        if agent is None or not visible_spaces(conn, session).allows(agent["space_id"]):
            raise HTTPException(404, "Not found")
        credentials = []
        for row in conn.execute(
            text(_CREDENTIALS), {**params, "now": now, "since": now - FAILURE_WINDOW}
        ).mappings():
            if row["revoked_at"] is not None:
                state = "revoked"
            elif row["expires_at"] <= now:
                state = "expired"
            else:
                state = "live"
            credentials.append({**row, "state": state, "failures": int(row["failures"])})
        # The one notice the agent's Overview shows, by Home's own rule.
        expiring, _ = expiring_rows(conn, session, now, principal=principal, limit=1)
        recent = [
            {**row, "label": action_label(runtime, row["action"])}
            for row in conn.execute(text(_RECENT), {**params, "limit": RECENT}).mappings()
        ]
        runs = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT run_id, issued_at, expires_at FROM execbound.agent_runs "
                    "WHERE tenant_id = :t AND principal_id = :p AND expires_at > :now "
                    "ORDER BY issued_at DESC, run_id LIMIT :limit"
                ),
                {**params, "now": now, "limit": RECENT + 1},
            ).mappings()
        ]
        groups = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT g.group_id, g.name FROM execbound.principal_group_members m "
                    "JOIN execbound.principal_groups g "
                    "ON g.tenant_id = m.tenant_id AND g.group_id = m.group_id "
                    "WHERE m.tenant_id = :t AND m.principal_id = :p ORDER BY g.name LIMIT :limit"
                ),
                params,
            ).mappings()
        ]
        requests = active_this_month(conn, tenant, now, only=principal).get(principal, 0)
        observe = store.enforcement_mode(conn, tenant) == "OBSERVE"
        try:
            # The agent's own space selects the bundle its limits are read from.
            bundle: BundleContent | None = store.active_bundle(conn, tenant, agent["space_id"])
        except ExecutionError:
            bundle = None
        limits = (
            limit_rows(
                runtime,
                conn,
                tenant,
                principal,
                bundle,
                space=agent["space_id"],
                observe=observe,
                now=now,
            )
            if bundle is not None
            else []
        )
        governed = reach_rows(
            runtime, conn, tenant, principal, now, bundle=bundle, space=agent["space_id"]
        )
        ruleset = bundle.ruleset if bundle is not None else None
        rules_origin = "rules" if ruleset is not None else None
        if bundle is not None and ruleset is None:
            # A seed bundle written as Cedar reads as the rules it was made from, as the policy
            # page reads it: only the recogniser's fingerprint lookup runs, no compilation.
            from execbound.surfaces.console_api.policy_starters import source_rules

            try:
                ruleset = source_rules(bundle, runtime.catalog)
            except (ValueError, KeyError):
                ruleset = None
            rules_origin = "recognized-seed" if ruleset is not None else None
        if ruleset is not None:
            # As the rules read, per action: the reading is the compiler's input, the
            # decision on any one target is the kernel's from the compiled bundle. The
            # effect and the identity stay apart so a page can name the rule and link to
            # it without taking a name back out of a sentence.
            for governed_row in governed:
                governed_row["rules"] = [
                    {"id": rule.id, "effect": rule.effect.lower(), "description": sentence(rule)}
                    for rule in rules_for(ruleset, governed_row["action"])
                ]
        # Whether this reader may change the agent: an administrator seated as an approver in
        # another space reads that space's agents and administers none of them (0072).
        agents = administered_clause(conn, session, "p")
        administered = bool(
            conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM execbound.principals p "
                    "WHERE p.tenant_id = :t AND p.principal_id = :p"
                    + agents.sql  # nosec B608 - one helper's predicate; values are bound
                    + ")"
                ),
                {**params, **agents.params},
            ).scalar_one()
        )
        binding = conn.execute(text(_BINDING_OF_PRINCIPAL), params).mappings().one_or_none()
        # Who bound it, by kind and number, for the id the binding names (#678).
        binder = (
            principal_facts(conn, tenant, [binding["bound_by"]]).get(binding["bound_by"])
            if binding is not None and binding["bound_by"] is not None
            else None
        )
        space_name = conn.execute(
            text("SELECT name FROM execbound.spaces WHERE tenant_id=:t AND space_id=:s"),
            {"t": tenant, "s": agent["space_id"]},
        ).scalar_one()
        bundle_space = (
            conn.execute(
                text(
                    "SELECT space_id FROM execbound.policy_bundle_contents "
                    "WHERE tenant_id=:t AND bundle_id=:b"
                ),
                {"t": tenant, "b": bundle.bundle_id},
            ).scalar_one()
            if bundle is not None
            else None
        )
        options = (
            [
                {**row, "class_label": CLASS_LABELS.get(row["identity_class"], "")}
                for row in conn.execute(
                    text(_UNBOUND_AGENTS), {"t": tenant, "limit": OPTIONS_LIMIT}
                ).mappings()
            ]
            if binding is None and agent["active"]
            else []
        )
        _admin(conn, runtime, session)
    discovered = _discovered(runtime, session, binding["agent_id"]) if binding else None
    return {
        "agent": dict(agent),
        "credentials": credentials,
        "expiring_key": expiring[0] if expiring else None,
        "recent": recent,
        "runs": runs[:RECENT],
        "more_runs": len(runs) > RECENT,
        "groups": groups,
        "requests": requests,
        "month": month_bounds(now)[0],
        "bundle": bundle is not None,
        "observe": observe,
        "limits": limits,
        "binding": {**dict(binding), "bound_by_facts": binder} if binding else None,
        "discovered": discovered,
        "reach": _combined_reach(discovered, governed, dict(binding) if binding else None),
        "by_rules": ruleset is not None,
        # The bundle the rule names above belong to, so a page can send a reader to the rules
        # themselves. None whenever there is no ruleset to name, which is the same condition
        # as `by_rules`, read from the bundle already in hand rather than from a second query.
        "rules_bundle_id": bundle.bundle_id if bundle is not None and ruleset is not None else None,
        "space": {"space_id": agent["space_id"], "name": space_name},
        "permissions_bundle_id": bundle.bundle_id if bundle is not None else None,
        # The exact documents whenever the bundle was not written as rules, a recognised seed
        # included, so its text is kept beside the rules it reads as.
        "policy_document": document_reading(bundle.authorization_policies, bundle.approval_policies)
        if bundle is not None and bundle.ruleset is None
        else None,
        "rules_origin": rules_origin,
        "administered": administered,
        "permissions_inherited": bundle_space is not None and bundle_space != agent["space_id"],
        "options": options,
        "now": now,
    }


def discovered_overview(runtime: Runtime, session: Session, agent: UUID) -> dict[str, Any]:
    """One discovered agent no binding claims: what Monitoring knows, and how to govern it."""
    discovered = _discovered(runtime, session, agent)
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        options = [
            dict(row)
            for row in conn.execute(
                text(_UNBOUND_PRINCIPALS), {"t": identity.tenant_id, "limit": OPTIONS_LIMIT}
            ).mappings()
        ]
        _admin(conn, runtime, session)
    return {
        "agent": None,
        "binding": None,
        "discovered": discovered,
        "reach": _combined_reach(discovered, [], None),
        "by_rules": False,
        "rules_bundle_id": None,
        "options": options,
    }


def create_agent(runtime: Runtime, session: Session, label: str) -> UUID:
    """A new agent with a label, two functions and two events in one transaction."""
    screened_label(label)
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        principal = _create_labelled(conn, session, label)
        _admin(conn, runtime, session)
    return principal


def _create_labelled(conn: Connection, session: Session, label: str) -> UUID:
    identity = session.identity
    actor = {"actor": identity.principal_id}
    # An agent is owned by one space: the one the administrator is looking at, or the
    # tenant's only one. Nothing the request carries names it.
    space = _space_to_write(conn, session)
    principal = _call(
        conn,
        "SELECT execbound.admin_create_principal(:actor, :kind, :space)",
        {**actor, "kind": "AGENT", "space": space},
    )
    append_event(
        conn,
        identity.tenant_id,
        identity.principal_id,
        "principal.created",
        {
            "principal_id": str(principal),
            "kind": "AGENT",
            **acted_with(session.identity.credential_id),
        },
    )
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
            **acted_with(session.identity.credential_id),
        },
    )
    return UUID(str(principal))


def bind_agent(runtime: Runtime, session: Session, *, agent: UUID, principal: UUID) -> None:
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        bindings.bind(conn, identity, agent, principal)
        _admin(conn, runtime, session)


def unbind_agent(runtime: Runtime, session: Session, principal: UUID, reason: str) -> None:
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        binding = (
            conn.execute(
                text(_BINDING_OF_PRINCIPAL),
                {"t": identity.tenant_id, "p": principal},
            )
            .mappings()
            .one_or_none()
        )
        if binding is None:
            raise AdministrationError("INVALID_STATE")
        bindings.unbind(conn, identity, binding["binding_id"], reason)
        _admin(conn, runtime, session)


def govern(
    runtime: Runtime, session: Session, agent: UUID, lifetime: timedelta | None
) -> IssuedSecret:
    """Create the principal, label it, bind it and issue its credential, all or nothing.

    The label is the source's display name, trimmed and cut to the 80 characters a label
    holds, unless that name is shaped like a credential: refusing provider-confirmed text
    would stop the agent being governed at all, so a credential-shaped name becomes the
    fallback label `Unnamed agent` instead (the discovered agent's own display name is
    untouched). A refusal at any step rolls every earlier one back, events included. A
    `lifetime` of `None` issues the agent's API key to never expire.
    """
    identity = session.identity
    if lifetime is not None and lifetime not in {value for value, _ in LIFETIMES.values()}:
        raise AdministrationError("INVALID_LIFETIME")
    now = store.now(runtime.clock)
    expires_at = NEVER if lifetime is None else now + lifetime
    credential = uuid4()
    token, digest = new_token(identity.tenant_id, credential)
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        name = conn.execute(
            text(
                "SELECT display_name FROM execbound.monitor_agents "
                "WHERE tenant_id = :t AND agent_id = :a"
            ),
            {"t": identity.tenant_id, "a": agent},
        ).scalar_one_or_none()
        if name is None:
            raise AdministrationError("INVALID_AGENT")
        if secret_shaped(name):
            # The display name is the identity provider's own text, not something a person
            # typed here: refusing it would stop the agent being governed at all, so a
            # credential-shaped name is replaced by a safe label instead of being refused.
            name = "Unnamed agent"
        principal = _create_labelled(conn, session, str(name).strip()[:LABEL_LIMIT].strip())
        bindings.bind(conn, identity, agent, principal)
        issued_kind = _call(
            conn,
            "SELECT execbound.admin_issue_credential("
            ":actor, :principal, :credential, :digest, :issued, :expires)",
            {
                "actor": identity.principal_id,
                "principal": principal,
                "credential": credential,
                "digest": digest,
                "issued": now,
                "expires": expires_at,
            },
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
                **acted_with(session.identity.credential_id),
            },
        )
        number = key_number(conn, identity.tenant_id, credential)
        _admin(conn, runtime, session)
    return IssuedSecret(token, credential, principal, str(issued_kind), expires_at, number)


def require_agent(
    runtime: Runtime,
    session: Session,
    principal: UUID,
    credential: UUID | None = None,
    *,
    administered: bool = True,
) -> None:
    """404 unless ``principal`` is an AGENT of this tenant (holding ``credential``, if given)
    in a space this administrator administers.

    A principal's kind and a credential's holder never change, so reading them before the
    write's own transaction cannot race. Without this, a form under ``/agents`` could label
    or deactivate a person the Agents page never shows. Since 0072 an administrator narrowed
    to spaces administers only the agents of spaces where their membership is `ADMIN`, so
    another space's agent is answered as one that does not exist, before the change runs
    rather than after it; the definer function refuses it again in its own statement.
    ``administered=False`` asks only whether it is an agent of this tenant.
    """
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        agents = administered_clause(conn, session, "p") if administered else NO_SPACE_FILTER
        found = conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.principals p "
                "WHERE p.tenant_id = :t AND p.principal_id = :p AND p.kind = 'AGENT' "
                "AND (CAST(:c AS uuid) IS NULL OR EXISTS (SELECT 1 FROM execbound.credentials c "
                "WHERE c.tenant_id = p.tenant_id AND c.principal_id = p.principal_id "
                "AND c.credential_id = CAST(:c AS uuid)))"
                + agents.sql  # nosec B608 - one helper's predicate; values are bound
                + ")"
            ),
            {"t": identity.tenant_id, "p": principal, "c": credential, **agents.params},
        ).scalar_one()
    if not found:
        raise HTTPException(404, "Not found")
