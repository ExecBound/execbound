# SPDX-License-Identifier: AGPL-3.0-only
"""`GET /api/console/v1/search?q=`: the records the command palette lists.

Targets by hostname, alias or provider id; requests by handle, external case ID and
execution/approval/delivery UUID prefix; agents by label, by their number ("agent 2") or by
their id prefix; people by label, number ("user 3") or id prefix (#678). At most twenty
results, scoped as the pages are: an approver's targets, executions and approvals are the ones
their active scopes admit, through the same scope clause the listings use; agents are an
administrator's alone because the Agents page is, inside the space view; and people are an
administrator's holding `access.manage` alone because the Users page is, across the workspace
because people belong to it rather than to a space. A person is never found by email: a
sign-in address stays on the people page. The query is a bounded string compared with `LIKE`
under its own escape; nothing here assembles query text from it. Every label and detail
travels as data.
"""

import re
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from execbound.access_control import has_permission
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.runtime import Runtime
from execbound.spaces import space_clause, space_names, visible_spaces
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.executions import STATE_WORDS
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.dashboard import action_label
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.names import principal_handle, principal_name
from execbound.surfaces.sessions import Session, check_session

QUERY_MAX = 80
RESULTS = 20
Kind = Literal["approval", "execution", "target", "agent", "person"]
_IDENTIFIER = re.compile(r"^[0-9a-f][0-9a-f-]{3,35}$")
# "agent 2", "Agent #2": the workspace's counting number, lower-cased and stripped first.
_AGENT_NUMBER = re.compile(r"^agent\s*#?(\d{1,9})$")
_USER_NUMBER = re.compile(r"^user\s*#?(\d{1,9})$")

# Each statement is written whole, with its scope clause inline, as the dashboard's reads are:
# a statement assembled from fragments cannot be read at the point it is sent, and the scope
# clause is the part that must be read.
_APPROVALS = (
    "SELECT a.approval_id, a.state AS approval_state, a.expires_at, e.execution_id, e.state, "
    "e.space_id, e.request_number, "
    "e.frozen -> 'intent' ->> 'action' AS action, "
    "e.frozen ->> 'resource_provider_id' AS provider_id "
    "FROM execbound.approvals a JOIN execbound.executions e "
    "ON e.tenant_id=a.tenant_id AND e.execution_id=a.execution_id "
    "WHERE a.tenant_id=:t AND CAST(a.approval_id AS text) LIKE :prefix "
    "AND (EXISTS (SELECT 1 FROM execbound.effective_approval_scopes s "
    "WHERE s.tenant_id=e.tenant_id AND s.approver_id=:p AND s.active "
    "AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/ "
    "ORDER BY a.created_at DESC, a.approval_id LIMIT :limit"
)
_EXECUTIONS = (
    "SELECT e.execution_id, e.state, e.created_at, e.space_id, e.request_number, "
    "e.frozen -> 'intent' ->> 'action' AS action, "
    "e.frozen ->> 'resource_provider_id' AS provider_id "
    "FROM execbound.executions e "
    "WHERE e.tenant_id=:t AND (CAST(e.execution_id AS text) LIKE :prefix "
    "OR ('eb-' || e.request_number)=:term "
    "OR lower(e.frozen->'request'->'external_case'->>'case_id')=:term "
    "OR EXISTS (SELECT 1 FROM execbound.approvals a "
    "JOIN execbound.approval_notifications n "
    "ON n.tenant_id=a.tenant_id AND n.approval_id=a.approval_id "
    "WHERE a.tenant_id=e.tenant_id AND a.execution_id=e.execution_id "
    "AND CAST(n.notification_id AS text) LIKE :prefix)) "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) "
    "OR EXISTS (SELECT 1 FROM execbound.effective_approval_scopes s "
    "WHERE s.tenant_id=e.tenant_id AND s.approver_id=:p AND s.active "
    "AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/ "
    "ORDER BY e.created_at DESC, e.execution_id LIMIT :limit"
)
# A target is a resource with a canonical identity; its hostname is its current alias of
# that kind, if any. An approver's targets are the ones an active scope names, for any action.
_TARGETS = (
    "SELECT i.canonical_target_id, r.provider_id, r.resource_type, r.role, r.environment, "
    "r.active, (SELECT al.normalized_value FROM execbound.resource_aliases al "
    "WHERE al.tenant_id=r.tenant_id AND al.account_id=r.account_id AND al.provider=r.provider "
    "AND al.resource_type=r.resource_type AND al.resource_id=r.resource_id "
    "AND al.kind='hostname' AND al.valid_from <= :now AND al.expires_at > :now "
    "ORDER BY al.valid_from DESC LIMIT 1) AS hostname "
    "FROM execbound.resources r JOIN execbound.resource_identities i "
    "ON i.tenant_id=r.tenant_id AND i.account_id=r.account_id AND i.provider=r.provider "
    "AND i.resource_type=r.resource_type AND i.resource_id=r.resource_id "
    "JOIN execbound.connector_accounts c ON c.tenant_id=r.tenant_id AND c.account_id=r.account_id "
    "WHERE r.tenant_id=:t AND (lower(r.provider_id) LIKE :like ESCAPE '\\' "
    "OR EXISTS (SELECT 1 FROM execbound.resource_aliases al "
    "WHERE al.tenant_id=r.tenant_id AND al.account_id=r.account_id AND al.provider=r.provider "
    "AND al.resource_type=r.resource_type AND al.resource_id=r.resource_id "
    "AND al.valid_from <= :now AND al.expires_at > :now "
    "AND al.normalized_value LIKE :like ESCAPE '\\')) "
    "AND (NOT :scoped OR c.space_id=ANY(CAST(:read_spaces AS uuid[])) "
    "OR (c.offered_tenant_wide AND cardinality(CAST(:read_spaces AS uuid[]))>0) "
    "OR EXISTS (SELECT 1 FROM execbound.effective_approval_scopes s "
    "WHERE s.tenant_id=r.tenant_id AND s.approver_id=:p AND s.active "
    "AND (CAST(:current_space AS uuid) IS NULL OR s.space_id=:current_space) "
    "AND s.canonical_target_id=i.canonical_target_id))/*space*/ "
    "ORDER BY r.provider_id, i.canonical_target_id LIMIT :limit"
)
_AGENTS = (
    "SELECT e.principal_id, e.label, e.number, e.active, e.space_id FROM execbound.principals e "
    "WHERE e.tenant_id=:t AND e.kind='AGENT' "
    "AND ((e.label IS NOT NULL AND lower(e.label) LIKE :contains ESCAPE '\\') "
    "OR e.number = CAST(:agent_number AS integer) "
    "OR (:identifier AND CAST(e.principal_id AS text) LIKE :prefix))/*space*/ "
    "ORDER BY e.label NULLS LAST, e.number, e.principal_id LIMIT :limit"
)
# People belong to the workspace, not to a space, so this statement has no space clause, as
# the people page has none; it never reads or matches an email.
_PEOPLE = (
    "SELECT e.principal_id, e.kind, e.label, e.number, e.active FROM execbound.principals e "
    "WHERE e.tenant_id=:t AND e.kind IN ('ADMIN', 'HUMAN_APPROVER') "
    "AND ((e.label IS NOT NULL AND lower(e.label) LIKE :contains ESCAPE '\\') "
    "OR e.number = CAST(:user_number AS integer) "
    "OR (:identifier AND CAST(e.principal_id AS text) LIKE :prefix)) "
    "ORDER BY e.label NULLS LAST, e.number, e.principal_id LIMIT :limit"
)


def scoped_to(statement: str, filter_sql: str) -> str:
    """One statement with the one helper's predicate where it was written for."""
    return statement.replace("/*space*/", filter_sql)  # nosec B608 - literals only


class SearchResult(BaseModel):
    kind: Kind
    id: UUID
    label: str
    detail: str
    state: str | None
    state_label: str | None
    # The space a row belongs to, named only when the reader can see more than one: two
    # of an MSSP's customers may both have a host called `WS-001`. A tenant with one space
    # sends `null` on every row and the console shows nothing.
    space_name: str | None = None
    # The record an approval or an execution opens in the drawer; a target and an agent open
    # Activity narrowed to them instead, and a person opens their page.
    execution_id: UUID | None


class SearchView(BaseModel):
    query: str
    results: list[SearchResult]


def _number(pattern: re.Pattern[str], term: str) -> int | None:
    found = pattern.fullmatch(term)
    return int(found.group(1)) if found else None


def _detail(kind: str, row: Any) -> str:
    """ "Agent 3" or "User 3" when a label is shown, else the noun; ", deactivated" after it."""
    noun = "Agent" if kind == "AGENT" else "User"
    shown = principal_handle(kind, row["number"]) if row["label"] else noun
    return shown + ("" if row["active"] else ", deactivated")


def escaped(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search(runtime: Runtime, session: Session, query: str) -> list[SearchResult]:
    """Bounded, scoped reads for one term; the identity and the session are rechecked."""
    identity = session.identity
    term = query.strip().lower()
    results: list[SearchResult] = []
    with runtime.db.transaction(identity.tenant_id) as conn:
        if identity.kind not in {"HUMAN_APPROVER", "ADMIN"}:
            raise ExecutionError("INVALID_IDENTITY")
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        store.fence(conn, identity.tenant_id, runtime.clock)
        check_session(conn, session, runtime.clock)
        from execbound.access_control import review_read_spaces, review_scoped

        scoped = review_scoped(conn, identity)
        # The visible set, inside the fence. `/search` answers within the current space,
        # and each row names its space whenever the reader can see more than one, because
        # two of an MSSP's customers may both have a host called `WS-001`.
        visibility = visible_spaces(conn, session)
        space = space_clause(visibility, "e")
        account_space = space_clause(visibility, "c", offered=True)
        # A row names its space only when the reader can see more than one: two of an
        # MSSP's customers may both have a host called `WS-001`, and a tenant with one
        # space has nothing to disambiguate.
        names = space_names(conn, identity.tenant_id)
        if len(names) < 2 or not visibility.allows_many(len(names)):
            names = {}
        params: dict[str, Any] = {
            **space.params,
            "t": identity.tenant_id,
            "p": identity.principal_id,
            "scoped": scoped,
            "read_spaces": [
                space
                for space in review_read_spaces(conn, identity)
                if visibility.current is None or space == visibility.current
            ],
            "current_space": visibility.current,
            "now": runtime.clock.now(),
            "like": escaped(term) + "%",
            "contains": "%" + escaped(term) + "%",
            "prefix": escaped(term) + "%",
            "term": term,
            "limit": RESULTS,
            "identifier": bool(_IDENTIFIER.match(term)),
            "agent_number": _number(_AGENT_NUMBER, term),
            "user_number": _number(_USER_NUMBER, term),
        }
        if _IDENTIFIER.match(term):
            for row in conn.execute(text(scoped_to(_APPROVALS, space.sql)), params).mappings():
                word = STATE_WORDS.get(str(row["state"]), str(row["state"]))
                results.append(
                    SearchResult(
                        kind="approval",
                        id=row["approval_id"],
                        label=f"Approval: {action_label(str(row['action']))} on "
                        f"{row['provider_id']}",
                        detail=f"EB-{row['request_number']}; {word}; "
                        f"approval {str(row['approval_state']).lower()}",
                        state=str(row["state"]),
                        state_label=word,
                        execution_id=row["execution_id"],
                        space_name=names.get(row["space_id"]),
                    )
                )
        for row in conn.execute(text(scoped_to(_EXECUTIONS, space.sql)), params).mappings():
            results.append(
                SearchResult(
                    kind="execution",
                    id=row["execution_id"],
                    label=f"{action_label(str(row['action']))} on {row['provider_id']}",
                    detail=f"Request EB-{row['request_number']}",
                    state=str(row["state"]),
                    state_label=STATE_WORDS.get(str(row["state"]), str(row["state"])),
                    execution_id=row["execution_id"],
                    space_name=names.get(row["space_id"]),
                )
            )
        for row in conn.execute(text(scoped_to(_TARGETS, account_space.sql)), params).mappings():
            parts = [str(row["resource_type"])]
            if row["role"]:
                parts.append(str(row["role"]))
            if row["environment"]:
                parts.append(str(row["environment"]))
            if not row["active"]:
                parts.append("inactive")
            results.append(
                SearchResult(
                    kind="target",
                    id=row["canonical_target_id"],
                    label=str(row["hostname"] or row["provider_id"]),
                    detail=(f"{row['provider_id']}; " if row["hostname"] else "")
                    + ", ".join(parts),
                    state=None,
                    state_label=None,
                    execution_id=None,
                )
            )
        if identity.kind == "ADMIN":
            for row in conn.execute(text(scoped_to(_AGENTS, space.sql)), params).mappings():
                results.append(
                    SearchResult(
                        kind="agent",
                        id=row["principal_id"],
                        label=principal_name(
                            "AGENT", row["label"], row["number"], row["principal_id"]
                        ),
                        detail=_detail("AGENT", row),
                        state=None,
                        state_label=None,
                        execution_id=None,
                        space_name=names.get(row["space_id"]),
                    )
                )
            # The palette offers a person only to someone who can open the Users page.
            if has_permission(conn, identity.tenant_id, identity.principal_id, "access.manage"):
                for row in conn.execute(text(_PEOPLE), params).mappings():
                    results.append(
                        SearchResult(
                            kind="person",
                            id=row["principal_id"],
                            label=principal_name(
                                str(row["kind"]), row["label"], row["number"], row["principal_id"]
                            ),
                            detail=_detail(str(row["kind"]), row),
                            state=None,
                            state_label=None,
                            execution_id=None,
                        )
                    )
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
    return results[:RESULTS]


def search_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/search", response_model=SearchView, operation_id="search")
    async def search_records(request: Request, q: str | None = None) -> SearchView:
        session, _ = await guards.session(request, query=frozenset({"q"}))
        query = request.query_params.get("q", "")
        if not 1 <= len(query.strip()) <= QUERY_MAX:
            raise ApiError("INVALID_REQUEST")
        results = await run_in_threadpool(search, runtime, session, query)
        return SearchView(query=query.strip(), results=results)
