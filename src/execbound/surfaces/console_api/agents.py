# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/agents`: the Agents page's functions, answered as JSON.

Every route wraps the function the Agents page calls today (`surfaces/agents_pages.py`), under
the same authority (an administrator's session), the same fence and the same bounds: the list
is the page's own query with its cursor at fifty, the detail resolves an id the way the page
does (a principal, a discovered agent, or a bound agent answered with its principal), and every
change goes through the one write path each fact already has. `Govern this agent` is the page's
own composition, all or nothing in one transaction, and the credential it issues comes back
once in the response that created it (#333).
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound.administration import AdministrationError
from execbound.runtime import Runtime
from execbound.surfaces import agents_pages as pages
from execbound.surfaces.admin_pages import delete, issue, revoke
from execbound.surfaces.console_api.credentials import ExpiringKey
from execbound.surfaces.console_api.directory import (
    UUID_PATTERN,
    AgentKeyBody,
    Created,
    CredentialRow,
    Empty,
    IssuedCredential,
    KeyLifetimeBody,
    LabelBody,
    ReasonBody,
    admin,
    body_of,
    credential_rows,
    filters_from,
    issued_view,
    key_lifetime_of,
    parse_uuid,
    query_parameters,
    refused,
)
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.principals import PrincipalRef, principal_ref
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.people_pages import deactivate, label_person, reactivate
from execbound.surfaces.recipes import render_recipe
from execbound.surfaces.sessions import Session

FILTERS: dict[str, tuple[str, ...]] = {
    "state": pages.STATES,
    "active": pages.ACTIVE,
    "population": pages.POPULATIONS,
    "source": pages.SOURCES,
    "ungoverned": pages.UNGOVERNED,
}
Population = Literal["bound", "governed", "discovered"]
Certainty = Literal["verified", "inferred", "unknown"]
PREFIX = 8


class Sponsor(BaseModel):
    kind: str
    ref: str


class AgentRow(BaseModel):
    row_id: UUID
    population: Population
    principal_id: UUID | None
    agent_id: UUID | None
    name: str | None
    # A governed agent's counting number in its workspace (0058); `None` for a discovered one.
    number: int | None
    active: bool | None
    # Dormancy (#439): whether this AGENT principal is asleep (`dormant_at IS NOT NULL`),
    # `None` for a discovered-only row exactly as `active` is. Distinct from `active` because
    # a sleeping agent still counts against the cap and a hand-deactivated one does not; the
    # page must tell them apart rather than show "Deactivated" for both.
    dormant: bool | None
    source: str | None
    source_label: str
    identity_class: str | None
    class_label: str
    enabled: bool | None
    gone_at: datetime | None
    last_seen: datetime | None
    sponsors: list[Sponsor]
    sponsor_state: str | None
    live: int
    requests: int
    last_request: datetime | None
    # The newest request in view and its reference, so Getting started links the record.
    last_execution_id: UUID | None
    last_request_ref: str | None
    consequential: int
    governed_paths: int
    lapsed: int
    findings: int


class SourceLine(BaseModel):
    connection_id: UUID
    label: str
    kind: str
    source_label: str
    active: bool
    last_sync_at: datetime | None
    health_state: str | None
    listed: int
    consequential: int
    bound: int
    unestablished: int


class LineTotals(BaseModel):
    listed: int
    consequential: int
    bound: int
    unestablished: int


class TenantLine(BaseModel):
    sources: list[SourceLine]
    totals: LineTotals
    profiled: bool
    principals: int
    principals_total: int
    bound: int
    # The workspace's agent limit (`tenants.max_agents`, #257), `None` when it has none;
    # `agents_held` counts live and sleeping AGENT principals exactly as the cap does, and
    # `agents_dormant` is the sleeping subset of that count.
    agent_limit: int | None
    agents_held: int
    agents_dormant: int


class AgentsPage(BaseModel):
    agents: list[AgentRow]
    next: str | None
    active_month: int
    month: datetime
    line: TenantLine
    # The asleep agents of the Space this list is read under, whatever the filters (#439):
    # the default State hides them, so the console tells a Space whose agents all sleep from a
    # Space with none by this, where `line.agents_dormant` is the whole workspace's.
    space_dormant: int


class GovernedFacts(BaseModel):
    principal_id: UUID
    # The agent's counting number in its workspace (0058), "Agent 3" where it has no label.
    number: int | None = None
    active: bool
    # Dormancy (#439): asleep after a long silence, distinct from `deactivated_at`
    # (a person turned it off by hand); the two are never both set. The detail page must
    # show which one this is, not just that the agent is inactive.
    dormant: bool
    label: str | None
    created_at: datetime | None
    deactivated_at: datetime | None


class Binding(BaseModel):
    binding_id: UUID
    agent_id: UUID
    principal_id: UUID
    bound_by: UUID | None
    bound_at: datetime
    # The person who bound it, by kind and number (#678).
    bound_by_ref: PrincipalRef | None


class DiscoveredFacts(BaseModel):
    agent_id: UUID
    platform_ref: str
    identity_class: str
    class_label: str
    source_label: str
    display_name: str
    enabled: bool
    blueprint_ref: str | None
    credential_kinds: list[str]
    sponsors: list[Sponsor]
    sponsor_state: str
    first_seen_at: datetime
    observed_at: datetime
    gone_at: datetime | None


class Finding(BaseModel):
    finding_id: UUID
    rule_version: str
    title: str
    created_at: datetime
    acknowledged_at: datetime | None


class Observation(BaseModel):
    occurred_at: datetime
    kind: str
    action: str | None
    outcome: str | None


class Discovered(BaseModel):
    agent: DiscoveredFacts
    findings: list[Finding]
    observations: list[Observation]


class RuleName(BaseModel):
    """One rule of the active bundle's ruleset about this action: its effect and its name.

    The two stay apart so the page can print the effect as a word and link the name to the
    rules page, rather than build a link out of a sentence. Empty for a path the rules do not
    reach, and for every row of a bundle written as a document.
    """

    id: str
    effect: str
    description: str | None = None


class ReachRow(BaseModel):
    action: str
    label: str
    path_kind: str
    path: str
    certainty: Certainty
    mode: str
    freshness: str
    govern: bool
    rules: list[RuleName]
    resource_scope: list[str] = Field(default_factory=list)


class RecentRow(BaseModel):
    execution_id: UUID
    action: str | None
    label: str
    canonical_target_id: UUID | None
    state: str
    created_at: datetime
    # "EB-<n>", the reference a person reads the record by.
    request_ref: str
    # The target's provider identifier, agent text rendered as text; null with no resource.
    target_label: str | None = None


class RunRow(BaseModel):
    run_id: UUID
    issued_at: datetime
    expires_at: datetime


class GroupRow(BaseModel):
    group_id: UUID
    name: str


class LimitRow(BaseModel):
    scope: str
    budget: str
    actions: str
    labels: str
    window: str
    count: int | None
    max_targets: int
    on_exceed: str


class BindOption(BaseModel):
    """What the other side of a binding can be: an agent for a principal, or the reverse."""

    id: UUID
    name: str | None
    detail: str


class AgentSpace(BaseModel):
    space_id: UUID
    name: str


class PolicyDocumentRule(BaseModel):
    id: str
    effect: str
    description: str | None


class PolicyDocument(BaseModel):
    authorization_policies: str
    approval_policies: str
    complete: bool
    rules: list[PolicyDocumentRule]


class AgentDetail(BaseModel):
    row_id: UUID
    kind: Literal["principal", "discovered"]
    agent: GovernedFacts | None
    binding: Binding | None
    discovered: Discovered | None
    credentials: list[CredentialRow]
    # The agent's soonest used key that expires within seven days, unless a live key
    # replaces it: the notice on its Overview, by the same rule as Home's.
    expiring_key: ExpiringKey | None = None
    recent: list[RecentRow]
    runs: list[RunRow]
    more_runs: bool
    groups: list[GroupRow]
    requests: int
    month: datetime | None
    bundle: bool
    observe: bool
    limits: list[LimitRow]
    reach: list[ReachRow]
    # The bundle whose rules the reach rows name, when the active bundle was written as
    # rules; None otherwise, and then no row carries a rule.
    rules_bundle_id: UUID | None
    space: AgentSpace | None = None
    permissions_bundle_id: UUID | None = None
    # Shared bundle provenance, not a claim about group-derived agent authority.
    permissions_inherited: bool = False
    policy_document: PolicyDocument | None = None
    # Where the rule ids link: the rules form for a bundle written as rules, the bundle page
    # for a seed written as Cedar that reads as rules; null when no rule is named.
    rules_origin: Literal["rules", "recognized-seed"] | None = None
    # Whether this reader may change the agent; one who only sees it is offered no change.
    administered: bool = True
    options: list[BindOption]


class BindBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(pattern=UUID_PATTERN)


class NextSteps(BaseModel):
    install: str
    mcp: str


class Governed(IssuedCredential):
    """The credential `Govern this agent` issued, with what to do next; the secret is above
    the recipes and never inside them."""

    next_steps: NextSteps


def _sponsors(value: Any) -> list[Sponsor]:
    """Sponsors as object id prefixes, never names, exactly as the page shows them."""
    if not isinstance(value, list):
        return []
    return [
        Sponsor(kind=str(item.get("kind", "")), ref=str(item.get("ref", ""))[:PREFIX])
        for item in value
        if isinstance(item, dict)
    ]


def _row(row: dict[str, Any]) -> AgentRow:
    return AgentRow(
        row_id=row["row_id"],
        population=row["population"],
        principal_id=row["principal_id"],
        agent_id=row["agent_id"],
        name=row["name"],
        number=row["number"],
        active=row["active"],
        dormant=row["dormant"],
        source=row["source"],
        source_label=row["source_label"],
        identity_class=row["identity_class"],
        class_label=row["class_label"],
        enabled=row["enabled"],
        gone_at=row["gone_at"],
        last_seen=row["last_seen"],
        sponsors=_sponsors(row["sponsors"]),
        sponsor_state=row["sponsor_state"],
        live=int(row["live"]),
        requests=int(row["requests"]),
        last_request=row["last_request"],
        last_execution_id=row["last_execution_id"],
        last_request_ref=row["last_request_ref"],
        consequential=int(row["consequential"]),
        governed_paths=int(row["governed_paths"]),
        lapsed=int(row["lapsed"]),
        findings=int(row["findings"]),
    )


def _line(line: dict[str, Any]) -> TenantLine:
    return TenantLine(
        sources=[
            SourceLine(
                connection_id=row["connection_id"],
                label=str(row["label"]),
                kind=str(row["kind"]),
                source_label=row["source_label"],
                active=bool(row["active"]),
                last_sync_at=row["last_sync_at"],
                health_state=row["health_state"],
                listed=row["listed"],
                consequential=row["consequential"],
                bound=row["bound"],
                unestablished=row["unestablished"],
            )
            for row in line["sources"]
        ],
        totals=LineTotals.model_validate(line["totals"]),
        profiled=line["profiled"],
        principals=line["principals"],
        principals_total=line["principals_total"],
        bound=line["bound"],
        agent_limit=line["agent_limit"],
        agents_held=line["agents_held"],
        agents_dormant=line["agents_dormant"],
    )


def _discovered(found: dict[str, Any] | None) -> Discovered | None:
    if found is None:
        return None
    facts = found["agent"]
    return Discovered(
        agent=DiscoveredFacts(
            agent_id=facts["agent_id"],
            platform_ref=str(facts["platform_ref"]),
            identity_class=str(facts["identity_class"]),
            class_label=facts["class_label"],
            source_label=facts["source_label"],
            display_name=str(facts["display_name"]),
            enabled=bool(facts["enabled"]),
            blueprint_ref=facts["blueprint_ref"],
            credential_kinds=[str(kind) for kind in (facts["credential_kinds"] or [])],
            sponsors=_sponsors(facts["sponsors"]),
            sponsor_state=str(facts["sponsor_state"]),
            first_seen_at=facts["first_seen_at"],
            observed_at=facts["observed_at"],
            gone_at=facts["gone_at"],
        ),
        findings=[Finding.model_validate(row) for row in found["findings"]],
        observations=[
            Observation(
                occurred_at=row["occurred_at"],
                kind=str(row["kind"]),
                action=row["action"],
                outcome=row["outcome"],
            )
            for row in found["observations"]
        ],
    )


def _limits(rows: list[dict[str, Any]]) -> list[LimitRow]:
    return [
        LimitRow(
            scope=row["scope"],
            budget=row["rule"].budget,
            actions=row["actions"],
            labels=row["labels"],
            window=row["window"],
            count=row["count"],
            max_targets=row["rule"].max_targets,
            on_exceed=row["rule"].on_exceed,
        )
        for row in rows
    ]


def _options(kind: str, rows: list[dict[str, Any]]) -> list[BindOption]:
    if kind == "principal":
        return [
            BindOption(
                id=row["agent_id"],
                name=row["display_name"],
                detail=" · ".join(part for part in (row["source"], row["class_label"]) if part),
            )
            for row in rows
        ]
    return [
        BindOption(id=row["principal_id"], name=row["label"], detail="agent principal")
        for row in rows
    ]


def _binding(binding: dict[str, Any]) -> Binding:
    facts = binding.get("bound_by_facts")
    bound_by = binding.get("bound_by")
    return Binding(
        binding_id=binding["binding_id"],
        agent_id=binding["agent_id"],
        principal_id=binding["principal_id"],
        bound_by=bound_by,
        bound_at=binding["bound_at"],
        bound_by_ref=(
            principal_ref(bound_by, {bound_by: facts})
            if bound_by is not None and facts is not None
            else None
        ),
    )


def _detail(kind: str, row_id: UUID, data: dict[str, Any]) -> AgentDetail:
    agent = data.get("agent")
    binding = data.get("binding")
    return AgentDetail(
        row_id=row_id,
        kind="principal" if kind == "principal" else "discovered",
        agent=GovernedFacts.model_validate(agent) if agent else None,
        binding=_binding(binding) if binding else None,
        discovered=_discovered(data.get("discovered")),
        credentials=credential_rows(data.get("credentials", [])),
        expiring_key=data.get("expiring_key"),
        recent=[RecentRow.model_validate(row) for row in data.get("recent", [])],
        runs=[RunRow.model_validate(row) for row in data.get("runs", [])],
        more_runs=bool(data.get("more_runs", False)),
        groups=[GroupRow.model_validate(row) for row in data.get("groups", [])],
        requests=int(data.get("requests", 0)),
        month=data.get("month"),
        bundle=bool(data.get("bundle", False)),
        observe=bool(data.get("observe", False)),
        limits=_limits(data.get("limits", [])),
        reach=[ReachRow.model_validate(row) for row in data.get("reach", [])],
        rules_bundle_id=data.get("rules_bundle_id"),
        space=data.get("space"),
        permissions_bundle_id=data.get("permissions_bundle_id"),
        permissions_inherited=bool(data.get("permissions_inherited", False)),
        policy_document=data.get("policy_document"),
        rules_origin=data.get("rules_origin"),
        administered=bool(data.get("administered", True)),
        options=_options(kind, data.get("options", [])),
    )


def read_detail(runtime: Runtime, session: Session, row_id: UUID) -> AgentDetail:
    """The page's own resolution: a bound agent's id answers with its principal's detail."""
    kind, resolved = pages.resolve(runtime, session, row_id)
    if kind == "discovered":
        return _detail(kind, resolved, pages.discovered_overview(runtime, session, resolved))
    return _detail("principal", resolved, pages.agent_overview(runtime, session, resolved))


def agents_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get(
        "/agents",
        response_model=AgentsPage,
        operation_id="listAgents",
        openapi_extra=query_parameters(FILTERS, cursor=True),
    )
    async def list_agents(request: Request) -> AgentsPage:
        session, _ = await guards.session(request, query=frozenset({*FILTERS, "cursor"}))
        admin(session)
        filters = filters_from(request.query_params, FILTERS)
        raw = request.query_params.get("cursor")
        cursor = pages.decode_cursor(raw) if raw is not None else None
        data = await run_in_threadpool(
            lambda: pages.agents_overview(runtime, session, cursor=cursor, **filters)
        )
        return AgentsPage(
            agents=[_row(row) for row in data["agents"]],
            next=data["next"],
            active_month=data["active_month"],
            month=data["month"],
            line=_line(data["line"]),
            space_dormant=data["space_dormant"],
        )

    @routes.post(
        "/agents",
        response_model=Created,
        operation_id="createAgent",
        openapi_extra=body_of(LabelBody),
    )
    async def create_agent(request: Request) -> Created:
        session, body = await guards.mutation(request, LabelBody)
        admin(session)
        try:
            principal = await run_in_threadpool(pages.create_agent, runtime, session, body.label)
        except AdministrationError as exc:
            raise refused(exc) from None
        return Created(principal_id=principal)

    @routes.get("/agents/{row_id}", response_model=AgentDetail, operation_id="readAgent")
    async def read_agent(request: Request, row_id: str) -> AgentDetail:
        session, _ = await guards.session(request)
        admin(session)
        return await run_in_threadpool(read_detail, runtime, session, parse_uuid(row_id))

    async def change(
        request: Request,
        principal_id: str,
        model: type[Any],
        apply: Any,
        *,
        credential: UUID | None = None,
    ) -> AgentDetail:
        """One change to a governed agent: the body, an AGENT of this tenant, the write, and
        the detail as it is afterwards."""
        session, body = await guards.mutation(request, model)
        admin(session)
        principal = parse_uuid(principal_id)
        await run_in_threadpool(pages.require_agent, runtime, session, principal, credential)
        try:
            await run_in_threadpool(apply, session, principal, body)
        except AdministrationError as exc:
            raise refused(exc) from None
        return await run_in_threadpool(read_detail, runtime, session, principal)

    @routes.post(
        "/agents/{principal_id}/label",
        response_model=AgentDetail,
        operation_id="labelAgent",
        openapi_extra=body_of(LabelBody),
    )
    async def label_agent(request: Request, principal_id: str) -> AgentDetail:
        def apply(session: Session, principal: UUID, body: LabelBody) -> None:
            label_person(runtime, session, principal, body.label)

        return await change(request, principal_id, LabelBody, apply)

    @routes.post(
        "/agents/{principal_id}/credentials/issue",
        response_model=IssuedCredential,
        operation_id="issueAgentCredential",
        openapi_extra=body_of(AgentKeyBody),
    )
    async def issue_agent_credential(request: Request, principal_id: str) -> IssuedCredential:
        session, body = await guards.mutation(request, AgentKeyBody)
        admin(session)
        principal = parse_uuid(principal_id)
        await run_in_threadpool(pages.require_agent, runtime, session, principal)
        try:
            issued = await run_in_threadpool(
                issue,
                runtime,
                session,
                principal=principal,
                kind=None,
                lifetime=key_lifetime_of(body.lifetime),
                replaces=None if body.replaces is None else parse_uuid(body.replaces, 400),
            )
        except AdministrationError as exc:
            raise refused(exc) from None
        return issued_view(issued)

    @routes.post(
        "/agents/{principal_id}/credentials/{credential_id}/revoke",
        response_model=AgentDetail,
        operation_id="revokeAgentCredential",
        openapi_extra=body_of(Empty),
    )
    async def revoke_agent_credential(
        request: Request, principal_id: str, credential_id: str
    ) -> AgentDetail:
        credential = parse_uuid(credential_id)

        def apply(session: Session, principal: UUID, body: Empty) -> None:
            revoke(runtime, session, credential)

        return await change(request, principal_id, Empty, apply, credential=credential)

    @routes.post(
        "/agents/{principal_id}/credentials/{credential_id}/delete",
        response_model=AgentDetail,
        operation_id="deleteAgentCredential",
        openapi_extra=body_of(Empty),
    )
    async def delete_agent_credential(
        request: Request, principal_id: str, credential_id: str
    ) -> AgentDetail:
        credential = parse_uuid(credential_id)

        def apply(session: Session, principal: UUID, body: Empty) -> None:
            delete(runtime, session, credential)

        return await change(request, principal_id, Empty, apply, credential=credential)

    @routes.post(
        "/agents/{principal_id}/deactivate",
        response_model=AgentDetail,
        operation_id="deactivateAgent",
        openapi_extra=body_of(ReasonBody),
    )
    async def deactivate_agent(request: Request, principal_id: str) -> AgentDetail:
        def apply(session: Session, principal: UUID, body: ReasonBody) -> None:
            deactivate(runtime, session, principal, body.reason)

        return await change(request, principal_id, ReasonBody, apply)

    @routes.post(
        "/agents/{principal_id}/reactivate",
        response_model=AgentDetail,
        operation_id="reactivateAgent",
        openapi_extra=body_of(Empty),
    )
    async def reactivate_agent(request: Request, principal_id: str) -> AgentDetail:
        def apply(session: Session, principal: UUID, body: Empty) -> None:
            reactivate(runtime, session, principal)

        return await change(request, principal_id, Empty, apply)

    @routes.post(
        "/agents/{principal_id}/unbind",
        response_model=AgentDetail,
        operation_id="unbindAgent",
        openapi_extra=body_of(ReasonBody),
    )
    async def unbind_agent(request: Request, principal_id: str) -> AgentDetail:
        def apply(session: Session, principal: UUID, body: ReasonBody) -> None:
            pages.unbind_agent(runtime, session, principal, body.reason)

        return await change(request, principal_id, ReasonBody, apply)

    @routes.post(
        "/agents/{row_id}/bind",
        response_model=AgentDetail,
        operation_id="bindAgent",
        openapi_extra=body_of(BindBody),
    )
    async def bind_agent(request: Request, row_id: str) -> AgentDetail:
        """Bind from either side: a governed principal names an agent, a discovered agent
        names a principal; the functions decide whether the pair may be bound."""
        session, body = await guards.mutation(request, BindBody)
        admin(session)
        subject = parse_uuid(row_id)
        target = parse_uuid(body.target, 400)
        kind, resolved = await run_in_threadpool(pages.resolve, runtime, session, subject)
        if kind == "bound":
            raise ApiError("CONFLICT")
        agent, principal = (target, subject) if kind == "principal" else (subject, target)
        try:
            await run_in_threadpool(
                lambda: pages.bind_agent(runtime, session, agent=agent, principal=principal)
            )
        except AdministrationError as exc:
            raise refused(exc) from None
        return await run_in_threadpool(read_detail, runtime, session, principal)

    @routes.post(
        "/agents/{row_id}/govern",
        response_model=Governed,
        operation_id="governAgent",
        openapi_extra=body_of(KeyLifetimeBody),
    )
    async def govern_agent(request: Request, row_id: str) -> Governed:
        session, body = await guards.mutation(request, KeyLifetimeBody)
        admin(session)
        subject = parse_uuid(row_id)
        kind, _ = await run_in_threadpool(pages.resolve, runtime, session, subject)
        if kind != "discovered":
            # Only an agent no binding claims can be governed; anything else is already its
            # own principal's page.
            raise ApiError("CONFLICT")
        try:
            issued = await run_in_threadpool(
                pages.govern, runtime, session, subject, key_lifetime_of(body.lifetime)
            )
        except AdministrationError as exc:
            raise refused(exc) from None
        return Governed(
            **issued_view(issued).model_dump(),
            next_steps=NextSteps(
                install=render_recipe("install.sh", config.origin),
                mcp=render_recipe("claude_code.sh", config.origin),
            ),
        )
