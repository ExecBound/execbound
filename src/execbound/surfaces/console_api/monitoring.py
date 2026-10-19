# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/monitor`: the monitoring pages as data (#333).

Every route wraps the function the Jinja page calls today, for an administrator, under the
monitoring store's own session check: `snapshot` for connections, sources, inventory, external
activity, findings and alert delivery; `findings` for the findings in one state
(`GET /monitor/findings?state=`) and `finding` for one finding by its identifier
(`GET /monitor/findings/{finding_id}`), both under the reads' space predicate; `agents_snapshot`
and `agent_detail` for the Scout agent views; `acknowledge` for a finding, with an optional
note, answered with the fresh snapshot as the page re-renders after its redirect; and
`acknowledge_many` for up to 50 at once, answered per finding and refused to tokens. Rows are
the store's, bounded at 200 as the pages are; a source's coverage word and a story's coverage
label are computed here exactly as `human.py` computes them for the template. Every string an
external platform supplied (a label, a story name, a display name, a tag) travels as data and
the client renders it as text.
"""

from datetime import date, datetime
from typing import Any, Literal, cast
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound.monitoring import due, egress
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import MonitorError
from execbound.notifications import FINDINGS, Destination
from execbound.runtime import Runtime
from execbound.surfaces.console_api.bodies import body
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.principals import PrincipalRef, principal_ref
from execbound.surfaces.human import COVERAGE_LABELS, HumanConfig
from execbound.surfaces.names import PrincipalFacts
from execbound.surfaces.sessions import Session

FindingState = Literal["open", "acknowledged", "all"]
FINDING_STATES: frozenset[str] = frozenset({"open", "acknowledged", "all"})


class MonitorCapability(BaseModel):
    state: str
    at: datetime | None = None


class MonitorConnection(BaseModel):
    connection_id: UUID
    # `fixture` is the synthetic directory (#355, step 4): read like a Microsoft Entra directory
    # from a fixed dataset in process, labelled "Synthetic directory" wherever it is shown.
    kind: Literal["tines", "entra_agent_id", "fixture"]
    # How the connection authenticates: `key_file` is an operator's key file on the host that
    # collects, with only its fingerprint in the database; `sealed` is a key pasted in the
    # console and sealed for the collector, which this answer never carries in any form;
    # `platform_app` is a directory whose administrator consented to the deployment's app;
    # `synthetic` holds no credential, because the synthetic directory exists only in process.
    credential_mode: Literal["key_file", "sealed", "platform_app", "synthetic"]
    label: str
    base_url: str
    team_id: str | None
    health_state: str
    health_changed_at: datetime | None
    audit_cursor: datetime | None
    last_run_at: datetime | None
    last_outcome: str | None
    last_error_code: str | None
    last_sync_at: datetime | None
    retry_after_seconds: int | None
    revoked_at: datetime | None
    platform_tenant_ref: str | None
    capabilities: dict[str, MonitorCapability]
    # The one freshness rule (`collection_overdue_since`, `collection_reporting`): when the
    # collection evidence went stale, and whether it shows collection running and complete.
    overdue_since: datetime | None
    reporting: bool
    # The schedule (#678), each interval with its kind's default filled in: Entra's full
    # collection, or Tines's inventory and its audit records (`activity_interval_seconds`,
    # which Entra has none of). A waiting "Collect now", who asked for it, whether a run holds
    # the connection now (never the run's lease), and when it is next due by the rule the
    # scheduled collector itself reads (`due.due_at`).
    collect_interval_seconds: int
    activity_interval_seconds: int | None
    collect_requested_at: datetime | None
    collect_requested_by: PrincipalRef | None
    collecting: bool
    next_due_at: datetime | None
    # A consented directory's consent: when and by whom it was last recorded, and whether a
    # permission it granted is now refused, so the administrator should update it.
    consented_at: datetime | None
    consented_by: PrincipalRef | None
    consent_needs_update: bool
    # Where a directory's next read of its service principal sign-ins starts (#355), and for a
    # Tines connection the addresses an administrator recorded as the tenant's egress, with
    # when and by whom: recorded by an administrator, never read from Tines.
    sign_in_cursor: datetime | None
    egress_addresses: list[str]
    egress_recorded_at: datetime | None
    egress_recorded_by: PrincipalRef | None


class MonitorSource(BaseModel):
    source_id: UUID
    label: str
    story_id: str
    coverage: str
    health_state: str
    health_changed_at: datetime | None
    last_event_at: datetime | None
    last_heartbeat_at: datetime | None
    heartbeat_seconds: int
    expires_at: datetime
    previous_valid_until: datetime | None
    revoked_at: datetime | None
    last_refusal_code: str | None
    accepted_count: int
    # Whether this administrator may rotate or revoke it: an administrator narrowed to Spaces
    # reads a source in a Space they only review and changes none there.
    administered: bool


class MonitorStory(BaseModel):
    external_id: str
    name: str
    coverage_class: str | None
    coverage: str
    gap_opened_at: datetime | None
    action_count: int
    any_outbound: bool
    any_unknown: bool
    source_id: str | None
    # Whether the source named beside the story is in a Space the reader sees and, only for one
    # they see, whether its token has expired, so it does not report the story now; a source
    # elsewhere is its identifier alone, and both are false when none is named. An open gap
    # beside a source that can report means that no inventory pass has run since, or, where the
    # story's connection was revoked (`connection_revoked`), that none ever will: a revoked
    # connection is not collected again.
    source_expired: bool
    source_visible: bool
    connection_revoked: bool
    disabled: bool | None


class MonitorCredential(BaseModel):
    external_id: str
    name: str
    item_type: str | None
    source_updated_at: datetime | None
    gone_at: datetime | None


class MonitorObservation(BaseModel):
    observation_id: UUID
    occurred_at: datetime
    received_at: datetime
    kind: str
    story_id: str | None
    action: str | None
    evidence: str
    operation_name: str | None
    actor_ref: str | None
    target_ref: str | None
    outcome: str | None
    evaluation_state: str
    evaluation_result: str | None
    integrity_conflict_at: datetime | None
    # The findings raised on this observation, in the spaces the reader sees.
    finding_ids: list[UUID]


class MonitorFindingAgent(BaseModel):
    """The directory agent a finding of an agent rule is about. The sponsors are counted, not
    sent."""

    agent_id: UUID
    display_name: str
    identity_class: str
    sponsor_state: str
    sponsor_count: int
    owner_count: int | None
    linked_principal_id: UUID | None


class MonitorFinding(BaseModel):
    finding_id: UUID
    title: str
    rule_version: str
    profile_version: int | None
    created_at: datetime
    source_id: UUID | None
    connection_id: UUID | None
    observation_id: UUID | None
    story_id: str | None
    action: str | None
    target_ref: str | None
    outcome: str | None
    acknowledged_at: datetime | None
    acknowledged_by: UUID | None
    # The person who acknowledged it, by kind and number (#678).
    acknowledged_by_ref: PrincipalRef | None
    # The acknowledging administrator's own note, screened at the write; rendered as text.
    acknowledgement_note: str | None
    # What the finding is about, by rule: the directory agent, the connection or the source.
    agent: MonitorFindingAgent | None
    connection_label: str | None
    source_label: str | None
    # The synthetic directory raised it (#355, step 4): seen here alone, never sent anywhere.
    synthetic: bool


class MonitorFindingCounts(BaseModel):
    open: int
    acknowledged: int


class MonitorDelivery(BaseModel):
    delivery_id: UUID
    finding_id: UUID
    # The destination a delivery goes to; null for a finding's intent that is waiting to be
    # routed or was closed without one (#31).
    destination_id: str | None
    created_at: datetime
    state: str
    attempts: int
    last_error: str | None


class MonitorProfile(BaseModel):
    version: int
    created_at: datetime


class MonitorDestinationSpace(BaseModel):
    space_id: UUID
    name: str


class MonitorDestination(BaseModel):
    """One findings destination (#31), as the private configuration names it: its id, kind,
    host, rules and Spaces, never its URL, address or secret. `rules` and `spaces` are null
    where it takes every one; a configured Space the reader cannot read is counted in
    `other_spaces`, never named. For a reader of every Space, `other_spaces` is 0 and a
    configured id that is no Space of this workspace is counted in `unknown_spaces`; for any
    other reader such an id is counted in `other_spaces`, so a hidden Space and a mistaken id
    look the same."""

    destination_id: str
    kind: str
    host: str
    rules: list[str] | None
    spaces: list[MonitorDestinationSpace] | None
    other_spaces: int
    unknown_spaces: int


class MonitorSyntheticDirectory(BaseModel):
    """The workspace's synthetic directory, which holds for every Space (#355, step 4), read for
    the workspace rather than for the Space the session looks at. `present`: one is active, so
    no Space connects Microsoft Entra. `addable`: none is active and no Space ever connected
    Microsoft Entra, said only to a reader of every Space and false to anyone else."""

    present: bool
    addable: bool


class MonitorSnapshot(BaseModel):
    connections: list[MonitorConnection]
    sources: list[MonitorSource]
    stories: list[MonitorStory]
    credentials: list[MonitorCredential]
    observations: list[MonitorObservation]
    findings: list[MonitorFinding]
    deliveries: list[MonitorDelivery]
    # The workspace's findings destinations, for every administrator (#31, ruling 12).
    destinations: list[MonitorDestination]
    profile: MonitorProfile | None
    open_findings: int
    synthetic_directory: MonitorSyntheticDirectory


class MonitorFindings(BaseModel):
    """The findings in one state, newest first and at most 200, with both totals counted in
    SQL beyond the page, and the active detection profile."""

    state: FindingState
    findings: list[MonitorFinding]
    counts: MonitorFindingCounts
    profile: MonitorProfile | None


class MonitorSponsor(BaseModel):
    kind: str
    ref: str


Source = Literal["entra_agent_id", "tines", "fixture"]
# How an actor's access is taken away at its source, which Scout never does itself: `entra`
# through the admin center's enterprise applications, `azure_resource` on the Azure resource a
# managed identity belongs to, `blueprint` through an agent identity's blueprint (#355, step 4).
Removal = Literal["entra", "azure_resource", "blueprint"]


def removal(identity_class: str, source: str) -> Removal | None:
    """Where a Microsoft Entra directory's actor's access is removed; nothing for a Tines story
    or the synthetic directory's actor, which exist in no Entra directory."""
    if source != "entra_agent_id":
        return None
    removals: dict[str, Removal] = {
        "service_principal": "entra",
        "consented_app": "entra",
        "managed_identity": "azure_resource",
        "agent_identity": "blueprint",
    }
    return removals.get(identity_class)


class MonitorDriverSummary(BaseModel):
    """An actor's strongest current driver row the reader may see (#355, step 4): its level, what
    kind of platform it names, and the platform's name, which renders as text."""

    evidence: Literal["declared", "network", "joined"]
    kind: Literal["publisher", "blueprint", "egress", "tines"]
    label: str


class MonitorAgentRow(BaseModel):
    agent_id: UUID
    platform_ref: str
    identity_class: str
    display_name: str
    enabled: bool | None
    sponsor_state: str
    sponsors: list[MonitorSponsor]
    owner_count: int | None
    tags: list[str]
    linked_principal_id: UUID | None
    linked_principal_ref: PrincipalRef | None
    consequential: int
    governed: int
    lapsed: int
    unresolved: int
    open_findings: int
    # The to-do list (#355, step 4). `did`: successful consequential observations of the last
    # thirty days outside ExecBound's own settled executions, "at least" where `did_at_least`.
    # `open_paths`: live, ungoverned paths to a consequential action with no acceptance in force;
    # `accepted`: those an acceptance covers, the earliest of whose expiries is `accepted_until`.
    did: int
    did_at_least: bool
    open_paths: int
    accepted: int
    accepted_until: datetime | None
    # The strongest current driver row and how many more; none is unattributed. `tines_driven`:
    # whether any current row the reader may see is a Tines tenant's, strongest or not, for the
    # Tines Gate recipe's pointer.
    driver: MonitorDriverSummary | None
    drivers_more: int
    tines_driven: bool
    source: Source
    synthetic: bool
    # The application id to filter the admin center's enterprise applications by, and where the
    # actor's access is removed; never an address built from a value.
    app_ref: str | None
    removal: Removal | None
    # Whether this session may accept or withdraw the actor's paths: its connection is in a Space
    # the session shows and this administrator administers. The list is the workspace's, an
    # acceptance its connection's Space's, so Accept is offered only where this is true.
    administered: bool


class MonitorAgentSources(BaseModel):
    entra: int
    tines: int
    synthetic: int


class MonitorAgentsTenant(BaseModel):
    enumerated: int
    shown: int
    with_reach: int
    governed: int
    unestablished: int
    # Whether a detection profile names consequential actions; without one nothing is done or
    # open, and the page says so. The actors each source lists, and the directory actors no
    # current driver row attributes, each over everything the connections could enumerate.
    assessed: bool
    # Whether, with no profile set, the synthetic directory is assessed against the built-in
    # sensitive action set, which `consequential` then lists (#355, step 4).
    built_in: bool
    per_source: MonitorAgentSources
    unattributed: int


class MonitorAgents(BaseModel):
    agents: list[MonitorAgentRow]
    consequential: list[str]
    tenant: MonitorAgentsTenant


class MonitorAgentIdentity(BaseModel):
    agent_id: UUID
    connection_id: UUID
    platform_ref: str
    identity_class: str
    display_name: str
    enabled: bool | None
    sponsor_state: str
    sponsors: list[MonitorSponsor]
    owner_count: int | None
    tags: list[str]
    blueprint_ref: str | None
    credential_kinds: list[str]
    linked_principal_id: UUID | None
    linked_principal_ref: PrincipalRef | None
    first_seen_at: datetime
    observed_at: datetime
    # The leading product token of the user agent its newest successful sign-in sent, and when
    # (#355). A client chooses its own user agent: a hint, never evidence of a driver.
    user_agent_hint: str | None
    user_agent_seen_at: datetime | None
    # Where it was listed, whether that is the synthetic directory, its application id and where
    # its access is removed (#355, step 4).
    source: Source
    synthetic: bool
    app_ref: str | None
    removal: Removal | None
    # Whether this session may accept or withdraw its paths, as on the Agents page's row.
    administered: bool


class MonitorDriver(BaseModel):
    """One piece of evidence of who drives an actor (#355), kept apart from what it can reach.

    `declared`: the directory names the driver, as the AI publisher catalog's entry for the
    principal's application or an agent identity's blueprint. `network`: its successful sign-ins
    came from a range the reviewed egress catalog attributes to a platform, or from an address an
    administrator recorded as the Space's Tines tenant's egress; it names a platform, never a
    workflow. `joined`: that Tines evidence plus every story in the Tines tenant that uses a
    credential allowed to call Microsoft Graph or Microsoft sign-in (`story_ids`, "at least" where
    `stories_capped`); it never names one story as the one that acted. A catalog row names its
    source and the day it was read; a Tines row counts the tenant's credentials with no host
    restriction, which are never joined. `label` is a catalog's name or, for a Tines tenant, the
    connection's own name, and renders as text.
    """

    evidence: Literal["declared", "network", "joined"]
    platform_kind: Literal["publisher", "blueprint", "egress", "tines"]
    platform_ref: str
    label: str
    source: str | None
    retrieved: date | None
    catalog_version: str | None
    story_ids: list[str]
    stories_capped: bool
    unrestricted_credentials: int | None
    first_seen_at: datetime
    last_seen_at: datetime
    gone_at: datetime | None


class MonitorDriverGaps(BaseModel):
    """What no network evidence can name: platforms that publish no stable egress, whose actors
    cannot be attributed by network, and those whose published feed has not been read into the
    catalog yet."""

    catalog_version: str
    unattributable: list[str]
    pending: list[str]


class MonitorGrant(BaseModel):
    grant_kind: str
    resource_ref: str
    value: str
    inherited: bool
    path_ref: str
    observed_at: datetime
    gone_at: datetime | None
    actions: list[str]
    breadth: str | None


class MonitorReach(BaseModel):
    action: str
    path_kind: str
    path_ref: str
    certainty: str
    effective: str
    enforcement_mode: str
    catalog_version: str
    valid_until: datetime
    gone_at: datetime | None
    reason_code: str | None
    accepted_at: datetime | None
    # The standing acceptance's expiry and author (#355, step 4); `accepted` while it is in force,
    # and `open` for a live, ungoverned path to a consequential action that none covers.
    expires_at: datetime | None
    accepted_by_ref: PrincipalRef | None
    accepted: bool
    open: bool


class MonitorAcceptance(BaseModel):
    """One acceptance of a path, or its withdrawal, as `monitor_reach_acceptances` keeps it."""

    change: Literal["accepted", "withdrawn"]
    action: str
    path_kind: str
    path_ref: str
    reason_code: str | None
    expires_at: datetime | None
    recorded_by_ref: PrincipalRef | None
    recorded_at: datetime


class MonitorAgentFinding(BaseModel):
    finding_id: UUID
    rule_version: str
    title: str
    created_at: datetime
    acknowledged_at: datetime | None


class MonitorAgentObservation(BaseModel):
    occurred_at: datetime
    kind: str
    action: str | None
    outcome: str | None
    operation_name: str | None


class MonitorAgentDetail(BaseModel):
    agent: MonitorAgentIdentity
    grants: list[MonitorGrant]
    reach: list[MonitorReach]
    findings: list[MonitorAgentFinding]
    observations: list[MonitorAgentObservation]
    unresolved: int
    # Who drives it, and how that is known; none is unattributed, not "nobody" (#355).
    drivers: list[MonitorDriver]
    driver_gaps: MonitorDriverGaps
    # Every acceptance of its paths and withdrawal, newest first, at most 50, and whether a
    # detection profile names consequential actions, without which no path is open.
    acceptances: list[MonitorAcceptance]
    assessed: bool


class ReachPath(BaseModel):
    """One path of an actor's, as its reach rows name it: one Accept offers, a live grant, role
    or inherited path."""

    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=3, max_length=65)
    path_kind: Literal["grant", "role", "inherited"]
    path_ref: str = Field(min_length=1, max_length=128)


class AcceptedPath(BaseModel):
    """One path whose acceptance stands, to withdraw: any kind an acceptance is recorded for,
    since `accept-reach` also accepts an observed path (#355, step 4)."""

    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=3, max_length=65)
    path_kind: Literal["grant", "role", "inherited", "execbound", "observation"]
    path_ref: str = Field(min_length=1, max_length=128)


class AcceptReach(BaseModel):
    """Accept one to 50 of an actor's paths for one reason and a period of days (#355, step 4).
    Accepting one already accepted renews it."""

    model_config = ConfigDict(extra="forbid")

    paths: list[ReachPath] = Field(min_length=1, max_length=monitor_store.MAX_ACCEPT_PATHS)
    reason_code: Literal[
        "COMPENSATING_CONTROL",
        "VENDOR_MANAGED",
        "BUSINESS_REQUIRED",
        "GOVERNANCE_PLANNED",
        "BREAK_GLASS",
    ]
    days: Literal[30, 90, 180, 365] = 90


class AcknowledgeFinding(BaseModel):
    """An optional note; `{}` acknowledges with none. The store trims and screens it."""

    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=monitor_store.NOTE_LIMIT)


class AcknowledgeFindings(BaseModel):
    """One to 50 distinct canonical finding identifiers and one optional note for them all."""

    model_config = ConfigDict(extra="forbid")

    finding_ids: list[str] = Field(min_length=1, max_length=monitor_store.BULK_LIMIT)
    note: str | None = Field(default=None, max_length=monitor_store.NOTE_LIMIT)


class MonitorAcknowledgement(BaseModel):
    finding_id: UUID
    # `unavailable` is a finding outside the spaces the reader sees or one that does not
    # exist, which are not told apart.
    outcome: Literal["acknowledged", "already_acknowledged", "unavailable"]


class MonitorAcknowledgements(BaseModel):
    """One answer per requested finding, in request order, as the server decided it."""

    results: list[MonitorAcknowledgement]


def coverage_word(source: dict[str, Any], now: datetime) -> str:
    """The word the Connections page puts beside a source, computed as the page computes it."""
    heartbeat = source["last_heartbeat_at"]
    if not source["active"] or source["revoked_at"] is not None:
        return "Disabled"
    if now >= source["expires_at"]:
        return "Expired"
    if heartbeat is None:
        return "No heartbeat"
    if (now - heartbeat).total_seconds() > source["heartbeat_seconds"] * 2:
        return "Stale"
    return "Reporting"


def _facts(rows: Any) -> dict[UUID, PrincipalFacts]:
    return {
        row["principal_id"]: PrincipalFacts(row["kind"], row["label"], row["number"])
        for row in rows or []
    }


def _finding(row: dict[str, Any], facts: dict[UUID, PrincipalFacts]) -> MonitorFinding:
    """One finding as every route answers it, so the snapshot, the list and the single read
    cannot drift."""
    agent = (
        None
        if row["agent_id"] is None or row["display_name"] is None
        else MonitorFindingAgent(
            agent_id=row["agent_id"],
            display_name=row["display_name"],
            identity_class=row["identity_class"],
            sponsor_state=row["sponsor_state"],
            sponsor_count=int(row["sponsor_count"] or 0),
            owner_count=row["owner_count"],
            linked_principal_id=row["linked_principal_id"],
        )
    )
    return MonitorFinding(
        **{
            key: row[key]
            for key in MonitorFinding.model_fields
            if key not in {"acknowledged_by_ref", "agent"}
        },
        acknowledged_by_ref=principal_ref(row["acknowledged_by"], facts),
        agent=agent,
    )


def _profile(rows: list[dict[str, Any]]) -> MonitorProfile | None:
    profile = rows[0] if rows else None
    if profile is None:
        return None
    return MonitorProfile(version=profile["version"], created_at=profile["created_at"])


# Computed for each connection rather than read from its row.
_CONNECTION_COMPUTED = frozenset(
    {
        "capabilities",
        "overdue_since",
        "reporting",
        "collect_interval_seconds",
        "activity_interval_seconds",
        "collect_requested_by",
        "consented_by",
        "consent_needs_update",
        "collecting",
        "next_due_at",
        "egress_addresses",
        "egress_recorded_by",
    }
)


def _connection(
    row: dict[str, Any], facts: dict[UUID, PrincipalFacts], now: datetime
) -> MonitorConnection:
    collect, activity = due.intervals(row)
    return MonitorConnection(
        **{
            key: row[key]
            for key in MonitorConnection.model_fields
            if key not in _CONNECTION_COMPUTED
        },
        capabilities={
            str(name): MonitorCapability(**value)
            for name, value in (row["capabilities"] or {}).items()
            if isinstance(value, dict)
        },
        overdue_since=monitor_store.collection_overdue_since(row, now),
        reporting=monitor_store.collection_reporting(row, now),
        collect_interval_seconds=collect,
        activity_interval_seconds=activity,
        collect_requested_by=principal_ref(row["collect_requested_by"], facts),
        consented_by=principal_ref(row["consented_by"], facts),
        consent_needs_update=bool(row["consent_needs_update"]),
        collecting=row["collecting_until"] is not None and row["collecting_until"] > now,
        next_due_at=due.due_at(row, now),
        egress_addresses=[str(address) for address in row["egress_addresses"] or []],
        egress_recorded_by=principal_ref(row["egress_recorded_by"], facts),
    )


def _findings_destinations(runtime: Runtime, session: Session) -> list[Destination]:
    """The workspace's findings destinations, in configuration order (#31)."""
    return [
        d
        for d in runtime.notifications
        if d.tenant_id == session.identity.tenant_id and FINDINGS in d.classes
    ]


def _destinations(
    destinations: list[Destination], names: dict[UUID, str], *, reads_every_space: bool
) -> list[MonitorDestination]:
    """The findings destinations as Alert settings lists them (#31, ruling 12).

    `names` holds the configured Spaces of this workspace the reader may read. Any other
    configured id is counted and never named. A reader of every Space can read each Space of
    the workspace, so for them an id outside `names` is no Space of it, a mistake in the
    configuration, and is counted apart. A reader narrowed to Spaces gets one count for both,
    so they learn neither a hidden Space's name nor its identifier, nor whether it exists.
    """
    listed = []
    for d in destinations:
        spaces = None if d.spaces is None else sorted(d.spaces)
        unnamed = 0 if spaces is None else sum(1 for s in spaces if s not in names)
        listed.append(
            MonitorDestination(
                destination_id=d.destination_id,
                kind=d.kind,
                host=urlsplit(d.url).hostname or "",
                rules=None if d.rules is None else sorted(d.rules),
                spaces=None
                if spaces is None
                else [
                    MonitorDestinationSpace(space_id=space, name=names[space])
                    for space in spaces
                    if space in names
                ],
                other_spaces=0 if reads_every_space else unnamed,
                unknown_spaces=unnamed if reads_every_space else 0,
            )
        )
    return listed


def read_snapshot(runtime: Runtime, session: Session) -> MonitorSnapshot:
    destinations = _findings_destinations(runtime, session)
    rows = monitor_store.snapshot(
        runtime.db,
        session,
        clock=runtime.clock,
        spaces={space for d in destinations for space in d.spaces or ()},
    )
    now = runtime.clock.now()
    acknowledgers = _facts(rows.get("acknowledgers"))
    requesters = _facts(rows.get("requesters"))
    return MonitorSnapshot(
        connections=[_connection(row, requesters, now) for row in rows["connections"]],
        sources=[
            MonitorSource(
                **{key: row[key] for key in MonitorSource.model_fields if key != "coverage"},
                coverage=coverage_word(row, now),
            )
            for row in rows["sources"]
        ],
        stories=[
            MonitorStory(
                **{key: row[key] for key in MonitorStory.model_fields if key != "coverage"},
                coverage=COVERAGE_LABELS.get(row["coverage_class"], COVERAGE_LABELS[None]),
            )
            for row in rows["coverage"]
        ],
        credentials=[
            MonitorCredential(**{key: row[key] for key in MonitorCredential.model_fields})
            for row in rows["inventory"]
            if row["item_kind"] == "credential"
        ],
        observations=[
            MonitorObservation(
                **{
                    key: row[key] for key in MonitorObservation.model_fields if key != "finding_ids"
                },
                finding_ids=list(row["finding_ids"] or []),
            )
            for row in rows["observations"]
        ],
        findings=[_finding(row, acknowledgers) for row in rows["findings"]],
        deliveries=[
            MonitorDelivery(**{key: row[key] for key in MonitorDelivery.model_fields})
            for row in rows["deliveries"]
        ],
        destinations=_destinations(
            destinations,
            {row["space_id"]: str(row["name"]) for row in rows["space_names"]},
            reads_every_space=bool(rows["reads_every_space"]),
        ),
        profile=_profile(rows["profile"]),
        # Counted in SQL under the same predicate, so it is right beyond the 200 shown.
        open_findings=int(rows["counts"]["open"]),
        synthetic_directory=MonitorSyntheticDirectory(**rows["synthetic_directory"]),
    )


def read_findings(runtime: Runtime, session: Session, state: str) -> MonitorFindings:
    rows = monitor_store.findings(runtime.db, session, state, clock=runtime.clock)
    facts = _facts(rows["principals"])
    return MonitorFindings(
        state=cast(FindingState, state),
        findings=[_finding(row, facts) for row in rows["findings"]],
        counts=MonitorFindingCounts(**rows["counts"]),
        profile=_profile(rows["profile"]),
    )


def read_finding(runtime: Runtime, session: Session, finding_id: UUID) -> MonitorFinding:
    found = monitor_store.finding(runtime.db, session, finding_id, clock=runtime.clock)
    return _finding(found["finding"], _facts(found["principals"]))


def _sponsors(value: Any) -> list[MonitorSponsor]:
    if not isinstance(value, list):
        return []
    return [
        MonitorSponsor(kind=str(item.get("kind", "")), ref=str(item.get("ref", "")))
        for item in value
        if isinstance(item, dict)
    ]


def _tags(value: Any) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


_ROW_COMPUTED = frozenset({"sponsors", "tags", "linked_principal_ref", "driver", "removal"})


def read_agents(runtime: Runtime, session: Session) -> MonitorAgents:
    rows = monitor_store.agents_snapshot(runtime.db, session, clock=runtime.clock)
    facts = _facts(rows.get("principals"))
    tenant = rows["tenant"]
    return MonitorAgents(
        agents=[
            MonitorAgentRow(
                **{
                    key: row[key]
                    for key in MonitorAgentRow.model_fields
                    if key not in _ROW_COMPUTED
                },
                sponsors=_sponsors(row["sponsors"]),
                tags=_tags(row["tags"]),
                linked_principal_ref=principal_ref(row["linked_principal_id"], facts),
                driver=MonitorDriverSummary(**row["driver"]) if row["driver"] else None,
                removal=removal(row["identity_class"], row["source"]),
            )
            for row in rows["agents"]
        ],
        consequential=list(rows["consequential"]),
        tenant=MonitorAgentsTenant(
            **{key: value for key, value in tenant.items() if key != "per_source"},
            per_source=MonitorAgentSources(**tenant["per_source"]),
        ),
    )


def read_agent(runtime: Runtime, session: Session, agent_id: UUID) -> MonitorAgentDetail:
    detail = monitor_store.agent_detail(runtime.db, session, agent_id, clock=runtime.clock)
    agent = detail["agent"]
    facts = _facts(detail.get("principals"))
    return MonitorAgentDetail(
        agent=MonitorAgentIdentity(
            **{
                key: agent[key]
                for key in MonitorAgentIdentity.model_fields
                if key
                not in {"sponsors", "tags", "credential_kinds", "linked_principal_ref", "removal"}
            },
            sponsors=_sponsors(agent["sponsors"]),
            tags=_tags(agent["tags"]),
            credential_kinds=_tags(agent["credential_kinds"]),
            linked_principal_ref=principal_ref(agent["linked_principal_id"], facts),
            removal=removal(agent["identity_class"], agent["source"]),
        ),
        grants=[
            MonitorGrant(**{key: row[key] for key in MonitorGrant.model_fields})
            for row in detail["grants"]
        ],
        reach=[
            MonitorReach(
                **{key: row[key] for key in MonitorReach.model_fields if key != "accepted_by_ref"},
                accepted_by_ref=principal_ref(row["accepted_by"], facts),
            )
            for row in detail["reach"]
        ],
        acceptances=[
            MonitorAcceptance(
                **{
                    key: row[key]
                    for key in MonitorAcceptance.model_fields
                    if key != "recorded_by_ref"
                },
                recorded_by_ref=principal_ref(row["recorded_by"], facts),
            )
            for row in detail["acceptances"]
        ],
        assessed=bool(detail["assessed"]),
        findings=[
            MonitorAgentFinding(**{key: row[key] for key in MonitorAgentFinding.model_fields})
            for row in detail["findings"]
        ],
        observations=[
            MonitorAgentObservation(
                **{key: row[key] for key in MonitorAgentObservation.model_fields}
            )
            for row in detail["observations"]
        ],
        unresolved=int(detail["unresolved"]),
        drivers=[
            MonitorDriver(
                evidence=row["evidence"],
                platform_kind=row["kind"],
                platform_ref=row["platform_ref"],
                label=str(row["label"]),
                source=row["source"],
                retrieved=row["retrieved"],
                catalog_version=row["catalog_version"],
                story_ids=list(row["detail_refs"]),
                stories_capped=bool(row["detail_capped"]),
                unrestricted_credentials=row["unrestricted_credentials"],
                first_seen_at=row["first_seen_at"],
                last_seen_at=row["last_seen_at"],
                gone_at=row["gone_at"],
            )
            for row in detail["drivers"]
        ],
        driver_gaps=MonitorDriverGaps(
            catalog_version=egress.VERSION,
            unattributable=[platform.label for platform in egress.PRODUCTION.unattributable],
            pending=[
                platform.label for platform in egress.PRODUCTION.platforms if platform.pending
            ],
        ),
    )


def _identifier(raw: str) -> UUID:
    """A path segment as one identifier; anything else is an address that does not exist."""
    try:
        parsed = UUID(raw)
    except ValueError:
        raise ApiError("NOT_FOUND") from None
    if str(parsed) != raw:
        raise ApiError("NOT_FOUND")
    return parsed


def _finding_ids(raw: list[str]) -> list[UUID]:
    """A batch's identifiers, each canonical and none twice; anything else is the body's fault,
    named, so a typo is never answered as a finding outside the reader's spaces."""
    parsed: list[UUID] = []
    for value in raw:
        try:
            identifier = UUID(value)
        except ValueError:
            raise ApiError("INVALID_BODY", fields=["finding_ids"]) from None
        if str(identifier) != value:
            raise ApiError("INVALID_BODY", fields=["finding_ids"])
        parsed.append(identifier)
    if len(set(parsed)) != len(parsed):
        raise ApiError("INVALID_BODY", fields=["finding_ids"])
    return parsed


def _read(read: Any, *, body: str = "finding_ids") -> Any:
    try:
        return read()
    except MonitorError as exc:
        if exc.code in {"AGENT_UNAVAILABLE", "FINDING_UNAVAILABLE"}:
            raise ApiError("NOT_FOUND") from None
        if exc.code == "INVALID_ADMIN":
            raise ApiError("FORBIDDEN") from None
        # The note is refused by name and never repeated.
        if exc.code == "INVALID_NOTE":
            raise ApiError("INVALID_BODY", fields=["note"]) from None
        if exc.code == "INVALID_INPUT":
            raise ApiError("INVALID_BODY", fields=[body]) from None
        # A withdrawal of a path no acceptance stands for: someone withdrew it first.
        if exc.code == "NOT_ACCEPTED":
            raise ApiError("CONFLICT") from None
        # A note for a finding someone acknowledged first: it was not saved.
        if exc.code == "ACKNOWLEDGED":
            raise ApiError("CONFLICT") from None
        raise ApiError("UNAVAILABLE") from None


def monitoring_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/monitor", response_model=MonitorSnapshot, operation_id="readMonitor")
    async def read_monitor(request: Request) -> MonitorSnapshot:
        current, _ = await guards.session(request, kind="ADMIN")
        return await run_in_threadpool(_read, lambda: read_snapshot(runtime, current))

    @routes.get("/monitor/agents", response_model=MonitorAgents, operation_id="readMonitorAgents")
    async def read_monitor_agents(request: Request) -> MonitorAgents:
        current, _ = await guards.session(request, kind="ADMIN")
        return await run_in_threadpool(_read, lambda: read_agents(runtime, current))

    @routes.get(
        "/monitor/agents/{agent_id}",
        response_model=MonitorAgentDetail,
        operation_id="readMonitorAgent",
    )
    async def read_monitor_agent(request: Request, agent_id: str) -> MonitorAgentDetail:
        current, _ = await guards.session(request, kind="ADMIN")
        identifier = _identifier(agent_id)
        return await run_in_threadpool(_read, lambda: read_agent(runtime, current, identifier))

    @routes.post(
        "/monitor/agents/{agent_id}/accept",
        response_model=MonitorAgentDetail,
        operation_id="acceptMonitorReach",
        openapi_extra=body(AcceptReach),
    )
    async def accept_monitor_reach(request: Request, agent_id: str) -> MonitorAgentDetail:
        current, values = await guards.mutation(request, AcceptReach, kind="ADMIN")
        identifier = _identifier(agent_id)

        def apply() -> MonitorAgentDetail:
            monitor_store.accept_paths(
                runtime.db,
                current,
                identifier,
                [(path.action, path.path_kind, path.path_ref) for path in values.paths],
                reason_code=values.reason_code,
                days=values.days,
                clock=runtime.clock,
            )
            return read_agent(runtime, current, identifier)

        return await run_in_threadpool(_read, apply, body="paths")

    @routes.post(
        "/monitor/agents/{agent_id}/withdraw",
        response_model=MonitorAgentDetail,
        operation_id="withdrawMonitorReach",
        openapi_extra=body(AcceptedPath),
    )
    async def withdraw_monitor_reach(request: Request, agent_id: str) -> MonitorAgentDetail:
        current, values = await guards.mutation(request, AcceptedPath, kind="ADMIN")
        identifier = _identifier(agent_id)

        def apply() -> MonitorAgentDetail:
            monitor_store.withdraw_path(
                runtime.db,
                current,
                identifier,
                (values.action, values.path_kind, values.path_ref),
                clock=runtime.clock,
            )
            return read_agent(runtime, current, identifier)

        return await run_in_threadpool(_read, apply, body="path_ref")

    @routes.get(
        "/monitor/findings", response_model=MonitorFindings, operation_id="readMonitorFindings"
    )
    async def read_monitor_findings(request: Request, state: str = "open") -> MonitorFindings:
        current, _ = await guards.session(request, query=frozenset({"state"}), kind="ADMIN")
        if state not in FINDING_STATES:
            raise ApiError("INVALID_REQUEST")
        return await run_in_threadpool(_read, lambda: read_findings(runtime, current, state))

    # Declared before the `{finding_id}` routes, so `acknowledge` is matched as itself.
    @routes.post(
        "/monitor/findings/acknowledge",
        response_model=MonitorAcknowledgements,
        operation_id="acknowledgeFindings",
        openapi_extra=body(AcknowledgeFindings),
    )
    async def acknowledge_findings(request: Request) -> MonitorAcknowledgements:
        current, values = await guards.mutation(request, AcknowledgeFindings, kind="ADMIN")
        identifiers = _finding_ids(values.finding_ids)

        def apply() -> MonitorAcknowledgements:
            results = monitor_store.acknowledge_many(
                runtime.db, current, identifiers, note=values.note, clock=runtime.clock
            )
            return MonitorAcknowledgements(
                results=[
                    MonitorAcknowledgement(finding_id=finding, outcome=cast(Any, outcome))
                    for finding, outcome in results
                ]
            )

        return await run_in_threadpool(_read, apply)

    @routes.get(
        "/monitor/findings/{finding_id}",
        response_model=MonitorFinding,
        operation_id="readMonitorFinding",
    )
    async def read_monitor_finding(request: Request, finding_id: str) -> MonitorFinding:
        current, _ = await guards.session(request, kind="ADMIN")
        identifier = _identifier(finding_id)
        return await run_in_threadpool(_read, lambda: read_finding(runtime, current, identifier))

    @routes.post(
        "/monitor/findings/{finding_id}/acknowledge",
        response_model=MonitorSnapshot,
        operation_id="acknowledgeFinding",
        openapi_extra=body(AcknowledgeFinding),
    )
    async def acknowledge_finding(request: Request, finding_id: str) -> MonitorSnapshot:
        current, values = await guards.mutation(request, AcknowledgeFinding, kind="ADMIN")
        identifier = _identifier(finding_id)

        def apply() -> MonitorSnapshot:
            monitor_store.acknowledge(
                runtime.db, current, identifier, note=values.note, clock=runtime.clock
            )
            return read_snapshot(runtime, current)

        return await run_in_threadpool(_read, apply)
