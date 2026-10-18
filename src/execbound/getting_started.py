# SPDX-License-Identifier: AGPL-3.0-only
"""Getting-started helpers: a target's facts as the rules read them, the tenant's progress,
and one Space's setup steps."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.domains import ScalarValue


class OnboardingError(ValueError):
    """Safe errors carry a code and never a code, token, name or database diagnostic."""

    def __init__(self, code: str = "ONBOARDING_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Onboarding unavailable")


# --- A target's facts, named as the rules read them ----------------------------------------

# The action the welcome page's effect column is about, per fixture class: the first SOC
# action on each, which is what the demo's first beat asks for.
FIRST_ACTION = {"endpoint": "endpoint.isolate", "identity": "identity.disable"}


def host_facts(host: Mapping[str, Any]) -> dict[str, ScalarValue]:
    """The facts a fixture host presents to the rules, named as the contract declares them.

    The same derivations the contract makes: `is_production` is the environment compared with
    production, and the incident facts are the host's one open incident. A host with no open
    incident presents no incident facts, and a reading over it says which facts it lacked.
    """
    facts: dict[str, ScalarValue] = {
        "environment": str(host["environment"]),
        "criticality": int(host["criticality"]),
        "is_production": host["environment"] == "production",
    }
    if host["resource_type"] == "endpoint":
        facts["role"] = str(host["role"])
    else:
        facts["privilege_class"] = str(host["privilege_class"])
    if host.get("incident_id") is not None:
        facts["incident_status"] = "OPEN"
        facts["incident_severity"] = str(host["incident_severity"])
    return facts


# --- The welcome page's progress, read from the tenant's own audit chain -------------------

# A claim refused before any decision is admission's `INVALID_CONTEXT`: the claimed incident
# is not one the inventory holds on the target. Before #545 admission audited every
# resolution refusal as `DEPENDENCY_OR_CONTEXT_UNAVAILABLE`, which the history keeps, so that
# reason still counts; an unknown action or target, now audited as its own code, does not.
PROGRESS_STEPS = (
    "claimed",
    "agent_credential",
    "approver_credential",
    "first_request",
    "denied",
    "claim_refused",
    "decided",
    "limit_refused",
)
_PROGRESS_SQL = """
SELECT step, min(occurred_at) AS at FROM (
  SELECT occurred_at, CASE
    WHEN kind IN ('tenant.claimed', 'sandbox.adopted') THEN 'claimed'
    WHEN kind = 'credential.issued' AND payload->>'kind' = 'AGENT' THEN 'agent_credential'
    WHEN kind = 'credential.issued' AND payload->>'kind' = 'HUMAN_APPROVER'
      THEN 'approver_credential'
    WHEN kind = 'execution.rejected' AND payload->>'operation' = 'admit'
      AND payload->>'reason' IN ('INVALID_CONTEXT', 'DEPENDENCY_OR_CONTEXT_UNAVAILABLE')
      THEN 'claim_refused'
    WHEN kind = 'execution.evaluated' AND payload->>'stage' = 'APPROVAL_REVIEW' THEN 'decided'
    WHEN kind = 'execution.evaluated' AND payload->'decision'->>'effect' = 'DENY'
      AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(payload->'decision'->'reasons') r
                  WHERE r LIKE 'HARD_LIMIT:%') THEN 'limit_refused'
    WHEN kind = 'execution.evaluated' AND payload->'decision'->>'effect' = 'DENY' THEN 'denied'
  END AS step
  FROM execbound.audit_events WHERE tenant_id = :t) s
WHERE step IS NOT NULL GROUP BY step
"""


def progress(conn: Connection, tenant_id: UUID) -> dict[str, datetime | None]:
    """When each demo step first happened, from the audit chain and the executions table.

    Nothing here is a counter kept for the page: every value is the earliest record that
    satisfies the step, so the page reads the same evidence the export carries.
    """
    found: dict[str, datetime | None] = dict.fromkeys(PROGRESS_STEPS)
    for row in conn.execute(text(_PROGRESS_SQL), {"t": tenant_id}).mappings():
        found[str(row["step"])] = row["at"].astimezone(UTC)
    first = conn.execute(
        text("SELECT min(created_at) FROM execbound.executions WHERE tenant_id = :t"),
        {"t": tenant_id},
    ).scalar_one()
    found["first_request"] = first.astimezone(UTC) if first is not None else None
    limit, denied = found["limit_refused"], found["denied"]
    if limit is not None and (denied is None or limit < denied):
        found["denied"] = limit
    return found


# --- Setup progress for one Space, read from the records that satisfy each step (#678) -----

SETUP_KEYS = ("policy", "agent_key", "first_request", "reviewer", "first_decision")
OBSERVED_WINDOW = timedelta(days=7)


@dataclass(frozen=True)
class SetupMilestone:
    """One step of setup, satisfied by a record or not; never by a click."""

    key: str
    # "done", "todo", "not_applicable" or "needs_enforcing".
    state: str
    at: datetime | None = None
    record_kind: str | None = None
    record_id: UUID | None = None
    request_ref: str | None = None


@dataclass(frozen=True)
class SetupState:
    connected: bool
    milestones: tuple[SetupMilestone, ...]
    observed: dict[str, int] | None
    observed_since: datetime | None


# An active connector account this Space owns or is offered, with an active mapping: the
# predicate the policy page's starter builds with `space_clause(..., offered=True)`.
_CONNECTED = """
SELECT EXISTS (
  SELECT 1 FROM execbound.operation_mappings m
  JOIN execbound.connector_accounts a USING (tenant_id, account_id, provider)
  WHERE m.tenant_id = :t AND m.active AND a.active
    AND (a.space_id = :s OR a.offered_tenant_wide))
"""
# A bundle holds requests for a person in two ways: an approval policy, and a limit whose
# `on_exceed` is REQUIRE_APPROVAL (the store's `limit:<rule_id>` obligations). A quorum rule
# adds no third way, because its obligation must name one of those two.
_POLICY = """
SELECT sel.bundle_id, sel.changed_at,
       btrim(coalesce(c.content->>'approval_policies', '')) <> ''
       OR EXISTS (
         SELECT 1 FROM jsonb_array_elements(coalesce(c.content->'limits', '[]'::jsonb)) l
         WHERE l->>'on_exceed' = 'REQUIRE_APPROVAL') AS reviews
FROM execbound.space_policy_selection sel
JOIN execbound.policy_bundle_contents c USING (tenant_id, bundle_id)
WHERE sel.tenant_id = :t AND sel.space_id = :s
"""
# A dormant agent is inactive, so it never counts.
_AGENT_KEY = """
SELECT p.principal_id, min(c.issued_at) AS at
FROM execbound.principals p
JOIN execbound.credentials c USING (tenant_id, principal_id)
WHERE p.tenant_id = :t AND p.kind = 'AGENT' AND p.active AND p.space_id = :s
  AND c.revoked_at IS NULL AND c.expires_at > :now
GROUP BY p.principal_id ORDER BY at, p.principal_id LIMIT 1
"""
_FIRST_REQUEST = """
SELECT execution_id, created_at, 'EB-' || request_number AS request_ref
FROM execbound.executions WHERE tenant_id = :t AND space_id = :s
ORDER BY created_at, execution_id LIMIT 1
"""
# The view already holds each scope to `approvals.decide` and unions the approval rules'
# group members; an action counts only when a mapping the selected bundle names serves it.
_REVIEWER = """
SELECT r.approver_id FROM execbound.effective_approval_scopes r
WHERE r.tenant_id = :t AND r.space_id = :s AND r.action IN (
  SELECT om.action
  FROM execbound.policy_bundle_contents c
  CROSS JOIN LATERAL jsonb_array_elements(c.content->'mappings') b
  JOIN execbound.operation_mappings om ON om.tenant_id = c.tenant_id
   AND om.operation_ref = b->>'operation_ref'
   AND om.account_id = CAST(b->>'account_id' AS uuid)
  WHERE c.tenant_id = :t AND c.bundle_id = :bundle)
ORDER BY r.approver_id LIMIT 1
"""
_FIRST_DECISION = """
SELECT e.execution_id, a.decided_at, 'EB-' || e.request_number AS request_ref
FROM execbound.approvals a JOIN execbound.executions e USING (tenant_id, execution_id)
WHERE a.tenant_id = :t AND a.space_id = :s AND a.decided_at IS NOT NULL
ORDER BY a.decided_at, a.approval_id LIMIT 1
"""
_OBSERVED = """
SELECT e.result->'observed'->>'effect' AS effect, count(*) AS n
FROM execbound.executions e
WHERE e.tenant_id = :t AND e.space_id = :s AND e.state = 'OBSERVED' AND e.created_at > :since
GROUP BY 1
"""
_OBSERVED_KEYS = {"ELIGIBLE": "eligible", "REQUIRE_APPROVAL": "held", "DENY": "denied"}


def _utc(value: datetime | None) -> datetime | None:
    return None if value is None else value.astimezone(UTC)


def setup_state(
    conn: Connection, tenant: UUID, space: UUID, *, now: datetime, observing: bool
) -> SetupState:
    """Which of the five setup steps hold in one Space, each from the record that satisfies it.

    Runs inside the caller's fenced transaction and writes nothing. `progress()` above is not
    reused: it is tenant-wide, its steps are the demo's eight, and three of these steps are
    current state (a policy selected, an agent holding a live key, someone able to review an
    action the policy maps), which a chain of first-done times cannot express. They un-tick
    when their record stops holding; the first request and the first decision are the
    earliest record and stay done.
    """
    params: dict[str, Any] = {"t": tenant, "s": space, "now": now}
    connected = bool(conn.execute(text(_CONNECTED), params).scalar_one())
    milestones: dict[str, SetupMilestone] = {}

    policy = conn.execute(text(_POLICY), params).mappings().one_or_none()
    milestones["policy"] = (
        SetupMilestone("policy", "todo")
        if policy is None
        else SetupMilestone(
            "policy",
            "done",
            at=_utc(policy["changed_at"]),
            record_kind="bundle",
            record_id=UUID(str(policy["bundle_id"])),
        )
    )

    agent = conn.execute(text(_AGENT_KEY), params).mappings().one_or_none()
    milestones["agent_key"] = (
        SetupMilestone("agent_key", "todo")
        if agent is None
        else SetupMilestone(
            "agent_key",
            "done",
            at=_utc(agent["at"]),
            record_kind="agent",
            record_id=UUID(str(agent["principal_id"])),
        )
    )

    first = conn.execute(text(_FIRST_REQUEST), params).mappings().one_or_none()
    milestones["first_request"] = (
        SetupMilestone("first_request", "todo")
        if first is None
        else SetupMilestone(
            "first_request",
            "done",
            at=_utc(first["created_at"]),
            record_kind="execution",
            record_id=UUID(str(first["execution_id"])),
            request_ref=str(first["request_ref"]),
        )
    )

    decided = conn.execute(text(_FIRST_DECISION), params).mappings().one_or_none()
    decision = (
        None
        if decided is None
        else SetupMilestone(
            "first_decision",
            "done",
            at=_utc(decided["decided_at"]),
            record_kind="execution",
            record_id=UUID(str(decided["execution_id"])),
            request_ref=str(decided["request_ref"]),
        )
    )

    if policy is None:
        milestones["reviewer"] = SetupMilestone("reviewer", "todo")
        milestones["first_decision"] = decision or SetupMilestone("first_decision", "todo")
    elif not policy["reviews"]:
        milestones["reviewer"] = SetupMilestone("reviewer", "not_applicable")
        milestones["first_decision"] = decision or SetupMilestone(
            "first_decision", "not_applicable"
        )
    else:
        reviewer = conn.execute(
            text(_REVIEWER), {**params, "bundle": policy["bundle_id"]}
        ).scalar_one_or_none()
        milestones["reviewer"] = (
            SetupMilestone("reviewer", "todo")
            if reviewer is None
            else SetupMilestone(
                "reviewer", "done", record_kind="approver", record_id=UUID(str(reviewer))
            )
        )
        milestones["first_decision"] = decision or SetupMilestone("first_decision", "todo")

    observed: dict[str, int] | None = None
    since: datetime | None = None
    if observing:
        # No approval can be created while the workspace observes, so a decision still owed
        # cannot be made now: it stays required, and is never offered as the next step.
        if milestones["first_decision"].state == "todo":
            milestones["first_decision"] = SetupMilestone("first_decision", "needs_enforcing")
        since = now - OBSERVED_WINDOW
        observed = dict.fromkeys(_OBSERVED_KEYS.values(), 0)
        for row in conn.execute(text(_OBSERVED), {**params, "since": since}).mappings():
            key = _OBSERVED_KEYS.get(str(row["effect"]))
            if key is not None:
                observed[key] = int(row["n"])
        since = since.astimezone(UTC)

    return SetupState(
        connected=connected,
        milestones=tuple(milestones[key] for key in SETUP_KEYS),
        observed=observed,
        observed_since=since,
    )
