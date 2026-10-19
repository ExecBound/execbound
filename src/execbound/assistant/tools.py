# SPDX-License-Identifier: AGPL-3.0-only
"""The read tools: each a thin wrapper over a function a page already uses.

Every tool runs with the asking person's session, inside the tenant fence, through the same
function the page calls, so it can read exactly what that person can read and nothing more:
a refusal by the page function is a `found: false` answer, never an error the model could
reason about. There is no generic query, no tool that writes and no tool that reaches a
provider. Each result is an explicit projection, bounded in rows and in text, with every
string that came from tenant data inside an `untrusted` envelope, and every result passes
the secret check before it leaves this module.
"""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text

from execbound.administration import AdministrationError
from execbound.assistant.client import ToolSpec
from execbound.assistant.help import TOPICS, text_of
from execbound.domains import BooleanDomain, IntegerDomain, StringDomain
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import MonitorError
from execbound.operations import CatalogError
from execbound.policy.models import BundleContent
from execbound.policy.rulesets import (
    FieldChoice,
    review_rule_ids,
    rules_for,
    sentence,
    writable_fields,
)
from execbound.policy.store import PolicyStoreError, load_active_bundle
from execbound.runtime import Runtime
from execbound.secrets import find_secrets
from execbound.surfaces.agents_pages import agent_overview
from execbound.surfaces.dashboard import overview as dashboard_overview
from execbound.surfaces.human import records
from execbound.surfaces.sessions import Session, SessionError

MAX_ROWS = 50
MAX_TEXT = 500
MAX_STEP = 200
# The catalog does not record reversal; these are the pairs the SOC pack ships, stated here
# so an explanation can say what undoes an action, and nothing is claimed for any other.
REVERSED_BY = {
    "endpoint.isolate": "endpoint.lift_isolation",
    "endpoint.lift_isolation": "endpoint.isolate",
    "identity.disable": "identity.enable",
    "identity.enable": "identity.disable",
}
# Every refusal a page function can make; each becomes `found: false` with the code.
REFUSALS = (ExecutionError, PolicyStoreError, AdministrationError, SessionError, MonitorError)


class ToolError(Exception):
    """`UNKNOWN_TOOL`, `INVALID_ARGUMENTS` or `REFUSED_SECRET`; each ends the turn."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ToolContext:
    runtime: Runtime
    session: Session


@dataclass(frozen=True)
class ToolResult:
    name: str
    data: dict[str, Any]
    ids: tuple[str, ...]
    step: str


def untrusted(value: object) -> dict[str, str] | None:
    """Tenant text inside its envelope, bounded; the instructions say it is never an order."""
    if value is None:
        return None
    return {"untrusted": str(value)[:MAX_TEXT]}


def _when(value: object) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


def _uuid(value: Any) -> UUID:
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        raise ToolError("INVALID_ARGUMENTS") from None


def _refused(code: str) -> dict[str, Any]:
    return {"found": False, "reason": code}


# --- Projections ---------------------------------------------------------------------------


def _facts(frozen: Any) -> list[dict[str, Any]]:
    return [
        {
            "name": fact.name,
            "value": fact.value,
            "origin": fact.origin,
            "source_kind": fact.source_kind,
            "observed_at": _when(fact.observed_at),
            "valid_until": _when(fact.valid_until),
        }
        for fact in frozen.facts
    ]


def _execution(row: Mapping[str, Any], *, detail: bool) -> tuple[dict[str, Any], list[str]]:
    frozen = store.frozen(dict(row))
    approval = row.get("approval")
    ids = [str(row["execution_id"])]
    data: dict[str, Any] = {
        "execution_id": str(row["execution_id"]),
        "state": row["state"],
        "action": frozen.intent.action,
        "resource_type": frozen.intent.resource_type,
        "canonical_target_id": str(row["canonical_target_id"]),
        "agent_principal_id": str(row["principal_id"]),
        "created_at": _when(row["created_at"]),
        "changed_at": _when(row["changed_at"]),
    }
    if approval:
        ids.append(str(approval["approval_id"]))
        data["approval"] = {
            "approval_id": str(approval["approval_id"]),
            "state": approval["state"],
            "deadline": _when(approval["expires_at"]),
        }
    if detail:
        data["target"] = {
            "kind": frozen.request.target.kind,
            "value": untrusted(frozen.request.target.value),
        }
        data["arguments"] = {
            name: untrusted(value) if isinstance(value, str) else value
            for name, value in dict(frozen.request.arguments).items()
        }
        data["facts"] = _facts(frozen)
        data["resolved_at"] = _when(frozen.resolved_at)
    return data, ids


def _approval(row: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    approval = row["approval"]
    decisions = [
        {
            "principal_id": str(decision["principal_id"]),
            "decision": decision["decision"],
            "decided_at": _when(decision["decided_at"]),
        }
        for decision in (row.get("decisions") or [])
    ]
    data = {
        "approval_id": str(approval["approval_id"]),
        "execution_id": str(row["execution_id"]),
        "state": approval["state"],
        "obligation_ids": [str(value) for value in (approval.get("obligation_ids") or [])],
        "created_at": _when(approval["created_at"]),
        "deadline": _when(approval["expires_at"]),
        "decided_at": _when(approval.get("decided_at")),
        "decisions": decisions,
    }
    return data, [str(approval["approval_id"]), str(row["execution_id"])]


def _decision_events(context: ToolContext, execution_id: UUID) -> list[dict[str, Any]]:
    """The kernel's own record of what it decided about this request, from the audit chain."""
    tenant = context.session.identity.tenant_id
    with context.runtime.db.transaction(tenant) as conn:
        rows = conn.execute(
            text(
                "SELECT kind, occurred_at, payload FROM execbound.audit_events "
                "WHERE tenant_id=:t AND kind IN ('execution.evaluated', 'execution.rejected') "
                "AND payload->>'execution_id' = :e ORDER BY sequence LIMIT 20"
            ),
            {"t": tenant, "e": str(execution_id)},
        ).mappings()
        events = []
        for row in rows:
            payload = row["payload"] or {}
            decision = payload.get("decision") or {}
            events.append(
                {
                    "kind": row["kind"],
                    "at": _when(row["occurred_at"]),
                    "stage": payload.get("stage"),
                    "effect": decision.get("effect"),
                    "reasons": [str(value) for value in (decision.get("reasons") or [])][:10],
                    "obligation_ids": [
                        str(value) for value in (decision.get("obligation_ids") or [])
                    ][:10],
                }
            )
        return events


# --- Tools ------------------------------------------------------------------------------


def tool_overview(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    data = dashboard_overview(context.runtime, context.session)
    denials: list[dict[str, Any]] = [
        {
            "execution_id": str(item.get("execution_id")),
            "action": item.get("action"),
            "reasons": [str(value) for value in (item.get("reasons") or [])][:10],
            "at": _when(item.get("created_at") or item.get("changed_at")),
        }
        for item in (data.get("denials") or [])[:10]
    ]
    bundle_id = str(data["bundle_id"]) if data.get("bundle_id") else None
    projected: dict[str, Any] = {
        key: data.get(key)
        for key in (
            "mode",
            "deadline",
            "pending",
            "lapsed",
            "unsettled",
            "denied",
            "executed",
            "observed",
        )
    }
    projected["bundle_id"] = bundle_id
    projected["activated_at"] = _when(data.get("activated_at"))
    projected["recent_denials"] = denials
    ids: list[str] = [str(row["execution_id"]) for row in denials]
    if bundle_id:
        ids.append(bundle_id)
    return ToolResult("overview", projected, tuple(ids), "Read the overview")


def tool_list_executions(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    limit = int(arguments.get("limit", 20))
    hours = arguments.get("since_hours")
    now = store.now(context.runtime.clock)
    principal = arguments.get("agent_principal_id")
    rows = records(
        context.runtime,
        context.session,
        state=arguments.get("state"),
        action=arguments.get("action"),
        principal=_uuid(principal) if principal else None,
        since=now - timedelta(hours=int(hours)) if hours else None,
        limit=limit,
    )
    items: list[dict[str, Any]] = []
    ids: list[str] = []
    for row in rows[:limit]:
        data, found = _execution(row, detail=False)
        items.append(data)
        ids.extend(found)
    return ToolResult(
        "list_executions",
        {"executions": items, "count": len(items)},
        tuple(ids),
        f"Read {len(items)} executions",
    )


def tool_get_execution(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    execution_id = _uuid(arguments["execution_id"])
    rows = records(context.runtime, context.session, execution_id=execution_id, limit=1)
    if not rows:
        return ToolResult("get_execution", _refused("NOT_FOUND"), (), "Read no execution")
    data, ids = _execution(rows[0], detail=True)
    data["found"] = True
    data["events"] = _decision_events(context, execution_id)
    if rows[0].get("approval"):
        approval, more = _approval(rows[0])
        data["approval"] = approval
        ids = list(dict.fromkeys([*ids, *more]))
    return ToolResult("get_execution", data, tuple(ids), f"Read execution {str(execution_id)[:8]}")


def tool_get_approval(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    approval_id = _uuid(arguments["approval_id"])
    rows = records(context.runtime, context.session, approval_id=approval_id, limit=1)
    if not rows or not rows[0].get("approval"):
        return ToolResult("get_approval", _refused("NOT_FOUND"), (), "Read no approval")
    data, ids = _approval(rows[0])
    data["found"] = True
    execution, more = _execution(rows[0], detail=True)
    data["execution"] = execution
    # What the active bundle says about the obligations: the quorum, and the rule's own name
    # when the bundle was written as rules.
    try:
        bundle = load_active_bundle(
            context.runtime.db, context.session.identity, context.runtime.clock
        )
    except PolicyStoreError:
        bundle = None
    required = 1
    names: dict[str, str] = {}
    if bundle is not None:
        for rule in bundle.quorum or ():
            if rule.obligation in data["obligation_ids"]:
                required = max(required, rule.required)
        if bundle.ruleset is not None:
            names = {
                obligation: rule_id
                for obligation, rule_id in review_rule_ids(bundle.ruleset).items()
                if obligation in data["obligation_ids"]
            }
    data["required_approvers"] = required
    data["rules"] = names
    ids = list(dict.fromkeys([*ids, *more, *names.values()]))
    return ToolResult("get_approval", data, tuple(ids), f"Read approval {str(approval_id)[:8]}")


def _served_actions(context: ToolContext, bundle: BundleContent) -> list[str]:
    """The catalog action each of the bundle's mappings serves, read from the tenant's mapping
    row, as admission dispatches it and the Agents page reads it (`agents_pages.limit_rows`).

    Never the ref's own name: a bundle written by hand may map an action under another ref and
    leave `action` out, which the store accepts because it reads such a bundle by its rows
    (`policy/store._components`). Every action the bundle names is listed, whichever space's
    account serves it, because this describes the policy rather than what one agent may reach.
    """
    tenant = context.session.identity.tenant_id
    with context.runtime.db.transaction(tenant) as conn:
        served = conn.execute(
            text(
                "SELECT DISTINCT action FROM execbound.operation_mappings "
                "WHERE tenant_id = :t AND operation_ref = ANY(:refs)"
            ),
            {"t": tenant, "refs": [mapping.operation_ref for mapping in bundle.mappings]},
        ).scalars()
        return sorted(str(action) for action in served)


def tool_get_policy(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    bundle = load_active_bundle(context.runtime.db, context.session.identity, context.runtime.clock)
    ids = [str(bundle.bundle_id)]
    data: dict[str, Any] = {
        "found": True,
        "bundle_id": str(bundle.bundle_id),
        "actions": _served_actions(context, bundle),
        "limits": [
            {
                "rule_id": rule.rule_id,
                "action": rule.action,
                "scope": rule.scope,
                "max_targets": rule.max_targets,
                "window_seconds": rule.window_seconds,
                "budget": rule.budget,
                "on_exceed": rule.on_exceed,
            }
            for rule in bundle.limits
        ],
        "quorum": [
            {"rule_id": rule.rule_id, "required": rule.required, "obligation": rule.obligation}
            for rule in (bundle.quorum or ())
        ],
    }
    if bundle.ruleset is not None:
        rules = []
        for action in data["actions"]:
            for rule in rules_for(bundle.ruleset, action):
                rules.append(
                    {
                        "id": rule.id,
                        "action": rule.action,
                        "effect": rule.effect,
                        "sentence": sentence(rule),
                        "note": untrusted(rule.note) if rule.note else None,
                    }
                )
                ids.append(rule.id)
        data["written_as"] = "rules"
        data["rules"] = rules
    else:
        data["written_as"] = "policy text"
        data["authorization_policies"] = untrusted(bundle.authorization_policies)
        data["approval_policies"] = untrusted(bundle.approval_policies)
    return ToolResult("get_policy", data, tuple(ids), "Read the active policy")


def _agent(context: ToolContext, principal: UUID) -> dict[str, Any]:
    return agent_overview(context.runtime, context.session, principal)


def tool_get_limits(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    principal = _uuid(arguments["agent_principal_id"])
    detail = _agent(context, principal)
    rows = []
    for row in detail.get("limits") or []:
        rule = row.get("rule")
        rows.append(
            {
                "rule_id": getattr(rule, "rule_id", None),
                "action": getattr(rule, "action", None),
                "scope": getattr(rule, "scope", None),
                "max_targets": getattr(rule, "max_targets", None),
                "budget": getattr(rule, "budget", None),
                "on_exceed": getattr(rule, "on_exceed", None),
                "window": row.get("window"),
                "used": row.get("count"),
            }
        )
    data = {"found": True, "agent_principal_id": str(principal), "limits": rows[:MAX_ROWS]}
    return ToolResult(
        "get_limits", data, (str(principal),), f"Read limits of agent {str(principal)[:8]}"
    )


def tool_get_agent(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    principal = _uuid(arguments["agent_principal_id"])
    detail = _agent(context, principal)
    agent = detail["agent"]
    binding = detail.get("binding")
    reach: list[dict[str, Any]] = [
        {
            "action": row.get("action"),
            "certainty": row.get("certainty"),
            "mode": row.get("mode"),
            # The page carries a rule's effect and its identity apart; the model reads the
            # same words it read before, one string a rule.
            "rules": [f"{rule['effect']} {rule['id']}" for rule in (row.get("rules") or [])][:10],
        }
        for row in (detail.get("reach") or [])[:MAX_ROWS]
    ]
    recent: list[dict[str, Any]] = [
        {
            "execution_id": str(row["execution_id"]),
            "state": row.get("state"),
            "canonical_target_id": (
                str(row["canonical_target_id"]) if row.get("canonical_target_id") else None
            ),
            "created_at": _when(row.get("created_at")),
        }
        for row in (detail.get("recent") or [])[:MAX_ROWS]
    ]
    bound: dict[str, Any] | None = (
        {"agent_id": str(binding["agent_id"]), "bound_at": _when(binding.get("bound_at"))}
        if binding
        else None
    )
    data: dict[str, Any] = {
        "found": True,
        "agent_principal_id": str(principal),
        "label": untrusted(agent.get("label")),
        "active": bool(agent.get("active")),
        "requests_this_month": detail.get("requests"),
        "reach": reach,
        "recent": recent,
        "binding": bound,
    }
    ids: list[str] = [str(principal), *(str(row["execution_id"]) for row in recent)]
    return ToolResult("get_agent", data, tuple(ids), f"Read agent {str(principal)[:8]}")


def tool_list_findings(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    limit = int(arguments.get("limit", 20))
    wanted = arguments.get("state", "open")
    snapshot = monitor_store.snapshot(
        context.runtime.db, context.session, clock=context.runtime.clock
    )
    rows: list[dict[str, Any]] = []
    for row in snapshot.get("findings") or []:
        acknowledged = row.get("acknowledged_at") is not None
        if (wanted == "open" and acknowledged) or (wanted == "acknowledged" and not acknowledged):
            continue
        rows.append(
            {
                "finding_id": str(row["finding_id"]),
                "title": untrusted(row.get("title")),
                "rule_version": row.get("rule_version"),
                "created_at": _when(row.get("created_at")),
                "acknowledged_at": _when(row.get("acknowledged_at")),
                "action": row.get("action"),
                "target": untrusted(row.get("target_ref")),
                "outcome": untrusted(row.get("outcome")),
                "actor": untrusted(row.get("actor_ref")),
                # Raised by the synthetic directory (#355): about no real actor or directory.
                "synthetic": bool(row.get("synthetic")),
            }
        )
        if len(rows) >= limit:
            break
    ids = [row["finding_id"] for row in rows]
    return ToolResult(
        "list_findings",
        {"findings": rows, "count": len(rows)},
        tuple(ids),
        f"Read {len(rows)} findings",
    )


def _domain(domain: object) -> dict[str, Any]:
    if isinstance(domain, StringDomain):
        return {"type": "string", "values": sorted(domain.values)}
    if isinstance(domain, IntegerDomain):
        return {"type": "integer", "minimum": domain.minimum, "maximum": domain.maximum}
    if isinstance(domain, BooleanDomain):
        return {"type": "boolean"}
    return {"type": type(domain).__name__}


def tool_explain_action(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    name = str(arguments["action"])
    actions = context.runtime.catalog.actions
    try:
        spec = actions.action(name)
    except CatalogError:
        return ToolResult("explain_action", _refused("UNKNOWN_ACTION"), (), "Read no action")
    data = {
        "found": True,
        "action": spec.action,
        "label": spec.label,
        "resource_type": spec.resource_type,
        "context_contract_version": spec.context_contract_version,
        "arguments": [
            {"name": argument.name, **_domain(argument.domain)} for argument in spec.arguments
        ],
        "bindings": [
            {"provider": binding.provider, "operation": binding.provider_operation}
            for binding in actions.bindings
            if binding.action == spec.action
        ],
        "reversed_by": REVERSED_BY.get(spec.action),
        "reversal_recorded": spec.action in REVERSED_BY,
    }
    return ToolResult("explain_action", data, (spec.action,), f"Read action {spec.action}")


def tool_help(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    """One packaged help text. The only tool that reads nothing of the tenant's, so it is
    also the only one whose answer is the same for everyone."""
    topic = str(arguments["topic"])
    if topic not in TOPICS:
        return ToolResult("help", _refused("UNKNOWN_TOPIC"), (), "Read no help text")
    data = {"found": True, "topic": topic, "text": text_of(topic)}
    return ToolResult("help", data, (), f"Read the help text on {topic}")


def _field(choice: FieldChoice) -> dict[str, Any]:
    data: dict[str, Any] = {
        "kind": choice.kind,
        "name": choice.name,
        "type": choice.cedar_type,
        "operators": list(choice.operators),
    }
    if choice.values:
        data["values"] = list(choice.values)
    if choice.minimum is not None:
        data["minimum"], data["maximum"] = choice.minimum, choice.maximum
    return data


def tool_get_contract(context: ToolContext, arguments: Mapping[str, Any]) -> ToolResult:
    """What a rule's condition may name, for the actions the active bundle maps.

    The catalog's own declaration: each fact and argument with its type, the operators that
    type admits and the values its domain admits. Nothing of the tenant's is in it, so it is
    the same answer for everyone, but it is read through the active bundle because the
    mappings are what decide which actions exist for this tenant.
    """
    bundle = load_active_bundle(context.runtime.db, context.session.identity, context.runtime.clock)
    fields = writable_fields(bundle.mappings, catalog=context.runtime.catalog)
    wanted = arguments.get("action")
    if wanted is not None:
        if wanted not in fields:
            return ToolResult("get_contract", _refused("NO_MAPPING"), (), "Read no contract")
        fields = {str(wanted): fields[str(wanted)]}
    data = {
        "found": True,
        "actions": [
            {"action": action, "fields": [_field(choice) for choice in choices]}
            for action, choices in sorted(fields.items())
        ],
    }
    named = ", ".join(sorted(fields)) if len(fields) == 1 else f"{len(fields)} actions"
    return ToolResult("get_contract", data, tuple(sorted(fields)), f"Read the contract of {named}")


Handler = Callable[[ToolContext, Mapping[str, Any]], ToolResult]

_ID = {"type": "string", "description": "A UUID as the pages print it."}
TOOLS: tuple[tuple[ToolSpec, Handler], ...] = (
    (
        ToolSpec(
            "overview",
            "The home page's figures: the active bundle, the enforcement mode, the approval "
            "deadline, pending, lapsed, unsettled, denied and executed counts, and recent "
            "denials. `pending` is the approvals a person can still decide; `lapsed` is those "
            "that ran out of time before a decision and await the recovery run's cleanup.",
            {},
        ),
        tool_overview,
    ),
    (
        ToolSpec(
            "list_executions",
            "Executions the asking person may see, newest first, at most 50. Filters are "
            "optional: a state, a catalog action, an agent's principal id, a window in hours.",
            {
                "state": {"type": "string", "description": "An execution state, exactly."},
                "action": {"type": "string", "description": "A catalog action name."},
                "agent_principal_id": _ID,
                "since_hours": {"type": "integer", "minimum": 1, "maximum": 720},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
            },
        ),
        tool_list_executions,
    ),
    (
        ToolSpec(
            "get_execution",
            "One execution: the frozen intent in words (action, target, arguments), the facts "
            "it was decided on with their sources, its state, its approval and the kernel's "
            "decision events with reasons and obligations.",
            {"execution_id": _ID},
            required=("execution_id",),
        ),
        tool_get_execution,
    ),
    (
        ToolSpec(
            "get_approval",
            "One approval: its state, obligations, deadline, required approvers, decisions so "
            "far, the rule behind each obligation when the policy was written as rules, and "
            "the execution it decides.",
            {"approval_id": _ID},
            required=("approval_id",),
        ),
        tool_get_approval,
    ),
    (
        ToolSpec(
            "get_policy",
            "The active policy bundle: its actions, limits and quorum, and its rules as "
            "sentences when it was written as rules, else its policy text.",
            {},
        ),
        tool_get_policy,
    ),
    (
        ToolSpec(
            "get_limits",
            "The budgets an agent draws on and their current use, as the Agents page shows "
            "them. Administrators only.",
            {"agent_principal_id": _ID},
            required=("agent_principal_id",),
        ),
        tool_get_limits,
    ),
    (
        ToolSpec(
            "get_agent",
            "One governed agent: label, reach through ExecBound, recent requests, binding. "
            "Administrators only.",
            {"agent_principal_id": _ID},
            required=("agent_principal_id",),
        ),
        tool_get_agent,
    ),
    (
        ToolSpec(
            "list_findings",
            "Monitoring findings with their rule and state, newest first, at most 50. One with "
            "`synthetic` true was raised by the synthetic directory, which exists only in "
            "ExecBound: it describes no real actor and no real directory.",
            {
                "state": {"type": "string", "enum": ["open", "acknowledged", "all"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
            },
        ),
        tool_list_findings,
    ),
    (
        ToolSpec(
            "get_contract",
            "What a rule's condition may name: for each action the active bundle maps, its "
            "facts and arguments with their types, the operators each admits and the values "
            "its domain admits. Name one action to read only that one.",
            {"action": {"type": "string", "description": "A catalog action name."}},
        ),
        tool_get_contract,
    ),
    (
        ToolSpec(
            "help",
            "One packaged help text about how ExecBound works, by topic: "
            + ", ".join(sorted(TOPICS))
            + ".",
            {"topic": {"type": "string", "enum": sorted(TOPICS)}},
            required=("topic",),
        ),
        tool_help,
    ),
    (
        ToolSpec(
            "explain_action",
            "The catalog entry for an action: its arguments with their domains, its provider "
            "bindings, and what reverses it when that is recorded.",
            {"action": {"type": "string", "description": "A catalog action name."}},
            required=("action",),
        ),
        tool_explain_action,
    ),
)
SPECS: tuple[ToolSpec, ...] = tuple(spec for spec, _ in TOOLS)
_HANDLERS: dict[str, tuple[ToolSpec, Handler]] = {
    spec.name: (spec, handler) for spec, handler in TOOLS
}


def validate_arguments(spec: ToolSpec, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """The schema the provider enforces, enforced here again: nothing is trusted to have
    been checked elsewhere."""
    if not isinstance(arguments, Mapping) or set(arguments) - set(spec.parameters):
        raise ToolError("INVALID_ARGUMENTS")
    if any(name not in arguments for name in spec.required):
        raise ToolError("INVALID_ARGUMENTS")
    checked: dict[str, Any] = {}
    for name, value in arguments.items():
        schema = spec.parameters[name]
        kind = schema["type"]
        if kind == "string":
            if type(value) is not str or not 1 <= len(value) <= 254:
                raise ToolError("INVALID_ARGUMENTS")
            if "enum" in schema and value not in schema["enum"]:
                raise ToolError("INVALID_ARGUMENTS")
        elif kind == "integer":
            if type(value) is not int:
                raise ToolError("INVALID_ARGUMENTS")
            if not schema.get("minimum", value) <= value <= schema.get("maximum", value):
                raise ToolError("INVALID_ARGUMENTS")
        else:
            raise ToolError("INVALID_ARGUMENTS")
        checked[name] = value
    return checked


def run_tool(context: ToolContext, name: str, arguments: Mapping[str, Any]) -> ToolResult:
    """One tool call: validated, run under the person's authority, projected, secret-checked.

    A page function's refusal is an answer (`found: false` with its code), because the
    person could not have read it either; a secret in a result ends the turn.
    """
    found = _HANDLERS.get(name)
    if found is None:
        raise ToolError("UNKNOWN_TOOL")
    spec, handler = found
    checked = validate_arguments(spec, arguments)
    try:
        result = handler(context, checked)
    except REFUSALS as exc:
        code = getattr(exc, "code", None) or "REFUSED"
        result = ToolResult(name, _refused(str(code)), (), f"Read nothing from {name}")
    if find_secrets(result.data, limit=1):
        raise ToolError("REFUSED_SECRET")
    # The projection is JSON: the model receives text, never an object.
    json.dumps(result.data)
    return ToolResult(result.name, result.data, result.ids, result.step[:MAX_STEP])
