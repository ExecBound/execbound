# SPDX-License-Identifier: AGPL-3.0-only
"""Fixed synthetic Cedar examples. No runtime, provider, or mutable state is reachable."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from execbound.policy.cedar import evaluate_policy_sets


class LearningRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: Literal["workstation", "domain_controller", "production"]


class LearningResult(BaseModel):
    scenario: str
    target: str
    decision: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    reason: str
    facts: dict[str, str]
    executed: Literal[False] = False
    scope: str = "Synthetic example policy; not your workspace policy. No provider is called."


SCHEMA = """
entity Agent;
entity Endpoint = {role: String, environment: String, incident: String};
action "endpoint.isolate" appliesTo {principal: [Agent], resource: [Endpoint], context: {}};
"""
AUTHORIZATION = """
permit(principal, action, resource) when {
    resource.role == "workstation" && resource.incident == "open critical"
};
forbid(principal, action, resource) when { resource.role == "domain_controller" };
"""
APPROVAL = 'permit(principal, action, resource) when { resource.environment == "production" };'


def example(scenario: Literal["workstation", "domain_controller", "production"]) -> LearningResult:
    facts = {
        "role": "domain_controller" if scenario == "domain_controller" else "workstation",
        "environment": "production" if scenario == "production" else "development",
        "incident": "open critical",
    }
    principal = {"type": "Agent", "id": "example-agent"}
    resource = {"type": "Endpoint", "id": f"example-{scenario}"}
    result = evaluate_policy_sets(
        schema=SCHEMA,
        authorization=AUTHORIZATION,
        approval=APPROVAL,
        request={
            "principal": principal,
            "action": {"type": "Action", "id": "endpoint.isolate"},
            "resource": resource,
            "context": {},
        },
        entities=[
            {"uid": principal, "attrs": {}, "parents": []},
            {"uid": resource, "attrs": facts, "parents": []},
        ],
    )
    if result.error:
        raise ValueError("The example policy could not be evaluated.")
    decision: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"] = (
        "DENY" if not result.authorized else "REQUIRE_APPROVAL" if result.approval_ids else "ALLOW"
    )
    reasons = {
        "ALLOW": (
            "This workstation has an open critical incident and matches the example allow rule."
        ),
        "DENY": (
            "The example policy blocks domain-controller isolation. "
            "Approval cannot override a denial."
        ),
        "REQUIRE_APPROVAL": (
            "The workstation matches the allow rule, but its production environment "
            "requires human approval before execution."
        ),
    }
    return LearningResult(
        scenario=scenario,
        target=resource["id"],
        decision=decision,
        reason=reasons[decision],
        facts=facts,
    )
