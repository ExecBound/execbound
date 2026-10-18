# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only wording of Cedar syntax, never an authorization decision.

Unsupported syntax invalidates a whole policy's reading, so a missing condition cannot
look like an unconditional permit. The exact documents accompany even a partial reading.
"""

import json
from typing import Any

import cedarpy

from execbound.operations import CatalogError, operation

_VARIABLES = {"principal": "agent", "action": "action", "resource": "target", "context": "context"}
_OPERATORS = {
    "==": "equals",
    "!=": "does not equal",
    "<": "is less than",
    "<=": "is at most",
    ">": "is greater than",
    ">=": "is at least",
    "&&": "AND",
    "||": "OR",
}


def _entity(value: dict[str, Any]) -> str:
    if set(value) != {"type", "id"} or not all(isinstance(v, str) for v in value.values()):
        raise ValueError
    return f"{value['type']}::{json.dumps(value['id'], ensure_ascii=True)}"


def _expression(node: dict[str, Any], depth: int = 0) -> str:
    if depth > 32 or not isinstance(node, dict) or len(node) != 1:
        raise ValueError
    operator, value = next(iter(node.items()))
    if operator == "Var":
        return _VARIABLES[value]
    if operator == "Value":
        if type(value) in (str, bool, int):
            return json.dumps(value, ensure_ascii=True)
        if isinstance(value, dict) and set(value) == {"__entity"}:
            return _entity(value["__entity"])
        raise ValueError
    if operator == "." and set(value) == {"left", "attr"}:
        attr = value["attr"]
        base = _expression(value["left"], depth + 1)
        return (
            f"{base}.{attr.replace('_', ' ')}"
            if attr.isidentifier()
            else f"{base}[{json.dumps(attr)}]"
        )
    if operator in _OPERATORS and set(value) == {"left", "right"}:
        left, right = (_expression(value[key], depth + 1) for key in ("left", "right"))
        return f"({left} {_OPERATORS[operator]} {right})"
    if operator == "!":
        return f"NOT ({_expression(value, depth + 1)})"
    raise ValueError


def _scope(name: str, scope: dict[str, Any]) -> str:
    label = _VARIABLES[name]
    if scope == {"op": "All"}:
        return f"any {label}"
    if set(scope) == {"op", "entity"} and scope["op"] == "==":
        if name == "action" and scope["entity"].get("type") == "ExecBound::Action":
            identifier = scope["entity"]["id"]
            try:
                return f"action is {operation(identifier).label} ({identifier})"
            except CatalogError:
                pass
        return f"{label} equals {_entity(scope['entity'])}"
    raise ValueError


def _description(policy: dict[str, Any]) -> str:
    result = "; ".join(_scope(key, policy[key]) for key in ("principal", "action", "resource"))
    for condition in policy["conditions"]:
        if set(condition) != {"kind", "body"} or condition["kind"] not in {"when", "unless"}:
            raise ValueError
        result += f"; {condition['kind']} {_expression(condition['body'])}"
    if len(result) > 8192:
        raise ValueError
    return result + "."


def document_reading(authorization: str, approval: str) -> dict[str, Any]:
    """Preserve policy-set identity, scope and every condition, or decline that reading."""
    result: dict[str, Any] = {
        "authorization_policies": authorization,
        "approval_policies": approval,
        "rules": [],
        "complete": True,
    }
    for kind, source in (("authorization", authorization), ("approval", approval)):
        try:
            parsed = json.loads(cedarpy.policies_to_json_str(source))
            if parsed["templates"] or parsed["templateLinks"]:
                raise ValueError
            policies = parsed["staticPolicies"]
            if len(policies) > 200:
                raise ValueError
        except Exception:
            result["complete"] = False
            continue
        for identifier, policy in policies.items():
            effect = {"permit": "Allow", "forbid": "Deny"}.get(policy.get("effect"))
            if effect is None or (kind == "approval" and effect != "Allow"):
                result["complete"] = False
                continue
            if kind == "approval":
                effect = "Require approval"
            try:
                description = _description(policy)
            except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
                description = None
                result["complete"] = False
            result["rules"].append(
                {
                    "id": f"{kind}:{identifier}",
                    "effect": effect,
                    "description": description,
                }
            )
    return result
