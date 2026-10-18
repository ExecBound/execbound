# SPDX-License-Identifier: AGPL-3.0-only
"""Narrow boundary to cedarpy 4.12.1, with no diagnostic text escaping.

The public authorization wrapper replaces absent diagnostics with empty values.
This adapter intentionally uses the pinned native JSON entry points to reject
missing fields before trusting a result. Revisit this contract on every upgrade.
No public entry point exposes the raw response as of 4.12.1; tests/test_cedar.py
guards the private entry points and their result shapes.
"""

import json
from dataclasses import dataclass
from typing import Any

import cedarpy

_MAX_COMPONENT_BYTES = 128 * 1024
_INVALID_CONFIGURATION = "Invalid Cedar policy configuration"


class CedarValidationError(ValueError):
    """A policy dependency failed validation without exposing its diagnostics.

    `component` is the bundle field `validate_policy_sets` found at fault, when it found one;
    a field name is the only detail that leaves this module.
    """

    def __init__(self, message: str = _INVALID_CONFIGURATION, *, component: str | None = None):
        super().__init__(message)
        self.component = component


@dataclass(frozen=True)
class CedarDecision:
    authorized: bool
    approval_ids: tuple[str, ...]
    error: bool


def approval_policy_ids(*, schema: str, approval: str) -> frozenset[str]:
    """The identifiers evaluation names as ``policy:<id>`` obligations for the approval set."""
    return frozenset(_validate_set(schema, approval, permit_only=True))


def validate_policy_sets(*, schema: str, authorization: str, approval: str) -> None:
    """Validate both schema-checked sets, permitting static approval permits only.

    A refusal names the component at fault: `cedar_schema` when Cedar refuses the schema on its
    own, otherwise the first of `authorization_policies` and `approval_policies` that does not
    validate against it. An engine that fails outright, rather than refusing a component,
    names none.
    """
    try:
        _validated_sets(schema=schema, authorization=authorization, approval=approval)
    except CedarValidationError:
        raise CedarValidationError(
            component=_component_at_fault(schema, authorization, approval)
        ) from None


def evaluate_policy_sets(
    *,
    schema: str,
    authorization: str,
    approval: str,
    request: dict[str, Any],
    entities: list[dict[str, Any]],
) -> CedarDecision:
    """Evaluate complete structured requests; an error in either set denies.

    Request principal/action/resource values must be structured ``{type, id}``
    UIDs. The caller supplies trusted facts; principal and resource must both
    exist in the entity list. Cedar checks request/context and entity schemas.
    Policy IDs are Cedar's positional identifiers, scoped to immutable content.
    """
    denied_error = CedarDecision(False, (), True)
    try:
        policy_sets = _validated_sets(schema=schema, authorization=authorization, approval=approval)
        native_request = _native_request(request, entities)
        native_entities = json.dumps(entities, allow_nan=False)
    except Exception:
        return denied_error

    results: list[tuple[bool, tuple[str, ...]]] = []
    failed = False
    for policies, policy_ids in zip((authorization, approval), policy_sets, strict=True):
        try:
            response = cedarpy._internal.is_authorized(
                native_request, policies, native_entities, schema, False
            )
            results.append(_decode_decision(response, policy_ids))
        except Exception:
            # Never stop before evaluating the other set, even after a denial
            # or dependency exception. Raw engine errors may contain facts.
            failed = True
    if failed:
        return denied_error
    authorized, _ = results[0]
    _, approval_ids = results[1]
    return CedarDecision(authorized, approval_ids if authorized else (), False)


def _validated_sets(
    *, schema: str, authorization: str, approval: str
) -> tuple[dict[str, str], dict[str, str]]:
    try:
        for component in (schema, authorization, approval):
            if type(component) is not str or len(component.encode("utf-8")) > _MAX_COMPONENT_BYTES:
                raise CedarValidationError(_INVALID_CONFIGURATION)
        if not schema.strip():
            raise CedarValidationError(_INVALID_CONFIGURATION)

        results = []
        failed = False
        for policies, permit_only in ((authorization, False), (approval, True)):
            try:
                results.append(_validate_set(schema, policies, permit_only=permit_only))
            except Exception:
                failed = True
        if failed:
            raise CedarValidationError(_INVALID_CONFIGURATION)
        return results[0], results[1]
    except Exception:
        raise CedarValidationError(_INVALID_CONFIGURATION) from None


def _component_at_fault(schema: str, authorization: str, approval: str) -> str | None:
    """Check each component on its own, once validating them together has failed.

    The schema first, against no policies, because a schema Cedar refuses fails both sets and
    is the one to fix; then each set against it. A component is at fault when its check
    raises a `ValueError`, which is how Cedar's parser and this module refuse text; any other
    exception is the engine failing, which is no component's fault.
    """
    components = {
        "cedar_schema": schema,
        "authorization_policies": authorization,
        "approval_policies": approval,
    }
    for name, value in components.items():
        if type(value) is not str or len(value.encode("utf-8")) > _MAX_COMPONENT_BYTES:
            return name
    if not schema.strip():
        return "cedar_schema"
    for name, policies, permit_only in (
        ("cedar_schema", "", False),
        ("authorization_policies", authorization, False),
        ("approval_policies", approval, True),
    ):
        try:
            _validate_set(schema, policies, permit_only=permit_only)
        except ValueError:
            return name
        except Exception:
            return None
    return None


def _validate_set(schema: str, policies: str, *, permit_only: bool) -> dict[str, str]:
    parsed = json.loads(cedarpy.policies_to_json_str(policies))
    if (
        type(parsed) is not dict
        or set(parsed) != {"staticPolicies", "templates", "templateLinks"}
        or parsed["templates"] != {}
        or parsed["templateLinks"] != []
        or type(parsed["staticPolicies"]) is not dict
    ):
        raise CedarValidationError(_INVALID_CONFIGURATION)
    policy_ids: dict[str, str] = {}
    for policy_id, policy in parsed["staticPolicies"].items():
        if (
            type(policy_id) is not str
            or not policy_id
            or type(policy) is not dict
            or policy.get("effect") not in ({"permit"} if permit_only else {"permit", "forbid"})
        ):
            raise CedarValidationError(_INVALID_CONFIGURATION)
        policy_ids[policy_id] = policy["effect"]

    validation = json.loads(cedarpy._internal.validate_policies(policies, schema))
    if (
        type(validation) is not dict
        or validation.get("validation_passed") is not True
        or type(validation.get("errors")) is not list
        or validation["errors"]
    ):
        raise CedarValidationError(_INVALID_CONFIGURATION)
    return policy_ids


def _entity_uid(value: Any) -> tuple[str, str]:
    if (
        type(value) is not dict
        or set(value) != {"type", "id"}
        or type(value["type"]) is not str
        or not value["type"]
        or type(value["id"]) is not str
        or not value["id"]
    ):
        raise CedarValidationError(_INVALID_CONFIGURATION)
    return value["type"], value["id"]


def _native_request(request: dict[str, Any], entities: list[dict[str, Any]]) -> dict[str, Any]:
    if (
        type(request) is not dict
        or set(request) != {"principal", "action", "resource", "context"}
        or type(request["context"]) is not dict
        or type(entities) is not list
    ):
        raise CedarValidationError(_INVALID_CONFIGURATION)
    request_uids = {key: _entity_uid(request[key]) for key in ("principal", "action", "resource")}
    supplied_uids = set()
    for entity in entities:
        if type(entity) is not dict:
            raise CedarValidationError(_INVALID_CONFIGURATION)
        uid = entity.get("uid")
        if type(uid) is dict and set(uid) == {"__entity"}:
            uid = uid["__entity"]
        supplied_uids.add(_entity_uid(uid))
    if any(request_uids[key] not in supplied_uids for key in ("principal", "resource")):
        raise CedarValidationError(_INVALID_CONFIGURATION)
    return {**request, "context": json.dumps(request["context"], allow_nan=False)}


def _decode_decision(response: str, policies: dict[str, str]) -> tuple[bool, tuple[str, ...]]:
    """Reject incomplete diagnostics and decisions inconsistent with known effects."""
    try:
        parsed = json.loads(response)
        if type(parsed) is not dict or parsed.get("decision") not in {"Allow", "Deny"}:
            raise CedarValidationError(_INVALID_CONFIGURATION)
        diagnostics = parsed.get("diagnostics")
        if (
            type(diagnostics) is not dict
            or type(diagnostics.get("errors")) is not list
            or diagnostics["errors"]
            or type(diagnostics.get("reason")) is not list
        ):
            raise CedarValidationError(_INVALID_CONFIGURATION)
        reasons = diagnostics["reason"]
        if any(type(reason) is not str or reason not in policies for reason in reasons):
            raise CedarValidationError(_INVALID_CONFIGURATION)
        allowed = parsed["decision"] == "Allow"
        if allowed and not reasons:
            raise CedarValidationError(_INVALID_CONFIGURATION)
        expected_effect = "permit" if allowed else "forbid"
        if any(policies[reason] != expected_effect for reason in reasons):
            raise CedarValidationError(_INVALID_CONFIGURATION)
        return allowed, tuple(sorted(set(reasons)))
    except Exception:
        raise CedarValidationError(_INVALID_CONFIGURATION) from None
