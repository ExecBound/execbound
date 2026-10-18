# SPDX-License-Identifier: AGPL-3.0-only
"""The real pinned Cedar engine must fail closed at the application boundary."""

import json
from copy import deepcopy
from dataclasses import FrozenInstanceError

import cedarpy
import pytest

from execbound.policy import cedar

SCHEMA = """
entity Agent;
entity Resource = {environment: String, number: Long};
action "isolate" appliesTo {
    principal: [Agent], resource: [Resource], context: {justified: Bool}
};
"""
PERMIT = "permit(principal, action, resource);"
FORBID = "forbid(principal, action, resource);"
OVERFLOW_FORBID = """
forbid(principal, action, resource) when { resource.number + 1 > 0 };
"""
OVERFLOW_APPROVAL = OVERFLOW_FORBID.replace("forbid", "permit")
APPROVAL = """
permit(principal, action, resource) when { resource.environment == "production" };
"""
REQUEST = {
    "principal": {"type": "Agent", "id": "a"},
    "action": {"type": "Action", "id": "isolate"},
    "resource": {"type": "Resource", "id": "r"},
    "context": {"justified": True},
}
ENTITIES = [
    {"uid": REQUEST["principal"], "attrs": {}, "parents": []},
    {
        "uid": REQUEST["resource"],
        "attrs": {"environment": "production", "number": 9223372036854775807},
        "parents": [],
    },
]


def evaluate(*, authorization=PERMIT, approval="", schema=SCHEMA, request=None, entities=None):
    return cedar.evaluate_policy_sets(
        schema=schema,
        authorization=authorization,
        approval=approval,
        request=deepcopy(REQUEST if request is None else request),
        entities=deepcopy(ENTITIES if entities is None else entities),
    )


def test_explicitly_empty_approval_set_is_valid_and_creates_no_obligation():
    cedar.validate_policy_sets(schema=SCHEMA, authorization=PERMIT, approval="")
    assert evaluate() == cedar.CedarDecision(True, (), False)


def test_authorization_accepts_forbid_and_it_overrides_permits_and_approvals():
    cedar.validate_policy_sets(schema=SCHEMA, authorization=PERMIT + FORBID, approval=APPROVAL)
    assert evaluate(authorization=PERMIT + FORBID, approval=APPROVAL) == cedar.CedarDecision(
        False, (), False
    )


def test_approval_cannot_supply_missing_base_authorization():
    assert evaluate(authorization="", approval=PERMIT) == cedar.CedarDecision(False, (), False)


def test_false_approval_condition_creates_no_obligation():
    assert evaluate(approval=APPROVAL.replace("production", "development")) == cedar.CedarDecision(
        True, (), False
    )


def test_approval_identifiers_are_sorted_engine_ids_not_annotation_values():
    policies = "\n".join(f'@id("same-label") {PERMIT}' for _ in range(12))
    assert evaluate(approval=policies) == cedar.CedarDecision(
        True, tuple(sorted(f"policy{i}" for i in range(12))), False
    )


def test_effect_validation_reads_structure_and_accepts_forbid_in_comments_and_strings():
    policies = "// forbid(principal,action,resource);\n" + APPROVAL.replace("production", "forbid")
    cedar.validate_policy_sets(schema=SCHEMA, authorization=PERMIT, approval=policies)


# Each invalid configuration, with the bundle component its refusal names.
INVALID_CONFIGURATIONS = [
    ("not a schema", PERMIT, "", "cedar_schema"),
    ("", PERMIT, "", "cedar_schema"),
    # A schema Cedar refuses fails both sets; the schema is named, not the first set.
    ("not a schema", "not a policy", "not a policy", "cedar_schema"),
    (SCHEMA, "not a policy", "", "authorization_policies"),
    (SCHEMA, PERMIT, "not a policy", "approval_policies"),
    (
        SCHEMA,
        "permit(principal,action,resource) when { resource.unknown };",
        "",
        "authorization_policies",
    ),
    (
        SCHEMA,
        PERMIT,
        'permit(principal,action,resource) when { resource.number == "x" };',
        "approval_policies",
    ),
    (SCHEMA, PERMIT, FORBID, "approval_policies"),
    (SCHEMA, PERMIT, "forbid(principal,action,resource) when { false };", "approval_policies"),
    (SCHEMA, "permit(principal == ?principal,action,resource);", "", "authorization_policies"),
    (SCHEMA, PERMIT, "permit(principal,action,resource == ?resource);", "approval_policies"),
    (SCHEMA, "not a policy", FORBID, "authorization_policies"),
    (SCHEMA, PERMIT, None, "approval_policies"),
    (SCHEMA, None, "", "authorization_policies"),
    (None, PERMIT, "", "cedar_schema"),
]


@pytest.mark.parametrize(
    ("schema", "authorization", "approval"), [case[:3] for case in INVALID_CONFIGURATIONS]
)
def test_invalid_configuration_is_rejected_without_raw_diagnostics(schema, authorization, approval):
    with pytest.raises(cedar.CedarValidationError, match="^Invalid Cedar policy configuration$"):
        cedar.validate_policy_sets(schema=schema, authorization=authorization, approval=approval)
    assert evaluate(schema=schema, authorization=authorization, approval=approval) == (
        cedar.CedarDecision(False, (), True)
    )


@pytest.mark.parametrize(
    ("schema", "authorization", "approval", "component"), INVALID_CONFIGURATIONS
)
def test_a_refused_configuration_names_the_component_at_fault(
    schema, authorization, approval, component
):
    """The bundle field a refusal can name, and nothing of Cedar's diagnostics: the schema when
    Cedar refuses it on its own, otherwise the first set that does not validate against it."""
    with pytest.raises(cedar.CedarValidationError) as refused:
        cedar.validate_policy_sets(schema=schema, authorization=authorization, approval=approval)
    assert refused.value.component == component
    assert str(refused.value) == "Invalid Cedar policy configuration"


@pytest.mark.parametrize(
    ("component", "named"),
    [
        ("schema", "cedar_schema"),
        ("authorization", "authorization_policies"),
        ("approval", "approval_policies"),
    ],
)
def test_configuration_components_have_a_utf8_byte_limit(component, named):
    values = {"schema": SCHEMA, "authorization": PERMIT, "approval": ""}
    values[component] += "//" + "é" * 65536
    with pytest.raises(cedar.CedarValidationError) as refused:
        cedar.validate_policy_sets(**values)
    assert refused.value.component == named


def test_engine_really_allows_broad_permit_while_recording_overflowing_forbid():
    result = cedarpy.is_authorized(REQUEST, PERMIT + OVERFLOW_FORBID, ENTITIES, schema=SCHEMA)
    assert result.allowed
    assert result.diagnostics.errors
    assert cedarpy.validate_policies(PERMIT + OVERFLOW_FORBID, SCHEMA).validation_passed


@pytest.mark.parametrize(
    ("authorization", "approval"),
    [
        (PERMIT + OVERFLOW_FORBID, APPROVAL),
        (PERMIT, OVERFLOW_APPROVAL),
        (PERMIT, PERMIT + OVERFLOW_APPROVAL),
        (FORBID, OVERFLOW_APPROVAL),
        ("", OVERFLOW_APPROVAL),
        (PERMIT + OVERFLOW_FORBID, OVERFLOW_APPROVAL),
    ],
)
def test_diagnostics_in_either_set_deny_even_when_base_authorization_denies(
    authorization, approval
):
    assert evaluate(authorization=authorization, approval=approval) == cedar.CedarDecision(
        False, (), True
    )


@pytest.mark.parametrize(
    "cedar_request",
    [
        {**REQUEST, "principal": {"type": "Resource", "id": "r"}},
        {**REQUEST, "action": {"type": "Action", "id": "unknown"}},
        {**REQUEST, "context": {}},
        {**REQUEST, "context": {"justified": "true"}},
        {**REQUEST, "context": {"justified": True, "extra": 1}},
        {**REQUEST, "resource": None},
        {**REQUEST, "principal": 'Agent::"a"'},
    ],
)
def test_runtime_schema_and_request_shape_are_checked(cedar_request):
    assert evaluate(request=cedar_request) == cedar.CedarDecision(False, (), True)


@pytest.mark.parametrize("missing", ["principal", "resource"])
def test_broad_permit_cannot_authorize_an_absent_request_entity(missing):
    entities = [entity for entity in ENTITIES if entity["uid"] != REQUEST[missing]]
    assert evaluate(entities=entities) == cedar.CedarDecision(False, (), True)


@pytest.mark.parametrize(
    "attrs", [{}, {"environment": "production"}, {"environment": 1, "number": 2}]
)
def test_entity_schema_is_enforced_even_when_the_policy_does_not_read_attributes(attrs):
    entities = deepcopy(ENTITIES)
    entities[1]["attrs"] = attrs
    assert evaluate(entities=entities) == cedar.CedarDecision(False, (), True)


def test_wrapped_entity_uids_are_supported():
    entities = [{**entity, "uid": {"__entity": entity["uid"]}} for entity in ENTITIES]
    assert evaluate(entities=entities) == cedar.CedarDecision(True, (), False)


@pytest.mark.parametrize("failure_set", [PERMIT, APPROVAL])
def test_engine_exception_is_safe_and_does_not_skip_the_other_set(
    failure_set, monkeypatch, capsys, caplog
):
    original = cedarpy._internal.is_authorized
    calls = []

    def unavailable(request, policies, entities, schema, verbose):
        calls.append(policies)
        if policies == failure_set:
            raise RuntimeError("synthetic-secret-in-engine-error")
        return original(request, policies, entities, schema, verbose)

    monkeypatch.setattr(cedarpy._internal, "is_authorized", unavailable)
    assert evaluate(approval=APPROVAL) == cedar.CedarDecision(False, (), True)
    assert calls == [PERMIT, APPROVAL]
    assert capsys.readouterr() == ("", "")
    assert caplog.text == ""


def test_validation_dependency_exception_is_generic(monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError("synthetic-secret-in-validation-error")

    monkeypatch.setattr(cedarpy._internal, "validate_policies", unavailable)
    with pytest.raises(
        cedar.CedarValidationError, match="^Invalid Cedar policy configuration$"
    ) as refused:
        cedar.validate_policy_sets(schema=SCHEMA, authorization=PERMIT, approval="")
    # The engine failed rather than refusing a component, so none is named.
    assert refused.value.component is None


@pytest.mark.parametrize(
    "response",
    [
        {},
        [],
        {"decision": "Allow"},
        {"decision": "Allow", "diagnostics": {}},
        {"decision": "Allow", "diagnostics": {"errors": [], "reason": []}},
        {"decision": "Maybe", "diagnostics": {"errors": [], "reason": ["policy0"]}},
        {"decision": "Allow", "diagnostics": {"errors": None, "reason": ["policy0"]}},
        {"decision": "Allow", "diagnostics": {"errors": [], "reason": ["unknown"]}},
        {"decision": "Allow", "diagnostics": {"errors": [], "reason": "policy0"}},
        {"decision": "Allow", "diagnostics": {"errors": [], "reason": [1]}},
        {"decision": "Deny", "diagnostics": {"errors": [], "reason": ["policy0"]}},
    ],
)
def test_malformed_native_responses_are_rejected(response):
    with pytest.raises(cedar.CedarValidationError):
        cedar._decode_decision(json.dumps(response), {"policy0": "permit"})


def test_decision_is_immutable():
    result = evaluate()
    with pytest.raises(FrozenInstanceError):
        result.authorized = False


def test_pinned_native_entry_points_keep_their_shape():
    """A cedarpy upgrade that changes the private entry points must fail here, not in decisions."""
    review = "cedarpy native entry point changed: review policy/cedar.py before upgrading"
    native = cedarpy._internal
    assert callable(getattr(native, "is_authorized", None)), review
    assert callable(getattr(native, "validate_policies", None)), review

    validation = native.validate_policies(PERMIT, SCHEMA)
    assert type(validation) is str, review
    parsed = json.loads(validation)
    assert parsed.get("validation_passed") is True and parsed.get("errors") == [], review

    response = native.is_authorized(
        cedar._native_request(REQUEST, ENTITIES), PERMIT, json.dumps(ENTITIES), SCHEMA, False
    )
    assert type(response) is str, review
    decision = json.loads(response)
    assert decision.get("decision") == "Allow", review
    assert decision.get("diagnostics", {}).get("errors") == [], review
    assert decision.get("diagnostics", {}).get("reason") == ["policy0"], review
