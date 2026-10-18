# SPDX-License-Identifier: AGPL-3.0-only
"""The request boundary rejects ambiguous targets and caller-supplied authority."""

import json
import traceback
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from execbound.domains import LONG_MAX, LONG_MIN
from execbound.requests import (
    ActionRequest,
    Arguments,
    ClaimedContext,
    InvalidRequest,
    ResourceSelector,
    parse_request,
)

RESOURCE_ID = "ABCDEF12-3456-7890-ABCD-EF1234567890"
RUN_ID = "6d3214e8-5769-48d8-9145-35a4d89a7a81"
INCIDENT_ID = "a6acfa20-6c9b-4861-985b-cd27fa3e2693"


def payload(**changes):
    return {
        "operation_ref": "crowdstrike.contain",
        "target": {"kind": "hostname", "value": "workstation.example.test"},
        "arguments": {},
        "idempotency_key": "request-01:A.b_c",
        **changes,
    }


def wire(**changes):
    return json.dumps(payload(**changes)).encode("utf-8")


def test_accepts_required_request_and_immutable_empty_defaults():
    request = parse_request(wire())
    assert isinstance(request, ActionRequest)
    assert request.operation_ref == "crowdstrike.contain"
    assert request.target.value == "workstation.example.test"
    assert request.arguments == Arguments()
    assert request.claimed_context == ClaimedContext()
    assert request.run_id is None
    assert request.idempotency_key == "request-01:A.b_c"


def test_strict_json_preserves_uuid_and_claimed_context_types():
    request = parse_request(
        wire(
            run_id=RUN_ID,
            claimed_context={
                "incident_id": INCIDENT_ID,
                "severity": "CRITICAL",
                "environment": "production",
                "role": "domain_controller",
                "criticality": 4,
            },
        )
    )
    assert request.run_id == UUID(RUN_ID)
    assert request.claimed_context.incident_id == UUID(INCIDENT_ID)
    assert request.claimed_context.criticality == 4
    assert request.claimed_context.severity == "CRITICAL"


@pytest.mark.parametrize(
    ("kind", "value", "normalized"),
    [
        ("hostname", "WORKSTATION.Example.Test.", "workstation.example.test"),
        ("hostname", "a", "a"),
        ("hostname", "1-node.2-example", "1-node.2-example"),
        ("canonical", RESOURCE_ID, RESOURCE_ID.lower()),
        ("provider_id", "AbC.12_X-y:z", "AbC.12_X-y:z"),
        ("provider_id", "x" * 128, "x" * 128),
    ],
)
def test_selector_normalization_matches_python_and_json(kind, value, normalized):
    selector = ResourceSelector(kind=kind, value=value)
    request = parse_request(wire(target={"kind": kind, "value": value}))
    assert request.target == selector
    assert selector.value == normalized


def test_equivalent_hostnames_and_canonical_uuid_have_identical_serialization():
    for kind, first, second in [
        ("hostname", "WORKSTATION.Example.Test.", "workstation.example.test"),
        ("canonical", RESOURCE_ID, RESOURCE_ID.lower()),
    ]:
        a = parse_request(wire(target={"kind": kind, "value": first}))
        b = parse_request(wire(target={"kind": kind, "value": second}))
        assert a.model_dump_json() == b.model_dump_json()
    lower = ResourceSelector(kind="provider_id", value="abc")
    upper = ResourceSelector(kind="provider_id", value="ABC")
    assert lower != upper


@pytest.mark.parametrize("primary", ["workstation.example.test", "tier0.example.test"])
@pytest.mark.parametrize(
    "secondary",
    [
        {"targets": ["workstation.example.test", "tier0.example.test"]},
        {"resource_id": RESOURCE_ID},
        {"filter": "role:domain_controller"},
        {"arguments": {"ids": [RESOURCE_ID]}},
        {"arguments": {"options": {"target": "tier0.example.test"}}},
    ],
)
def test_q_rejects_mixed_targets_and_embedded_target_arguments(primary, secondary):
    with pytest.raises(InvalidRequest):
        parse_request(wire(target={"kind": "hostname", "value": primary}, **secondary))


@pytest.mark.parametrize(
    "arguments", [{"target": "tier0.example.test"}, {"device_id": RESOURCE_ID}]
)
def test_scalar_arguments_named_like_a_target_carry_no_authority(arguments):
    """A bounded scalar parses as an opaque option: the resolved action's catalog spec, not the
    request boundary, decides which argument names exist, and the single target stands."""
    request = parse_request(wire(arguments=arguments))
    assert request.arguments.root == arguments
    assert request.target.value == "workstation.example.test"


@pytest.mark.parametrize(
    "authority",
    [
        "tenant_id",
        "principal_id",
        "credential_id",
        "connector_id",
        "connector_account_id",
        "connector_url",
        "provider_credentials",
        "action",
        "canonical_action",
        "trusted_context",
    ],
)
def test_caller_cannot_add_authority_fields(authority):
    with pytest.raises(InvalidRequest):
        parse_request(wire(**{authority: "untrusted-authority"}))


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('"operation_ref":', '"operation_ref": "another.operation", "operation_ref":'),
        ('"kind":', '"kind": "canonical", "kind":'),
        ('"value":', '"value": "tier0.example.test", "value":'),
        ('"arguments": {}', '"arguments": {"ids": [], "ids": []}'),
        ('"arguments": {}', '"arguments": {}, "arguments": {}'),
        ('"arguments": {}', '"arguments": {}, "\\u0061rguments": {}'),
        (
            '"arguments": {}',
            '"arguments": {}, "claimed_context": {"criticality": 0, "criticality": 4}',
        ),
    ],
)
def test_rejects_duplicate_json_keys_at_every_nesting(old, new):
    raw = wire().replace(old.encode(), new.encode())
    assert raw != wire()
    with pytest.raises(InvalidRequest):
        parse_request(raw)


@pytest.mark.parametrize(
    "selector",
    [
        {"kind": "hostname", "value": "host", "provider_id": "secondary"},
        {"kind": "hostname", "value": ["primary", "secondary"]},
        [{"kind": "hostname", "value": "primary"}],
        {"kind": "url", "value": "https://example.test"},
        {"kind": "hostname", "value": 123},
        {"kind": "hostname", "value": True},
        {"kind": "hostname"},
        None,
    ],
)
def test_rejects_invalid_selector_structure(selector):
    with pytest.raises(InvalidRequest):
        parse_request(wire(target=selector))


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".",
        "host..",
        "a..b",
        ".host",
        "-host",
        "host-",
        "host_name",
        " host",
        "host ",
        "host\n",
        "host\t",
        "höst",
        "https://host",
        "host/path",
        "host:443",
        "host?query",
        "host#fragment",
        "user@host",
        "a" * 64,
        ".".join(["a" * 63] * 4),
    ],
)
def test_rejects_invalid_hostnames(value):
    with pytest.raises(InvalidRequest):
        parse_request(wire(target={"kind": "hostname", "value": value}))


def test_accepts_maximum_dns_name_and_single_trailing_root_dot():
    hostname = ".".join(["a" * 63] * 3 + ["b" * 61])
    assert len(hostname) == 253
    for value in (hostname, hostname + "."):
        assert parse_request(wire(target={"kind": "hostname", "value": value})).target.value == (
            hostname
        )


@pytest.mark.parametrize(
    "value",
    [
        RESOURCE_ID.replace("-", ""),
        "{" + RESOURCE_ID + "}",
        "urn:uuid:" + RESOURCE_ID,
        RESOURCE_ID + "\n",
        "g" + RESOURCE_ID[1:],
        "not-a-uuid",
    ],
)
def test_canonical_selector_requires_hyphenated_uuid(value):
    with pytest.raises(InvalidRequest):
        parse_request(wire(target={"kind": "canonical", "value": value}))


@pytest.mark.parametrize("value", ["", "x" * 129, "ä", "abc\n", "a/b", "a b", "a?b"])
def test_provider_id_rejects_unbounded_or_nonopaque_values(value):
    with pytest.raises(InvalidRequest):
        parse_request(wire(target={"kind": "provider_id", "value": value}))


@pytest.mark.parametrize("value", [True, False, "0", "4", -1, 5, 1.0, [], {}])
def test_criticality_is_a_bounded_strict_integer(value):
    with pytest.raises(InvalidRequest):
        parse_request(wire(claimed_context={"criticality": value}))
    with pytest.raises(ValidationError):
        ClaimedContext(criticality=value)


@pytest.mark.parametrize(
    "claims",
    [
        {"severity": "critical"},
        {"environment": "prod"},
        {"role": "admin"},
        {"incident_id": "not-a-uuid"},
        {"source": "trusted"},
        {"tenant_id": RUN_ID},
        {"criticality": 1, "trusted_context": {}},
        None,
        [],
    ],
)
def test_claimed_context_rejects_unknown_fields_and_invalid_types(claims):
    with pytest.raises(InvalidRequest):
        parse_request(wire(claimed_context=claims))


@pytest.mark.parametrize("arguments", [None, [], "{}", False, 0])
def test_requires_an_explicit_arguments_object(arguments):
    with pytest.raises(InvalidRequest):
        parse_request(wire(arguments=arguments))


@pytest.mark.parametrize("required", ["operation_ref", "target", "arguments", "idempotency_key"])
def test_rejects_missing_required_fields(required):
    data = payload()
    del data[required]
    with pytest.raises(InvalidRequest):
        parse_request(json.dumps(data).encode())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("operation_ref", ""),
        ("operation_ref", "A.action"),
        ("operation_ref", "1action"),
        ("operation_ref", "a" * 81),
        ("operation_ref", "a\n"),
        ("operation_ref", "actión"),
        ("operation_ref", "a/b"),
        ("operation_ref", 1),
        ("operation_ref", True),
        ("idempotency_key", ""),
        ("idempotency_key", "a" * 129),
        ("idempotency_key", "a b"),
        ("idempotency_key", "a\n"),
        ("idempotency_key", "ä"),
        ("idempotency_key", 1),
        ("run_id", 1),
        ("run_id", "not-a-uuid"),
    ],
)
def test_rejects_invalid_operation_retry_and_run_fields(field, value):
    with pytest.raises(InvalidRequest):
        parse_request(wire(**{field: value}))


def test_accepts_operation_and_idempotency_length_boundaries():
    assert parse_request(wire(operation_ref="a" * 80, idempotency_key="A" * 128))
    assert parse_request(wire(operation_ref="a", idempotency_key="A"))


def with_reference(reference, **changes):
    data = payload(**changes)
    del data["idempotency_key"]
    data["reference"] = reference
    return json.dumps(data).encode("utf-8")


@pytest.mark.parametrize(
    "reference",
    ["INC-4711", "  INC-4711 ", "case 12 / step 3", "a" * 200, "ticket:#42?", "Ärende 7"],
)
def test_reference_derives_the_key_exactly_as_the_client_does(reference):
    """A model-driven host that passes the ticket lands on the same intent as the Python
    client that derived its key from the same ticket (#251)."""
    from execbound_client import intent_key

    from execbound.requests import derive_key

    request = parse_request(with_reference(reference))
    expected = intent_key("crowdstrike.contain", "hostname", "workstation.example.test", reference)
    assert request.idempotency_key == expected
    assert request.reference == reference.strip()
    derived = derive_key(
        "crowdstrike.contain", "hostname", "workstation.example.test", reference.strip()
    )
    assert derived == expected
    assert 1 <= len(request.idempotency_key) <= 128
    # Byte for byte: the same request is the same intent again.
    assert parse_request(with_reference(reference)).idempotency_key == expected


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps({**payload(), "reference": "INC-1"}).encode(),  # both
        json.dumps({k: v for k, v in payload().items() if k != "idempotency_key"}).encode(),
        with_reference(""),
        with_reference("   "),
        with_reference("a" * 201),
        with_reference(7),
        with_reference(None),
    ],
    ids=["both", "neither", "empty", "blank", "too-long", "number", "null"],
)
def test_reference_and_key_are_exactly_one(raw):
    with pytest.raises(InvalidRequest):
        parse_request(raw)


@pytest.mark.parametrize("number", [b"NaN", b"Infinity", b"-Infinity", b"1.0", b"1e0", b"1E400"])
def test_rejects_noninteger_json_tokens(number):
    raw = wire(claimed_context={"criticality": 1}).replace(
        b'"criticality": 1', b'"criticality": ' + number
    )
    with pytest.raises(InvalidRequest):
        parse_request(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{} trailing",
        b"[]",
        b"null",
        b"true",
        b"1",
        b'"string"',
        b"{",
        b"\xff",
        b'{"target":"\xed\xa0\x80"}',
        b'{"target":"\\ud800"}',
        b"[" * 2000 + b"]" * 2000,
        b'{"arguments":' + b"[" * 2000 + b"]" * 2000 + b"}",
    ],
)
def test_malformed_unicode_json_and_deep_nesting_fail_safely(raw):
    with pytest.raises(InvalidRequest, match="^Invalid request$"):
        parse_request(raw)


def test_request_body_has_a_16_kib_byte_limit():
    raw = wire()
    at_limit = raw + b" " * (16 * 1024 - len(raw))
    assert parse_request(at_limit) == parse_request(raw)
    with pytest.raises(InvalidRequest):
        parse_request(at_limit + b" ")


@pytest.mark.parametrize("raw", ["{}", bytearray(b"{}"), None, 1])
def test_request_parser_requires_bytes(raw):
    with pytest.raises(InvalidRequest):
        parse_request(raw)


def test_invalid_request_exposes_no_caller_content_or_underlying_exception():
    secret = "SYNTHETIC-CALLER-SECRET"
    with pytest.raises(InvalidRequest) as result:
        parse_request(wire(**{secret: secret}))
    assert str(result.value) == "Invalid request"
    assert secret not in "".join(traceback.format_exception(result.value))
    assert result.value.__cause__ is None
    assert result.value.__context__ is None


def test_validated_request_and_all_nested_models_are_frozen():
    request = parse_request(wire(claimed_context={"criticality": 4}))
    for instance, field, value in [
        (request, "operation_ref", "another.action"),
        (request.target, "value", "tier0.example.test"),
        (request.claimed_context, "criticality", 0),
        (request.arguments, "target", "tier0.example.test"),
    ]:
        with pytest.raises(ValidationError):
            setattr(instance, field, value)
    assert request.claimed_context.criticality == 4
    assert isinstance(hash(request), int)


def test_freezing_an_intent_copies_the_arguments_the_caller_still_holds():
    from execbound.resolution.models import CanonicalIntent, intent_hash

    request = parse_request(wire(arguments={"reason": "remediated"}))
    intent = CanonicalIntent(
        tenant_id=uuid4(),
        principal_id=uuid4(),
        account_id=uuid4(),
        target_id=uuid4(),
        arguments=request.arguments,
    )
    frozen_hash = intent_hash(intent)
    request.arguments.root["target"] = "tier0.example.test"
    assert intent.arguments.root == {"reason": "remediated"}
    assert intent_hash(intent) == frozen_hash


@pytest.mark.parametrize(
    "arguments",
    [
        {"reason": "x"},
        {"reason": "x" * 254},
        {"count": LONG_MIN},
        {"count": LONG_MAX},
        {f"a{index:02d}": index for index in range(16)},
        {"a" + "b" * 62: True},
    ],
    ids=[
        "shortest string",
        "longest string",
        "smallest integer",
        "largest integer",
        "most keys",
        "longest key",
    ],
)
def test_accepts_the_scalar_and_size_boundaries(arguments):
    assert parse_request(wire(arguments=arguments)).arguments.root == arguments


def test_serialized_copy_cannot_mutate_the_validated_request():
    request = parse_request(wire(claimed_context={"criticality": 4}))
    copied = request.model_dump()
    copied["claimed_context"]["criticality"] = 0
    copied["arguments"]["target"] = "tier0.example.test"
    assert request.claimed_context.criticality == 4
    assert request.arguments.model_dump() == {}


@pytest.mark.parametrize(
    "arguments",
    [
        {"reason": {"nested": True}},
        {"reason": ["remediated"]},
        {"reason": None},
        {"count": 1.5},
        {"reason": ""},
        {"reason": "x" * 255},
        {"Reason": "remediated"},
        {"count": 2**63},
        {f"a{index:02d}": True for index in range(17)},
        [],
        "remediated",
    ],
    ids=[
        "nested",
        "list",
        "null",
        "float",
        "empty string",
        "oversized string",
        "bad key",
        "oversized integer",
        "too many",
        "list body",
        "string body",
    ],
)
def test_rejects_non_scalar_or_unbounded_arguments(arguments):
    with pytest.raises(InvalidRequest):
        parse_request(wire(arguments=arguments))


def test_rejects_duplicate_argument_keys_in_the_original_bytes():
    raw = wire().replace(b'"arguments": {}', b'"arguments": {"a": 1, "a": 2}')
    assert b'"a": 1, "a": 2' in raw
    with pytest.raises(InvalidRequest):
        parse_request(raw)


def test_accepts_bounded_scalar_arguments_without_coercion():
    request = parse_request(wire(arguments={"reason": "remediated", "count": 3, "flag": False}))
    assert request.arguments.root == {"reason": "remediated", "count": 3, "flag": False}
    assert type(request.arguments.root["count"]) is int
    assert type(request.arguments.root["flag"]) is bool
    assert request.model_dump(mode="json")["arguments"] == {
        "count": 3,
        "flag": False,
        "reason": "remediated",
    }


def test_empty_arguments_keep_their_serialized_form():
    from execbound.execution.models import wire_hash

    assert Arguments().model_dump(mode="json") == {}
    assert parse_request(wire()).model_dump(mode="json")["arguments"] == {}
    assert wire_hash(parse_request(wire())) != wire_hash(
        parse_request(wire(arguments={"reason": "remediated"}))
    )
