# SPDX-License-Identifier: AGPL-3.0-only
"""Continuation state is authenticated metadata, never an approval decision."""

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import get_args
from uuid import uuid4

import pytest
from pydantic import ValidationError

from execbound.surfaces import tokens as api


def claims(api, **changes):
    values = {
        "tenant_id": uuid4(),
        "principal_id": uuid4(),
        "credential_id": uuid4(),
        "audience": "approval.decide",
        "execution_id": uuid4(),
        "approval_id": uuid4(),
        "plan_hash": "a" * 64,
        "expires_at": datetime(2026, 9, 14, 4, 10, tzinfo=UTC),
        "nonce": "n" * 32,
    }
    return api.Continuation(**(values | changes))


def verify(api, token, keys, expected, **changes):
    arguments = {
        "tenant_id": expected.tenant_id,
        "principal_id": expected.principal_id,
        "credential_id": expected.credential_id,
        "audience": expected.audience,
        "now": datetime(2026, 9, 14, 4, 0, tzinfo=UTC),
    }
    return api.verify(token, keys, **(arguments | changes))


def encode_signed(payload, key=b"k" * 32):
    if not isinstance(payload, bytes):
        payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def decode_payload(token):
    encoded = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def test_signed_token_binds_all_identity_and_plan_fields():
    expected = claims(api)
    keys = api.TokenKeys("continuation-v1", {"continuation-v1": b"k" * 32})
    token = api.sign(expected, keys)
    assert verify(api, token, keys, expected) == expected
    payload = decode_payload(token)
    assert payload["version"] == 1
    assert payload["algorithm"] == "HS256"
    assert payload["key_id"] == "continuation-v1"
    assert payload["claims"] == expected.model_dump(mode="json")
    assert len(token) <= 4096
    assert "=" not in token
    assert str(expected.tenant_id) not in token


@pytest.mark.parametrize("field", ["tenant_id", "principal_id", "credential_id", "audience"])
def test_authentication_scope_or_audience_switch_rejects_valid_token(field):
    expected = claims(api)
    keys = api.TokenKeys("continuation-v1", {"continuation-v1": b"k" * 32})
    token = api.sign(expected, keys)
    replacement = "execution.status" if field == "audience" else uuid4()
    with pytest.raises(api.InvalidContinuation, match="^Invalid continuation$"):
        verify(api, token, keys, expected, **{field: replacement})


def test_unknown_and_retired_keys_reject_even_correctly_signed_tokens():
    expected = claims(api)
    old_keys = api.TokenKeys("old", {"old": b"k" * 32})
    token = api.sign(expected, old_keys)
    rotation = api.TokenKeys("new", {"old": b"k" * 32, "new": b"v" * 32})
    assert verify(api, token, rotation, expected) == expected
    assert decode_payload(api.sign(expected, rotation))["key_id"] == "new"
    retired = api.TokenKeys("new", {"new": b"v" * 32})
    with pytest.raises(api.InvalidContinuation):
        verify(api, token, retired, expected)


@pytest.mark.parametrize(
    "offset", [timedelta(0), timedelta(microseconds=-1), timedelta(minutes=16)]
)
def test_expired_and_excessive_future_expiry_rejected(offset):
    now = datetime(2026, 9, 14, 4, 0, tzinfo=UTC)
    expected = claims(api, expires_at=now + offset)
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    with pytest.raises(api.InvalidContinuation):
        verify(api, api.sign(expected, keys), keys, expected, now=now)


@pytest.mark.parametrize("offset", [timedelta(microseconds=1), timedelta(minutes=15)])
def test_exact_valid_expiry_edges(offset):
    now = datetime(2026, 9, 14, 4, 0, tzinfo=UTC)
    expected = claims(api, expires_at=now + offset)
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    assert verify(api, api.sign(expected, keys), keys, expected, now=now) == expected


@pytest.mark.parametrize("part", ["signature", "execution_id", "approval_id", "plan_hash", "nonce"])
def test_tampered_signature_or_bound_claim_rejected(part):
    expected = claims(api)
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    token = api.sign(expected, keys)
    if part == "signature":
        token = token[:-1] + ("a" if token[-1] != "a" else "b")
    else:
        payload = decode_payload(token)
        payload["claims"][part] = str(uuid4()) if part.endswith("_id") else "b" * 64
        encoded = encode_signed(payload).split(".")[0]
        token = encoded + "." + token.split(".")[1]
    with pytest.raises(api.InvalidContinuation):
        verify(api, token, keys, expected)


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("version", 1.0),
        ("version", 1.5),
        ("version", "1"),
        ("version", 2),
        ("algorithm", "none"),
        ("algorithm", "HS512"),
        ("algorithm", "hs256"),
        ("key_id", "unknown"),
        ("key_id", "../key"),
        ("key_id", 1),
        ("extra", "forbidden"),
    ],
)
def test_invalid_envelope_rejected_even_with_valid_mac(field, value):
    expected = claims(api)
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    payload = decode_payload(api.sign(expected, keys))
    payload[field] = value
    with pytest.raises(api.InvalidContinuation):
        verify(api, encode_signed(payload), keys, expected)


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "not-a-uuid"),
        ("principal_id", 1),
        ("credential_id", None),
        ("execution_id", True),
        ("approval_id", "broken"),
        ("approval_id", None),
        ("audience", "admin"),
        ("plan_hash", "g" * 64),
        ("plan_hash", "A" * 64),
        ("plan_hash", "a" * 63),
        ("expires_at", "2026-09-14T04:10:00"),
        ("expires_at", "yesterday"),
        ("expires_at", 1789359000),
        ("nonce", "n" * 21),
        ("nonce", "n" * 129),
        ("nonce", "n" * 31 + "="),
        ("nonce", None),
        ("approved", True),
    ],
)
def test_invalid_claims_rejected_even_with_valid_mac(field, value):
    expected = claims(api)
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    payload = decode_payload(api.sign(expected, keys))
    payload["claims"][field] = value
    with pytest.raises(api.InvalidContinuation):
        verify(api, encode_signed(payload), keys, expected)


@pytest.mark.parametrize("member", ["version", "algorithm", "key_id", "claims"])
def test_missing_required_envelope_member_rejected(member):
    expected = claims(api)
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    payload = decode_payload(api.sign(expected, keys))
    del payload[member]
    with pytest.raises(api.InvalidContinuation):
        verify(api, encode_signed(payload), keys, expected)


@pytest.mark.parametrize("mutation", ["top_duplicate", "claim_duplicate", "nan", "infinity"])
def test_duplicate_json_and_nonfinite_numbers_rejected_before_decoder_discards_them(mutation):
    expected = claims(api)
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    payload = json.dumps(decode_payload(api.sign(expected, keys)), separators=(",", ":"))
    if mutation == "top_duplicate":
        payload = payload.replace('"version":1', '"version":2,"version":1')
    elif mutation == "claim_duplicate":
        payload = payload.replace('"audience":', '"audience":"execution.status","audience":')
    else:
        payload = payload.replace(
            '"version":1', '"version":' + ("NaN" if mutation == "nan" else "Infinity")
        )
    with pytest.raises(api.InvalidContinuation):
        verify(api, encode_signed(payload.encode()), keys, expected)


@pytest.mark.parametrize(
    "mutation",
    [
        "whitespace",
        "json_order",
        "unicode_escape",
        "uppercase_uuid",
        "uuid_no_hyphens",
        "date_offset",
        "date_precision",
        "omitted_null",
    ],
)
def test_noncanonical_json_rejected_even_when_authentic(mutation):
    expected = claims(api, audience="execution.status", approval_id=None)
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    original = decode_payload(api.sign(expected, keys))
    raw = json.dumps(original, sort_keys=True, separators=(",", ":"))
    if mutation == "whitespace":
        raw += " "
    elif mutation == "json_order":
        raw = json.dumps(dict(reversed(list(original.items()))))
    elif mutation == "unicode_escape":
        raw = raw.replace('"algorithm"', '"\\u0061lgorithm"')
    elif mutation == "uppercase_uuid":
        raw = raw.replace(str(expected.tenant_id), str(expected.tenant_id).upper())
    elif mutation == "uuid_no_hyphens":
        raw = raw.replace(str(expected.tenant_id), expected.tenant_id.hex)
    elif mutation == "date_offset":
        raw = raw.replace("04:10:00Z", "04:10:00+00:00")
    elif mutation == "date_precision":
        raw = raw.replace("04:10:00Z", "04:10:00.000000Z")
    else:
        raw = raw.replace('"approval_id":null,', "")
    with pytest.raises(api.InvalidContinuation):
        verify(api, encode_signed(raw.encode()), keys, expected)


@pytest.mark.parametrize(
    "mutation",
    [
        "padding",
        "newline",
        "hex_case",
        "extra_dot",
        "empty",
        "oversize",
        "bytes",
        "unicode",
        "bad_base64",
        "short_mac",
    ],
)
def test_malformed_wire_tokens_fail_generically(mutation):
    expected = claims(api)
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    token = api.sign(expected, keys)
    payload, mac = token.split(".")
    altered = {
        "padding": payload + "=." + mac,
        "newline": token + "\n",
        "hex_case": payload + "." + mac.upper(),
        "extra_dot": token + ".",
        "empty": "",
        "oversize": "a" * 4097,
        "bytes": token.encode(),
        "unicode": "é" + token,
        "bad_base64": "a." + mac,
        "short_mac": payload + "." + mac[:-1],
    }[mutation]
    with pytest.raises(api.InvalidContinuation, match="^Invalid continuation$"):
        verify(api, altered, keys, expected)


@pytest.mark.parametrize(
    "active,keys",
    [
        ("key", {}),
        ("missing", {"key": b"k" * 32}),
        ("key", {"key": b"k" * 31}),
        ("key", {"key": "k" * 32}),
        ("key", {"key": bytearray(b"k" * 32)}),
        ("bad key", {"bad key": b"k" * 32}),
        ("key", {"key": b"k" * 32, "bad key": b"v" * 32}),
        (1, {1: b"k" * 32}),
    ],
)
def test_invalid_key_configuration_fails(active, keys):
    with pytest.raises(ValueError):
        api.TokenKeys(active, keys)


def test_keys_are_private_and_immutable_copies():
    original = {"key": b"private-signing-key-never-in-repr!"}
    keys = api.TokenKeys("key", original)
    original["key"] = b"changed" * 8
    assert keys.keys["key"] == b"private-signing-key-never-in-repr!"
    assert "private-signing" not in repr(keys)
    with pytest.raises(TypeError):
        keys.keys["key"] = b"changed" * 8
    with pytest.raises(AttributeError):
        keys.active_key_id = "other"


def test_invalid_model_copy_cannot_be_signed():
    invalid = claims(api).model_copy(update={"plan_hash": "invalid"})
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    with pytest.raises(api.InvalidContinuation):
        api.sign(invalid, keys)


def test_naive_verifier_time_is_not_silently_interpreted_as_local_time():
    expected = claims(api)
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    with pytest.raises(api.InvalidContinuation):
        verify(api, api.sign(expected, keys), keys, expected, now=datetime(2026, 9, 14, 4, 0))


# The act grant of an external execution checkpoint: its own audience, bound to the one
# operation the grant names, and expressible as a continuation because the act window is
# exactly the token ceiling.
EXISTING_AUDIENCES = ("execution.status", "approval.decide", "execution.reconcile")


def act(api, **changes):
    return claims(
        api,
        audience="execution.checkpoint_outcome",
        approval_id=None,
        operation_id=uuid4(),
        **changes,
    )


def test_every_audience_is_named_and_the_new_one_is_last():
    # Each existing audience has a verifier call site (runtime.status, and the human
    # surface's approval and reconcile forms). A later member must be considered against
    # every one of them rather than silently accepted somewhere, so the set is pinned.
    assert get_args(api.Audience) == (*EXISTING_AUDIENCES, "execution.checkpoint_outcome")


def test_a_checkpoint_continuation_binds_its_operation_and_verifies():
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    expected = act(api)
    token = api.sign(expected, keys)
    assert verify(api, token, keys, expected) == expected
    assert decode_payload(token)["claims"]["operation_id"] == str(expected.operation_id)


@pytest.mark.parametrize("audience", EXISTING_AUDIENCES)
def test_the_checkpoint_audience_is_refused_by_every_existing_call_site(audience):
    # A grant confers no authority to read status, decide an approval or reconcile, so the
    # token that carries it must be worthless at every audience that already exists.
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    expected = act(api)
    with pytest.raises(api.InvalidContinuation):
        verify(api, api.sign(expected, keys), keys, expected, audience=audience)


@pytest.mark.parametrize("audience", EXISTING_AUDIENCES)
def test_an_operation_identifier_belongs_to_no_other_audience(audience):
    with pytest.raises(ValidationError):
        claims(api, audience=audience, operation_id=uuid4())


def test_a_checkpoint_continuation_without_an_operation_is_refused():
    with pytest.raises(ValidationError):
        claims(api, audience="execution.checkpoint_outcome", approval_id=None)


def test_an_unset_operation_is_absent_from_every_existing_token():
    # In-flight continuations of the other three audiences stay byte-valid: the field is
    # serialized only when set, so a token signed before this change verifies unchanged
    # and a token signed now carries no key the old shape did not.
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    expected = claims(api)
    payload = decode_payload(api.sign(expected, keys))
    assert set(payload["claims"]) == {
        "tenant_id",
        "principal_id",
        "credential_id",
        "audience",
        "execution_id",
        "approval_id",
        "plan_hash",
        "expires_at",
        "nonce",
    }
    assert verify(api, api.sign(expected, keys), keys, expected) == expected


def test_an_explicit_null_operation_is_not_the_canonical_form():
    keys = api.TokenKeys("key", {"key": b"k" * 32})
    expected = claims(api)
    payload = decode_payload(api.sign(expected, keys))
    payload["claims"]["operation_id"] = None
    with pytest.raises(api.InvalidContinuation):
        verify(api, encode_signed(payload), keys, expected)
