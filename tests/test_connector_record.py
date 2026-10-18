# SPDX-License-Identifier: AGPL-3.0-only
"""The record a connector signs when the vendor co-signs nothing, and every refusal."""

import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from execbound.audit import canonical_json
from execbound.execution.models import DispatchCommand
from execbound.provider.connector_record import (
    CONNECTOR_RECORD_V1,
    ConnectorExchange,
    ConnectorRecordVerifier,
    sign_exchange,
)
from execbound.provider.models import ProviderError
from execbound.requests import ActionRequest, Arguments, ResourceSelector
from execbound.resolution.models import CanonicalIntent, ResolvedRequest

KEY_ID = "connector-v1"
NOW = datetime(2026, 9, 18, 3, 0, tzinfo=UTC)
# A real composite, the shape `execbound_protocol.composite` produces and the frozen plan
# carries as its version.
COMPOSITE = "graph-user.v1:" + "a" * 64


@pytest.fixture
def graph_command():
    """One dispatch against the real provider binding, with no database involved."""
    tenant, principal, account, target = (uuid4() for _ in range(4))
    frozen = ResolvedRequest(
        request=ActionRequest(
            operation_ref="identity.disable",
            target=ResourceSelector(kind="canonical", value=str(target)),
            arguments=Arguments(),
            idempotency_key="connector-record",
        ),
        intent=CanonicalIntent(
            tenant_id=tenant,
            principal_id=principal,
            account_id=account,
            provider="graph",
            provider_operation="disable",
            action="identity.disable",
            resource_type="identity",
            target_id=target,
            arguments=Arguments(),
        ),
        resource_provider_id="9bfbda7f-0000-4000-8000-000000000000",
        resource_version=COMPOSITE,
        mapping_version="map-v1",
        context_contract_version="identity-control.v1",
        facts=(),
        resolved_at=NOW,
        valid_until=NOW + timedelta(minutes=10),
    )
    return DispatchCommand(
        execution_id=uuid4(),
        canonical_target_id=target,
        operation_id=uuid4(),
        intent_hash="a" * 64,
        plan_hash="b" * 64,
        frozen=frozen,
    )


def world(command):
    frozen = command.frozen
    return ConnectorExchange(
        operation_id=command.operation_id,
        account_id=frozen.intent.account_id,
        intent_hash=command.intent_hash,
        plan_hash=command.plan_hash,
        provider=frozen.intent.provider,
        provider_operation=frozen.intent.provider_operation,
        frozen=frozen.resource_version,
        observed=frozen.resource_version,
        window_ms=12,
        status=204,
        outcome="EXECUTED",
    )


@pytest.fixture
def signed(graph_command):
    key = secrets.token_bytes(32)
    exchange = world(graph_command)
    return exchange, key, sign_exchange(exchange, KEY_ID, key)


def verifier(command, key):
    return ConnectorRecordVerifier(
        command.frozen.intent.account_id, command.frozen.intent.provider, {KEY_ID: key}
    )


def test_a_record_this_connector_signed_for_this_execution_verifies(graph_command, signed):
    _, key, evidence = signed
    terminal = verifier(graph_command, key).verify(graph_command, evidence)
    assert terminal.outcome == "EXECUTED" and terminal.reason == "EXECUTED"
    assert terminal.operation_id == graph_command.operation_id
    # The record is the authenticated thing; the digest is over exactly those bytes.
    assert terminal.authenticated_record and terminal.proof_digest


def test_this_verifier_does_not_attest_external_execution(graph_command, signed):
    """The flag two guards read: a connector record must never settle a checkpoint grant."""
    _, key, _ = signed
    assert verifier(graph_command, key).attests_external_execution is False


def test_an_altered_record_no_longer_verifies(graph_command, signed):
    """The one property an unsigned blob would not have."""
    _, key, evidence = signed
    tampered = json.loads(evidence)
    tampered["record"]["window_ms"] = 0
    with pytest.raises(ProviderError):
        verifier(graph_command, key).verify(graph_command, json.dumps(tampered).encode())


def test_a_record_signed_with_a_key_this_deployment_does_not_hold_is_refused(graph_command, signed):
    exchange, _, _ = signed
    stranger = sign_exchange(exchange, KEY_ID, secrets.token_bytes(32))
    with pytest.raises(ProviderError):
        verifier(graph_command, secrets.token_bytes(32)).verify(graph_command, stranger)


@pytest.mark.parametrize(
    "field",
    ["operation_id", "intent_hash", "plan_hash", "provider_operation", "frozen"],
)
def test_evidence_from_another_execution_is_refused_on_each_bound_field(
    graph_command, signed, field
):
    """A signature ExecBound made cannot itself prove which operation it describes.

    So the four-field binding is the check that actually matters, and one regression per
    field is what says each of them is load-bearing rather than decorative.
    """
    exchange, key, _ = signed
    moved = {
        "operation_id": uuid4(),
        "intent_hash": "b" * 64,
        "plan_hash": "c" * 64,
        "provider_operation": "enable",
        "frozen": "graph-user.v1:" + "d" * 64,
    }[field]
    other = exchange.model_copy(update={field: moved})
    if field == "frozen":
        other = other.model_copy(update={"observed": moved})
    with pytest.raises(ProviderError):
        verifier(graph_command, key).verify(graph_command, sign_exchange(other, KEY_ID, key))


MOVED = "graph-user.v1:" + "e" * 64


def forge(exchange, key, **changes):
    """Bytes this codebase will not sign: a correct signature over an incoherent record.

    `sign_exchange` refuses these at construction, which is where they should die. A record
    is read back from storage long after it was written, though, possibly by a build older
    or newer than the one that wrote it, so the check has to hold at parse as well. Signing
    a hand-built payload is the only way to put one in front of the verifier.
    """
    record = exchange.model_dump(mode="json") | changes
    message = canonical_json({"scheme": CONNECTOR_RECORD_V1, "key_id": KEY_ID, "record": record})
    signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    return json.dumps({"key_id": KEY_ID, "record": record, "signature": signature}).encode()


def test_an_executed_record_whose_composites_differ_never_reached_a_write(graph_command, signed):
    """A write happened only because the comparison agreed, so claiming both is incoherent."""
    exchange, key, _ = signed
    with pytest.raises(ProviderError):
        verifier(graph_command, key).verify(graph_command, forge(exchange, key, observed=MOVED))


def test_an_incoherent_record_is_refused_at_parse_however_well_it_is_signed(graph_command, signed):
    """The signature is valid and the content still states two different things."""
    exchange, key, _ = signed
    # Unchanged, the same hand-built bytes verify. Without this the refusals below would
    # pass just as well on a signature `forge` had got wrong, proving nothing.
    assert verifier(graph_command, key).verify(graph_command, forge(exchange, key)).proof_digest
    for changes in ({"outcome": "VERSION_MISMATCH"}, {"status": 500}, {"observed": None}):
        with pytest.raises(ProviderError):
            verifier(graph_command, key).verify(graph_command, forge(exchange, key, **changes))


def test_the_comparison_that_stopped_a_write_is_itself_evidence(graph_command, signed):
    """The record `CHECKED_BY_CONNECTOR` exists to retain, and the one this nearly lost.

    A drift the connector caught is the case the class is *about*: ExecBound read, compared
    and did not write. Settling it needs a record whose composites differ, which an earlier
    draft of the verifier refused outright, leaving two of the three outcomes this record
    advertises unconstructable.
    """
    exchange, key, _ = signed
    mismatch = ConnectorExchange(
        **exchange.model_dump() | {"observed": MOVED, "status": 200, "outcome": "VERSION_MISMATCH"}
    )
    terminal = verifier(graph_command, key).verify(
        graph_command, sign_exchange(mismatch, KEY_ID, key)
    )
    # STALE_AUTHORIZATION downstream, and a refund this deployment can make honestly,
    # because nothing was dispatched.
    assert terminal.outcome == "FAILED_NOT_EXECUTED" and terminal.reason == "VERSION_MISMATCH"


def test_a_subject_that_was_gone_carries_no_composite_at_all(graph_command, signed):
    exchange, key, _ = signed
    missing = ConnectorExchange(
        **exchange.model_dump() | {"observed": None, "status": 404, "outcome": "TARGET_NOT_FOUND"}
    )
    terminal = verifier(graph_command, key).verify(
        graph_command, sign_exchange(missing, KEY_ID, key)
    )
    assert terminal.outcome == "FAILED_NOT_EXECUTED" and terminal.reason == "TARGET_NOT_FOUND"


INCOHERENT = {
    # A mismatch is the drift; composites that agree state nothing.
    "a mismatch whose composites agree": {"outcome": "VERSION_MISMATCH"},
    "a mismatch with no observation": {"observed": None, "outcome": "VERSION_MISMATCH"},
    # A subject that was gone was never read, so there is nothing to have observed.
    "a missing subject with a composite": {"outcome": "TARGET_NOT_FOUND"},
    # No status outside the 2xx range establishes that a write happened.
    "an execution the vendor refused": {"status": 403},
    "an execution the vendor failed": {"status": 500},
    # Graph offers no cancellation, so no record of one can be made under this scheme.
    "a cancellation": {"observed": None, "status": 200, "outcome": "CANCELLED_NOT_EXECUTED"},
}


@pytest.mark.parametrize("name", sorted(INCOHERENT))
def test_a_record_that_states_two_different_things_cannot_be_constructed(signed, name):
    """Held where a journal is held, so a signature is never made over an incoherent claim."""
    exchange, _, _ = signed
    with pytest.raises(ValidationError):
        ConnectorExchange(**exchange.model_dump() | INCOHERENT[name])


def test_a_record_made_under_another_scheme_does_not_verify_under_this_one(graph_command, signed):
    exchange, key, _ = signed
    assert exchange.scheme == CONNECTOR_RECORD_V1
    other = exchange.model_copy(update={"scheme": "connector-record.v2"})
    with pytest.raises(ProviderError):
        verifier(graph_command, key).verify(graph_command, sign_exchange(other, KEY_ID, key))


def test_a_signing_key_shorter_than_the_floor_is_refused(graph_command, signed):
    exchange, _, _ = signed
    with pytest.raises(ProviderError):
        sign_exchange(exchange, KEY_ID, secrets.token_bytes(16))
