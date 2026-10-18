# SPDX-License-Identifier: AGPL-3.0-only
"""Trusted evidence, fixed destinations and the gateway's one-send integration."""

import json
import secrets
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from execbound.provider.connector import ConnectionConfig, JournalVerifier
from execbound.provider.models import (
    JournalRecord,
    ProviderAccount,
    ProviderCommand,
    ProviderError,
    SignedJournal,
    parse_provider,
    sign_record,
)


@pytest.fixture
def protocol():
    command = ProviderCommand(
        tenant_id=uuid4(),
        account_id=uuid4(),
        canonical_target_id=uuid4(),
        resource_provider_id="synthetic-device",
        expected_version="v1",
        operation_id=uuid4(),
        execution_id=uuid4(),
        intent_hash="a" * 64,
        plan_hash="b" * 64,
    )
    account = ProviderAccount(
        command.tenant_id, command.account_id, "c" * 64, "d" * 64, secrets.token_bytes(32)
    )
    record = JournalRecord(
        command=command,
        command_hash=command.command_hash,
        outcome="EXECUTED",
        occurred_at=datetime.now(UTC),
        resulting_version="v2",
        mutation_count=1,
    )
    return command, account, record


def test_signed_journal_checks_complete_command(protocol):
    command, account, record = protocol
    verifier = JournalVerifier(
        account.tenant_id, account.account_id, {account.key_id: account.signing_key}
    )
    signed = sign_record(record, account)
    assert verifier.verify_command(command, signed.model_dump_json().encode()).reason == "EXECUTED"
    for field, value in (
        ("resource_provider_id", "other"),
        ("canonical_target_id", uuid4()),
        ("expected_version", "v3"),
        ("execution_id", uuid4()),
    ):
        changed = command.model_copy(update={field: value})
        with pytest.raises(ProviderError):
            verifier.verify_command(changed, signed.model_dump_json().encode())


@pytest.mark.parametrize(
    "change", ["signature", "key_id", "outcome", "duplicate", "boolean", "missing"]
)
def test_untrusted_proof_cannot_release_capacity(protocol, change):
    command, account, record = protocol
    verifier = JournalVerifier(
        account.tenant_id, account.account_id, {account.key_id: account.signing_key}
    )
    signed = sign_record(record, account).model_dump(mode="json")
    if change == "signature":
        signed["signature"] = "0" * 64
    elif change == "key_id":
        signed["key_id"] = "untrusted"
    elif change == "outcome":
        signed["record"]["outcome"] = "CANCELLED_NOT_EXECUTED"
    raw = json.dumps(signed).encode()
    if change == "duplicate":
        raw = raw.replace(b'"version": 1', b'"version": 1, "version": 1', 1)
    if change == "boolean":
        raw = b'{"failed":true}'
    if change == "missing":
        raw = b'{"status":"not_found"}'
    with pytest.raises(ProviderError):
        verifier.verify_command(command, raw)


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/redirect",
        "https://example.com?dest=other",
        "file:///tmp/provider",
        "http://localhost:8123",
        "https://example.com/#fragment",
    ],
)
def test_provider_origin_is_fixed_and_has_no_ambient_components(protocol, origin):
    command, account, _ = protocol
    with pytest.raises(ValueError):
        ConnectionConfig(
            tenant_id=command.tenant_id,
            account_id=account.account_id,
            origin=origin,
            dispatch_token="independent-dispatch-token",
            control_token="independent-control-token",
            evidence_keys={account.key_id: account.signing_key},
        )


@pytest.mark.parametrize("field", ["version", "mutation_count"])
def test_provider_numbers_reject_booleans(protocol, field):
    _, account, record = protocol
    signed = sign_record(record, account).model_dump(mode="json")
    if field == "version":
        signed["version"] = True
    else:
        signed["record"]["mutation_count"] = True
    with pytest.raises(ProviderError):
        parse_provider(json.dumps(signed).encode(), SignedJournal)
