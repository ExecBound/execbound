# SPDX-License-Identifier: AGPL-3.0-only
"""Existing endpoint hashes and journals survive new action-family support."""

import json
from pathlib import Path

import pytest

from execbound.audit import canonical_json
from execbound.execution.models import DispatchCommand
from execbound.policy.models import BundleContent
from execbound.provider.connector import JournalVerifier
from execbound.provider.models import SignedJournal, provider_command, signature
from execbound.resolution.models import binding_hash, intent_hash, plan_hash


@pytest.fixture
def retained():
    return json.loads(
        (Path(__file__).parent / "fixtures/endpoint-contract-v1.json").read_text(encoding="utf-8")
    )


def test_retained_endpoint_plan_and_bundle_bytes(retained):
    command = DispatchCommand.model_validate_json(json.dumps(retained["dispatch"]))
    bundle = BundleContent.model_validate_json(json.dumps(retained["bundle"]))
    frozen = command.frozen
    assert canonical_json(frozen.model_dump(mode="json")) == retained["resolved_canonical"]
    assert binding_hash(frozen) == retained["binding_hash"]
    assert intent_hash(frozen.intent) == command.intent_hash
    assert plan_hash(frozen, bundle.security_versions) == command.plan_hash
    assert canonical_json(bundle.model_dump(mode="json")) == retained["bundle_canonical"]
    assert bundle.content_hash == retained["bundle_hash"]
    assert (
        canonical_json(provider_command(command).model_dump(mode="json"))
        == retained["command_canonical"]
    )


def test_retained_endpoint_journal_signature_and_verification(retained):
    dispatch = DispatchCommand.model_validate_json(json.dumps(retained["dispatch"]))
    signed = SignedJournal.model_validate_json(json.dumps(retained["signed_journal"]))
    assert canonical_json(signed.model_dump(mode="json")) == retained["signed_journal_canonical"]
    key = bytes.fromhex(retained["test_verification_key_hex"])
    assert signature(signed.record, signed.key_id, key) == signed.signature
    verifier = JournalVerifier(
        dispatch.frozen.intent.tenant_id, dispatch.frozen.intent.account_id, {signed.key_id: key}
    )
    evidence = verifier.verify(dispatch, retained["signed_journal_canonical"].encode())
    assert evidence.outcome == "EXECUTED"
    assert evidence.operation_id == dispatch.operation_id
    assert evidence.plan_hash == dispatch.plan_hash
