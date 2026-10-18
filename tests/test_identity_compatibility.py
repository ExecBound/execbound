# SPDX-License-Identifier: AGPL-3.0-only
"""Identity plans, commands and journals captured before the action catalog stay byte-identical."""

import json
from pathlib import Path

import pytest

from execbound.audit import canonical_json
from execbound.execution.models import DispatchCommand
from execbound.policy.models import BundleContent
from execbound.provider.connector import JournalVerifier
from execbound.provider.models import SignedJournal, provider_command, signature
from execbound.resolution.models import binding_hash, intent_hash, plan_hash

RETAINED = json.loads(
    (Path(__file__).parent / "fixtures/identity-contract-v1.json").read_text(encoding="utf-8")
)
assert sorted(RETAINED["actions"]) == [
    "identity.disable",
    "identity.enable",
    "identity.revoke_sessions",
]


@pytest.fixture(params=sorted(RETAINED["actions"]))
def retained(request):
    return RETAINED["actions"][request.param]


def test_retained_identity_bundle_bytes():
    bundle = BundleContent.model_validate_json(json.dumps(RETAINED["bundle"]))
    assert canonical_json(bundle.model_dump(mode="json")) == RETAINED["bundle_canonical"]
    assert bundle.content_hash == RETAINED["bundle_hash"]


def test_retained_identity_plan_and_command_bytes(retained):
    command = DispatchCommand.model_validate_json(json.dumps(retained["dispatch"]))
    bundle = BundleContent.model_validate_json(json.dumps(RETAINED["bundle"]))
    frozen = command.frozen
    assert canonical_json(frozen.model_dump(mode="json")) == retained["resolved_canonical"]
    assert binding_hash(frozen) == retained["binding_hash"]
    assert intent_hash(frozen.intent) == command.intent_hash
    assert plan_hash(frozen, bundle.security_versions) == command.plan_hash
    assert (
        canonical_json(provider_command(command).model_dump(mode="json"))
        == retained["command_canonical"]
    )


def test_retained_identity_journal_signature_and_verification(retained):
    dispatch = DispatchCommand.model_validate_json(json.dumps(retained["dispatch"]))
    signed = SignedJournal.model_validate_json(json.dumps(retained["signed_journal"]))
    assert canonical_json(signed.model_dump(mode="json")) == retained["signed_journal_canonical"]
    key = bytes.fromhex(RETAINED["test_verification_key_hex"])
    assert signature(signed.record, signed.key_id, key) == signed.signature
    verifier = JournalVerifier(
        dispatch.frozen.intent.tenant_id,
        dispatch.frozen.intent.account_id,
        {signed.key_id: key},
        provider="mock_entra",
    )
    evidence = verifier.verify(dispatch, retained["signed_journal_canonical"].encode())
    assert evidence.outcome == "EXECUTED"
    assert evidence.operation_id == dispatch.operation_id
    assert evidence.plan_hash == dispatch.plan_hash
