# SPDX-License-Identifier: AGPL-3.0-only
"""Configured destinations, one HTTP attempt and authenticated terminal evidence."""

import hashlib
from collections.abc import Mapping
from uuid import UUID

from execbound_connectors.mock import ConnectionConfig as ConnectionConfig
from execbound_connectors.mock import MockConnector as MockConnector
from execbound_protocol.connector import Connector as Connector
from execbound_protocol.connector import ConnectorConfig as ConnectorConfig
from execbound_protocol.connector import check_journal

from execbound.execution.models import (
    DispatchCommand,
    TerminalEvidence,
    VerifiedTier,
)
from execbound.operations import ProviderName
from execbound.provider.models import (
    ProviderCommand,
    provider_command,
)


class JournalVerifier:
    # A provider's journal speaks for the operation ExecBound dispatched and says nothing
    # about what an external executor did, so it settles no checkpoint grant — and
    # answering the question rather than leaving it to a default is what keeps
    # `outcomes._never_executor_evidence` off this verifier's own settlements.
    attests_external_execution = False

    def __init__(
        self,
        tenant_id: UUID,
        account_id: UUID,
        keys: Mapping[str, bytes],
        *,
        provider: ProviderName = "mock_crowdstrike",
    ) -> None:
        if (
            provider not in {"mock_crowdstrike", "mock_entra"}
            or not keys
            or any(len(key) < 32 for key in keys.values())
        ):
            raise ValueError("Invalid journal keys")
        self.tenant_id, self.account_id = tenant_id, account_id
        self.provider = provider
        self._keys = dict(keys)

    def verify_command(self, command: ProviderCommand, evidence: bytes) -> TerminalEvidence:
        signed = check_journal(
            command,
            evidence,
            self._keys,
            tenant_id=self.tenant_id,
            account_id=self.account_id,
            provider=self.provider,
        )
        command = signed.record.command
        authenticated_record = signed.model_dump_json()
        return TerminalEvidence(
            operation_id=command.operation_id,
            account_id=command.account_id,
            intent_hash=command.intent_hash,
            plan_hash=command.plan_hash,
            outcome="EXECUTED" if signed.record.outcome == "EXECUTED" else "FAILED_NOT_EXECUTED",
            reason=signed.record.outcome,
            proof_digest=hashlib.sha256(authenticated_record.encode()).hexdigest(),
            authenticated_record=authenticated_record,
        )

    def verify(self, command: DispatchCommand, evidence: bytes) -> TerminalEvidence:
        return self.verify_command(provider_command(command), evidence)

    def verified_tier(self, proof: TerminalEvidence) -> VerifiedTier:
        # Never read. This verifier settles only operations ExecBound dispatched, where
        # `_settle` writes no tier, and a checkpoint refuses it before any tier is asked
        # because it attests no external execution. A checkpoint's journal is checked by
        # `CheckpointVerifier`, which composes this class and answers the tier itself.
        return "ATTESTED"
