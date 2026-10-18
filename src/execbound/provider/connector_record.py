# SPDX-License-Identifier: AGPL-3.0-only
"""What a connector ExecBound owns can offer as evidence when the vendor co-signs nothing.

Every mock proves an outcome with a ``SignedJournal``: an HMAC made with a key ExecBound and
the provider **share**, so the signature is the provider's statement. Microsoft Graph will
never produce one. There is no shared secret with Microsoft and no vendor-signed receipt for
a ``PATCH``.

What ExecBound does have is its own account of the exchange it performed: the request it
sent, the status the vendor returned, the composite it compared and the window it measured.
Signing that with a key ExecBound holds keeps ``TerminalEvidence.authenticated_record`` an
honest name — the record **is** authenticated, as ExecBound's own — and gives the one
property an unsigned blob would not, which is a retained record nobody without the key can
quietly edit afterwards.

**It is not evidence the vendor did anything.** A signature ExecBound makes over its own
observation proves the record is ours and intact, and no more. Every surface that renders or
exports one says whose signature it is; see docs/PROVIDER.md, A vendor that co-signs
nothing.
"""

import hashlib
from collections.abc import Mapping
from uuid import UUID

from execbound_protocol.connector import check_connector_record
from execbound_protocol.connector_record import CONNECTOR_RECORD_V1 as CONNECTOR_RECORD_V1
from execbound_protocol.connector_record import ConnectorExchange as ConnectorExchange
from execbound_protocol.connector_record import ConnectorRecord as ConnectorRecord
from execbound_protocol.connector_record import record_signature as record_signature
from execbound_protocol.connector_record import sign_exchange as sign_exchange

from execbound.execution.models import (
    DispatchCommand,
    TerminalEvidence,
    VerifiedTier,
)
from execbound.provider.models import (
    provider_command,
)


class ConnectorRecordVerifier:
    """Checks that a retained record is ExecBound's own and describes *this* execution.

    ``attests_external_execution`` is False and must stay so: this is a record of an
    operation ExecBound dispatched, and the two guards that read the flag are what keep an
    outstanding checkpoint grant from settling on connector evidence.
    """

    attests_external_execution = False

    def __init__(self, account_id: UUID, provider: str, keys: Mapping[str, bytes]) -> None:
        if not keys or any(len(key) < 32 for key in keys.values()):
            raise ValueError("Invalid connector signing keys")
        self._account_id = account_id
        self._provider = provider
        self._keys = dict(keys)

    def verify(self, command: DispatchCommand, evidence: bytes) -> TerminalEvidence:
        signed = check_connector_record(
            provider_command(command),
            evidence,
            self._keys,
            account_id=self._account_id,
            provider=self._provider,
        )
        exchange = signed.record
        authenticated = signed.model_dump_json()
        return TerminalEvidence(
            operation_id=exchange.operation_id,
            account_id=exchange.account_id,
            intent_hash=exchange.intent_hash,
            plan_hash=exchange.plan_hash,
            # TERMINAL_PAIRS restated for the three reasons a connector record may carry;
            # `consistent` refuses the fourth, so this branch is exhaustive.
            outcome="EXECUTED" if exchange.outcome == "EXECUTED" else "FAILED_NOT_EXECUTED",
            reason=exchange.outcome,
            proof_digest=hashlib.sha256(authenticated.encode()).hexdigest(),
            authenticated_record=authenticated,
            # Stated here because the kernel treats the record above as opaque bytes. The
            # record remains the authority; this is the verifier's reading of it, exactly
            # as `outcome` and `reason` beside it are.
            window_ms=exchange.window_ms,
        )

    def verified_tier(self, proof: TerminalEvidence) -> VerifiedTier:
        # Never read. This verifier settles only operations ExecBound dispatched, where
        # `_settle` writes no tier, and a checkpoint refuses it before any tier is asked
        # because it attests no external execution.
        return "ATTESTED"
