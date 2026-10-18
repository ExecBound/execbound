# SPDX-License-Identifier: AGPL-3.0-only
"""The evidence a checkpoint settles from: its executor's record, or its provider's journal.

A checkpoint is an operation ExecBound never dispatched, so its connector paths refuse it
and its settlement rests on what the report presents. Two parties can speak for it. The
executor signs its own record, which proves who spoke. A provider that speaks ExecBound's
provider protocol signs a journal of the exact command, which a party other than the
executor made, and which verifies under a key the operator configured for that Gate
account and the executor never holds. This module composes the two checks behind one
verifier and says which tier the evidence it checked establishes.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from uuid import UUID

from execbound.execution.models import DispatchCommand, TerminalEvidence, VerifiedTier
from execbound.operations import ProviderName
from execbound.provider.connector import JournalVerifier
from execbound.provider.executor import ExecutorVerifier
from execbound.provider.models import ProviderError, SignedJournal, parse_provider
from execbound.requests import _unique_object

_KEY_ID = re.compile(r"[a-zA-Z0-9_.-]{1,64}")
JOURNAL_PROVIDERS = frozenset({"mock_crowdstrike", "mock_entra"})


@dataclass(frozen=True)
class CheckpointProvider:
    """The journal key one Gate account's provider signs with; no URL, no token."""

    tenant_id: UUID
    account_id: UUID
    provider: ProviderName
    evidence_keys: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.tenant_id) is not UUID
            or type(self.account_id) is not UUID
            or self.provider not in JOURNAL_PROVIDERS
            or not self.evidence_keys
            or any(not _KEY_ID.fullmatch(key_id) for key_id in self.evidence_keys)
            or any(type(key) is not bytes or len(key) < 32 for key in self.evidence_keys.values())
        ):
            raise ValueError("Invalid checkpoint provider")
        object.__setattr__(self, "evidence_keys", MappingProxyType(dict(self.evidence_keys)))

    def verifier(self) -> JournalVerifier:
        return JournalVerifier(
            self.tenant_id, self.account_id, self.evidence_keys, provider=self.provider
        )


def journal_envelope(raw: bytes) -> bool:
    """A provider journal, told from an executor envelope by the record it carries.

    Recognized after leading whitespace, as `ExecutorVerifier.verify` recognizes a JSON
    envelope, because JSON admits it and an administrator's pasted journal may carry it.
    """
    if raw.lstrip()[:1] != b"{":
        return False
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        return False
    record = value.get("record") if isinstance(value, dict) else None
    return isinstance(record, dict) and "command" in record


class CheckpointVerifier:
    """One grant's verifier: the executor's key ring, and its provider's journal key if any."""

    # Everything this verifier settles is a checkpoint, and it declares so for the guards
    # that keep checkpoint evidence off operations ExecBound dispatched.
    attests_external_execution = True

    def __init__(self, executor: ExecutorVerifier, journal: JournalVerifier | None) -> None:
        self._executor, self._journal = executor, journal

    def verify(self, command: DispatchCommand, evidence: bytes) -> TerminalEvidence:
        if not journal_envelope(evidence):
            return self._executor.verify(command, evidence)
        if self._journal is None:
            raise ProviderError("INVALID_EVIDENCE")
        signed = parse_provider(evidence, SignedJournal)
        # A journal of an effect before the grant existed describes some other attempt.
        if signed.record.occurred_at < self._executor.granted_at:
            raise ProviderError("INVALID_EVIDENCE")
        return self._journal.verify(command, evidence)

    def verified_tier(self, proof: TerminalEvidence) -> VerifiedTier:
        # Read from the authenticated record the verifier above returned: a journal's is the
        # `SignedJournal` it checked, and neither executor envelope carries a command.
        if journal_envelope(proof.authenticated_record.encode()):
            return "PROVIDER_VERIFIED"
        return "ATTESTED"
