# SPDX-License-Identifier: Apache-2.0
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
exports one says whose signature it is; see "A vendor that co-signs nothing" in
``docs/PROVIDER.md``.
"""

import hashlib
import hmac
from typing import Self
from uuid import UUID

from pydantic import Field, model_validator

from execbound_protocol.canonical import canonical_json
from execbound_protocol.outcomes import TerminalReason
from execbound_protocol.provider import ProviderError
from execbound_protocol.strict import StrictModel

# The signature covers this name as well as the content, so a record made under a different
# scheme can never verify under this one even if the fields happen to line up.
CONNECTOR_RECORD_V1 = "connector-record.v1"


class ConnectorExchange(StrictModel):
    """One vendor exchange, as ExecBound performed it."""

    version: int = 1
    scheme: str = Field(default=CONNECTOR_RECORD_V1, min_length=1, max_length=64)
    # The four fields that bind a record to one execution. Evidence belonging to another
    # execution is refused on these, which is the check that actually matters here: a
    # signature made by ExecBound cannot itself prove which operation it describes.
    operation_id: UUID
    account_id: UUID
    intent_hash: str = Field(min_length=64, max_length=64)
    plan_hash: str = Field(min_length=64, max_length=64)
    provider: str = Field(min_length=1, max_length=64)
    provider_operation: str = Field(min_length=1, max_length=64)
    # What the exchange did. `frozen` is the composite the plan carried and `observed` the
    # one the connector computed from its own read immediately before writing. Both are
    # retained so a reader is not asked to take the comparison on trust, and `consistent`
    # below holds the pair to the outcome the record claims.
    frozen: str = Field(min_length=1, max_length=80)
    observed: str | None = Field(default=None, min_length=1, max_length=80)
    window_ms: int = Field(ge=0, le=3_600_000)
    # The last response the vendor sent: the write's status on an execution, the read's
    # when the connector compared and never reached a write.
    status: int = Field(ge=100, le=599)
    # The kernel's own vocabulary, not a connector-invented one. A Graph disable settles
    # EXECUTED, VERSION_MISMATCH when the composite moved before the write, or
    # TARGET_NOT_FOUND when the subject was gone.
    outcome: TerminalReason

    @model_validator(mode="after")
    def consistent(self) -> Self:
        """The composites and the outcome have to state the same thing, as a journal's do.

        A record is the connector's account of a read, a comparison and at most one write,
        so what it retains of the comparison must agree with the outcome it claims. The
        mocks' `JournalRecord.consistent` holds a signed journal to the same standard, and
        for the same reason: a signature over an incoherent statement is still incoherent.
        Refusing the combinations here rather than in the verifier means such a record
        cannot be constructed at all, and parsing one off the wire runs this same check.
        """
        if self.outcome == "EXECUTED":
            # Written only because the composites matched, and no status outside the 2xx
            # range establishes that a write happened at all.
            if self.observed != self.frozen or not 200 <= self.status < 300:
                raise ValueError("Invalid executed connector record")
        elif self.outcome == "VERSION_MISMATCH":
            # The drift is the evidence. A mismatch whose composites agree states nothing,
            # and this is the record `CHECKED_BY_CONNECTOR` exists to retain: the read and
            # the comparison that stopped a write, which is all this class ever proves.
            if self.observed is None or self.observed == self.frozen:
                raise ValueError("Invalid version mismatch connector record")
        elif self.outcome == "TARGET_NOT_FOUND":
            # There was no subject to compute a composite from.
            if self.observed is not None:
                raise ValueError("Invalid target not found connector record")
        else:
            # CANCELLED_NOT_EXECUTED. Graph offers no cancellation, so a connector record
            # claiming one would settle an execution as deliberately withdrawn on nothing.
            raise ValueError("A connector record cannot claim a cancellation")
        return self


class ConnectorRecord(StrictModel):
    key_id: str = Field(min_length=1, max_length=64)
    record: ConnectorExchange
    signature: str = Field(min_length=64, max_length=64)


def record_signature(record: ConnectorExchange, key_id: str, key: bytes) -> str:
    message = canonical_json(
        {"scheme": CONNECTOR_RECORD_V1, "key_id": key_id, "record": record.model_dump(mode="json")}
    )
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def sign_exchange(record: ConnectorExchange, key_id: str, key: bytes) -> bytes:
    if len(key) < 32:
        raise ProviderError("INVALID_EVIDENCE")
    signed = ConnectorRecord(
        key_id=key_id, record=record, signature=record_signature(record, key_id, key)
    )
    return signed.model_dump_json().encode()
