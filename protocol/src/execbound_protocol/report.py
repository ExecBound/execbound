# SPDX-License-Identifier: Apache-2.0
"""The checkpoint report: what an external executor tells ExecBound about the act it was granted.

An external executor holds its own vendor credential, asks ExecBound before it acts, and
reports afterwards on `POST /v1/executions/{execution_id}/outcome`. This is that report's body,
the model the server parses every report with, so an executor can build one with the protocol
alone and the JSON Schema `protocol/executor/v1/checkpoint-report.schema.json` publishes is
generated from it. Chapter 2 of the executor protocol is its normative text (#37).

What the report may carry as evidence is defined beside it: the Ed25519 envelope and the ES256
token in `execbound_protocol.executor`, and a provider's signed journal in
`execbound_protocol.provider`. Here each is opaque, exactly as the server reads it: the shape of
the report is checked when it is parsed, and the signed bytes are the verifier's to check, which
is the server's.
"""

from typing import Annotated, Any, Literal, Self, get_args

from pydantic import AwareDatetime, Field, model_validator

from execbound_protocol.canonical import canonical_json
from execbound_protocol.outcomes import TerminalReason, consistent_terminal
from execbound_protocol.strict import StrictModel

# The largest report body ExecBound reads, in bytes. The server's parser holds the bound; a
# body over it is refused before anything in it is read.
MAX_REPORT_BYTES = 16 * 1024

# The report secret's shape, named so the absence of one is a type and not a sentinel.
ReportSecret = Annotated[str, Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]

# What an unverifiable statement may say, which is the verified vocabulary plus one member
# on each side. FAILED_EFFECT_UNKNOWN is deliberately parallel to FAILED_NOT_EXECUTED,
# which states that the vendor did not act; it states that whether it acted is not
# established. REPORTED_FAILURE is the one reason that names a statement rather than an
# established fact. It refunds nothing, and that is a property of TERMINAL_PAIRS rather
# than of the reason: the table maps it to FAILED_EFFECT_UNKNOWN and to nothing else, so
# no outcome that refunds may accompany it.
AssertedReason = Literal[
    "EXECUTED",
    "VERSION_MISMATCH",
    "CANCELLED_NOT_EXECUTED",
    "TARGET_NOT_FOUND",
    "REPORTED_FAILURE",
]

# What an external executor's report may say happened. UNKNOWN is deliberately not a
# member of TerminalOutcome: an executor whose vendor call timed out can honestly attest
# none of the terminal reasons, and the absence of a terminal outcome is not a kind of
# one, so an unknown result constructs no evidence of either tier and settles nothing.
ReportedResult = Literal["EXECUTED", "FAILED_NOT_EXECUTED", "UNKNOWN", "FAILED_EFFECT_UNKNOWN"]

# A compact JWS in its only admitted spelling: three unpadded base64url segments. The
# shape is refused at the parser, so a malformed token reads no execution row and loads no
# key ring; what the segments decode to is the verifier's to check.
JwsToken = Annotated[
    str,
    Field(
        min_length=5,
        max_length=4096,
        pattern=r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$",
    ),
]


class OutcomeReport(StrictModel):
    """What an external executor states about the one act its grant described.

    The report itself names no operation, account or hash: the execution it settles is the
    one the route was addressed to and the one whose secret it presents, and the bound
    fields of the retained evidence are taken from that execution's frozen command. Signed
    evidence (a record, an attestation or a journal) does state them, and the verifier
    checks them against the same command.

    The report secret is the whole of its authority. An act grant is not presented here
    and cannot be: extra fields are refused, so a caller can add nothing to this that
    stands in for the secret the execution retains the digest of.
    """

    report_secret: ReportSecret
    outcome: ReportedResult
    reason: AssertedReason | None = None
    # The executor's own clock, retained as a reported time and never a confirmation
    # time: a future-dated confirmation would deny every later execution in the tenant.
    reported_at: AwareDatetime | None = None
    # The executor's signed envelope, opaque here and parsed by the verifier that checks
    # it, exactly as a provider journal is opaque to this module.
    record: dict[str, Any] | None = None
    # An ES256 compact JWS, the envelope a platform that cannot sign Ed25519 produces.
    attestation: JwsToken | None = None
    # A provider's signed journal for this exact command, opaque here as a record is.
    journal: dict[str, Any] | None = None

    @property
    def signed(self) -> tuple[str, ...]:
        """Which evidence fields this report carries."""
        return tuple(
            name
            for name, value in (
                ("record", self.record),
                ("attestation", self.attestation),
                ("journal", self.journal),
            )
            if value is not None
        )

    @property
    def evidence(self) -> bytes | None:
        """The one piece of evidence as the verifier reads it, or None for a bare word."""
        if self.record is not None:
            return canonical_json(self.record).encode()
        if self.journal is not None:
            return canonical_json(self.journal).encode()
        if self.attestation is not None:
            return self.attestation.encode("ascii")
        return None

    @model_validator(mode="after")
    def consistent_report(self) -> Self:
        signed = self.signed
        if len(signed) > 1:
            # One statement, one piece of evidence: a report carrying two would settle on
            # whichever the verifier read and retain nothing of the other.
            raise ValueError("A report carries one piece of evidence")
        if self.outcome == "UNKNOWN":
            # Nothing signed can express an unknown result, because every envelope binds a
            # terminal outcome, and no reason names one either.
            if self.reason is not None or signed:
                raise ValueError("An unknown result carries no reason and nothing signed")
        elif self.reason is None or not consistent_terminal(self.outcome, self.reason):
            raise ValueError("A terminal outcome carries its own reason")
        elif signed and self.reason not in get_args(TerminalReason):
            # Signed evidence may carry only a reason a verifier could return, so a report
            # presenting it beside a reason the asserted vocabulary alone admits is
            # refused when it is parsed rather than after a signature check. The envelopes
            # would refuse it anyway; refusing here means no execution row is read and no
            # key ring is loaded for it.
            raise ValueError("Signed evidence states only what a verifier could return")
        if (self.reported_at is None) == (not signed):
            # Signed evidence carries the executor's time inside the bytes that were
            # signed, so a second, unsigned one beside it would be a time nothing holds it to.
            raise ValueError("A reported time accompanies exactly a report with no evidence")
        return self
