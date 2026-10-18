# SPDX-License-Identifier: Apache-2.0
"""The terminal outcome a provider, a connector or an executor may state, and the one
pairing of outcome and reason that is a statement at all."""

from types import MappingProxyType
from typing import Literal

# The terminal values a settled operation carries, named once so that terminal evidence,
# the executor's record and an asserted outcome bind exactly one set and cannot drift
# apart. These are plain aliases for the literals TerminalEvidence already declared
# inline, so they add a member to nothing and change no serialized byte and no JSON
# schema; test_the_terminal_aliases_are_the_evidence_literals holds that.
#
# These two are the *verified* vocabulary and do not move: what a verifier may return,
# what a provider's journal and an executor's signed record may state, and what
# TerminalEvidence binds. The asserted vocabulary below is a superset of each, and the
# split is what makes the new pairing unconstructable by any verifier rather than merely
# unconstructed by the shipped ones.
TerminalOutcome = Literal["EXECUTED", "FAILED_NOT_EXECUTED"]
TerminalReason = Literal[
    "EXECUTED", "VERSION_MISMATCH", "CANCELLED_NOT_EXECUTED", "TARGET_NOT_FOUND"
]


# A total map from each reason to the one outcome that may accompany it, and the guard the
# settlement vocabulary rests on. The parity test it replaces admitted every non-executed
# reason beside every non-executed outcome, which for the widened literals above would have
# admitted nine pairings for five statements — among them FAILED_EFFECT_UNKNOWN beside
# VERSION_MISMATCH, which `_terminal_state` settles at STALE_AUTHORIZATION at tier ASSERTED
# and `replay/verify.py:_asserted` then refuses, ending that tenant's export permanently.
# It is also what lets `_terminal_state` keep its single branch: the table forbids the one
# pairing that would have needed a second, so the two are cross-referenced rather than left
# to be found.
TERMINAL_PAIRS = MappingProxyType(
    {
        "EXECUTED": "EXECUTED",
        "VERSION_MISMATCH": "FAILED_NOT_EXECUTED",
        "CANCELLED_NOT_EXECUTED": "FAILED_NOT_EXECUTED",
        "TARGET_NOT_FOUND": "FAILED_NOT_EXECUTED",
        "REPORTED_FAILURE": "FAILED_EFFECT_UNKNOWN",
    }
)


def consistent_terminal(outcome: str, reason: str) -> bool:
    """Each reason names exactly one outcome; anything else is not a statement."""
    return TERMINAL_PAIRS.get(reason) == outcome
