# SPDX-License-Identifier: AGPL-3.0-only
"""What a dispatch ExecBound made itself carried, through retained evidence and replay.

A settlement tier is a statement about an external executor's word. A precondition class is
a statement about the vendor's API. Replay has to carry both and must never let the second
be read as atomicity, which is the claim `CHECKED_BY_CONNECTOR` exists to deny.
"""

import pytest
from replay_fixtures import chain_export

from execbound.replay.verify import ReplayValidationError, verify_export

ATTEMPT = "execution.dispatch_attempt"


def attempt(**payload):
    return chain_export([(ATTEMPT, {"execution_id": "e", "plan_hash": "h", **payload})])


def verified(export):
    return verify_export(export, export.head).events[-1]


def test_a_connector_checked_dispatch_reports_its_class():
    event = verified(attempt(precondition_class="CHECKED_BY_CONNECTOR"))
    assert event.precondition_class == "CHECKED_BY_CONNECTOR"
    # The class is never read as a settlement tier: one is about a vendor's API, the other
    # about an external executor's word, and a reader conflating them is the whole risk.
    assert event.settlement_tier is None
    assert event.terminal_evidence is None


def test_an_attempt_carries_no_window_however_its_payload_is_written():
    """A class is known when the attempt commits. A measured gap is not, and cannot be.

    `take_dispatch` commits the one send attempt before the connector performs anything,
    and a dispatch is one-shot, so at that point nothing has measured a gap and nothing
    ever will for this event. The window has exactly one source, the signed record the
    settlement retains, and the attempt payload is not a second one: a key forged here is
    read by nothing. `test_graph_dispatch.py` holds the producer to that.
    """
    event = verified(attempt(precondition_class="CHECKED_BY_CONNECTOR", precondition_window_ms=37))
    assert event.precondition_class == "CHECKED_BY_CONNECTOR"
    assert event.precondition_window_ms is None


def test_a_dispatch_that_predates_the_class_carries_none_rather_than_a_guarantee():
    event = verified(attempt())
    assert event.precondition_class is None
    assert event.precondition_window_ms is None


def test_an_enforced_dispatch_carries_no_window_because_there_was_no_gap_to_measure():
    """A vendor that enforced the precondition itself measured nothing for anyone to read.

    Structural rather than checked: only `ConnectorRecordVerifier` states a window, so no
    settlement under any other envelope has one to carry. `_terminal` refuses retained
    evidence whose window disagrees with the record it came from.
    """
    event = verified(attempt(precondition_class="ENFORCED_BY_PROVIDER"))
    assert event.precondition_class == "ENFORCED_BY_PROVIDER"
    assert event.precondition_window_ms is None


@pytest.mark.parametrize(
    "payload",
    [
        # A class nothing declares.
        {"precondition_class": "ENFORCED_BY_VIBES"},
        {"precondition_class": "checked_by_connector"},
    ],
)
def test_a_payload_that_cannot_be_believed_is_refused_rather_than_read_past(payload):
    export = attempt(**payload)
    with pytest.raises(ReplayValidationError):
        verify_export(export, export.head)


def test_no_other_event_acquires_a_precondition():
    export = chain_export([("demo.provisioned", {"precondition_class": "CHECKED_BY_CONNECTOR"})])
    event = verify_export(export, export.head).events[-1]
    # The field belongs to the attempt that made the dispatch, not to any payload that
    # happens to carry the key.
    assert event.precondition_class is None
