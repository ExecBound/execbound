# SPDX-License-Identifier: AGPL-3.0-only
"""The message every notification kind renders from, and the label sanitizer (#179)."""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from execbound.transports import (
    DELIVERED,
    ApprovalMessage,
    ClosedMessage,
    SendResult,
    closed_body,
    decide_by,
    render_slack,
    render_teams,
    safe_label,
    webhook_body,
    window_words,
)

TENANT = UUID("00000000-0000-4000-8000-000000000001")
APPROVAL = UUID("00000000-0000-4000-8000-000000000002")
EXECUTION = UUID("00000000-0000-4000-8000-000000000003")
TARGET = UUID("00000000-0000-4000-8000-000000000004")
DELIVERY = UUID("00000000-0000-4000-8000-00000000000d")


def message(**changes: object) -> ApprovalMessage:
    values: dict[str, object] = {
        "tenant_id": TENANT,
        "approval_id": APPROVAL,
        "execution_id": EXECUTION,
        "canonical_target_id": TARGET,
        "action": "endpoint.isolate",
        "action_label": "Isolate endpoint",
        "resource_class": "workstation",
        "environment": "production",
        "expires_at": datetime(2026, 9, 18, 3, 28, tzinfo=UTC),
        "assigned_approvers": 1,
        "approval_url": "https://app.example.net/approvals",
    }
    values.update(changes)
    return ApprovalMessage(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Isolate endpoint", "Isolate endpoint"),
        ("workstation", "workstation"),
        ("production", "production"),
        ("user account (disabled)", "user account (disabled)"),
        ("a<b>c", "abc"),
        ("*bold* _it_", "bold _it_"),
        ("line\nbreak\r\nhere", "line break here"),
        ("jane@example.com", "janeexample.com"),
        ("  lots   of\tspace  ", "lots of space"),
        ("x" * 200, "x" * 80),
        ("", "unknown"),
        ("<>", "unknown"),
        (None, "unknown"),
        (True, "True"),
        (3, "3"),
        ("prod/eu-1: tier.2", "prod/eu-1: tier.2"),
    ],
)
def test_safe_label_keeps_only_plain_label_characters(raw, expected):
    assert safe_label(raw) == expected


def test_without_a_plugin_path_the_link_is_the_plain_approval_address():
    expected = f"https://app.example.net/approvals/{APPROVAL}"
    assert message().link == expected
    assert message().classic_link == f"{expected}/classic"


def test_the_webhook_body_keeps_its_documented_bytes():
    expected = json.dumps(
        {
            "version": 1,
            "kind": "approval.pending",
            "tenant_id": str(TENANT),
            "approval_id": str(APPROVAL),
            "execution_id": str(EXECUTION),
            "action": "endpoint.isolate",
            "resource_class": "workstation",
            "environment": "production",
            "canonical_target_id": str(TARGET),
            "expires_at": "2026-09-18T03:28:00+00:00",
            "assigned_approvers": 1,
            "approval_url": "https://app.example.net/approvals",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert webhook_body(message()) == expected


# Every field a rendered message names besides the facts (#678); the webhook reads none.
EVERY_NEW_FIELD: dict[str, object] = {
    "request_ref": "EB-20",
    "workspace": "Synthetic SOC",
    "space": "Default",
    "requested_by": "Agent 3",
    "sent_at": datetime(2026, 9, 18, 3, 24, tzinfo=UTC),
    "kind": "approval.pending",
    "recorded": (1, 2),
}


def test_ay5_new_fields_never_change_the_webhook_body():
    assert webhook_body(message(**EVERY_NEW_FIELD)) == webhook_body(message())
    # The renderings do read them, so the fields are not simply ignored everywhere.
    assert render_slack(DELIVERY, message(**EVERY_NEW_FIELD)) != render_slack(DELIVERY, message())
    assert render_teams(DELIVERY, message(**EVERY_NEW_FIELD)) != render_teams(DELIVERY, message())


@pytest.mark.parametrize(
    ("seconds", "words"),
    [
        (600, "About 10 minutes"),
        (125, "About 2 minutes"),
        (120, "About 2 minutes"),
        (119, "About 1 minute"),
        (60, "About 1 minute"),
        (59, "Less than a minute"),
        (15, "Less than a minute"),
    ],
)
def test_ay6_window_words_are_the_bare_duration(seconds, words):
    expires = datetime(2026, 9, 18, 3, 28, 7, tzinfo=UTC)
    sent = expires - timedelta(seconds=seconds)
    assert window_words(message(expires_at=expires, sent_at=sent)) == words


def test_ay6_the_deadline_is_given_to_the_second_and_dated_across_midnight():
    expires = datetime(2026, 9, 18, 0, 3, 7, tzinfo=UTC)
    same_day = message(expires_at=expires, sent_at=expires - timedelta(seconds=180))
    assert decide_by(same_day) == "00:03:07 UTC"
    next_day = message(expires_at=expires, sent_at=datetime(2026, 9, 17, 23, 58, tzinfo=UTC))
    assert decide_by(next_day) == "2026-09-18 00:03:07 UTC"
    # Without a send time nothing is relative: the full date, and no window anywhere.
    unsent = message(expires_at=expires)
    assert decide_by(unsent) == "2026-09-18 00:03:07 UTC"
    for render in (render_slack, render_teams):
        assert "Time to decide" not in render(DELIVERY, unsent).decode()


def test_the_webhook_body_keeps_raw_fact_values_as_today():
    # The webhook contract carries the retained values; only the rendered kinds sanitize.
    body = json.loads(webhook_body(message(resource_class=7, environment=None)))
    assert body["resource_class"] == 7 and body["environment"] is None


def test_a_send_result_is_a_code_or_a_delivery():
    assert DELIVERED == SendResult(True)
    assert SendResult(False, "RECEIVER_RATE_LIMITED", 7).retry_after == 7
    with pytest.raises(ValueError):
        SendResult(False, "not a code")
    with pytest.raises(ValueError):
        SendResult(True, "RECEIVER_UNAVAILABLE")
    with pytest.raises(ValueError):
        SendResult(False)


# Close-outs (#678): how an announced approval ended.


def closed(**changes: object) -> ClosedMessage:
    values: dict[str, object] = {
        "tenant_id": TENANT,
        "approval_id": APPROVAL,
        "execution_id": EXECUTION,
        "action": "endpoint.isolate",
        "action_label": "Isolate endpoint",
        "resource_class": "workstation",
        "outcome": "APPROVED",
        "closed_at": datetime(2026, 9, 18, 3, 25, 10, tzinfo=UTC),
        "approval_url": "https://app.example.net/approvals",
        "request_ref": "EB-20",
        "workspace": "Synthetic SOC",
        "pending_delivery_id": UUID("00000000-0000-4000-8000-00000000000e"),
        "sent_at": datetime(2026, 9, 18, 3, 25, 40, tzinfo=UTC),
    }
    values.update(changes)
    return ClosedMessage(**values)  # type: ignore[arg-type]


# The documented close-out body: compact, sorted, lowercase outcome, and nothing that could
# be read as more than a report.
CLOSED_BODY = (
    b'{"action":"endpoint.isolate","approval_id":"00000000-0000-4000-8000-000000000002",'
    b'"approval_url":"https://app.example.net/approvals",'
    b'"closed_at":"2026-09-18T03:25:10+00:00",'
    b'"execution_id":"00000000-0000-4000-8000-000000000003","kind":"approval.closed",'
    b'"outcome":"approved","tenant_id":"00000000-0000-4000-8000-000000000001","version":1}'
)


def test_ay9_the_close_out_webhook_body_keeps_its_documented_bytes():
    assert closed_body(closed()) == CLOSED_BODY
    assert len(CLOSED_BODY) < 4096
    for outcome in ("REFUSED", "LAPSED", "WITHDRAWN"):
        body = json.loads(closed_body(closed(outcome=outcome)))
        assert body["outcome"] == outcome.lower() and body["kind"] == "approval.closed"
    # Names, labels and the workspace are the renderings' alone; the body carries none.
    assert closed_body(closed(workspace="Other", request_ref="EB-1")) == CLOSED_BODY


def test_ay9_a_close_out_has_no_other_outcome():
    with pytest.raises(ValueError):
        closed(outcome="RAN")


# Reminders (#678): the announcement again, still waiting, under its own kind.


def test_ay10_a_reminder_webhook_body_is_the_announcement_with_its_kind():
    announcement = webhook_body(message(**EVERY_NEW_FIELD))
    reminder = webhook_body(message(**EVERY_NEW_FIELD | {"kind": "approval.reminder"}))
    assert reminder == announcement.replace(
        b'"kind":"approval.pending"', b'"kind":"approval.reminder"'
    )
    assert json.loads(reminder)["kind"] == "approval.reminder"
    assert len(reminder) < 4096


@pytest.mark.parametrize("kind", ["approval.closed", "approval.Pending", "reminder", ""])
def test_ay10_an_announcement_is_pending_or_a_reminder_and_nothing_else(kind):
    with pytest.raises(ValueError):
        message(kind=kind)
