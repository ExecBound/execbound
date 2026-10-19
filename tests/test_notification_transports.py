# SPDX-License-Identifier: AGPL-3.0-only
"""The message every notification kind renders from, and the label sanitizer (#179)."""

import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from uuid import UUID

import pytest

from execbound import transports
from execbound.transports import (
    DELIVERED,
    ApprovalMessage,
    ClosedMessage,
    SendResult,
    closed_body,
    decide_by,
    render_slack,
    render_teams,
    retry_after_seconds,
    safe_label,
    webhook_body,
    window_words,
)

TENANT = UUID("00000000-0000-4000-8000-000000000001")
APPROVAL = UUID("00000000-0000-4000-8000-000000000002")
EXECUTION = UUID("00000000-0000-4000-8000-000000000003")
TARGET = UUID("00000000-0000-4000-8000-000000000004")
DELIVERY = UUID("00000000-0000-4000-8000-00000000000d")
# "Security" in Cyrillic and "production" in Japanese: `safe_label` keeps nothing of either.
NON_LATIN_WORKSPACE = "Безопасность"
NON_LATIN_SPACE = "本番"
# What a chat target could read as italics, an emoji and a link, all inside `safe_label`'s
# alphabet, so the label is the name as written.
MARKUP = "_x_ :smile: example.com"
MARKS = ("_x_", ":smile:", "example.com")
# Each shape a chat target could format, on its own and inside `safe_label`'s alphabet:
# italics, an emoji code, a bare domain, a path, and the two list items a Teams fact can start.
FORMATTABLE = ("a_b", "x :smile:", "example.com", "a/b", "-x", "1) x")
# A name with none of them, which every card shows in place.
PLAIN = "SOC (EU) - East"


def chosen_by_tenant(tenant: UUID) -> str:
    """The line naming the workspace to choose when nothing of its name can be shown."""
    return f"If you belong to more than one workspace, choose the one whose tenant id is {tenant}."


def chosen_like(label: str, tenant: UUID) -> str:
    """The line naming the workspace to choose when its name shows only as a reduced label."""
    return (
        "If you belong to more than one workspace, "
        f"choose the one named like {label} (tenant id {tenant})."
    )


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
        # Accents and compatibility forms fold to their letters before anything is dropped.
        ("\u00c9quipe S\u00e9curit\u00e9", "Equipe Securite"),
        ("Cr\u00e8me Br\u00fbl\u00e9e SOC", "Creme Brulee SOC"),
        ("\uff21\uff23\uff2d\uff25 \uff33\uff2f\uff23", "ACME SOC"),
    ],
)
def test_safe_label_keeps_only_plain_label_characters(raw, expected):
    assert safe_label(raw) == expected


@pytest.mark.parametrize(
    "name", [NON_LATIN_WORKSPACE, NON_LATIN_SPACE, "\U0001f512", "  ", "<>", None]
)
def test_ay6_a_name_safe_label_keeps_nothing_of_is_no_name(name):
    """A message words itself without such a name rather than calling it "unknown"; a label
    that is not a name still reads "unknown", as it always has."""
    assert transports.name_label(name) is None
    assert safe_label(name) == "unknown"


@pytest.mark.parametrize(
    ("name", "label"),
    [
        ("Synthetic SOC", "Synthetic SOC"),
        ("Acme & Co", "Acme Co"),
        ("\u00c9quipe S\u00e9curit\u00e9", "Equipe Securite"),
        (MARKUP, MARKUP),
        # A workspace its administrators called "unknown" keeps that name.
        ("unknown", "unknown"),
    ],
)
def test_ay6_a_name_with_anything_left_is_its_label(name, label):
    assert transports.name_label(name) == label == safe_label(name)


@pytest.mark.parametrize(
    ("name", "shown"),
    [
        ("Synthetic SOC", "as written"),
        ("  Synthetic \t SOC\n", "as written"),
        (MARKUP, "as written"),
        ("Acme & Co", "Acme Co"),
        ("Acme, Inc.", "Acme Inc."),
        ("O'Brien SOC", "OBrien SOC"),
        ("\u00c9quipe S\u00e9curit\u00e9", "Equipe Securite"),
        ("W" * 81, "W" * 80),
        (NON_LATIN_WORKSPACE, None),
    ],
)
def test_ay6_the_choose_line_names_a_workspace_only_as_its_owner_wrote_it(name, shown):
    """Whitespace apart, a label that differs from the name could match another workspace's
    name, or none the reader sees. It stays as a hint beside the tenant id, which only an
    administrator sees in Workspace settings; the tenant id stands alone only when nothing of
    the name survives."""
    if shown == "as written":
        expected = f"If you belong to more than one workspace, choose {safe_label(name)}."
    elif shown is None:
        expected = chosen_by_tenant(TENANT)
    else:
        expected = chosen_like(shown, TENANT)
    assert transports.choose_workspace(name, TENANT) == expected


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


class FixedClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


# A receiver's own moment: the HTTP-dates below are read against it.
ANSWERED = datetime(2026, 10, 21, 7, 27, tzinfo=UTC)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        # Delta-seconds, clamped to 1..3600.
        ("7", 7),
        (" 120 ", 120),
        ("3600", 3600),
        ("0", 1),
        ("-5", 1),
        ("99999", 3600),
        # An HTTP-date, measured from the clock: a minute ahead, a day ahead, a day behind, now.
        ("Wed, 21 Oct 2026 07:28:00 GMT", 60),
        ("Thu, 22 Oct 2026 07:27:00 GMT", 3600),
        ("Tue, 20 Oct 2026 07:27:00 GMT", 1),
        ("Wed, 21 Oct 2026 07:27:00 GMT", 1),
        # `-0000` and the obsolete asctime form parse with no zone; an HTTP-date is always GMT.
        ("Wed, 21 Oct 2026 07:29:00 -0000", 120),
        ("Wed Oct 21 07:28:00 2026", 60),
        ("Wednesday, 21-Oct-26 07:28:00 GMT", 60),
        # Absent, or neither form: the default.
        (None, 30),
        ("", 30),
        ("soon", 30),
        ("Wed, 99 Oct 2026 07:28:00 GMT", 30),
        ("Wed, 21 Foo 2026 07:28:00 GMT", 30),
        ("7 seconds", 30),
    ],
)
def test_retry_after_reads_seconds_or_an_http_date_against_the_clock(value, expected):
    assert retry_after_seconds(value, clock=FixedClock(ANSWERED)) == expected


@pytest.mark.parametrize("past", [250, 500, 750])
def test_an_http_date_is_rounded_up_so_the_retry_never_lands_before_it(past):
    """59.75, 59.5 and 59.25 s to the date all wait 60: rounding to nearest gives 59 for the
    last, and truncating gives 59 for all three."""
    clock = FixedClock(ANSWERED + timedelta(milliseconds=past))
    assert retry_after_seconds("Wed, 21 Oct 2026 07:28:00 GMT", clock=clock) == 60


def test_an_http_date_with_no_clock_is_measured_from_now():
    ahead = format_datetime(datetime.now(UTC) + timedelta(seconds=120), usegmt=True)
    assert 110 <= retry_after_seconds(ahead) <= 121
    behind = format_datetime(datetime.now(UTC) - timedelta(days=1), usegmt=True)
    assert retry_after_seconds(behind) == 1


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
