# SPDX-License-Identifier: AGPL-3.0-only
"""What a finding message carries, in each kind (#31): FD2's pinned bytes and FD5.

No database and no network. A message carries identifiers, the rule's version and fixed label,
when the finding was raised, the workspace and Space names reduced by `safe_label`, and the
console's link to the finding; never anything a source, a provider or a person wrote. The
webhook body is the loopback worker's `monitor.finding` version 1 with three keys added, pinned
byte for byte.
"""

import json
from datetime import UTC, datetime, timedelta, timezone
from email import message_from_string, policy
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from chat_fakes import finding_slack_shape_ok, finding_teams_shape_ok, slack_texts, teams_texts
from test_notification_transports import (
    FORMATTABLE,
    MARKUP,
    NON_LATIN_SPACE,
    NON_LATIN_WORKSPACE,
    PLAIN,
    chosen_by_tenant,
    chosen_like,
)

from execbound.transports import (
    FINDING_DISCLAIMER,
    MAX_PAYLOAD_BYTES,
    FindingMessage,
    MailConfig,
    finding_body,
    render_email,
    render_slack,
    render_teams,
)

FIXTURE = Path(__file__).parent / "fixtures" / "notifications" / "monitor-finding-webhook-v1.json"
MAIL = MailConfig("localhost", 2525, "tls", "user", "pw", "no-reply@notify.example.com")
HOSTILE = (
    "<img src=x onerror=alert(1)> @here <!channel> [link](https://evil.example)"
    "\r\nBcc: x@evil.example"
)
CHOOSE = "If you belong to more than one workspace, choose Synthetic SOC."
# The identifiers line of each shape of finding: one a source reported, and one read from a
# directory, which names its connection and agent and has no source or observation.
SOURCE_IDENTIFIERS = (
    "Finding f1f1f1f1-0000-4000-8000-000000000001 | Source 5050aaaa-0000-4000-8000-000000000002 "
    "| Observation 0b0b0b0b-0000-4000-8000-000000000004 "
    "| Delivery d0d0d0d0-0000-4000-8000-000000000001"
)
DIRECTORY_IDENTIFIERS = (
    "Finding f1f1f1f1-0000-4000-8000-000000000001 "
    "| Connection c0c0c0c0-0000-4000-8000-000000000005 "
    "| Agent a9a9a9a9-0000-4000-8000-000000000006 "
    "| Delivery d0d0d0d0-0000-4000-8000-000000000001"
)
DIRECTORY = {
    "rule_version": "new-agent.v1",
    "rule_label": "New agent",
    "source_id": None,
    "observation_id": None,
    "connection_id": UUID("c0c0c0c0-0000-4000-8000-000000000005"),
    "agent_id": UUID("a9a9a9a9-0000-4000-8000-000000000006"),
    "profile_version": None,
}


def message(**changes: object) -> FindingMessage:
    values: dict[str, object] = {
        "tenant_id": UUID("7f8e9d0c-0000-4000-8000-000000000003"),
        "finding_id": UUID("f1f1f1f1-0000-4000-8000-000000000001"),
        "delivery_id": UUID("d0d0d0d0-0000-4000-8000-000000000001"),
        "rule_version": "sensitive-action.v2",
        "rule_label": "Sensitive action reported",
        "created_at": datetime(2026, 10, 17, 12, 0, tzinfo=UTC),
        "origin": "https://console.example.net",
        "workspace": "Synthetic SOC",
        "space": "Default",
        "source_id": UUID("5050aaaa-0000-4000-8000-000000000002"),
        "observation_id": UUID("0b0b0b0b-0000-4000-8000-000000000004"),
        "profile_version": 3,
    }
    return FindingMessage(**(values | changes))  # type: ignore[arg-type]


def rendered(found: FindingMessage) -> dict[str, str]:
    email = render_email(MAIL, "jane@example.com", found.delivery_id, found)
    return {
        "webhook": finding_body(found).decode(),
        "email": email.get_content(),
        "slack": render_slack(found.delivery_id, found).decode(),
        "teams": render_teams(found.delivery_id, found).decode(),
    }


def test_fd2_the_webhook_body_is_pinned_byte_for_byte():
    assert finding_body(message()) == FIXTURE.read_bytes().rstrip(b"\n")


def test_fd2_the_time_raised_is_written_in_utc_whatever_zone_it_was_read_in():
    """PostgreSQL hands a `timestamptz` back in the session's zone. The same instant read two
    hours east renders the pinned bytes and the same time raised."""
    found = message(created_at=datetime(2026, 10, 17, 14, 0, tzinfo=timezone(timedelta(hours=2))))
    assert finding_body(found) == FIXTURE.read_bytes().rstrip(b"\n")
    assert "Raised: 2026-10-17 12:00:00 UTC" in rendered(found)["email"]


def test_fd2_the_email_has_its_subject_headers_link_and_fixed_line():
    found = message()
    email = render_email(MAIL, "jane@example.com", found.delivery_id, found)
    assert email["Subject"] == "[ExecBound · Synthetic SOC] Finding: Sensitive action reported"
    assert email["Message-ID"] == f"<{found.delivery_id}@notify.example.com>"
    assert email["Auto-Submitted"] == "auto-generated"
    assert email["X-ExecBound-Delivery"] == str(found.delivery_id)
    assert email["X-ExecBound-Finding"] == str(found.finding_id)
    assert email.get_content_type() == "text/plain"
    body = email.get_content()
    assert "It is not enforcement" in body
    assert f"Open the finding: {found.link}" in body
    assert "If you belong to more than one workspace, choose Synthetic SOC." in body
    assert found.link == (
        "https://console.example.net/monitor?view=findings&state=all"
        "&open=f1f1f1f1-0000-4000-8000-000000000001"
    )


def test_fd2_the_chat_messages_have_the_shapes_the_fakes_accept():
    found = message()
    slack = json.loads(render_slack(found.delivery_id, found))
    teams = json.loads(render_teams(found.delivery_id, found))
    assert finding_slack_shape_ok(slack) and finding_teams_shape_ok(teams)
    [button] = slack["blocks"][3]["elements"]
    assert (button["text"]["text"], button["url"]) == ("Open the finding", found.link)
    facts = [
        ("Workspace", "Synthetic SOC"),
        ("Space", "Default"),
        ("Rule", "Sensitive action reported (sensitive-action.v2)"),
        ("Raised", "2026-10-17 12:00:00 UTC"),
    ]
    assert [field["text"] for field in slack["blocks"][1]["fields"]] == [
        f"{title}: {value}" for title, value in facts
    ]
    card = teams["attachments"][0]["content"]
    assert card["body"][0]["text"] == "Finding: Sensitive action reported"
    assert [(fact["title"], fact["value"]) for fact in card["body"][1]["facts"]] == facts
    [action] = card["actions"]
    assert (action["title"], action["url"]) == ("Open the finding", found.link)


@pytest.mark.parametrize(
    "changes,identifiers", [({}, SOURCE_IDENTIFIERS), (DIRECTORY, DIRECTORY_IDENTIFIERS)]
)
def test_fd2_every_kind_carries_the_identifiers_the_disclaimer_and_the_workspace_line(
    changes, identifiers
):
    """Each part a finding message must carry, pinned in each kind it is rendered in: the exact
    identifiers line, whichever identifiers the finding has, the fixed disclaimer, and the
    sentence that names the workspace to choose."""
    found = message(**changes)
    lines = render_email(MAIL, "jane@example.com", found.delivery_id, found).get_content()
    assert {identifiers, FINDING_DISCLAIMER, CHOOSE} <= set(lines.splitlines())
    slack = json.loads(render_slack(found.delivery_id, found))["blocks"]
    assert slack[2]["text"]["text"] == FINDING_DISCLAIMER
    assert [block["elements"][0]["text"] for block in slack[4:]] == [CHOOSE, identifiers]
    teams = json.loads(render_teams(found.delivery_id, found))
    assert [block["text"] for block in teams["attachments"][0]["content"]["body"][2:]] == [
        FINDING_DISCLAIMER,
        CHOOSE,
        identifiers,
    ]


def test_fd2_the_finding_email_is_7bit_so_its_source_reads_as_written():
    """As the weekly summary is: the raw message holds each line whole, never quoted-printable
    soft breaks, so the source a recipient views says what the body says."""
    found = message()
    email = render_email(MAIL, "jane@example.com", found.delivery_id, found)
    assert email["Content-Transfer-Encoding"] == "7bit"
    source = email.as_string()
    assert FINDING_DISCLAIMER in source and SOURCE_IDENTIFIERS in source


def test_fd2_the_time_raised_is_aware_and_written_to_the_second():
    """PostgreSQL's `timestamptz` carries microseconds; the body's `created_at` keeps the pinned
    shape, to the second. A time with no zone is refused, never read as the host's own."""
    found = message(created_at=datetime(2026, 10, 17, 12, 0, 0, 654321, tzinfo=UTC))
    assert finding_body(found) == FIXTURE.read_bytes().rstrip(b"\n")
    with pytest.raises(ValueError):
        message(created_at=datetime(2026, 10, 17, 12, 0))


@pytest.mark.parametrize("kind", ["email", "slack", "teams"])
def test_fd2_a_renderer_refuses_a_delivery_id_that_is_not_the_messages_own(kind):
    found = message()
    other = uuid4()
    with pytest.raises(ValueError):
        if kind == "email":
            render_email(MAIL, "jane@example.com", other, found)
        elif kind == "slack":
            render_slack(other, found)
        else:
            render_teams(other, found)


def test_fd5_hostile_workspace_and_space_names_reach_no_body_as_markup():
    found = message(workspace=HOSTILE, space=HOSTILE)
    for kind, body in rendered(found).items():
        for mark in ("<", ">", "@", "onerror="):
            assert mark not in body, (kind, mark)
    email = render_email(MAIL, "jane@example.com", found.delivery_id, found)
    subject = str(email["Subject"])
    assert all(mark not in subject for mark in ("<", ">", "@", "\r", "\n"))
    # This documents that no `Bcc` header is read back. It does not catch an injection itself:
    # `safe_label` drops the line break, and Python's email library refuses a line break in a
    # header before any message exists.
    parsed = message_from_string(email.as_string(), policy=policy.default)
    assert parsed["Bcc"] is None and parsed["Subject"] == subject


def card_facts(kind: str, body: dict) -> list[tuple[str, str]]:
    """The facts a reader sees, in order, from a FactSet or from text runs."""
    if kind == "slack":
        [section] = [b for b in body["blocks"] if b["type"] == "section" and "fields" in b]
        return [tuple(field["text"].split(": ", 1)) for field in section["fields"]]
    found: list[tuple[str, str]] = []
    for block in body["attachments"][0]["content"]["body"]:
        if block["type"] == "FactSet":
            found += [(fact["title"], fact["value"]) for fact in block["facts"]]
        elif block["type"] == "RichTextBlock" and len(block["inlines"]) == 2:
            title, value = block["inlines"]
            found.append((title["text"].removesuffix(": "), value["text"]))
    return found


def test_fd5_a_name_nothing_of_which_survives_is_left_out_and_chosen_by_tenant_id():
    """Names in a script `safe_label` drops would read "unknown", and "choose unknown" helps
    nobody: every kind leaves them out and names the tenant id Workspace settings shows."""
    found = message(workspace=NON_LATIN_WORKSPACE, space=NON_LATIN_SPACE)
    by_tenant = chosen_by_tenant(found.tenant_id)
    email = render_email(MAIL, "jane@example.com", found.delivery_id, found)
    subject, body = str(email["Subject"]), email.get_content()
    assert "unknown" not in subject + body
    assert subject == "[ExecBound] Finding: Sensitive action reported"
    lines = body.splitlines()
    assert lines[0] == "A finding was raised at 2026-10-17 12:00:00 UTC."
    assert not any(line.startswith(("Workspace:", "Space:")) for line in lines)
    assert by_tenant in lines
    assert "You receive this because this address is a findings destination." in lines
    facts = [
        ("Rule", "Sensitive action reported (sensitive-action.v2)"),
        ("Raised", "2026-10-17 12:00:00 UTC"),
    ]
    slack = json.loads(render_slack(found.delivery_id, found))
    assert "unknown" not in json.dumps(slack)
    assert finding_slack_shape_ok(slack) and card_facts("slack", slack) == facts
    assert slack["text"] == "Finding: Sensitive action reported"
    assert by_tenant in [item["text"] for item in slack_texts(slack)]
    teams = json.loads(render_teams(found.delivery_id, found))
    assert "unknown" not in json.dumps(teams)
    assert finding_teams_shape_ok(teams) and card_facts("teams", teams) == facts
    assert by_tenant in sum(teams_texts(teams), [])
    # The webhook body names neither, and keeps its pinned bytes.
    assert finding_body(found) == FIXTURE.read_bytes().rstrip(b"\n")


@pytest.mark.parametrize("kind", ["email", "slack", "teams"])
@pytest.mark.parametrize(
    ("name", "label"),
    [
        ("Acme & Co", "Acme Co"),
        ("Acme, Inc.", "Acme Inc."),
        ("O'Brien SOC", "OBrien SOC"),
        ("\u00c9quipe S\u00e9curit\u00e9", "Equipe Securite"),
    ],
)
def test_fd5_a_reduced_name_still_shows_but_the_reader_chooses_by_tenant_id(kind, name, label):
    """`Acme & Co` reads `Acme Co`, which may be another workspace's name, so the reader is told
    the tenant id with the label as a hint; an accented name folds to its letters rather than
    losing them."""
    found = message(workspace=name)
    hint = chosen_like(label, found.tenant_id)
    if kind == "email":
        lines = render_email(MAIL, "jane@example.com", found.delivery_id, found).get_content()
        assert {f"Workspace: {label}", hint} <= set(lines.splitlines())
        return
    raw = (render_slack if kind == "slack" else render_teams)(found.delivery_id, found)
    assert ("Workspace", label) in card_facts(kind, json.loads(raw))
    assert hint in raw.decode() and f"choose {label}." not in raw.decode()


LONGEST = " ".join([MARKUP] * 4)
HEADER = "Finding: Sensitive action reported"


def named_finding(name: str) -> FindingMessage:
    if name == LONGEST:
        return message(workspace=name, space=name, connection_id=uuid4())
    return message(workspace=name, space=name)


@pytest.mark.parametrize("name", [*FORMATTABLE, LONGEST])
def test_fd5_slack_reads_a_name_it_could_format_only_as_plain_text(name):
    """Slack reads the notification line as mrkdwn, so a name it could format is left out of
    it; the blocks, `plain_text` with `emoji` off, still name it."""
    found = named_finding(name)
    raw = render_slack(found.delivery_id, found)
    assert len(raw) <= MAX_PAYLOAD_BYTES
    body = json.loads(raw)
    assert body["text"] == HEADER
    texts = slack_texts(body)
    assert all(item["type"] == "plain_text" and item["emoji"] is False for item in texts)
    assert f"Workspace: {name[:80].strip()}" in [item["text"] for item in texts]
    assert finding_slack_shape_ok(body)


@pytest.mark.parametrize("name", [*FORMATTABLE, LONGEST])
def test_fd5_teams_reads_a_name_it_could_format_only_as_text_runs(name):
    """Teams reads text blocks and facts as Markdown, so the facts and the sentence naming the
    workspace to choose travel in text runs, which Adaptive Cards show as written, and the
    name appears nowhere else."""
    found = named_finding(name)
    raw = render_teams(found.delivery_id, found)
    assert len(raw) <= MAX_PAYLOAD_BYTES
    body = json.loads(raw)
    parsed, literal = teams_texts(body)
    label = name[:80].strip()
    assert not [text for text in parsed if label in text]
    assert label in literal
    assert any(text.startswith("If you belong to more than one workspace") for text in literal)
    assert finding_teams_shape_ok(body)


def test_fd5_a_plain_name_keeps_the_fact_set_and_the_notification_line():
    """`SOC (EU) - East` holds nothing either target formats: the card is unchanged."""
    found = message(workspace=PLAIN, space=PLAIN)
    assert json.loads(render_slack(found.delivery_id, found))["text"] == f"{HEADER} in {PLAIN}"
    body = json.loads(render_teams(found.delivery_id, found))
    types = [block["type"] for block in body["attachments"][0]["content"]["body"]]
    assert types == ["TextBlock", "FactSet", "TextBlock", "TextBlock", "TextBlock"]
    parsed, literal = teams_texts(body)
    assert literal == [] and f"If you belong to more than one workspace, choose {PLAIN}." in parsed


@pytest.mark.parametrize(("workspace", "space"), [("Synthetic SOC", "a_b"), ("a_b", "Default")])
def test_fd5_either_name_alone_puts_the_card_in_text_runs(workspace, space):
    """A Space name Teams could format puts the card in text runs as a workspace name does;
    Slack's line names only the workspace, so it keeps a plain one."""
    found = message(workspace=workspace, space=space)
    parsed, literal = teams_texts(json.loads(render_teams(found.delivery_id, found)))
    assert "a_b" in literal and not [text for text in parsed if "a_b" in text]
    line = json.loads(render_slack(found.delivery_id, found))["text"]
    assert line == (f"{HEADER} in Synthetic SOC" if workspace == "Synthetic SOC" else HEADER)


def test_fd5_every_body_is_bounded():
    """The longest message there can be: every identifier, the longest origin the rules admit,
    the longest profile version and names far past the label length, which `safe_label` cuts."""
    found = message(
        workspace="W" * 5000,
        space="S" * 5000,
        origin="https://" + "o" * 253,
        connection_id=uuid4(),
        agent_id=uuid4(),
        profile_version=2**31 - 1,
        rule_version="first-consequential-action.v1",
        rule_label="First consequential action outside ExecBound",
    )
    assert all(
        value is not None
        for value in (
            found.source_id,
            found.connection_id,
            found.observation_id,
            found.agent_id,
        )
    )
    email = render_email(MAIL, "jane@example.com", found.delivery_id, found)
    for kind, body in {**rendered(found), "email": email.as_string()}.items():
        assert len(body.encode()) <= MAX_PAYLOAD_BYTES, kind


@pytest.mark.parametrize(
    "changes",
    [
        {"origin": "javascript:alert(1)"},
        {"origin": "https://console.example.net/<x>"},
        {"rule_label": "<b>Sensitive</b>"},
        {"rule_version": "<x>"},
        # Both names are required: their columns are never null, and a message with none
        # would name a workspace that does not exist.
        {"workspace": None},
        {"space": None},
        # The time raised is a `datetime` with its zone, never its text.
        {"created_at": "2026-10-17T12:00:00+00:00"},
    ],
)
def test_fd5_a_link_or_label_outside_the_rules_is_refused(changes):
    with pytest.raises(ValueError):
        message(**changes)
