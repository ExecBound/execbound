# SPDX-License-Identifier: AGPL-3.0-only
"""Slack and Teams delivery of approval notifications (#179 phase 2).

The kinds' URL rules, the rendered blocks and card against checked-in fixtures, the sender
against local fakes that check the payload shape, and the drain's fan-out, `Retry-After`
handling and one-send-per-second pacing on real PostgreSQL.
"""

import json
import secrets
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
from chat_fakes import TEAMS_QUERY, chat_fake
from conftest import assert_secret_free
from smtp_double import free_port
from sqlalchemy import text
from test_approval_notifications import destination as webhook_destination
from test_approval_notifications import pending, rows
from test_execution import registry as registry
from test_execution import world as world
from test_monitoring_worker import receiver as receiver
from test_notification_email import AGENT_LABEL, configuration, label_agent, load, named
from test_notification_transports import APPROVAL, EXECUTION
from test_notification_transports import closed as closed_message
from test_notification_transports import message as approval
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.notifications import Destination, deliver_pending
from execbound.replay.verify import reject_secrets
from execbound.runtime import Runtime
from execbound.surfaces.sessions import issue_session, load_session
from execbound.surfaces.settings_pages import tenant_overview
from execbound.surfaces.tokens import TokenKeys
from execbound.transports import DELIVERED, SendResult, render_slack, render_teams, send_chat

FIXTURES = Path(__file__).parent / "fixtures" / "notifications"
DELIVERY = UUID("00000000-0000-4000-8000-00000000000d")
SLACK = "https://hooks.slack.com/services/T0001/B0001/secretpart0001"
TEAMS = "https://prod-00.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke"


def chat(world, kind, url, destination_id=None):
    return {
        "destination_id": destination_id or f"soc-{kind}",
        "tenant_id": str(world["identity"].tenant_id),
        "kind": kind,
        "url": url,
    }


def test_slack_and_teams_destinations_load(tmp_path, world, connector):
    value = configuration(
        world,
        connector,
        [chat(world, "slack", SLACK), chat(world, "teams", f"{TEAMS}?{TEAMS_QUERY}")],
        mail=None,
    )
    runtime = load(tmp_path, value)
    assert [(d.kind, d.secret, d.to) for d in runtime.notifications] == [
        ("slack", "", None),
        ("teams", "", None),
    ]
    assert all("secretpart" not in repr(d) and "sig=" not in repr(d) for d in runtime.notifications)


@pytest.mark.parametrize(
    ("kind", "url"),
    [
        ("slack", SLACK + "?x=1"),
        ("slack", "https://hooks.slack.com/api/chat.postMessage"),
        ("slack", "https://hooks.slack.com/services/"),
        ("slack", "https://hooks.slack.com.evil.example.net/services/T/B/X"),
        ("slack", "http://hooks.slack.com/services/T/B/X"),
        ("slack", "https://user:pw@hooks.slack.com/services/T/B/X"),
        ("slack", SLACK + "#fragment"),
        ("slack", "https://hooks.slack.com:8443/services/T/B/X"),
        ("teams", "https://contoso.webhook.office.com/webhookb2/abc?sig=secretpart"),
        ("teams", "https://alerts.example.net/workflows/abc?sig=secretpart"),
        ("teams", "https://logic.azure.com/workflows/abc?sig=secretpart"),
        ("teams", f"{TEAMS}?{TEAMS_QUERY}#fragment"),
        ("teams", f"http://prod-00.westus.logic.azure.com/workflows/abc?{TEAMS_QUERY}"),
    ],
)
def test_chat_urls_outside_the_rules_refuse_without_quoting_them(
    tmp_path, world, connector, kind, url
):
    with pytest.raises(ValueError) as refused:
        load(tmp_path, configuration(world, connector, [chat(world, kind, url)], mail=None))
    assert "secretpart" not in str(refused.value) and "sig=" not in str(refused.value)


@pytest.mark.parametrize(
    "host",
    [
        "prod-00.westus.logic.azure.com",
        "api.powerautomate.com",
        "api.powerplatform.com",
        "flow.microsoft.com",
    ],
)
def test_each_workflows_host_is_accepted_with_its_signed_query(host):
    Destination("teams", uuid4(), f"https://{host}/workflows/abc?{TEAMS_QUERY}", "", kind="teams")


def test_the_tenant_overview_shows_kind_and_host_never_the_url(runtime, world):
    tenant = world["identity"].tenant_id
    grant = issue_session(runtime.db, world["admin"], clock=runtime.clock)
    session = load_session(runtime.db, grant.token, clock=runtime.clock)
    destinations = (
        Destination("soc-slack", tenant, SLACK, "", kind="slack"),
        Destination("soc-teams", tenant, f"{TEAMS}?{TEAMS_QUERY}", "", kind="teams"),
        Destination("jane", tenant, "", "", kind="email", to="jane@example.com"),
    )
    fake = SimpleNamespace(
        db=runtime.db, clock=runtime.clock, catalog=runtime.catalog, notifications=destinations
    )
    data = tenant_overview(fake, session)
    assert [(d["destination_id"], d["kind"], d["host"]) for d in data["destinations"]] == [
        ("soc-slack", "slack", "hooks.slack.com"),
        ("soc-teams", "teams", "prod-00.westus.logic.azure.com"),
        ("jane", "email", ""),
    ]
    reject_secrets(data["destinations"])
    dumped = json.dumps(data, default=str)
    for private in ("secretpart", "/services/", "sig=", "/workflows/", "jane@example.com"):
        assert private not in dumped


def test_a_chat_destination_carries_neither_a_secret_nor_a_recipient():
    tenant = uuid4()
    Destination("slack", tenant, SLACK, "", kind="slack")
    with pytest.raises(ValueError):
        Destination("slack", tenant, SLACK, "s" * 40, kind="slack")
    with pytest.raises(ValueError):
        Destination("slack", tenant, SLACK, "", kind="slack", to="jane@example.com")
    with pytest.raises(ValueError):
        Destination("teams", tenant, "", "", kind="teams")


@pytest.mark.parametrize(
    ("render", "fixture"),
    [(render_slack, "slack-approval.json"), (render_teams, "teams-approval.json")],
)
def test_rendering_matches_the_checked_in_fixture(render, fixture):
    raw = render(DELIVERY, named())
    assert json.loads(raw) == json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))
    assert len(raw) <= 4096
    shown = raw.decode()
    assert_secret_free(shown)
    assert "<" not in shown
    assert f"https://app.example.net/approvals/{APPROVAL}" in shown
    assert f"https://app.example.net/approvals/{APPROVAL}/classic" in shown
    assert "If the console does not load, use the basic page." in shown
    assert "Request EB-20" in shown


@pytest.mark.parametrize("render", [render_slack, render_teams])
def test_a_message_without_a_reference_keeps_its_identifiers_and_header(render):
    raw = render(DELIVERY, approval())
    body = json.loads(raw)
    header = (
        body["blocks"][0]["text"]["text"]
        if render is render_slack
        else body["attachments"][0]["content"]["body"][0]["text"]
    )
    assert header == "Approval needed"
    shown = raw.decode()
    assert str(EXECUTION) in shown and str(DELIVERY) in shown
    assert "Time to decide" not in shown and "Workspace" not in shown


def facts(render, message):
    """The rendered facts as (title, value) pairs, in the order a reader sees them."""
    body = json.loads(render(DELIVERY, message))
    if render is render_slack:
        [section] = [b for b in body["blocks"] if b["type"] == "section"]
        for field in section["fields"]:
            assert field["type"] == "plain_text" and field["emoji"] is False
        return [tuple(f["text"].split(": ", 1)) for f in section["fields"]]
    card = body["attachments"][0]["content"]
    [fact_set] = [b for b in card["body"] if b["type"] == "FactSet"]
    return [(f["title"], f["value"]) for f in fact_set["facts"]]


@pytest.mark.parametrize("render", [render_slack, render_teams])
def test_ay7_facts_lead_with_the_deadline(render):
    order = [
        "Decide by",
        "Time to decide",
        "Workspace",
        "Space",
        "Action",
        "Resource class",
        "Environment",
        "Requested by",
    ]
    shown = facts(render, named())
    assert [title for title, _ in shown] == order
    assert dict(shown) == {
        "Decide by": "2026-09-18 03:28:00 UTC",
        "Time to decide": "About 4 minutes when sent",
        "Workspace": "Synthetic SOC",
        "Space": "Default",
        "Action": "Isolate endpoint",
        "Resource class": "workstation",
        "Environment": "production",
        "Requested by": "Agent 3",
    }
    quorum = facts(render, named(recorded=(1, 2)))
    assert [title for title, _ in quorum] == [*order, "Approvals recorded"]
    assert quorum[-1] == ("Approvals recorded", "1 of 2")
    raw = render(DELIVERY, named(recorded=(1, 2)))
    assert len(raw) <= 4096
    body = json.loads(raw)
    if render is render_slack:
        # Nine fields, inside Slack's ten; the phone's line carries the deadline.
        assert body["blocks"][0]["text"]["text"] == "EB-20 \u00b7 Isolate endpoint needs a decision"
        assert body["text"] == (
            "EB-20 \u00b7 Isolate endpoint needs a decision by 03:28:00 UTC in Synthetic SOC"
        )
        for block in body["blocks"]:
            for item in [block.get("text"), *block.get("fields", []), *block.get("elements", [])]:
                if isinstance(item, dict) and "emoji" in item:
                    assert item["type"] == "plain_text"
    else:
        card = body["attachments"][0]["content"]
        assert card["body"][0]["text"] == "EB-20 \u00b7 Isolate endpoint needs a decision"


def headline(render, body):
    """The header a reader sees first, and Slack's notification line (None for Teams)."""
    if render is render_slack:
        return body["blocks"][0]["text"]["text"], body["text"]
    return body["attachments"][0]["content"]["body"][0]["text"], None


@pytest.mark.parametrize("render", [render_slack, render_teams])
def test_ay10_a_reminder_card_is_the_announcement_still_needing_a_decision(render):
    raw = render(DELIVERY, named(kind="approval.reminder"))
    assert len(raw) <= 4096
    assert_secret_free(raw.decode())
    reminder = json.loads(raw)
    announcement = json.loads(render(DELIVERY, named()))
    header, line = headline(render, reminder)
    assert header == "EB-20 \u00b7 Isolate endpoint still needs a decision"
    if render is render_slack:
        assert line == (
            "EB-20 \u00b7 Isolate endpoint still needs a decision by 03:28:00 UTC in Synthetic SOC"
        )
    # The header and the notification line are all that change: the same facts led by the
    # deadline, the same two links and the same footer.
    if render is render_slack:
        reminder["blocks"][0]["text"]["text"] = announcement["blocks"][0]["text"]["text"]
        reminder["text"] = announcement["text"]
    else:
        card = reminder["attachments"][0]["content"]
        card["body"][0]["text"] = announcement["attachments"][0]["content"]["body"][0]["text"]
    assert reminder == announcement


@pytest.mark.parametrize("render", [render_slack, render_teams])
def test_ay10_a_reminder_without_a_reference_says_the_approval_is_still_needed(render):
    header, _ = headline(render, json.loads(render(DELIVERY, approval(kind="approval.reminder"))))
    assert header == "Approval still needed"


@pytest.mark.parametrize(
    ("render", "fixture"),
    [(render_slack, "slack-closed.json"), (render_teams, "teams-closed.json")],
)
def test_ay9_a_close_out_card_matches_the_checked_in_fixture(render, fixture):
    raw = render(DELIVERY, closed_message())
    assert json.loads(raw) == json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))
    assert len(raw) <= 4096
    shown = raw.decode()
    assert_secret_free(shown)
    assert "<" not in shown and "/classic" not in shown and "basic page" not in shown
    assert f"https://app.example.net/approvals/{APPROVAL}" in shown
    # Beyond the fixed disclaimer nothing says or implies that the action ran, and no agent,
    # person or target is named.
    rest = shown.replace("does not say whether the action ran", "")
    for absent in (" ran", "executed", "Requested by", "Agent", "Resource class"):
        assert absent not in rest, absent


@pytest.mark.parametrize("render", [render_slack, render_teams])
@pytest.mark.parametrize(
    ("outcome", "header"),
    [
        ("APPROVED", "EB-20 \u00b7 Isolate endpoint: approved"),
        ("REFUSED", "EB-20 \u00b7 Isolate endpoint: refused"),
        ("LAPSED", "EB-20 \u00b7 Isolate endpoint: lapsed without a decision"),
        ("WITHDRAWN", "EB-20 \u00b7 Isolate endpoint: closed without a decision"),
    ],
)
def test_ay9_each_outcome_has_its_header_and_one_link(render, outcome, header):
    body = json.loads(render(DELIVERY, closed_message(outcome=outcome)))
    if render is render_slack:
        assert body["blocks"][0]["text"]["text"] == header
        [actions] = [b for b in body["blocks"] if b["type"] == "actions"]
        assert [e["action_id"] for e in actions["elements"]] == ["open_approval"]
    else:
        card = body["attachments"][0]["content"]
        assert card["body"][0]["text"] == header
        assert [a["title"] for a in card["actions"]] == ["Open the approval"]


@pytest.mark.parametrize("render", [render_slack, render_teams])
def test_hostile_labels_are_reduced_before_rendering(render):
    hostile = named(
        action_label="<!channel> *Approve* [here](https://evil.example.net)",
        resource_class="<@U123> ws01.corp.example",
        environment="prod & <https://evil.example.net|click>",
        workspace="<!here> Acme\r\n*SOC* <https://evil.example.net|x>",
        space="Tier 1 <@U999> & `ops`",
    )
    shown = render(DELIVERY, hostile).decode()
    assert "<" not in shown and "!channel" not in shown and "[here]" not in shown
    assert "evil.example.net|" not in shown and "&" not in shown
    assert "!here" not in shown and "*SOC*" not in shown and "`" not in shown
    titles = dict(facts(render, hostile))
    assert titles["Workspace"] == "here Acme SOC https://evil.example.netx"
    assert titles["Space"] == "Tier 1 U999 ops"


def test_the_sender_maps_each_answer_to_a_result():
    with chat_fake() as fake, httpx.Client(trust_env=False, follow_redirects=False) as client:

        def send(kind):
            url = fake.slack_url if kind == "slack" else fake.teams_url
            return send_chat(kind, url, DELIVERY, approval(), client)

        assert send("slack") == DELIVERED
        assert send("teams") == DELIVERED
        fake.answer(200)
        assert send("teams") == DELIVERED
        fake.answer(429, **{"Retry-After": "7"})
        assert send("slack") == SendResult(False, "RECEIVER_RATE_LIMITED", 7)
        fake.answer(429)
        assert send("slack") == SendResult(False, "RECEIVER_RATE_LIMITED", 30)
        fake.answer(429, **{"Retry-After": "99999"})
        assert send("teams") == SendResult(False, "RECEIVER_RATE_LIMITED", 3600)
        fake.answer(429, **{"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})
        assert send("teams") == SendResult(False, "RECEIVER_RATE_LIMITED", 30)
        fake.answer(404)
        assert send("slack") == SendResult(False, "RECEIVER_REFUSED")
        fake.answer(500)
        assert send("teams") == SendResult(False, "RECEIVER_UNAVAILABLE")
        assert fake.refused == [] and len(fake.received) == 9
        closed = send_chat(
            "slack",
            f"http://127.0.0.1:{free_port()}/services/T/B/X",
            DELIVERY,
            approval(),
            client,
        )
        assert closed == SendResult(False, "RECEIVER_UNAVAILABLE")


# The drain, on real PostgreSQL.


def chatting(db, world, connector, *destinations):
    return Runtime(
        db,
        [connector],
        clock=world["clock"],
        keys=TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)}),
        approval_url="http://127.0.0.1/approvals",
        notifications=list(destinations),
    )


def chat_destination(world, kind, url, destination_id=None):
    return Destination(destination_id or kind, world["identity"].tenant_id, url, "", kind=kind)


def drain_chat(db, world, runtime, **kw):
    return deliver_pending(
        db,
        world["admin"],
        runtime.notifications,
        approval_url=runtime.approval_url or "",
        clock=world["clock"],
        **kw,
    )


def test_c1_an_approval_fans_out_to_slack_teams_and_a_webhook_once_each(
    db, world, admin_engine, connector, receiver
):
    with chat_fake() as fake:
        runtime = chatting(
            db,
            world,
            connector,
            chat_destination(world, "slack", fake.slack_url),
            chat_destination(world, "teams", fake.teams_url),
            webhook_destination(world, receiver, "hook"),
        )
        view = pending(runtime, world)
        label_agent(admin_engine, world)
        assert drain_chat(db, world, runtime) == {"delivered": 3, "failed": 0, "closed": 0}
        assert drain_chat(db, world, runtime)["delivered"] == 0
        assert sorted(kind for kind, _ in fake.received) == ["slack", "teams"]
        assert fake.refused == []
        for _, body in fake.received:
            assert f"http://127.0.0.1/approvals/{view.approval_id}" in json.dumps(body)
            assert "WS01" not in json.dumps(body)
            # The agent is named by its handle, never by the label an administrator gave it.
            dumped = json.dumps(body)
            assert AGENT_LABEL not in dumped and "script" not in dumped
            assert "Requested by" in dumped and "Agent " in dumped
    assert {r["state"] for r in rows(admin_engine, world["identity"].tenant_id)} == {"DELIVERED"}


def test_c2_a_429_reschedules_at_retry_after_and_counts_as_an_attempt(
    db, world, admin_engine, connector
):
    with chat_fake() as fake:
        runtime = chatting(db, world, connector, chat_destination(world, "slack", fake.slack_url))
        pending(runtime, world)
        fake.answer(429, **{"Retry-After": "7"})
        assert drain_chat(db, world, runtime)["delivered"] == 0
        [row] = rows(admin_engine, world["identity"].tenant_id)
        assert (row["state"], row["attempts"], row["last_error"]) == (
            "PENDING",
            1,
            "RECEIVER_RATE_LIMITED",
        )
        with admin_engine.begin() as conn:
            due = conn.execute(
                text("SELECT next_attempt_at FROM execbound.approval_notifications")
            ).scalar_one()
        assert due == world["clock"].now() + timedelta(seconds=7)
        world["clock"].value += timedelta(seconds=8)
        assert drain_chat(db, world, runtime)["delivered"] == 1


def test_c3_one_send_per_second_per_chat_destination(db, world, admin_engine, connector):
    waits = []
    with chat_fake() as fake:
        runtime = chatting(
            db,
            world,
            connector,
            chat_destination(world, "slack", fake.slack_url),
            chat_destination(world, "teams", fake.teams_url),
        )
        pending(runtime, world)
        for key in ("second", "third"):
            with admin_engine.begin() as conn:
                conn.execute(text("UPDATE execbound.executions SET state='DENIED'"))
            pending(runtime, world, idempotency_key=key)
        result = drain_chat(db, world, runtime, sleep=waits.append, monotonic=lambda: 100.0)
        assert result["delivered"] == 6 and len(fake.received) == 6
    # Two waits per destination: the second and third send to each waited a full second.
    assert waits == [1.0] * 4
