# SPDX-License-Identifier: AGPL-3.0-only
"""Email delivery of approval notifications (#179 phase 1), on real PostgreSQL.

The configuration rules, the SMTP transport against a local double with a CA the tests mint,
and the AN rules mirrored for the kind: queued with the approval, delivered once, backed off
and failed visibly, never sent for a closed approval, identifiers and labels only.
"""

import json
import os
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from conftest import assert_secret_free
from smtp_double import PASSWORD as RELAY_PASSWORD
from smtp_double import USERNAME as RELAY_USER
from smtp_double import free_port, relay
from sqlalchemy import text
from test_approval_notifications import destination as webhook_destination
from test_approval_notifications import pending, rows, widen
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_human_surface import credential
from test_monitoring_worker import receiver as receiver
from test_notification_transports import (
    APPROVAL,
    EXECUTION,
    NON_LATIN_SPACE,
    NON_LATIN_WORKSPACE,
)
from test_notification_transports import closed as closed_message
from test_notification_transports import message as approval
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider

from execbound import notifications
from execbound.cli import main
from execbound.db import Database
from execbound.execution import decide_approval
from execbound.execution.models import ExecutionError
from execbound.notifications import Destination, deliver_pending
from execbound.runtime import Runtime
from execbound.surfaces.configuration import load_runtime
from execbound.surfaces.names import principal_handle
from execbound.surfaces.tokens import TokenKeys
from execbound.transports import (
    DELIVERED,
    MailConfig,
    SendResult,
    render_email,
    safe_label,
    send_email,
)

PASSWORD = "re_" + "p" * 36
ADDRESS = "jane@example.com"
MAIL = {
    "host": "smtp.resend.com",
    "port": 465,
    "tls": "tls",
    "username": "resend",
    "password": PASSWORD,
    "from": "no-reply@notify.example.com",
}


def configuration(world, connector, notifications, mail=MAIL):
    config = connector.config
    value = {
        "origin": "http://127.0.0.1:8000",
        "active_key_id": "k1",
        "continuation_keys": {"k1": "11" * 32},
        "connectors": [
            {
                "tenant_id": str(world["identity"].tenant_id),
                "account_id": str(world["account"]),
                "origin": config.origin,
                "dispatch_token": config.dispatch_token,
                "control_token": config.control_token,
                "evidence_keys": {k: v.hex() for k, v in config.evidence_keys.items()},
            }
        ],
        "notifications": notifications,
    }
    if mail is not None:
        value["mail"] = mail
    return value


def email(world, **changes):
    return {
        "destination_id": "soc-email-jane",
        "tenant_id": str(world["identity"].tenant_id),
        "kind": "email",
        "to": ADDRESS,
    } | changes


def load(tmp_path, value):
    path = tmp_path / "private.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    engine = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        runtime, _ = load_runtime(path, engine)
    finally:
        engine.close()
    for item in runtime.connectors.values():
        item.close()
    return runtime


def test_an_email_destination_and_its_mail_block_load(tmp_path, world, connector):
    runtime = load(tmp_path, configuration(world, connector, [email(world)]))
    [destination] = runtime.notifications
    assert (destination.kind, destination.to, destination.url, destination.secret) == (
        "email",
        ADDRESS,
        "",
        "",
    )
    assert runtime.mail == MailConfig(
        host="smtp.resend.com",
        port=465,
        tls="tls",
        username="resend",
        password=PASSWORD,
        sender="no-reply@notify.example.com",
    )
    assert runtime.mail.daily_limit == 500
    assert PASSWORD not in repr(runtime.mail)


@pytest.mark.parametrize(
    ("notification", "mail"),
    [
        pytest.param({}, None, id="email-without-mail-block"),
        pytest.param({}, MAIL | {"port": 25}, id="port-25"),
        pytest.param({}, MAIL | {"tls": "none"}, id="plaintext"),
        pytest.param({}, MAIL | {"from": "Ops <ops@example.com>"}, id="display-name-sender"),
        pytest.param({}, MAIL | {"daily_limit": 0}, id="zero-cap"),
        pytest.param({}, MAIL | {"host": "smtp://smtp.resend.com"}, id="host-with-scheme"),
        pytest.param({"to": f"Jane <{ADDRESS}>"}, MAIL, id="display-name-recipient"),
        pytest.param({"to": ADDRESS + "\nBcc: x@example.net"}, MAIL, id="header-injection"),
        pytest.param(
            {"to": "j" * 64 + "@" + ".".join(["d" * 60] * 3) + ".example.com"},
            MAIL,
            id="too-long",
        ),
        pytest.param({"url": "https://alerts.example.net/hook"}, MAIL, id="email-with-url"),
        pytest.param({"secret": "s" * 40}, MAIL, id="email-with-secret"),
        pytest.param({"to": None}, MAIL, id="email-without-recipient"),
    ],
)
def test_invalid_email_configuration_refuses_without_quoting_it(
    tmp_path, world, connector, notification, mail
):
    value = configuration(world, connector, [email(world) | notification], mail=mail)
    with pytest.raises(ValueError) as refused:
        load(tmp_path, value)
    assert PASSWORD not in str(refused.value) and ADDRESS not in str(refused.value)


def test_a_webhook_destination_may_not_carry_a_recipient(tmp_path, world, connector):
    webhook = {
        "destination_id": "soc",
        "tenant_id": str(world["identity"].tenant_id),
        "kind": "webhook",
        "url": "https://alerts.example.net/hook",
        "secret": "s" * 40,
        "to": ADDRESS,
    }
    with pytest.raises(ValueError):
        load(tmp_path, configuration(world, connector, [webhook]))


def test_destination_rules_hold_without_the_configuration_file():
    tenant = uuid4()
    Destination("jane", tenant, "", "", kind="email", to=ADDRESS)
    for bad in (
        {"url": "https://alerts.example.net/hook"},
        {"secret": "s" * 40},
        {"to": None},
        {"to": "not an address"},
    ):
        values = {"url": "", "secret": "", "to": ADDRESS} | bad
        with pytest.raises(ValueError):
            Destination("jane", tenant, kind="email", **values)
    with pytest.raises(ValueError):
        Destination("soc", tenant, "https://alerts.example.net/hook", "s" * 40, to=ADDRESS)
    hook = Destination("soc", tenant, "https://alerts.example.net/hook/path", "s3cr3t" * 7)
    assert "hook/path" not in repr(hook) and "s3cr3t" not in repr(hook)


def test_the_runtime_refuses_email_destinations_without_mail(db, world, connector):
    destination = Destination("jane", world["identity"].tenant_id, "", "", kind="email", to=ADDRESS)
    with pytest.raises(ValueError):
        Runtime(db, [connector], notifications=[destination])
    mail = MailConfig("smtp.resend.com", 465, "tls", "resend", PASSWORD, "no-reply@example.com")
    assert Runtime(db, [connector], notifications=[destination], mail=mail).mail == mail


@pytest.mark.parametrize(
    "changes",
    [
        {"port": 2525},
        {"tls": "ssl"},
        {"username": ""},
        {"username": "has space"},
        {"password": ""},
        {"password": "line\nbreak"},
        {"sender": "no-reply"},
        {"daily_limit": 100001},
        {"host": "-bad.example.com"},
    ],
)
def test_mail_config_rules(changes):
    values = {
        "host": "smtp.resend.com",
        "port": 587,
        "tls": "starttls",
        "username": "resend",
        "password": PASSWORD,
        "sender": "no-reply@notify.example.com",
    }
    MailConfig(**values)
    with pytest.raises(ValueError):
        MailConfig(**(values | changes))


def test_a_loopback_relay_may_use_any_port():
    MailConfig("localhost", 2525, "tls", "user", "pw", "no-reply@example.com")
    MailConfig("127.0.0.1", 2525, "starttls", "user", "pw", "no-reply@example.com")


SENDER = "no-reply@notify.example.com"
DELIVERY = UUID("00000000-0000-4000-8000-00000000000d")


def relay_mail(port, tls="tls", password=RELAY_PASSWORD, **changes):
    return MailConfig("localhost", port, tls, RELAY_USER, password, SENDER, **changes)


def named(**changes):
    """The documented example: a workspace, a space, an agent's handle and a send time."""
    values = {
        "request_ref": "EB-20",
        "workspace": "Synthetic SOC",
        "space": "Default",
        "requested_by": "Agent 3",
        "sent_at": datetime(2026, 9, 18, 3, 24, tzinfo=UTC),
    }
    return approval(**(values | changes))


def test_the_rendered_email_is_plain_text_with_fixed_headers_and_labels_only():
    rendered = render_email(relay_mail(2525), ADDRESS, DELIVERY, named())
    assert rendered.get_content_type() == "text/plain" and not rendered.is_multipart()
    assert rendered["From"] == SENDER and rendered["To"] == ADDRESS
    assert rendered["Subject"] == (
        "[ExecBound \u00b7 Synthetic SOC \u00b7 EB-20] "
        "Decide by 03:28:00 UTC: Isolate endpoint on workstation"
    )
    assert rendered["Auto-Submitted"] == "auto-generated"
    assert rendered["X-ExecBound-Delivery"] == str(DELIVERY)
    assert rendered["X-ExecBound-Execution"] == str(EXECUTION)
    assert rendered["X-ExecBound-Approval"] == str(APPROVAL)
    assert rendered["Message-ID"] == f"<{DELIVERY}@notify.example.com>"
    body = rendered.get_content()
    assert body.isascii()
    assert body == (
        "Decide by 03:28:00 UTC in Synthetic SOC.\n"
        "About 4 minutes to decide when this was sent.\n"
        "\n"
        "Request: EB-20\n"
        "Action: Isolate endpoint\n"
        "Resource class: workstation\n"
        "Environment: production\n"
        "Space: Default\n"
        "Requested by: Agent 3\n"
        "Decide by: 2026-09-18 03:28:00 UTC\n"
        "\n"
        f"Open the approval: https://app.example.net/approvals/{APPROVAL}\n"
        "\n"
        "If the console does not load, use the basic page: "
        f"https://app.example.net/approvals/{APPROVAL}/classic\n"
        "\n"
        "This message decides nothing. Approve or refuse on the page, signed in as yourself. "
        "If the deadline passes, nothing runs.\n"
        "You receive this because this address is a notification destination for "
        "Synthetic SOC.\n"
        "Sent automatically; replies are not read.\n"
    )
    for shown in (rendered["Subject"], body):
        assert_secret_free(shown)
        assert "<" not in shown


def test_an_unnamed_message_keeps_the_plain_subject_and_the_execution_reference():
    # A message built without the drain's names: no workspace in the tag, the execution id as
    # the reference, the deadline dated in full and no relative window.
    rendered = render_email(relay_mail(2525), ADDRESS, DELIVERY, approval())
    assert rendered["Subject"] == (
        "[ExecBound] Decide by 2026-09-18 03:28:00 UTC: Isolate endpoint on workstation"
    )
    body = rendered.get_content()
    assert body.startswith("Decide by 2026-09-18 03:28:00 UTC.\n\nRequest: ")
    assert f"Request: {EXECUTION}" in body
    for absent in ("to decide when this was sent", "Space:", "Requested by:", "You receive"):
        assert absent not in body


@pytest.mark.parametrize("kind", ["approval.pending", "approval.reminder", "approval.closed"])
def test_ay6_a_name_nothing_of_which_survives_is_left_out_not_called_unknown(kind):
    """A workspace or Space name in a script `safe_label` drops would read "unknown": the
    subject's tag and the first line leave the workspace out, the Space line is not written,
    and the last sentence still says why the address receives the message."""
    message = (
        closed_message(workspace=NON_LATIN_WORKSPACE)
        if kind == "approval.closed"
        else named(workspace=NON_LATIN_WORKSPACE, space=NON_LATIN_SPACE, kind=kind)
    )
    rendered = render_email(relay_mail(2525), ADDRESS, DELIVERY, message)
    subject, body = str(rendered["Subject"]), rendered.get_content()
    assert "unknown" not in subject + body
    if kind == "approval.closed":
        assert subject == "[ExecBound \u00b7 EB-20] Approved: Isolate endpoint on workstation"
        return
    lead = "Still waiting, decide by" if kind == "approval.reminder" else "Decide by"
    assert subject == (
        f"[ExecBound \u00b7 EB-20] {lead} 03:28:00 UTC: Isolate endpoint on workstation"
    )
    lines = body.splitlines()
    assert lines[0].endswith("Decide by 03:28:00 UTC.")
    assert not any(line.startswith(("Workspace:", "Space:")) for line in lines)
    assert "You receive this because this address is a notification destination." in lines


def test_ay6_hostile_workspace_and_space_names_never_reach_a_header():
    hostile = named(
        workspace="Acme\r\nBcc: x@evil.test <b>",
        space='Tier 1 "SOC"',
        requested_by="Agent 7",
        recorded=(0, 2),
        sent_at=datetime(2026, 9, 18, 3, 18, tzinfo=UTC),
    )
    rendered = render_email(relay_mail(2525), ADDRESS, DELIVERY, hostile)
    assert rendered["Subject"] == (
        "[ExecBound \u00b7 Acme Bcc: xevil.test b \u00b7 EB-20] "
        "Decide by 03:28:00 UTC: Isolate endpoint on workstation"
    )
    assert rendered.get_all("Subject") == [rendered["Subject"]]
    assert rendered["Bcc"] is None and rendered.get_all("Bcc") is None
    headers = rendered.as_bytes().split(b"\n\n", 1)[0]
    assert b"\nBcc:" not in headers and b"\rBcc:" not in headers
    body = rendered.get_content()
    for shown in (rendered["Subject"], body):
        assert "<" not in shown and "@" not in shown and '"' not in shown
    for line in (
        "Decide by 03:28:00 UTC in Acme Bcc: xevil.test b.",
        "About 10 minutes to decide when this was sent.",
        "Space: Tier 1 SOC",
        "Requested by: Agent 7",
        "Approvals recorded: 0 of 2",
        "Decide by: 2026-09-18 03:28:00 UTC",
        "Approve or refuse on the page",
    ):
        assert line in body
    # The quorum line follows Requested by; the page's own verb is Refuse, never deny.
    assert body.index("Requested by:") < body.index("Approvals recorded:")
    assert "deny" not in body.lower()


@pytest.mark.parametrize("mode", ["tls", "starttls"])
def test_delivery_over_verified_tls(tmp_path, mode):
    with relay(tmp_path, mode) as local:
        result = send_email(
            relay_mail(local.port, mode), ADDRESS, DELIVERY, approval(), context=local.context
        )
        assert result == DELIVERED
        assert local.envelopes == [(SENDER, [ADDRESS])]
        [received] = local.messages()
        assert received["Message-ID"] == f"<{DELIVERY}@notify.example.com>"
        assert f"/approvals/{APPROVAL}" in received.get_content()


@pytest.mark.parametrize("mode", ["tls", "starttls"])
def test_an_unverified_certificate_is_never_sent_to(tmp_path, mode):
    with relay(tmp_path, mode) as local:
        # No context: the system trust store, which does not trust the test CA.
        result = send_email(relay_mail(local.port, mode), ADDRESS, DELIVERY, approval())
        assert result == SendResult(False, "TLS_UNVERIFIED") and local.raw == []


def test_a_relay_without_starttls_is_never_sent_to_in_plaintext(tmp_path):
    with relay(tmp_path, "plain") as local:
        result = send_email(
            relay_mail(local.port, "starttls"), ADDRESS, DELIVERY, approval(), context=local.context
        )
        assert result == SendResult(False, "TLS_UNAVAILABLE") and local.raw == []


def test_refusals_map_to_codes(tmp_path):
    with relay(tmp_path, "tls", refuse=(ADDRESS,)) as local:
        wrong = send_email(
            relay_mail(local.port, password="wrong-password"),
            ADDRESS,
            DELIVERY,
            approval(),
            context=local.context,
        )
        refused = send_email(
            relay_mail(local.port), ADDRESS, DELIVERY, approval(), context=local.context
        )
        assert wrong == SendResult(False, "MAIL_AUTH_FAILED")
        assert refused == SendResult(False, "MAIL_REFUSED") and local.raw == []
    closed = send_email(relay_mail(free_port()), ADDRESS, DELIVERY, approval(), timeout=2)
    assert closed == SendResult(False, "RECEIVER_UNAVAILABLE")


# The drain: AN1 to AN12 mirrored for the email kind, on real PostgreSQL with the relay.


# Reminders (#678): the announcement again, saying it is still waiting.


def test_ay10_a_reminder_email_says_the_request_is_still_waiting():
    reminder = render_email(relay_mail(2525), ADDRESS, DELIVERY, named(kind="approval.reminder"))
    announcement = render_email(relay_mail(2525), ADDRESS, DELIVERY, named())
    assert reminder["Subject"] == (
        "[ExecBound \u00b7 Synthetic SOC \u00b7 EB-20] "
        "Still waiting, decide by 03:28:00 UTC: Isolate endpoint on workstation"
    )
    body = reminder.get_content()
    assert body.isascii()
    first, rest = body.split("\n", 1)
    assert first == "Still waiting for a decision. Decide by 03:28:00 UTC in Synthetic SOC."
    # Everything after the first line is the announcement's: the window as of sending, the
    # facts, both links, the routing line and no control.
    assert rest == announcement.get_content().split("\n", 1)[1]
    assert rest.startswith("About 4 minutes to decide when this was sent.\n")
    for header in ("Message-ID", "Auto-Submitted", "X-ExecBound-Delivery", "X-ExecBound-Approval"):
        assert reminder[header] == announcement[header]
    assert reminder["In-Reply-To"] is None
    for shown in (reminder["Subject"], body):
        assert_secret_free(shown)
        assert "<" not in shown


def test_ay10_an_unnamed_reminder_dates_its_deadline_in_full():
    rendered = render_email(relay_mail(2525), ADDRESS, DELIVERY, approval(kind="approval.reminder"))
    assert rendered["Subject"] == (
        "[ExecBound] Still waiting, decide by 2026-09-18 03:28:00 UTC: "
        "Isolate endpoint on workstation"
    )
    assert rendered.get_content().startswith(
        "Still waiting for a decision. Decide by 2026-09-18 03:28:00 UTC.\n\nRequest: "
    )


# Close-outs (#678): the outcome, its time, the disclaimer and the link, threaded under
# the announcement.
CLOSED_SUBJECTS = {
    "APPROVED": "Approved",
    "REFUSED": "Refused",
    "LAPSED": "Lapsed without a decision",
    "WITHDRAWN": "Closed without a decision",
}
CLOSED_LINES = {
    "APPROVED": "EB-20 was approved at 03:25:10 UTC.",
    "REFUSED": "EB-20 was refused at 03:25:10 UTC.",
    "LAPSED": "EB-20 lapsed without a decision at 03:25:10 UTC.",
    "WITHDRAWN": "EB-20 closed without a decision by 03:25:10 UTC.",
}


@pytest.mark.parametrize("outcome", sorted(CLOSED_SUBJECTS))
def test_ay9_each_close_out_email_says_how_the_approval_ended_and_nothing_more(outcome):
    rendered = render_email(relay_mail(2525), ADDRESS, DELIVERY, closed_message(outcome=outcome))
    assert rendered.get_content_type() == "text/plain" and not rendered.is_multipart()
    assert rendered["Subject"] == (
        f"[ExecBound \u00b7 Synthetic SOC \u00b7 EB-20] {CLOSED_SUBJECTS[outcome]}: "
        "Isolate endpoint on workstation"
    )
    parent = "<00000000-0000-4000-8000-00000000000e@notify.example.com>"
    assert rendered["In-Reply-To"] == parent and rendered["References"] == parent
    assert rendered["Message-ID"] == f"<{DELIVERY}@notify.example.com>"
    assert rendered["Auto-Submitted"] == "auto-generated"
    assert rendered["X-ExecBound-Approval"] == str(APPROVAL)
    body = rendered.get_content()
    assert body.isascii()
    assert body == (
        f"{CLOSED_LINES[outcome]}\n"
        "\n"
        "This message decides nothing and does not say whether the action ran. "
        "The approval page has the record.\n"
        "\n"
        f"Open the approval: https://app.example.net/approvals/{APPROVAL}\n"
        "\n"
        "Sent automatically; replies are not read.\n"
    )
    # Beyond the fixed disclaimer, nothing says or implies that anything ran, and no control,
    # person or target is named.
    rest = body.replace("does not say whether the action ran", "")
    for shown in (rendered["Subject"], rest):
        assert_secret_free(shown)
        for absent in (" ran", "executed", "Agent", "Requested by", "basic page", "<"):
            assert absent not in shown, absent


def test_ay9_a_close_out_without_an_announcement_starts_its_own_thread():
    rendered = render_email(
        relay_mail(2525),
        ADDRESS,
        DELIVERY,
        closed_message(pending_delivery_id=None, request_ref=None, sent_at=None),
    )
    assert rendered["In-Reply-To"] is None and rendered["References"] is None
    assert rendered["Subject"] == (
        "[ExecBound \u00b7 Synthetic SOC] Approved: Isolate endpoint on workstation"
    )
    assert rendered.get_content().startswith(
        "This request was approved at 2026-09-18 03:25:10 UTC.\n"
    )


def jane(world, approvers=None, destination_id="jane"):
    return Destination(
        destination_id,
        world["identity"].tenant_id,
        "",
        "",
        frozenset(approvers) if approvers is not None else None,
        kind="email",
        to=ADDRESS,
    )


def emailing(db, world, connector, mail, *destinations):
    return Runtime(
        db,
        [connector],
        clock=world["clock"],
        keys=TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)}),
        approval_url="http://127.0.0.1/approvals",
        notifications=list(destinations),
        mail=mail,
    )


def drain_email(db, world, runtime, context=None, **kw):
    return deliver_pending(
        db,
        world["admin"],
        runtime.notifications,
        approval_url=runtime.approval_url or "",
        clock=world["clock"],
        mail=runtime.mail,
        tls_context=context,
        **kw,
    )


def test_e1_email_rows_are_queued_with_the_approval_beside_webhooks(
    db, world, admin_engine, connector, receiver
):
    mail = relay_mail(2525)
    runtime = emailing(
        db,
        world,
        connector,
        mail,
        webhook_destination(world, receiver, "everyone"),
        jane(world, [world["human"].principal_id]),
        jane(world, [world["admin"].principal_id], "nobody"),
    )
    view = pending(runtime, world)
    queued = rows(admin_engine, world["identity"].tenant_id)
    assert [(r["destination_id"], r["state"]) for r in queued] == [
        ("everyone", "PENDING"),
        ("jane", "PENDING"),
    ]
    assert {r["approval_id"] for r in queued} == {view.approval_id}


AGENT_LABEL = "<script>alert(1)</script>"


def names(admin_engine, world, execution_id):
    """The seeded workspace, the execution's space and the agent's handle, read as stored."""
    with admin_engine.begin() as conn:
        found = (
            conn.execute(
                text(
                    "SELECT t.name AS workspace, s.name AS space, p.number "
                    "FROM execbound.executions e "
                    "JOIN execbound.tenants t ON t.tenant_id=e.tenant_id "
                    "JOIN execbound.spaces s ON s.tenant_id=e.tenant_id AND s.space_id=e.space_id "
                    "JOIN execbound.principals p "
                    "  ON p.tenant_id=e.tenant_id AND p.principal_id=e.principal_id "
                    "WHERE e.execution_id=:e"
                ),
                {"e": execution_id},
            )
            .mappings()
            .one()
        )
    handle = principal_handle("AGENT", found["number"], world["identity"].principal_id)
    return found["workspace"], found["space"], handle


def label_agent(admin_engine, world, label=AGENT_LABEL):
    """An administrator's label on the requesting agent, which no message may show."""
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label=:l WHERE principal_id=:p"),
            {"l": label, "p": world["identity"].principal_id},
        )


def test_e2_the_drain_emails_once_with_the_documented_rendering(
    db, world, admin_engine, connector, tmp_path
):
    with relay(tmp_path, "tls") as local:
        runtime = emailing(db, world, connector, relay_mail(local.port), jane(world))
        view = pending(runtime, world)
        label_agent(admin_engine, world)
        world["clock"].value += timedelta(seconds=30)
        assert drain_email(db, world, runtime, local.context) == {
            "delivered": 1,
            "failed": 0,
            "closed": 0,
        }
        assert drain_email(db, world, runtime, local.context)["delivered"] == 0
        [received] = local.messages()
    [row] = rows(admin_engine, world["identity"].tenant_id)
    assert (row["state"], row["attempts"], row["last_error"]) == ("DELIVERED", 1, None)
    workspace, space, handle = names(admin_engine, world, view.execution_id)
    assert handle.startswith("Agent ") and handle[len("Agent ") :].isdigit()
    with admin_engine.begin() as conn:
        expires = conn.execute(
            text("SELECT expires_at FROM execbound.approvals WHERE approval_id=:a"),
            {"a": view.approval_id},
        ).scalar_one()
    when = expires.astimezone(UTC)
    sent = world["clock"].now().astimezone(UTC)
    short = when.strftime("%H:%M:%S" if sent.date() == when.date() else "%Y-%m-%d %H:%M:%S")
    assert received["To"] == ADDRESS
    assert received["Message-ID"] == f"<{row['notification_id']}@notify.example.com>"
    tag = f"[ExecBound \u00b7 {safe_label(workspace)} \u00b7 {view.request_ref}]"
    assert str(received["Subject"]).startswith(f"{tag} Decide by {short} UTC: ")
    body = received.get_content().replace("\r\n", "\n")
    assert f"Open the approval: http://127.0.0.1/approvals/{view.approval_id}" in body
    assert f"use the basic page: http://127.0.0.1/approvals/{view.approval_id}/classic" in body
    assert f"Request: {view.request_ref}" in body
    # Sent 30 s into the 120 s window: the window is worded as of sending.
    assert "About 1 minute to decide when this was sent." in body
    assert f"Space: {safe_label(space)}" in body
    assert f"Requested by: {handle}\n" in body
    assert f"Decide by: {when.strftime('%Y-%m-%d %H:%M:%S')} UTC" in body
    assert f"notification destination for {safe_label(workspace)}." in body
    assert "Approvals recorded" not in body
    assert received["X-ExecBound-Approval"] == str(view.approval_id)
    assert "Delivery:" not in body and "Execution:" not in body
    assert received["X-ExecBound-Delivery"] == str(row["notification_id"])
    for shown in (str(received["Subject"]), body):
        assert_secret_free(shown)
        assert "WS01" not in shown and "<" not in shown
        assert "script" not in shown and "alert" not in shown


@pytest.mark.parametrize(
    ("window", "attempts"),
    [
        # Facts valid for hours and the deadline off: every attempt fits, up to MAX_ATTEMPTS.
        pytest.param(7200, 5, id="long-window"),
        # The default 120 s deadline: the third retry would land past it (#678, AY4).
        pytest.param(None, 3, id="default-window"),
    ],
)
def test_e3_failures_back_off_and_fail_visibly_with_the_transport_code(
    db, world, admin_engine, connector, live_provider, monkeypatch, window, attempts
):
    tenant = world["identity"].tenant_id
    runtime = emailing(db, world, connector, relay_mail(2525), jane(world))
    view = pending(runtime, world)
    if window is not None:
        widen(admin_engine, view.approval_id, window)
    monkeypatch.setattr(
        notifications, "send_email", lambda *a, **k: SendResult(False, "MAIL_REFUSED")
    )
    assert drain_email(db, world, runtime)["delivered"] == 0
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["attempts"], row["last_error"]) == ("PENDING", 1, "MAIL_REFUSED")
    # Backoff: nothing is due until the next attempt time passes.
    assert drain_email(db, world, runtime) == {"delivered": 0, "failed": 0, "closed": 0}
    for _ in range(4):
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.approval_notifications SET next_attempt_at=:now"),
                {"now": world["clock"].now()},
            )
        drain_email(db, world, runtime)
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["attempts"], row["last_error"]) == (
        "FAILED",
        attempts,
        "MAIL_REFUSED",
    )
    if window is not None:
        # Put back the window admission gave it: the plan it was frozen with expires first.
        widen(admin_engine, view.approval_id, 120)
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    done = runtime.execute(world["identity"], request(world).model_dump_json().encode())
    assert done.state == "EXECUTED"


def test_e4_a_closed_approval_is_never_emailed(db, world, admin_engine, connector, monkeypatch):
    runtime = emailing(db, world, connector, relay_mail(2525), jane(world))
    view = pending(runtime, world)
    decide_approval(db, world["human"], view.approval_id, "DENY", world["clock"])
    monkeypatch.setattr(notifications, "send_email", lambda *a, **k: pytest.fail("sent"))
    assert drain_email(db, world, runtime)["closed"] == 1
    [row] = rows(admin_engine, world["identity"].tenant_id)
    assert (row["state"], row["last_error"]) == ("FAILED", "APPROVAL_CLOSED")


def test_e5_concurrent_drains_email_once(db, world, admin_engine, connector, monkeypatch):
    runtime = emailing(db, world, connector, relay_mail(2525), jane(world))
    pending(runtime, world)
    sent = []
    monkeypatch.setattr(
        notifications,
        "send_email",
        lambda mail, to, delivery_id, *a, **k: sent.append(delivery_id) or DELIVERED,
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: drain_email(db, world, runtime), range(2)))
    assert len(sent) == 1
    assert {r["state"] for r in rows(admin_engine, world["identity"].tenant_id)} == {"DELIVERED"}


@pytest.mark.parametrize("long", [True, False], ids=["long-window", "default-window"])
def test_e6_the_daily_cap_defers_a_long_window_and_fails_a_short_one(
    db, world, admin_engine, connector, tmp_path, long
):
    tenant = world["identity"].tenant_id
    with relay(tmp_path, "tls") as local:
        runtime = emailing(db, world, connector, relay_mail(local.port, daily_limit=1), jane(world))
        pending(runtime, world)
        assert drain_email(db, world, runtime, local.context)["delivered"] == 1
        with admin_engine.begin() as conn:
            conn.execute(text("UPDATE execbound.executions SET state='DENIED'"))
        second = pending(runtime, world, idempotency_key="second")
        if long:
            # Deadline off and facts valid two hours: the hour's deferral still arrives in time.
            widen(admin_engine, second.approval_id, 7200)
        assert drain_email(db, world, runtime, local.context) == {
            "delivered": 0,
            "failed": 0 if long else 1,
            "closed": 0,
        }
        assert len(local.raw) == 1
    queued = rows(admin_engine, tenant)
    capped = ("PENDING", 0, "RATE_LIMITED") if long else ("FAILED", 0, "RATE_LIMITED")
    assert sorted((r["state"], r["attempts"], r["last_error"]) for r in queued) == sorted(
        [("DELIVERED", 1, None), capped]
    )
    if long:
        with admin_engine.begin() as conn:
            deferred = conn.execute(
                text(
                    "SELECT next_attempt_at FROM execbound.approval_notifications "
                    "WHERE state='PENDING'"
                )
            ).scalar_one()
        assert deferred == world["clock"].now() + timedelta(hours=1)


def test_e7_a_drain_without_the_mail_block_refuses_before_leasing(
    db, world, admin_engine, connector
):
    runtime = emailing(db, world, connector, relay_mail(2525), jane(world))
    pending(runtime, world)
    with pytest.raises(ExecutionError) as refused:
        deliver_pending(db, world["admin"], runtime.notifications, clock=world["clock"])
    assert refused.value.code == "INVALID_CONFIGURATION"
    [row] = rows(admin_engine, world["identity"].tenant_id)
    assert (row["state"], row["attempts"]) == ("PENDING", 0)


def test_e8_the_notify_command_hands_the_mail_block_to_the_drain(
    tmp_path, world, admin_engine, connector, monkeypatch, capsys
):
    config = tmp_path / "private.json"
    config.write_text(json.dumps(configuration(world, connector, [email(world)])), encoding="utf-8")
    admin_file = tmp_path / "admin.token"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(config))
    seen = {}

    def fake(db, identity, destinations, **kw):
        seen.update(kw, destinations=destinations)
        return {"delivered": 0, "failed": 0, "closed": 0}

    monkeypatch.setattr(notifications, "deliver_pending", fake)
    tenant = str(world["identity"].tenant_id)
    command = ["execbound", "notify", "--tenant", tenant, "--credential-file", str(admin_file)]
    monkeypatch.setattr(sys, "argv", command)
    main()
    assert json.loads(capsys.readouterr().out) == {"delivered": 0, "failed": 0, "closed": 0}
    assert seen["mail"] == MailConfig(
        host="smtp.resend.com",
        port=465,
        tls="tls",
        username="resend",
        password=PASSWORD,
        sender="no-reply@notify.example.com",
    )
    assert [d.kind for d in seen["destinations"]] == ["email"]
    # No plugin named in the private configuration, so no approval-links point to read: the
    # drain gets no path builder and falls back to the plain `/approvals/{id}` address. The
    # plugin's own tests hold the counterpart with its approval links loaded.
    assert seen["approval_path"] is None
