# SPDX-License-Identifier: AGPL-3.0-only
"""Notification transports: one identifier-only message, rendered once per destination kind.

The message links; nothing in a message decides. No kind renders an approve or refuse control,
because a mail recipient or a chat identity is not an ExecBound principal and a control in a
message would route authority around the session, CSRF and continuation model the approval
page enforces. A message carries identifiers, catalog labels, fact labels passed through
`safe_label`, the workspace and space names passed through `safe_label`, the requesting
agent's tenant-local handle ("Agent 3", never its label), the deadline to the second and the
fixed link to the approval's own page, never an agent, provider or request string. Every
recipient and URL comes from the private configuration.

Besides the `approval.pending` announcement, a destination that asks for them receives two
follow-ups (#678). An `approval.reminder` is the announcement again under its own kind, saying
the request is still waiting: the same facts, links and rules, and a webhook body that differs
from the announcement's only in `kind`. An `approval.closed` (`ClosedMessage`) says how the
approval ended and when, with the workspace and the same link. A close-out carries the same
rules and less: no target fact, no agent, no person, no control, and a fixed sentence that it
decides nothing and does not say whether the action ran. An email close-out threads under the
announcement it follows.
"""

import ipaddress
import json
import re
import smtplib
import ssl
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from email.message import EmailMessage
from email.utils import formatdate
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx

CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_FULL_TIME = "%Y-%m-%d %H:%M:%S UTC"
MAX_PAYLOAD_BYTES = 4096
# A bare address: no display name, no quoting, no comment, nothing a header could carry.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
EMAIL_ADDRESS = re.compile(rf"[A-Za-z0-9._%+-]{{1,64}}@{_LABEL}(?:\.{_LABEL})+")
_HOST = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
_USERNAME = re.compile(r"[\x21-\x7e]{1,256}")
_PASSWORD = re.compile(r"[\x20-\x7e]{1,512}")
MAIL_PORTS = frozenset({465, 587})
# Slack's app-created incoming webhooks; the URL is the secret.
SLACK_HOST = "hooks.slack.com"
# Power Automate Workflows triggers, the replacement for the Office 365 connectors retired
# in May 2026. The signature travels in the query (`sig=`), so this kind alone keeps one.
TEAMS_HOSTS = frozenset({"api.powerautomate.com", "api.powerplatform.com", "flow.microsoft.com"})
TEAMS_SUFFIX = ".logic.azure.com"
CHAT_KINDS = frozenset({"slack", "teams"})
RETRY_AFTER_DEFAULT = 30


def is_address(value: object) -> bool:
    return type(value) is str and len(value) <= 254 and EMAIL_ADDRESS.fullmatch(value) is not None


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class MailConfig:
    """The deployment's one SMTP relay; only the private configuration creates it.

    Implicit TLS (`tls`) or STARTTLS (`starttls`) on 465 or 587, never plaintext. A loopback
    host may use any port, which only the test double does, as a webhook may use `http` only
    on a loopback address.
    """

    host: str
    port: int
    tls: str
    username: str
    password: str = field(repr=False)
    sender: str
    daily_limit: int = 500
    weekly_summary: bool = False
    weekly_summary_daily_cap: int = 200

    def __post_init__(self) -> None:
        host_ok = type(self.host) is str and (
            is_loopback_host(self.host)
            or (len(self.host) <= 253 and _HOST.fullmatch(self.host) is not None)
        )
        if (
            not host_ok
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or (self.port not in MAIL_PORTS and not is_loopback_host(self.host))
            or self.tls not in {"tls", "starttls"}
            or type(self.username) is not str
            or not _USERNAME.fullmatch(self.username)
            or type(self.password) is not str
            or not _PASSWORD.fullmatch(self.password)
            or not is_address(self.sender)
            or type(self.daily_limit) is not int
            or not 1 <= self.daily_limit <= 100_000
            or type(self.weekly_summary) is not bool
            or type(self.weekly_summary_daily_cap) is not int
            or not 1 <= self.weekly_summary_daily_cap <= 100_000
        ):
            raise ValueError("Invalid mail configuration")


def _domain(mail: MailConfig) -> str:
    """The sender's domain, which is the only thing a `Message-ID` may be built from here."""
    return mail.sender.rsplit("@", 1)[1]


_NOT_LABEL = re.compile(r"[^A-Za-z0-9 ._:/()-]")
_SPACE = re.compile(r"\s+")
LABEL_LENGTH = 80


def safe_label(value: object) -> str:
    """A label a subject, a body, a block or a card may show.

    Letters, digits, space and ``._:/()-`` survive; whitespace collapses; anything else is
    dropped rather than escaped, so no transport has markup, mention or header syntax to
    interpret. Catalog labels pass through unchanged; fact values usually do.
    """
    if value is None:
        return "unknown"
    text = _SPACE.sub(" ", str(value))
    text = _SPACE.sub(" ", _NOT_LABEL.sub("", text)).strip()[:LABEL_LENGTH].strip()
    return text or "unknown"


# The kinds an `ApprovalMessage` is sent as: the announcement, and the same message again as a
# reminder. A close-out is its own `ClosedMessage`.
ANNOUNCEMENT_KINDS = ("approval.pending", "approval.reminder")


@dataclass(frozen=True)
class ApprovalMessage:
    """What every kind renders for one pending approval; built in the drain's lease."""

    tenant_id: UUID
    approval_id: UUID
    execution_id: UUID
    canonical_target_id: UUID
    action: str
    action_label: str
    resource_class: str | int | bool
    environment: str | int | bool | None
    expires_at: datetime
    assigned_approvers: int
    approval_url: str
    request_ref: str | None = None
    path: str | None = None
    # What a rendered message names besides the facts (#678). Each defaults, so
    # `webhook_body`, which reads none of them, keeps its documented bytes.
    workspace: str | None = None
    space: str | None = None
    requested_by: str | None = None
    # The drain's clock when the attempt was leased: the window is worded as of sending.
    sent_at: datetime | None = None
    kind: str = "approval.pending"
    # Approvals recorded and required, set only when more than one approver is required.
    recorded: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        if self.kind not in ANNOUNCEMENT_KINDS:
            raise ValueError("INVALID_NOTIFICATION")

    @property
    def reminder(self) -> bool:
        return self.kind == "approval.reminder"

    @property
    def link(self) -> str:
        """The console's approval address: a plugin's own path when it gives one."""
        if self.path is not None:
            return self.approval_url.removesuffix("/approvals") + self.path
        return f"{self.approval_url}/{self.approval_id}"

    @property
    def classic_link(self) -> str:
        """The server-rendered approval page, for a phone whose console does not load."""
        return f"{self.link}/classic"


# What a close-out says of each outcome: the subject's word, the chat header's, the sentence.
CLOSED_WORDS = {
    "APPROVED": ("Approved", "approved", "was approved at"),
    "REFUSED": ("Refused", "refused", "was refused at"),
    "LAPSED": (
        "Lapsed without a decision",
        "lapsed without a decision",
        "lapsed without a decision at",
    ),
    "WITHDRAWN": (
        "Closed without a decision",
        "closed without a decision",
        "closed without a decision by",
    ),
}
CLOSED_DISCLAIMER = (
    "This message decides nothing and does not say whether the action ran. "
    "The approval page has the record."
)


@dataclass(frozen=True)
class ClosedMessage:
    """How an announced approval ended, for a destination that lists `closed` (#678).

    Built in the drain's lease from the announcement's own reads. `outcome` and `closed_at`
    were fixed when the row was queued; `pending_delivery_id` is the announcement's delivery id,
    which an email close-out threads under, or None when the destination never received one.
    """

    tenant_id: UUID
    approval_id: UUID
    execution_id: UUID
    action: str
    action_label: str
    resource_class: str | int | bool
    outcome: str
    closed_at: datetime
    approval_url: str
    request_ref: str | None = None
    workspace: str | None = None
    path: str | None = None
    pending_delivery_id: UUID | None = None
    sent_at: datetime | None = None
    kind: str = "approval.closed"

    def __post_init__(self) -> None:
        if self.outcome not in CLOSED_WORDS:
            raise ValueError("INVALID_NOTIFICATION")

    @property
    def link(self) -> str:
        """The approval's own page, as the announcement linked it."""
        if self.path is not None:
            return self.approval_url.removesuffix("/approvals") + self.path
        return f"{self.approval_url}/{self.approval_id}"


def closed_at_words(message: ClosedMessage) -> str:
    """The close-out's time to the second: the time alone on the send's UTC day, else dated."""
    closed = message.closed_at.astimezone(UTC)
    if message.sent_at is not None and message.sent_at.astimezone(UTC).date() == closed.date():
        return closed.strftime("%H:%M:%S UTC")
    return closed.strftime(_FULL_TIME)


def closed_line(message: ClosedMessage) -> str:
    """`EB-20 was approved at 13:35:10 UTC.`, and the same for each outcome."""
    subject = safe_label(message.request_ref) if message.request_ref else "This request"
    return f"{subject} {CLOSED_WORDS[message.outcome][2]} {closed_at_words(message)}."


@dataclass(frozen=True)
class SendResult:
    """One attempt's outcome: delivered, or a code and an optional server-chosen delay."""

    delivered: bool
    code: str | None = None
    retry_after: int | None = None

    def __post_init__(self) -> None:
        if self.delivered != (self.code is None) or (
            self.code is not None and not CODE.fullmatch(self.code)
        ):
            raise ValueError("Invalid send result")
        if self.retry_after is not None and (
            type(self.retry_after) is not int or not 1 <= self.retry_after <= 3600
        ):
            raise ValueError("Invalid send result")


DELIVERED = SendResult(True)


def decide_by(message: ApprovalMessage) -> str:
    """The deadline to the second, as a subject or a first line gives it.

    The time alone when it falls on the same UTC day as the send, the full date otherwise
    (and whenever the send time is unknown).
    """
    expires = message.expires_at.astimezone(UTC)
    if message.sent_at is not None and message.sent_at.astimezone(UTC).date() == expires.date():
        return expires.strftime("%H:%M:%S UTC")
    return expires.strftime(_FULL_TIME)


def window_words(message: ApprovalMessage) -> str:
    """The time left as of sending, as a bare phrase: "About 4 minutes", never a fresh count.

    Callers leave the phrase out when `sent_at` is unset; it then reads as no time left.
    """
    if message.sent_at is None:
        return "Less than a minute"
    seconds = int((message.expires_at - message.sent_at).total_seconds())
    if seconds >= 120:
        return f"About {seconds // 60} minutes"
    if seconds >= 60:
        return "About 1 minute"
    return "Less than a minute"


def webhook_body(message: ApprovalMessage) -> bytes:
    """The signed webhook's documented JSON; its keys and bytes are a published contract.

    It carries the retained values as they are, as it always has; only the rendered kinds
    pass labels through `safe_label`. A reminder's body is the announcement's with
    `"kind":"approval.reminder"`, sent only to a destination whose operator listed `reminder`.
    """
    body = {
        "version": 1,
        "kind": message.kind,
        "tenant_id": str(message.tenant_id),
        "approval_id": str(message.approval_id),
        "execution_id": str(message.execution_id),
        "action": message.action,
        "resource_class": message.resource_class,
        "environment": message.environment,
        "canonical_target_id": str(message.canonical_target_id),
        "expires_at": message.expires_at.isoformat(),
        "assigned_approvers": message.assigned_approvers,
        "approval_url": message.approval_url,
    }
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValueError("INVALID_NOTIFICATION")
    return encoded


def closed_body(message: ClosedMessage) -> bytes:
    """A close-out's signed webhook JSON: the additive `approval.closed` kind, version 1.

    Only a destination whose operator listed `closed` receives it, so a receiver that never
    reads `kind` never sees one. `outcome` is lowercase; `approved` is not permission for the
    receiver to do anything, and nothing here says whether the action ran.
    """
    body = {
        "version": 1,
        "kind": "approval.closed",
        "tenant_id": str(message.tenant_id),
        "approval_id": str(message.approval_id),
        "execution_id": str(message.execution_id),
        "action": message.action,
        "outcome": message.outcome.lower(),
        "closed_at": message.closed_at.isoformat(),
        "approval_url": message.approval_url,
    }
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValueError("INVALID_NOTIFICATION")
    return encoded


def _tag(workspace: str | None, ref: str | None) -> str:
    return " \u00b7 ".join(part for part in ("ExecBound", workspace, ref) if part is not None)


def render_email(
    mail: MailConfig, to: str, delivery_id: UUID, message: ApprovalMessage | ClosedMessage
) -> EmailMessage:
    """The one `text/plain` message for an approval: fixed subject, fixed body, labels only.

    A close-out renders its own fixed copy (`_closed_email`); everything below is the
    announcement's, and a reminder's, which differs only in its subject and first line.

    The subject names the workspace, because request references are counted per workspace
    and two workspaces could otherwise send identical subjects. The `Message-ID` is derived
    from the delivery id, so a redelivery after an uncertain attempt collapses into the first
    in the recipient's mailbox.
    """
    if isinstance(message, ClosedMessage):
        return _closed_email(mail, to, delivery_id, message)
    action = safe_label(message.action_label)
    resource = safe_label(message.resource_class)
    workspace = None if message.workspace is None else safe_label(message.workspace)
    ref = safe_label(message.request_ref) if message.request_ref else None
    when = decide_by(message)
    email = EmailMessage()
    email["From"] = mail.sender
    email["To"] = to
    lead = "Still waiting, decide by" if message.reminder else "Decide by"
    email["Subject"] = f"[{_tag(workspace, ref)}] {lead} {when}: {action} on {resource}"
    email["Date"] = formatdate(usegmt=True)
    email["Message-ID"] = f"<{delivery_id}@{mail.sender.rsplit('@', 1)[1]}>"
    email["Auto-Submitted"] = "auto-generated"
    email["X-ExecBound-Delivery"] = str(delivery_id)
    email["X-ExecBound-Execution"] = str(message.execution_id)
    email["X-ExecBound-Approval"] = str(message.approval_id)
    lines = [
        ("Still waiting for a decision. " if message.reminder else "")
        + f"Decide by {when}"
        + ("." if workspace is None else f" in {workspace}.")
    ]
    if message.sent_at is not None:
        lines.append(f"{window_words(message)} to decide when this was sent.")
    lines += [
        "",
        f"Request: {ref or message.execution_id}",
        f"Action: {action}",
        f"Resource class: {resource}",
        f"Environment: {safe_label(message.environment)}",
    ]
    if message.space is not None:
        lines.append(f"Space: {safe_label(message.space)}")
    if message.requested_by is not None:
        lines.append(f"Requested by: {safe_label(message.requested_by)}")
    if message.recorded is not None:
        lines.append(f"Approvals recorded: {message.recorded[0]} of {message.recorded[1]}")
    lines += [
        f"Decide by: {message.expires_at.astimezone(UTC).strftime(_FULL_TIME)}",
        "",
        f"Open the approval: {message.link}",
        "",
        f"{BASIC_PAGE} {message.classic_link}",
        "",
        "This message decides nothing. Approve or refuse on the page, signed in as yourself. "
        "If the deadline passes, nothing runs.",
    ]
    if workspace is not None:
        lines.append(
            f"You receive this because this address is a notification destination for {workspace}."
        )
    lines.append("Sent automatically; replies are not read.")
    email.set_content("\n".join(lines) + "\n")
    return email


def _closed_email(
    mail: MailConfig, to: str, delivery_id: UUID, message: ClosedMessage
) -> EmailMessage:
    """A close-out: the outcome and its time, the disclaimer and the link, nothing else.

    It threads under the announcement (`In-Reply-To` and `References`) when the destination
    received one, so a mailbox shows the outcome beneath the request.
    """
    action = safe_label(message.action_label)
    resource = safe_label(message.resource_class)
    workspace = None if message.workspace is None else safe_label(message.workspace)
    ref = safe_label(message.request_ref) if message.request_ref else None
    email = EmailMessage()
    email["From"] = mail.sender
    email["To"] = to
    word = CLOSED_WORDS[message.outcome][0]
    email["Subject"] = f"[{_tag(workspace, ref)}] {word}: {action} on {resource}"
    email["Date"] = formatdate(usegmt=True)
    email["Message-ID"] = f"<{delivery_id}@{_domain(mail)}>"
    if message.pending_delivery_id is not None:
        parent = f"<{message.pending_delivery_id}@{_domain(mail)}>"
        email["In-Reply-To"] = parent
        email["References"] = parent
    email["Auto-Submitted"] = "auto-generated"
    email["X-ExecBound-Delivery"] = str(delivery_id)
    email["X-ExecBound-Execution"] = str(message.execution_id)
    email["X-ExecBound-Approval"] = str(message.approval_id)
    lines = [
        closed_line(message),
        "",
        CLOSED_DISCLAIMER,
        "",
        f"Open the approval: {message.link}",
        "",
        "Sent automatically; replies are not read.",
    ]
    email.set_content("\n".join(lines) + "\n")
    return email


def _deliver(
    mail: MailConfig,
    to: str,
    email: EmailMessage,
    *,
    context: ssl.SSLContext | None,
    timeout: float,
) -> SendResult:
    """One SMTP attempt over verified TLS; never plaintext, never a quoted error."""
    context = context or ssl.create_default_context()
    try:
        client = (
            smtplib.SMTP_SSL(mail.host, mail.port, timeout=timeout, context=context)
            if mail.tls == "tls"
            else smtplib.SMTP(mail.host, mail.port, timeout=timeout)
        )
        with client:
            if mail.tls == "starttls":
                try:
                    client.starttls(context=context)
                except smtplib.SMTPNotSupportedError:
                    # A relay that does not offer STARTTLS is never sent to in plaintext.
                    return SendResult(False, "TLS_UNAVAILABLE")
            client.login(mail.username, mail.password)
            client.send_message(email, from_addr=mail.sender, to_addrs=[to])
        return DELIVERED
    except ssl.SSLCertVerificationError:
        return SendResult(False, "TLS_UNVERIFIED")
    except smtplib.SMTPAuthenticationError:
        return SendResult(False, "MAIL_AUTH_FAILED")
    except smtplib.SMTPRecipientsRefused:
        return SendResult(False, "MAIL_REFUSED")
    except smtplib.SMTPResponseException as exc:
        return SendResult(
            False, "MAIL_REFUSED" if 500 <= exc.smtp_code < 600 else "RECEIVER_UNAVAILABLE"
        )
    except (smtplib.SMTPException, OSError):
        return SendResult(False, "RECEIVER_UNAVAILABLE")


def send_email(
    mail: MailConfig,
    to: str,
    delivery_id: UUID,
    message: ApprovalMessage | ClosedMessage,
    *,
    context: ssl.SSLContext | None = None,
    timeout: float = 10,
) -> SendResult:
    """One approval notification, of either kind, through the relay.

    `context` is the system trust store unless a caller passes one; the tests pass a context
    that trusts the CA they mint, so verification runs exactly as it does in production.
    """
    email = render_email(mail, to, delivery_id, message)
    return _deliver(mail, to, email, context=context, timeout=timeout)


_INVITE_LINK = re.compile(r"https?://[A-Za-z0-9.:\[\]-]{1,253}/join")
_INVITE_TOKEN = re.compile(r"ebt1\.[0-9a-f-]{36}\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}")


def render_teammate_invitation(
    mail: MailConfig,
    to: str,
    invitation_id: UUID,
    workspace: str,
    inviter: str | None,
    link: str,
    token: str,
    expires_at: datetime,
) -> EmailMessage:
    """The teammate `invitation` class: one recipient, a fixed template, and the link once.

    Workspace and inviter names are reduced through `safe_label`, never rendered raw: an
    administrator's own label or a workspace name is free text nobody else validated. The
    secret travels in the fragment, exactly as a signup verification link's does, so a browser
    never sends it to any server; the page that opens reads it with its own script. The
    `Message-ID` is fresh for every attempt because every attempt carries a fresh link.
    """
    if not _INVITE_LINK.fullmatch(link) or not _INVITE_TOKEN.fullmatch(token) or not is_address(to):
        raise ValueError("INVALID_TEAMMATE_INVITATION")
    workspace_label = safe_label(workspace)
    inviter_label = safe_label(inviter)
    expires = expires_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    email = EmailMessage()
    email["From"] = mail.sender
    email["To"] = to
    email["Subject"] = f"[ExecBound] {inviter_label} invited you to {workspace_label}"
    email["Date"] = formatdate(usegmt=True)
    email["Message-ID"] = f"<{uuid4()}@{_domain(mail)}>"
    email["Auto-Submitted"] = "auto-generated"
    email["X-ExecBound-Invitation"] = str(invitation_id)
    email.set_content(
        f"{inviter_label} invited you to join {workspace_label} on ExecBound.\n"
        "\n"
        f"Open this link:\n\n    {link}#{token}\n\n"
        f"It works until {expires} and only in the latest message we sent. If you did not "
        "expect this, ignore it: nothing changes until the link is opened and you choose to "
        "continue.\n"
        "\n"
        f"Invitation: {invitation_id}\n",
        cte="7bit",
    )
    return email


def send_teammate_invitation(
    mail: MailConfig,
    to: str,
    invitation_id: UUID,
    workspace: str,
    inviter: str | None,
    link: str,
    token: str,
    expires_at: datetime,
    *,
    context: ssl.SSLContext | None = None,
    timeout: float = 10,
) -> SendResult:
    """One teammate invitation through the relay."""
    email = render_teammate_invitation(
        mail, to, invitation_id, workspace, inviter, link, token, expires_at
    )
    return _deliver(mail, to, email, context=context, timeout=timeout)


# --- The weekly summary (#678): counts and fixed copy, one link, and its own unsubscribe ---

_SUMMARY_ORIGIN = re.compile(r"https?://[A-Za-z0-9.:\[\]-]{1,253}")
_SUMMARY_LINK = re.compile(
    r"https?://[A-Za-z0-9.:\[\]-]{1,253}/weekly-summary/unsubscribe/"
    r"ebw1\.[0-9a-f-]{36}\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}"
)


@dataclass(frozen=True)
class WeeklyCounts:
    """What one summary says: counts and nothing else. `None` is "not counted for you"."""

    requests: int
    executed: int
    refused_policy: int
    refused_limit: int
    refused_busy: int
    held: int
    approved: int
    refused_by_person: int
    lapsed: int
    waiting: int
    median_seconds_to_decide: int | None
    unsettled_now: int
    effect_unknown: int
    observed: int
    would_refuse: int
    would_refuse_by_limit: int
    would_hold: int
    would_run: int
    quiet_sources: int | None
    open_findings: int | None


def _minutes(seconds: int | None) -> str:
    if seconds is None:
        return "not available"
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{round(seconds / 60)} min"
    return f"{round(seconds / 360) / 10} h"


def render_weekly_summary(
    mail: MailConfig,
    to: str,
    workspace: str,
    counts: WeeklyCounts,
    previous: WeeklyCounts,
    week_ending: date,
    origin: str,
    link: str,
) -> EmailMessage:
    """The `weekly summary` class: one recipient, a fixed template of counts, one link.

    The workspace name is reduced through `safe_label`; nothing else in it is a string anybody
    but this template wrote, so it carries no agent, provider, target or person, no approval
    or execution identifier and no control. The unsubscribe link is the one-click address
    RFC 8058 asks for, in the `List-Unsubscribe` header and once in the body.
    """
    if (
        not is_address(to)
        or not _SUMMARY_ORIGIN.fullmatch(origin)
        or not _SUMMARY_LINK.fullmatch(link)
        or type(week_ending) is not date
    ):
        raise ValueError("INVALID_WEEKLY_SUMMARY")
    name = safe_label(workspace)
    day = week_ending.isoformat()
    email = EmailMessage()
    email["From"] = mail.sender
    email["To"] = to
    email["Subject"] = f"[ExecBound] Weekly summary for {name}: 7 days to {day}"
    email["Date"] = formatdate(usegmt=True)
    email["Message-ID"] = f"<{uuid4()}@{_domain(mail)}>"
    email["Auto-Submitted"] = "auto-generated"
    email["List-Unsubscribe"] = f"<{link}>"
    email["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    lines = [
        f"ExecBound in {name}, the 7 days to Monday {day} 00:00 UTC.",
        "",
        f"Requests made: {counts.requests} ({previous.requests} the week before)",
        f"Executed: {counts.executed}",
        f"Refused by policy or a failed check: {counts.refused_policy}",
        f"Refused by an impact limit: {counts.refused_limit}",
        f"Refused because another request held the target: {counts.refused_busy}",
        f"Held for a person: {counts.held} (approved {counts.approved}, refused "
        f"{counts.refused_by_person}, lapsed before a decision {counts.lapsed}, still waiting "
        f"{counts.waiting})",
        f"Median time to decide: {_minutes(counts.median_seconds_to_decide)}",
        f"Still unsettled: {counts.unsettled_now}",
        f"Effect unknown: {counts.effect_unknown}",
    ]
    if counts.quiet_sources is not None and counts.open_findings is not None:
        lines += [
            "",
            "Monitoring, as reported by sources (not enforced):",
            f"Sources quiet: {counts.quiet_sources}",
            f"Findings open: {counts.open_findings}",
        ]
    if counts.observed > 0:
        lines += [
            "",
            "Observe mode (nothing was enforced):",
            f"Would have refused: {counts.would_refuse} (by a limit: "
            f"{counts.would_refuse_by_limit}), held: {counts.would_hold}, run: "
            f"{counts.would_run}",
        ]
    lines += [
        "",
        "These are counts of what ExecBound recorded. A refusal is not proof that harm was "
        "prevented.",
        "",
        f"Open the console: {origin}/",
        f"If you belong to more than one workspace, choose {name}.",
        "",
        "You get this because you turned on the weekly summary in My account.",
        f"Stop it with one click: {link}",
    ]
    email.set_content("\n".join(lines) + "\n", cte="7bit")
    return email


def send_weekly_summary(
    mail: MailConfig,
    to: str,
    workspace: str,
    counts: WeeklyCounts,
    previous: WeeklyCounts,
    week_ending: date,
    origin: str,
    link: str,
    *,
    context: ssl.SSLContext | None = None,
    timeout: float = 10,
) -> SendResult:
    """One weekly summary through the relay."""
    email = render_weekly_summary(mail, to, workspace, counts, previous, week_ending, origin, link)
    return _deliver(mail, to, email, context=context, timeout=timeout)


def chat_url_ok(kind: str, url: object) -> bool:
    """Whether `url` is a destination the `slack` or `teams` kind may post to.

    The host is pinned, https is required, there is no userinfo, no fragment and no port
    but the default, and only a Teams URL keeps a query. A loopback host may use `http` and
    any port, which only the test fakes do. Retired Office 365 connector hosts are refused
    because they are not on the list.
    """
    if kind not in CHAT_KINDS or type(url) is not str or not url.isascii() or len(url) > 2048:
        return False
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    host = parsed.hostname or ""
    loopback = bool(host) and is_loopback_host(host)
    if (
        not host
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.scheme not in {"http", "https"}
        or (parsed.scheme == "http" and not loopback)
        or (port not in {None, 443} and not loopback)
    ):
        return False
    if kind == "slack":
        return (
            not parsed.query
            and parsed.path.startswith("/services/")
            and len(parsed.path) > len("/services/")
            and (loopback or host == SLACK_HOST)
        )
    return bool(parsed.query) and (
        loopback
        or host in TEAMS_HOSTS
        or (host.endswith(TEAMS_SUFFIX) and len(host) > len(TEAMS_SUFFIX))
    )


# The footer of every rendered approval notification: the classic page is the no-script
# fallback of the rebuilt console (#333),
# and a locked-down phone that blocks scripts still decides there.
BASIC_PAGE = "If the console does not load, use the basic page:"


def _facts(message: ApprovalMessage) -> list[tuple[str, str]]:
    """The facts, led by the deadline: at most nine, inside Slack's ten section fields."""
    facts = [("Decide by", message.expires_at.astimezone(UTC).strftime(_FULL_TIME))]
    if message.sent_at is not None:
        facts.append(("Time to decide", f"{window_words(message)} when sent"))
    if message.workspace is not None:
        facts.append(("Workspace", safe_label(message.workspace)))
    if message.space is not None:
        facts.append(("Space", safe_label(message.space)))
    facts += [
        ("Action", safe_label(message.action_label)),
        ("Resource class", safe_label(message.resource_class)),
        ("Environment", safe_label(message.environment)),
    ]
    if message.requested_by is not None:
        facts.append(("Requested by", safe_label(message.requested_by)))
    if message.recorded is not None:
        facts.append(("Approvals recorded", f"{message.recorded[0]} of {message.recorded[1]}"))
    return facts


def _needs(message: ApprovalMessage) -> str:
    return "still needs a decision" if message.reminder else "needs a decision"


def _header(message: ApprovalMessage) -> str:
    """`EB-20 · <action> needs a decision`, or `still needs` for a reminder; a message with no
    reference keeps the old header."""
    if not message.request_ref:
        return "Approval still needed" if message.reminder else "Approval needed"
    return (
        f"{safe_label(message.request_ref)} \u00b7 {safe_label(message.action_label)} "
        f"{_needs(message)}"
    )


def _summary(message: ApprovalMessage) -> str:
    """The one line a phone's notification shows: the header, the deadline and the workspace."""
    action = safe_label(message.action_label)
    lead = f"{safe_label(message.request_ref)} \u00b7 {action}" if message.request_ref else action
    workspace = "" if message.workspace is None else f" in {safe_label(message.workspace)}"
    return f"{lead} {_needs(message)} by {decide_by(message)}{workspace}"


def _identifiers(delivery_id: UUID, message: ApprovalMessage) -> str:
    if message.request_ref:
        return f"Request {safe_label(message.request_ref)}"
    return (
        f"Approval {message.approval_id} | Execution {message.execution_id} | "
        f"Delivery {delivery_id}"
    )


def _encode(body: object) -> bytes:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValueError("INVALID_NOTIFICATION")
    return encoded


def _plain(value: str) -> dict[str, object]:
    return {"type": "plain_text", "text": value, "emoji": False}


def _closed_header(message: ClosedMessage) -> str:
    """`EB-20 \u00b7 <action>: approved`, and the same for each outcome."""
    action = safe_label(message.action_label)
    lead = f"{safe_label(message.request_ref)} \u00b7 {action}" if message.request_ref else action
    return f"{lead}: {CLOSED_WORDS[message.outcome][1]}"


def _closed_facts(message: ClosedMessage) -> list[tuple[str, str]]:
    """Workspace, Outcome and At: what ended and when, and nothing about the target."""
    facts = []
    if message.workspace is not None:
        facts.append(("Workspace", safe_label(message.workspace)))
    facts += [
        ("Outcome", CLOSED_WORDS[message.outcome][0]),
        ("At", message.closed_at.astimezone(UTC).strftime(_FULL_TIME)),
    ]
    return facts


def _closed_identifiers(delivery_id: UUID, message: ClosedMessage) -> str:
    if message.request_ref:
        return f"Request {safe_label(message.request_ref)}"
    return (
        f"Approval {message.approval_id} | Execution {message.execution_id} | "
        f"Delivery {delivery_id}"
    )


def _closed_slack(delivery_id: UUID, message: ClosedMessage) -> bytes:
    """A close-out's blocks: the header, three facts and the one link; no basic-page button,
    because nothing is left to decide."""
    workspace = "" if message.workspace is None else f" in {safe_label(message.workspace)}"
    return _encode(
        {
            "text": f"{_closed_header(message)}{workspace}",
            "blocks": [
                {"type": "header", "text": _plain(_closed_header(message))},
                {
                    "type": "section",
                    "fields": [_plain(f"{t}: {v}") for t, v in _closed_facts(message)],
                },
                {"type": "section", "text": _plain(CLOSED_DISCLAIMER)},
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": _plain("Open the approval"),
                            "url": message.link,
                            "action_id": "open_approval",
                        }
                    ],
                },
                {
                    "type": "context",
                    "elements": [_plain(_closed_identifiers(delivery_id, message))],
                },
            ],
        }
    )


def _closed_teams(delivery_id: UUID, message: ClosedMessage) -> bytes:
    """The Adaptive Card that mirrors `_closed_slack`."""
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {
                "type": "TextBlock",
                "text": _closed_header(message),
                "weight": "Bolder",
                "size": "Medium",
                "wrap": True,
            },
            {
                "type": "FactSet",
                "facts": [{"title": t, "value": v} for t, v in _closed_facts(message)],
            },
            {"type": "TextBlock", "text": CLOSED_DISCLAIMER, "wrap": True},
            {
                "type": "TextBlock",
                "text": _closed_identifiers(delivery_id, message),
                "isSubtle": True,
                "size": "Small",
                "wrap": True,
            },
        ],
        "actions": [{"type": "Action.OpenUrl", "title": "Open the approval", "url": message.link}],
    }
    return _encode(
        {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": card,
                }
            ],
        }
    )


def render_slack(delivery_id: UUID, message: ApprovalMessage | ClosedMessage) -> bytes:
    """Block Kit for an incoming webhook: every text object `plain_text`, one link button.

    `plain_text` means Slack interprets no mention, link or formatting syntax; the labels
    have been reduced by `safe_label` besides. The button opens the approval's own page and
    decides nothing.
    """
    if isinstance(message, ClosedMessage):
        return _closed_slack(delivery_id, message)
    plain = _plain
    return _encode(
        {
            "text": _summary(message),
            "blocks": [
                {"type": "header", "text": plain(_header(message))},
                {
                    "type": "section",
                    "fields": [plain(f"{title}: {value}") for title, value in _facts(message)],
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": plain("Open the approval"),
                            "url": message.link,
                            "action_id": "open_approval",
                        },
                        {
                            "type": "button",
                            "text": plain("Use the basic page"),
                            "url": message.classic_link,
                            "action_id": "open_basic_page",
                        },
                    ],
                },
                {"type": "context", "elements": [plain(BASIC_PAGE[:-1] + ".")]},
                {"type": "context", "elements": [plain(_identifiers(delivery_id, message))]},
            ],
        }
    )


def render_teams(delivery_id: UUID, message: ApprovalMessage | ClosedMessage) -> bytes:
    """A Workflows `message` carrying one Adaptive Card that mirrors the Slack blocks."""
    if isinstance(message, ClosedMessage):
        return _closed_teams(delivery_id, message)
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {
                "type": "TextBlock",
                "text": _header(message),
                "weight": "Bolder",
                "size": "Medium",
                "wrap": True,
            },
            {
                "type": "FactSet",
                "facts": [{"title": title, "value": value} for title, value in _facts(message)],
            },
            {
                "type": "TextBlock",
                "text": BASIC_PAGE[:-1] + ".",
                "isSubtle": True,
                "size": "Small",
                "wrap": True,
            },
            {
                "type": "TextBlock",
                "text": _identifiers(delivery_id, message),
                "isSubtle": True,
                "size": "Small",
                "wrap": True,
            },
        ],
        "actions": [
            {"type": "Action.OpenUrl", "title": "Open the approval", "url": message.link},
            {"type": "Action.OpenUrl", "title": "Use the basic page", "url": message.classic_link},
        ],
    }
    return _encode(
        {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": card,
                }
            ],
        }
    )


def retry_after_seconds(value: str | None) -> int:
    """`Retry-After` in whole seconds, clamped to 1..3600; 30 when absent or a date."""
    try:
        seconds = int((value or "").strip())
    except ValueError:
        return RETRY_AFTER_DEFAULT
    return min(max(seconds, 1), 3600)


def send_chat(
    kind: str,
    url: str,
    delivery_id: UUID,
    message: ApprovalMessage | ClosedMessage,
    client: httpx.Client,
) -> SendResult:
    """One POST to a Slack or Teams webhook; reads only the status and `Retry-After`.

    Slack delivers on 200 and Teams on 200 or 202, since a Workflows trigger accepts the
    request and runs the flow afterwards. No exception text or response body leaves here,
    because an error could quote the URL, which is the secret.
    """
    body = (
        render_slack(delivery_id, message)
        if kind == "slack"
        else render_teams(delivery_id, message)
    )
    try:
        with client.stream(
            "POST",
            url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-ExecBound-Delivery": str(delivery_id),
            },
            follow_redirects=False,
            timeout=5,
        ) as response:
            status = response.status_code
            retry = response.headers.get("Retry-After")
    except httpx.HTTPError:
        return SendResult(False, "RECEIVER_UNAVAILABLE")
    if status == 200 or (kind == "teams" and status == 202):
        return DELIVERED
    if status == 429:
        return SendResult(False, "RECEIVER_RATE_LIMITED", retry_after_seconds(retry))
    if 400 <= status < 500:
        return SendResult(False, "RECEIVER_REFUSED")
    return SendResult(False, "RECEIVER_UNAVAILABLE")
