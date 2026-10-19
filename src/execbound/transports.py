# SPDX-License-Identifier: AGPL-3.0-only
"""Notification transports: one identifier-only message, rendered once per destination kind.

The message links; nothing in a message decides. No kind renders an approve or refuse control,
because a mail recipient or a chat identity is not an ExecBound principal and a control in a
message would route authority around the session, CSRF and continuation model the approval
page enforces. A message carries identifiers, catalog labels, fact labels passed through
`safe_label`, the workspace and space names passed through `name_label`, the requesting
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

A finding message (#31) is the third: the rule's fixed label, the finding's identifiers, when it
was raised, the workspace and Space names reduced by `name_label` and the console's link to the
finding, with a fixed sentence that monitoring is not enforcement. It carries nothing a source,
a provider or a person wrote.

A name `name_label` keeps nothing of, such as one written in a non-Latin script, is left out
of a message rather than shown as "unknown", and `choose_workspace` names the tenant id when
the label is not the name as written. A name a chat target could format, such as `_x_`,
`:smile:` or `example.com`, travels only where the target shows text as written: Slack's
`plain_text` blocks and Teams' text runs. Neither target offers an escape for all of these,
so nothing is escaped.
"""

import ipaddress
import json
import math
import re
import smtplib
import ssl
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from email.message import EmailMessage
from email.policy import EmailPolicy
from email.utils import formatdate, parsedate_to_datetime
from typing import TYPE_CHECKING
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx

from execbound.egress import NOT_PUBLIC, refused

if TYPE_CHECKING:
    from execbound.resolution.models import Clock

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


class _OneClickPolicy(EmailPolicy):
    """The default policy, except that `List-Unsubscribe` goes out on one line, unfolded.

    Folded at 78 columns, a one-click link, which has no space to fold at, would go out as RFC
    2047 encoded words, which a mail client reading `List-Unsubscribe` does not take for an
    address. Every other header folds as usual, so a subject that grows with a workspace name
    keeps its lines within 78 columns and any encoded word in it within RFC 2047's 75
    characters. A renderer's own pattern for its link admits no space, CR or LF, and
    `verify_generated_headers`, left on, still refuses a line break on the way out.
    """

    def fold(self, name: str, value: str) -> str:
        if name.lower() == "list-unsubscribe":
            return f"{name}: {value}{self.linesep}"
        folded: str = super().fold(name, value)
        return folded

    def fold_binary(self, name: str, value: str) -> bytes:
        if name.lower() == "list-unsubscribe":
            return f"{name}: {value}{self.linesep}".encode("ascii")
        return super().fold_binary(name, value)


# The policy of every message that carries a one-click `List-Unsubscribe` (RFC 8058): core's
# weekly summary and a plugin's own, such as the hosted approval email.
ONE_CLICK_POLICY = _OneClickPolicy()


_NOT_LABEL = re.compile(r"[^A-Za-z0-9 ._:/()-]")
_SPACE = re.compile(r"\s+")
LABEL_LENGTH = 80


def _reduce(value: object) -> str:
    """Fold accents and compatibility forms to their letters first (NFKD, then dropping the
    combining marks), so `Équipe Sécurité` reads `Equipe Securite` rather than `quipe Scurit`;
    then collapse whitespace, drop what is not label alphabet and cut to a label's length. The
    fold only turns a character into others, which the alphabet still decides on."""
    text = unicodedata.normalize("NFKD", str(value))
    text = _SPACE.sub(" ", "".join(c for c in text if not unicodedata.combining(c)))
    return _SPACE.sub(" ", _NOT_LABEL.sub("", text)).strip()[:LABEL_LENGTH].strip()


def safe_label(value: object) -> str:
    """A label a subject, a body, a block or a card may show.

    Accents fold to their letters; letters, digits, space and ``._:/()-`` survive; whitespace
    collapses; anything else is dropped rather than escaped, so no transport has markup,
    mention or header syntax to interpret. Catalog labels pass through unchanged; fact values
    usually do. A workspace's, a Space's or a person's name goes through `name_label` instead.
    """
    if value is None:
        return "unknown"
    return _reduce(value) or "unknown"


def name_label(value: object) -> str | None:
    """A workspace's, a Space's or a person's name as a message shows it: `safe_label`'s
    reduction, or None when nothing of the name survives it, as nothing of one written in a
    non-Latin script does.

    A message words itself without a name it cannot show. "unknown" in its place would read as
    a workspace ExecBound does not know, or one called that.
    """
    if value is None:
        return None
    return _reduce(value) or None


def choose_workspace(name: object, tenant_id: UUID) -> str:
    """The line that tells someone in several workspaces which one to open a message's link in.

    It names the workspace alone only when `safe_label` shows the name as its administrators
    wrote it, whitespace apart. A label that differs (`Acme, Inc.` reads `Acme Inc.`) could
    match another workspace's name or none the reader sees, so the line gives the tenant id
    beside it, keeping the label as a hint: the tenant id alone is often no help, because only
    an administrator sees it, in Workspace settings. The tenant id stands alone only when
    nothing of the name survives.
    """
    label = name_label(name)
    lead = "If you belong to more than one workspace, choose"
    if label is None:
        return f"{lead} the one whose tenant id is {tenant_id}."
    if label == _SPACE.sub(" ", str(name)).strip():
        return f"{lead} {label}."
    return f"{lead} the one named like {label} (tenant id {tenant_id})."


# A chat target reads some of `safe_label`'s alphabet as formatting: Slack's mrkdwn and
# Teams' Markdown take `_x_` as italics, Slack takes `:smile:` as an emoji, both may turn
# `example.com` or a path into a link, and a Teams fact that starts `-` or `1)` is a list.
# Neither offers an escape for all of these (Slack's mrkdwn escapes only `&`, `<` and `>`), so
# a name that holds one travels only where the target shows text as written.
_CHAT_PLAIN = re.compile(r"(?![0-9]+\)|-)[A-Za-z0-9 ()-]*")


def _chat_plain(label: str | None) -> bool:
    """Whether a chat target would show `label` as written wherever it reads markup."""
    return label is None or _CHAT_PLAIN.fullmatch(label) is not None


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
    mail: MailConfig,
    to: str,
    delivery_id: UUID,
    message: "ApprovalMessage | ClosedMessage | FindingMessage",
) -> EmailMessage:
    """The one `text/plain` message for an approval or a finding: fixed subject, fixed body,
    labels only.

    A close-out renders its own fixed copy (`_closed_email`), and a finding its own
    (`_finding_email`); everything below is the announcement's, and a reminder's, which differs
    only in its subject and first line.

    The subject names the workspace whenever anything of its name survives `name_label`,
    because request references are counted per workspace and two workspaces could otherwise
    send identical subjects; a name nothing of which survives is left out of the subject and
    of the sentences rather than read as "unknown", and two such workspaces can then send
    identical subjects. The `Message-ID` is derived from the delivery id, so a redelivery after an
    uncertain attempt collapses into the first in the recipient's mailbox.

    A finding's `Message-ID` is its delivery id's too, and a finding message carries that id
    itself, so a `delivery_id` that differs from it is refused.
    """
    if isinstance(message, FindingMessage):
        _own_delivery(delivery_id, message)
        return _finding_email(mail, to, message)
    if isinstance(message, ClosedMessage):
        return _closed_email(mail, to, delivery_id, message)
    action = safe_label(message.action_label)
    resource = safe_label(message.resource_class)
    workspace = name_label(message.workspace)
    space = name_label(message.space)
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
    if space is not None:
        lines.append(f"Space: {space}")
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
    if message.workspace is not None:
        lines.append(
            "You receive this because this address is a notification destination"
            + ("." if workspace is None else f" for {workspace}.")
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
    workspace = name_label(message.workspace)
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
    message: "ApprovalMessage | ClosedMessage | FindingMessage",
    *,
    context: ssl.SSLContext | None = None,
    timeout: float = 10,
) -> SendResult:
    """One approval notification, of any kind, or one finding, rendered and sent through the
    relay.

    `context` is the system trust store unless a caller passes one; the tests pass a context
    that trusts the CA they mint, so verification runs exactly as it does in production.
    """
    email = render_email(mail, to, delivery_id, message)
    return _deliver(mail, to, email, context=context, timeout=timeout)


def deliver_email(
    mail: MailConfig,
    to: str,
    email: EmailMessage,
    *,
    context: ssl.SSLContext | None = None,
    timeout: float = 10,
) -> SendResult:
    """One message already rendered, through the relay: the findings drain renders under its
    lease and sends after it (#31), where `send_email` renders and sends in one call."""
    return _deliver(mail, to, email, context=context, timeout=timeout)


_INVITE_LINK = re.compile(r"https?://[A-Za-z0-9.:\[\]-]{1,253}/join")
# What a mail client could turn into a link in a label: a scheme's colon, a path's slash, or a
# dotted host-like word such as `example.com`. A full stop that ends a word links nothing.
_LINKABLE = re.compile(r"[:/]|[A-Za-z0-9]\.[A-Za-z0-9]")


def _invitation_name(value: object, fallback: str) -> str:
    """A workspace or inviter name as an invitation shows it: its label, or `fallback` when
    nothing of it survives or the label holds anything a mail client could link."""
    label = name_label(value)
    return fallback if label is None or _LINKABLE.search(label) else label


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

    Workspace and inviter names are reduced through `name_label`, never rendered raw: an
    administrator's own label or a workspace name is free text nobody else validated, and on
    the hosted service anyone who signs up chooses both. A name nothing of which survives, or
    whose label holds anything a mail client could make a link of (`_LINKABLE`), reads "a
    workspace" or "An administrator", as the page the link opens says when it has no inviter's
    name, so the only link in the message is the invitation's own; the invitee is not a member
    yet, so a tenant id would tell them nothing, and that page names the workspace in full.
    The secret travels in the fragment, exactly as a signup verification link's does, so a
    browser never sends it to any server; the page that opens reads it with its own script.
    The `Message-ID` is fresh for every attempt because every attempt carries a fresh link.
    """
    if not _INVITE_LINK.fullmatch(link) or not _INVITE_TOKEN.fullmatch(token) or not is_address(to):
        raise ValueError("INVALID_TEAMMATE_INVITATION")
    workspace_label = _invitation_name(workspace, "a workspace")
    inviter_label = _invitation_name(inviter, "An administrator")
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


def is_message_origin(origin: object) -> bool:
    """Whether a message may build its links from `origin`: lower-case `http` or `https` and an
    ASCII host, port or bracketed address with nothing after it. `FindingMessage` holds its
    origin to this, and `configuration.read_outbound` holds `process --deliver`'s to it too
    (#31), beside the console's own rule, which takes some origins this refuses."""
    return type(origin) is str and _SUMMARY_ORIGIN.fullmatch(origin) is not None


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
    *,
    tenant_id: UUID,
) -> EmailMessage:
    """The `weekly summary` class: one recipient, a fixed template of counts, one link.

    The workspace name is reduced through `name_label`, and reads "your workspace" when nothing
    of it survives; nothing else in it is a string anybody but this template wrote, so it
    carries no agent, provider, target or person, no approval or execution identifier and no
    control. `choose_workspace` names the workspace a reader of several should choose, by the
    tenant id when the label is not the name as written. The unsubscribe link is the one-click
    address RFC 8058 asks for, in the `List-Unsubscribe` header and once in the body; the
    header goes out on one line under `ONE_CLICK_POLICY`, so a mail client reads it as the
    address it is.
    """
    if (
        not is_address(to)
        or not _SUMMARY_ORIGIN.fullmatch(origin)
        or not _SUMMARY_LINK.fullmatch(link)
        or type(week_ending) is not date
        or type(tenant_id) is not UUID
    ):
        raise ValueError("INVALID_WEEKLY_SUMMARY")
    name = name_label(workspace) or "your workspace"
    day = week_ending.isoformat()
    email = EmailMessage(policy=ONE_CLICK_POLICY)
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
        choose_workspace(workspace, tenant_id),
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
    tenant_id: UUID,
    context: ssl.SSLContext | None = None,
    timeout: float = 10,
) -> SendResult:
    """One weekly summary through the relay."""
    email = render_weekly_summary(
        mail, to, workspace, counts, previous, week_ending, origin, link, tenant_id=tenant_id
    )
    return _deliver(mail, to, email, context=context, timeout=timeout)


# --- Findings delivery (#31): one finding, identifiers and a rule's fixed label only ---

FINDING_DISCLAIMER = (
    "Monitoring reports what a source or a directory recorded. It is not enforcement, and "
    "this message decides nothing."
)


@dataclass(frozen=True)
class FindingMessage:
    """What every kind renders for one finding and one destination; built in the drain's lease.

    Identifiers, the rule's version and its fixed label (`monitoring.delivery.FINDING_RULES`),
    when the finding was raised, the workspace and Space names (reduced by `name_label` where
    they are rendered) and the console's link to the finding. Never the finding's stored title,
    its target, story, action or outcome, a person's or an agent's name, or anything a source
    or a provider supplied. Both names are required, as their columns are never null: a
    message without one would tell its reader to choose a workspace that does not exist. The
    time raised must carry its zone, so it is never read as the host's own.
    """

    tenant_id: UUID
    finding_id: UUID
    delivery_id: UUID
    rule_version: str
    rule_label: str
    created_at: datetime
    origin: str
    workspace: str
    space: str
    source_id: UUID | None = None
    connection_id: UUID | None = None
    observation_id: UUID | None = None
    agent_id: UUID | None = None
    profile_version: int | None = None

    def __post_init__(self) -> None:
        if (
            not is_message_origin(self.origin)
            or safe_label(self.rule_label) != self.rule_label
            or safe_label(self.rule_version) != self.rule_version
            or type(self.workspace) is not str
            or type(self.space) is not str
            or not isinstance(self.created_at, datetime)
            or self.created_at.utcoffset() is None
        ):
            raise ValueError("INVALID_NOTIFICATION")

    @property
    def link(self) -> str:
        """The console's own address for the finding, which Findings opens in place."""
        return f"{self.origin}/monitor?view=findings&state=all&open={self.finding_id}"

    def identifiers(self) -> str:
        found = [f"Finding {self.finding_id}"]
        for name, value in (
            ("Source", self.source_id),
            ("Connection", self.connection_id),
            ("Observation", self.observation_id),
            ("Agent", self.agent_id),
        ):
            if value is not None:
                found.append(f"{name} {value}")
        return " | ".join([*found, f"Delivery {self.delivery_id}"])


def _own_delivery(delivery_id: UUID, message: FindingMessage) -> None:
    """A finding message names its delivery in its identifiers, headers and body; a renderer
    asked for another delivery would send one id in the message and another in the request."""
    if delivery_id != message.delivery_id:
        raise ValueError("INVALID_NOTIFICATION")


def _raised(message: FindingMessage) -> str:
    return message.created_at.astimezone(UTC).strftime(_FULL_TIME)


def _choose(message: FindingMessage) -> str:
    """Hosted has no finding address of its own per workspace (#31), as the weekly summary has
    none: the console opens the finding in the workspace the person is signed in to."""
    return choose_workspace(message.workspace, message.tenant_id)


def _finding_facts(message: FindingMessage) -> list[tuple[str, str]]:
    """The Workspace and Space facts, each left out when nothing of its name survives, then the
    rule and when the finding was raised."""
    names = [("Workspace", name_label(message.workspace)), ("Space", name_label(message.space))]
    return [
        *((title, label) for title, label in names if label is not None),
        ("Rule", f"{message.rule_label} ({message.rule_version})"),
        ("Raised", _raised(message)),
    ]


def finding_body(message: FindingMessage) -> bytes:
    """The signed webhook's `monitor.finding` version 1 body: what the loopback worker always
    sent, every value a string, with `tenant_id`, `created_at` (to the second) and `finding_url`
    added. It is built from the finding and the configured origin, which `finding_url` names, so
    every attempt sends the same bytes while the origin stays the same; a fixture pins them."""

    def value(item: object) -> str | None:
        return None if item is None else str(item)

    return _encode(
        {
            "version": 1,
            "kind": "monitor.finding",
            "delivery_id": str(message.delivery_id),
            "finding_id": str(message.finding_id),
            "source_id": value(message.source_id),
            "observation_id": value(message.observation_id),
            "rule_version": message.rule_version,
            "profile_version": value(message.profile_version),
            "tenant_id": str(message.tenant_id),
            "created_at": message.created_at.astimezone(UTC).isoformat(timespec="seconds"),
            "finding_url": message.link,
        }
    )


def _finding_email(mail: MailConfig, to: str, message: FindingMessage) -> EmailMessage:
    """One `text/plain` message for a finding: a fixed subject naming the workspace and the
    rule's label, the facts, the identifiers, the link and the fixed sentence. The `Message-ID`
    is the delivery id's, so a redelivery collapses into the first in the mailbox. A workspace
    name nothing of which survives `name_label` is left out of the subject and the sentences."""
    workspace = name_label(message.workspace)
    where = "" if workspace is None else f" in {workspace}"
    email = EmailMessage()
    email["From"] = mail.sender
    email["To"] = to
    email["Subject"] = f"[{_tag(workspace, None)}] Finding: {message.rule_label}"
    email["Date"] = formatdate(usegmt=True)
    email["Message-ID"] = f"<{message.delivery_id}@{_domain(mail)}>"
    email["Auto-Submitted"] = "auto-generated"
    email["X-ExecBound-Delivery"] = str(message.delivery_id)
    email["X-ExecBound-Finding"] = str(message.finding_id)
    lines = [
        f"A finding was raised{where} at {_raised(message)}.",
        "",
        *(f"{title}: {value}" for title, value in _finding_facts(message)),
        "",
        message.identifiers(),
        "",
        f"Open the finding: {message.link}",
        _choose(message),
        "",
        FINDING_DISCLAIMER,
        "You receive this because this address is a findings destination"
        + ("." if workspace is None else f" for {workspace}."),
        "Sent automatically; replies are not read.",
    ]
    # Every line is `safe_label` copy or fixed ASCII, so the source reads as the body does.
    email.set_content("\n".join(lines) + "\n", cte="7bit")
    return email


def _finding_slack(message: FindingMessage) -> bytes:
    """Block Kit for a finding: every text object `plain_text`, one link button. The
    notification line, which Slack reads as mrkdwn, names the workspace only when Slack would
    show the name as written (`_chat_name`)."""
    header = f"Finding: {message.rule_label}"
    workspace = _chat_name(message.workspace)
    return _encode(
        {
            "text": header if workspace is None else f"{header} in {workspace}",
            "blocks": [
                {"type": "header", "text": _plain(header)},
                {
                    "type": "section",
                    "fields": [_plain(f"{t}: {v}") for t, v in _finding_facts(message)],
                },
                {"type": "section", "text": _plain(FINDING_DISCLAIMER)},
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": _plain("Open the finding"),
                            "url": message.link,
                            "action_id": "open_finding",
                        }
                    ],
                },
                {"type": "context", "elements": [_plain(_choose(message))]},
                {"type": "context", "elements": [_plain(message.identifiers())]},
            ],
        }
    )


def _finding_teams(message: FindingMessage) -> bytes:
    """The Adaptive Card that mirrors `_finding_slack`. A name Teams could format puts the
    facts and the line naming the workspace in text runs (`_teams_facts`)."""
    small = {"isSubtle": True, "size": "Small", "wrap": True}
    runs = _runs(message.workspace, message.space)
    choose = (
        _run_line(_choose(message), isSubtle=True, size="Small")
        if runs
        else {"type": "TextBlock", "text": _choose(message), **small}
    )
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {
                "type": "TextBlock",
                "text": f"Finding: {message.rule_label}",
                "weight": "Bolder",
                "size": "Medium",
                "wrap": True,
            },
            *_teams_facts(_finding_facts(message), runs),
            {"type": "TextBlock", "text": FINDING_DISCLAIMER, "wrap": True},
            choose,
            {"type": "TextBlock", "text": message.identifiers(), **small},
        ],
        "actions": [{"type": "Action.OpenUrl", "title": "Open the finding", "url": message.link}],
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
    for title, name in (("Workspace", message.workspace), ("Space", message.space)):
        label = name_label(name)
        if label is not None:
            facts.append((title, label))
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
    """The one line a phone's notification shows: the header, the deadline and the workspace,
    which Slack reads as mrkdwn, so a name it could format is left out (`_chat_name`)."""
    action = safe_label(message.action_label)
    lead = f"{safe_label(message.request_ref)} \u00b7 {action}" if message.request_ref else action
    name = _chat_name(message.workspace)
    workspace = "" if name is None else f" in {name}"
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


# How a chat message carries a workspace's or a Space's name (#31, #179). Slack shows a
# `plain_text` object with `emoji` off as written, and every block already uses one; its one
# field read as mrkdwn is the notification line, which leaves out a name Slack could format.
# Teams reads every text block and every fact as Markdown, so a card with such a name, or an
# approval whose environment (a fact value a provider reported) holds such text, carries its
# facts, and the line naming the workspace, in text runs, which Adaptive Cards never read as
# Markdown. A card whose names need none of this is unchanged.


def _chat_name(value: object) -> str | None:
    """A name for Slack's notification line, or None when the line must leave it out: nothing
    of it survives `name_label`, or Slack could format what does."""
    label = name_label(value)
    return label if label is not None and _chat_plain(label) else None


def _runs(*names: object) -> bool:
    """Whether a Teams card carries its facts in text runs: one of `names` (the workspace's and
    Space's names, and an approval's environment) survives `name_label` holding something Teams
    could format."""
    return not all(_chat_plain(name_label(name)) for name in names)


def _run_line(text: str, **style: object) -> dict[str, object]:
    """One line Teams shows as written: a RichTextBlock of a single TextRun."""
    return {"type": "RichTextBlock", "inlines": [{"type": "TextRun", "text": text, **style}]}


def _teams_facts(facts: list[tuple[str, str]], runs: bool) -> list[dict[str, object]]:
    """The facts as one FactSet, or, when `runs`, one RichTextBlock per fact: a bold title run
    and the value's own run, both shown as written."""
    if not runs:
        return [{"type": "FactSet", "facts": [{"title": t, "value": v} for t, v in facts]}]
    return [
        {
            "type": "RichTextBlock",
            "inlines": [
                {"type": "TextRun", "text": f"{title}: ", "weight": "Bolder"},
                {"type": "TextRun", "text": value},
            ],
        }
        for title, value in facts
    ]


def _closed_header(message: ClosedMessage) -> str:
    """`EB-20 \u00b7 <action>: approved`, and the same for each outcome."""
    action = safe_label(message.action_label)
    lead = f"{safe_label(message.request_ref)} \u00b7 {action}" if message.request_ref else action
    return f"{lead}: {CLOSED_WORDS[message.outcome][1]}"


def _closed_facts(message: ClosedMessage) -> list[tuple[str, str]]:
    """Workspace, Outcome and At: what ended and when, and nothing about the target."""
    facts = []
    workspace = name_label(message.workspace)
    if workspace is not None:
        facts.append(("Workspace", workspace))
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
    name = _chat_name(message.workspace)
    workspace = "" if name is None else f" in {name}"
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
            *_teams_facts(_closed_facts(message), _runs(message.workspace)),
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


def render_slack(
    delivery_id: UUID, message: ApprovalMessage | ClosedMessage | FindingMessage
) -> bytes:
    """Block Kit for an incoming webhook: every text object `plain_text`, link buttons only.

    `plain_text` with `emoji` off means Slack interprets no mention, link, emoji or formatting
    syntax; the labels have been reduced by `safe_label` besides, and the notification line,
    which Slack reads as mrkdwn, leaves out a name it could format. An approval's buttons open
    its own page, and a finding's opens the finding in the console; neither decides anything.
    A finding message carries its own delivery id, so a `delivery_id` that differs from it is
    refused.
    """
    if isinstance(message, FindingMessage):
        _own_delivery(delivery_id, message)
        return _finding_slack(message)
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


def render_teams(
    delivery_id: UUID, message: ApprovalMessage | ClosedMessage | FindingMessage
) -> bytes:
    """A Workflows `message` carrying one Adaptive Card that mirrors the Slack blocks, for an
    approval or a finding; a finding message's own delivery id must be `delivery_id`. A card
    with a workspace or Space name Teams could format carries its facts in text runs, which
    Teams shows as written (`_teams_facts`)."""
    if isinstance(message, FindingMessage):
        _own_delivery(delivery_id, message)
        return _finding_teams(message)
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
            # The environment is a fact value a provider reported, so it counts as a name does.
            *_teams_facts(
                _facts(message), _runs(message.workspace, message.space, message.environment)
            ),
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


def retry_after_seconds(value: str | None, clock: "Clock | None" = None) -> int:
    """`Retry-After` in whole seconds, clamped to 1..3600; 30 when absent or unreadable.

    The value is delta-seconds or an HTTP-date. A date is measured from `clock`, the drain's
    when it has one and the host's otherwise, and rounded up, so a retry never lands before it;
    a date already past is the floor of one second.
    """
    text = (value or "").strip()
    try:
        seconds = int(text)
    except ValueError:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError, OverflowError):
            return RETRY_AFTER_DEFAULT
        if when.tzinfo is None:
            # `-0000` and the obsolete asctime form carry no zone; an HTTP-date is always GMT.
            when = when.replace(tzinfo=UTC)
        now = clock.now() if clock is not None else datetime.now(UTC)
        seconds = math.ceil((when - now).total_seconds())
    return min(max(seconds, 1), 3600)


def send_chat(
    kind: str,
    url: str,
    delivery_id: UUID,
    message: ApprovalMessage | ClosedMessage | FindingMessage,
    client: httpx.Client,
    *,
    clock: "Clock | None" = None,
) -> SendResult:
    """One message rendered for its Slack or Teams destination and posted by `post_chat`."""
    body = (
        render_slack(delivery_id, message)
        if kind == "slack"
        else render_teams(delivery_id, message)
    )
    return post_chat(kind, url, delivery_id, body, client, clock=clock)


def post_chat(
    kind: str,
    url: str,
    delivery_id: UUID,
    body: bytes,
    client: httpx.Client,
    *,
    clock: "Clock | None" = None,
) -> SendResult:
    """One POST of a body already rendered to a Slack or Teams webhook; reads only the status
    and `Retry-After`, a date in it measured from `clock`. The findings drain renders under its
    lease and posts after it (#31).

    Slack delivers on 200 and Teams on 200 or 202, since a Workflows trigger accepts the
    request and runs the flow afterwards. No exception text or response body leaves here,
    because an error could quote the URL, which is the secret.
    """
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
    except httpx.HTTPError as error:
        # The guard's refusal is told apart; nothing of the error's text leaves here.
        return SendResult(False, NOT_PUBLIC if refused(error) else "RECEIVER_UNAVAILABLE")
    if status == 200 or (kind == "teams" and status == 202):
        return DELIVERED
    if status == 429:
        return SendResult(False, "RECEIVER_RATE_LIMITED", retry_after_seconds(retry, clock))
    if 400 <= status < 500:
        return SendResult(False, "RECEIVER_REFUSED")
    return SendResult(False, "RECEIVER_UNAVAILABLE")
