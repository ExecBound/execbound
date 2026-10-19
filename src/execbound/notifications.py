# SPDX-License-Identifier: AGPL-3.0-only
"""Approval notifications: operator destinations, a transactional outbox and a bounded drain.

A notification never grants, extends or replaces an approval. Its payload carries identifiers,
catalog labels, timestamps and the fixed approval page link, never an untrusted string.

The message links; nothing in a message decides. No kind, webhook, email or chat, carries an
approve or deny control: the decision happens on the approval page, under the approver's
session, as everywhere else. Kinds are transports over one message (`transports.py`); the
queueing, leasing, retry and visibility below are the same for all of them.

A notification is not sent, retried or deferred once it could not arrive with time to act:
inside `LAPSE_MARGIN` of the approval's deadline a row is closed unsent as
`LAPSED_BEFORE_DELIVERY`, and a retry or a cap deferral that would land past that point fails
the row with its own code instead (#678).

Each row has a kind (#678): `approval.pending` announces a held request. A destination whose
`messages` ask for them also gets two follow-ups: `approval.reminder`, the announcement again
once half the approval's window has passed with at least `REMINDER_FLOOR` still left, and
`approval.closed`, how the approval ended. The drain queues both itself, at the start of a run.
A reminder never extends or changes an approval, and a window too short for one to arrive in
time gets none. At most one message of each kind goes to a destination per approval, which the
table's unique key holds; a destination receives only the kinds its `messages` list, and a row
queued before a configuration change that switched its message off is settled `MESSAGE_OFF`,
unsent. A follow-up never spends the last tenth of the daily email cap, which stays for the
pending announcement, the only message that can still be acted on.
"""

import ipaddress
import ssl
import time
from collections.abc import Callable, Container, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4, uuid5

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.db import Database, check_runtime
from execbound.egress import guarded_client
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.execution.scheduled import ScheduledActor, scheduled_check
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.monitoring.delivery import FINDING_RULES, send_notification
from execbound.resolution.models import Clock, SystemClock
from execbound.transports import (
    CHAT_KINDS,
    DELIVERED,
    ApprovalMessage,
    ClosedMessage,
    MailConfig,
    SendResult,
    chat_url_ok,
    closed_body,
    is_address,
    send_chat,
    send_email,
    webhook_body,
)

MAX_ATTEMPTS = 5
# The wait after each failed attempt. Five attempts have four waits, 5, 25, 125 and 625 s: the
# fifth value is looked up at every fifth attempt that brings no `Retry-After`, delivered or
# not, and thrown away, since nothing follows a fifth (this drain, `monitoring.worker`, `export`
# and the hosted approval email all stop at `MAX_ATTEMPTS`). It stays because this drain and the
# hosted one index it there before they check the count.
BACKOFF = (5, 25, 125, 625, 3125)
# Delivery closes this long before an approval's deadline (#678): a message
# that arrives later leaves the approver no time to open the page and decide.
LAPSE_MARGIN = timedelta(seconds=15)
# A still-PENDING approval is reported lapsed only this long after its deadline: a decision is
# refused from `expires_at` on, and the grace absorbs clock skew between the gateway and the
# host the drain runs on (#678).
CLOSE_GRACE = timedelta(seconds=30)
# A reminder is queued once half an approval's window has passed and only while at least this
# long is left: three one-minute drain intervals, so it can still arrive with time to act. A
# 300-second window (a five-minute context cap) and the 120-second default never qualify (#678).
REMINDER_FLOOR = timedelta(seconds=180)
# The most a drain's start takes per follow-up scan: approvals for reminders, approval and
# destination pairs for close-outs. Each scan skips what it already queued, so the next drain
# reaches the next batch.
FOLLOWUP_BATCH = 50

# The messages a destination may ask for, in the one order every reader shows them, and the
# message each stored kind is.
MESSAGE_ORDER = ("pending", "reminder", "closed")
DEFAULT_MESSAGES = frozenset({"pending"})
KIND_MESSAGE = {
    "approval.pending": "pending",
    "approval.reminder": "reminder",
    "approval.closed": "closed",
}
# How a close-out reports each approval outcome on the webhook, and the stored codes.
OUTCOMES = ("APPROVED", "REFUSED", "LAPSED", "WITHDRAWN")

# The classes a destination may carry (#179 decision 4, #31), in the one order every reader
# shows them: `approvals` announces held requests and `findings` sends monitoring findings. A
# destination the configuration gives none is an approval destination, as every one was.
APPROVALS = "approvals"
FINDINGS = "findings"
CLASS_ORDER = (APPROVALS, FINDINGS)
DEFAULT_CLASSES = frozenset({APPROVALS})


def _narrowing(
    value: object, item_type: type, findings: bool, known: Container[str] | None = None
) -> bool:
    """None, or a non-empty frozenset of `item_type` on a findings destination, every item in
    `known` unless `known` is None. An empty `known` admits nothing."""
    if value is None:
        return True
    return (
        findings
        and type(value) is frozenset
        and bool(value)
        and all(type(item) is item_type for item in value)
        and (known is None or all(item in known for item in value))
    )


@dataclass(frozen=True)
class Destination:
    """One operator channel; only the private configuration creates these.

    A `webhook` or `security-events` destination is a signed HTTPS endpoint with a shared
    secret; an `email` destination is one bare address sent through the deployment's `mail`
    relay and carries no URL and no secret; a `slack` or `teams` destination is a pinned-host
    webhook URL that is itself the secret. The URL and the secret never appear in a repr.
    Its `classes` say what it receives (#31): approval announcements, monitoring findings or
    both, a findings destination narrowed by `rules` and `spaces`.
    """

    destination_id: str
    tenant_id: UUID
    url: str = field(repr=False)
    secret: str = field(repr=False)
    approvers: frozenset[UUID] | None = None
    kind: str = "webhook"
    to: str | None = None
    # Which approval messages it receives (#678): a non-empty subset of `MESSAGE_ORDER`,
    # where a close-out follows only a message the destination received. The default is the
    # one announcement every destination always received.
    messages: frozenset[str] = DEFAULT_MESSAGES
    # Which classes it receives (#31): a non-empty subset of `CLASS_ORDER`. `messages` and
    # `approvers` are an approval destination's alone, and an audit export keeps the default.
    classes: frozenset[str] = DEFAULT_CLASSES
    # A findings destination's narrowing: the rules and the Spaces whose findings it receives,
    # or every one where None.
    rules: frozenset[str] | None = None
    spaces: frozenset[UUID] | None = None

    def __post_init__(self) -> None:
        import re

        if (
            type(self.messages) is not frozenset
            or not self.messages
            or not self.messages <= set(MESSAGE_ORDER)
            or ("closed" in self.messages and not self.messages & {"pending", "reminder"})
            or (self.kind == "security-events" and self.messages != DEFAULT_MESSAGES)
        ):
            raise ValueError("Invalid notification destination")
        findings = FINDINGS in self.classes if type(self.classes) is frozenset else False
        if (
            type(self.classes) is not frozenset
            or not self.classes
            or not self.classes <= set(CLASS_ORDER)
            or (self.kind == "security-events" and self.classes != DEFAULT_CLASSES)
            or (
                APPROVALS not in self.classes
                and (self.messages != DEFAULT_MESSAGES or self.approvers is not None)
            )
            or not _narrowing(self.rules, str, findings, FINDING_RULES)
            or not _narrowing(self.spaces, UUID, findings)
        ):
            raise ValueError("Invalid notification destination")
        if (
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.destination_id)
            or type(self.tenant_id) is not UUID
            or (
                self.approvers is not None
                and any(type(value) is not UUID for value in self.approvers)
            )
        ):
            raise ValueError("Invalid notification destination")
        if self.kind == "email":
            if self.url or self.secret or not is_address(self.to):
                raise ValueError("Invalid notification destination")
            return
        if self.kind in CHAT_KINDS:
            if self.secret or self.to is not None or not chat_url_ok(self.kind, self.url):
                raise ValueError("Invalid notification destination")
            return
        if self.kind not in {"webhook", "security-events"} or self.to is not None:
            raise ValueError("Invalid notification destination")
        parsed = urlsplit(self.url)
        loopback = False
        try:
            loopback = (
                bool(parsed.hostname) and ipaddress.ip_address(parsed.hostname or "").is_loopback
            )
        except ValueError:
            loopback = False
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.scheme not in {"http", "https"}
            or (parsed.scheme == "http" and not loopback)
            or not 32 <= len(self.secret) <= 256
            or not self.secret.isascii()
        ):
            raise ValueError("Invalid notification destination")


# The kinds an approval is announced through; `security-events` is the audit export.
APPROVAL_KINDS = frozenset({"webhook", "email", "slack", "teams"})


def announces_approvals(destination: Destination) -> bool:
    """Whether a destination announces approvals: an approval kind whose classes include
    `approvals` (#31). Every approval reader keeps only these, so a findings-only destination
    is never queued, drained or counted for an approval."""
    return destination.kind in APPROVAL_KINDS and APPROVALS in destination.classes


# Who may decide an approval: the active scopes on its execution's stored target, action and
# Space. The one routing rule, shared by `matching_destinations` and the reminder scan.
_ASSIGNED = (
    "s.tenant_id=e.tenant_id AND s.canonical_target_id=e.canonical_target_id "
    "AND s.action=e.frozen->'intent'->>'action' AND s.space_id=e.space_id"
)
_ASSIGNED_APPROVERS = text(f"""
    SELECT s.approver_id FROM execbound.approvals a
      JOIN execbound.executions e ON e.tenant_id=a.tenant_id AND e.execution_id=a.execution_id
      JOIN execbound.effective_approval_scopes s ON {_ASSIGNED}
     WHERE a.tenant_id=:t AND a.approval_id=:a AND s.active
""")  # nosec B608 - only the fixed `_ASSIGNED` join; values are bound parameters


def matching_destinations(
    conn: Connection,
    tenant: UUID,
    approval_id: UUID,
    destinations: Sequence[Destination],
    message: str = "pending",
) -> tuple[list[Destination], int]:
    """Recipients for the approval's stored target, action and Space, never caller hints.

    Only destinations whose `messages` list `message` are selected; the count of assigned
    approvers is the approval's own, whatever the message.
    """
    assigned = {
        row[0] for row in conn.execute(_ASSIGNED_APPROVERS, {"t": tenant, "a": approval_id})
    }
    selected = [
        d
        for d in destinations
        if d.tenant_id == tenant
        and announces_approvals(d)
        and message in d.messages
        and (d.approvers is None or d.approvers & assigned)
    ]
    return selected, len(assigned)


# A notification's id is fixed by its approval, destination and kind, so a row queued twice
# collides on the primary key `(tenant_id, notification_id)` as well as on the one-per-kind key.
# The conflict clause names no target, so it covers both: one naming only the one-per-kind key
# lets two racing inserts both pass its check, and the second then fails on the primary key
# instead of doing nothing.
_QUEUE_ANNOUNCEMENT = text("""
    INSERT INTO execbound.approval_notifications
    (tenant_id, notification_id, approval_id, destination_id, kind, created_at, next_attempt_at)
    VALUES (:t, :n, :a, :d, 'approval.pending', :now, :now)
    ON CONFLICT DO NOTHING
""")


def queue_notifications(
    conn: Connection,
    tenant: UUID,
    approval_id: UUID,
    canonical_target_id: UUID,
    action: str,
    now: datetime,
    destinations: Sequence[Destination],
) -> int:
    """Queue under the tenant fence; retained target/action arguments cannot choose recipients.

    The call shape is kept for admission, but routing is derived from the stored approval's
    execution so an assignment for the same resource in another Space is never used.
    """
    selected, _ = matching_destinations(conn, tenant, approval_id, destinations, "pending")
    for destination in selected:
        conn.execute(
            _QUEUE_ANNOUNCEMENT,
            {
                "t": tenant,
                "n": uuid5(approval_id, destination.destination_id),
                "a": approval_id,
                "d": destination.destination_id,
                "now": now,
            },
        )
    return len(selected)


def approval_message(
    conn: Connection,
    tenant: UUID,
    approval: dict[str, Any],
    approval_url: str,
    *,
    approval_path: Callable[[UUID, UUID], str] | None = None,
    sent_at: datetime | None = None,
    kind: str = "approval.pending",
) -> ApprovalMessage:
    """The one message every kind renders, read under the drain's lease.

    ``approval_path`` is a loaded plugin's own link builder (``ApprovalLinks.path``); without
    one the message links to the plain ``/approvals/{approval_id}`` address. ``sent_at`` is
    the drain's clock at lease, which the rendered window is worded from. ``kind`` is the
    announcement's, or ``approval.reminder`` for the same message sent again.

    The workspace and space are named from their own rows, and the requesting agent by its
    tenant-local handle ("Agent 3"), never by its label: a label is administrator free text,
    and nothing the agent supplied is read (#678).
    """
    row = store.read(conn, tenant, approval["execution_id"])
    frozen = store.frozen(row)
    _, assigned = matching_destinations(conn, tenant, approval["approval_id"], ())
    from execbound.contracts import PRODUCTION_CATALOG
    from execbound.surfaces.human import action_label, environment_label, resource_class
    from execbound.surfaces.names import principal_facts, principal_handle

    workspace = conn.execute(
        text("SELECT name FROM execbound.tenants WHERE tenant_id=:t"), {"t": tenant}
    ).scalar_one_or_none()
    space = conn.execute(
        text("SELECT name FROM execbound.spaces WHERE tenant_id=:t AND space_id=:s"),
        {"t": tenant, "s": row["space_id"]},
    ).scalar_one_or_none()
    facts = principal_facts(conn, tenant, [row["principal_id"]]).get(row["principal_id"])
    required = int(approval.get("required_approvers", 1) or 1)
    recorded = None
    if required > 1:
        decisions = store.approval_decisions(conn, tenant, approval["approval_id"])
        recorded = (sum(1 for d in decisions if d["decision"] == "APPROVE"), required)

    return ApprovalMessage(
        request_ref=f"EB-{row['request_number']}",
        tenant_id=tenant,
        approval_id=approval["approval_id"],
        execution_id=row["execution_id"],
        canonical_target_id=row["canonical_target_id"],
        action=frozen.intent.action,
        action_label=action_label(frozen, PRODUCTION_CATALOG),
        resource_class=resource_class(frozen, PRODUCTION_CATALOG),
        environment=environment_label(frozen),
        expires_at=approval["expires_at"],
        assigned_approvers=assigned,
        approval_url=approval_url,
        path=None if approval_path is None else approval_path(tenant, approval["approval_id"]),
        workspace=None if workspace is None else str(workspace),
        space=None if space is None else str(space),
        requested_by=principal_handle(
            "AGENT", facts.number if facts else None, row["principal_id"]
        ),
        sent_at=sent_at,
        kind=kind,
        recorded=recorded,
    )


def closed_message(
    announcement: ApprovalMessage,
    *,
    outcome: str,
    closed_at: datetime,
    pending_delivery_id: UUID | None,
) -> ClosedMessage:
    """A close-out built from the announcement's reads: labels, reference, workspace, link.

    It keeps no fact about the target, the agent or a person: the close-out reports how the
    approval ended and nothing about whether anything ran.
    """
    if outcome not in OUTCOMES:
        raise ExecutionError("INVALID_NOTIFICATION")
    return ClosedMessage(
        tenant_id=announcement.tenant_id,
        approval_id=announcement.approval_id,
        execution_id=announcement.execution_id,
        action=announcement.action,
        action_label=announcement.action_label,
        resource_class=announcement.resource_class,
        request_ref=announcement.request_ref,
        workspace=announcement.workspace,
        outcome=outcome,
        closed_at=closed_at,
        approval_url=announcement.approval_url,
        path=announcement.path,
        pending_delivery_id=pending_delivery_id,
        sent_at=announcement.sent_at,
    )


def payload(
    conn: Connection,
    tenant: UUID,
    approval: dict[str, Any],
    approval_url: str,
    *,
    approval_path: Callable[[UUID, UUID], str] | None = None,
) -> bytes:
    try:
        return webhook_body(
            approval_message(conn, tenant, approval, approval_url, approval_path=approval_path)
        )
    except ValueError:
        raise ExecutionError("INVALID_NOTIFICATION") from None


@dataclass(frozen=True)
class NotificationRow:
    notification_id: UUID
    approval_id: UUID
    destination_id: str
    kind: str
    state: str
    attempts: int
    created_at: datetime
    next_attempt_at: datetime
    delivered_at: datetime | None
    last_error: str | None


def _admin(conn: Connection, admin: Identity | ScheduledActor, clock: Clock) -> None:
    check_runtime(conn)
    if isinstance(admin, ScheduledActor):
        # The scheduled drain (#503) holds no workspace credential: the workspace must be
        # active, which is what an administrator's check also required of it.
        scheduled_check(conn, admin)
    else:
        store.identity_check(conn, admin, clock, "ADMIN")


# The lock a workspace's email is counted under (`email_capped`), one key per workspace: the
# cap is a workspace's, so one workspace's drains never wait on another's.
EMAIL_CAP_LOCK = "email-cap:{tenant}"

_EMAIL_COUNTED = text("""
    SELECT (SELECT count(*) FROM execbound.approval_notifications
             WHERE tenant_id = :t AND destination_id = ANY(CAST(:ids AS text[]))
               AND ((state = 'DELIVERED' AND delivered_at > :since)
                    OR (state = 'IN_FLIGHT' AND lease_until > :now)))
         + (SELECT count(*) FROM execbound.monitor_deliveries
             WHERE tenant_id = :t AND destination_id = ANY(CAST(:ids AS text[]))
               AND ((state = 'DELIVERED' AND delivered_at > :since)
                    OR (state = 'IN_FLIGHT' AND lease_until > :now)))
""")


def email_capped(
    conn: Connection,
    tenant: UUID,
    now: datetime,
    mail: MailConfig,
    email_ids: list[str],
    *,
    reserve: int = 0,
) -> bool:
    """True when this tenant's email in the last 24 hours, delivered or being sent, reached
    the cap.

    Every message counts toward the relay's limit, an approval's and a finding's alike (#31):
    both outboxes are read, for every email destination the configuration names for the
    workspace (`email_destination_ids`). `reserve` is the headroom a message that can no longer
    be acted on must leave: a follow-up or a finding is sent only below `daily_limit - reserve`,
    so the last of the cap stays for a new request's announcement (#678).

    A message counts once it is delivered or while a drain holds it under a live lease, so a
    send in flight is counted before it settles. The row a drain has in hand never counts
    itself: a drain takes only a `PENDING` row or one whose lease has lapsed. A message the
    relay took from a drain that died before settling it is not counted once its lease lapses,
    and is counted again when it is resent, so on such a day the relay holds one more than the
    count.

    The count is read under one transaction-scoped advisory lock per workspace
    (`EMAIL_CAP_LOCK`), taken here, as the first statement, so every caller takes it: the
    approval drain's announcement and follow-up and the findings drain alike. The caller writes
    its lease in the same transaction, so the lock is held until that lease is committed, and a
    second drain counts only once the first's lease is there to count: two drains cannot both
    take the last of the cap or of a share. The order in both drains is the row's lock first
    (`FOR UPDATE ... SKIP LOCKED`, which never waits), then this lock, the count, the lease and
    the commit, and nothing waits on a row lock while this one is held, so two drains never
    wait on each other. This lock is never taken before the row is chosen. It holds only under
    READ COMMITTED, `Database.transaction`'s default, where the count's snapshot is taken after
    the lock is granted; under `snapshot=True` (REPEATABLE READ) the snapshot predates the wait
    and would miss the other drain's lease. The lock is held for a count, a few reads, a render
    and a lease; a wait past the transaction's `lock_timeout` stops the drain as any database
    failure does, with nothing leased.
    """
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": EMAIL_CAP_LOCK.format(tenant=tenant)},
    )
    sent = conn.execute(
        _EMAIL_COUNTED,
        {"t": tenant, "ids": email_ids, "since": now - timedelta(days=1), "now": now},
    ).scalar_one()
    return int(sent) >= mail.daily_limit - reserve


def email_destination_ids(destinations: Sequence[Destination], tenant: UUID) -> list[str]:
    """Every email destination the configuration names for a workspace, whatever its classes:
    the set the one cap counts (#31)."""
    return sorted(
        d.destination_id for d in destinations if d.tenant_id == tenant and d.kind == "email"
    )


def announcement_reserve(mail: MailConfig) -> int:
    """The last tenth of the daily email cap, at least one message, kept for announcements."""
    return max(1, mail.daily_limit // 10)


def _send(
    destination: Destination,
    notification_id: UUID,
    message: ApprovalMessage | ClosedMessage,
    body: bytes,
    client: httpx.Client,
    mail: MailConfig | None,
    tls_context: ssl.SSLContext | None,
    clock: Clock,
) -> SendResult:
    """One attempt through the destination's kind; the result settles the row. A chat
    receiver's `Retry-After` date is measured from the drain's `clock`."""
    if destination.kind == "email":
        if mail is None or destination.to is None:
            raise ExecutionError("INVALID_CONFIGURATION")
        return send_email(mail, destination.to, notification_id, message, context=tls_context)
    if destination.kind in CHAT_KINDS:
        return send_chat(
            destination.kind, destination.url, notification_id, message, client, clock=clock
        )
    accepted = send_notification(destination, notification_id, body, client)
    return DELIVERED if accepted else SendResult(False, "RECEIVER_UNAVAILABLE")


# A close-out row is one destination's follow-up to a message it received about an approval
# that has since closed: decided, invalidated, or lapsed past `CLOSE_GRACE`. The outcome and its
# time are fixed here, at enqueue, so a retry says the same thing and a later state change of
# the approval (APPROVED to CONSUMED or EXPIRED) changes nothing. `decided_at` is written only by
# the final decision, never by a partial quorum, so an approval that lapses with one of two
# approvals recorded reads LAPSED. The one-day and one-hour bounds keep the scan small and drop
# a close-out that would arrive more than an hour late; the `NOT EXISTS` lets the next drain
# reach the next fifty rather than the same ones.
_CLOSE_OUTS = text("""
    SELECT DISTINCT ON (n.approval_id, n.destination_id) n.approval_id, n.destination_id,
           CASE WHEN a.state = 'DENIED' THEN 'REFUSED'
                WHEN a.decided_at IS NOT NULL THEN 'APPROVED'
                WHEN a.state = 'INVALIDATED' THEN 'WITHDRAWN'
                ELSE 'LAPSED' END AS outcome,
           CASE WHEN a.decided_at IS NOT NULL THEN a.decided_at
                WHEN a.state = 'INVALIDATED' THEN CAST(:now AS timestamptz)
                ELSE a.expires_at END AS closed_at
      FROM execbound.approval_notifications n
      JOIN execbound.approvals a ON a.tenant_id = n.tenant_id AND a.approval_id = n.approval_id
     WHERE n.tenant_id = :t AND n.state = 'DELIVERED' AND n.kind <> 'approval.closed'
       AND n.destination_id = ANY(CAST(:closing AS text[]))
       AND n.delivered_at > CAST(:now AS timestamptz) - interval '1 day'
       AND a.expires_at > CAST(:now AS timestamptz) - interval '1 hour'
       AND (a.state <> 'PENDING' OR a.expires_at <= CAST(:now AS timestamptz) - :grace)
       AND NOT EXISTS (SELECT 1 FROM execbound.approval_notifications c
                        WHERE c.tenant_id = n.tenant_id AND c.approval_id = n.approval_id
                          AND c.destination_id = n.destination_id
                          AND c.kind = 'approval.closed')
     ORDER BY n.approval_id, n.destination_id
     LIMIT :batch
""")


# As `_QUEUE_ANNOUNCEMENT`, with no conflict target, so two racing drains queue one row and
# neither raises.
_QUEUE_CLOSE_OUT = text("""
    INSERT INTO execbound.approval_notifications
    (tenant_id, notification_id, approval_id, destination_id, kind, outcome, closed_at,
     created_at, next_attempt_at)
    VALUES (:t, :n, :a, :d, 'approval.closed', :o, :c, :now, :now)
    ON CONFLICT DO NOTHING
""")


# A reminder is due for a still-PENDING approval once half its window has passed, while at
# least `REMINDER_FLOOR` is left, and only once: the `NOT EXISTS` and the order mean an approval
# already reminded is never taken again, so the next drain reaches the next batch, soonest
# deadline first. An approval no destination listing `reminder` routes would get no row and be
# taken again every drain, ahead of later ones that are routed; the last clause leaves it out,
# by the same assignment rule `matching_destinations` routes by. The partial index
# `approvals_pending_expiry` serves the scan.
_REMINDERS = text(f"""
    SELECT a.approval_id
      FROM execbound.approvals a
     WHERE a.tenant_id = :t AND a.state = 'PENDING'
       AND a.expires_at >= CAST(:now AS timestamptz) + :floor
       AND CAST(:now AS timestamptz) >= a.created_at + (a.expires_at - a.created_at) / 2
       AND NOT EXISTS (SELECT 1 FROM execbound.approval_notifications r
                        WHERE r.tenant_id = a.tenant_id AND r.approval_id = a.approval_id
                          AND r.kind = 'approval.reminder')
       AND (:everyone OR EXISTS (
            SELECT 1 FROM execbound.executions e
              JOIN execbound.effective_approval_scopes s ON {_ASSIGNED}
             WHERE e.tenant_id = a.tenant_id AND e.execution_id = a.execution_id
               AND s.active AND s.approver_id = ANY(CAST(:approvers AS uuid[]))))
     ORDER BY a.expires_at, a.approval_id
     LIMIT :batch
""")  # nosec B608 - only the fixed `_ASSIGNED` join; values are bound parameters


# As `_QUEUE_ANNOUNCEMENT`, with no conflict target, so two racing drains queue one row and
# neither raises.
_QUEUE_REMINDER = text("""
    INSERT INTO execbound.approval_notifications
    (tenant_id, notification_id, approval_id, destination_id, kind, created_at, next_attempt_at)
    VALUES (:t, :n, :a, :d, 'approval.reminder', :now, :now)
    ON CONFLICT DO NOTHING
""")


def _enqueue_reminders(
    conn: Connection, tenant: UUID, now: datetime, reminding: list[Destination]
) -> int:
    """Queue each due reminder for the destinations that list `reminder`; returns how many.

    Each approval is routed by `matching_destinations`, exactly as admission routes its
    announcement, so an escalation destination (`reminder` alone) is reached the same way.
    """
    approvers = sorted({a for d in reminding if d.approvers is not None for a in d.approvers})
    queued = 0
    for (approval_id,) in conn.execute(
        _REMINDERS,
        {
            "t": tenant,
            "now": now,
            "floor": REMINDER_FLOOR,
            "everyone": any(d.approvers is None for d in reminding),
            "approvers": approvers,
            "batch": FOLLOWUP_BATCH,
        },
    ).all():
        selected, _ = matching_destinations(conn, tenant, approval_id, reminding, "reminder")
        for destination in selected:
            queued += conn.execute(
                _QUEUE_REMINDER,
                {
                    "t": tenant,
                    "n": uuid5(approval_id, destination.destination_id + "#reminder"),
                    "a": approval_id,
                    "d": destination.destination_id,
                    "now": now,
                },
            ).rowcount
    return int(queued)


def _enqueue_followups(
    conn: Connection, tenant: UUID, now: datetime, destinations: Sequence[Destination]
) -> int:
    """Queue each due reminder and close-out for the destinations that list it; returns how many.

    Run in its own short transaction under the tenant fence at the start of a drain. A row's id
    is `uuid5(approval_id, destination_id + "#reminder")` or `+ "#closed"`: `#` is outside the
    destination id alphabet, so it can never equal an announcement's id, and `ON CONFLICT DO
    NOTHING` over every key makes two racing drains queue one row.
    """
    queued = 0
    reminding = [d for d in destinations if "reminder" in d.messages]
    if reminding:
        queued += _enqueue_reminders(conn, tenant, now, reminding)
    closing = sorted(d.destination_id for d in destinations if "closed" in d.messages)
    if not closing:
        return queued
    for found in (
        conn.execute(
            _CLOSE_OUTS,
            {
                "t": tenant,
                "now": now,
                "closing": closing,
                "grace": CLOSE_GRACE,
                "batch": FOLLOWUP_BATCH,
            },
        )
        .mappings()
        .all()
    ):
        queued += conn.execute(
            _QUEUE_CLOSE_OUT,
            {
                "t": tenant,
                "n": uuid5(found["approval_id"], found["destination_id"] + "#closed"),
                "a": found["approval_id"],
                "d": found["destination_id"],
                "o": found["outcome"],
                "c": found["closed_at"],
                "now": now,
            },
        ).rowcount
    return int(queued)


def _settle(conn: Connection, params: dict[str, Any], code: str) -> None:
    """Settle a claimed row FAILED with `code`, unsent, its attempts and next time untouched."""
    conn.execute(
        text("""UPDATE execbound.approval_notifications SET state='FAILED',
        last_error=:code, lease_until=NULL, lease_token=NULL
        WHERE tenant_id=:t AND notification_id=:n"""),
        {**params, "code": code},
    )


def deliver_pending(
    db: Database,
    admin: Identity | ScheduledActor,
    destinations: Sequence[Destination],
    *,
    limit: int = 50,
    approval_url: str = "",
    clock: Clock | None = None,
    mail: MailConfig | None = None,
    tls_context: ssl.SSLContext | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    approval_path: Callable[[UUID, UUID], str] | None = None,
) -> dict[str, int]:
    """Lease and send pending notifications; failure is recorded, retried and finally visible.

    `mail` is the deployment's relay and is required when the tenant has an email
    destination; `tls_context` is the system trust store unless a caller passes one. A chat
    destination receives at most one message per second within a drain, the rate Slack
    documents for incoming webhooks; `sleep` and `monotonic` are injectable for the tests.
    `approval_path` is a loaded plugin's own link builder, threaded through to every
    rendered message.
    """
    clock = clock or SystemClock()
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ExecutionError("INVALID_LIMIT")
    by_id = {
        d.destination_id: d
        for d in destinations
        if d.tenant_id == admin.tenant_id and announces_approvals(d)
    }
    email_ids = sorted(d.destination_id for d in by_id.values() if d.kind == "email")
    if email_ids and type(mail) is not MailConfig:
        # A caller's mistake, refused before anything is leased rather than failed row by row.
        raise ExecutionError("INVALID_CONFIGURATION")
    # The one cap counts every email destination of the workspace, findings ones too (#31).
    counted = email_destination_ids(destinations, admin.tenant_id)
    counts = {"delivered": 0, "failed": 0, "closed": 0}
    last_chat: dict[str, float] = {}
    following = sorted(
        (d for d in by_id.values() if d.messages & {"reminder", "closed"}),
        key=lambda d: d.destination_id,
    )
    try:
        if following:
            # Follow-ups are queued in their own short transaction before anything is leased,
            # so this drain may send them too (#678).
            with db.transaction(admin.tenant_id) as conn:
                _admin(conn, admin, clock)
                _enqueue_followups(conn, admin.tenant_id, store.now(clock), following)
                _admin(conn, admin, clock)
        with guarded_client() as client:
            for _ in range(limit):
                lease = uuid4()
                with db.transaction(admin.tenant_id) as conn:
                    _admin(conn, admin, clock)
                    now = store.now(clock)
                    row = (
                        conn.execute(
                            text("""
                        SELECT n.*, a.state AS approval_state,
                               a.expires_at AS approval_expires_at
                        FROM execbound.approval_notifications n
                        JOIN execbound.approvals a
                          ON a.tenant_id=n.tenant_id AND a.approval_id=n.approval_id
                        WHERE n.tenant_id=:t AND (
                          (n.state='PENDING' AND n.next_attempt_at<=:now)
                          OR (n.state='IN_FLIGHT' AND n.lease_until<=:now))
                        ORDER BY n.next_attempt_at, n.notification_id
                        LIMIT 1 FOR UPDATE OF n SKIP LOCKED
                        """),
                            {"t": admin.tenant_id, "now": now},
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if row is None:
                        break
                    notification = dict(row)
                    params: dict[str, Any] = {
                        "t": admin.tenant_id,
                        "n": row["notification_id"],
                        "lease": lease,
                        "until": now + timedelta(seconds=30),
                    }
                    destination = by_id.get(row["destination_id"])
                    kind = row["kind"]
                    # A close-out exists because its approval closed: neither the closed rule
                    # nor the lapse margin applies to it, and its retries have no deadline.
                    announces = kind != "approval.closed"
                    # The last moment a message can usefully arrive: delivery, a retry and a
                    # deferral all stop here, read from the stored approval (#678).
                    cutoff = row["approval_expires_at"] - LAPSE_MARGIN if announces else None
                    closed = announces and row["approval_state"] != "PENDING"
                    lapsing = cutoff is not None and not closed and cutoff <= now
                    # A row whose message its destination no longer lists, queued before a
                    # restart with a changed configuration, is never sent.
                    switched_off = (
                        destination is not None and KIND_MESSAGE[kind] not in destination.messages
                    )
                    if (
                        closed
                        or lapsing
                        or destination is None
                        or switched_off
                        or row["attempts"] >= MAX_ATTEMPTS
                    ):
                        code = (
                            "APPROVAL_CLOSED"
                            if closed
                            else "LAPSED_BEFORE_DELIVERY"
                            if lapsing
                            else "DESTINATION_UNKNOWN"
                            if destination is None
                            else "MESSAGE_OFF"
                            if switched_off
                            else "DELIVERY_UNCERTAIN"
                        )
                        _settle(conn, params, code)
                        counts["closed" if closed or lapsing else "failed"] += 1
                        continue
                    followup = kind != "approval.pending"
                    if (
                        destination.kind == "email"
                        and mail is not None
                        and followup
                        and email_capped(
                            conn,
                            admin.tenant_id,
                            now,
                            mail,
                            counted,
                            reserve=announcement_reserve(mail),
                        )
                    ):
                        # A follow-up never spends the last tenth of the cap, and is refused
                        # rather than deferred: an hour late, it would only be noise.
                        _settle(conn, params, "RATE_LIMITED")
                        counts["failed"] += 1
                        continue
                    if (
                        destination.kind == "email"
                        and mail is not None
                        and not followup
                        and email_capped(conn, admin.tenant_id, now, mail, counted)
                    ):
                        # The cap defers an hour where the approval would still be open, and
                        # fails at once where it would not: either way the row keeps its
                        # attempts, and a deferral never lands past the deadline.
                        deferred = now + timedelta(hours=1)
                        if cutoff is None or deferred >= cutoff:
                            _settle(conn, params, "RATE_LIMITED")
                            counts["failed"] += 1
                            continue
                        conn.execute(
                            text("""UPDATE execbound.approval_notifications SET state='PENDING',
                            next_attempt_at=:next, last_error='RATE_LIMITED',
                            lease_until=NULL, lease_token=NULL
                            WHERE tenant_id=:t AND notification_id=:n"""),
                            {**params, "next": deferred},
                        )
                        continue
                    approval = (
                        conn.execute(
                            text(
                                "SELECT * FROM execbound.approvals "
                                "WHERE tenant_id=:t AND approval_id=:a"
                            ),
                            {"t": admin.tenant_id, "a": row["approval_id"]},
                        )
                        .mappings()
                        .one()
                    )
                    # A reminder is the announcement again under its own kind; a close-out is
                    # built from the announcement's reads.
                    announcement = approval_message(
                        conn,
                        admin.tenant_id,
                        dict(approval),
                        approval_url,
                        approval_path=approval_path,
                        sent_at=now,
                        kind=kind if announces else "approval.pending",
                    )
                    message: ApprovalMessage | ClosedMessage = (
                        announcement
                        if announces
                        else closed_message(
                            announcement,
                            outcome=row["outcome"],
                            closed_at=row["closed_at"],
                            # Threaded under the announcement this destination received.
                            pending_delivery_id=(
                                uuid5(row["approval_id"], row["destination_id"])
                                if "pending" in destination.messages
                                else None
                            ),
                        )
                    )
                    body = b""
                    if destination.kind == "webhook":
                        try:
                            body = (
                                webhook_body(message)
                                if isinstance(message, ApprovalMessage)
                                else closed_body(message)
                            )
                        except ValueError:
                            raise ExecutionError("INVALID_NOTIFICATION") from None
                    conn.execute(
                        text("""UPDATE execbound.approval_notifications SET state='IN_FLIGHT',
                        attempts=attempts+1, lease_token=:lease, lease_until=:until
                        WHERE tenant_id=:t AND notification_id=:n"""),
                        params,
                    )
                    _admin(conn, admin, clock)
                if destination.kind in CHAT_KINDS:
                    previous = last_chat.get(destination.destination_id)
                    if previous is not None and (wait := 1.0 - (monotonic() - previous)) > 0:
                        sleep(wait)
                    last_chat[destination.destination_id] = monotonic()
                result = _send(
                    destination,
                    notification["notification_id"],
                    message,
                    body,
                    client,
                    mail,
                    tls_context,
                    clock,
                )
                with db.transaction(admin.tenant_id) as conn:
                    _admin(conn, admin, clock)
                    attempts = notification["attempts"] + 1
                    settled = store.now(clock)
                    delay = result.retry_after or BACKOFF[min(attempts, MAX_ATTEMPTS) - 1]
                    retry = settled + timedelta(seconds=delay)
                    if result.delivered:
                        conn.execute(
                            text("""UPDATE execbound.approval_notifications
                            SET state='DELIVERED', delivered_at=:now, lease_until=NULL,
                                lease_token=NULL, last_error=NULL
                            WHERE tenant_id=:t AND notification_id=:n AND lease_token=:lease"""),
                            {**params, "now": settled},
                        )
                        counts["delivered"] += 1
                        state = "DELIVERED"
                    elif attempts >= MAX_ATTEMPTS or (cutoff is not None and retry >= cutoff):
                        # Out of attempts, or the next one could not arrive in time: the row
                        # fails with the attempt's own code, so a broken receiver stays visible
                        # as a failure rather than a lapse.
                        conn.execute(
                            text("""UPDATE execbound.approval_notifications
                            SET state='FAILED', last_error=:code,
                                lease_until=NULL, lease_token=NULL
                            WHERE tenant_id=:t AND notification_id=:n AND lease_token=:lease"""),
                            {**params, "code": result.code},
                        )
                        counts["failed"] += 1
                        state = "FAILED"
                    else:
                        conn.execute(
                            text("""UPDATE execbound.approval_notifications
                            SET state='PENDING', next_attempt_at=:next, last_error=:code,
                                lease_until=NULL, lease_token=NULL
                            WHERE tenant_id=:t AND notification_id=:n AND lease_token=:lease"""),
                            {
                                **params,
                                "code": result.code,
                                "next": retry,
                            },
                        )
                        state = "PENDING"
                    _admin(conn, admin, clock)
                # One line per attempt, once it is settled: the state the row is left in and
                # the attempt's code. Never the destination's URL or secret, nor the message.
                log_event(
                    "notifications.delivered",
                    level="INFO" if result.delivered else "WARNING",
                    tenant_id=admin.tenant_id,
                    approval_id=notification["approval_id"],
                    destination_id=destination.destination_id,
                    state=state,
                    attempts=attempts,
                    code=result.code,
                )
        return counts
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None


def destination_tenants(destinations: Sequence[Destination]) -> list[UUID]:
    """The workspaces a scheduled drain visits (#503): every one an approval can be announced
    to. A row is queued only for a configured destination, so no other workspace can have
    anything to deliver; audit-export and findings-only destinations announce nothing and are
    left out."""
    return sorted({d.tenant_id for d in destinations if announces_approvals(d)})


def notify_scheduled(
    db: Database,
    tenant: UUID,
    destinations: Sequence[Destination],
    *,
    limit: int = 50,
    approval_url: str = "",
    mail: MailConfig | None = None,
    clock: Clock | None = None,
    tls_context: ssl.SSLContext | None = None,
    approval_path: Callable[[UUID, UUID], str] | None = None,
) -> dict[str, int]:
    """One workspace's drain for the scheduled pass (#503), with no workspace credential.

    `approval_path` is a loaded plugin's own link builder, as for `deliver_pending`: the
    scheduled drain links to the same address an administrator's drain would.
    """
    return dict(
        deliver_pending(
            db,
            ScheduledActor(tenant),
            destinations,
            limit=limit,
            approval_url=approval_url,
            mail=mail,
            clock=clock,
            tls_context=tls_context,
            approval_path=approval_path,
        )
    )


# A row whose destination this configuration does not name is settled only once it is older
# than the drain's whole retry schedule. The recover cron reads its own copy of the private
# configuration; if that copy ever lags the notify cron's, a live row is still delivered first.
ORPHAN_AFTER = timedelta(days=1)


def settle_orphaned(
    db: Database,
    actor: ScheduledActor,
    destinations: Sequence[Destination],
    *,
    clock: Clock | None = None,
) -> int:
    """Settle, sending nothing, queued rows whose approval is closed, and rows whose
    destination is gone (older than `ORPHAN_AFTER`) (#503).

    The scheduled drain visits only workspaces that still have a destination, so a row whose
    destination was removed, or whose approval closed after its workspace's last destination
    went, would read "notification pending" on its approval for ever. The recovery pass visits
    every workspace and settles both kinds with the drain's own codes. A close-out row is never
    settled as closed, since it exists because its approval closed. The first kind includes
    rows a drain would also reach, which is harmless: nothing is sent, and the drain would
    settle the row the same way. A row a drain holds under a live lease is left to that
    drain, and a row whose destination is merely absent from this copy of the configuration
    is left until it is older than `ORPHAN_AFTER`.
    """
    clock = clock or SystemClock()
    configured = sorted(
        d.destination_id
        for d in destinations
        if d.tenant_id == actor.tenant_id and announces_approvals(d)
    )
    with db.transaction(actor.tenant_id) as conn:
        _admin(conn, actor, clock)
        now = store.now(clock)
        params = {"t": actor.tenant_id, "now": now, "ids": configured}
        closed = conn.execute(
            text("""
            UPDATE execbound.approval_notifications n SET state = 'FAILED',
                   last_error = 'APPROVAL_CLOSED', lease_until = NULL, lease_token = NULL
              FROM execbound.approvals a
             WHERE n.tenant_id = :t AND a.tenant_id = n.tenant_id
               AND a.approval_id = n.approval_id AND a.state <> 'PENDING'
               AND n.kind <> 'approval.closed'
               AND (n.state = 'PENDING' OR (n.state = 'IN_FLIGHT' AND n.lease_until <= :now))
            """),
            params,
        ).rowcount
        unknown = conn.execute(
            text("""
            UPDATE execbound.approval_notifications SET state = 'FAILED',
                   last_error = 'DESTINATION_UNKNOWN', lease_until = NULL, lease_token = NULL
             WHERE tenant_id = :t AND NOT (destination_id = ANY(CAST(:ids AS text[])))
               AND (state = 'PENDING' OR (state = 'IN_FLIGHT' AND lease_until <= :now))
               AND created_at <= :settled
            """),
            {**params, "settled": now - ORPHAN_AFTER},
        ).rowcount
    return int(closed) + int(unknown)


def list_notifications(
    db: Database, admin: Identity, *, state: str | None = None, clock: Clock | None = None
) -> list[NotificationRow]:
    clock = clock or SystemClock()
    if state is not None and state not in {"PENDING", "IN_FLIGHT", "DELIVERED", "FAILED"}:
        raise ExecutionError("INVALID_STATE")
    try:
        with db.transaction(admin.tenant_id) as conn:
            _admin(conn, admin, clock)
            rows = (
                conn.execute(
                    text(
                        "SELECT notification_id, approval_id, destination_id, kind, state, "
                        "attempts, "
                        "created_at, next_attempt_at, delivered_at, last_error "
                        "FROM execbound.approval_notifications WHERE tenant_id=:t "
                        "AND (CAST(:state AS text) IS NULL OR state=:state) "
                        "ORDER BY created_at DESC, notification_id LIMIT 200"
                    ),
                    {"t": admin.tenant_id, "state": state},
                )
                .mappings()
                .all()
            )
        return [NotificationRow(**dict(row)) for row in rows]
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None


# A row the drain closed because its approval was no longer pending (`APPROVAL_CLOSED`), read
# by how the approval ended: the sweep ended it before anyone met its quorum (lapsed), it was
# decided first, or approved and then left unused (closed), or the request stopped being
# valid before anyone decided it (withdrawn). The quorum counts approving decisions against
# `required_approvers`, as the decision itself does.
_SUMMARY = """
SELECT n.state, n.last_error, a.state AS approval_state,
       (SELECT count(*) FROM execbound.approval_decisions d
         WHERE d.tenant_id = a.tenant_id AND d.approval_id = a.approval_id
           AND d.decision = 'APPROVE') >= a.required_approvers AS met,
       count(*) AS rows
  FROM execbound.approval_notifications n
  JOIN execbound.approvals a ON a.tenant_id = n.tenant_id AND a.approval_id = n.approval_id
 WHERE n.tenant_id = :t AND n.approval_id = :a AND n.kind = 'approval.pending'
 GROUP BY n.state, n.last_error, a.state, met
"""


def _closed_key(approval_state: str, met: bool) -> str:
    if approval_state == "INVALIDATED":
        return "withdrawn"
    if approval_state == "EXPIRED":
        return "closed" if met else "lapsed"
    return "closed" if approval_state in {"APPROVED", "DENIED", "CONSUMED"} else "failed"


def summary(conn: Connection, tenant: UUID, approval_id: UUID) -> dict[str, int]:
    """Announcement counts for one approval, for the approvals page.

    Only `approval.pending` rows count, so a follow-up never reads as another destination
    notified. A row closed unsent because the approval would have lapsed before it arrived is
    `lapsed`, apart from `failed`: nobody's receiver failed (#678). So is a row the recovery
    run's sweep beat to it, while the quorum was not met. A row the drain closed because the
    approval was decided first, or approved and then left unused, is `closed`, and one whose
    request stopped being valid before anyone decided it is `withdrawn`.
    """
    counts = {"delivered": 0, "pending": 0, "failed": 0, "lapsed": 0, "closed": 0, "withdrawn": 0}
    for state, code, approval_state, met, count in conn.execute(
        text(_SUMMARY), {"t": tenant, "a": approval_id}
    ):
        if state == "FAILED" and code == "LAPSED_BEFORE_DELIVERY":
            key = "lapsed"
        elif state == "FAILED" and code == "APPROVAL_CLOSED":
            key = _closed_key(str(approval_state), bool(met))
        else:
            key = {"DELIVERED": "delivered", "FAILED": "failed"}.get(state, "pending")
        counts[key] += int(count)
    return counts


@dataclass(frozen=True)
class DeliveryTimes:
    """When an approval's announcements were first queued and last delivered, for its page."""

    queued_at: datetime | None
    last_delivered_at: datetime | None


def delivery_times(conn: Connection, tenant: UUID, approval_id: UUID) -> DeliveryTimes:
    """Over the approval's `approval.pending` rows only, read inside the caller's fence."""
    found = (
        conn.execute(
            text(
                "SELECT min(created_at) AS queued_at, max(delivered_at) AS last_delivered_at "
                "FROM execbound.approval_notifications "
                "WHERE tenant_id=:t AND approval_id=:a AND kind='approval.pending'"
            ),
            {"t": tenant, "a": approval_id},
        )
        .mappings()
        .one()
    )
    return DeliveryTimes(found["queued_at"], found["last_delivered_at"])
