# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit bounded worker: evaluation, and findings delivery's router and drain (#31). A
delivery's lease never owns protected execution, and a send never touches a finding, an approval
or an execution."""

import ssl
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Any
from uuid import UUID, uuid4, uuid5

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.db import Database
from execbound.egress import guarded_client
from execbound.execution.scheduled import ScheduledActor
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.monitoring.delivery import FINDING_RULES, LocalReceiver, post_signed
from execbound.monitoring.models import DELIVERY_STATES, MonitorError
from execbound.monitoring.store import (
    DEPENDENCY_ERRORS,
    _check_actor,
    _now,
    check_admin,
    derive_reach,
    evaluate_actions,
    evaluate_health,
    evaluate_pending,
    purge_audit_observations,
)
from execbound.notifications import (
    BACKOFF,
    FINDINGS,
    MAX_ATTEMPTS,
    Destination,
    announcement_reserve,
    email_capped,
    email_destination_ids,
)
from execbound.resolution.models import Clock, SystemClock
from execbound.transports import (
    CHAT_KINDS,
    FindingMessage,
    MailConfig,
    SendResult,
    deliver_email,
    finding_body,
    post_chat,
    render_email,
    render_slack,
    render_teams,
)

SYSTEM_CLOCK = SystemClock()


@dataclass(frozen=True)
class Outbound:
    """Where findings go (#31): the deployment's destinations, its relay and its origin.

    Read from the private configuration by `configuration.read_outbound`, or made for the
    loopback receiver by `local_outbound`. `tls_context` is the system trust store unless a
    caller passes one; the tests pass one that trusts the CA they mint.
    """

    destinations: tuple[Destination, ...]
    origin: str
    mail: MailConfig | None = None
    tls_context: ssl.SSLContext | None = field(default=None, repr=False, compare=False)


# The kinds a finding is sent through; the audit export (`security-events`) sends none.
FINDING_KINDS = frozenset({"webhook", "email", "slack", "teams"})
# An intent first routed more than a day after the intent was written is closed unsent (#31,
# decision 5): turning delivery on never floods a channel with old findings, which stay in the
# console. It is the intent's age, which can differ from the finding's, as where a finding
# waited for a baseline.
TOO_OLD = timedelta(hours=24)
# At most this many intents more than a day old are closed in one statement before a pass takes
# its batch, oldest first. A pass routes fifty intents, so without it a backlog above about
# 14,000 in one workspace would hold every new finding back until it too was a day old, and then
# close it unsent. Bounded, so a pass over any backlog stays one short statement.
STALE_BATCH = 5000

# The acknowledgement is recorded before the age, as the batch records it (ruling 1). The ids
# are chosen once, oldest first, skipping an intent another router holds as the batch does, so
# two routers at once never wait on each other; the update checks the state again. They are a
# `MATERIALIZED` CTE, not an `IN (...)` subquery: the planner may rescan such a subquery for
# every row it joins, and each rescan of a `LIMIT ... FOR UPDATE SKIP LOCKED` can pick rows the
# last one did not, so the bound would not hold.
_CLOSE_STALE = text("""
    WITH stale AS MATERIALIZED (
        SELECT s.delivery_id
          FROM execbound.monitor_deliveries s
         WHERE s.tenant_id = :t AND s.destination_id IS NULL AND s.state = 'PENDING'
           AND s.created_at < :stale
         ORDER BY s.created_at, s.delivery_id
         LIMIT :n
           FOR UPDATE SKIP LOCKED
    )
    UPDATE execbound.monitor_deliveries d
       SET state = 'FAILED',
           last_error = CASE WHEN f.acknowledged_at IS NOT NULL THEN 'FINDING_ACKNOWLEDGED'
                             ELSE 'TOO_OLD_TO_SEND' END
      FROM stale, execbound.monitor_findings f
     WHERE d.tenant_id = :t AND d.delivery_id = stale.delivery_id
       AND d.destination_id IS NULL AND d.state = 'PENDING'
       AND f.tenant_id = d.tenant_id AND f.finding_id = d.finding_id
""")
# `synthetic`: the synthetic directory raised the finding, by its connection or its actor's
# (#355, step 4), so nothing outside the console is told.
_INTENTS = text("""
    SELECT d.delivery_id, d.finding_id, d.created_at, f.rule_version, f.space_id,
           f.acknowledged_at IS NOT NULL AS acknowledged,
           EXISTS (SELECT 1 FROM execbound.monitor_connections c
                   WHERE c.tenant_id = f.tenant_id AND c.kind = 'fixture'
                     AND c.connection_id = coalesce(f.connection_id, (
                         SELECT a.connection_id FROM execbound.monitor_agents a
                         WHERE a.tenant_id = f.tenant_id AND a.agent_id = f.agent_id)))
               AS synthetic
      FROM execbound.monitor_deliveries d
      JOIN execbound.monitor_findings f
        ON f.tenant_id = d.tenant_id AND f.finding_id = d.finding_id
     WHERE d.tenant_id = :t AND d.destination_id IS NULL AND d.state = 'PENDING'
     ORDER BY d.created_at, d.delivery_id
     LIMIT :n
       FOR UPDATE OF d SKIP LOCKED
""")
# A delivery's id is fixed by its finding and destination, and `#` is outside the destination
# id alphabet, so it never equals the intent's `uuid5(finding_id, "delivery")`. The conflict
# clause names no target, so it covers the primary key and the one-per-destination index alike,
# as `notifications._QUEUE_ANNOUNCEMENT` explains for its own table.
_ROUTE = text("""
    INSERT INTO execbound.monitor_deliveries
    (tenant_id, delivery_id, finding_id, destination_id, created_at, next_attempt_at)
    VALUES (:t, :d, :f, :dest, :now, :now)
    ON CONFLICT DO NOTHING
""")
_CLOSE_INTENT = text("""
    UPDATE execbound.monitor_deliveries SET state = :state, last_error = :code
     WHERE tenant_id = :t AND delivery_id = :d AND state = 'PENDING'
""")


def admits(destination: Destination, rule: str, space: UUID) -> bool:
    """Whether a destination receives a finding of `rule` in `space` (#31): it lists `findings`,
    and its `rules` and `spaces`, where it has them, name both."""
    return (
        FINDINGS in destination.classes
        and destination.kind in FINDING_KINDS
        and (destination.rules is None or rule in destination.rules)
        and (destination.spaces is None or space in destination.spaces)
    )


def route_findings(
    db: Database,
    actor: Identity | ScheduledActor,
    destinations: Sequence[Destination],
    *,
    limit: int = 50,
    clock: Clock = SYSTEM_CLOCK,
) -> dict[str, int]:
    """Route up to `limit` pending intents, in one short transaction under the workspace fence.

    Each intent is routed once, to the destinations configured at that moment: one delivery per
    destination that admits its finding, and the intent marked `ROUTED` even where none does, so
    a destination added later receives none of it (no backfill, #31). An intent whose finding was
    acknowledged first is closed `FINDING_ACKNOWLEDGED`, and one first routed more than a day
    after the intent was written `TOO_OLD_TO_SEND`; neither gets a delivery. Nor does one the
    synthetic directory raised, closed `SYNTHETIC_DIRECTORY` (#355, step 4): its findings are
    seen in the console alone, and the database refuses a destination's delivery of one. Before
    the batch is taken, up to `STALE_BATCH` intents more than a day old are closed in one
    statement, so a backlog larger than the batch never holds a fresh finding back. `SKIP LOCKED`
    and the unique keys make two routers at once write each delivery once.
    """
    if type(limit) is not int or not 1 <= limit <= 50:
        raise MonitorError("INVALID_LIMIT")
    tenant = actor.tenant_id
    eligible = sorted(
        (d for d in destinations if d.tenant_id == tenant), key=lambda d: d.destination_id
    )
    counts = {"routed": 0, "queued": 0, "closed": 0}
    try:
        with db.transaction(tenant) as conn:
            _check_actor(conn, actor, clock)
            now = _now(clock)
            counts["closed"] += conn.execute(
                _CLOSE_STALE, {"t": tenant, "stale": now - TOO_OLD, "n": STALE_BATCH}
            ).rowcount
            for row in conn.execute(_INTENTS, {"t": tenant, "n": limit}).mappings().all():
                params = {"t": tenant, "d": row["delivery_id"]}
                code = (
                    "SYNTHETIC_DIRECTORY"
                    if row["synthetic"]
                    else "FINDING_ACKNOWLEDGED"
                    if row["acknowledged"]
                    else "TOO_OLD_TO_SEND"
                    if row["created_at"] < now - TOO_OLD
                    else None
                )
                if code is not None:
                    conn.execute(_CLOSE_INTENT, {**params, "state": "FAILED", "code": code})
                    counts["closed"] += 1
                    continue
                for destination in eligible:
                    if admits(destination, row["rule_version"], row["space_id"]):
                        counts["queued"] += conn.execute(
                            _ROUTE,
                            {
                                "t": tenant,
                                "d": uuid5(
                                    row["finding_id"], destination.destination_id + "#finding"
                                ),
                                "f": row["finding_id"],
                                "dest": destination.destination_id,
                                "now": now,
                            },
                        ).rowcount
                conn.execute(_CLOSE_INTENT, {**params, "state": "ROUTED", "code": None})
                counts["routed"] += 1
            _check_actor(conn, actor, clock)
    except MonitorError:
        raise
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


# Above the worst-case send (ruling 24): an HTTP send ends inside the egress guard's ten-second
# deadline, and SMTP's ten-second timeout applies to each step of an exchange of a few steps. A
# relay slower than this may be sent to twice; the `Message-ID` collapses the copy.
LEASE = timedelta(seconds=60)
LOCAL_RECEIVER = "local-receiver"
# Over the shared daily email cap a findings email waits an hour, and fails once its delivery
# is a day old (#31): later than that it would only be noise.
EMAIL_DEFER = timedelta(hours=1)
EMAIL_GIVE_UP = timedelta(hours=24)

_DUE = text("""
    SELECT d.delivery_id, d.finding_id, d.destination_id, d.attempts, d.created_at,
           f.rule_version, f.source_id, f.connection_id, f.observation_id, f.agent_id,
           f.profile_version, f.space_id, f.created_at AS raised_at,
           f.acknowledged_at IS NOT NULL AS acknowledged
      FROM execbound.monitor_deliveries d
      JOIN execbound.monitor_findings f
        ON f.tenant_id = d.tenant_id AND f.finding_id = d.finding_id
     WHERE d.tenant_id = :t AND d.destination_id IS NOT NULL
       AND ((d.state = 'PENDING' AND d.next_attempt_at <= :now)
            OR (d.state = 'IN_FLIGHT' AND d.lease_until <= :now))
     ORDER BY d.next_attempt_at, d.delivery_id
     LIMIT 1
       FOR UPDATE OF d SKIP LOCKED
""")
_CLOSE = text("""
    UPDATE execbound.monitor_deliveries SET state = 'FAILED', last_error = :code,
           lease_until = NULL, lease_token = NULL
     WHERE tenant_id = :t AND delivery_id = :d
""")
_LEASE = text("""
    UPDATE execbound.monitor_deliveries SET state = 'IN_FLIGHT', attempts = attempts + 1,
           lease_token = :lease, lease_until = :until
     WHERE tenant_id = :t AND delivery_id = :d
""")
_SETTLE = text("""
    UPDATE execbound.monitor_deliveries SET state = :state, delivered_at = :done,
           next_attempt_at = :next, last_error = :code, lease_token = NULL, lease_until = NULL
     WHERE tenant_id = :t AND delivery_id = :d AND state = 'IN_FLIGHT' AND lease_token = :lease
""")
_DEFER = text("""
    UPDATE execbound.monitor_deliveries SET state = 'PENDING', next_attempt_at = :next,
           last_error = 'RATE_LIMITED', lease_until = NULL, lease_token = NULL
     WHERE tenant_id = :t AND delivery_id = :d
""")


def local_outbound(receiver: LocalReceiver, tenant: UUID, origin: str) -> Outbound:
    """The loopback test receiver as one findings destination (`process --deliver-local`): a
    signed webhook, findings only, routed and drained like any other (#31)."""
    local = Destination(
        LOCAL_RECEIVER, tenant, receiver.url, receiver.secret, classes=frozenset({FINDINGS})
    )
    return Outbound((local,), origin)


# The closings that say the delivery was no longer wanted, counted `closed` and logged at INFO:
# a person's acknowledgement, or the operator's own change of configuration. A fifth lease that
# expired unsettled and a capped email given up are counted `failed` and logged at WARNING.
UNSENT = frozenset({"DESTINATION_UNKNOWN", "CLASS_OFF", "FINDING_ACKNOWLEDGED"})


def _closing(destination: Destination | None, row: Mapping[str, Any]) -> str | None:
    """Why a leased delivery is closed unsent, or None to send it (#31, rulings 1 and 4)."""
    if destination is None:
        return "DESTINATION_UNKNOWN"
    if FINDINGS not in destination.classes or destination.kind not in FINDING_KINDS:
        return "CLASS_OFF"
    if row["acknowledged"]:
        return "FINDING_ACKNOWLEDGED"
    if row["attempts"] >= MAX_ATTEMPTS:
        return "DELIVERY_UNCERTAIN"
    return None


def _message(conn: Connection, tenant: UUID, row: Mapping[str, Any], origin: str) -> FindingMessage:
    """The message for one leased delivery, read under its lease: the finding's identifiers
    and rule, and the workspace's and Space's names from their own rows (#31). Both names are
    never null, and a finding's Space is its workspace's, so each is read as exactly one row."""
    workspace = conn.execute(
        text("SELECT name FROM execbound.tenants WHERE tenant_id = :t"), {"t": tenant}
    ).scalar_one()
    space = conn.execute(
        text("SELECT name FROM execbound.spaces WHERE tenant_id = :t AND space_id = :s"),
        {"t": tenant, "s": row["space_id"]},
    ).scalar_one()
    return FindingMessage(
        tenant_id=tenant,
        finding_id=row["finding_id"],
        delivery_id=row["delivery_id"],
        rule_version=row["rule_version"],
        rule_label=FINDING_RULES[row["rule_version"]],
        created_at=row["raised_at"],
        origin=origin,
        workspace=str(workspace),
        space=str(space),
        source_id=row["source_id"],
        connection_id=row["connection_id"],
        observation_id=row["observation_id"],
        agent_id=row["agent_id"],
        profile_version=row["profile_version"],
    )


def _render(
    destination: Destination, message: FindingMessage, outbound: Outbound
) -> bytes | EmailMessage:
    """What one attempt sends, rendered under the lease (ruling 25), so a message that cannot be
    rendered is refused before an attempt is spent, as the approval drain renders its webhook
    body."""
    try:
        if destination.kind == "email":
            if outbound.mail is None or destination.to is None:
                raise MonitorError("INVALID_CONFIGURATION")
            return render_email(outbound.mail, destination.to, message.delivery_id, message)
        if destination.kind == "slack":
            return render_slack(message.delivery_id, message)
        if destination.kind == "teams":
            return render_teams(message.delivery_id, message)
        return finding_body(message)
    except MonitorError:
        # A `MonitorError` is a `ValueError`: it keeps its own code.
        raise
    except ValueError:
        raise MonitorError("INVALID_NOTIFICATION") from None


def _send(
    destination: Destination,
    delivery_id: UUID,
    rendered: bytes | EmailMessage,
    client: httpx.Client,
    outbound: Outbound,
    clock: Clock,
) -> SendResult:
    """One attempt of what `_render` built, through the destination's kind. Email goes to the
    operator's relay by the mail path, with the relay's TLS context; only the webhook and chat
    kinds go through `client`, the egress guard's, which never sees that context. A receiver's
    `Retry-After` date is measured from the drain's `clock`."""
    if isinstance(rendered, EmailMessage):
        if outbound.mail is None or destination.to is None:
            raise MonitorError("INVALID_CONFIGURATION")
        return deliver_email(outbound.mail, destination.to, rendered, context=outbound.tls_context)
    if destination.kind in CHAT_KINDS:
        return post_chat(
            destination.kind, destination.url, delivery_id, rendered, client, clock=clock
        )
    return post_signed(destination, delivery_id, rendered, client, clock=clock)


def deliver_findings(
    db: Database,
    actor: Identity | ScheduledActor,
    outbound: Outbound,
    *,
    limit: int = 50,
    clock: Clock = SYSTEM_CLOCK,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, int]:
    """Lease and send up to `limit` due deliveries, one at a time; a failure is recorded,
    retried and finally visible (#31).

    A delivery is closed unsent when its destination is gone (`DESTINATION_UNKNOWN`), no longer
    lists `findings` (`CLASS_OFF`) or its finding was acknowledged (`FINDING_ACKNOWLEDGED`). A send
    is at most five attempts, 5, 25, 125 and 625 s apart on the approval drain's backoff, a 429
    waiting its `Retry-After` (a date in it read against `clock`); a fifth lease that expired
    unsettled ends `DELIVERY_UNCERTAIN` with no sixth send. An email over the findings' share of the
    one daily cap, which keeps its last tenth for approval announcements, waits an hour before
    anything is leased, spending no attempt, and fails `RATE_LIMITED` once its delivery is a day
    old. The delivery id never changes, so a receiver deduplicates on it. A chat destination gets at
    most one message a second within a drain; `sleep` and `monotonic` are the tests'. Every body is
    rendered under the lease, and every HTTP send goes through the egress guard inside its
    ten-second deadline. A settle that finds the lease gone writes, counts and logs nothing: the
    drain that leased the row again settles it. A delivery closed unsent, or given up at the cap,
    logs its closing as a settled attempt does. Nothing here touches the finding, an approval or an
    execution.
    """
    if type(limit) is not int or not 1 <= limit <= 50:
        raise MonitorError("INVALID_LIMIT")
    tenant = actor.tenant_id
    by_id = {d.destination_id: d for d in outbound.destinations if d.tenant_id == tenant}
    if type(outbound.mail) is not MailConfig and any(
        d.kind == "email" and FINDINGS in d.classes for d in by_id.values()
    ):
        # A caller's mistake, refused before anything is leased rather than failed row by row.
        raise MonitorError("INVALID_CONFIGURATION")
    # The one cap counts every email destination of the workspace, approval ones too.
    counted = email_destination_ids(outbound.destinations, tenant)
    counts = {"delivered": 0, "failed": 0, "closed": 0}
    last_chat: dict[str, float] = {}
    try:
        with guarded_client() as client:
            for _ in range(limit):
                lease = uuid4()
                with db.transaction(tenant) as conn:
                    _check_actor(conn, actor, clock)
                    now = _now(clock)
                    found = conn.execute(_DUE, {"t": tenant, "now": now}).mappings().one_or_none()
                    if found is None:
                        break
                    row = dict(found)
                    params: dict[str, Any] = {
                        "t": tenant,
                        "d": row["delivery_id"],
                        "lease": lease,
                        "until": now + LEASE,
                    }
                    destination = by_id.get(row["destination_id"])
                    closed = _closing(destination, row)
                    if (
                        closed is None
                        and destination is not None
                        and destination.kind == "email"
                        and outbound.mail is not None
                        and email_capped(
                            conn,
                            tenant,
                            now,
                            outbound.mail,
                            counted,
                            reserve=announcement_reserve(outbound.mail),
                        )
                    ):
                        # Never the last tenth of the cap, which stays for announcements; the
                        # row keeps its attempts either way.
                        if now - row["created_at"] < EMAIL_GIVE_UP:
                            conn.execute(_DEFER, {**params, "next": now + EMAIL_DEFER})
                            continue
                        closed = "RATE_LIMITED"
                    if closed is not None or destination is None:
                        conn.execute(_CLOSE, {**params, "code": closed})
                    else:
                        try:
                            message = _message(conn, tenant, row, outbound.origin)
                        except ValueError:
                            raise MonitorError("INVALID_NOTIFICATION") from None
                        rendered = _render(destination, message, outbound)
                        conn.execute(_LEASE, params)
                        _check_actor(conn, actor, clock)
                if closed is not None or destination is None:
                    # Closed unsent, once that is committed: one line as a settled attempt
                    # writes, since an operator needs the uncertain one most of all (a send may
                    # have landed). A deferral is neither a closing nor an attempt.
                    counts["closed" if closed in UNSENT else "failed"] += 1
                    log_event(
                        "monitor.delivered",
                        level="INFO" if closed in UNSENT else "WARNING",
                        tenant_id=tenant,
                        finding_id=row["finding_id"],
                        destination_id=row["destination_id"],
                        state="FAILED",
                        attempts=int(row["attempts"]),
                        code=closed,
                    )
                    continue
                if destination.kind in CHAT_KINDS:
                    previous = last_chat.get(destination.destination_id)
                    if previous is not None and (wait := 1.0 - (monotonic() - previous)) > 0:
                        sleep(wait)
                    last_chat[destination.destination_id] = monotonic()
                # A crash here leaves a lease that expires; the next drain resends the same id.
                result = _send(destination, row["delivery_id"], rendered, client, outbound, clock)
                with db.transaction(tenant) as conn:
                    _check_actor(conn, actor, clock)
                    attempts = int(row["attempts"]) + 1
                    settled = _now(clock)
                    if result.delivered:
                        state, done, retry = "DELIVERED", settled, settled
                    elif attempts >= MAX_ATTEMPTS:
                        state, done, retry = "FAILED", None, settled
                    else:
                        delay = result.retry_after or BACKOFF[attempts - 1]
                        state, done, retry = "PENDING", None, settled + timedelta(seconds=delay)
                    written = conn.execute(
                        _SETTLE,
                        {
                            **params,
                            "state": state,
                            "done": done,
                            "next": retry,
                            "code": result.code,
                        },
                    ).rowcount
                    _check_actor(conn, actor, clock)
                if not written:
                    # The lease expired during the send and another drain took the row: what
                    # this attempt would have written is not the row's state, so it is neither
                    # counted nor logged.
                    continue
                if state == "DELIVERED":
                    counts["delivered"] += 1
                elif state == "FAILED":
                    counts["failed"] += 1
                # One line per settled attempt: identifiers, the state and the attempt's code;
                # never a destination's URL, address or secret, nor the message.
                log_event(
                    "monitor.delivered",
                    level="INFO" if result.delivered else "WARNING",
                    tenant_id=tenant,
                    finding_id=row["finding_id"],
                    destination_id=destination.destination_id,
                    state=state,
                    attempts=attempts,
                    code=result.code,
                )
    except MonitorError:
        raise
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


def deliver_scheduled(
    db: Database,
    tenant: UUID,
    outbound: Outbound,
    *,
    limit: int = 50,
    clock: Clock = SYSTEM_CLOCK,
) -> dict[str, int]:
    """The scheduled pass's delivery in one workspace (#31): its pending intents routed and
    its due deliveries sent, as the workspace's scheduled actor with no credential, under the
    workspace's own fence. Every visited workspace routes, so a destination added later gets
    no backfill (ruling 2)."""
    actor = ScheduledActor(tenant)
    routed = route_findings(db, actor, outbound.destinations, limit=limit, clock=clock)
    sent = deliver_findings(db, actor, outbound, limit=limit, clock=clock)
    return {
        "routed": routed["routed"],
        "delivered": sent["delivered"],
        "failed": sent["failed"],
        "closed": routed["closed"] + sent["closed"],
    }


@dataclass(frozen=True)
class DeliveryRow:
    """One row of `monitor_deliveries` as `deliveries` lists it: identifiers, state and codes,
    never a destination's URL, address or secret, nor anything a source reported."""

    delivery_id: UUID
    finding_id: UUID
    destination_id: str | None
    state: str
    attempts: int
    created_at: datetime
    next_attempt_at: datetime
    delivered_at: datetime | None
    last_error: str | None


def list_deliveries(
    db: Database, admin: Identity, *, state: str | None = None, clock: Clock = SYSTEM_CLOCK
) -> list[DeliveryRow]:
    """Every delivery row of the administrator's workspace, intents included, newest first and
    at most 200 (`deliveries`, #31): what `notifications` lists for approvals."""
    if state is not None and state not in DELIVERY_STATES:
        raise MonitorError("INVALID_STATE")
    try:
        with db.transaction(admin.tenant_id) as conn:
            check_admin(conn, admin, clock=clock)
            rows = (
                conn.execute(
                    text(
                        "SELECT delivery_id, finding_id, destination_id, state, attempts, "
                        "created_at, next_attempt_at, delivered_at, last_error "
                        "FROM execbound.monitor_deliveries WHERE tenant_id = :t "
                        "AND (CAST(:state AS text) IS NULL OR state = :state) "
                        "ORDER BY created_at DESC, delivery_id LIMIT 200"
                    ),
                    {"t": admin.tenant_id, "state": state},
                )
                .mappings()
                .all()
            )
    except MonitorError:
        raise
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return [DeliveryRow(**dict(row)) for row in rows]


def process(
    db: Database, identity: Identity, outbound: Outbound | None = None, *, limit: int = 50
) -> dict[str, int]:
    if type(limit) is not int or not 1 <= limit <= 50:
        raise MonitorError("INVALID_LIMIT")
    evaluated = evaluate_pending(db, identity, limit=limit)
    health_changes = evaluate_health(db, identity)
    # Observed and verified reach are read from observations and settled executions here,
    # never written by the execution path, which owns no monitoring row.
    derived = derive_reach(db, identity)
    # An actor's first consequential action is read from the observations just derived (#355).
    actions = evaluate_actions(db, identity)
    delivered = 0
    if outbound is not None:
        try:
            # Routed at drain time, to the destinations configured now (#31).
            route_findings(db, identity, outbound.destinations, limit=limit)
            delivered = deliver_findings(db, identity, outbound, limit=limit)["delivered"]
        except MonitorError:
            # Delivery reads no audit observation, so the purge never waits on it: a finding
            # that cannot be rendered is refused before its lease and comes first again at
            # every pass, so a purge behind it would never run again. The pass still fails with
            # the delivery's code, and a purge that fails as well is tried again at the next.
            with suppress(MonitorError):
                purge_audit_observations(db, identity)
            raise
    # Last, once every rule has read them and what they raised is delivered: the audit
    # observations none reads any more, so a purge that fails never holds back a finding. An
    # evaluation that fails ends the pass before this, since what it raises must cite its
    # observations before the uncited ones go.
    purged = purge_audit_observations(db, identity)
    log_event("monitor.processed", tenant_id=identity.tenant_id, count=evaluated + delivered)
    return {
        "evaluated": evaluated,
        "health_changes": health_changes,
        "delivered": delivered,
        "reach": derived["verified"] + derived["observed"],
        "actions": actions["raised"],
        "purged": purged["purged"],
    }


def evaluate_scheduled(
    db: Database,
    tenant: UUID,
    *,
    limit: int = 50,
    clock: Clock = SYSTEM_CLOCK,
    outbound: Outbound | None = None,
) -> dict[str, int]:
    """The scheduled pass's evaluation in one workspace (#503): its pending observations, its
    sources' health, its derived reach, the actions first observed from it and, last, the purge
    of the directory audit observations no rule reads any more (#355), as the workspace's
    scheduled actor with no credential, each step under the workspace's own fence. Without
    `outbound` it delivers nothing. With it, where `process --deliver` asks, the workspace's
    findings are routed and sent (`deliver_scheduled`, #31) before the purge, as `process`
    sends them, so a purge that fails never keeps a finding from its destination, and a
    delivery that fails never keeps the purge from running: the pass purges, then fails with
    the delivery's code. An evaluation that fails ends the pass with no purge."""
    if type(limit) is not int or not 1 <= limit <= 50:
        raise MonitorError("INVALID_LIMIT")
    actor = ScheduledActor(tenant)
    evaluated = evaluate_pending(db, actor, limit=limit, clock=clock)
    health_changes = evaluate_health(db, actor, clock=clock)
    derived = derive_reach(db, actor, clock=clock)
    actions = evaluate_actions(db, actor, clock=clock)
    outcome = {
        "evaluated": evaluated,
        "health_changes": health_changes,
        "reach": derived["verified"] + derived["observed"],
        "actions": actions["raised"],
    }
    if outbound is not None:
        try:
            outcome |= deliver_scheduled(db, tenant, outbound, limit=limit, clock=clock)
        except MonitorError:
            # As in `process`: delivery reads no audit observation, so a delivery refused at
            # every pass never holds the purge back, and the workspace fails with its code.
            with suppress(MonitorError):
                purge_audit_observations(db, actor, clock=clock)
            raise
    # Last, once every rule has read them and what they raised is sent: the audit observations
    # none reads any more.
    outcome["purged"] = purge_audit_observations(db, actor, clock=clock)["purged"]
    return outcome
