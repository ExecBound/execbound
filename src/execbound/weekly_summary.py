# SPDX-License-Identifier: AGPL-3.0-only
"""The weekly summary (#678): a person's opt-in, its outbox and its drain.

A person turns the summary on under My account. Each Monday `run` queues one message per active
subscription, inside each workspace's own fence (`weekly_summary_enqueue`), then drains the due
messages the way the teammate invitation outbox is drained: listed across tenants as
identifiers alone (`weekly_summary_due`), leased one at a time in the message's own tenant,
sent outside any transaction, and settled with a code-shaped error. The counts are the
recipient's own, read under their authority when the message is sent (`value.for_principal`),
so a person whose authority narrowed gets the narrowed counts and a deactivated one gets none.

Nothing a summary says is a string an agent, a provider or a person wrote, apart from the
workspace name through `safe_label`; it carries one link to the console and the one-click
unsubscribe link RFC 8058 describes, whose fresh 256-bit secret is kept only as its SHA-256.
A week with nothing in it is skipped. Delivery is logged, not audited, as approval
notification delivery is; turning the summary on and off is audited.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import ssl
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database, UnsafeDatabaseRole, check_runtime
from execbound.execution import store
from execbound.logging_schema import log_event
from execbound.resolution.models import Clock, SystemClock
from execbound.transports import (
    MailConfig,
    SendResult,
    WeeklyCounts,
    is_address,
    send_weekly_summary,
)

if TYPE_CHECKING:
    from execbound.runtime import Runtime
    from execbound.surfaces.sessions import Session
    from execbound.surfaces.value import ValueCounts

LINK_PREFIX = "ebw1"
LINK = re.compile(r"ebw1\.([0-9a-f-]{36})\.([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})")
MAX_ATTEMPTS = 5
BACKOFF = (300, 900, 3600, 10800, 43200)
MAX_DRAIN = 50
# A summary not delivered by its Monday plus three days is no longer this week's news.
STALE_AFTER = timedelta(days=3)
DAY = timedelta(days=1)
WEEK = timedelta(days=7)
_TERMINAL = frozenset({"INVALID_ADDRESS"})


class SummaryError(Exception):
    """A refusal by code; the console maps it, and nothing else reaches a person."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def offered(mail: MailConfig | None) -> bool:
    """Whether this deployment sends the summary at all: a relay, with the summary on."""
    return mail is not None and mail.weekly_summary


def week_ending(moment: datetime) -> date:
    """The Monday a run at `moment` reports on: the most recent at or before it, in UTC."""
    day = moment.astimezone(UTC).date()
    return day - timedelta(days=day.weekday())


def _midnight(week: date) -> datetime:
    return datetime(week.year, week.month, week.day, tzinfo=UTC)


def window(week: date) -> tuple[datetime, datetime]:
    """The seven days before that Monday's midnight, UTC."""
    until = _midnight(week)
    return until - WEEK, until


def resolve_address(conn: Connection, tenant: UUID, principal: UUID) -> str | None:
    """The address a person's summary goes to, read inside the tenant's fence.

    A person who reaches the workspace through an account has that account's address, which
    `0059`'s acceptance may have left off the principal (its address is unique globally), so an
    account in a second workspace still has one here. Otherwise the principal's own address,
    and otherwise none. The one implementation: the settings view, the switch and the drain.
    """
    from execbound.user_accounts import account_context

    account = conn.execute(
        text(
            "SELECT account_id FROM execbound.workspace_memberships "
            "WHERE tenant_id=:t AND principal_id=:p AND active ORDER BY created_at LIMIT 1"
        ),
        {"t": tenant, "p": principal},
    ).scalar_one_or_none()
    if account is not None:
        account_context(conn, UUID(str(account)))
        try:
            email = conn.execute(
                text("SELECT email FROM execbound.user_accounts WHERE account_id=:a"),
                {"a": account},
            ).scalar_one_or_none()
        finally:
            conn.execute(text("SELECT set_config('execbound.account_id', '', true)"))
        if email is not None and is_address(email):
            return str(email)
    email = conn.execute(
        text("SELECT email FROM execbound.principals WHERE tenant_id=:t AND principal_id=:p"),
        {"t": tenant, "p": principal},
    ).scalar_one_or_none()
    return str(email) if email is not None and is_address(email) else None


def subscribed(conn: Connection, tenant: UUID, principal: UUID) -> bool:
    return (
        conn.execute(
            text(
                "SELECT ended_at IS NULL FROM execbound.weekly_summary_subscriptions "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "p": principal},
        ).scalar_one_or_none()
        is True
    )


def subscribe(runtime: Runtime, session: Session, on: bool) -> None:
    """Turn the session's own person's summary on or off, audited, inside their fence.

    `CONFLICT` for a change that changes nothing, `NO_ADDRESS` for turning it on with no
    address to send it to. The row is the person's own: no principal travels in the request.
    """
    from execbound.surfaces.sessions import check_session

    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
        now = store.now(runtime.clock)
        params = {"t": identity.tenant_id, "p": identity.principal_id, "n": now}
        current = subscribed(conn, identity.tenant_id, identity.principal_id)
        if current == on:
            raise SummaryError("CONFLICT")
        if on:
            if resolve_address(conn, identity.tenant_id, identity.principal_id) is None:
                raise SummaryError("NO_ADDRESS")
            conn.execute(
                text(
                    "INSERT INTO execbound.weekly_summary_subscriptions "
                    "(tenant_id, principal_id, subscribed_at) VALUES (:t, :p, :n) "
                    "ON CONFLICT (tenant_id, principal_id) DO UPDATE SET subscribed_at = :n, "
                    "ended_at = NULL, ended_via = NULL"
                ),
                params,
            )
        else:
            conn.execute(
                text(
                    "UPDATE execbound.weekly_summary_subscriptions SET ended_at=:n, "
                    "ended_via='SETTINGS' WHERE tenant_id=:t AND principal_id=:p"
                ),
                params,
            )
        if on:
            append_event(
                conn, identity.tenant_id, identity.principal_id, "weekly_summary.subscribed", {}
            )
        else:
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "weekly_summary.unsubscribed",
                {"via": "settings"},
            )
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)


def unsubscribe_link(origin: str, tenant: UUID, message: UUID, secret: str) -> str:
    return f"{origin}/weekly-summary/unsubscribe/{LINK_PREFIX}.{tenant}.{message}.{secret}"


def parse_link(link: str) -> tuple[UUID, UUID, str] | None:
    """The tenant, message and secret of a well-formed link, or None; never raises."""
    found = LINK.fullmatch(link)
    if found is None:
        return None
    try:
        tenant, message = UUID(found.group(1)), UUID(found.group(2))
    except ValueError:
        return None
    if str(tenant) != found.group(1) or str(message) != found.group(2):
        return None
    return tenant, message, found.group(3)


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


def unsubscribe(db: Database, link: str, clock: Clock) -> bool:
    """End the subscription a one-click link names, when the link is that message's own.

    Every failure, a forged, unknown, used or malformed link and a tenant that does not exist
    included, answers False and changes nothing; the caller answers every outcome alike.
    """
    parsed = parse_link(link)
    if parsed is None:
        return False
    tenant, message, secret = parsed
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            now = store.now(clock)
            principal = conn.execute(
                text("SELECT execbound.weekly_summary_unsubscribe(:m, :h, :n)"),
                {"m": message, "h": digest(secret), "n": now},
            ).scalar_one()
            if principal is None:
                return False
            append_event(
                conn,
                tenant,
                UUID(str(principal)),
                "weekly_summary.unsubscribed",
                {"via": "link"},
            )
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError, LookupError):
        return False
    log_event("weekly_summary.unsubscribed", tenant_id=tenant, message_id=message)
    return True


# --- The drain ------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Prepared:
    """What one leased message needs to be sent, or the code it is skipped or failed with."""

    to: str | None = None
    workspace: str = ""
    counts: WeeklyCounts | None = None
    previous: WeeklyCounts | None = None
    week: date | None = None
    link: str = ""
    skip: str | None = None
    fail: str | None = None


def _weekly(counts: ValueCounts) -> WeeklyCounts:
    return WeeklyCounts(
        requests=counts.requests,
        executed=counts.executed,
        refused_policy=counts.refused_policy,
        refused_limit=counts.refused_limit,
        refused_busy=counts.refused_busy,
        held=counts.held_total,
        approved=counts.approved,
        refused_by_person=counts.refused_by_person,
        lapsed=counts.lapsed,
        waiting=counts.waiting,
        median_seconds_to_decide=counts.median_seconds_to_decide,
        unsettled_now=counts.unsettled_now,
        effect_unknown=counts.effect_unknown,
        observed=counts.observed_total,
        would_refuse=counts.would_refuse,
        would_refuse_by_limit=counts.would_refuse_by_limit,
        would_hold=counts.would_hold,
        would_run=counts.would_run,
        quiet_sources=counts.quiet_sources,
        open_findings=counts.open_findings,
    )


def _enqueue_all(db: Database, clock: Clock) -> int:
    """This week's messages, queued inside each subscribed workspace's own fence."""
    week = week_ending(store.now(clock))
    # A week past its last deliverable day is not queued at all: it would only fail.
    if store.now(clock) > _midnight(week) + STALE_AFTER:
        return 0
    with db.transaction(uuid4()) as conn:
        check_runtime(conn)
        tenants = [
            UUID(str(found))
            for found in conn.execute(
                text("SELECT tenant_id FROM execbound.weekly_summary_tenants(:n)"),
                {"n": store.now(clock)},
            ).scalars()
        ]
    queued = 0
    for tenant in tenants:
        try:
            with db.transaction(tenant) as conn:
                check_runtime(conn)
                queued += int(
                    conn.execute(
                        text("SELECT execbound.weekly_summary_enqueue(:w, :n)"),
                        {"w": week, "n": store.now(clock)},
                    ).scalar_one()
                )
        except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
            log_event(
                "weekly_summary.failed", level="WARNING", tenant_id=tenant, code="ENQUEUE_FAILED"
            )
    return queued


def _due(db: Database, clock: Clock, limit: int) -> list[tuple[UUID, UUID]]:
    with db.transaction(uuid4()) as conn:
        check_runtime(conn)
        rows = conn.execute(
            text("SELECT tenant_id, message_id FROM execbound.weekly_summary_due(:n, :limit)"),
            {"n": store.now(clock), "limit": limit},
        ).all()
    return [(UUID(str(tenant)), UUID(str(message))) for tenant, message in rows]


def _capped(db: Database, tenant: UUID, mail: MailConfig, clock: Clock) -> bool:
    """Whether this workspace's daily allowance or the deployment's is spent for now."""
    since = store.now(clock) - DAY
    with db.transaction(tenant) as conn:
        check_runtime(conn)
        own = conn.execute(
            text(
                "SELECT count(*) FROM execbound.weekly_summary_messages "
                "WHERE tenant_id=:t AND state='DELIVERED' AND delivered_at > :s"
            ),
            {"t": tenant, "s": since},
        ).scalar_one()
        everyone = conn.execute(
            text("SELECT execbound.weekly_summary_sent(:s)"), {"s": since}
        ).scalar_one()
    return int(own) >= mail.daily_limit or int(everyone) >= mail.weekly_summary_daily_cap


def _lease(
    db: Database, tenant: UUID, message_id: UUID, clock: Clock, lease: UUID
) -> dict[str, Any] | None:
    """Take one message under its own tenant's fence; `SKIP LOCKED` keeps two drains apart."""
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            now = store.now(clock)
            row = (
                conn.execute(
                    text("""
                SELECT m.message_id, m.principal_id, m.week_ending, m.attempts
                  FROM execbound.weekly_summary_messages m
                 WHERE m.tenant_id = :t AND m.message_id = :m AND (
                   (m.state = 'PENDING' AND m.next_attempt_at <= :now)
                   OR (m.state = 'IN_FLIGHT' AND m.lease_until <= :now))
                 FOR UPDATE OF m SKIP LOCKED
                """),
                    {"t": tenant, "m": message_id, "now": now},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            message = dict(row)
            conn.execute(
                text(
                    "UPDATE execbound.weekly_summary_messages SET state='IN_FLIGHT', "
                    "attempts=least(attempts+1, 5), lease_token=:lease, lease_until=:until "
                    "WHERE tenant_id=:t AND message_id=:m"
                ),
                {
                    "t": tenant,
                    "m": message_id,
                    "lease": lease,
                    "until": now + timedelta(seconds=60),
                },
            )
            return message
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        return None


def _prepare(
    db: Database, tenant: UUID, message: dict[str, Any], origin: str, clock: Clock
) -> _Prepared:
    """The recipient's address and counts, read at send time, and a fresh unsubscribe secret
    whose hash is stored; or why the message is skipped or failed."""
    from execbound.surfaces.value import for_principal

    week = message["week_ending"]
    now = store.now(clock)
    if now > _midnight(week) + STALE_AFTER:
        return _Prepared(fail="WEEK_PASSED")
    since, until = window(week)
    principal = UUID(str(message["principal_id"]))
    with db.transaction(tenant) as conn:
        check_runtime(conn)
        counts, reason = for_principal(conn, tenant, principal, since, until, now)
        if counts is None:
            return _Prepared(skip=reason or "PRINCIPAL_INACTIVE")
        to = resolve_address(conn, tenant, principal)
        if to is None:
            return _Prepared(skip="NO_ADDRESS")
        if counts.empty():
            return _Prepared(skip="EMPTY_WEEK")
        previous, _ = for_principal(conn, tenant, principal, since - WEEK, since, now)
        workspace = conn.execute(
            text("SELECT name FROM execbound.tenants WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
        secret = secrets.token_urlsafe(32)
        conn.execute(
            text(
                "UPDATE execbound.weekly_summary_messages SET unsubscribe_hash=:h "
                "WHERE tenant_id=:t AND message_id=:m"
            ),
            {"t": tenant, "m": message["message_id"], "h": digest(secret)},
        )
    assert previous is not None
    return _Prepared(
        to=to,
        workspace=str(workspace),
        counts=_weekly(counts),
        previous=_weekly(previous),
        week=week,
        link=unsubscribe_link(origin, tenant, UUID(str(message["message_id"])), secret),
    )


def _settle(
    db: Database,
    tenant: UUID,
    clock: Clock,
    message: dict[str, Any],
    lease: UUID,
    state: str,
    code: str | None,
    retry_after: int | None,
    counts: dict[str, int],
) -> None:
    attempts = int(message["attempts"]) + 1
    if state == "PENDING" and attempts >= MAX_ATTEMPTS:
        state = "FAILED"
    params = {"t": tenant, "m": message["message_id"], "lease": lease, "code": code}
    now = store.now(clock)
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            if state == "DELIVERED":
                conn.execute(
                    text(
                        "UPDATE execbound.weekly_summary_messages SET state='DELIVERED', "
                        "delivered_at=:now, lease_until=NULL, lease_token=NULL, last_error=NULL "
                        "WHERE tenant_id=:t AND message_id=:m AND lease_token=:lease"
                    ),
                    {**params, "now": now},
                )
            elif state == "PENDING":
                delay = retry_after or BACKOFF[min(attempts, MAX_ATTEMPTS) - 1]
                conn.execute(
                    text(
                        "UPDATE execbound.weekly_summary_messages SET state='PENDING', "
                        "next_attempt_at=:next, last_error=:code, lease_until=NULL, "
                        "lease_token=NULL "
                        "WHERE tenant_id=:t AND message_id=:m AND lease_token=:lease"
                    ),
                    {**params, "next": now + timedelta(seconds=delay)},
                )
            else:
                conn.execute(
                    text(
                        "UPDATE execbound.weekly_summary_messages SET state=:state, "
                        "last_error=:code, lease_until=NULL, lease_token=NULL "
                        "WHERE tenant_id=:t AND message_id=:m AND lease_token=:lease"
                    ),
                    {**params, "state": state},
                )
    except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
        counts["failed"] += 1
        return
    key = {"DELIVERED": "delivered", "PENDING": "deferred", "SKIPPED": "skipped"}.get(
        state, "failed"
    )
    counts[key] += 1
    fields = {
        "tenant_id": tenant,
        "message_id": message["message_id"],
        "state": state,
        "code": code,
    }
    if state == "DELIVERED":
        log_event("weekly_summary.delivered", **fields)
    elif state == "SKIPPED":
        log_event("weekly_summary.skipped", **fields)
    else:
        log_event("weekly_summary.failed", level="WARNING", **fields)


def run(
    db: Database,
    *,
    mail: MailConfig,
    origin: str,
    limit: int = MAX_DRAIN,
    clock: Clock | None = None,
    tls_context: ssl.SSLContext | None = None,
    enqueue: bool = True,
) -> dict[str, int]:
    """Queue this week's summaries, then send every due one.

    Needs no identity: the two owner-only lists reach every workspace on their own, and every
    write runs inside one workspace's fence. `enqueue=False` drains without queueing, which is
    how a test separates the two.
    """
    clock = clock or SystemClock()
    if type(limit) is not int or not 1 <= limit <= MAX_DRAIN:
        raise SummaryError("INVALID_LIMIT")
    if type(mail) is not MailConfig or not mail.weekly_summary:
        raise SummaryError("INVALID_CONFIGURATION")
    counts = {"queued": 0, "delivered": 0, "skipped": 0, "failed": 0, "deferred": 0}
    if enqueue:
        counts["queued"] = _enqueue_all(db, clock)
    for tenant, message_id in _due(db, clock, limit):
        try:
            if _capped(db, tenant, mail, clock):
                counts["deferred"] += 1
                continue
        except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
            counts["deferred"] += 1
            continue
        lease = uuid4()
        message = _lease(db, tenant, message_id, clock, lease)
        if message is None:
            continue
        try:
            prepared = _prepare(db, tenant, message, origin, clock)
        except (SQLAlchemyError, UnsafeDatabaseRole, ValueError):
            _settle(
                db, tenant, clock, message, lease, "PENDING", "RECEIVER_UNAVAILABLE", None, counts
            )
            continue
        if prepared.fail is not None:
            _settle(db, tenant, clock, message, lease, "FAILED", prepared.fail, None, counts)
            continue
        if prepared.skip is not None:
            _settle(db, tenant, clock, message, lease, "SKIPPED", prepared.skip, None, counts)
            continue
        assert prepared.to is not None and prepared.counts is not None
        assert prepared.previous is not None and prepared.week is not None
        try:
            result: SendResult = send_weekly_summary(
                mail,
                prepared.to,
                prepared.workspace,
                prepared.counts,
                prepared.previous,
                prepared.week,
                origin,
                prepared.link,
                context=tls_context,
            )
        except ValueError:
            result = SendResult(False, "INVALID_ADDRESS")
        if result.delivered:
            _settle(db, tenant, clock, message, lease, "DELIVERED", None, None, counts)
        elif result.code in _TERMINAL:
            _settle(db, tenant, clock, message, lease, "FAILED", result.code, None, counts)
        else:
            _settle(
                db,
                tenant,
                clock,
                message,
                lease,
                "PENDING",
                result.code,
                result.retry_after,
                counts,
            )
    return counts
