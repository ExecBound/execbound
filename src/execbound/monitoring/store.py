# SPDX-License-Identifier: AGPL-3.0-only
"""Transactional external monitoring; source reports confer no execution authority."""

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, get_args
from uuid import UUID, uuid4, uuid5

from execbound_connectors.graph import GRAPH_ORIGIN as GRAPH_ORIGIN
from pydantic import ValidationError
from sqlalchemy import TextClause, text
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from execbound import bindings
from execbound.administration import AdministrationError
from execbound.audit import acted_with, append_event
from execbound.db import Database, UnsafeDatabaseRole, check_runtime
from execbound.execution.models import ExecutionError
from execbound.execution.scheduled import ScheduledActor, scheduled_check
from execbound.identity import AuthenticationFailed, Identity, Reason
from execbound.monitoring import ai_publishers, reach
from execbound.monitoring.grant_catalog import ENTRA, PRODUCTION_GRANTS
from execbound.monitoring.models import (
    CHANGE_CLASSES,
    DEFAULT_ACTIVITY_SECONDS,
    DEFAULT_COLLECT_SECONDS,
    TINES_OPERATIONS,
    DetectionProfile,
    MonitorError,
    ObservationEvent,
    ProfileRecord,
    SourceGrant,
)
from execbound.policy.store import PolicyStoreError, _identity
from execbound.resolution.models import Clock, SystemClock
from execbound.secrets import secret_shaped
from execbound.spaces import (
    SpaceError,
    Visibility,
    default_space,
    space_clause,
    visible_spaces,
    write_space,
)
from execbound.surfaces.names import principal_facts
from execbound.surfaces.sessions import Session, SessionError, check_session

MAX_SOURCE_EVENTS = 10000
MAX_EVENTS_PER_MINUTE = 120
MAX_SOURCES = 100
# A reporting token minted or rotated here reports for at most thirty days, whoever mints it
# (#678): the console offers 1, 7 or 30 days and the command line 1 to 24 hours.
MAX_SOURCE_LIFETIME = timedelta(days=30)
# Whether the administrator bound as `:administrator` may change what sits in the space that
# `{space}` names, as one expression a read can carry: a membership narrows an administrator to
# the spaces they administer, and one with no membership administers every space. `_administers`
# asks exactly this, so a page never offers a change the store refuses.
ADMINISTERS = (
    "(NOT EXISTS (SELECT 1 FROM execbound.space_members am WHERE am.tenant_id=:t "
    "AND am.principal_id=:administrator) OR EXISTS (SELECT 1 FROM execbound.space_members am "
    "WHERE am.tenant_id=:t AND am.principal_id=:administrator AND am.space_id={space} "
    "AND am.role='ADMIN'))"
)
# A source as the Connections view reads it, in the snapshot and on its own; `administered`
# needs `:administrator` bound to the reader.
SOURCE_COLUMNS = (
    "e.source_id, e.label, e.story_id, e.created_at, e.expires_at, e.active, "
    "e.revoked_at, e.heartbeat_seconds, e.last_event_at, e.last_heartbeat_at, "
    "e.last_refusal_code, e.last_refusal_at, e.accepted_count, e.previous_valid_until, "
    "e.health_state, e.health_changed_at, e.health_checked_at, "
    + ADMINISTERS.format(space="e.space_id")
    + " AS administered"
)
RULE_VERSION = "sensitive-action.v2"
CHANGE_RULE = "monitored-path-change.v1"
KNOWN_RULE_VERSIONS = frozenset({"sensitive-action.v1", RULE_VERSION, CHANGE_RULE})
RESTRICTED_RULE = "restricted-target.v1"
RATE_RULE = "observed-rate.v1"
HEALTH_RULE = "source-health.v1"
SKEW_RULE = "clock-skew.v1"
# Receipt-time plausibility bounds for reported event time; external time is never rewritten.
SKEW_AHEAD = timedelta(minutes=5)
SKEW_BEHIND = timedelta(hours=24)
# How many of a directory's audit-log observations (#355) one evaluation takes, beside and never
# instead of its `limit` of the rest: as many as one read stores (`graph.MAX_AUDIT_PAGES` pages of
# `graph.AUDIT_PAGE_SIZE`), so a back-fill, which raises nothing of its own, drains as fast as a
# read writes it and never queues ahead of what a source reports.
AUDIT_EVALUATIONS = 400
SENSITIVE_ACTIONS = frozenset(
    {
        "endpoint.isolate",
        "identity.disable",
        "identity.enable",
        "identity.revoke_sessions",
    }
)
DEPENDENCY_ERRORS = (SQLAlchemyError, UnsafeDatabaseRole, PolicyStoreError, SessionError)
SYSTEM_CLOCK = SystemClock()


def _now(clock: Clock) -> datetime:
    now = clock.now()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise MonitorError("INVALID_CLOCK")
    return now.astimezone(UTC)


def check_admin(conn: Connection, identity: Identity, *, clock: Clock = SYSTEM_CLOCK) -> None:
    """Revalidate current ADMIN authority in an already tenant-scoped transaction."""
    try:
        check_runtime(conn)
        _identity(conn, identity, clock, admin=True)
    except DEPENDENCY_ERRORS:
        raise MonitorError("INVALID_ADMIN") from None


def _check_actor(
    conn: Connection,
    actor: Identity | ScheduledActor,
    clock: Clock,
    *,
    collecting: bool = False,
    lease: UUID | None = None,
) -> None:
    """An administrator's current ADMIN authority, or the scheduled pass's admission (#503).

    The scheduled pass holds no credential. It is admitted under the transaction's own fence,
    in an active workspace whose scheduler principal it is (`scheduled_check`), and, when it
    is collecting, only with a lease (`collecting`): a scheduled run outside a lease could
    overlap another. Either refusal is INVALID_ADMIN.
    """
    if isinstance(actor, ScheduledActor):
        if collecting and lease is None:
            raise MonitorError("INVALID_ADMIN")
        try:
            check_runtime(conn)
            scheduled_check(conn, actor)
        except (ExecutionError, *DEPENDENCY_ERRORS):
            raise MonitorError("INVALID_ADMIN") from None
        return
    if not isinstance(actor, Identity):
        raise MonitorError("INVALID_ADMIN")
    check_admin(conn, actor, clock=clock)


def _session(conn: Connection, session: Session, clock: Clock) -> None:
    check_admin(conn, session.identity, clock=clock)
    # Session revocation updates this same row; retain its read lock until commit.
    conn.execute(
        text("""
        SELECT session_id FROM execbound.human_sessions
        WHERE tenant_id=:t AND session_id=:s FOR SHARE
    """),
        {"t": session.identity.tenant_id, "s": session.session_id},
    )
    check_session(conn, session, clock)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _selectors(token: str) -> tuple[UUID, UUID]:
    try:
        if type(token) is not str or len(token) > 160:
            raise ValueError
        version, tenant_text, source_text, secret = token.split(".")
        tenant, source = UUID(tenant_text), UUID(source_text)
        if (
            version != "mo1"
            or str(tenant) != tenant_text
            or str(source) != source_text
            or re.fullmatch(r"[A-Za-z0-9_-]{43}", secret) is None
        ):
            raise ValueError
        decoded = base64.b64decode(secret + "=", altchars=b"-_", validate=True)
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != secret:
            raise ValueError
        return tenant, source
    except ValueError:
        raise MonitorError("INVALID_SOURCE", failure=AuthenticationFailed()) from None


def _check_source_space(conn: Connection, identity: Identity, space: UUID) -> None:
    """A source is minted into a space of the tenant that is not archived and that its creator
    administers: a membership narrows an administrator to the spaces they administer, and
    reviewer access never grants minting. Each refusal is its own code."""
    archived = conn.execute(
        text(
            "SELECT archived_at IS NOT NULL FROM execbound.spaces "
            "WHERE tenant_id=:t AND space_id=:s"
        ),
        {"t": identity.tenant_id, "s": space},
    ).scalar_one_or_none()
    if archived is None:
        raise MonitorError("INVALID_SPACE")
    if archived:
        raise MonitorError("SPACE_ARCHIVED")
    if not _administers(conn, identity, space):
        raise MonitorError("INVALID_ADMIN")


def create_source(
    db: Database,
    identity: Identity,
    *,
    label: str,
    story_id: str,
    expires_at: datetime,
    heartbeat_seconds: int = 300,
    clock: Clock = SYSTEM_CLOCK,
    space: UUID | None = None,
    session: Session | None = None,
) -> SourceGrant:
    """Register one story's reporting source and mint its token, shown once to the caller.

    The source records who minted it (`created_by`) and lands in a space its creator may mint
    in: the one named, or the tenant's first; with a console `session`, the session's own space,
    and none is guessed where it has several. A story already holding an unrevoked source in that
    space is `SOURCE_EXISTS`, unless that source has kept all its events: rotation keeps that
    count, so the story is registered again beside it, and the full source is revoked after.
    Its token reports for at most thirty days, and a label or story ID shaped like a secret is
    refused before anything is written. Nothing here touches the execution audit chain or
    execution state.
    """
    now = _now(clock)
    if (
        type(label) is not str
        or not 1 <= len(label) <= 96
        or not label.strip()
        or not label.isprintable()
        or type(story_id) is not str
        or re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", story_id) is None
        or not isinstance(expires_at, datetime)
        or expires_at.tzinfo is None
        or expires_at.utcoffset() is None
        or expires_at <= now
        or expires_at > now + MAX_SOURCE_LIFETIME
        or type(heartbeat_seconds) is not int
        or not 30 <= heartbeat_seconds <= 86400
        # Both reach the source's row and the pages that read it: one that reads as a secret
        # is refused rather than recorded.
        or secret_shaped(label, story_id)
        or (session is not None and (space is not None or session.identity != identity))
    ):
        raise MonitorError("INVALID_INPUT")
    source_id = uuid4()
    token = f"mo1.{identity.tenant_id}.{source_id}.{secrets.token_urlsafe(32)}"
    try:
        with db.transaction(identity.tenant_id) as conn:
            if session is None:
                check_admin(conn, identity, clock=clock)
            else:
                _session(conn, session, clock)
            # Serialize only this monitoring registry; never initialize execution/audit state.
            conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"monitor-sources:{identity.tenant_id}"},
            )
            if session is not None:
                try:
                    space = write_space(conn, identity.tenant_id, visible_spaces(conn, session))
                except SpaceError:
                    raise MonitorError("SPACE_REQUIRED") from None
            else:
                space = space or default_space(conn, identity.tenant_id)
            _check_source_space(conn, identity, space)
            # One unrevoked source per story in a space that can still take its events, expired
            # or not: an expired one is rotated, and a mint repeated after an answer that was
            # lost is refused rather than leaving a second one nobody holds a token for. The
            # refusal names no source; the one already made is among the space's sources. A
            # source that has kept all its events, which rotation does not reset, does not
            # count, so its story is registered again while it stands, and its administrator
            # revokes it once the story reports through the new one: where the workspace is
            # full, the capacity check below refuses the new source with nothing given up.
            if conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM execbound.monitor_sources WHERE tenant_id=:t "
                    "AND space_id=:space AND story_id=:story AND active AND revoked_at IS NULL "
                    "AND accepted_count < :kept)"
                ),
                {
                    "t": identity.tenant_id,
                    "space": space,
                    "story": story_id,
                    "kept": MAX_SOURCE_EVENTS,
                },
            ).scalar_one():
                raise MonitorError("SOURCE_EXISTS")
            if (
                conn.execute(text("SELECT count(*) FROM execbound.monitor_sources")).scalar_one()
                >= MAX_SOURCES
            ):
                raise MonitorError("SOURCE_CAPACITY")
            conn.execute(
                text("""
                INSERT INTO execbound.monitor_sources
                (tenant_id, source_id, label, story_id, token_hash, created_at, expires_at,
                 heartbeat_seconds, rate_window_at, space_id, created_by)
                VALUES (:t, :s, :label, :story, :hash, :now, :expiry, :heartbeat, :now, :space,
                        :by)
            """),
                {
                    "t": identity.tenant_id,
                    "space": space,
                    "s": source_id,
                    "label": label,
                    "story": story_id,
                    "hash": _hash(token),
                    "now": now,
                    "expiry": expires_at.astimezone(UTC),
                    "heartbeat": heartbeat_seconds,
                    "by": identity.principal_id,
                },
            )
            if session is None:
                check_admin(conn, identity, clock=clock)
            else:
                _session(conn, session, clock)
            _check_source_space(conn, identity, space)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return SourceGrant(identity.tenant_id, source_id, token)


def source(
    db: Database, session: Session, source_id: UUID, *, clock: Clock = SYSTEM_CLOCK
) -> dict[str, Any]:
    """One source as the Connections view reads it, if the session's spaces hold it: one
    outside them, or none at all, is `SOURCE_UNAVAILABLE`. A revoked source is still read."""
    if type(source_id) is not UUID:
        raise MonitorError("SOURCE_UNAVAILABLE")
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            _session(conn, session, clock)
            row = (
                conn.execute(
                    text(
                        f"SELECT {SOURCE_COLUMNS}, e.space_id "  # nosec B608 - a literal column list
                        "FROM execbound.monitor_sources e "
                        "WHERE e.tenant_id = :t AND e.source_id = :s"
                    ),
                    {
                        "t": identity.tenant_id,
                        "s": source_id,
                        "administrator": identity.principal_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None or not visible_spaces(conn, session).allows(row["space_id"]):
                raise MonitorError("SOURCE_UNAVAILABLE")
            _session(conn, session, clock)
            return dict(row)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def _locked_source(
    conn: Connection, tenant: UUID, source_id: UUID, *, visibility: Visibility | None = None
) -> dict[str, Any]:
    """The source, locked; with a console session's `visibility`, only one its spaces hold,
    so naming one outside them neither changes it nor says it is there."""
    if type(source_id) is not UUID:
        raise MonitorError("SOURCE_UNAVAILABLE")
    # Serialize only this monitoring registry; never initialize execution/audit state.
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"monitor-sources:{tenant}"},
    )
    row = (
        conn.execute(
            text(
                "SELECT * FROM execbound.monitor_sources "
                "WHERE tenant_id=:t AND source_id=:s FOR UPDATE"
            ),
            {"t": tenant, "s": source_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None or (visibility is not None and not visibility.allows(row["space_id"])):
        raise MonitorError("SOURCE_UNAVAILABLE")
    if row["revoked_at"] is not None or not row["active"]:
        raise MonitorError("INVALID_STATE")
    return dict(row)


def rotate_source(
    db: Database,
    identity: Identity,
    source_id: UUID,
    *,
    expires_at: datetime,
    grace_seconds: int = 600,
    clock: Clock = SYSTEM_CLOCK,
    session: Session | None = None,
) -> SourceGrant:
    """Issue a replacement reporting token; the old one keeps working for a bounded grace
    window (never past its own expiry, and not at all once it has expired). The registration
    digest is never rewritten: the active digest lives in current_token_hash. The new token
    reports for at most thirty days. With a console `session`, a source outside its spaces does
    not exist for it; an administrator narrowed to other spaces is refused either way."""
    now = _now(clock)
    if (
        not isinstance(expires_at, datetime)
        or expires_at.tzinfo is None
        or expires_at.utcoffset() is None
        or expires_at <= now
        or expires_at > now + MAX_SOURCE_LIFETIME
        or type(grace_seconds) is not int
        or not 0 <= grace_seconds <= 3600
        or (session is not None and session.identity != identity)
    ):
        raise MonitorError("INVALID_INPUT")
    token = f"mo1.{identity.tenant_id}.{source_id}.{secrets.token_urlsafe(32)}"
    try:
        with db.transaction(identity.tenant_id) as conn:
            _source_actor(conn, identity, session, clock)
            row = _locked_source(
                conn, identity.tenant_id, source_id, visibility=_visibility(conn, session)
            )
            if not _administers(conn, identity, row["space_id"]):
                raise MonitorError("INVALID_ADMIN")
            previous_hash, previous_until = None, None
            if grace_seconds > 0 and now < row["expires_at"]:
                previous_hash = row["current_token_hash"] or row["token_hash"]
                previous_until = min(now + timedelta(seconds=grace_seconds), row["expires_at"])
            conn.execute(
                text("""
                UPDATE execbound.monitor_sources
                SET current_token_hash=:hash, expires_at=:expiry, previous_token_hash=:previous,
                    previous_valid_until=:until, rotated_at=:now, rotated_by=:actor
                WHERE tenant_id=:t AND source_id=:s
            """),
                {
                    "hash": _hash(token),
                    "expiry": expires_at.astimezone(UTC),
                    "previous": previous_hash,
                    "until": previous_until,
                    "now": now,
                    "actor": identity.principal_id,
                    "t": identity.tenant_id,
                    "s": source_id,
                },
            )
            _source_actor(conn, identity, session, clock)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return SourceGrant(identity.tenant_id, source_id, token, previous_until)


def revoke_source(
    db: Database,
    identity: Identity,
    source_id: UUID,
    *,
    clock: Clock = SYSTEM_CLOCK,
    session: Session | None = None,
) -> dict[str, Any]:
    """Disable a source for good; every token it ever had stops reporting at once. With a
    console `session`, a source outside its spaces does not exist for it; an administrator
    narrowed to other spaces is refused either way. A source in an archived space may still be
    revoked, because revoking issues nothing. Answers the revoked source as the Connections view
    reads it, read in the transaction that revoked it, so nothing after the commit can fail the
    answer to a revocation that took effect."""
    now = _now(clock)
    if session is not None and session.identity != identity:
        raise MonitorError("INVALID_INPUT")
    try:
        with db.transaction(identity.tenant_id) as conn:
            _source_actor(conn, identity, session, clock)
            row = _locked_source(
                conn, identity.tenant_id, source_id, visibility=_visibility(conn, session)
            )
            if not _administers(conn, identity, row["space_id"]):
                raise MonitorError("INVALID_ADMIN")
            conn.execute(
                text("""
                UPDATE execbound.monitor_sources
                SET active=false, revoked_at=:now, revoked_by=:actor,
                    previous_token_hash=NULL, previous_valid_until=NULL
                WHERE tenant_id=:t AND source_id=:s
            """),
                {
                    "now": now,
                    "actor": identity.principal_id,
                    "t": identity.tenant_id,
                    "s": source_id,
                },
            )
            revoked = (
                conn.execute(
                    text(
                        f"SELECT {SOURCE_COLUMNS} FROM execbound.monitor_sources e "  # nosec B608 - a literal column list
                        "WHERE e.tenant_id = :t AND e.source_id = :s"
                    ),
                    {
                        "t": identity.tenant_id,
                        "s": source_id,
                        "administrator": identity.principal_id,
                    },
                )
                .mappings()
                .one()
            )
            _source_actor(conn, identity, session, clock)
            return dict(revoked)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def _source_actor(
    conn: Connection, identity: Identity, session: Session | None, clock: Clock
) -> None:
    """The administrator's current authority, and with a console session the session's too."""
    if session is None:
        check_admin(conn, identity, clock=clock)
    else:
        _session(conn, session, clock)


def _visibility(conn: Connection, session: Session | None) -> Visibility | None:
    return None if session is None else visible_spaces(conn, session)


def _finding(
    conn: Connection,
    tenant: UUID,
    source: UUID | None,
    observation: UUID | None,
    rule: str,
    title: str,
    now: datetime,
    *,
    finding_id: UUID | None = None,
    profile: ProfileRecord | None = None,
    connection: UUID | None = None,
    agent: UUID | None = None,
    deliver: bool = True,
) -> None:
    """Record one finding and queue its delivery. `deliver=False` records it without a delivery,
    for a finding another one already speaks for: the episodes a directory's baseline opens,
    which its inventory summary counts, and a newcomer's reach, which `new-actor.v1` reports."""
    if finding_id is None:
        if observation is None:
            raise MonitorError("INVALID_INPUT")
        finding_id = uuid5(observation, rule)
    conn.execute(
        text("""
        INSERT INTO execbound.monitor_findings
        (tenant_id, finding_id, source_id, connection_id, observation_id, rule_version, title,
         created_at, profile_id, profile_version, agent_id, space_id)
        VALUES (:t, :f, :s, :c, :o, :rule, :title, :now, :profile, :version, :agent,
                -- A finding derives its space from whatever it is about: the observation
                -- it was raised on, else the source or the connection that produced it,
                -- else the discovered agent's connection. A tenant that never made a
                -- second space falls through to its only one.
                COALESCE(
                    (SELECT b.space_id FROM execbound.monitor_observations b
                      WHERE b.tenant_id = :t AND b.observation_id = :o),
                    (SELECT m.space_id FROM execbound.monitor_sources m
                      WHERE m.tenant_id = :t AND m.source_id = :s),
                    (SELECT n.space_id FROM execbound.monitor_connections n
                      WHERE n.tenant_id = :t AND n.connection_id = :c),
                    (SELECT n.space_id FROM execbound.monitor_agents a
                      JOIN execbound.monitor_connections n
                        ON n.tenant_id = a.tenant_id AND n.connection_id = a.connection_id
                      WHERE a.tenant_id = :t AND a.agent_id = :agent),
                    (SELECT p.space_id FROM execbound.spaces p
                      WHERE p.tenant_id = :t ORDER BY p.space_id LIMIT 1)))
        ON CONFLICT (tenant_id, finding_id) DO NOTHING
    """),
        {
            "t": tenant,
            "f": finding_id,
            "s": source,
            "c": connection,
            "o": observation,
            "rule": rule,
            "title": title,
            "now": now,
            "profile": profile.profile_id if profile else None,
            "version": profile.version if profile else None,
            "agent": agent,
        },
    )
    if not deliver:
        return
    conn.execute(
        text("""
        INSERT INTO execbound.monitor_deliveries
        (tenant_id, delivery_id, finding_id, created_at, next_attempt_at)
        VALUES (:t, :d, :f, :now, :now)
        ON CONFLICT (tenant_id, delivery_id) DO NOTHING
    """),
        {"t": tenant, "d": uuid5(finding_id, "delivery"), "f": finding_id, "now": now},
    )


def _refusal(conn: Connection, tenant: UUID, source: UUID, code: str, now: datetime) -> None:
    conn.execute(
        text("""
        UPDATE execbound.monitor_sources SET last_refusal_code=:code, last_refusal_at=:now
        WHERE tenant_id=:t AND source_id=:s
    """),
        {"code": code, "now": now, "t": tenant, "s": source},
    )


def ingest(
    db: Database,
    token: str,
    event: ObservationEvent,
    *,
    clock: Clock = SYSTEM_CLOCK,
) -> dict[str, Any]:
    tenant, source_id = _selectors(token)
    if type(event) is not ObservationEvent:
        raise MonitorError("INVALID_INPUT")
    try:
        # Reject unvalidated model_construct/model_copy objects at the store boundary too.
        event = ObservationEvent.model_validate_json(event.model_dump_json())
    except (ValidationError, ValueError, TypeError):
        raise MonitorError("INVALID_INPUT") from None
    digest = _hash(event.model_dump_json())
    refusal = None
    result: dict[str, Any] = {}
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            source = (
                conn.execute(
                    text("""
                SELECT * FROM execbound.monitor_sources
                WHERE tenant_id=:t AND source_id=:s FOR UPDATE
            """),
                    {"t": tenant, "s": source_id},
                )
                .mappings()
                .one_or_none()
            )
            now = _now(clock)
            supplied = _hash(token)
            # Both comparisons always run so a rotated source costs the same as any other.
            active_hash = (
                (source["current_token_hash"] or source["token_hash"]) if source else "0" * 64
            )
            current = hmac.compare_digest(supplied, active_hash)
            previous = hmac.compare_digest(
                supplied, (source["previous_token_hash"] if source else None) or "1" * 64
            )
            matches = current or (
                previous
                and source is not None
                and source["previous_valid_until"] is not None
                and now < source["previous_valid_until"]
            )
            active = conn.execute(
                text("SELECT active FROM execbound.tenants WHERE tenant_id=:t"), {"t": tenant}
            ).scalar_one_or_none()
            if source is None:
                raise MonitorError(
                    "INVALID_SOURCE",
                    failure=AuthenticationFailed(reason="UNKNOWN", context_tenant=tenant),
                )
            attributed: dict[str, Any] = {
                "tenant_id": tenant,
                "subject_kind": "source",
                "subject_id": source_id,
            }
            reason: Reason | None = None
            if not matches:
                reason = "MISMATCH"
            elif source["revoked_at"] is not None or not source["active"]:
                reason = "REVOKED"
            elif not source["created_at"] <= now < source["expires_at"]:
                reason = "EXPIRED"
            elif not active:
                reason = "INACTIVE"
            if reason is not None:
                raise MonitorError(
                    "INVALID_SOURCE", failure=AuthenticationFailed(reason=reason, **attributed)
                )
            if event.story_id != source["story_id"]:
                raise MonitorError("INVALID_SOURCE")
            window = source["rate_window_at"]
            count = source["rate_count"]
            if now >= window + timedelta(minutes=1):
                window, count = now, 0
            if count >= MAX_EVENTS_PER_MINUTE:
                refusal = "SOURCE_RATE_LIMIT"
            else:
                conn.execute(
                    text("""
                    UPDATE execbound.monitor_sources SET rate_window_at=:window, rate_count=:count
                    WHERE tenant_id=:t AND source_id=:s
                """),
                    {"window": window, "count": count + 1, "t": tenant, "s": source_id},
                )
                if event.kind == "heartbeat":
                    # A heartbeat proves receipt-time freshness, not an action. Keep it off
                    # the observation queue and lifetime event count, including at capacity.
                    # Authentication, story binding and the shared rate limit still hold.
                    conn.execute(
                        text("""
                        UPDATE execbound.monitor_sources SET last_heartbeat_at=:now
                        WHERE tenant_id=:t AND source_id=:s
                    """),
                        {"t": tenant, "s": source_id, "now": now},
                    )
                    return {"observation_id": None, "duplicate": False}
                existing = (
                    conn.execute(
                        text("""
                    SELECT observation_id, content_hash FROM execbound.monitor_observations
                    WHERE tenant_id=:t AND source_id=:s AND event_id=:e
                """),
                        {"t": tenant, "s": source_id, "e": event.event_id},
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is not None:
                    result = {"observation_id": str(existing["observation_id"]), "duplicate": True}
                    if not hmac.compare_digest(existing["content_hash"], digest):
                        refusal = "EVENT_CONFLICT"
                        conn.execute(
                            text("""
                            UPDATE execbound.monitor_observations
                            SET integrity_conflict_at=coalesce(integrity_conflict_at, :now)
                            WHERE tenant_id=:t AND observation_id=:o
                        """),
                            {"now": now, "t": tenant, "o": existing["observation_id"]},
                        )
                        _finding(
                            conn,
                            tenant,
                            source_id,
                            existing["observation_id"],
                            "source-event-integrity.v1",
                            "Conflicting source event ID",
                            now,
                        )
                elif source["accepted_count"] >= MAX_SOURCE_EVENTS:
                    refusal = "SOURCE_CAPACITY"
                else:
                    observation_id = uuid5(source_id, event.event_id)
                    conn.execute(
                        text("""
                        INSERT INTO execbound.monitor_observations
                        (tenant_id, observation_id, source_id, event_id, story_id, version,
                         occurred_at, received_at, kind, action, target_ref, outcome,
                         content_hash, rule_version, space_id)
                        SELECT :t, :o, :s, :event, :story, 1, :occurred, :now,
                               :kind, :action, :target, :outcome, :hash, :rule, m.space_id
                          FROM execbound.monitor_sources m
                         WHERE m.tenant_id = :t AND m.source_id = :s
                    """),
                        {
                            "t": tenant,
                            "o": observation_id,
                            "s": source_id,
                            "event": event.event_id,
                            "story": event.story_id,
                            "occurred": event.occurred_at,
                            "now": now,
                            "kind": event.kind,
                            "action": event.action,
                            "target": event.target_ref,
                            "outcome": event.outcome,
                            "hash": digest,
                            "rule": RULE_VERSION,
                        },
                    )
                    conn.execute(
                        text("""
                        UPDATE execbound.monitor_sources
                        SET accepted_count=accepted_count+1, last_event_at=:now
                        WHERE tenant_id=:t AND source_id=:s
                    """),
                        {
                            "t": tenant,
                            "s": source_id,
                            "now": now,
                        },
                    )
                    result = {"observation_id": str(observation_id), "duplicate": False}
            if refusal:
                _refusal(conn, tenant, source_id, refusal, now)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    if refusal:
        # Retained refusal evidence commits even though the caller receives an error.
        raise MonitorError(refusal)
    return result


def _record(row: dict[str, Any]) -> ProfileRecord:
    return ProfileRecord(
        row["profile_id"],
        int(row["version"]),
        row["created_at"],
        row["created_by"],
        row["retired_at"],
        DetectionProfile(
            sensitive_actions=tuple(row["sensitive_actions"]),
            restricted_targets=tuple(row["restricted_targets"]),
            burst_threshold=row["burst_threshold"],
            burst_window_seconds=row["burst_window_seconds"],
            ai_tool_actions=dict(row["ai_tool_actions"]),
        ),
    )


def _active_profile(conn: Connection, tenant: UUID) -> ProfileRecord | None:
    row = (
        conn.execute(
            text(
                "SELECT * FROM execbound.monitor_profiles WHERE tenant_id=:t AND retired_at IS NULL"
            ),
            {"t": tenant},
        )
        .mappings()
        .one_or_none()
    )
    return _record(dict(row)) if row is not None else None


def set_profile(
    db: Database, identity: Identity, profile: DetectionProfile, *, clock: Clock = SYSTEM_CLOCK
) -> ProfileRecord:
    """Insert the next immutable profile version and retire the current one, as one change."""
    if type(profile) is not DetectionProfile:
        raise MonitorError("INVALID_INPUT")
    profile = DetectionProfile.model_validate_json(profile.model_dump_json())
    now = _now(clock)
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_admin(conn, identity, clock=clock)
            conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"monitor-profiles:{identity.tenant_id}"},
            )
            version = conn.execute(
                text("SELECT coalesce(max(version), 0) + 1 FROM execbound.monitor_profiles"),
            ).scalar_one()
            conn.execute(
                text(
                    "UPDATE execbound.monitor_profiles SET retired_at=:now "
                    "WHERE tenant_id=:t AND retired_at IS NULL"
                ),
                {"now": now, "t": identity.tenant_id},
            )
            record = ProfileRecord(uuid4(), int(version), now, identity.principal_id, None, profile)
            conn.execute(
                text("""
                INSERT INTO execbound.monitor_profiles
                (tenant_id, profile_id, version, sensitive_actions, restricted_targets,
                 burst_threshold, burst_window_seconds, created_at, created_by, ai_tool_actions)
                VALUES (:t, :p, :v, CAST(:actions AS jsonb), CAST(:targets AS jsonb),
                        :threshold, :window, :now, :actor, CAST(:tools AS jsonb))
            """),
                {
                    "t": identity.tenant_id,
                    "p": record.profile_id,
                    "v": record.version,
                    "actions": json.dumps(list(profile.sensitive_actions)),
                    "targets": json.dumps(list(profile.restricted_targets)),
                    "tools": json.dumps(profile.ai_tool_actions, sort_keys=True),
                    "threshold": profile.burst_threshold,
                    "window": profile.burst_window_seconds,
                    "now": now,
                    "actor": identity.principal_id,
                },
            )
            check_admin(conn, identity, clock=clock)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return record


def active_profile(
    db: Database, identity: Identity, *, clock: Clock = SYSTEM_CLOCK
) -> ProfileRecord | None:
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_admin(conn, identity, clock=clock)
            return _active_profile(conn, identity.tenant_id)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def _burst(conn: Connection, tenant: UUID, row: dict[str, Any], profile: DetectionProfile) -> bool:
    """Receipts of tool results from this source in the trailing window, including this one."""
    assert profile.burst_threshold is not None and profile.burst_window_seconds is not None
    collected = row.get("connection_id") is not None
    count = conn.execute(
        text(
            "SELECT count(*) FROM execbound.monitor_observations "
            "WHERE tenant_id=:t AND connection_id=:s AND kind='ai_tool_run' "
            "AND received_at > :start AND received_at <= :end"
            if collected
            else "SELECT count(*) FROM execbound.monitor_observations "
            "WHERE tenant_id=:t AND source_id=:s AND kind='tool_result' "
            "AND received_at > :start AND received_at <= :end"
        ),
        {
            "t": tenant,
            "s": row["connection_id"] if collected else row["source_id"],
            "start": row["received_at"] - timedelta(seconds=profile.burst_window_seconds),
            "end": row["received_at"],
        },
    ).scalar_one()
    return int(count) >= profile.burst_threshold


def evaluate_pending(
    db: Database,
    actor: Identity | ScheduledActor,
    *,
    limit: int = 50,
    clock: Clock = SYSTEM_CLOCK,
) -> int:
    """Evaluate up to `limit` pending observations, oldest received first, and beside them up to
    `AUDIT_EVALUATIONS` of a directory's audit-log observations, oldest received first too.

    The two are taken apart because an audit log is read in bulk, a connection's first look-back
    and every backlog a few hundred entries a pass, and its observations raise nothing of their
    own: in one queue a back-fill would hold a source's reported action, and the findings it
    raises, back for as many passes as the back-fill fills.
    """
    if type(limit) is not int or not 1 <= limit <= 500:
        raise MonitorError("INVALID_INPUT")
    try:
        with db.transaction(actor.tenant_id) as conn:
            _check_actor(conn, actor, clock)
            rows = [
                row
                for audit, budget in ((False, limit), (True, AUDIT_EVALUATIONS))
                for row in conn.execute(
                    text("""
                SELECT observation_id, source_id, connection_id, kind, action, target_ref,
                       rule_version, occurred_at, received_at, operation_name, story_id
                FROM execbound.monitor_observations
                WHERE tenant_id=:t AND evaluation_state='PENDING'
                  AND (kind = 'entra_audit') = :audit
                ORDER BY received_at, observation_id LIMIT :limit FOR UPDATE SKIP LOCKED
            """),
                    {"t": actor.tenant_id, "audit": audit, "limit": budget},
                )
                .mappings()
                .all()
            ]
            now = _now(clock)
            profile = _active_profile(conn, actor.tenant_id)
            configured = profile.profile if profile is not None else None
            actions = set(configured.sensitive_actions) if configured else SENSITIVE_ACTIONS
            registered: set[str] | None = None
            for row in rows:
                if row["rule_version"] not in KNOWN_RULE_VERSIONS:
                    raise MonitorError("RULE_UNAVAILABLE")
                result = "NO_MATCH"
                origin = row["source_id"] or row["connection_id"]
                connection = row["connection_id"]
                if row["kind"] == "config_change":
                    if registered is None:
                        registered = {
                            story
                            for (story,) in conn.execute(
                                text(
                                    "SELECT story_id FROM execbound.monitor_sources "
                                    "WHERE tenant_id=:t"
                                ),
                                {"t": actor.tenant_id},
                            )
                        }
                    change = TINES_OPERATIONS.get(row["operation_name"] or "")
                    if change not in CHANGE_CLASSES:
                        # An operation outside the versioned mapping is not established as
                        # benign; it is a coverage statement, never a silent pass.
                        result = "INSUFFICIENT_EVIDENCE"
                    elif change == "credential" or (
                        change in {"story", "action"} and row["story_id"] in registered
                    ):
                        result = "MATCH"
                        _finding(
                            conn,
                            actor.tenant_id,
                            None,
                            row["observation_id"],
                            CHANGE_RULE,
                            "Platform recorded a change on a monitored path",
                            now,
                            connection=connection,
                        )
                elif row["kind"] == "ai_tool_run":
                    mapped = (
                        configured.ai_tool_actions.get(row["action"] or "")
                        if configured is not None
                        else None
                    )
                    if mapped is None:
                        # An unmapped tool name says nothing about what the tool did.
                        result = "INSUFFICIENT_EVIDENCE"
                    elif mapped in actions:
                        result = "MATCH"
                        _finding(
                            conn,
                            actor.tenant_id,
                            None,
                            row["observation_id"],
                            RULE_VERSION,
                            "Platform recorded a consequential AI tool run",
                            now,
                            profile=profile,
                            connection=connection,
                        )
                    if (
                        configured is not None
                        and configured.burst_threshold is not None
                        and configured.burst_window_seconds is not None
                        and _burst(conn, actor.tenant_id, dict(row), configured)
                    ):
                        window = configured.burst_window_seconds
                        epoch = int(row["received_at"].timestamp()) // window * window
                        start = datetime.fromtimestamp(epoch, UTC)
                        _finding(
                            conn,
                            actor.tenant_id,
                            None,
                            row["observation_id"],
                            RATE_RULE,
                            "Collected activity exceeded the configured rate",
                            now,
                            finding_id=uuid5(origin, f"{RATE_RULE}:{start.isoformat()}"),
                            profile=profile,
                            connection=connection,
                        )
                elif row["kind"] == "entra_audit":
                    # A directory's own record of an application's action (#355) is classified
                    # and raises no finding of its own: it feeds observed reach and the actor's
                    # first consequential action, which is raised once per actor, rather than a
                    # finding for every routine change.
                    if configured is None:
                        result = "INSUFFICIENT_EVIDENCE"
                    elif row["action"] in actions:
                        result = "MATCH"
                elif row["kind"] == "tool_result":
                    # Without a profile the built-in set is not a tenant statement of what is
                    # benign, so an unlisted action stays a coverage limit, not a pass.
                    if configured is None:
                        result = "INSUFFICIENT_EVIDENCE"
                    if row["action"] == "unknown":
                        # A label the story could not establish is a coverage statement.
                        result = "INSUFFICIENT_EVIDENCE"
                        if "unknown" in actions and configured is not None:
                            _finding(
                                conn,
                                actor.tenant_id,
                                row["source_id"],
                                row["observation_id"],
                                RULE_VERSION,
                                "Source reported an action it could not identify",
                                now,
                                profile=profile,
                            )
                    elif row["action"] in actions:
                        result = "MATCH"
                        _finding(
                            conn,
                            actor.tenant_id,
                            row["source_id"],
                            row["observation_id"],
                            RULE_VERSION,
                            "Source reported a consequential action",
                            now,
                            profile=profile,
                        )
                    if configured is not None and configured.matches_target(row["target_ref"]):
                        _finding(
                            conn,
                            actor.tenant_id,
                            row["source_id"],
                            row["observation_id"],
                            RESTRICTED_RULE,
                            "Source reported a restricted target",
                            now,
                            profile=profile,
                        )
                    if (
                        configured is not None
                        and configured.burst_threshold is not None
                        and configured.burst_window_seconds is not None
                        and _burst(conn, actor.tenant_id, dict(row), configured)
                    ):
                        # One finding per window episode: the identifier is the window start.
                        window = configured.burst_window_seconds
                        epoch = int(row["received_at"].timestamp()) // window * window
                        start = datetime.fromtimestamp(epoch, UTC)
                        _finding(
                            conn,
                            actor.tenant_id,
                            row["source_id"],
                            row["observation_id"],
                            RATE_RULE,
                            "Source activity exceeded the configured rate",
                            now,
                            finding_id=uuid5(row["source_id"], f"{RATE_RULE}:{start.isoformat()}"),
                            profile=profile,
                        )
                # Receipt-time health: implausible reported time is flagged, never corrected.
                skew = None
                if row["occurred_at"] > row["received_at"] + SKEW_AHEAD:
                    skew = "Reported time is ahead of receipt by more than five minutes"
                elif (
                    row["occurred_at"] < row["received_at"] - SKEW_BEHIND
                    # A directory's audit log is read on a schedule, from as far back as its
                    # retention holds: an entry behind its receipt is the read, not the clock.
                    and row["kind"] != "entra_audit"
                ):
                    skew = "Reported time is behind receipt by more than a day"
                if skew is not None:
                    _finding(
                        conn,
                        actor.tenant_id,
                        row["source_id"],
                        row["observation_id"],
                        SKEW_RULE,
                        skew,
                        now,
                        connection=row["connection_id"],
                    )
                conn.execute(
                    text("""
                    UPDATE execbound.monitor_observations
                    SET evaluation_state='COMPLETED', evaluation_result=:result, evaluated_at=:now
                    WHERE tenant_id=:t AND observation_id=:o
                """),
                    {
                        "result": result,
                        "now": now,
                        "t": actor.tenant_id,
                        "o": row["observation_id"],
                    },
                )
            _check_actor(conn, actor, clock)
            return len(rows)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def evaluate_health(
    db: Database, actor: Identity | ScheduledActor, *, clock: Clock = SYSTEM_CLOCK
) -> int:
    """Persist receipt-time source health; each new gap is one durable, delivered finding."""
    now = _now(clock)
    changed = 0
    try:
        with db.transaction(actor.tenant_id) as conn:
            _check_actor(conn, actor, clock)
            rows = (
                conn.execute(
                    text("""
                SELECT source_id, created_at, heartbeat_seconds, last_heartbeat_at,
                       last_event_at, health_state
                FROM execbound.monitor_sources
                WHERE tenant_id=:t AND active AND revoked_at IS NULL AND expires_at > :now
                ORDER BY source_id FOR UPDATE SKIP LOCKED
            """),
                    {"t": actor.tenant_id, "now": now},
                )
                .mappings()
                .all()
            )
            for row in rows:
                signals = [s for s in (row["last_heartbeat_at"], row["last_event_at"]) if s]
                latest = max(signals) if signals else None
                window = timedelta(seconds=2 * row["heartbeat_seconds"])
                if now - (latest or row["created_at"]) > window:
                    state = "STALE"
                elif latest is not None:
                    state = "REPORTING"
                else:
                    state = "UNKNOWN"
                if state != row["health_state"]:
                    changed += 1
                    if state == "STALE":
                        title = (
                            "Source stopped reporting"
                            if latest is not None
                            else "Source never reported after registration"
                        )
                        _finding(
                            conn,
                            actor.tenant_id,
                            row["source_id"],
                            None,
                            HEALTH_RULE,
                            title,
                            now,
                            finding_id=uuid5(row["source_id"], f"{HEALTH_RULE}:{now.isoformat()}"),
                        )
                conn.execute(
                    text("""
                    UPDATE execbound.monitor_sources
                    SET health_state=:state, health_checked_at=:now,
                        health_changed_at=CASE WHEN CAST(:state AS text) <> health_state THEN :now
                                               ELSE health_changed_at END
                    WHERE tenant_id=:t AND source_id=:s
                """),
                    {"state": state, "now": now, "t": actor.tenant_id, "s": row["source_id"]},
                )
            _check_actor(conn, actor, clock)
            return changed
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def _coverage_rows(
    conn: Connection, tenant: UUID, visibility: Visibility, now: datetime
) -> list[dict[str, Any]]:
    """Retained coverage: each discovered story beside the source that reports it, if any.

    Only the stories of connections in the spaces the reader sees, an open gap first and the
    oldest gap first among them, so healthy stories never push a gap past the 200 shown. The
    join to the sources stays tenant-wide: a story reported by a source in another space still
    reads as reported, and only the source's identifier is shown. Only an unrevoked source is
    named, so a story whose source was revoked reads as having none and can be reported again;
    one source at most, so a story's actions are counted once: one in a space the reader sees
    before one elsewhere, then, among those the reader sees, one whose token can report now
    before one whose token has expired, then the latest to expire. The row says whether the
    source it named is one the reader sees (`source_visible`) and, only for one they see,
    whether its token has expired (`source_expired`), because the gap is reassessed only by an
    inventory pass: a source registered since the last one is named beside a gap still open,
    and can report. Nothing about a source elsewhere follows its token: its `source_expired` is
    false, and which of several such sources is named goes by identifier alone. A revoked
    connection is never collected again, so no pass reassesses its stories' gaps, and the row
    says so (`connection_revoked`).
    """
    space = space_clause(visibility, "c")
    seen = space_clause(visibility, "u")
    return [
        dict(row)
        for row in conn.execute(
            text(
                # nosec B608 - a literal statement and the one helper's predicate; values bound
                """
        SELECT i.connection_id, i.external_id, i.name, i.disabled, i.gap_opened_at,
               i.coverage_class,
               bool_or(a.outbound IS TRUE) AS any_outbound,
               bool_or(a.outbound IS NULL AND a.external_id IS NOT NULL) AS any_unknown,
               count(a.external_id) AS action_count,
               max(s.source_id::text) AS source_id,
               coalesce(bool_or(s.expired), false) AS source_expired,
               coalesce(bool_or(s.seen), false) AS source_visible,
               bool_or(NOT c.active OR c.revoked_at IS NOT NULL) AS connection_revoked
        FROM execbound.monitor_inventory i
        JOIN execbound.monitor_connections c
          ON c.tenant_id=i.tenant_id AND c.connection_id=i.connection_id
        LEFT JOIN execbound.monitor_inventory a
          ON a.tenant_id=i.tenant_id AND a.connection_id=i.connection_id
          AND a.item_kind='action' AND a.story_external_id=i.external_id AND a.gone_at IS NULL
        LEFT JOIN LATERAL (
          SELECT u.source_id, u.expires_at <= :now AND (TRUE"""  # nosec B608 - literal
                + seen.sql
                + """) AS expired, (TRUE"""  # nosec B608 - literal
                + seen.sql
                + """) AS seen
          FROM execbound.monitor_sources u
          WHERE u.tenant_id=i.tenant_id AND u.story_id=i.external_id
            AND u.active AND u.revoked_at IS NULL
          ORDER BY seen DESC, CASE WHEN (TRUE"""  # nosec B608 - literal
                + seen.sql
                + """) THEN u.expires_at END DESC, u.source_id
          LIMIT 1
        ) s ON true
        WHERE i.tenant_id=:t AND i.item_kind='story' AND i.gone_at IS NULL"""  # nosec B608 - literal
                + space.sql
                + """
        GROUP BY i.connection_id, i.external_id, i.name, i.disabled, i.gap_opened_at,
                 i.coverage_class
        ORDER BY (i.gap_opened_at IS NULL), i.gap_opened_at, i.external_id LIMIT 200
    """
            ),
            {"t": tenant, "now": now, **space.params, **seen.params},
        ).mappings()
    ]


# A finding with what it is about: the observation it was raised on, the directory agent, the
# connection and the source it names. The sponsors themselves are not read; the row needs only
# their number, counted as the console API's `_sponsors` reads them (objects only).
FINDING_COLUMNS = (
    "f.finding_id, f.source_id, f.connection_id, f.observation_id, f.rule_version, f.title, "
    "f.created_at, f.acknowledged_at, f.acknowledged_by, f.acknowledgement_note, "
    "f.profile_id, f.profile_version, f.agent_id, o.story_id, o.action, o.target_ref, "
    "o.outcome, o.evidence, o.operation_name, o.actor_ref, a.display_name, a.identity_class, "
    "a.sponsor_state, "
    "(SELECT count(*) FROM jsonb_array_elements(a.sponsors) x "
    "WHERE jsonb_typeof(x) = 'object') AS sponsor_count, "
    "a.owner_count, a.linked_principal_id, n.label AS connection_label, s.label AS source_label"
)
FINDING_RELATION = (
    "execbound.monitor_findings f "
    "LEFT JOIN execbound.monitor_observations o "
    "ON o.tenant_id=f.tenant_id AND o.observation_id=f.observation_id "
    "LEFT JOIN execbound.monitor_agents a ON a.tenant_id=f.tenant_id AND a.agent_id=f.agent_id "
    "LEFT JOIN execbound.monitor_connections n "
    "ON n.tenant_id=f.tenant_id AND n.connection_id=f.connection_id "
    "LEFT JOIN execbound.monitor_sources s ON s.tenant_id=f.tenant_id AND s.source_id=f.source_id"
)
# A state names one of these literals and is never text from a request.
FINDING_STATES = {
    "open": " AND f.acknowledged_at IS NULL",
    "acknowledged": " AND f.acknowledged_at IS NOT NULL",
    "all": "",
}
FINDINGS_SHOWN = 200


def _finding_rows(
    conn: Connection,
    tenant: UUID,
    visibility: Visibility,
    *,
    state: str,
    finding_id: UUID | None = None,
    limit: int = FINDINGS_SHOWN,
) -> list[dict[str, Any]]:
    """The findings in one state that the reader's spaces hold, newest first: the one reader
    the snapshot, the findings list and the single finding share."""
    space = space_clause(visibility, "f")
    one = " AND f.finding_id=:f" if finding_id is not None else ""
    return [
        dict(row)
        for row in conn.execute(
            text(
                # nosec B608 - FINDING_COLUMNS, FINDING_RELATION and the state are literals
                # chosen above and the predicate is `space_clause`'s; values are bound
                f"SELECT {FINDING_COLUMNS} FROM {FINDING_RELATION} WHERE f.tenant_id=:t"  # nosec B608 - literals
                + FINDING_STATES[state]
                + one
                + space.sql
                + " ORDER BY f.created_at DESC, f.finding_id DESC LIMIT :limit"
            ),
            {"t": tenant, "f": finding_id, "limit": limit, **space.params},
        ).mappings()
    ]


def _finding_counts(conn: Connection, tenant: UUID, visibility: Visibility) -> dict[str, int]:
    """The open and acknowledged totals in the reader's spaces, counted beyond the page."""
    space = space_clause(visibility, "f")
    row = (
        conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE f.acknowledged_at IS NULL) AS open, "
                "count(*) FILTER (WHERE f.acknowledged_at IS NOT NULL) AS acknowledged "
                "FROM execbound.monitor_findings f WHERE f.tenant_id=:t" + space.sql  # nosec B608 - the one helper's predicate; values bound
            ),
            {"t": tenant, **space.params},
        )
        .mappings()
        .one()
    )
    return {"open": int(row["open"]), "acknowledged": int(row["acknowledged"])}


def _principal_rows(
    conn: Connection, tenant: UUID, ids: Sequence[UUID | None]
) -> list[dict[str, Any]]:
    """The kind, label and number of the principals these rows name, read in the caller's
    transaction (#678)."""
    return [
        {"principal_id": key, "kind": value.kind, "label": value.label, "number": value.number}
        for key, value in principal_facts(
            conn, tenant, [found for found in ids if found is not None]
        ).items()
    ]


def _profile_rows(conn: Connection, tenant: UUID) -> list[dict[str, Any]]:
    active = _active_profile(conn, tenant)
    if active is None:
        return []
    return [
        {
            "profile_id": active.profile_id,
            "version": active.version,
            "created_at": active.created_at,
            **active.profile.model_dump(),
        }
    ]


# What the Connections view reads of a connection, on alias `e`. Whether a run holds the
# connection, never which: the lease's id stays in the database, and so do a sealed key, the
# collector key it names and every key's fingerprint.
# A consented directory whose probe now refuses a permission it had: a capability the row reads
# as forbidden, and the finding `record_capabilities` raises when an available one turns
# forbidden (rule `COLLECTION_HEALTH_RULE`, title `HEALTH_TITLES["CAPABILITY_LOST"]`, written
# out here because this is a column expression). Updating the consent records a later one,
# which hides the line only until the first probe after it: a finding raised since that consent,
# or a probe since it that still reads a capability as forbidden, shows it again. A permission
# still refused raises no second finding, because the probe sees forbidden turn to forbidden.
CONSENT_NEEDS_UPDATE = (
    "(e.credential_mode = 'platform_app' "
    "AND EXISTS (SELECT 1 FROM jsonb_each(e.capabilities) AS c(name, value) "
    "WHERE c.value ->> 'state' = 'forbidden') "
    "AND EXISTS (SELECT 1 FROM execbound.monitor_findings f "
    "WHERE f.tenant_id = e.tenant_id AND f.connection_id = e.connection_id "
    "AND f.rule_version = 'collection-health.v1' "
    "AND f.title = 'A collection capability that was available is now refused' "
    "AND (f.created_at >= e.consented_at OR e.capabilities_at > e.consented_at))) "
    "AS consent_needs_update"
)
CONNECTION_COLUMNS = (
    "e.connection_id, e.kind, e.label, e.base_url, e.team_id, e.created_at, e.active, "
    "e.revoked_at, e.capabilities, e.capabilities_at, e.health_state, "
    "e.health_changed_at, e.audit_cursor, e.platform_tenant_ref, e.last_run_at, "
    "e.last_outcome, e.last_error_code, e.last_sync_at, e.retry_after_seconds, "
    "e.consecutive_rate_limited, e.consecutive_backlog, e.credential_mode, "
    "e.collect_interval_seconds, e.activity_interval_seconds, e.collect_requested_at, "
    "e.collect_requested_by, e.collecting_until, e.consented_at, e.consented_by, "
    + CONSENT_NEEDS_UPDATE
)


def snapshot(
    db: Database,
    session: Session,
    *,
    clock: Clock = SYSTEM_CLOCK,
) -> dict[str, Any]:
    # Each relation: its columns, its FROM clause, the alias its space predicate applies to
    # and its newest-first order. Sources, observations and connections carry
    # a space of their own; inventory takes its connection's, through the join, and a delivery
    # takes its finding's. Findings come from `_finding_rows`.
    relations: dict[str, tuple[str, str, str, str]] = {
        "sources": (
            SOURCE_COLUMNS,
            "execbound.monitor_sources e",
            "e",
            "e.created_at",
        ),
        "observations": (
            "e.observation_id, e.source_id, e.connection_id, e.event_id, e.story_id, e.version, "
            "e.occurred_at, e.received_at, e.kind, e.action, e.target_ref, e.outcome, "
            "e.rule_version, e.evaluation_state, e.evaluation_result, e.evaluated_at, "
            "e.integrity_conflict_at, e.evidence, e.operation_name, e.external_ref, e.actor_ref, "
            "e.input_tokens, e.output_tokens, "
            "ARRAY(SELECT x.finding_id FROM execbound.monitor_findings x "
            "WHERE x.tenant_id=e.tenant_id AND x.observation_id=e.observation_id/*x*/ "
            "ORDER BY x.created_at, x.finding_id) AS finding_ids",
            "execbound.monitor_observations e",
            "e",
            "e.received_at",
        ),
        "deliveries": (
            "d.delivery_id, d.finding_id, d.created_at, d.state, d.attempts, d.next_attempt_at, "
            "d.lease_until, d.delivered_at, d.last_error",
            "execbound.monitor_deliveries d JOIN execbound.monitor_findings e "
            "ON e.tenant_id=d.tenant_id AND e.finding_id=d.finding_id",
            "e",
            "d.created_at",
        ),
        "connections": (
            CONNECTION_COLUMNS,
            "execbound.monitor_connections e",
            "e",
            "e.created_at",
        ),
        "inventory": (
            "i.connection_id, i.item_kind, i.external_id, i.story_external_id, i.name, "
            "i.name_truncated, i.item_type, i.disabled, i.outbound, i.first_seen_at, "
            "i.last_seen_at, i.gone_at, i.source_updated_at, i.gap_opened_at",
            "execbound.monitor_inventory i JOIN execbound.monitor_connections e "
            "ON e.tenant_id=i.tenant_id AND e.connection_id=i.connection_id",
            "e",
            "i.last_seen_at",
        ),
    }
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            _session(conn, session, clock)
            tenant = session.identity.tenant_id
            visibility = visible_spaces(conn, session)
            result: dict[str, Any] = {}
            for key, (selected, relation, alias, order) in relations.items():
                space = space_clause(visibility, alias)
                # The findings an observation raised, under the findings' own predicate.
                selected = selected.replace("/*x*/", space_clause(visibility, "x").sql)
                params = {"t": tenant, **space.params}
                if key == "sources":
                    # Whether the reader administers each source's space (`ADMINISTERS`).
                    params["administrator"] = session.identity.principal_id
                result[key] = [
                    dict(row)
                    for row in conn.execute(
                        text(
                            # nosec B608 - selected/relation/order are the literals chosen
                            # above and every predicate is `space_clause`'s; only :t and
                            # the helper's own bound values reach the statement
                            f"SELECT {selected} FROM {relation} WHERE {alias}.tenant_id=:t"  # nosec B608 - literals; :t bound
                            + space.sql
                            + f" ORDER BY {order} DESC LIMIT 200"  # nosec B608 - literals; :t bound
                        ),
                        params,
                    ).mappings()
                ]
            result["findings"] = _finding_rows(conn, tenant, visibility, state="all")
            result["counts"] = _finding_counts(conn, tenant, visibility)
            result["coverage"] = _coverage_rows(conn, tenant, visibility, _now(clock))
            # Who acknowledged each finding, by kind and number, for the ids those rows name
            # (#678).
            result["acknowledgers"] = _principal_rows(
                conn, tenant, [row["acknowledged_by"] for row in result["findings"]]
            )
            # Who asked for each waiting collection, and who consented to each consented
            # directory, the same way (#678).
            result["requesters"] = _principal_rows(
                conn,
                tenant,
                [
                    person
                    for row in result["connections"]
                    for person in (row["collect_requested_by"], row["consented_by"])
                ],
            )
            result["profile"] = _profile_rows(conn, tenant)
            _session(conn, session, clock)
            return result
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def findings(
    db: Database, session: Session, state: str, *, clock: Clock = SYSTEM_CLOCK
) -> dict[str, Any]:
    """The findings in one state that the session's spaces hold, newest first and at most
    200, with the open and acknowledged totals counted beyond the page."""
    if state not in FINDING_STATES:
        raise MonitorError("INVALID_STATE")
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            _session(conn, session, clock)
            tenant = session.identity.tenant_id
            visibility = visible_spaces(conn, session)
            rows = _finding_rows(conn, tenant, visibility, state=state)
            result = {
                "findings": rows,
                "counts": _finding_counts(conn, tenant, visibility),
                "profile": _profile_rows(conn, tenant),
                "principals": _principal_rows(
                    conn, tenant, [row["acknowledged_by"] for row in rows]
                ),
            }
            _session(conn, session, clock)
            return result
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def finding(
    db: Database, session: Session, finding_id: UUID, *, clock: Clock = SYSTEM_CLOCK
) -> dict[str, Any]:
    """One finding the session's spaces hold. One outside them is refused exactly as one that
    does not exist."""
    if type(finding_id) is not UUID:
        raise MonitorError("FINDING_UNAVAILABLE")
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            _session(conn, session, clock)
            tenant = session.identity.tenant_id
            rows = _finding_rows(
                conn, tenant, visible_spaces(conn, session), state="all", finding_id=finding_id
            )
            if not rows:
                raise MonitorError("FINDING_UNAVAILABLE")
            result = {
                "finding": rows[0],
                "principals": _principal_rows(conn, tenant, [rows[0]["acknowledged_by"]]),
            }
            _session(conn, session, clock)
            return result
    except MonitorError:
        raise
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


AGENT_COLUMNS = (
    "agent_id, connection_id, platform_ref, identity_class, display_name, enabled, "
    "blueprint_ref, blueprint_object_ref, credential_kinds, sponsors, sponsor_state, "
    "sponsor_group_count, owner_count, tags, linked_principal_id, first_seen_at, observed_at, "
    "gone_at, reach_gap_opened_at, sponsor_gap_opened_at"
)


def _agent_counts(
    conn: Connection, tenant: UUID, consequential: list[str], now: datetime
) -> dict[UUID, dict[str, Any]]:
    rows = conn.execute(
        text("""
        SELECT r.agent_id,
               count(*) FILTER (
                   WHERE r.path_kind IN ('grant', 'role', 'inherited')
                     AND r.action = ANY(:actions) AND r.valid_until > :now
               ) AS consequential,
               count(*) FILTER (WHERE r.path_kind = 'execbound') AS governed,
               count(*) FILTER (WHERE r.valid_until <= :now) AS lapsed
        FROM execbound.monitor_agent_reach r
        WHERE r.tenant_id = :t AND r.gone_at IS NULL
        GROUP BY r.agent_id
    """),
        {"t": tenant, "actions": consequential, "now": now},
    ).mappings()
    return {row["agent_id"]: dict(row) for row in rows}


def agents_snapshot(
    db: Database, session: Session, *, clock: Clock = SYSTEM_CLOCK
) -> dict[str, Any]:
    """The Agents page's rows, and a tenant line that states its own denominator."""
    now = _now(clock)
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            _session(conn, session, clock)
            tenant = session.identity.tenant_id
            profile = _active_profile(conn, tenant)
            consequential = sorted(profile.profile.sensitive_actions) if profile else []
            total = conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_agents "
                    "WHERE tenant_id=:t AND gone_at IS NULL"
                ),
                {"t": tenant},
            ).scalar_one()
            agents = [
                dict(row)
                for row in conn.execute(
                    text(
                        # AGENT_COLUMNS is a literal; only :t is bound.
                        f"SELECT {AGENT_COLUMNS} FROM execbound.monitor_agents "  # nosec B608 - a literal
                        "WHERE tenant_id=:t AND gone_at IS NULL "
                        "ORDER BY identity_class, display_name LIMIT 200"
                    ),
                    {"t": tenant},
                ).mappings()
            ]
            counts = _agent_counts(conn, tenant, consequential, now)
            grants = conn.execute(
                text(
                    "SELECT agent_id, grant_kind, resource_ref, value FROM "
                    "execbound.monitor_agent_grants WHERE tenant_id=:t AND gone_at IS NULL"
                ),
                {"t": tenant},
            ).mappings()
            unresolved: dict[UUID, int] = {}
            for grant in grants:
                if not PRODUCTION_GRANTS.lookup(
                    ENTRA, grant["grant_kind"], grant["resource_ref"], grant["value"]
                ):
                    unresolved[grant["agent_id"]] = unresolved.get(grant["agent_id"], 0) + 1
            space = space_clause(visible_spaces(conn, session), "e")
            findings = conn.execute(
                text(
                    "SELECT e.agent_id, count(*) AS open FROM execbound.monitor_findings e "
                    "WHERE e.tenant_id=:t AND e.agent_id IS NOT NULL "
                    "AND e.acknowledged_at IS NULL"
                    + space.sql  # nosec B608 - one helper's predicate; values are bound
                    + " GROUP BY e.agent_id"
                ),
                {"t": tenant, **space.params},
            ).mappings()
            open_findings = {row["agent_id"]: row["open"] for row in findings}
            for agent in agents:
                row = counts.get(agent["agent_id"], {})
                agent["consequential"] = row.get("consequential", 0)
                agent["governed"] = row.get("governed", 0)
                agent["lapsed"] = row.get("lapsed", 0)
                agent["unresolved"] = unresolved.get(agent["agent_id"], 0)
                agent["open_findings"] = open_findings.get(agent["agent_id"], 0)
            principals = _principal_rows(
                conn, tenant, [agent["linked_principal_id"] for agent in agents]
            )
            _session(conn, session, clock)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return {
        "principals": principals,
        "agents": agents,
        "consequential": consequential,
        "tenant": {
            # Every number here counts agents this connection could enumerate. It is not a
            # count of the agents that exist, and the page says so in those words.
            "enumerated": total,
            "shown": len(agents),
            "with_reach": sum(1 for a in agents if a["consequential"]),
            "governed": sum(1 for a in agents if a["governed"]),
            # Reach we could not establish: a grant the catalog cannot explain, a claim whose
            # proof has lapsed, or accountability the directory would not let us read.
            "unestablished": sum(
                1
                for a in agents
                if a["unresolved"]
                or a["lapsed"]
                or a["sponsor_state"] in {"unreadable", "not_read"}
            ),
        },
    }


def agent_detail(
    db: Database, session: Session, agent_id: UUID, *, clock: Clock = SYSTEM_CLOCK
) -> dict[str, Any]:
    """One agent: its grants, every path it reaches, and what could not be established."""
    now = _now(clock)
    if type(agent_id) is not UUID:
        raise MonitorError("AGENT_UNAVAILABLE")
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            _session(conn, session, clock)
            tenant = session.identity.tenant_id
            agent = (
                conn.execute(
                    text(
                        # AGENT_COLUMNS is a literal; only the tenant and agent are bound.
                        f"SELECT {AGENT_COLUMNS} FROM execbound.monitor_agents "  # nosec B608 - a literal
                        "WHERE tenant_id=:t AND agent_id=:a"
                    ),
                    {"t": tenant, "a": agent_id},
                )
                .mappings()
                .one_or_none()
            )
            if agent is None:
                raise MonitorError("AGENT_UNAVAILABLE")
            grants = [
                dict(row)
                for row in conn.execute(
                    text(
                        "SELECT grant_kind, resource_ref, value, inherited, path_ref, "
                        "observed_at, gone_at FROM execbound.monitor_agent_grants "
                        "WHERE tenant_id=:t AND agent_id=:a ORDER BY grant_kind, value LIMIT 200"
                    ),
                    {"t": tenant, "a": agent_id},
                ).mappings()
            ]
            for grant in grants:
                entries = PRODUCTION_GRANTS.lookup(
                    ENTRA, grant["grant_kind"], grant["resource_ref"], grant["value"]
                )
                grant["actions"] = sorted({entry.action for entry in entries})
                grant["breadth"] = entries[0].breadth if entries else None
            reach_rows = [
                dict(row)
                for row in conn.execute(
                    text(
                        "SELECT r.action, r.path_kind, r.path_ref, r.certainty, "
                        "r.enforcement_mode, r.catalog_version, r.computed_at, r.valid_until, "
                        "r.gone_at, e.reason_code, e.accepted_at, e.expires_at "
                        "FROM execbound.monitor_agent_reach r "
                        "LEFT JOIN execbound.monitor_reach_exceptions e "
                        "  ON e.tenant_id=r.tenant_id AND e.agent_id=r.agent_id "
                        "     AND e.action=r.action AND e.path_kind=r.path_kind "
                        "     AND e.path_ref=r.path_ref AND e.withdrawn_at IS NULL "
                        "WHERE r.tenant_id=:t AND r.agent_id=:a "
                        "ORDER BY r.action, r.path_kind LIMIT 200"
                    ),
                    {"t": tenant, "a": agent_id},
                ).mappings()
            ]
            for row in reach_rows:
                row["effective"] = reach.effective(row, now)
            # The findings the read and acknowledge routes would answer for: the reads' own
            # space predicate, so this list names nothing in a space the session does not see.
            space = space_clause(visible_spaces(conn, session), "f")
            findings = [
                dict(row)
                for row in conn.execute(
                    text(
                        "SELECT f.finding_id, f.rule_version, f.title, f.created_at, "
                        "f.acknowledged_at FROM execbound.monitor_findings f "
                        "WHERE f.tenant_id=:t AND f.agent_id=:a"
                        + space.sql  # nosec B608 - the one helper's predicate; values bound
                        + " ORDER BY f.created_at DESC LIMIT 50"
                    ),
                    {"t": tenant, "a": agent_id, **space.params},
                ).mappings()
            ]
            observations = [
                dict(row)
                for row in conn.execute(
                    text(
                        "SELECT occurred_at, kind, action, outcome, operation_name "
                        "FROM execbound.monitor_observations "
                        "WHERE tenant_id=:t AND actor_ref=:ref "
                        "ORDER BY occurred_at DESC LIMIT 50"
                    ),
                    {"t": tenant, "ref": agent["platform_ref"]},
                ).mappings()
            ]
            principals = _principal_rows(conn, tenant, [agent["linked_principal_id"]])
            _session(conn, session, clock)
    except MonitorError:
        raise
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return {
        "principals": principals,
        "agent": dict(agent),
        "grants": grants,
        "reach": reach_rows,
        "findings": findings,
        "observations": observations,
        "unresolved": sum(1 for g in grants if not g["actions"] and g["gone_at"] is None),
    }


# A person's note on an acknowledgement: at most this many characters after trimming.
NOTE_LIMIT = 500


def _note(note: str | None) -> str | None:
    """A person's note, trimmed, or a refusal that never carries it.

    Empty after trimming is no note. A note that is not printable text (newlines aside), is
    longer than `NOTE_LIMIT` or is shaped like a secret is refused as `INVALID_NOTE`, the
    screen every other piece of people's text passes (T7.7).
    """
    if note is None:
        return None
    if type(note) is not str:
        raise MonitorError("INVALID_NOTE")
    value = note.strip()
    if not value:
        return None
    if (
        len(value) > NOTE_LIMIT
        or not value.replace("\n", " ").isprintable()
        or secret_shaped(value)
    ):
        raise MonitorError("INVALID_NOTE")
    return value


def acknowledge(
    db: Database,
    session: Session,
    finding_id: UUID,
    *,
    note: str | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> None:
    """Acknowledge one finding in the reader's spaces, with an optional note.

    An acknowledgement is final. Acknowledging an acknowledged finding again without a note
    changes nothing; with a note it is refused as `ACKNOWLEDGED`, because the note would not
    be saved.
    """
    if type(finding_id) is not UUID:
        raise MonitorError("FINDING_UNAVAILABLE")
    value = _note(note)
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            _session(conn, session, clock)
            # The reads' own predicate: a finding in a space this session does not see is
            # refused exactly as one that does not exist, so naming its identifier neither
            # acknowledges it nor says that it is there.
            space = space_clause(visible_spaces(conn, session), "f")
            row = (
                conn.execute(
                    text(
                        "SELECT f.acknowledged_at, f.rule_version, f.space_id "
                        "FROM execbound.monitor_findings f "
                        "WHERE f.tenant_id=:t AND f.finding_id=:f"
                        + space.sql  # nosec B608 - the one helper's predicate; values bound
                        + " FOR UPDATE OF f"
                    ),
                    {"t": session.identity.tenant_id, "f": finding_id, **space.params},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise MonitorError("FINDING_UNAVAILABLE")
            if row["acknowledged_at"] is None:
                _acknowledge_row(conn, session, row, finding_id, _now(clock), value)
            elif value is not None:
                raise MonitorError("ACKNOWLEDGED")
            _session(conn, session, clock)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


# The most findings one bulk acknowledgement takes. It bounds the transaction's lock set.
BULK_LIMIT = 50


def acknowledge_many(
    db: Database,
    session: Session,
    finding_ids: Sequence[UUID],
    *,
    note: str | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> list[tuple[UUID, str]]:
    """Acknowledge up to `BULK_LIMIT` findings with one shared note, answering for each.

    The answer is in request order: `acknowledged` for a finding this call acknowledged,
    `already_acknowledged` for one someone had (its note is left as it was), and
    `unavailable` for one outside the reader's spaces or that does not exist, which are not
    told apart. A duplicate, a value that is not an identifier, or an empty or oversized
    batch is refused as `INVALID_INPUT` before anything is read.

    The visible rows are locked in `finding_id` order, so two overlapping batches take their
    locks in the same order and neither can wait on a row the other holds while holding one
    it wants.
    """
    ids = list(finding_ids) if isinstance(finding_ids, (list, tuple)) else None
    if (
        ids is None
        or not 1 <= len(ids) <= BULK_LIMIT
        or any(type(item) is not UUID for item in ids)
        or len(set(ids)) != len(ids)
    ):
        raise MonitorError("INVALID_INPUT")
    value = _note(note)
    outcomes: dict[UUID, str] = {}
    try:
        with db.transaction(session.identity.tenant_id) as conn:
            _session(conn, session, clock)
            space = space_clause(visible_spaces(conn, session), "f")
            rows = (
                conn.execute(
                    text(
                        "SELECT f.finding_id, f.acknowledged_at, f.rule_version, f.space_id "
                        "FROM execbound.monitor_findings f "
                        "WHERE f.tenant_id=:t AND f.finding_id = ANY(CAST(:ids AS uuid[]))"
                        + space.sql  # nosec B608 - the one helper's predicate; values bound
                        + " ORDER BY f.finding_id FOR UPDATE OF f"
                    ),
                    {
                        "t": session.identity.tenant_id,
                        "ids": [str(item) for item in ids],
                        **space.params,
                    },
                )
                .mappings()
                .all()
            )
            now = _now(clock)
            for row in rows:
                finding = row["finding_id"]
                if row["acknowledged_at"] is None:
                    _acknowledge_row(conn, session, row, finding, now, value)
                    outcomes[finding] = "acknowledged"
                else:
                    outcomes[finding] = "already_acknowledged"
            _session(conn, session, clock)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return [(item, outcomes.get(item, "unavailable")) for item in ids]


def _acknowledge_row(
    conn: Connection,
    session: Session,
    row: Any,
    finding_id: UUID,
    now: datetime,
    note: str | None,
) -> None:
    """Acknowledge one open finding the caller has locked, and audit it in the same transaction.

    The event is an administrator's decision about a finding, not monitoring history: it
    names the finding, its rule and the credential that acted (a browser session's, or a
    personal access token's backing credential), and carries no observation content; the
    person's screened note, when there is one, goes with it. The finding's space goes on the
    row's own column. An already acknowledged finding is the caller's to skip; the guard here
    only keeps a second update from writing again.
    """
    identity = session.identity
    updated = conn.execute(
        text(
            "UPDATE execbound.monitor_findings SET acknowledged_at=:now, acknowledged_by=:p, "
            "acknowledgement_note=:note "
            "WHERE tenant_id=:t AND finding_id=:f AND acknowledged_at IS NULL"
        ),
        {
            "now": now,
            "p": identity.principal_id,
            "note": note,
            "t": identity.tenant_id,
            "f": finding_id,
        },
    ).rowcount
    if updated != 1:
        return
    append_event(
        conn,
        identity.tenant_id,
        identity.principal_id,
        "monitor.finding_acknowledged",
        {
            "finding_id": str(finding_id),
            "rule_version": row["rule_version"],
            **({"note": note} if note is not None else {}),
            **acted_with(identity.credential_id),
        },
        space=row["space_id"],
    )


# Collection freshness: one rule, read at request time from server time, that the setup
# verifier, the Connections view and the counts all call. It writes nothing.
COLLECTION_FRESH = timedelta(days=1)
# Inventory is re-read once a day, on the first run after it falls due
# (collection.SYNC_INTERVAL), so a healthy hourly collector's last sync is routinely a run
# interval older than a day. Two days is where a missing sync stops being timing and becomes
# a fault.
SYNC_FRESH = 2 * COLLECTION_FRESH
# The count of overdue connections, under the caller's space predicate on alias `e`: the same
# rule and the same boundary as `collection_overdue_since`, with `:now`,
# `:fresh_after = now - COLLECTION_FRESH` and `:sync_after = now - SYNC_FRESH`. A connection
# the scheduled collector opens itself is overdue at twice its own interval or a day,
# whichever is shorter: `now - least(2 * interval, a day)` is the later of `now - 2 * interval`
# and `:fresh_after`. The numbers are the kinds' default intervals (`DEFAULT_ACTIVITY_SECONDS`,
# `DEFAULT_COLLECT_SECONDS`), which a test holds this to.
OVERDUE_CONNECTIONS = (
    "SELECT count(*) FROM execbound.monitor_connections e "
    "WHERE e.tenant_id = :t AND e.active AND e.revoked_at IS NULL "
    "AND (COALESCE(e.last_run_at, e.created_at) <= CASE WHEN e.credential_mode = 'key_file' "
    "THEN CAST(:fresh_after AS timestamptz) "
    "ELSE GREATEST(CAST(:fresh_after AS timestamptz), CAST(:now AS timestamptz) - "
    "make_interval(secs => 2 * CASE WHEN e.kind = 'tines' "
    "THEN COALESCE(e.activity_interval_seconds, 900) "
    "ELSE COALESCE(e.collect_interval_seconds, 21600) END)) END "
    "OR e.last_sync_at <= :sync_after)"
)


def overdue_bounds(now: datetime) -> dict[str, datetime]:
    """The bound values `OVERDUE_CONNECTIONS` compares with, from one instant."""
    return {"now": now, "fresh_after": now - COLLECTION_FRESH, "sync_after": now - SYNC_FRESH}


def _overdue_after(row: Mapping[str, Any]) -> timedelta:
    """How long after its last run a connection is overdue. A day for an operator's key file,
    whose presence on the collector the database does not know; for a connection the
    scheduled collector opens itself, twice its own interval or a day, whichever is shorter:
    the activity interval for Tines, whose every run reads audit records, and the collect
    interval for Entra, each with its default where the row leaves it null."""
    if row.get("credential_mode", "key_file") == "key_file":
        return COLLECTION_FRESH
    if row["kind"] == "tines":
        every = row["activity_interval_seconds"] or DEFAULT_ACTIVITY_SECONDS
    else:
        every = row["collect_interval_seconds"] or DEFAULT_COLLECT_SECONDS[row["kind"]]
    return min(2 * timedelta(seconds=every), COLLECTION_FRESH)


def collection_overdue_since(row: Mapping[str, Any], now: datetime) -> datetime | None:
    """When an active connection's collection evidence went stale: a while after its last run
    of any outcome (or its registration, if it never ran; `_overdue_after` says how long), or
    two days after its last inventory sync, whichever is first. None while it is fresh, and
    for an inactive or revoked connection. An error inside that while is the run's error, not
    a stalled collector."""
    if not row["active"] or row["revoked_at"] is not None:
        return None
    due: datetime = (row["last_run_at"] or row["created_at"]) + _overdue_after(row)
    if row["last_sync_at"] is not None:
        due = min(due, row["last_sync_at"] + SYNC_FRESH)
    return due if due <= now else None


def collection_reporting(row: Mapping[str, Any], now: datetime) -> bool:
    """Whether a connection's evidence shows collection running and complete: the one test
    behind the verifier's `reporting` and the Connections view's allow tone."""
    states = {
        value.get("state")
        for value in (row["capabilities"] or {}).values()
        if isinstance(value, dict)
    }
    return bool(
        row["active"]
        and row["revoked_at"] is None
        and collection_overdue_since(row, now) is None
        and row["last_outcome"] == "COMPLETE"
        and row["last_error_code"] is None
        and row["last_sync_at"] is not None
        and "available" in states
        and "forbidden" not in states
    )


MAX_CONNECTIONS = 20
MAX_INVENTORY = 6000
MAX_CONNECTION_EVENTS = 200000
# How long a Microsoft Entra connection's audit reads may go without catching up with the log
# before the health finding says so (#355): longer than a quiet directory's first look-back
# takes, short of the seven days Graph keeps the log on Entra ID Free.
AUDIT_BEHIND_ALERT = timedelta(days=1)
# How far apart a directory may log one change, as one request's `Update user` and `Disable
# account`, under one correlation id, and its entries still be one observation (#355). A caller
# may use its correlation id again; the same assertion under it logged later is an observation
# of its own, so a reused id never folds a later action into an earlier one.
AUDIT_SAME_CHANGE = timedelta(seconds=10)
# The least a receipt after a connection's activity baseline is later than it: what the
# database's moments resolve.
_AFTER = timedelta(microseconds=1)
GAP_RULE = "instrumentation-gap.v1"
COLLECTION_HEALTH_RULE = "collection-health.v1"
# The outcomes a run records of itself. `INTERRUPTED` is not one: only a claim that finds a
# lease expired unfinished records it (0086), because a run cannot know it was interrupted.
RUN_OUTCOMES = frozenset(
    {"COMPLETE", "BACKLOG", "RATE_LIMITED", "AUTH_LOST", "RETENTION_GAP", "ERROR"}
)
RATE_LIMIT_EPISODES = 3
BACKLOG_EPISODES = 5
COVERAGE_CLASSES = (
    "instrumented",
    "registered_stale",
    "discovered_only",
    "no_outbound",
    "coverage_unknown",
    "disabled",
)
HEALTH_TITLES = {
    "AUTH_LOST": "Collection lost permission on the connected platform",
    "RATE_LIMITED": "Collection is repeatedly rate limited by the platform",
    "RETENTION_GAP": "Audit retention passed the collection cursor; a window is unrecoverable",
    "BACKLOG": "Collection has not caught up with the platform's audit backlog",
    "FOREIGN_TENANT": "A response claimed a different platform tenant and was quarantined",
    "CAPABILITY_LOST": "A collection capability that was available is now refused",
    # A directory's audit read refused by the connection's observation bound (#355): nothing
    # removes an observation, so no later read records more.
    "CAPACITY": "Collection reached the connection's observation bound and records no more",
}


def _connection_key(tenant: UUID) -> str:
    return f"monitor-connections:{tenant}"


CONNECTION_KINDS = ("tines", "entra_agent_id")
GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"


def _connection_shape(
    kind: str, base_url: str, team_id: str | None, directory_ref: str | None, client_ref: str | None
) -> bool:
    """Each platform's connection carries what its own reads need, and nothing else."""
    if kind == "tines":
        return (
            re.fullmatch(r"https://[A-Za-z0-9.-]{1,240}\.tines\.(com|io)", base_url) is not None
            and directory_ref is None
            and client_ref is None
            and (team_id is None or re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", team_id) is not None)
        )
    # The token request needs the directory and the app registration before any read; a
    # team scope is a Tines concept with no equivalent here.
    return (
        base_url == GRAPH_ORIGIN
        and team_id is None
        and directory_ref is not None
        and client_ref is not None
        and re.fullmatch(GUID, directory_ref) is not None
        and re.fullmatch(GUID, client_ref) is not None
    )


def _check_connection_space(conn: Connection, identity: Identity, space: UUID) -> None:
    archived = conn.execute(
        text(
            "SELECT archived_at IS NOT NULL FROM execbound.spaces "
            "WHERE tenant_id=:t AND space_id=:s"
        ),
        {"t": identity.tenant_id, "s": space},
    ).scalar_one_or_none()
    may_administer = conn.execute(
        text(
            "SELECT NOT EXISTS (SELECT 1 FROM execbound.space_members "
            "WHERE tenant_id=:t AND principal_id=:p) OR EXISTS ("
            "SELECT 1 FROM execbound.space_members WHERE tenant_id=:t "
            "AND principal_id=:p AND space_id=:s AND role='ADMIN')"
        ),
        {"t": identity.tenant_id, "p": identity.principal_id, "s": space},
    ).scalar_one()
    # check_admin verifies the live tenant-level identity in this same transaction.
    # A membership narrows it: reviewer access never grants collector administration.
    if archived is not False or not may_administer:
        raise MonitorError("INVALID_SPACE")


def create_connection(
    db: Database,
    identity: Identity,
    *,
    label: str,
    base_url: str,
    key_fingerprint: str,
    kind: str = "tines",
    team_id: str | None = None,
    directory_ref: str | None = None,
    client_ref: str | None = None,
    clock: Clock = SYSTEM_CLOCK,
    space: UUID | None = None,
) -> UUID:
    """Register one active read-only collection connection per space for that platform."""
    now = _now(clock)
    if (
        type(label) is not str
        or not 1 <= len(label) <= 96
        or not label.strip()
        or not label.isprintable()
        or type(base_url) is not str
        or kind not in CONNECTION_KINDS
        or type(key_fingerprint) is not str
        or re.fullmatch(r"[0-9a-f]{64}", key_fingerprint) is None
        or not _connection_shape(kind, base_url, team_id, directory_ref, client_ref)
        # The label and team id reach the audit chain: one that reads as a secret is refused
        # rather than recorded.
        or secret_shaped(label, base_url, team_id)
    ):
        raise MonitorError("INVALID_INPUT")
    connection_id = uuid4()
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_admin(conn, identity, clock=clock)
            conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": _connection_key(identity.tenant_id)},
            )
            if (
                conn.execute(
                    text("SELECT count(*) FROM execbound.monitor_connections")
                ).scalar_one()
                >= MAX_CONNECTIONS
            ):
                raise MonitorError("CONNECTION_CAPACITY")
            # One per platform, not one in total: a tenant runs Tines and Entra at once.
            space = space or default_space(conn, identity.tenant_id)
            # Operator commands may name a space, but that name grants no authority.
            # Recheck membership and archive inside this registration transaction,
            # including the implicit default. Space tables remain SELECT-only to the
            # runtime; registration confers no execution authority.
            _check_connection_space(conn, identity, space)
            # One per platform per space, not one per tenant: an MSSP runs one Tines
            # connection for each of its customers, and a tenant runs Tines and Entra
            # at once.
            if conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM execbound.monitor_connections "
                    "WHERE active AND kind = :kind AND space_id = :space)"
                ),
                {"kind": kind, "space": space},
            ).scalar_one():
                raise MonitorError("CONNECTION_EXISTS")
            conn.execute(
                text("""
                INSERT INTO execbound.monitor_connections
                (tenant_id, connection_id, label, base_url, team_id, key_fingerprint,
                 created_at, created_by, kind, directory_ref, client_ref, space_id)
                VALUES (:t, :c, :label, :url, :team, :hash, :now, :by, :kind, :dir, :client,
                        :space)
            """),
                {
                    "t": identity.tenant_id,
                    "space": space or default_space(conn, identity.tenant_id),
                    "c": connection_id,
                    "label": label,
                    "url": base_url,
                    "team": team_id,
                    "hash": key_fingerprint,
                    "now": now,
                    "by": identity.principal_id,
                    "kind": kind,
                    "dir": directory_ref,
                    "client": client_ref,
                },
            )
            check_admin(conn, identity, clock=clock)
            _check_connection_space(conn, identity, space)
            # A connection holds or reaches a credential, so who registered it is evidence
            # beside the tenant's chain: the last write, under the registry lock.
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "monitor.connection_created",
                {
                    "connection_id": str(connection_id),
                    "space_id": str(space),
                    "kind": kind,
                    "credential_mode": "key_file",
                    "label": label,
                    **acted_with(identity.credential_id),
                },
                space=space,
            )
    except IntegrityError as exc:
        # One active Microsoft Entra connection per directory across the deployment (0088): a
        # directory another workspace reads is refused by name, and the workspace not named.
        diagnostic = getattr(exc.orig, "diag", None)
        if getattr(diagnostic, "constraint_name", None) == "monitor_connections_directory_once":
            raise MonitorError("DIRECTORY_UNAVAILABLE") from None
        raise MonitorError() from None
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return connection_id


def _administers(conn: Connection, identity: Identity, space: UUID) -> bool:
    """`_check_connection_space`'s membership rule alone (`ADMINISTERS`): a membership narrows
    an administrator to the spaces they administer. An archived space's connection may still be
    revoked, because revoking takes nothing new into it."""
    return bool(
        conn.execute(
            text("SELECT " + ADMINISTERS.format(space=":s")),
            {"t": identity.tenant_id, "administrator": identity.principal_id, "s": space},
        ).scalar_one()
    )


def placement(
    db: Database, session: Session, *, clock: Clock = SYSTEM_CLOCK
) -> dict[str, Any] | None:
    """Where a connection or reporting source made now in this session lands: the session's
    write space by id and name, whether it is archived and whether this administrator
    administers it. None where the session sees several spaces and has chosen none, so nothing
    is guessed."""
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            _session(conn, session, clock)
            try:
                space = write_space(conn, identity.tenant_id, visible_spaces(conn, session))
            except SpaceError:
                return None
            row = (
                conn.execute(
                    text(
                        "SELECT sp.space_id, sp.name, sp.archived_at IS NOT NULL AS archived, "  # nosec B608 - literals and the module's own expression; values bound
                        + ADMINISTERS.format(space="sp.space_id")
                        + " AS administered FROM execbound.spaces sp "
                        "WHERE sp.tenant_id=:t AND sp.space_id=:s"
                    ),
                    {"t": identity.tenant_id, "s": space, "administrator": identity.principal_id},
                )
                .mappings()
                .one_or_none()
            )
            _session(conn, session, clock)
            return dict(row) if row is not None else None
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def revoke_connection(
    db: Database,
    identity: Identity,
    connection_id: UUID,
    *,
    clock: Clock = SYSTEM_CLOCK,
    session: Session | None = None,
) -> None:
    """Stop collecting a connection for good, keeping its row and its evidence.

    The statement that clears `active` also ends any lease a run holds (0086's trigger), so a
    run in progress writes nothing more. One administrator narrowed to other spaces is refused;
    with a console `session`, a connection outside its spaces does not exist for it. The
    revocation appends `monitor.connection_revoked` as its last write.
    """
    now = _now(clock)
    if type(connection_id) is not UUID:
        raise MonitorError("CONNECTION_UNAVAILABLE")
    try:
        with db.transaction(identity.tenant_id) as conn:
            if session is None:
                check_admin(conn, identity, clock=clock)
            else:
                _session(conn, session, clock)
            conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": _connection_key(identity.tenant_id)},
            )
            row = (
                conn.execute(
                    text(
                        "SELECT space_id, active FROM execbound.monitor_connections "
                        "WHERE tenant_id=:t AND connection_id=:c FOR UPDATE"
                    ),
                    {"t": identity.tenant_id, "c": connection_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None or (
                session is not None and not visible_spaces(conn, session).allows(row["space_id"])
            ):
                raise MonitorError("CONNECTION_UNAVAILABLE")
            if not row["active"]:
                raise MonitorError("CONNECTION_REVOKED")
            if not _administers(conn, identity, row["space_id"]):
                raise MonitorError("INVALID_ADMIN")
            conn.execute(
                text("""
                UPDATE execbound.monitor_connections SET active=false, revoked_at=:now
                WHERE tenant_id=:t AND connection_id=:c AND active
            """),
                {"now": now, "t": identity.tenant_id, "c": connection_id},
            )
            if session is None:
                check_admin(conn, identity, clock=clock)
            else:
                _session(conn, session, clock)
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "monitor.connection_revoked",
                {"connection_id": str(connection_id), **acted_with(identity.credential_id)},
                space=row["space_id"],
            )
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def release_directories(conn: Connection, tenant: UUID, actor: UUID, now: datetime) -> list[UUID]:
    """Revoke a workspace's active Microsoft Entra connections, in the transaction of an owner
    operation that deactivates the workspace.

    A directory is connected in one workspace across the whole deployment, and a deactivated
    workspace can neither revoke a connection nor learn why another workspace is refused its
    directory, so deactivation gives the directory up. The statement that clears `active` frees
    each directory's claim (0088's trigger) and ends any lease a run holds (0086's). Each
    revocation appends `monitor.connection_revoked` under `actor`, the operation's own; no
    credential acted. The connections' other evidence stays, and reactivating the workspace
    does not restore them.
    """
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": _connection_key(tenant)},
    )
    revoked = (
        conn.execute(
            text("""
            UPDATE execbound.monitor_connections SET active=false, revoked_at=:now
            WHERE tenant_id=:t AND kind='entra_agent_id' AND active
            RETURNING connection_id, space_id
        """),
            {"now": now, "t": tenant},
        )
        .mappings()
        .all()
    )
    ordered = sorted(revoked, key=lambda row: str(row["connection_id"]))
    for row in ordered:
        append_event(
            conn,
            tenant,
            actor,
            "monitor.connection_revoked",
            {"connection_id": str(row["connection_id"])},
            space=row["space_id"],
        )
    return [row["connection_id"] for row in ordered]


def _unleased(conn: Connection, tenant: UUID, connection_id: UUID) -> MonitorError:
    """Why a leased write found no row: the connection was revoked, or the lease is not this
    run's any more.

    Every write a run makes to its connection row (0086) carries
    `AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))` in its own
    statement: it lands only while the run still holds the lease on an active connection, and
    without a lease, as an operator's own call to a writer, the condition adds nothing."""
    active = conn.execute(
        text(
            "SELECT active FROM execbound.monitor_connections "
            "WHERE tenant_id=:t AND connection_id=:c"
        ),
        {"t": tenant, "c": connection_id},
    ).scalar_one_or_none()
    return MonitorError("LEASE_LOST" if active else "CONNECTION_REVOKED")


def _leased(row: Mapping[str, Any], lease: UUID | None) -> None:
    """For a run's step that writes no connection row: the lease is still this run's, on an
    active connection. The row is locked, so neither can change before commit."""
    if lease is None:
        return
    if not row["active"] or row["revoked_at"] is not None:
        raise MonitorError("CONNECTION_REVOKED")
    if row["collecting_lease"] != lease:
        raise MonitorError("LEASE_LOST")


def _locked_connection(
    conn: Connection,
    tenant: UUID,
    connection_id: UUID,
    *,
    lease: UUID | None = None,
    guarded: bool = False,
) -> dict[str, Any]:
    """The connection row, locked. Without a lease an inactive one is refused. With one, the
    lease is checked here (`_leased`), or, where `guarded`, by the caller's own write to the
    connection row, so that the write itself is what refuses a stale run."""
    if type(connection_id) is not UUID:
        raise MonitorError("CONNECTION_UNAVAILABLE")
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": _connection_key(tenant)},
    )
    row = (
        conn.execute(
            text(
                "SELECT * FROM execbound.monitor_connections "
                "WHERE tenant_id=:t AND connection_id=:c FOR UPDATE"
            ),
            {"t": tenant, "c": connection_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise MonitorError("CONNECTION_UNAVAILABLE")
    if lease is None:
        if not row["active"] or row["revoked_at"] is not None:
            raise MonitorError("INVALID_STATE")
    elif not guarded:
        _leased(dict(row), lease)
    return dict(row)


def load_connection(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, Any]:
    try:
        with db.transaction(actor.tenant_id) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            return _locked_connection(conn, actor.tenant_id, connection_id, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def _health(
    conn: Connection,
    tenant: UUID,
    connection_id: UUID,
    row: dict[str, Any],
    state: str,
    now: datetime,
) -> datetime:
    """Move a connection's health state, returning the moment the current episode began."""
    changed_at: datetime = row["health_changed_at"]
    if state != row["health_state"] or changed_at is None:
        changed_at = now
    conn.execute(
        text("""
        UPDATE execbound.monitor_connections
        SET health_state=:state, health_changed_at=:changed
        WHERE tenant_id=:t AND connection_id=:c
    """),
        {"state": state, "changed": changed_at, "t": tenant, "c": connection_id},
    )
    return changed_at


def _health_finding(
    conn: Connection,
    tenant: UUID,
    connection_id: UUID,
    code: str,
    episode: datetime,
    now: datetime,
) -> None:
    _finding(
        conn,
        tenant,
        None,
        None,
        COLLECTION_HEALTH_RULE,
        HEALTH_TITLES[code],
        now,
        finding_id=uuid5(connection_id, f"{COLLECTION_HEALTH_RULE}:{code}:{episode.isoformat()}"),
        connection=connection_id,
    )


def record_capabilities(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    capabilities: dict[str, dict[str, Any]],
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> None:
    """Retain the probe's classification only; a lost capability records one finding."""
    now = _now(clock)
    if type(capabilities) is not dict or len(capabilities) > 16:
        raise MonitorError("INVALID_INPUT")
    for name, value in capabilities.items():
        if (
            re.fullmatch(r"[a-z_]{1,32}", name) is None
            or type(value) is not dict
            or set(value) != {"state", "at"}
            or value["state"] not in {"available", "forbidden", "unsupported", "unknown"}
        ):
            raise MonitorError("INVALID_INPUT")
    tenant = actor.tenant_id
    try:
        with db.transaction(tenant) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            row = _locked_connection(conn, tenant, connection_id, lease=lease, guarded=True)
            lost = [
                name
                for name, value in capabilities.items()
                if value["state"] == "forbidden"
                and (row["capabilities"].get(name) or {}).get("state") == "available"
            ]
            if not conn.execute(
                text("""
                UPDATE execbound.monitor_connections
                SET capabilities=CAST(:value AS jsonb), capabilities_at=:now
                WHERE tenant_id=:t AND connection_id=:c
                  AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))
            """),
                {
                    "value": json.dumps(capabilities, sort_keys=True),
                    "now": now,
                    "t": tenant,
                    "c": connection_id,
                    "lease": lease,
                },
            ).rowcount:
                raise _unleased(conn, tenant, connection_id)
            if lost:
                _health_finding(conn, tenant, connection_id, "CAPABILITY_LOST", now, now)
            if row["health_state"] == "NEVER_COLLECTED":
                _health(conn, tenant, connection_id, row, "COLLECTING", now)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def apply_inventory(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    items: Sequence[Any],
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, int]:
    """Replace one connection's inventory snapshot; items no longer listed are marked gone."""
    now = _now(clock)
    if len(items) > MAX_INVENTORY:
        raise MonitorError("INVENTORY_CAPACITY")
    counts = {"stories": 0, "actions": 0, "credentials": 0, "gone": 0}
    tenant = actor.tenant_id
    try:
        with db.transaction(tenant) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            _locked_connection(conn, tenant, connection_id, lease=lease, guarded=True)
            seen: set[tuple[str, str]] = set()
            for item in items:
                seen.add((item.item_kind, item.external_id))
                counts[
                    {"story": "stories", "action": "actions", "credential": "credentials"}[
                        item.item_kind
                    ]
                ] += 1
                conn.execute(
                    text("""
                    INSERT INTO execbound.monitor_inventory
                    (tenant_id, connection_id, item_kind, external_id, story_external_id, name,
                     name_truncated, item_type, disabled, outbound, first_seen_at, last_seen_at,
                     source_updated_at)
                    VALUES (:t, :c, :kind, :external, :story, :name, :truncated, :type,
                            :disabled, :outbound, :now, :now, :updated)
                    ON CONFLICT (tenant_id, connection_id, item_kind, external_id) DO UPDATE
                    SET name=EXCLUDED.name, name_truncated=EXCLUDED.name_truncated,
                        item_type=EXCLUDED.item_type, disabled=EXCLUDED.disabled,
                        outbound=EXCLUDED.outbound, last_seen_at=EXCLUDED.last_seen_at,
                        source_updated_at=EXCLUDED.source_updated_at, gone_at=NULL
                """),
                    {
                        "t": tenant,
                        "c": connection_id,
                        "kind": item.item_kind,
                        "external": item.external_id,
                        "story": item.story_external_id,
                        "name": item.name,
                        "truncated": item.name_truncated,
                        "type": item.item_type,
                        "disabled": item.disabled,
                        "outbound": item.outbound,
                        "now": now,
                        "updated": item.source_updated_at,
                    },
                )
            counts["gone"] = conn.execute(
                text("""
                UPDATE execbound.monitor_inventory SET gone_at=:now
                WHERE tenant_id=:t AND connection_id=:c AND gone_at IS NULL AND last_seen_at < :now
            """),
                {"now": now, "t": tenant, "c": connection_id},
            ).rowcount
            if not conn.execute(
                text("""
                UPDATE execbound.monitor_connections SET last_sync_at=:now
                WHERE tenant_id=:t AND connection_id=:c
                  AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))
            """),
                {"now": now, "t": tenant, "c": connection_id, "lease": lease},
            ).rowcount:
                raise _unleased(conn, tenant, connection_id)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


MAX_AGENTS = 1000


def apply_agents(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    records: Sequence[Any],
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, int]:
    """Replace one connection's agent snapshot; principals no longer listed are marked gone.

    Identity, class and first sighting are written once and never rewritten: an agent that
    changed its display name is the same agent, and one that changed its object identifier
    is a different one.
    """
    now = _now(clock)
    if len(records) > MAX_AGENTS:
        raise MonitorError("AGENT_CAPACITY")
    counts = {"agents": 0, "agent_identities": 0, "service_principals": 0, "gone": 0}
    tenant = actor.tenant_id
    try:
        with db.transaction(tenant) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            _locked_connection(conn, tenant, connection_id, lease=lease, guarded=True)
            for record in records:
                counts["agents"] += 1
                counts[
                    "agent_identities"
                    if record.identity_class == "agent_identity"
                    else "service_principals"
                ] += 1
                conn.execute(
                    text("""
                    INSERT INTO execbound.monitor_agents
                    (tenant_id, agent_id, connection_id, platform_ref, identity_class,
                     display_name, display_name_truncated, enabled, blueprint_ref, tags,
                     sponsors, sponsor_state, first_seen_at, observed_at, owner_org_ref,
                     ai_publisher)
                    VALUES (:t, :a, :c, :ref, :class, :name, :truncated, :enabled, :blueprint,
                            CAST(:tags AS jsonb), '[]'::jsonb, 'not_read', :now, :now, :owner,
                            :publisher)
                    ON CONFLICT (tenant_id, connection_id, platform_ref) DO UPDATE
                    SET display_name=EXCLUDED.display_name,
                        display_name_truncated=EXCLUDED.display_name_truncated,
                        enabled=EXCLUDED.enabled, blueprint_ref=EXCLUDED.blueprint_ref,
                        tags=EXCLUDED.tags, observed_at=EXCLUDED.observed_at,
                        owner_org_ref=EXCLUDED.owner_org_ref,
                        ai_publisher=EXCLUDED.ai_publisher, gone_at=NULL
                """),
                    {
                        "t": tenant,
                        "a": uuid4(),
                        "c": connection_id,
                        "ref": record.platform_ref,
                        "class": record.identity_class,
                        "name": record.display_name,
                        "truncated": record.display_name_truncated,
                        "enabled": record.enabled,
                        "blueprint": record.blueprint_ref,
                        "tags": json.dumps(list(record.tags)),
                        "owner": record.owner_org_ref,
                        "publisher": record.ai_publisher,
                        "now": now,
                    },
                )
            counts["gone"] = conn.execute(
                text("""
                UPDATE execbound.monitor_agents SET gone_at=:now
                WHERE tenant_id=:t AND connection_id=:c AND gone_at IS NULL AND observed_at < :now
            """),
                {"now": now, "t": tenant, "c": connection_id},
            ).rowcount
            if not conn.execute(
                text("""
                UPDATE execbound.monitor_connections SET last_sync_at=:now
                WHERE tenant_id=:t AND connection_id=:c
                  AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))
            """),
                {"now": now, "t": tenant, "c": connection_id, "lease": lease},
            ).rowcount:
                raise _unleased(conn, tenant, connection_id)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


# Where a delta link may point (#355): the pinned Graph origin and the service principal delta
# path, with a query. The database holds the same prefix as a check.
DELTA_PREFIX = f"{GRAPH_ORIGIN}/v1.0/servicePrincipals/delta?"
MAX_DELTA_LINK = 4096


def held_agents(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    refs: Sequence[str],
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, tuple[str, str | None]]:
    """The class and blueprint the store holds for each of `refs` it holds, read under the run's
    lease and writing nothing (#355).

    A delta pass reads these before it reads anything else from the directory: Graph represents
    an updated instance with only some of its properties, so the class that decides whether
    sponsors or owners are read, and the blueprint whose inherited grants apply, are the store's.
    """
    if len(refs) > MAX_AGENTS:
        raise MonitorError("AGENT_CAPACITY")
    tenant = actor.tenant_id
    try:
        with db.transaction(tenant) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            if _locked_connection(conn, tenant, connection_id, lease=lease)["kind"] != (
                "entra_agent_id"
            ):
                raise MonitorError("INVALID_STATE")
            rows = conn.execute(
                text(
                    "SELECT platform_ref, identity_class, blueprint_ref "
                    "FROM execbound.monitor_agents "
                    "WHERE tenant_id=:t AND connection_id=:c AND platform_ref = ANY(:refs)"
                ),
                {"t": tenant, "c": connection_id, "refs": list(refs)},
            ).all()
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return {row[0]: (row[1], row[2]) for row in rows}


def apply_agent_changes(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    listed: Sequence[Any],
    removed: Sequence[str],
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, int]:
    """A delta pass's changes to one connection's principals (#355).

    A principal the connection has not seen is inserted, first seen now. One marked gone is
    restored. One removed is marked gone, with its grants and the paths they established. Nothing
    else about a principal the store already holds is rewritten: Graph represents an updated
    instance with at least its changed properties, so a missing field is not a cleared one, and
    the full collection refreshes the rest. Its AI publisher key is only ever added here.

    A full collection refuses a directory past `MAX_AGENTS` principals whole, and so does this:
    changes that would leave the connection holding more are refused with `AGENT_CAPACITY` and
    nothing is written, rather than leaving principals the rules could only read in part.
    """
    now = _now(clock)
    if len(listed) > MAX_AGENTS or len(removed) > MAX_AGENTS:
        raise MonitorError("AGENT_CAPACITY")
    counts = {"listed": 0, "new": 0, "restored": 0, "gone": 0}
    tenant = actor.tenant_id
    try:
        with db.transaction(tenant) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            if _locked_connection(conn, tenant, connection_id, lease=lease)["kind"] != (
                "entra_agent_id"
            ):
                raise MonitorError("INVALID_STATE")
            held = {
                row["platform_ref"]: dict(row)
                for row in conn.execute(
                    text(
                        "SELECT platform_ref, gone_at FROM execbound.monitor_agents "
                        "WHERE tenant_id=:t AND connection_id=:c AND platform_ref = ANY(:refs)"
                    ),
                    {
                        "t": tenant,
                        "c": connection_id,
                        "refs": [record.platform_ref for record in listed],
                    },
                ).mappings()
            }
            for record in listed:
                counts["listed"] += 1
                current = held.get(record.platform_ref)
                if current is None:
                    counts["new"] += 1
                    conn.execute(
                        text("""
                        INSERT INTO execbound.monitor_agents
                        (tenant_id, agent_id, connection_id, platform_ref, identity_class,
                         display_name, display_name_truncated, enabled, blueprint_ref, tags,
                         sponsors, sponsor_state, first_seen_at, observed_at, owner_org_ref,
                         ai_publisher)
                        VALUES (:t, :a, :c, :ref, :class, :name, :truncated, :enabled,
                                :blueprint, CAST(:tags AS jsonb), '[]'::jsonb, 'not_read',
                                :now, :now, :owner, :publisher)
                    """),
                        {
                            "t": tenant,
                            "a": uuid4(),
                            "c": connection_id,
                            "ref": record.platform_ref,
                            "class": record.identity_class,
                            "name": record.display_name,
                            "truncated": record.display_name_truncated,
                            "enabled": record.enabled,
                            "blueprint": record.blueprint_ref,
                            "tags": json.dumps(list(record.tags)),
                            "owner": record.owner_org_ref,
                            "publisher": record.ai_publisher,
                            "now": now,
                        },
                    )
                    continue
                counts["restored"] += current["gone_at"] is not None
                conn.execute(
                    text("""
                    UPDATE execbound.monitor_agents
                    SET gone_at = NULL, observed_at = :now,
                        ai_publisher = COALESCE(ai_publisher, :publisher)
                    WHERE tenant_id=:t AND connection_id=:c AND platform_ref=:ref
                """),
                    {
                        "now": now,
                        "publisher": record.ai_publisher,
                        "t": tenant,
                        "c": connection_id,
                        "ref": record.platform_ref,
                    },
                )
            gone = (
                conn.execute(
                    text("""
                    UPDATE execbound.monitor_agents SET gone_at = :now
                    WHERE tenant_id=:t AND connection_id=:c AND platform_ref = ANY(:refs)
                      AND gone_at IS NULL
                    RETURNING agent_id
                """),
                    {"now": now, "t": tenant, "c": connection_id, "refs": list(removed)},
                )
                .scalars()
                .all()
            )
            counts["gone"] = len(gone)
            if gone:
                # As a full collection leaves a principal it no longer lists: its grants and
                # the paths they established stop being live claims, and are kept.
                conn.execute(
                    text(
                        "UPDATE execbound.monitor_agent_grants SET gone_at = :now "
                        "WHERE tenant_id=:t AND agent_id = ANY(:agents) AND gone_at IS NULL"
                    ),
                    {"now": now, "t": tenant, "agents": gone},
                )
                conn.execute(
                    text(
                        "UPDATE execbound.monitor_agent_reach SET gone_at = :now "
                        "WHERE tenant_id=:t AND agent_id = ANY(:agents) AND gone_at IS NULL "
                        "AND path_kind <> 'observation'"
                    ),
                    {"now": now, "t": tenant, "agents": gone},
                )
            if (
                conn.execute(
                    text(
                        "SELECT count(*) FROM execbound.monitor_agents "
                        "WHERE tenant_id=:t AND connection_id=:c AND gone_at IS NULL"
                    ),
                    {"t": tenant, "c": connection_id},
                ).scalar_one()
                > MAX_AGENTS
            ):
                raise MonitorError("AGENT_CAPACITY")
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


def record_delta(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    link: str | None,
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> None:
    """Keep the delta link a round ended with, or drop it (`None`) for the next full collection
    to replace (#355). Advancing it records when; dropping it leaves that moment as it was.

    The link was validated by the collector; this checks its prefix again, and the database
    checks it a third time, and only a connection with a baseline may hold one.
    """
    now = _now(clock)
    if link is not None and (
        type(link) is not str or not link.startswith(DELTA_PREFIX) or len(link) > MAX_DELTA_LINK
    ):
        raise MonitorError("INVALID_INPUT")
    tenant = actor.tenant_id
    try:
        with db.transaction(tenant) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            row = _locked_connection(conn, tenant, connection_id, lease=lease, guarded=True)
            if row["kind"] != "entra_agent_id" or (link is not None and row["baseline_at"] is None):
                raise MonitorError("INVALID_STATE")
            if not conn.execute(
                text("""
                UPDATE execbound.monitor_connections
                SET delta_link = :link,
                    delta_at = CASE WHEN CAST(:link AS text) IS NULL THEN delta_at ELSE :now END
                WHERE tenant_id=:t AND connection_id=:c
                  AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))
            """),
                {"link": link, "now": now, "t": tenant, "c": connection_id, "lease": lease},
            ).rowcount:
                raise _unleased(conn, tenant, connection_id)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


REACH_RULE = "ungoverned-reach.v1"
SPONSOR_RULE = "sponsorless-agent.v1"
# No longer raised (#355): `new-actor.v1` reports a newcomer only when it can act. The value stays
# admitted, so every finding it raised stays readable.
NEW_AGENT_RULE = "new-agent.v1"
NEW_ACTOR_RULE = "new-actor.v1"
FIRST_ACTION_RULE = "first-consequential-action.v1"
AI_CONSENT_RULE = "new-ai-consent.v1"
INVENTORY_RULE = "initial-inventory.v1"
# How long after its first sighting an actor is still new: long enough for the slowest full
# collection to read a consent granted after the principal appeared, short enough that an actor
# gaining reach months after it arrived is a recurrence for `ungoverned-reach.v1`, not news.
NEW_WINDOW = timedelta(days=7)
# What a full collection read of the directory's principals: both collections ("whole"), not
# one because Graph would not answer this time ("partial"), or not one because the registration
# is refused it ("refused"). Only a whole read can be a baseline.
Coverage = Literal["whole", "partial", "refused"]
COVERAGES: frozenset[str] = frozenset(get_args(Coverage))
# What `evaluate_agents` counts, which a collection's result reports.
AGENT_FINDING_COUNTS = (
    "ungoverned",
    "resolved",
    "sponsorless",
    "new_actor",
    "ai_consent",
    "inventory",
    "insufficient",
)
# Each new rule's episode marker: the statement that opens it and the one that closes it.
_MARKERS = {
    NEW_ACTOR_RULE: (
        text(
            "UPDATE execbound.monitor_agents SET new_actor_opened_at = :now "
            "WHERE tenant_id = :t AND agent_id = :a"
        ),
        text(
            "UPDATE execbound.monitor_agents SET new_actor_opened_at = NULL "
            "WHERE tenant_id = :t AND agent_id = :a"
        ),
        "new_actor_opened_at",
    ),
    FIRST_ACTION_RULE: (
        text(
            "UPDATE execbound.monitor_agents SET first_action_opened_at = :now "
            "WHERE tenant_id = :t AND agent_id = :a"
        ),
        text(
            "UPDATE execbound.monitor_agents SET first_action_opened_at = NULL "
            "WHERE tenant_id = :t AND agent_id = :a"
        ),
        "first_action_opened_at",
    ),
    AI_CONSENT_RULE: (
        text(
            "UPDATE execbound.monitor_agents SET ai_consent_opened_at = :now "
            "WHERE tenant_id = :t AND agent_id = :a"
        ),
        text(
            "UPDATE execbound.monitor_agents SET ai_consent_opened_at = NULL "
            "WHERE tenant_id = :t AND agent_id = :a"
        ),
        "ai_consent_opened_at",
    ),
}


def accept_reach(
    db: Database,
    identity: Identity,
    *,
    connection_id: UUID,
    platform_ref: str,
    action: str,
    path_kind: str,
    path_ref: str,
    reason_code: str,
    expires_at: datetime | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> None:
    """Record that an ADMIN accepts one ungoverned path, with a reason and an expiry.

    The reach row stays exactly as it was. An exception says the organization has decided to
    live with that route, not that the route closed, which is why it is recorded beside the
    finding rather than by deleting the evidence that produced it.
    """
    now = _now(clock)
    if (
        re.fullmatch(r"[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}", action or "") is None
        or path_kind not in {"grant", "role", "inherited", "execbound", "observation"}
        or re.fullmatch(r"[A-Z_]{1,48}", reason_code or "") is None
        or (expires_at is not None and expires_at <= now)
    ):
        raise MonitorError("INVALID_INPUT")
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_admin(conn, identity, clock=clock)
            _locked_connection(conn, identity.tenant_id, connection_id)
            agent_id = conn.execute(
                text(
                    "SELECT agent_id FROM execbound.monitor_agents "
                    "WHERE tenant_id=:t AND connection_id=:c AND platform_ref=:ref"
                ),
                {"t": identity.tenant_id, "c": connection_id, "ref": platform_ref},
            ).scalar_one_or_none()
            if agent_id is None:
                raise MonitorError("AGENT_UNAVAILABLE")
            conn.execute(
                text("""
                INSERT INTO execbound.monitor_reach_exceptions
                (tenant_id, agent_id, action, path_kind, path_ref, accepted_by, accepted_at,
                 expires_at, reason_code)
                VALUES (:t, :a, :action, :kind, :path, :by, :now, :expires, :reason)
                ON CONFLICT (tenant_id, agent_id, action, path_kind, path_ref) DO UPDATE
                SET withdrawn_at = NULL
            """),
                {
                    "t": identity.tenant_id,
                    "a": agent_id,
                    "action": action,
                    "kind": path_kind,
                    "path": path_ref,
                    "by": identity.principal_id,
                    "now": now,
                    "expires": expires_at,
                    "reason": reason_code,
                },
            )
            check_admin(conn, identity, clock=clock)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def evaluate_agents(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    *,
    full: bool = True,
    coverage: Coverage = "whole",
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, int]:
    """The agent rules, evaluated after a collection under the tenant's active profile.

    A connection's first complete full collection that read every principal collection
    (`full`, `coverage` "whole", with no baseline yet) is its baseline: it raises none of the
    new-actor rules, because everything is new then, and opens one `initial-inventory.v1`
    summary instead (#355). The `ungoverned-reach.v1` and `sponsorless-agent.v1` episodes it
    opens are recorded without a delivery each, because the summary counts them: connecting a
    directory sends one message. After it, `new-actor.v1` and `new-ai-consent.v1` speak only
    about actors first seen after the baseline, and a newcomer's `new-actor.v1` is the one
    message for the reach episode that opens beside it.

    A collection that could not read one of the principal collections takes no baseline: a
    principal a later read stores for the first time was there all along, and would otherwise
    be called new. What the connection's first run opens without reading both ("partial", as
    when Graph throttles the probe) waits, undelivered, for the summary the next is expected to
    send. It waits no longer: a later collection that cannot send the summary either delivers
    what waited, and what it opens is delivered one by one, as is everything a registration
    refused a collection outright opens ("refused"), so a connection that never reads both is
    never silent. What waited is counted by the summary when it comes, or, if its condition
    ended before it, delivered with it.
    """
    now = _now(clock)
    counts = dict.fromkeys(AGENT_FINDING_COUNTS, 0)
    if coverage not in COVERAGES:
        raise MonitorError("INVALID_INPUT")
    try:
        with db.transaction(actor.tenant_id) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            connection = _locked_connection(conn, actor.tenant_id, connection_id, lease=lease)
            directory = connection.get("directory_ref")
            baseline = connection.get("baseline_at")
            first = full and baseline is None
            # This collection takes the baseline: its summary is the one message it sends.
            takes = first and coverage == "whole"
            # Before the baseline, what is opened waits for the summary on the collection that
            # sends it, and on the connection's first run, whose next collection is expected to.
            # Never longer: a summary that has not come by then may never come.
            quiet = takes or (first and coverage == "partial" and connection["last_run_at"] is None)
            profile = _active_profile(conn, actor.tenant_id)
            # "Consequential" is the tenant's own list, which an ADMIN sets and the
            # sensitive-action rule already uses. Without one, this rule has no subject: it
            # reports insufficient evidence rather than matching against every action.
            consequential = set(profile.profile.sensitive_actions) if profile else set()
            agents = (
                conn.execute(
                    text(
                        "SELECT * FROM execbound.monitor_agents "
                        "WHERE tenant_id=:t AND connection_id=:c AND gone_at IS NULL "
                        "ORDER BY platform_ref LIMIT :limit"
                    ),
                    {"t": actor.tenant_id, "c": connection_id, "limit": MAX_AGENTS + 1},
                )
                .mappings()
                .all()
            )
            if len(agents) > MAX_AGENTS:
                # Every principal or none: never the first thousand and silence on the rest.
                raise MonitorError("AGENT_CAPACITY")
            reaching = _reaching(conn, actor.tenant_id, consequential, now)
            summary = {"reaching": 0, "ungoverned": 0, "unaccountable": 0, "ai": 0}
            for row in agents:
                agent = dict(row)
                open_paths = (
                    _ungoverned_paths(conn, actor.tenant_id, agent["agent_id"], consequential, now)
                    if consequential
                    else 0
                )
                # New: first seen after the baseline, and recently enough that it still is.
                fresh = (
                    baseline is not None
                    and agent["first_seen_at"] > baseline
                    and agent["first_seen_at"] > now - NEW_WINDOW
                )
                kind = str(agent["identity_class"]).replace("_", " ")
                announced = _once(
                    conn,
                    actor.tenant_id,
                    connection_id,
                    agent,
                    NEW_ACTOR_RULE,
                    opens=fresh and open_paths > 0,
                    holds=open_paths > 0,
                    title=f"New {kind} reaches a consequential action through a path "
                    "nothing governs",
                    profile=profile,
                    now=now,
                )
                counts["new_actor"] += announced
                if consequential:
                    counts_delta = _reach_episode(
                        conn,
                        actor.tenant_id,
                        connection_id,
                        agent,
                        open_paths,
                        profile,
                        now,
                        deliver=not quiet and not announced,
                    )
                    counts["ungoverned"] += counts_delta[0]
                    counts["resolved"] += counts_delta[1]
                else:
                    counts["insufficient"] += 1
                opened, unaccountable = _sponsor_episode(
                    conn,
                    actor.tenant_id,
                    connection_id,
                    agent,
                    profile,
                    now,
                    directory=directory,
                    reaching=agent["agent_id"] in reaching,
                    deliver=not quiet,
                )
                counts["sponsorless"] += opened
                if agent["sponsor_state"] in {"unreadable", "not_read"}:
                    counts["insufficient"] += 1
                summary["reaching"] += agent["agent_id"] in reaching
                summary["ungoverned"] += open_paths > 0
                summary["unaccountable"] += unaccountable
                summary["ai"] += agent["ai_publisher"] is not None
                publisher = ai_publishers.PRODUCTION.label(agent["ai_publisher"])
                counts["ai_consent"] += _once(
                    conn,
                    actor.tenant_id,
                    connection_id,
                    agent,
                    AI_CONSENT_RULE,
                    opens=fresh and agent["ai_publisher"] is not None,
                    holds=agent["ai_publisher"] is not None,
                    title=f"New consent to an application from {publisher or 'an AI publisher'}",
                    profile=profile,
                    now=now,
                )
            # An actor that left the directory holds none of the conditions any more.
            conn.execute(
                text("""
                UPDATE execbound.monitor_agents
                SET new_actor_opened_at = NULL, first_action_opened_at = NULL,
                    ai_consent_opened_at = NULL
                WHERE tenant_id=:t AND connection_id=:c AND gone_at IS NOT NULL
                  AND (new_actor_opened_at IS NOT NULL OR first_action_opened_at IS NOT NULL
                       OR ai_consent_opened_at IS NOT NULL)
            """),
                {"t": actor.tenant_id, "c": connection_id},
            )
            if first and (takes or not quiet):
                _deliver_waiting(
                    conn, actor.tenant_id, connection_id, now, counted=takes and bool(consequential)
                )
            if takes:
                counts["inventory"] = _baseline(
                    conn,
                    actor.tenant_id,
                    connection_id,
                    _inventory_title(len(agents), summary, assessed=bool(consequential)),
                    profile,
                    now,
                    lease,
                )
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


def _deliver_waiting(
    conn: Connection, tenant: UUID, connection_id: UUID, now: datetime, *, counted: bool
) -> None:
    """Deliver what an episode opened before the baseline was left waiting for (#355).

    Before a connection's baseline, an `ungoverned-reach.v1` or `sponsorless-agent.v1` finding
    is recorded without a delivery only to wait for the inventory summary. When the summary
    cannot come (`counted` False), everything waiting is delivered now. When it comes
    (`counted`), it counts the episodes still open on a principal still in the directory, and
    the rest, whose condition ended while they waited, are delivered with it, so a finding that
    waited is either counted by the summary or delivered, never neither. The delivery is the
    one `_finding` would have queued, under the same identifier.
    """
    waiting = (
        conn.execute(
            text("""
        SELECT f.finding_id FROM execbound.monitor_findings f
        JOIN execbound.monitor_agents a ON a.tenant_id = f.tenant_id AND a.agent_id = f.agent_id
        WHERE f.tenant_id = :t AND f.connection_id = :c
          AND f.rule_version IN (:reach, :sponsor)
          AND NOT EXISTS (SELECT 1 FROM execbound.monitor_deliveries d
                          WHERE d.tenant_id = f.tenant_id AND d.finding_id = f.finding_id)
          AND NOT (:counted AND a.gone_at IS NULL
                   AND f.created_at IS NOT DISTINCT FROM CASE f.rule_version
                       WHEN :reach THEN a.reach_gap_opened_at ELSE a.sponsor_gap_opened_at END)
        ORDER BY f.created_at, f.finding_id
    """),
            {
                "t": tenant,
                "c": connection_id,
                "reach": REACH_RULE,
                "sponsor": SPONSOR_RULE,
                "counted": counted,
            },
        )
        .scalars()
        .all()
    )
    for finding_id in waiting:
        conn.execute(
            text("""
            INSERT INTO execbound.monitor_deliveries
            (tenant_id, delivery_id, finding_id, created_at, next_attempt_at)
            VALUES (:t, :d, :f, :now, :now)
            ON CONFLICT (tenant_id, delivery_id) DO NOTHING
        """),
            {"t": tenant, "d": uuid5(finding_id, "delivery"), "f": finding_id, "now": now},
        )


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _inventory_title(actors: int, summary: dict[str, int], *, assessed: bool) -> str:
    """Counts only: the summary names no actor, so it carries nothing a page would escape."""
    consents = _plural(summary["ai"], "AI publisher consent")
    if not assessed:
        return (
            f"Initial inventory: {_plural(actors, 'actor')}, {consents}; consequential reach "
            "not assessed without sensitive actions"
        )
    return (
        f"Initial inventory: {_plural(actors, 'actor')}, {summary['reaching']} with "
        f"consequential reach, {summary['ungoverned']} with an ungoverned path, "
        f"{summary['unaccountable']} with nobody accountable, {consents}"
    )


def _baseline(
    conn: Connection,
    tenant: UUID,
    connection_id: UUID,
    title: str,
    profile: ProfileRecord | None,
    now: datetime,
    lease: UUID | None,
) -> int:
    """Set the connection's baseline once and open its one inventory summary."""
    if not conn.execute(
        text("""
        UPDATE execbound.monitor_connections SET baseline_at = :now
        WHERE tenant_id=:t AND connection_id=:c AND baseline_at IS NULL
          AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))
    """),
        {"now": now, "t": tenant, "c": connection_id, "lease": lease},
    ).rowcount:
        raise _unleased(conn, tenant, connection_id)
    _finding(
        conn,
        tenant,
        None,
        None,
        INVENTORY_RULE,
        title,
        now,
        finding_id=uuid5(connection_id, INVENTORY_RULE),
        profile=profile,
        connection=connection_id,
    )
    return 1


def _once(
    conn: Connection,
    tenant: UUID,
    connection_id: UUID,
    agent: dict[str, Any],
    rule: str,
    *,
    opens: bool,
    holds: bool,
    title: str,
    profile: ProfileRecord | None,
    now: datetime,
    observation: UUID | None = None,
) -> int:
    """One finding per actor per rule, ever (#355). The episode opens when `opens`, closes when
    the condition no longer `holds`, and never reopens: the finding's identifier is the actor's
    and the rule's, and a recurrence is what `ungoverned-reach.v1` is for."""
    opening, closing, marker = _MARKERS[rule]
    if agent[marker] is not None:
        if not holds:
            conn.execute(closing, {"t": tenant, "a": agent["agent_id"]})
        return 0
    if (
        not opens
        or conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_findings "
                "WHERE tenant_id = :t AND agent_id = :a AND rule_version = :rule)"
            ),
            {"t": tenant, "a": agent["agent_id"], "rule": rule},
        ).scalar_one()
    ):
        return 0
    conn.execute(opening, {"now": now, "t": tenant, "a": agent["agent_id"]})
    _finding(
        conn,
        tenant,
        None,
        observation,
        rule,
        title,
        now,
        finding_id=uuid5(agent["agent_id"], rule),
        profile=profile,
        connection=connection_id,
        agent=agent["agent_id"],
    )
    return 1


def _ungoverned_paths(
    conn: Connection, tenant: UUID, agent_id: UUID, consequential: set[str], now: datetime
) -> int:
    """Live paths to a consequential action that nothing governs and nobody has accepted."""
    return int(
        conn.execute(
            text("""
            SELECT count(*) FROM execbound.monitor_agent_reach r
            LEFT JOIN execbound.monitor_reach_exceptions e
              ON e.tenant_id = r.tenant_id AND e.agent_id = r.agent_id AND e.action = r.action
                 AND e.path_kind = r.path_kind AND e.path_ref = r.path_ref
                 AND e.withdrawn_at IS NULL
                 AND (e.expires_at IS NULL OR e.expires_at > :now)
            WHERE r.tenant_id = :t AND r.agent_id = :a AND r.gone_at IS NULL
              AND r.valid_until > :now
              AND r.path_kind IN ('grant', 'role', 'inherited')
              AND r.action = ANY(:actions)
              AND e.agent_id IS NULL
        """),
            {"t": tenant, "a": agent_id, "now": now, "actions": sorted(consequential)},
        ).scalar_one()
    )


def _reach_episode(
    conn: Connection,
    tenant: UUID,
    connection_id: UUID,
    agent: dict[str, Any],
    open_paths: int,
    profile: ProfileRecord | None,
    now: datetime,
    *,
    deliver: bool = True,
) -> tuple[int, int]:
    """One finding per agent per episode. A governed route does not close it; losing the
    ungoverned one does, and so does an ADMIN accepting it. `deliver=False` opens the episode
    without a delivery of its own, when another finding is already its message."""
    opened = agent["reach_gap_opened_at"]
    if open_paths and opened is None:
        conn.execute(
            text(
                "UPDATE execbound.monitor_agents SET reach_gap_opened_at=:now "
                "WHERE tenant_id=:t AND agent_id=:a"
            ),
            {"now": now, "t": tenant, "a": agent["agent_id"]},
        )
        _finding(
            conn,
            tenant,
            None,
            None,
            REACH_RULE,
            "Agent reaches a consequential action through a path nothing governs",
            now,
            finding_id=uuid5(agent["agent_id"], f"{REACH_RULE}:{now.isoformat()}"),
            profile=profile,
            connection=connection_id,
            agent=agent["agent_id"],
            deliver=deliver,
        )
        return (1, 0)
    if not open_paths and opened is not None:
        conn.execute(
            text(
                "UPDATE execbound.monitor_agents SET reach_gap_opened_at=NULL "
                "WHERE tenant_id=:t AND agent_id=:a"
            ),
            {"t": tenant, "a": agent["agent_id"]},
        )
        return (0, 1)
    return (0, 0)


def _reaching(conn: Connection, tenant: UUID, consequential: set[str], now: datetime) -> set[UUID]:
    """Agents with a live claim on a consequential action, whatever path establishes it."""
    if not consequential:
        return set()
    return {
        row[0]
        for row in conn.execute(
            text("""
            SELECT DISTINCT agent_id FROM execbound.monitor_agent_reach
            WHERE tenant_id = :t AND gone_at IS NULL AND valid_until > :now
              AND action = ANY(:actions)
        """),
            {"t": tenant, "now": now, "actions": sorted(consequential)},
        )
    }


def _sponsor_episode(
    conn: Connection,
    tenant: UUID,
    connection_id: UUID,
    agent: dict[str, Any],
    profile: ProfileRecord | None,
    now: datetime,
    *,
    directory: str | None = None,
    reaching: bool = True,
    deliver: bool = True,
) -> tuple[int, bool]:
    """An agent identity with no sponsor, or a classic principal with no owner. A read the
    directory refused is insufficient evidence, counted separately and never a finding.
    Returns whether this evaluation opened the episode, and whether its condition holds.

    Two conditions keep this a finding somebody can act on. A principal whose application
    belongs to **another organization** is not the customer's to sponsor: a live directory
    holds two dozen of Microsoft's own service principals, none of them owned, and asking
    anyone to take accountability for the Workload Identity Control Plane is how people are
    taught to ignore findings. And a principal that **reaches nothing consequential** is not
    worth waking anyone for; without that the rule degenerates into "this tenant contains
    service principals", which is always true.

    Neither condition hides the principal. It stays in the inventory and in reach, because a
    consented third-party application holding write access to users is a real risk — it is
    just not a question about sponsorship.
    """
    foreign = (
        directory is not None
        and agent.get("owner_org_ref") is not None
        and str(agent["owner_org_ref"]).lower() != str(directory).lower()
    )
    missing = (
        not foreign
        and reaching
        and (
            agent["sponsor_state"] == "absent"
            if agent["identity_class"] == "agent_identity"
            else agent["owner_count"] == 0
        )
    )
    opened = agent["sponsor_gap_opened_at"]
    if missing and opened is None:
        conn.execute(
            text(
                "UPDATE execbound.monitor_agents SET sponsor_gap_opened_at=:now "
                "WHERE tenant_id=:t AND agent_id=:a"
            ),
            {"now": now, "t": tenant, "a": agent["agent_id"]},
        )
        _finding(
            conn,
            tenant,
            None,
            None,
            SPONSOR_RULE,
            "Agent has nobody accountable for it",
            now,
            finding_id=uuid5(agent["agent_id"], f"{SPONSOR_RULE}:{now.isoformat()}"),
            profile=profile,
            connection=connection_id,
            agent=agent["agent_id"],
            deliver=deliver,
        )
        return 1, True
    if not missing and opened is not None:
        conn.execute(
            text(
                "UPDATE execbound.monitor_agents SET sponsor_gap_opened_at=NULL "
                "WHERE tenant_id=:t AND agent_id=:a"
            ),
            {"t": tenant, "a": agent["agent_id"]},
        )
    return 0, missing


MAX_DERIVED = 500
UNLINK_REASON = "withdrawn with unlink-agent"
# What the binding functions refuse, in the codes this module has always reported.
LINK_CODES = {
    "INVALID_PRINCIPAL": "PRINCIPAL_UNAVAILABLE",
    "INVALID_AGENT": "AGENT_UNAVAILABLE",
    "INVALID_STATE": "LINK_CONFLICT",
    "INVALID_ACTOR": "INVALID_ADMIN",
    "INVALID_TENANT": "INVALID_ADMIN",
}


def link_agent(
    db: Database,
    identity: Identity,
    *,
    connection_id: UUID,
    platform_ref: str,
    principal_id: UUID | None,
    clock: Clock = SYSTEM_CLOCK,
) -> None:
    """Say which ExecBound principal is this external agent, or take the statement back.

    Nothing infers this. A display name that resembles a registered principal is not
    evidence, and a wrong link would attribute a verified execution to the wrong agent.
    The statement is a binding (migration 0037): only an active AGENT principal, one to one,
    recorded with who made it, through the same functions and events the Agents page uses.
    Linking an agent already bound to that principal changes nothing; binding it to another
    principal needs the first binding withdrawn, and withdrawing records its reason.
    """
    if (
        type(platform_ref) is not str
        or re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", platform_ref) is None
    ):
        raise MonitorError("INVALID_INPUT")
    if principal_id is not None and type(principal_id) is not UUID:
        raise MonitorError("INVALID_INPUT")
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_admin(conn, identity, clock=clock)
            _locked_connection(conn, identity.tenant_id, connection_id)
            agent_id = conn.execute(
                text(
                    "SELECT agent_id FROM execbound.monitor_agents "
                    "WHERE tenant_id=:t AND connection_id=:c AND platform_ref=:ref "
                    "AND gone_at IS NULL"
                ),
                {"t": identity.tenant_id, "c": connection_id, "ref": platform_ref},
            ).scalar_one_or_none()
            if agent_id is None:
                raise MonitorError("AGENT_UNAVAILABLE")
            current = bindings.active_binding(conn, identity.tenant_id, agent=agent_id)
            if principal_id is None:
                if current is not None:
                    bindings.unbind(conn, identity, current["binding_id"], UNLINK_REASON)
            elif current is None:
                bindings.bind(conn, identity, agent_id, principal_id)
            elif current["principal_id"] != principal_id:
                raise MonitorError("LINK_CONFLICT")
            check_admin(conn, identity, clock=clock)
    except AdministrationError as exc:
        raise MonitorError(LINK_CODES.get(exc.code, "MONITOR_UNAVAILABLE")) from None
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


# Verified and observed reach, each grouped by agent and action and read a page of
# `MAX_DERIVED` at a time in that order, past the last pair read (`:after_agent`,
# `:after_action`), so every pair is derived however many sort before it.
_VERIFIED_REACH = text("""
    SELECT a.agent_id, a.linked_principal_id,
           e.frozen->'intent'->>'action' AS action, max(e.changed_at) AS at
    FROM execbound.monitor_agents a
    JOIN execbound.executions e
      ON e.tenant_id = a.tenant_id AND e.principal_id = a.linked_principal_id
    WHERE a.tenant_id = :t AND a.linked_principal_id IS NOT NULL
      AND a.gone_at IS NULL AND e.state = 'EXECUTED' AND e.changed_at > :horizon
      AND e.frozen->'intent'->>'action' IS NOT NULL
      AND (CAST(:after_agent AS uuid) IS NULL
           OR (a.agent_id, e.frozen->'intent'->>'action')
              > (CAST(:after_agent AS uuid), CAST(:after_action AS text)))
    GROUP BY a.agent_id, a.linked_principal_id, e.frozen->'intent'->>'action'
    ORDER BY a.agent_id, e.frozen->'intent'->>'action'
    LIMIT :limit
""")
_OBSERVED_REACH = text("""
    SELECT a.agent_id, a.platform_ref, o.action, max(o.occurred_at) AS at
    FROM execbound.monitor_agents a
    JOIN execbound.monitor_observations o
      ON o.tenant_id = a.tenant_id AND o.connection_id = a.connection_id
         AND o.actor_ref = a.platform_ref
    WHERE a.tenant_id = :t AND a.gone_at IS NULL AND o.action IS NOT NULL
      AND o.occurred_at > :horizon
      -- A directory's record of an attempt it refused shows no reach (#355).
      AND (o.kind <> 'entra_audit' OR o.outcome = 'success')
      AND (CAST(:after_agent AS uuid) IS NULL
           OR (a.agent_id, o.action) > (CAST(:after_agent AS uuid), CAST(:after_action AS text)))
    GROUP BY a.agent_id, a.platform_ref, o.action
    ORDER BY a.agent_id, o.action
    LIMIT :limit
""")


def _reach_pages(
    conn: Connection, query: TextClause, tenant: UUID, horizon: datetime
) -> Iterator[RowMapping]:
    """Every row of a reach query, a page at a time: never the first page and silence on the
    rest. The pages end: each starts past the last pair read, and a workspace holds at most
    `MAX_CONNECTIONS` connections of at most `MAX_AGENTS` live principals each, each reaching
    the catalog's actions."""
    after: tuple[UUID, str] | None = None
    while True:
        rows = (
            conn.execute(
                query,
                {
                    "t": tenant,
                    "horizon": horizon,
                    "after_agent": after[0] if after else None,
                    "after_action": after[1] if after else None,
                    "limit": MAX_DERIVED,
                },
            )
            .mappings()
            .all()
        )
        yield from rows
        if len(rows) < MAX_DERIVED:
            return
        after = (rows[-1]["agent_id"], rows[-1]["action"])


def _evidence_until(at: datetime, now: datetime) -> datetime:
    """How long evidence from `at` stays current: `reach.EVIDENCE_VALIDITY` from its moment, and
    never from later than `now`, since no evidence is fresher than the derivation reading it. A
    moment a source stamped ahead of the clock is therefore never counted from, and no moment
    the calendar holds can run its validity off the calendar's end."""
    return min(at, now) + reach.EVIDENCE_VALIDITY


def derive_reach(
    db: Database, actor: Identity | ScheduledActor, *, clock: Clock = SYSTEM_CLOCK
) -> dict[str, int]:
    """Reach the collector cannot establish: what actually ran, and what ExecBound settled.

    Read here rather than written by the execution path. Making settlement write a
    monitoring row would put a second writer inside the execution fence and couple execution
    to monitoring, which is kept apart from execution authority and settlement. The pass is
    idempotent on the row's own identity, so a crash re-derives instead of duplicating. Every
    agent and action is derived, a page at a time, however many sort before it.
    """
    now = _now(clock)
    horizon = now - reach.EVIDENCE_VALIDITY
    counts = {"verified": 0, "observed": 0}
    try:
        with db.transaction(actor.tenant_id) as conn:
            _check_actor(conn, actor, clock)
            modes = reach.governed(conn, actor.tenant_id)
            for row in _reach_pages(conn, _VERIFIED_REACH, actor.tenant_id, horizon):
                counts["verified"] += _derived(
                    conn,
                    actor.tenant_id,
                    row["agent_id"],
                    action=row["action"],
                    path_kind="execbound",
                    path_ref=str(row["linked_principal_id"]),
                    certainty="verified",
                    # An execution that traversed the kernel proves that route, at whatever
                    # mode the tenant's active bundle supports for the action today.
                    mode=modes.get(row["action"], "native"),
                    now=now,
                    until=_evidence_until(row["at"], now),
                )
            for row in _reach_pages(conn, _OBSERVED_REACH, actor.tenant_id, horizon):
                counts["observed"] += _derived(
                    conn,
                    actor.tenant_id,
                    row["agent_id"],
                    action=row["action"],
                    path_kind="observation",
                    path_ref=row["platform_ref"],
                    certainty="observed",
                    # Telemetry is visibility. It never proves anything stood in the way.
                    mode="observed",
                    now=now,
                    until=_evidence_until(row["at"], now),
                )
            _check_actor(conn, actor, clock)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


# How far either side of an execution's dispatch and settlement a directory's own record of it
# may fall: the directory's clock and this one's (#355).
SETTLED_ALLOWANCE = timedelta(minutes=10)
# The directory audit-log observations ExecBound's own executions account for (#355), as decided
# on 16 October 2026: an `entra_audit` observation matches an execution that settled
# `EXECUTED` through the Graph provider for the same action, on the same target object id, with
# the observation within the allowance either side of that execution's dispatch and settlement.
# One is left out only when exactly one execution matches it and that execution matches no
# other observation: two executions for one observation, or two observations for one execution,
# leave out none of them, so an automation acting on the same target in the same window is
# reported, not hidden. Each connection holds one reading of its directory's log, one
# observation for each change, so an execution's observations are counted within the
# connection that holds them: a revoked connection and the one that connects its directory
# again hold copies of the same entries, which are one change, not two acting in the window.
# The database cannot recognise ExecBound's own service principal, whose client id lives only
# in runtime configuration, so the match is the test. The one definition: Home's board reads it
# too, so what the rule leaves out is never drawn as ungoverned. It is a common table
# expression, `settled`, bound by `:t`, `:allowance` and `:settled_since`, which must be no
# later than the earliest observation the reader asks about, or null for every one.
SETTLED_OBSERVATIONS = """
    matched AS (
        SELECT o.observation_id, o.connection_id, e.execution_id
        FROM execbound.executions e
        JOIN execbound.monitor_observations o
          ON o.tenant_id = e.tenant_id AND o.kind = 'entra_audit' AND o.outcome = 'success'
         AND o.action = e.frozen->'intent'->>'action'
         AND o.target_ref = lower(e.frozen->>'resource_provider_id')
         AND o.occurred_at >= e.dispatch_attempted_at - :allowance
         AND o.occurred_at <= e.changed_at + :allowance
        WHERE e.tenant_id = :t AND e.state = 'EXECUTED'
          AND e.frozen->'intent'->>'provider' = 'graph'
          AND e.dispatch_attempted_at IS NOT NULL
          AND (CAST(:settled_since AS timestamptz) IS NULL
               OR e.changed_at > CAST(:settled_since AS timestamptz) - :allowance)
    ),
    settled AS (
        SELECT n.observation_id FROM (
            SELECT m.observation_id,
                   count(*) OVER (PARTITION BY m.execution_id, m.connection_id) AS observations,
                   count(*) OVER (PARTITION BY m.observation_id) AS executions
            FROM matched m
        ) n
        WHERE n.observations = 1 AND n.executions = 1
    )
"""
# Whether observation `o` is news about its actor, on connection `c`: a consequential action
# after the connection's baseline and within the thirty days observations stay current. A
# directory's audit-log observation is news only when it succeeded, when a read after the
# connection's first complete audit read, which is its activity baseline, stored it, however
# early Graph stamped it, and when no execution ExecBound settled accounts for it (#355).
_QUALIFIES = """
    o.action = ANY(:actions) AND o.occurred_at > c.baseline_at AND o.occurred_at > :horizon
    AND (o.kind <> 'entra_audit' OR (
        o.outcome = 'success' AND o.received_at > c.audit_baseline_at
        AND NOT EXISTS (SELECT 1 FROM settled s WHERE s.observation_id = o.observation_id)))
"""
# An observation attributed to the actor's own directory principal was taken with that
# principal's own credential, outside ExecBound: a governed route the actor holds for the same
# action (a link) stands in front of the requests that traverse it, not in front of that
# credential, so it neither excuses the observation nor closes the episode. An actor observed
# acting at or before the baseline is part of it, and so, for an audit-log observation, is one
# the activity baseline's read or a read before it found acting, or any read before there is
# one. An audit-log observation an execution ExecBound settled accounts for is left out there
# too, however old: it is not the actor acting outside ExecBound, so it makes no actor part of
# the baseline, and ExecBound's own executor, whose executions the first read finds in its
# look-back, is still reported the first time its credential acts outside ExecBound. The
# settled-execution match reads every execution here (`:settled_since` null), because the
# baseline holds observations of any age.
_FIRST_ACTIONS_SQL = """
    WITH {settled}
    SELECT a.agent_id, a.connection_id, a.first_action_opened_at, t.observation_id, t.action
    FROM execbound.monitor_agents a
    JOIN execbound.monitor_connections c
      ON c.tenant_id = a.tenant_id AND c.connection_id = a.connection_id
    LEFT JOIN LATERAL (
        SELECT o.observation_id, o.action FROM execbound.monitor_observations o
        WHERE o.tenant_id = a.tenant_id AND o.connection_id = a.connection_id
          AND o.actor_ref = a.platform_ref AND {qualifies}
        ORDER BY o.occurred_at, o.observation_id
        LIMIT 1
    ) t ON true
    WHERE a.tenant_id = :t AND a.gone_at IS NULL
      AND c.kind = 'entra_agent_id' AND c.baseline_at IS NOT NULL
      AND (CAST(:after AS uuid) IS NULL OR a.agent_id > :after)
      AND (a.first_action_opened_at IS NOT NULL OR (
          t.observation_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM execbound.monitor_findings f
              WHERE f.tenant_id = a.tenant_id AND f.agent_id = a.agent_id
                AND f.rule_version = 'first-consequential-action.v1')
          AND NOT EXISTS (
              SELECT 1 FROM execbound.monitor_observations p
              WHERE p.tenant_id = a.tenant_id AND p.connection_id = a.connection_id
                AND p.actor_ref = a.platform_ref AND p.action = ANY(:actions)
                AND CASE WHEN p.kind = 'entra_audit'
                    THEN p.outcome = 'success' AND (c.audit_baseline_at IS NULL
                         OR p.received_at <= c.audit_baseline_at
                         OR p.occurred_at <= c.baseline_at)
                         AND NOT EXISTS (
                             SELECT 1 FROM settled s WHERE s.observation_id = p.observation_id)
                    ELSE p.occurred_at <= c.baseline_at END)))
    ORDER BY a.agent_id
    LIMIT :limit
"""
_FIRST_ACTIONS = text(_FIRST_ACTIONS_SQL.format(settled=SETTLED_OBSERVATIONS, qualifies=_QUALIFIES))
# Without a sensitive-action list there is no subject: the actors observed acting since their
# connection's baseline, as the rule would read them, are counted as insufficient evidence
# instead.
_ACTORS_ACTING_SQL = """
    WITH {settled}
    SELECT count(DISTINCT a.agent_id)
    FROM execbound.monitor_agents a
    JOIN execbound.monitor_connections c
      ON c.tenant_id = a.tenant_id AND c.connection_id = a.connection_id
    JOIN execbound.monitor_observations o
      ON o.tenant_id = a.tenant_id AND o.connection_id = a.connection_id
         AND o.actor_ref = a.platform_ref
    WHERE a.tenant_id = :t AND a.gone_at IS NULL AND c.baseline_at IS NOT NULL
      AND o.action IS NOT NULL AND o.occurred_at > c.baseline_at AND o.occurred_at > :horizon
      AND (o.kind <> 'entra_audit' OR (
          o.outcome = 'success' AND o.received_at > c.audit_baseline_at
          AND NOT EXISTS (SELECT 1 FROM settled s WHERE s.observation_id = o.observation_id)))
"""
_ACTORS_ACTING = text(_ACTORS_ACTING_SQL.format(settled=SETTLED_OBSERVATIONS))


def evaluate_actions(
    db: Database, actor: Identity | ScheduledActor, *, clock: Clock = SYSTEM_CLOCK
) -> dict[str, int]:
    """`first-consequential-action.v1` (#355), evaluated after observed reach is derived.

    It opens when an actor on a connection with a baseline is observed, after the baseline and
    within the thirty days observations stay current, taking an action the tenant calls
    consequential, whether or not the actor is linked and so holds a governed route for that
    action: the observation is of the actor's own directory credential, outside ExecBound. The
    finding carries the earliest such observation. An actor observed taking a consequential
    action at or before the baseline is part of the baseline, so its acting is not news; an
    action an execution ExecBound settled accounts for is not the actor acting outside
    ExecBound, so it neither qualifies nor makes its actor part of the baseline. The
    episode closes only when no such observation is current or the actor is gone, which
    `evaluate_agents` closes it for, and, like the other new-actor rules, never reopens. Every
    actor with an open episode or a new qualifying observation is read, a page at a time,
    however many sort before it.
    """
    now = _now(clock)
    horizon = now - reach.EVIDENCE_VALIDITY
    counts = {"raised": 0, "closed": 0, "insufficient": 0}
    try:
        with db.transaction(actor.tenant_id) as conn:
            _check_actor(conn, actor, clock)
            profile = _active_profile(conn, actor.tenant_id)
            consequential = sorted(profile.profile.sensitive_actions) if profile else []
            if not consequential:
                counts["insufficient"] = int(
                    conn.execute(
                        _ACTORS_ACTING,
                        {
                            "t": actor.tenant_id,
                            "horizon": horizon,
                            "settled_since": horizon,
                            "allowance": SETTLED_ALLOWANCE,
                        },
                    ).scalar_one()
                )
                return counts
            # Every candidate, a page at a time: never the first page and silence on the rest.
            # An open episode stays a candidate until it closes, so a cut would leave an actor
            # that sorts after a page of them unraised, and their own episodes unclosed. The
            # pages end: each starts past the last actor read, and a workspace holds at most
            # `MAX_CONNECTIONS` connections of at most `MAX_AGENTS` live principals each.
            after: UUID | None = None
            while True:
                rows = (
                    conn.execute(
                        _FIRST_ACTIONS,
                        {
                            "t": actor.tenant_id,
                            "actions": consequential,
                            "horizon": horizon,
                            "settled_since": None,
                            "allowance": SETTLED_ALLOWANCE,
                            "after": after,
                            "limit": MAX_DERIVED,
                        },
                    )
                    .mappings()
                    .all()
                )
                for row in rows:
                    agent = dict(row)
                    held = agent["observation_id"] is not None
                    if agent["first_action_opened_at"] is not None:
                        counts["closed"] += not held
                    raised = _once(
                        conn,
                        actor.tenant_id,
                        agent["connection_id"],
                        agent,
                        FIRST_ACTION_RULE,
                        opens=held,
                        holds=held,
                        title=f"First consequential action outside ExecBound: {agent['action']}",
                        profile=profile,
                        now=now,
                        observation=agent["observation_id"],
                    )
                    counts["raised"] += raised
                if len(rows) < MAX_DERIVED:
                    break
                after = rows[-1]["agent_id"]
            _check_actor(conn, actor, clock)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


def _derived(
    conn: Connection,
    tenant: UUID,
    agent_id: UUID,
    *,
    action: str,
    path_kind: str,
    path_ref: str,
    certainty: str,
    mode: str,
    now: datetime,
    until: datetime,
) -> int:
    if re.fullmatch(r"[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}", action or "") is None:
        # An action the kernel does not name cannot become a reach claim.
        return 0
    return conn.execute(
        text("""
        INSERT INTO execbound.monitor_agent_reach
        (tenant_id, agent_id, action, path_kind, path_ref, certainty, enforcement_mode,
         catalog_version, computed_at, valid_until)
        VALUES (:t, :a, :action, :kind, :path, :certainty, :mode, :version, :now, :until)
        ON CONFLICT (tenant_id, agent_id, action, path_kind, path_ref) DO UPDATE
        SET certainty=EXCLUDED.certainty, enforcement_mode=EXCLUDED.enforcement_mode,
            computed_at=EXCLUDED.computed_at, valid_until=EXCLUDED.valid_until, gone_at=NULL
    """),
        {
            "t": tenant,
            "a": agent_id,
            "action": action,
            "kind": path_kind,
            "path": path_ref,
            "certainty": certainty,
            "mode": mode,
            "version": PRODUCTION_GRANTS.version,
            "now": now,
            "until": max(until, now + timedelta(seconds=1)),
        },
    ).rowcount


MAX_AGENT_GRANTS = 200


def apply_agent_detail(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    details: Sequence[Any],
    *,
    only_listed: bool = False,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, int]:
    """Write each agent's grants and accountability; a grant no longer held is marked gone.

    Nothing is deleted. A grant that disappears keeps its row with the moment it stopped
    being held, because "this agent used to reach that action" is evidence, and because the
    runtime role has no authority to delete collected evidence at all.

    A full collection read every agent, so a grant of any agent this run did not see is gone.
    A delta pass (`only_listed`) read only the agents it lists, so only theirs can be (#355).
    """
    now = _now(clock)
    counts = {
        "grants": 0,
        "inherited": 0,
        "gone": 0,
        "sponsored": 0,
        "unreadable": 0,
        "reach": 0,
        "unresolved": 0,
        "reach_gone": 0,
    }
    try:
        with db.transaction(actor.tenant_id) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            _locked_connection(conn, actor.tenant_id, connection_id, lease=lease)
            modes = reach.governed(conn, actor.tenant_id)
            for record in details:
                if len(record.grants) > MAX_AGENT_GRANTS:
                    raise MonitorError("GRANT_CAPACITY")
                agent_id = conn.execute(
                    text(
                        "SELECT agent_id FROM execbound.monitor_agents "
                        "WHERE tenant_id=:t AND connection_id=:c AND platform_ref=:ref"
                    ),
                    {"t": actor.tenant_id, "c": connection_id, "ref": record.platform_ref},
                ).scalar_one_or_none()
                if agent_id is None:
                    continue
                linked = conn.execute(
                    text(
                        "SELECT linked_principal_id FROM execbound.monitor_agents "
                        "WHERE tenant_id=:t AND agent_id=:a"
                    ),
                    {"t": actor.tenant_id, "a": agent_id},
                ).scalar_one()
                counts["sponsored"] += record.sponsor_state == "present"
                counts["unreadable"] += record.sponsor_state == "unreadable"
                conn.execute(
                    text("""
                    UPDATE execbound.monitor_agents
                    SET sponsors = CAST(:sponsors AS jsonb), sponsor_state = :state,
                        sponsor_group_count = :groups, owner_count = :owners,
                        blueprint_object_ref = :blueprint,
                        credential_kinds = CAST(:kinds AS text[]), observed_at = :now
                    WHERE tenant_id=:t AND agent_id=:a
                """),
                    {
                        "sponsors": json.dumps(
                            [
                                {"kind": sponsor.kind, "ref": sponsor.ref}
                                for sponsor in record.sponsors
                            ]
                        ),
                        "state": record.sponsor_state,
                        "groups": sum(1 for sponsor in record.sponsors if sponsor.kind == "group"),
                        "owners": record.owner_count,
                        "blueprint": record.blueprint_object_ref,
                        "kinds": list(record.credential_kinds),
                        "now": now,
                        "t": actor.tenant_id,
                        "a": agent_id,
                    },
                )
                # Inferred reach is a pure function of the grants just written and the
                # shipped catalog, so it commits in the same transaction as them.
                rows, unresolved = reach.from_grants(record.grants)
                counts["unresolved"] += unresolved
                for row in (*rows, *reach.execbound_paths(modes, linked)):
                    counts["reach"] += 1
                    conn.execute(
                        text("""
                        INSERT INTO execbound.monitor_agent_reach
                        (tenant_id, agent_id, action, path_kind, path_ref, certainty,
                         enforcement_mode, catalog_version, computed_at, valid_until)
                        VALUES (:t, :a, :action, :kind, :path, :certainty, :mode, :version,
                                :now, :until)
                        ON CONFLICT (tenant_id, agent_id, action, path_kind, path_ref)
                        DO UPDATE SET certainty=EXCLUDED.certainty,
                                      enforcement_mode=EXCLUDED.enforcement_mode,
                                      catalog_version=EXCLUDED.catalog_version,
                                      computed_at=EXCLUDED.computed_at,
                                      valid_until=EXCLUDED.valid_until, gone_at=NULL
                        WHERE execbound.monitor_agent_reach.certainty <> 'verified'
                           OR EXCLUDED.certainty = 'verified'
                    """),
                        {
                            "t": actor.tenant_id,
                            "a": agent_id,
                            "action": row.action,
                            "kind": row.path_kind,
                            "path": row.path_ref,
                            "certainty": row.certainty,
                            "mode": row.enforcement_mode,
                            "version": row.catalog_version,
                            "now": now,
                            "until": now + row.validity,
                        },
                    )
                for grant in record.grants:
                    counts["grants"] += 1
                    counts["inherited"] += grant.inherited
                    conn.execute(
                        text("""
                        INSERT INTO execbound.monitor_agent_grants
                        (tenant_id, agent_id, grant_kind, resource_ref, value, inherited,
                         path_ref, observed_at)
                        VALUES (:t, :a, :kind, :resource, :value, :inherited, :path, :now)
                        ON CONFLICT (tenant_id, agent_id, grant_kind, resource_ref, value)
                        DO UPDATE SET path_ref=EXCLUDED.path_ref,
                                      observed_at=EXCLUDED.observed_at, gone_at=NULL
                    """),
                        {
                            "t": actor.tenant_id,
                            "a": agent_id,
                            "kind": grant.grant_kind,
                            "resource": grant.resource_ref,
                            "value": grant.value,
                            "inherited": grant.inherited,
                            "path": grant.path_ref,
                            "now": now,
                        },
                    )
            # Every agent of the connection, or for a delta pass only those it listed.
            scope = {
                "now": now,
                "t": actor.tenant_id,
                "c": connection_id,
                "partial": only_listed,
                "refs": [record.platform_ref for record in details],
            }
            counts["gone"] = conn.execute(
                text("""
                UPDATE execbound.monitor_agent_grants g SET gone_at=:now
                FROM execbound.monitor_agents a
                WHERE g.tenant_id=a.tenant_id AND g.agent_id=a.agent_id
                  AND a.tenant_id=:t AND a.connection_id=:c
                  AND g.gone_at IS NULL AND g.observed_at < :now
                  AND (NOT :partial OR a.platform_ref = ANY(:refs))
            """),
                scope,
            ).rowcount
            # A path whose basis this run did not see stops being a live claim. The row is
            # kept: that this agent once reached that action is evidence, and the runtime
            # has no authority to delete collected evidence in any case.
            counts["reach_gone"] = conn.execute(
                text("""
                UPDATE execbound.monitor_agent_reach r SET gone_at=:now
                FROM execbound.monitor_agents a
                WHERE r.tenant_id=a.tenant_id AND r.agent_id=a.agent_id
                  AND a.tenant_id=:t AND a.connection_id=:c
                  AND r.gone_at IS NULL AND r.computed_at < :now
                  AND r.path_kind <> 'observation'
                  AND (NOT :partial OR a.platform_ref = ANY(:refs))
            """),
                scope,
            ).rowcount
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


def ingest_collected_page(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    records: Sequence[Any],
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, int]:
    """Persist one audit page, its pending evaluations and the cursor in one transaction."""
    now = _now(clock)
    counts = {"accepted": 0, "duplicates": 0, "quarantined": 0}
    try:
        with db.transaction(actor.tenant_id) as conn:
            check_runtime(conn)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            row = _locked_connection(
                conn, actor.tenant_id, connection_id, lease=lease, guarded=True
            )
            expected = row["platform_tenant_ref"]
            retained = conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_observations "
                    "WHERE tenant_id=:t AND connection_id=:c"
                ),
                {"t": actor.tenant_id, "c": connection_id},
            ).scalar_one()
            latest: datetime | None = None
            for record in records:
                if record.tenant_ref is not None:
                    if expected is None:
                        # The first collected record pins the platform tenant this
                        # connection speaks for; every later record must agree with it.
                        expected = record.tenant_ref
                    elif record.tenant_ref != expected:
                        counts["quarantined"] += 1
                        continue
                existing = (
                    conn.execute(
                        text("""
                    SELECT observation_id, content_hash FROM execbound.monitor_observations
                    WHERE tenant_id=:t AND connection_id=:c AND event_id=:e
                """),
                        {"t": actor.tenant_id, "c": connection_id, "e": record.event_id},
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is not None:
                    counts["duplicates"] += 1
                    if not hmac.compare_digest(existing["content_hash"], record.content_hash):
                        conn.execute(
                            text("""
                            UPDATE execbound.monitor_observations
                            SET integrity_conflict_at=coalesce(integrity_conflict_at, :now)
                            WHERE tenant_id=:t AND observation_id=:o
                        """),
                            {"now": now, "t": actor.tenant_id, "o": existing["observation_id"]},
                        )
                        _finding(
                            conn,
                            actor.tenant_id,
                            None,
                            existing["observation_id"],
                            "source-event-integrity.v1",
                            "Conflicting collected record identifier",
                            now,
                            connection=connection_id,
                        )
                    continue
                if retained + counts["accepted"] >= MAX_CONNECTION_EVENTS:
                    _refusal_connection(conn, actor.tenant_id, connection_id, "CAPACITY", now)
                    break
                conn.execute(
                    text("""
                    INSERT INTO execbound.monitor_observations
                    (tenant_id, observation_id, connection_id, event_id, story_id, version,
                     occurred_at, received_at, kind, action, outcome, content_hash, rule_version,
                     operation_name, external_ref, evidence, actor_ref, input_tokens,
                     output_tokens, space_id)
                    SELECT :t, :o, :c, :event, :story, 1, :occurred, :now, :kind, :action,
                           :outcome, :hash, :rule, :operation, :external, 'collected', :actor,
                           :input_tokens, :output_tokens, m.space_id
                      FROM execbound.monitor_connections m
                     WHERE m.tenant_id = :t AND m.connection_id = :c
                """),
                    {
                        "t": actor.tenant_id,
                        "o": uuid5(connection_id, record.event_id),
                        "c": connection_id,
                        "event": record.event_id,
                        "story": record.story_ref,
                        "occurred": record.occurred_at,
                        "now": now,
                        "kind": record.kind,
                        "action": record.action,
                        "outcome": record.outcome,
                        "hash": record.content_hash,
                        "rule": CHANGE_RULE if record.kind == "config_change" else RULE_VERSION,
                        "operation": record.operation_name,
                        "external": record.external_ref,
                        "actor": record.actor_ref,
                        "input_tokens": record.input_tokens,
                        "output_tokens": record.output_tokens,
                    },
                )
                counts["accepted"] += 1
                latest = record.occurred_at if latest is None else max(latest, record.occurred_at)
            if counts["quarantined"]:
                _health_finding(conn, actor.tenant_id, connection_id, "FOREIGN_TENANT", now, now)
            # One write to the connection row for every page, an empty one included, so a
            # leased run's page commits only while the run holds the lease. The platform
            # tenant is the one this page pinned or agreed with, and the cursor never passes
            # a record the transaction did not accept.
            if not conn.execute(
                text("""
                UPDATE execbound.monitor_connections
                SET audit_cursor=CASE
                        WHEN CAST(:cursor AS timestamptz) IS NOT NULL
                         AND (audit_cursor IS NULL OR audit_cursor < :cursor)
                        THEN :cursor ELSE audit_cursor END,
                    platform_tenant_ref=:ref
                WHERE tenant_id=:t AND connection_id=:c
                  AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))
            """),
                {
                    "ref": expected,
                    "cursor": latest,
                    "t": actor.tenant_id,
                    "c": connection_id,
                    "lease": lease,
                },
            ).rowcount:
                raise _unleased(conn, actor.tenant_id, connection_id)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


def apply_directory_audit(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    entries: Sequence[Any],
    *,
    cursor: datetime | None,
    caught_up: bool = False,
    gap: bool = False,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, int]:
    """Persist one read of a directory's audit log in one transaction (#355): an `entra_audit`
    observation for each entry it mapped, the cursor, how long the reads have gone without
    catching up, and, when it is the connection's first read that caught up (`caught_up`), the
    activity baseline.

    The baseline is dated by receipt, not by the entries' own moments: what this read and the
    reads before it stored is the actors' habit, and what a later read stores is news, however
    early Graph stamped it, because an entry Graph publishes late is found only by a later read.
    So `audit_baseline_at` is this transaction's moment, and never earlier than the receipt of
    anything the connection already holds; an observation a later read stores is received after
    it, whatever the host's clock says by then.

    An entry is a duplicate when the connection holds an observation of the same change, the
    same assertion under the same correlation id, logged within `AUDIT_SAME_CHANGE` of it, as
    one change the directory logged twice is or an entry read again is. Its identifier names
    everything it asserts, so no two observations under one identifier can differ: an entry
    asserting something else, even under an entry id already read, is another change and an
    observation of its own, and so is the same change logged later. The connection's
    observation bound refuses the rest of the read like any refused read: it moves neither the
    cursor nor the baseline, so nothing past what was kept is skipped, and it records nothing on
    the connection's outcome or last refusal. Nothing removes an observation, so the bound
    refuses every later read too, and its first refusal raises `collection-health.v1` at once,
    once an episode. The cursor never moves back, and every write proves the run's lease.

    `audit_behind_since` dates the episode of reads that have not caught up, from the first such
    read to the next that does, or to a run that does not read (`end_audit_episode`). It raises
    `collection-health.v1` once an episode, when the episode has run `AUDIT_BEHIND_ALERT`, and
    once an episode when a read starts from a cursor Graph's retention has passed (`gap`).
    Neither changes the connection's health state, which stays its inventory's.
    """
    now = _now(clock)
    counts = {"accepted": 0, "duplicates": 0, "capacity": 0}
    tenant = actor.tenant_id
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            row = _locked_connection(conn, tenant, connection_id, lease=lease, guarded=True)
            if row["kind"] != "entra_agent_id":
                raise MonitorError("INVALID_STATE")
            retained = conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_observations "
                    "WHERE tenant_id=:t AND connection_id=:c"
                ),
                {"t": tenant, "c": connection_id},
            ).scalar_one()
            baseline: datetime | None = row["audit_baseline_at"]
            # After the baseline whatever the host's clock says, so a read after it is news.
            received = now if baseline is None or now > baseline else baseline + _AFTER
            for entry in entries:
                # The identifiers are the change's in the entry's window and either neighbour,
                # so one held under any of them is within two windows; the moments decide.
                # Everything an observation asserts is in its identifier, so one found under it
                # asserts the same: a copy, never a conflict to compare.
                if conn.execute(
                    text("""
                    SELECT EXISTS (SELECT 1 FROM execbound.monitor_observations
                    WHERE tenant_id=:t AND connection_id=:c AND event_id = ANY(:events)
                      AND occurred_at BETWEEN :earliest AND :latest)
                """),
                    {
                        "t": tenant,
                        "c": connection_id,
                        "events": list(entry.nearby_event_ids),
                        "earliest": entry.occurred_at - AUDIT_SAME_CHANGE,
                        "latest": entry.occurred_at + AUDIT_SAME_CHANGE,
                    },
                ).scalar_one():
                    counts["duplicates"] += 1
                    continue
                if retained + counts["accepted"] >= MAX_CONNECTION_EVENTS:
                    # Counted in the read's own result, as any refused read is.
                    counts["capacity"] = 1
                    break
                conn.execute(
                    text("""
                    INSERT INTO execbound.monitor_observations
                    (tenant_id, observation_id, connection_id, event_id, version, occurred_at,
                     received_at, kind, action, target_ref, outcome, content_hash, rule_version,
                     operation_name, external_ref, evidence, actor_ref, space_id)
                    SELECT :t, :o, :c, :event, 1, :occurred, :received, 'entra_audit', :action,
                           :target, :outcome, :hash, :rule, :operation, :external, 'collected',
                           :actor, m.space_id
                      FROM execbound.monitor_connections m
                     WHERE m.tenant_id = :t AND m.connection_id = :c
                """),
                    {
                        "t": tenant,
                        "o": uuid5(connection_id, entry.event_id),
                        "c": connection_id,
                        "event": entry.event_id,
                        "occurred": entry.occurred_at,
                        "received": received,
                        "action": entry.action,
                        "target": entry.target_ref,
                        "outcome": entry.outcome,
                        "hash": entry.content_hash,
                        "rule": RULE_VERSION,
                        "operation": entry.operation_name,
                        "external": entry.entry_ref,
                        "actor": entry.actor_ref,
                    },
                )
                counts["accepted"] += 1
            refused = bool(counts["capacity"])
            caught_up = caught_up and not refused
            if caught_up and baseline is None:
                # Everything this read and the reads before it stored, received no later.
                latest = conn.execute(
                    text(
                        "SELECT max(received_at) FROM execbound.monitor_observations "
                        "WHERE tenant_id=:t AND connection_id=:c AND kind='entra_audit'"
                    ),
                    {"t": tenant, "c": connection_id},
                ).scalar_one()
                baseline = now if latest is None else max(now, latest)
            # The episode this read belongs to: the one already open, or one it opens.
            episode: datetime = row["audit_behind_since"] or now
            if not conn.execute(
                text("""
                UPDATE execbound.monitor_connections
                SET audit_cursor=CASE
                        WHEN CAST(:cursor AS timestamptz) IS NOT NULL AND NOT :refused
                         AND (audit_cursor IS NULL OR audit_cursor < :cursor)
                        THEN :cursor ELSE audit_cursor END,
                    audit_baseline_at=coalesce(audit_baseline_at, CAST(:baseline AS timestamptz)),
                    audit_behind_since=CASE
                        WHEN :caught THEN NULL ELSE CAST(:episode AS timestamptz) END
                WHERE tenant_id=:t AND connection_id=:c
                  AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))
            """),
                {
                    "cursor": cursor,
                    "refused": refused,
                    "caught": caught_up,
                    "baseline": baseline,
                    "episode": episode,
                    "t": tenant,
                    "c": connection_id,
                    "lease": lease,
                },
            ).rowcount:
                raise _unleased(conn, tenant, connection_id)
            if gap:
                _health_finding(conn, tenant, connection_id, "RETENTION_GAP", episode, now)
            if refused:
                # At once: unlike a backlog, it does not pass by itself.
                _health_finding(conn, tenant, connection_id, "CAPACITY", episode, now)
            if not caught_up and now - episode >= AUDIT_BEHIND_ALERT:
                _health_finding(conn, tenant, connection_id, "BACKLOG", episode, now)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


def end_audit_episode(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> None:
    """End the episode of audit reads that have not caught up, for a run that does not read the
    log because the last probe found it `forbidden` or `unsupported` (#355).

    Only a read sets or clears `audit_behind_since`, so one that Graph refused before the probe
    recorded the refusal would otherwise date an episode no skipped read can end, and the first
    read once the permission is granted would inherit it and raise the backlog finding at once.
    A run that does not read has no read behind; the next read that does not catch up begins an
    episode of its own. The write proves the run's lease.
    """
    tenant = actor.tenant_id
    try:
        with db.transaction(tenant) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            row = _locked_connection(conn, tenant, connection_id, lease=lease, guarded=True)
            if row["kind"] != "entra_agent_id":
                raise MonitorError("INVALID_STATE")
            if not conn.execute(
                text("""
                UPDATE execbound.monitor_connections SET audit_behind_since = NULL
                WHERE tenant_id=:t AND connection_id=:c
                  AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))
            """),
                {"t": tenant, "c": connection_id, "lease": lease},
            ).rowcount:
                raise _unleased(conn, tenant, connection_id)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def _refusal_connection(
    conn: Connection, tenant: UUID, connection_id: UUID, code: str, now: datetime
) -> None:
    conn.execute(
        text("""
        UPDATE execbound.monitor_connections SET last_error_code=:code
        WHERE tenant_id=:t AND connection_id=:c
    """),
        {"code": code, "t": tenant, "c": connection_id},
    )


def reconcile_coverage(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    *,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> dict[str, int]:
    """Classify every discovered story against the tenant's registered reporting sources."""
    now = _now(clock)
    counts = dict.fromkeys(COVERAGE_CLASSES, 0)
    counts["sources_without_story"] = 0
    try:
        with db.transaction(actor.tenant_id) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            _locked_connection(conn, actor.tenant_id, connection_id, lease=lease)
            stories = (
                conn.execute(
                    text("""
                SELECT external_id, disabled, gap_opened_at, coverage_class
                FROM execbound.monitor_inventory
                WHERE tenant_id=:t AND connection_id=:c AND item_kind='story' AND gone_at IS NULL
                ORDER BY external_id FOR UPDATE
            """),
                    {"t": actor.tenant_id, "c": connection_id},
                )
                .mappings()
                .all()
            )
            outbound = {
                row["story_external_id"]: row
                for row in conn.execute(
                    text("""
                SELECT story_external_id,
                       bool_or(outbound IS TRUE) AS any_outbound,
                       bool_or(outbound IS NULL) AS any_unknown
                FROM execbound.monitor_inventory
                WHERE tenant_id=:t AND connection_id=:c AND item_kind='action'
                  AND gone_at IS NULL AND disabled IS NOT TRUE
                GROUP BY story_external_id
            """),
                    {"t": actor.tenant_id, "c": connection_id},
                ).mappings()
            }
            # One source per story, chosen the same way on every pass: a story keeps an earlier
            # source on record beside the one that replaced it, revoked or left to expire, so a
            # live source wins, then the one heard from last, then the newest.
            sources = {
                row["story_id"]: dict(row)
                for row in conn.execute(
                    text("""
                SELECT DISTINCT ON (story_id)
                       story_id, active, revoked_at, expires_at, created_at, heartbeat_seconds,
                       last_heartbeat_at, last_event_at
                FROM execbound.monitor_sources WHERE tenant_id=:t
                ORDER BY story_id,
                         (active AND revoked_at IS NULL AND expires_at > :now) DESC,
                         greatest(last_heartbeat_at, last_event_at) DESC NULLS LAST,
                         created_at DESC, source_id
            """),
                    {"t": actor.tenant_id, "now": now},
                ).mappings()
            }
            discovered = {row["external_id"] for row in stories}
            counts["sources_without_story"] = len(set(sources) - discovered)
            for story in stories:
                external = story["external_id"]
                source = sources.get(external)
                if source is not None and (
                    not source["active"]
                    or source["revoked_at"] is not None
                    or now >= source["expires_at"]
                ):
                    # A revoked or expired source no longer covers the story; the story is
                    # uninstrumented again, and a closed gap episode reopens as a new one.
                    source = None
                reporting = None
                if source is not None:
                    signals = [
                        value
                        for value in (source["last_heartbeat_at"], source["last_event_at"])
                        if value
                    ]
                    latest = max(signals) if signals else source["created_at"]
                    reporting = now - latest <= timedelta(seconds=2 * source["heartbeat_seconds"])
                actions = outbound.get(external)
                if story["disabled"]:
                    state = "disabled"
                elif reporting:
                    state = "instrumented"
                elif source is not None:
                    state = "registered_stale"
                elif actions is not None and actions["any_outbound"]:
                    state = "discovered_only"
                elif actions is not None and actions["any_unknown"]:
                    # An action type the collector does not recognize is never "no outbound".
                    state = "coverage_unknown"
                else:
                    state = "no_outbound"
                counts[state] += 1
                if state != story["coverage_class"]:
                    conn.execute(
                        text("""
                        UPDATE execbound.monitor_inventory SET coverage_class=:state
                        WHERE tenant_id=:t AND connection_id=:c AND item_kind='story'
                          AND external_id=:e
                    """),
                        {
                            "state": state,
                            "t": actor.tenant_id,
                            "c": connection_id,
                            "e": external,
                        },
                    )
                _gap_episode(conn, actor.tenant_id, connection_id, dict(story), state, now)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return counts


def _gap_episode(
    conn: Connection,
    tenant: UUID,
    connection_id: UUID,
    story: dict[str, Any],
    state: str,
    now: datetime,
) -> None:
    """One finding per uninstrumented-story episode; registering a source closes it."""
    opened = story["gap_opened_at"]
    if state == "discovered_only" and opened is None:
        conn.execute(
            text("""
            UPDATE execbound.monitor_inventory SET gap_opened_at=:now
            WHERE tenant_id=:t AND connection_id=:c AND item_kind='story' AND external_id=:e
        """),
            {"now": now, "t": tenant, "c": connection_id, "e": story["external_id"]},
        )
        _finding(
            conn,
            tenant,
            None,
            None,
            GAP_RULE,
            "Story has outbound actions and no reporting source",
            now,
            finding_id=uuid5(connection_id, f"{GAP_RULE}:{story['external_id']}:{now.isoformat()}"),
            connection=connection_id,
        )
    elif state != "discovered_only" and opened is not None:
        conn.execute(
            text("""
            UPDATE execbound.monitor_inventory SET gap_opened_at=NULL
            WHERE tenant_id=:t AND connection_id=:c AND item_kind='story' AND external_id=:e
        """),
            {"t": tenant, "c": connection_id, "e": story["external_id"]},
        )


def record_run_outcome(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    *,
    outcome: str,
    run_id: UUID,
    error_code: str | None = None,
    retry_after: int | None = None,
    synced: bool = False,
    clock: Clock = SYSTEM_CLOCK,
    lease: UUID | None = None,
) -> None:
    """Move health, count consecutive degradations and open one finding per episode."""
    now = _now(clock)
    if outcome not in RUN_OUTCOMES:
        raise MonitorError("INVALID_INPUT")
    try:
        with db.transaction(actor.tenant_id) as conn:
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
            row = _locked_connection(
                conn, actor.tenant_id, connection_id, lease=lease, guarded=True
            )
            state = {
                "COMPLETE": "COLLECTING",
                "BACKLOG": "COLLECTING",
                "RATE_LIMITED": "RATE_LIMITED",
                "AUTH_LOST": "AUTH_LOST",
                "RETENTION_GAP": "RETENTION_GAP",
                "ERROR": "ERROR",
            }[outcome]
            rate_limited = row["consecutive_rate_limited"] + 1 if outcome == "RATE_LIMITED" else 0
            backlog = row["consecutive_backlog"] + 1 if outcome == "BACKLOG" else 0
            episode = _health(conn, actor.tenant_id, connection_id, row, state, now)
            if not conn.execute(
                text("""
                UPDATE execbound.monitor_connections
                SET last_run_at=:now, last_run_id=:run, last_outcome=:outcome,
                    last_error_code=:code, retry_after_seconds=:retry,
                    consecutive_rate_limited=:rate, consecutive_backlog=:backlog
                WHERE tenant_id=:t AND connection_id=:c
                  AND (CAST(:lease AS uuid) IS NULL OR (collecting_lease = :lease AND active))
            """),
                {
                    "now": now,
                    "run": run_id,
                    "outcome": outcome,
                    "code": error_code,
                    "retry": retry_after,
                    "rate": min(rate_limited, 1000000),
                    "backlog": min(backlog, 1000000),
                    "t": actor.tenant_id,
                    "c": connection_id,
                    "lease": lease,
                },
            ).rowcount:
                raise _unleased(conn, actor.tenant_id, connection_id)
            if outcome in {"AUTH_LOST", "RETENTION_GAP"}:
                _health_finding(conn, actor.tenant_id, connection_id, outcome, episode, now)
            elif outcome == "RATE_LIMITED" and rate_limited >= RATE_LIMIT_EPISODES:
                _health_finding(conn, actor.tenant_id, connection_id, outcome, episode, now)
            elif outcome == "BACKLOG" and backlog >= BACKLOG_EPISODES:
                _health_finding(conn, actor.tenant_id, connection_id, outcome, episode, now)
            _check_actor(conn, actor, clock, collecting=True, lease=lease)
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
