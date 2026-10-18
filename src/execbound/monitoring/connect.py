# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring connections changed from the console (#228, #678).

An administrator's session connects Tines by pasting its API key once, which is sealed to the
collector's public key before it reaches the database; replaces that key; asks for a collection;
sets a connection's schedule; and revokes it. Each change:

- opens the tenant's transaction and rechecks the session's ADMIN authority (`_session`);
- takes the connection registry lock the monitoring store takes (`_connection_key`);
- finds the connection under the session's spaces, so one outside them does not exist here;
- calls the one definer function that may write it, which checks the actor, the space and the
  connection again inside the database;
- rechecks the session, and appends one informational audit event as its last write, naming the
  connection and the credential that acted, with the connection's space on the row.

It takes no tenant control row: connecting a monitoring source is an administrative act outside
execution, as provisioning a signal source is. No event carries a key, a ciphertext or a
fingerprint, and no refusal repeats a value. Monitoring confers no execution authority; nothing
here admits, approves, settles or changes a limit, and the gateway never calls Tines.
"""

import re
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from execbound.audit import acted_with, append_event
from execbound.db import Database
from execbound.monitoring.collection import fingerprint
from execbound.monitoring.models import MonitorError
from execbound.monitoring.sealing import API_KEY, CollectorPublicKey, seal_for_collector
from execbound.monitoring.store import (
    CONNECTION_COLUMNS,
    DEPENDENCY_ERRORS,
    SYSTEM_CLOCK,
    _connection_key,
    _principal_rows,
    _session,
)
from execbound.monitoring.store import (
    revoke_connection as _revoke,
)
from execbound.resolution.models import Clock
from execbound.secrets import secret_shaped
from execbound.spaces import SpaceError, visible_spaces, write_space
from execbound.surfaces.sessions import Session

TINES_ORIGIN = re.compile(r"https://[A-Za-z0-9.-]{1,240}\.tines\.(com|io)")
TEAM = re.compile(r"[A-Za-z0-9._:-]{1,64}")
# The definer functions' refusals, each to the code a caller sees.
_REFUSALS = {
    "INVALID_TENANT": "INVALID_ADMIN",
    "INVALID_ACTOR": "INVALID_ADMIN",
    "INVALID_SPACE": "SPACE_REQUIRED",
    "SPACE_ARCHIVED": "SPACE_ARCHIVED",
    "CONNECTION_CAPACITY": "CONNECTION_CAPACITY",
    "CONNECTION_EXISTS": "CONNECTION_EXISTS",
    "INVALID_SCHEDULE": "INVALID_SCHEDULE",
    "INVALID_INPUT": "INVALID_INPUT",
    "INVALID_STATE": "CONNECTION_REVOKED",
}


def _refusal(exc: DBAPIError) -> MonitorError:
    diagnostic = getattr(exc.orig, "diag", None)
    message = str(getattr(diagnostic, "message_primary", None) or "")
    return MonitorError(_REFUSALS.get(message, "MONITOR_UNAVAILABLE"))


def _label(label: object) -> str:
    if (
        type(label) is not str
        or not 1 <= len(label) <= 96
        or not label.strip()
        or not label.isprintable()
        or secret_shaped(label)
    ):
        raise MonitorError("INVALID_LABEL")
    return label


def _key(api_key: object) -> str:
    if type(api_key) is not str or API_KEY.fullmatch(api_key) is None:
        raise MonitorError("INVALID_KEY")
    return api_key


def _registry(conn: Connection, tenant: UUID) -> None:
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": _connection_key(tenant)},
    )


def _visible(conn: Connection, session: Session, connection_id: UUID) -> dict[str, Any]:
    """The connection, locked, if the session's spaces hold it: one outside them, or none at
    all, is `CONNECTION_UNAVAILABLE`, so naming it neither changes it nor says it is there; a
    revoked one is `CONNECTION_REVOKED`."""
    if type(connection_id) is not UUID:
        raise MonitorError("CONNECTION_UNAVAILABLE")
    row = (
        conn.execute(
            text(
                "SELECT connection_id, space_id, kind, credential_mode, active, "
                "collect_requested_at FROM execbound.monitor_connections "
                "WHERE tenant_id = :t AND connection_id = :c FOR UPDATE"
            ),
            {"t": session.identity.tenant_id, "c": connection_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None or not visible_spaces(conn, session).allows(row["space_id"]):
        raise MonitorError("CONNECTION_UNAVAILABLE")
    if not row["active"]:
        raise MonitorError("CONNECTION_REVOKED")
    return dict(row)


def create_sealed_connection(
    db: Database,
    session: Session,
    *,
    label: str,
    base_url: str,
    team_id: str | None,
    api_key: str,
    public: CollectorPublicKey,
    clock: Clock = SYSTEM_CLOCK,
) -> UUID:
    """A sealed Tines connection in the session's space, asked for its first collection.

    The key is sealed to the collector's public key before anything is written, and only the
    ciphertext and the key's SHA-256 reach the database. A label, team id or address that is
    not one, or that reads as a secret, is refused before anything is written.
    """
    name = _label(label)
    if (
        type(base_url) is not str
        or TINES_ORIGIN.fullmatch(base_url) is None
        or secret_shaped(base_url)
    ):
        raise MonitorError("INVALID_BASE_URL")
    if team_id is not None and (
        type(team_id) is not str or TEAM.fullmatch(team_id) is None or secret_shaped(team_id)
    ):
        raise MonitorError("INVALID_TEAM")
    key = _key(api_key)
    identity = session.identity
    connection_id = uuid4()
    ciphertext = seal_for_collector(public, identity.tenant_id, connection_id, "tines", key)
    try:
        with db.transaction(identity.tenant_id) as conn:
            _session(conn, session, clock)
            _registry(conn, identity.tenant_id)
            try:
                space = write_space(conn, identity.tenant_id, visible_spaces(conn, session))
            except SpaceError:
                raise MonitorError("SPACE_REQUIRED") from None
            conn.execute(
                text(
                    "SELECT execbound.admin_create_sealed_connection(:a, :s, :c, :label, :url, "
                    ":team, :fingerprint, :ct, :kid)"
                ),
                {
                    "a": identity.principal_id,
                    "s": space,
                    "c": connection_id,
                    "label": name,
                    "url": base_url,
                    "team": team_id,
                    "fingerprint": fingerprint(key),
                    "ct": ciphertext,
                    "kid": public.key_id,
                },
            )
            _session(conn, session, clock)
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "monitor.connection_created",
                {
                    "connection_id": str(connection_id),
                    "space_id": str(space),
                    "kind": "tines",
                    "credential_mode": "sealed",
                    "label": name,
                    **acted_with(identity.credential_id),
                },
                space=space,
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return connection_id


def replace_sealed_key(
    db: Database,
    session: Session,
    connection_id: UUID,
    *,
    api_key: str,
    public: CollectorPublicKey,
    clock: Clock = SYSTEM_CLOCK,
) -> None:
    """A new pasted key for an active sealed connection, which is then asked for a
    collection. An operator's key file is replaced on the host that holds it, not here."""
    key = _key(api_key)
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            _session(conn, session, clock)
            _registry(conn, identity.tenant_id)
            row = _visible(conn, session, connection_id)
            if row["credential_mode"] != "sealed":
                raise MonitorError("CONNECTION_NOT_SEALED")
            conn.execute(
                text("SELECT execbound.admin_replace_sealed_key(:a, :c, :fingerprint, :ct, :kid)"),
                {
                    "a": identity.principal_id,
                    "c": connection_id,
                    "fingerprint": fingerprint(key),
                    "ct": seal_for_collector(
                        public, identity.tenant_id, connection_id, row["kind"], key
                    ),
                    "kid": public.key_id,
                },
            )
            _session(conn, session, clock)
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "monitor.key_replaced",
                {"connection_id": str(connection_id), **acted_with(identity.credential_id)},
                space=row["space_id"],
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def request_collection(
    db: Database, session: Session, connection_id: UUID, *, clock: Clock = SYSTEM_CLOCK
) -> None:
    """ "Collect now": a request the next scheduled pass answers, never a collection here. A
    request already waiting is the one answered, so a second changes and appends nothing."""
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            _session(conn, session, clock)
            _registry(conn, identity.tenant_id)
            row = _visible(conn, session, connection_id)
            conn.execute(
                text("SELECT execbound.admin_request_collection(:a, :c)"),
                {"a": identity.principal_id, "c": connection_id},
            )
            _session(conn, session, clock)
            if row["collect_requested_at"] is None:
                append_event(
                    conn,
                    identity.tenant_id,
                    identity.principal_id,
                    "monitor.collection_requested",
                    {"connection_id": str(connection_id), **acted_with(identity.credential_id)},
                    space=row["space_id"],
                )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def set_schedule(
    db: Database,
    session: Session,
    connection_id: UUID,
    *,
    collect: int | None,
    activity: int | None,
    clock: Clock = SYSTEM_CLOCK,
) -> None:
    """A connection's intervals, null for the kind's default, in any credential mode. The
    database holds each to its kind's range (`INVALID_SCHEDULE`)."""
    identity = session.identity
    for value in (collect, activity):
        if value is not None and type(value) is not int:
            raise MonitorError("INVALID_SCHEDULE")
    try:
        with db.transaction(identity.tenant_id) as conn:
            _session(conn, session, clock)
            _registry(conn, identity.tenant_id)
            row = _visible(conn, session, connection_id)
            conn.execute(
                text("SELECT execbound.admin_set_collection_schedule(:a, :c, :collect, :activity)"),
                {
                    "a": identity.principal_id,
                    "c": connection_id,
                    "collect": collect,
                    "activity": activity,
                },
            )
            _session(conn, session, clock)
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "monitor.schedule_changed",
                {
                    "connection_id": str(connection_id),
                    "collect_interval_seconds": collect,
                    "activity_interval_seconds": activity,
                    **acted_with(identity.credential_id),
                },
                space=row["space_id"],
            )
    except DBAPIError as exc:
        raise _refusal(exc) from None
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None


def revoke_connection(
    db: Database, session: Session, connection_id: UUID, *, clock: Clock = SYSTEM_CLOCK
) -> None:
    """The store's own revocation, for a connection the session's spaces hold."""
    _revoke(db, session.identity, connection_id, clock=clock, session=session)


def connection(
    db: Database, session: Session, connection_id: UUID, *, clock: Clock = SYSTEM_CLOCK
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """One connection as the Connections view reads it, with who asked for its collection:
    what a change answers with. The lease's id and the sealed key are not among the columns."""
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            _session(conn, session, clock)
            row = (
                conn.execute(
                    text(
                        f"SELECT {CONNECTION_COLUMNS}, e.space_id "  # nosec B608 - a literal column list
                        "FROM execbound.monitor_connections e "
                        "WHERE e.tenant_id = :t AND e.connection_id = :c"
                    ),
                    {"t": identity.tenant_id, "c": connection_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None or not visible_spaces(conn, session).allows(row["space_id"]):
                raise MonitorError("CONNECTION_UNAVAILABLE")
            requesters = _principal_rows(
                conn, identity.tenant_id, [row["collect_requested_by"], row["consented_by"]]
            )
            return dict(row), requesters
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
