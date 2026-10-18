# SPDX-License-Identifier: AGPL-3.0-only
"""When a monitoring connection is next due, and one leased collection run (#228).

A connection is collected on its kind's intervals, or sooner once an administrator asks for a
collection. `due_at` is the one rule: the Connections view's "next due" time and
`collect-due`'s choice of what to collect both read it, so the two cannot disagree.

A run holds its connection's lease (`collector_claim`, migration 0086) for at most
`LEASE_SECONDS`, proves it on every write to the connection row, and returns it in a
`finally`. Two runs never collect one connection at once, whoever started them: the scheduled
`collect-due` or an operator's `collect-tines` or `collect-entra`. A run that outlived its
lease, or whose connection was revoked while it ran, writes nothing more and stops.

`collect-due` runs `collect_workspace` in every active workspace with a `ScheduledActor` that
names no principal: collection appends no audit event, so it never makes the workspace's
scheduler principal. A `key_file` connection is collected only where the collector holds
`<key files>/<connection id>.env`. Without that file it is counted `no_key_file` and nothing is
recorded on it, because the file may live on an operator's own host. A `sealed` connection is
opened with the collector's own private key (`sealing.open_for_collector`); without it, or with
a ciphertext that names another row, the run records why on the connection and sends nothing.
A `platform_app` connection, a directory an administrator consented to, is read with the
deployment's platform app (`graph.PlatformApp`); without it, or for a connection that names
another app's client id, the run records why and sends nothing either.
Collection produces evidence only: nothing here admits, approves, settles or changes a limit.

A run reads its connection's credential again once it holds the lease: a pass reads every due
connection first and may claim one minutes later, and a key an administrator replaced in
between, whose collection request the claim answered, is the key that run must use.

`collector-reseal` moves every sealed connection in every active workspace to a new collector
key (`reseal_due`): each row is opened with the old key and sealed again to the new one, through
`collector_reseal`, with its fingerprint unchanged because its key is, and only while the row
still holds the ciphertext the re-seal opened. A deactivated workspace is not visited; the
report counts it, and its connections stay sealed to the old key.
"""

import time
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from execbound.db import Database
from execbound.execution.scheduled import ScheduledActor
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.monitoring import collection, graph
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import (
    DEFAULT_ACTIVITY_SECONDS,
    DEFAULT_COLLECT_SECONDS,
    MonitorError,
)
from execbound.monitoring.sealing import (
    CollectorKeyRing,
    CollectorPublicKey,
    open_for_collector,
    seal_for_collector,
)
from execbound.monitoring.tines import TinesConfig, TinesConfigError
from execbound.resolution.models import Clock, SystemClock

# Null intervals mean these (`models.py`, which the overdue rule reads too).
DEFAULT_COLLECT = DEFAULT_COLLECT_SECONDS
DEFAULT_ACTIVITY = DEFAULT_ACTIVITY_SECONDS
# How long one run may hold a connection before another may take it; the database refuses
# more than fifteen minutes whatever a caller asks for.
LEASE_SECONDS = 600
# One pass's bounds: inside the five-minute schedule, and fair to every workspace.
BUDGET_SECONDS = 240
PER_TENANT = 4
SYSTEM_CLOCK = SystemClock()

# The database's refusals, each to the code a caller sees.
_REFUSALS = {
    "INVALID_TENANT": "INVALID_ADMIN",
    "INVALID_LEASE": "INVALID_INPUT",
    "INVALID_STATE": "CONNECTION_UNAVAILABLE",
    "LEASE_LOST": "LEASE_LOST",
}


def intervals(row: Mapping[str, Any]) -> tuple[int, int | None]:
    """A connection's collect and activity intervals, each kind's default filled in. Entra
    has no activity interval: every run reads the whole directory."""
    collect = row["collect_interval_seconds"] or DEFAULT_COLLECT[row["kind"]]
    if row["kind"] != "tines":
        return collect, None
    return collect, row["activity_interval_seconds"] or DEFAULT_ACTIVITY


def due_at(row: Mapping[str, Any], now: datetime) -> datetime | None:
    """When an active connection is next due; None for an inactive or revoked one.

    Due once its last run of any outcome is a whole interval old (the activity interval for
    Tines, whose every run reads audit records, and the collect interval for Entra), from its
    registration if it never ran, or from the moment an administrator asked, whichever is
    first. A run the platform rate-limited is not followed before the Retry-After it was given,
    whoever asked. A connection another run holds is not due before that lease ends. The moment
    itself counts as due.
    """
    if not row["active"] or row["revoked_at"] is not None:
        return None
    collect, activity = intervals(row)
    every = activity if activity is not None else collect
    last = row["last_run_at"]
    due: datetime = row["created_at"] if last is None else last + timedelta(seconds=every)
    requested = row["collect_requested_at"]
    if requested is not None:
        due = min(due, requested)
    retry = row["retry_after_seconds"]
    if last is not None and row["last_outcome"] == "RATE_LIMITED" and retry is not None:
        due = max(due, last + timedelta(seconds=retry))
    held = row["collecting_until"]
    if held is not None and held > now:
        due = max(due, held)
    return due


def is_due(row: Mapping[str, Any], now: datetime) -> bool:
    due = due_at(row, now)
    return due is not None and due <= now


def delta_eligible(row: Mapping[str, Any], now: datetime) -> bool:
    """Whether a connection gets a delta pass now rather than nothing (#355).

    An active Entra connection that holds a delta link and a baseline, whose last run completed,
    that is not due for a full collection, that no run holds and for which no administrator's
    request waits: a request is answered by a full collection, never a delta pass.
    """
    held = row["collecting_until"]
    return (
        row["kind"] == "entra_agent_id"
        and bool(row["active"])
        and row["revoked_at"] is None
        and row["delta_link"] is not None
        and row["baseline_at"] is not None
        and row["last_outcome"] == "COMPLETE"
        and row["collect_requested_at"] is None
        and (held is None or held <= now)
        and not is_due(row, now)
    )


def _message(exc: DBAPIError) -> str:
    """The database function's own refusal, `INVALID_STATE` and the like, or nothing."""
    diagnostic = getattr(exc.orig, "diag", None)
    return str(getattr(diagnostic, "message_primary", None) or "")


def claim(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    lease: UUID,
    *,
    seconds: int = LEASE_SECONDS,
    clock: Clock = SYSTEM_CLOCK,
) -> bool:
    """Take the connection's lease; False while another run holds it. A full run's lease that
    expired unfinished is recorded `INTERRUPTED` first, by the database; a delta pass's records
    nothing, because a delta pass records no outcome."""
    if type(connection_id) is not UUID or type(lease) is not UUID:
        raise MonitorError("CONNECTION_UNAVAILABLE")
    try:
        with db.transaction(actor.tenant_id) as conn:
            monitor_store._check_actor(conn, actor, clock)
            answer = conn.execute(
                text("SELECT execbound.collector_claim(:c, :l, :s)"),
                {"c": connection_id, "l": lease, "s": seconds},
            ).scalar_one()
            monitor_store._check_actor(conn, actor, clock)
    except DBAPIError as exc:
        raise MonitorError(_REFUSALS.get(_message(exc), "MONITOR_UNAVAILABLE")) from None
    except monitor_store.DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return answer.get("claimed") is True


def claim_delta(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    lease: UUID,
    *,
    seconds: int = LEASE_SECONDS,
    clock: Clock = SYSTEM_CLOCK,
) -> bool:
    """Take the connection's lease for a delta pass; False unless the connection is
    `delta_eligible` in the same transaction that claims it (#355).

    The claim is `collector_claim_delta`, which marks the lease as a delta pass's, so a pass that
    dies holding it is not recorded as an interrupted run. It never answers a collection request:
    it refuses a connection with one waiting and leaves the request for a full collection, and a
    request made meanwhile waits on the row lock and survives the claim. A full run's lease that
    expired unfinished is recorded `INTERRUPTED` and returned, and the claim takes nothing.
    """
    if type(connection_id) is not UUID or type(lease) is not UUID:
        raise MonitorError("CONNECTION_UNAVAILABLE")
    try:
        with db.transaction(actor.tenant_id) as conn:
            monitor_store._check_actor(conn, actor, clock)
            row = (
                conn.execute(
                    text(_DUE + " AND connection_id = :c FOR UPDATE"),
                    {"t": actor.tenant_id, "c": connection_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None or not delta_eligible(dict(row), monitor_store._now(clock)):
                return False
            answer = conn.execute(
                text("SELECT execbound.collector_claim_delta(:c, :l, :s)"),
                {"c": connection_id, "l": lease, "s": seconds},
            ).scalar_one()
            monitor_store._check_actor(conn, actor, clock)
    except DBAPIError as exc:
        raise MonitorError(_REFUSALS.get(_message(exc), "MONITOR_UNAVAILABLE")) from None
    except monitor_store.DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return answer.get("claimed") is True


def release(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    lease: UUID,
    *,
    clock: Clock = SYSTEM_CLOCK,
) -> None:
    """Return the lease; `LEASE_LOST` when the connection no longer carries it."""
    try:
        with db.transaction(actor.tenant_id) as conn:
            monitor_store._check_actor(conn, actor, clock)
            conn.execute(
                text("SELECT execbound.collector_release(:c, :l)"),
                {"c": connection_id, "l": lease},
            )
    except DBAPIError as exc:
        raise MonitorError(_REFUSALS.get(_message(exc), "MONITOR_UNAVAILABLE")) from None
    except monitor_store.DEPENDENCY_ERRORS:
        raise MonitorError() from None


def claim_and_run[T](
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    run: Callable[[UUID], T],
    *,
    seconds: int = LEASE_SECONDS,
    clock: Clock = SYSTEM_CLOCK,
    delta: bool = False,
) -> T | None:
    """Claim the connection, run with the lease, release it: None, having run nothing, while
    another run holds the connection, or, for a `delta` pass, once it is no longer eligible."""
    lease = uuid4()
    take = claim_delta if delta else claim
    if not take(db, actor, connection_id, lease, seconds=seconds, clock=clock):
        return None
    try:
        return run(lease)
    finally:
        try:
            release(db, actor, connection_id, lease, clock=clock)
        except MonitorError as error:
            if error.code != "LEASE_LOST":
                raise
            # Revoked while the run went on, or held past its lease by a run that took it
            # next: nothing this run wrote after that landed, and it has nothing to return.
            log_event(
                "monitor.lease_lost",
                level="WARNING",
                tenant_id=actor.tenant_id,
                connection_id=connection_id,
            )


# What a run returns when it refused its key file before any request: counted `failed`, never
# `collected`.
_KEY_REFUSED = object()

# What `collect_workspace` reads of each connection to choose what is due: `due_at`'s columns
# and the credential mode. The credential itself is read again under the run's lease.
_DUE = (
    "SELECT tenant_id, connection_id, kind, credential_mode, active, revoked_at, created_at, "
    "last_run_at, last_outcome, retry_after_seconds, collect_interval_seconds, "
    "activity_interval_seconds, collect_requested_at, collecting_until, delta_link, "
    "delta_at, baseline_at "
    "FROM execbound.monitor_connections WHERE tenant_id = :t AND active"
)
# A connection's credential as it stands once a run holds its lease: the fingerprint the key
# must match, and a sealed connection's ciphertext with the collector key it names.
_CREDENTIAL = (
    "SELECT tenant_id, connection_id, kind, credential_mode, key_fingerprint, sealed_ct, "
    "sealed_key_id, client_ref FROM execbound.monitor_connections "
    "WHERE tenant_id = :t AND connection_id = :c AND active AND collecting_lease = :lease"
)
# The credential modes the collector opens itself, with no operator key file.
OPENED = frozenset({"sealed", "platform_app"})


def _credential(
    db: Database,
    actor: Identity | ScheduledActor,
    connection_id: UUID,
    lease: UUID,
    clock: Clock,
) -> dict[str, Any]:
    """The connection's credential under the run's own lease; `LEASE_LOST` or
    `CONNECTION_REVOKED` when the run no longer holds an active connection."""
    try:
        with db.transaction(actor.tenant_id) as conn:
            monitor_store._check_actor(conn, actor, clock)
            row = (
                conn.execute(
                    text(_CREDENTIAL),
                    {"t": actor.tenant_id, "c": connection_id, "lease": lease},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise monitor_store._unleased(conn, actor.tenant_id, connection_id)
    except monitor_store.DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return dict(row)


def _secret(row: Mapping[str, Any], path: Path) -> tuple[str | None, str | None]:
    """The key in an operator's key file, or the code that refuses it: a file that is not a
    key file, or a key that is not the one registered. Neither reaches the platform."""
    try:
        if row["kind"] == "tines":
            secret = TinesConfig.from_file(path).api_key
            registered = collection.fingerprint(secret)
        else:
            secret = graph.EntraConfig.from_file(path).client_secret
            registered = graph.fingerprint(secret)
    except (TinesConfigError, graph.GraphError):
        return None, "KEY_FILE_INVALID"
    if registered != row["key_fingerprint"]:
        return None, "KEY_MISMATCH"
    return secret, None


def _sealed(row: Mapping[str, Any], ring: CollectorKeyRing | None) -> tuple[str | None, str | None]:
    """A sealed connection's key, opened with the collector's own key, or the code that refuses
    it: no collector key that opens it, an envelope naming another row, or a key that is not the
    one registered. None of them reaches the platform."""
    if ring is None:
        return None, "COLLECTOR_KEY_UNAVAILABLE"
    try:
        secret = open_for_collector(ring, row)
    except MonitorError as refused:
        return None, refused.code
    if collection.fingerprint(secret) != row["key_fingerprint"]:
        return None, "KEY_MISMATCH"
    return secret, None


def _platform(
    row: Mapping[str, Any], app: graph.PlatformApp | None
) -> tuple[graph.PlatformApp | None, str | None]:
    """The platform app for a consented connection, or the code that refuses it: no app on this
    collector, or a connection consented to another app. Neither reaches the platform."""
    if app is None:
        return None, "COLLECTOR_KEY_UNAVAILABLE"
    if app.client_id != str(row["client_ref"]).lower():
        return None, "CLIENT_MISMATCH"
    return app, None


def collect_workspace(
    db: Database,
    actor: Identity | ScheduledActor,
    *,
    key_files: Path | None,
    client: httpx.Client,
    collector: CollectorKeyRing | None = None,
    platform_app: graph.PlatformApp | None = None,
    per_tenant: int = PER_TENANT,
    stop: Callable[[], bool] = lambda: False,
    clock: Clock = SYSTEM_CLOCK,
) -> dict[str, int]:
    """Collect one workspace's due connections, oldest due first, each inside its own lease.

    A `key_file` connection whose key file the collector does not hold is counted
    `no_key_file` and left alone. A `sealed` one is opened with `collector`, the collector's own
    key, and a `platform_app` one read with `platform_app`, inside its lease; a refusal is
    recorded on it and counted `failed`. At most
    `per_tenant` runs start, so one workspace cannot spend a whole pass; the rest are
    `deferred` to the next pass, where they are due first. Once `stop` says the
    pass's budget is spent, nothing more starts (`not_reached`). A connection another run
    holds is `busy`. A run's own refusal is that connection's `failed`, and so is a key file
    the run refused before any request; the workspace's refusal of the actor is the
    workspace's.

    Then, within the same cap and budget, each Entra connection that is `delta_eligible` gets a
    delta pass (#355), the one whose link is oldest first: `delta` counts the passes that
    completed and `delta_failed` the rest. A delta pass records nothing on the connection's
    outcome or health, a refused credential included; the next full collection does.
    `audit_failed` counts the runs, full or delta, whose read of the directory's audit log Graph
    refused, `audit_backlog` those whose read stopped at its pages before catching up with the
    log, and `audit_bounded` those whose read met the connection's observation bound and kept
    of each new entry only what the rules would miss without it (`store._AtBound`); none
    changes a run's outcome. Nor does a read of the directory's service principal sign-ins:
    `sign_ins_failed` counts the runs whose read Graph refused, or the reports budget before its
    first page, and `sign_ins_sampled` those whose read stopped at its bound with the rest of its
    window unread.
    """
    counts = dict.fromkeys(
        (
            "collected",
            "no_key_file",
            "deferred",
            "not_reached",
            "busy",
            "failed",
            "delta",
            "delta_failed",
            "audit_failed",
            "audit_backlog",
            "audit_bounded",
            "sign_ins_failed",
            "sign_ins_sampled",
        ),
        0,
    )

    def audited(outcome: object) -> None:
        # An audit-log read that was refused, has not caught up or met the observation bound
        # changes no run's outcome, so it is counted here (#355); so does a sign-in read that
        # was refused or stopped at its bound.
        audit = (outcome.get("audit") or {}) if isinstance(outcome, dict) else {}
        state = audit.get("state")
        if state in {"failed", "backlog"}:
            counts[f"audit_{state}"] += 1
        if audit.get("bounded"):
            counts["audit_bounded"] += 1
        sign_ins = (outcome.get("sign_ins") or {}) if isinstance(outcome, dict) else {}
        if sign_ins.get("state") in {"failed", "sampled"}:
            counts[f"sign_ins_{sign_ins['state']}"] += 1

    try:
        with db.transaction(actor.tenant_id) as conn:
            monitor_store._check_actor(conn, actor, clock)
            rows = [
                dict(row)
                for row in conn.execute(text(_DUE), {"t": actor.tenant_id}).mappings().all()
            ]
    except monitor_store.DEPENDENCY_ERRORS:
        raise MonitorError() from None
    now = monitor_store._now(clock)
    pending = sorted(
        (row for row in rows if is_due(row, now)),
        key=lambda row: (due_at(row, now), str(row["connection_id"])),
    )

    def collect(lease: UUID, connection_id: UUID, path: Path | None, delta: bool = False) -> object:
        # The credential as it stands now this run holds the lease, not as the pass read it:
        # a key replaced in between is the one to use. A key_file row without its file never
        # starts, so `path` is set for one.
        row = _credential(db, actor, connection_id, lease, clock)
        mode = row["credential_mode"]
        app: graph.PlatformApp | None = None
        secret: str | None = None
        if mode == "platform_app":
            app, refused = _platform(row, platform_app)
        elif mode == "sealed" or path is None:
            secret, refused = _sealed(row, collector)
        else:
            secret, refused = _secret(row, path)
        if refused is not None or (secret is None and app is None):
            if not delta:
                # Recorded where the page shows it, so a wrong or unreadable key file is not a
                # connection that silently never runs. A delta pass records no outcome; the
                # next full collection meets the same refusal and records it.
                monitor_store.record_run_outcome(
                    db,
                    actor,
                    row["connection_id"],
                    outcome="ERROR",
                    run_id=uuid4(),
                    error_code=refused,
                    clock=clock,
                    lease=lease,
                )
            return _KEY_REFUSED
        if delta:
            return graph.run_delta(
                db,
                actor,
                connection_id=row["connection_id"],
                client_secret=secret,
                app=app,
                client=client,
                clock=clock,
                lease=lease,
            )
        if row["kind"] == "tines" and secret is not None:
            return collection.run(
                db,
                actor,
                connection_id=row["connection_id"],
                api_key=secret,
                client=client,
                clock=clock,
                lease=lease,
            )
        return graph.run(
            db,
            actor,
            connection_id=row["connection_id"],
            client_secret=secret,
            app=app,
            client=client,
            clock=clock,
            lease=lease,
        )

    def key_path(row: Mapping[str, Any]) -> tuple[bool, Path | None]:
        """Whether the collector can open the connection's credential, and the key file."""
        opened = row["credential_mode"] in OPENED
        path = None if key_files is None else key_files / f"{row['connection_id']}.env"
        return opened or (path is not None and path.is_file()), path

    started = 0
    for row in pending:
        connection_id = row["connection_id"]
        held, path = key_path(row)
        if not held:
            counts["no_key_file"] += 1
            continue
        if started >= per_tenant:
            counts["deferred"] += 1
            continue
        if stop():
            counts["not_reached"] += 1
            continue
        started += 1
        try:
            outcome = claim_and_run(
                db,
                actor,
                connection_id,
                partial(collect, connection_id=connection_id, path=path),
                clock=clock,
            )
        except MonitorError as error:
            if error.code == "INVALID_ADMIN":
                # The workspace refused the actor itself: every other connection would too.
                raise
            counts["failed"] += 1
            continue
        if outcome is None:
            counts["busy"] += 1
        else:
            # A refused key file is recorded on the connection, and nothing was collected.
            counts["failed" if outcome is _KEY_REFUSED else "collected"] += 1
            audited(outcome)

    # Between full collections, a delta pass for each eligible directory, oldest link first. A
    # connection this pass just collected read as due above, so it is not eligible here.
    deltas = sorted(
        (row for row in rows if delta_eligible(row, now)),
        key=lambda row: (row["delta_at"] or row["baseline_at"], str(row["connection_id"])),
    )
    for row in deltas:
        held, path = key_path(row)
        if not held or started >= per_tenant or stop():
            continue
        started += 1
        connection_id = row["connection_id"]
        try:
            outcome = claim_and_run(
                db,
                actor,
                connection_id,
                partial(collect, connection_id=connection_id, path=path, delta=True),
                clock=clock,
                delta=True,
            )
        except MonitorError as error:
            if error.code == "INVALID_ADMIN":
                raise
            counts["delta_failed"] += 1
            continue
        if outcome is None:
            # Taken by another run, or no longer eligible: nothing ran.
            continue
        completed = isinstance(outcome, dict) and outcome.get("outcome") == "COMPLETE"
        counts["delta" if completed else "delta_failed"] += 1
        audited(outcome)
    return counts


def collect_due(
    db: Database,
    *,
    key_files: Path | None,
    client: httpx.Client,
    collector: CollectorKeyRing | None = None,
    platform_app: graph.PlatformApp | None = None,
    per_tenant: int = PER_TENANT,
    budget_seconds: float = BUDGET_SECONDS,
    clock: Clock = SYSTEM_CLOCK,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """`collect-due --all-tenants`: every active workspace, as its scheduled actor (#503).

    The actor names no principal, because collection appends no audit event. One workspace's
    refusal is its own line in the report and never the run's; the budget stops new workspaces
    and new connections alike.
    """
    from execbound.jobs import every_workspace

    began = monotonic()

    def spent() -> bool:
        return monotonic() - began >= budget_seconds

    return every_workspace(
        db,
        lambda tenant: collect_workspace(
            db,
            ScheduledActor(tenant),
            key_files=key_files,
            client=client,
            collector=collector,
            platform_app=platform_app,
            per_tenant=per_tenant,
            stop=spent,
            clock=clock,
        ),
        command="collect-due",
        budget_seconds=budget_seconds,
        monotonic=monotonic,
    )


# What a re-seal reads of each sealed connection, revoked ones included: a revoked connection's
# key moves too, so the old collector key can be retired. Its ciphertext is what the re-seal
# names back to `collector_reseal`, which writes only while the row still holds it.
_SEALED = (
    "SELECT tenant_id, connection_id, kind, credential_mode, sealed_ct, sealed_key_id "
    "FROM execbound.monitor_connections WHERE tenant_id = :t AND credential_mode = 'sealed' "
    "ORDER BY connection_id"
)


def reseal_workspace(
    db: Database,
    actor: Identity | ScheduledActor,
    old: CollectorKeyRing,
    new: CollectorPublicKey,
    *,
    clock: Clock = SYSTEM_CLOCK,
) -> dict[str, int]:
    """Re-seal one workspace's sealed connections from `old` to `new`.

    A row already under `new` is `already`; one under a key `old` does not hold is left alone
    and counted `other_key`; one `old` cannot open, or whose re-seal the database refuses, is
    `failed`, among them a row whose key an administrator replaced after it was read, which
    the next pass moves. The key is the same, so its fingerprint stays as it is.
    """
    counts = dict.fromkeys(("resealed", "already", "other_key", "failed"), 0)
    try:
        with db.transaction(actor.tenant_id) as conn:
            monitor_store._check_actor(conn, actor, clock)
            rows = [
                dict(row)
                for row in conn.execute(text(_SEALED), {"t": actor.tenant_id}).mappings().all()
            ]
    except monitor_store.DEPENDENCY_ERRORS:
        raise MonitorError() from None
    for row in rows:
        if row["sealed_key_id"] == new.key_id:
            counts["already"] += 1
            continue
        if old.get(row["sealed_key_id"]) is None:
            counts["other_key"] += 1
            continue
        try:
            key = open_for_collector(old, row)
            ciphertext = seal_for_collector(
                new, row["tenant_id"], row["connection_id"], row["kind"], key
            )
            with db.transaction(actor.tenant_id) as conn:
                monitor_store._check_actor(conn, actor, clock)
                conn.execute(
                    text("SELECT execbound.collector_reseal(:c, :old, :oldct, :ct, :kid)"),
                    {
                        "c": row["connection_id"],
                        "old": row["sealed_key_id"],
                        "oldct": row["sealed_ct"],
                        "ct": ciphertext,
                        "kid": new.key_id,
                    },
                )
        except (MonitorError, DBAPIError):
            counts["failed"] += 1
            continue
        counts["resealed"] += 1
    return counts


def reseal_due(
    db: Database,
    old: CollectorKeyRing,
    new: CollectorPublicKey,
    *,
    clock: Clock = SYSTEM_CLOCK,
) -> dict[str, Any]:
    """`collector-reseal --all-tenants`: every active workspace as its scheduled actor, with the
    counts summed over them beside the walk's own. A deactivated workspace is counted
    `inactive` and not visited, so its sealed connections stay under the old key."""
    from execbound.jobs import every_workspace

    report = every_workspace(
        db,
        lambda tenant: reseal_workspace(db, ScheduledActor(tenant), old, new, clock=clock),
        command="collector-reseal",
        budget_seconds=3600,
    )
    totals = dict.fromkeys(("resealed", "already", "other_key", "failed"), 0)
    for outcome in report["tenants"].values():
        for name in totals:
            value = outcome.get(name, 0)
            totals[name] += value if type(value) is int else 0
    totals["failed"] += report["failed"]
    return {
        **totals,
        "visited": report["visited"],
        "inactive": report["inactive"],
        "not_reached": report["not_reached"],
    }
