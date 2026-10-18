# SPDX-License-Identifier: AGPL-3.0-only
"""Current-admin tenant export; database reads and exclusive local publication only."""

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.audit import GENESIS
from execbound.db import Database, check_runtime
from execbound.identity import Identity
from execbound.policy.models import BundleContent
from execbound.policy.store import _identity
from execbound.replay.models import (
    MAX_BUNDLES,
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_EVENTS,
    MAX_EXPORT_BYTES,
    AuditEvent,
    ReplayExport,
    TrustedHead,
)
from execbound.replay.verify import parse_export, referenced_bundle_ids, verify_export
from execbound.resolution.models import Clock, SystemClock


class ExportError(ValueError):
    """A safe export failure without database, policy or filesystem diagnostics."""

    def __init__(self) -> None:
        super().__init__("History export unavailable")


@contextmanager
def _read_only(
    db: Database, identity: Identity, isolation: Literal["REPEATABLE READ", "READ COMMITTED"]
) -> Iterator[Connection]:
    # Start read-only before the first SELECT pins a snapshot. No execution fence,
    # audit append or mutable projection is needed to establish this capability.
    with db.engine.connect().execution_options(isolation_level=isolation) as conn:
        with conn.begin():
            conn.execute(text("SET TRANSACTION READ ONLY"))
            conn.execute(text("SELECT set_config('statement_timeout','10000',true)"))
            conn.execute(text("SELECT set_config('lock_timeout','5000',true)"))
            conn.execute(
                text("SELECT set_config('execbound.tenant_id',:tenant,true)"),
                {"tenant": str(identity.tenant_id)},
            )
            check_runtime(conn)
            yield conn


def export_history(
    db: Database,
    identity: Identity,
    clock: Clock | None = None,
    *,
    permission: Literal["workspace.manage", "policy.manage"] = "workspace.manage",
) -> ReplayExport:
    """Read one complete bounded tenant prefix with its referenced immutable policy.

    The returned head authenticates internal consistency only. Retaining that head
    independently is a separate operator responsibility. Current projections never
    fill missing historical authority, facts, approvals or semantic timestamps.

    The export is a workspace administrator's (`workspace.manage`). Only the bundle preview
    passes `policy.manage`, so a Policy manager's preview can read the whole chain its
    integrity check needs; `policy/preview.py` then keeps only the decisions recorded in
    Spaces where that person holds `policy.manage`, and nothing else leaves it.
    """
    clock = clock or SystemClock()
    # The default is the store's own administrator check, unchanged: an ADMIN kind holding
    # `workspace.manage`. Only `policy.manage` is passed through as a named permission.
    granting = None if permission == "workspace.manage" else permission
    try:
        with _read_only(db, identity, "REPEATABLE READ") as conn:
            _identity(conn, identity, clock, admin=True, permission=granting)
            raw_head = (
                conn.execute(
                    text(
                        "SELECT sequence,event_hash FROM execbound.audit_heads WHERE tenant_id=:t"
                    ),
                    {"t": identity.tenant_id},
                )
                .mappings()
                .one_or_none()
            )
            head = TrustedHead(
                tenant_id=identity.tenant_id,
                sequence=raw_head["sequence"] if raw_head else 0,
                event_hash=raw_head["event_hash"] if raw_head else GENESIS,
            )
            if head.sequence > MAX_EVENTS:
                raise ValueError("Bound exceeded")
            events: list[AuditEvent] = []
            size = 0
            # Stream instead of buffering the entire tenant payload. The SQL size
            # gate rejects an oversized owner-written payload before transferring
            # it; normal JSONB spacing can expand valid canonical audit JSON.
            rows = conn.execute(
                text("""SELECT tenant_id,sequence,event_id,actor_id,kind,occurred_at,
                    CASE WHEN octet_length(payload::text)<=:payload_limit
                         THEN payload END AS payload,
                    octet_length(payload::text) AS payload_bytes,previous_hash,event_hash
                    FROM execbound.audit_events WHERE tenant_id=:t
                    ORDER BY sequence LIMIT :limit""").execution_options(yield_per=64),
                {
                    "t": identity.tenant_id,
                    "limit": MAX_EVENTS + 1,
                    "payload_limit": MAX_EVENT_PAYLOAD_BYTES * 2,
                },
            ).mappings()
            for row in rows:
                if len(events) >= MAX_EVENTS or row["payload_bytes"] > MAX_EVENT_PAYLOAD_BYTES * 2:
                    raise ValueError("Bound exceeded")
                event = AuditEvent.model_validate(
                    {k: v for k, v in row.items() if k != "payload_bytes"}
                )
                size += len(event.model_dump_json().encode("utf-8"))
                if size > MAX_EXPORT_BYTES:
                    raise ValueError("Bound exceeded")
                events.append(event)
            references = referenced_bundle_ids(tuple(events))
            if len(references) > MAX_BUNDLES:
                raise ValueError("Bound exceeded")
            bundles = []
            for bundle_id in sorted(references, key=str):
                metadata = (
                    conn.execute(
                        text(
                            "SELECT content_hash,octet_length(content::text) AS size "
                            "FROM execbound.policy_bundle_contents "
                            "WHERE tenant_id=:t AND bundle_id=:b"
                        ),
                        {"t": identity.tenant_id, "b": bundle_id},
                    )
                    .mappings()
                    .one()
                )
                if metadata["size"] + size > MAX_EXPORT_BYTES:
                    raise ValueError("Bound exceeded")
                content = conn.execute(
                    text(
                        "SELECT content::text FROM execbound.policy_bundle_contents "
                        "WHERE tenant_id=:t AND bundle_id=:b"
                    ),
                    {"t": identity.tenant_id, "b": bundle_id},
                ).scalar_one()
                bundle = BundleContent.model_validate_json(content)
                if (
                    bundle.tenant_id != identity.tenant_id
                    or bundle.bundle_id != bundle_id
                    or bundle.content_hash != metadata["content_hash"]
                ):
                    raise ValueError("Invalid bundle")
                size += len(bundle.model_dump_json().encode("utf-8"))
                bundles.append(bundle)
            history = ReplayExport(
                tenant_id=identity.tenant_id,
                head=head,
                events=tuple(events),
                bundles=tuple(bundles),
            )
            encoded = history.model_dump_json().encode("utf-8")
            if len(encoded) > MAX_EXPORT_BYTES:
                raise ValueError("Bound exceeded")
            history = parse_export(encoded)
            verify_export(history, head)
            _identity(conn, identity, clock, admin=True, permission=granting)
            return history
    # Raise the generic error outside the handler; a nested one may name private input.
    except Exception:  # nosec B110 - a nested exception may hold private data
        pass
    # Raise outside the handler: nested exceptions may contain private SQL/JSON.
    raise ExportError()


def _stage(data: bytes, destination: Path) -> Path:
    descriptor, filename = tempfile.mkstemp(prefix=".execbound-export-", dir=destination.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.chmod(temporary, 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def publish_export(
    db: Database,
    identity: Identity,
    history: ReplayExport,
    *,
    output: Path,
    checkpoint: Path,
    clock: Clock | None = None,
) -> None:
    """Publish new files after fresh current ADMIN authentication.

    Checkpoint is linked first, export last; existence of a complete export is the
    publication point. Ordinary failure removes only artifacts created by this call.
    A process/machine crash between the two links can leave an orphan checkpoint;
    callers must verify the pair, and a retry never overwrites that checkpoint.
    The accompanying checkpoint is not an independently trusted historical anchor.
    No cross-file crash atomicity or privileged-storage tamper protection is claimed.
    """
    clock = clock or SystemClock()
    staged: list[Path] = []
    published: list[tuple[Path, os.stat_result]] = []
    succeeded = False
    try:
        output, checkpoint = Path(output).absolute(), Path(checkpoint).absolute()
        if (
            output.resolve() == checkpoint.resolve()
            or os.path.lexists(output)
            or os.path.lexists(checkpoint)
            or not output.parent.is_dir()
            or not checkpoint.parent.is_dir()
        ):
            raise ValueError("Invalid output")
        raw = history.model_dump_json().encode("utf-8")
        if len(raw) + 1 > MAX_EXPORT_BYTES:
            raise ValueError("Bound exceeded")
        validated = parse_export(raw)
        verify_export(validated, validated.head)
        if validated.tenant_id != identity.tenant_id:
            raise ValueError("Invalid tenant")
        staged.append(_stage(raw + b"\n", output))
        staged.append(_stage((validated.head.model_dump_json() + "\n").encode("utf-8"), checkpoint))
        # A repeatable-read recheck would miss revocation committed after export.
        # This separate transaction sees current role, credential and tenant state.
        for source, destination in ((staged[1], checkpoint), (staged[0], output)):
            # Checkpoint publication can block on filesystem I/O. Recheck again
            # before exposing the complete export so that delay cannot extend
            # a role or credential that was valid before the checkpoint link.
            with _read_only(db, identity, "READ COMMITTED") as conn:
                _identity(conn, identity, clock, admin=True)
            owned = source.stat()
            os.link(source, destination)
            published.append((destination, owned))
        succeeded = True
    # Raise the generic error after cleanup; nested errors may name private paths.
    except Exception:  # nosec B110 - a nested exception may name a private path
        pass
    finally:
        if not succeeded:
            for path, owned in reversed(published):
                try:
                    current = path.lstat()
                    if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                        path.unlink()
                except OSError:
                    pass
        for path in staged:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
    if not succeeded:
        raise ExportError()
