# SPDX-License-Identifier: AGPL-3.0-only
"""The scheduled pass's actor (#503): a workspace's scheduler principal, never an identity.

A scheduled pass holds no workspace credential. It acts in a workspace as that workspace's
scheduler principal (kind `SYSTEM`, migration 0064), which the database keeps from ever
authenticating or holding authority, and it is admitted by `scheduled_check` wherever a run an
administrator starts is admitted by the ADMIN check: the workspace is active and, once the
actor names a principal, that principal is the workspace's own active scheduler principal. An
actor that names none is admitted on the workspace alone, even when the workspace already has
a scheduler principal, which is what `tenant_active` asks. `actor_check` answers for either.
Only the call sites `tests/test_scheduled_actor.py` pins may accept a `ScheduledActor`;
`store.identity_check` refuses one, so one that leaked anywhere else fails closed.

This module imports submodules only, never the `execbound.execution` package's own names: the
package imports `authority`, and `authority` imports this module.
"""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from execbound.audit import append_event
from execbound.db import Database
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.identity import Identity
from execbound.resolution.models import Clock


@dataclass(frozen=True)
class ScheduledActor:
    """A workspace, and its scheduler principal once the pass has something to attribute.

    `principal_id` stays None until the pass is about to write its first event in the
    workspace (`enlist`), so a workspace with nothing due never gains a scheduler principal.
    `store.identity_check` refuses one with INVALID_IDENTITY because it is not an `Identity`,
    whatever its `kind`, rather than failing on a credential it does not have. `kind` is
    SYSTEM only so that a caller comparing `.kind` with a person's or an agent's kind before
    anything else refuses it too, as `samples.py`'s ADMIN check and `policy.store._identity`
    do.
    """

    tenant_id: UUID
    principal_id: UUID | None = None
    kind: Literal["SYSTEM"] = "SYSTEM"


RecoveryActor = Identity | ScheduledActor


def scheduled_check(conn: Connection, actor: ScheduledActor) -> None:
    """Under the caller's fence: the workspace is active and the actor is its own scheduler.

    The workspace must be the one the transaction is fenced to, so an actor for another
    workspace is refused even for a role that bypasses row security.
    """
    if not isinstance(actor, ScheduledActor):
        raise ExecutionError("INVALID_IDENTITY")
    row = conn.execute(
        text(
            "SELECT t.active, (SELECT p.active FROM execbound.principals p "
            "WHERE p.tenant_id = t.tenant_id AND p.principal_id = CAST(:p AS uuid) "
            "AND p.kind = 'SYSTEM') AS scheduler "
            "FROM execbound.tenants t WHERE t.tenant_id = :t "
            "AND t.tenant_id = nullif(current_setting('execbound.tenant_id', true), '')::uuid"
        ),
        {"t": actor.tenant_id, "p": actor.principal_id},
    ).one_or_none()
    if row is None or row[0] is not True:
        raise ExecutionError("INVALID_IDENTITY")
    if actor.principal_id is not None and row[1] is not True:
        raise ExecutionError("INVALID_IDENTITY")


def actor_check(conn: Connection, actor: RecoveryActor, clock: Clock) -> None:
    """The ADMIN check for an administrator's run, the scheduled check for the scheduled pass."""
    if isinstance(actor, ScheduledActor):
        scheduled_check(conn, actor)
    else:
        store.identity_check(conn, actor, clock, "ADMIN")


def tenant_active(db: Database, tenant: UUID) -> bool:
    """Whether a scheduled pass may act in this workspace at all."""
    try:
        with db.transaction(tenant) as conn:
            scheduled_check(conn, ScheduledActor(tenant))
    except ExecutionError:
        return False
    return True


def enlist(db: Database, actor: ScheduledActor, clock: Clock) -> ScheduledActor:
    """The workspace's scheduler principal, made just before the first event it attributes.

    Under the tenant lock (`store.fence`), so two passes racing to make it serialise: one
    creates it and records `principal.created`, the other reads the row the first committed.
    """
    if actor.principal_id is not None:
        return actor
    try:
        with db.transaction(actor.tenant_id) as conn:
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, actor.tenant_id, clock)
            scheduled_check(conn, actor)
            answer = conn.execute(text("SELECT execbound.scheduler_actor()")).scalar_one()
            principal = UUID(str(answer["principal_id"]))
            if answer["created"]:
                append_event(
                    conn,
                    actor.tenant_id,
                    principal,
                    "principal.created",
                    {"principal_id": str(principal), "kind": "SYSTEM"},
                )
    except DBAPIError as exc:
        # `scheduler_actor` refuses a workspace deactivated since the check with
        # INVALID_TENANT. Anything else is EXECUTION_UNAVAILABLE: the database being
        # unavailable, or a tenant that does not exist, whose fence fails the foreign key
        # from `tenant_policy_control` to `tenants` before the check is reached.
        diagnostic = getattr(exc.orig, "diag", None)
        message = getattr(diagnostic, "message_primary", None)
        raise ExecutionError(
            "INVALID_IDENTITY" if message == "INVALID_TENANT" else "EXECUTION_UNAVAILABLE"
        ) from None
    return ScheduledActor(actor.tenant_id, principal)
