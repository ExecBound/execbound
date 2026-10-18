# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only preview of a candidate bundle against the tenant's recent frozen history.

Composes the ADMIN export, offline verification and the replay simulator in memory.
It never activates the candidate and never touches live budgets, approvals or
execution state; hypothetical effects carry the simulator's own uncertainty markers.
"""

from collections import Counter
from datetime import timedelta
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound.access_control import has_permission
from execbound.contracts import PRODUCTION_CATALOG, Catalog
from execbound.db import Database
from execbound.identity import Identity
from execbound.policy.store import PolicyStoreError, _policy_identity, read_bundle
from execbound.replay.export import ExportError, export_history
from execbound.replay.simulate import simulate
from execbound.replay.verify import ReplayValidationError, verify_export
from execbound.requests import StrictModel
from execbound.resolution.models import Clock, SystemClock

MAX_WINDOW = timedelta(days=30)
Scope = Literal["workspace", "spaces"]


class ChangedDecision(StrictModel):
    execution_id: UUID
    action: str
    semantic_time: AwareDatetime
    baseline_effect: str
    baseline_reasons: tuple[str, ...]
    candidate_effect: str
    candidate_reasons: tuple[str, ...]
    # The obligations the candidate raised, so a page can name the rule behind a review
    # rather than print the engine's positional identifier. Empty when the candidate owes none.
    candidate_obligations: tuple[str, ...] = ()
    differences: tuple[str, ...]
    required_approvers: int


class BundlePreview(StrictModel):
    bundle_id: UUID
    content_hash: str
    state: str
    window_seconds: int
    considered: int
    changed: tuple[ChangedDecision, ...]
    baseline_effects: dict[str, int]
    candidate_effects: dict[str, int]
    complete: bool
    issues: tuple[str, ...]
    # Whose decisions were counted: the whole workspace's, for a workspace-wide
    # administrator, or only those recorded in the Spaces where the reader holds
    # `policy.manage`, for everyone else (#678).
    scope: Scope = "workspace"


def preview_scope(db: Database, identity: Identity, clock: Clock | None = None) -> Scope:
    """Whether this person previews the whole workspace's decisions or only their Spaces'.

    `"workspace"` exactly when they hold `workspace.manage` with no Space and `any_scope` left
    false, which is the check the console's preview made before Policy managers could run it,
    moved here rather than widened. `any_scope=True` would be wrong: an `ADMIN`-kind principal
    seated in some Spaces holds `workspace.manage` only through `access_has_permission`'s
    `p_any` branch (`0047_access_control`), so a narrowed administrator would read every
    Space's decisions labelled as the workspace's. That is the class of fault
    `0071_space_credential_scope` (#662) fixed for keys. Everyone else is `"spaces"`.
    """
    clock = clock or SystemClock()
    try:
        with db.transaction(identity.tenant_id, snapshot=True) as conn:
            _policy_identity(conn, identity, clock)
            workspace = has_permission(
                conn, identity.tenant_id, identity.principal_id, "workspace.manage"
            )
    except PolicyStoreError:
        raise
    except (SQLAlchemyError, ValueError):
        raise PolicyStoreError() from None
    return "workspace" if workspace else "spaces"


# The executions among the window's decisions whose Space is one where the reader holds
# `policy.manage`. Everything outside this set is dropped before anything is counted.
_PERMITTED = (
    "SELECT execution_id FROM execbound.executions "
    "WHERE tenant_id = :t AND execution_id = ANY(CAST(:ids AS uuid[])) "
    "AND execbound.access_has_permission(:p, 'policy.manage', space_id, false)"
)


def _permitted(db: Database, identity: Identity, ids: set[UUID]) -> set[UUID]:
    if not ids:
        return set()
    try:
        with db.transaction(identity.tenant_id, snapshot=True) as conn:
            return set(
                conn.execute(
                    text(_PERMITTED),
                    {
                        "t": identity.tenant_id,
                        "ids": sorted(str(item) for item in ids),
                        "p": identity.principal_id,
                    },
                ).scalars()
            )
    except SQLAlchemyError:
        raise PolicyStoreError("PREVIEW_UNAVAILABLE") from None


def preview_bundle(
    db: Database,
    identity: Identity,
    bundle_id: UUID,
    *,
    window: timedelta,
    clock: Clock | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> BundlePreview:
    """Replay the candidate over decisions recorded within ``window`` before now."""
    clock = clock or SystemClock()
    if not timedelta(0) < window <= MAX_WINDOW:
        raise PolicyStoreError("INVALID_WINDOW")
    record = read_bundle(db, identity, bundle_id, clock)
    # Decided before the export, so the export is asked with the right permission.
    scope = preview_scope(db, identity, clock)
    try:
        # The chain is read whole even for a reader filtered to their Spaces, because its
        # integrity check needs the complete prefix; only the permitted decisions leave here.
        history = export_history(
            db,
            identity,
            clock,
            permission="workspace.manage" if scope == "workspace" else "policy.manage",
        )
        report = simulate(verify_export(history, history.head), record.content, catalog=catalog)
    except (ExportError, ReplayValidationError, ValueError):
        raise PolicyStoreError("PREVIEW_UNAVAILABLE") from None
    since = clock.now() - window
    in_window = [
        decision
        for decision in report.decisions
        if decision.semantic_time >= since and decision.candidate is not None
    ]
    permitted = (
        _permitted(db, identity, {item.execution_id for item in in_window})
        if scope == "spaces"
        else None
    )
    baseline: Counter[str] = Counter()
    candidate: Counter[str] = Counter()
    changed: list[ChangedDecision] = []
    considered = 0
    for decision in in_window:
        if decision.candidate is None:
            continue
        # A reader filtered to their Spaces counts nothing recorded outside them.
        if permitted is not None and decision.execution_id not in permitted:
            continue
        considered += 1
        baseline[decision.baseline.effect] += 1
        candidate[decision.candidate.effect] += 1
        if decision.baseline.effect != decision.candidate.effect or decision.differences:
            changed.append(
                ChangedDecision(
                    execution_id=decision.execution_id,
                    action=decision.action,
                    semantic_time=decision.semantic_time,
                    baseline_effect=decision.baseline.effect,
                    baseline_reasons=decision.baseline.reasons,
                    candidate_effect=decision.candidate.effect,
                    candidate_reasons=decision.candidate.reasons,
                    candidate_obligations=tuple(decision.candidate.obligation_ids),
                    differences=decision.differences,
                    required_approvers=record.content.required_approvers(
                        decision.candidate.obligation_ids
                    ),
                )
            )
    return BundlePreview(
        bundle_id=record.content.bundle_id,
        content_hash=record.content.content_hash,
        state=record.state,
        window_seconds=int(window.total_seconds()),
        considered=considered,
        changed=tuple(changed),
        baseline_effects=dict(sorted(baseline.items())),
        candidate_effects=dict(sorted(candidate.items())),
        complete=report.complete,
        issues=report.issues,
        scope=scope,
    )
