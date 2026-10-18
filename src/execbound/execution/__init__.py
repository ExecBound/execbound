# SPDX-License-Identifier: AGPL-3.0-only
"""Durable internal coordinator. No network operation or public mutation route lives here.

The package is split by transaction path: admission, approvals, dispatch, outcomes and
reconciliation each hold one, and authority holds the decision, stale-authorization and
rejection helpers they share. Every writer takes the tenant fence in the lock order
documented in docs/EXECUTION.md and cites it there.
"""

from execbound.execution import store as store
from execbound.execution.admission import admit, get_execution
from execbound.execution.approvals import decide_approval
from execbound.execution.authority import _rejection as _rejection
from execbound.execution.dispatch import _never_a_checkpoint as _never_a_checkpoint
from execbound.execution.dispatch import mark_indeterminate, take_dispatch
from execbound.execution.modes import (
    approval_deadline,
    enforcement_mode,
    observe_report,
    set_approval_deadline,
    set_enforcement_mode,
)
from execbound.execution.outcomes import _correctable as _correctable
from execbound.execution.outcomes import record_outcome, report_outcome
from execbound.execution.reconciliation import reconcile
from execbound.execution.snapshot import attest_snapshot as attest_snapshot
from execbound.execution.snapshot import resolve_snapshot as resolve_snapshot
from execbound.execution.stops import activate_stop, release_stop, stop_status

__all__ = [
    "admit",
    "decide_approval",
    "get_execution",
    "take_dispatch",
    "mark_indeterminate",
    "record_outcome",
    "report_outcome",
    "reconcile",
    "activate_stop",
    "release_stop",
    "stop_status",
    "set_enforcement_mode",
    "enforcement_mode",
    "set_approval_deadline",
    "approval_deadline",
    "observe_report",
]
