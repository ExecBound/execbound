# SPDX-License-Identifier: AGPL-3.0-only
"""What became of a request, as SQL predicates a count and a list share (#678).

Every statement elsewhere in the surfaces is written out whole and never assembled:
`dashboard.py` and `board.py` say why, and bandit agrees. This module is the one deliberate
exception. A count a person reads on Home or on the report and the Activity list its link
opens must be one predicate, because two written-out copies drift, and a count that
disagrees with the list it opens is the defect this module exists to remove. So the
predicates live here once, as module literals over an `executions e` row, and the two
fragments the readers need are assembled once at import from those literals alone:
`OUTCOME_FILTER`, the clause `records()` appends, and `COUNT_COLUMNS`, the
`count(*) FILTER (WHERE …)` list the value read selects. No request value reaches the
text: the fragments exist before any route does, and `records()` binds `:outcome` rather
than formatting it. No other module joins SQL text.

An approval past its deadline is classified at read time on the server's clock, bound as
`:now`, in two classes told apart by `decided_at`: `lapsed`, which nobody decided, and
`approved_unused`, which a person approved and the agent did not use before the deadline.
Together they are exactly `records(lapsed=True)`'s set and the recovery run's selector.
Nothing here writes: the recovery run alone moves an approval to `EXPIRED`.
"""

from collections.abc import Mapping
from typing import Any, Literal

# The kind of a denial, from the codes its `DENIED` transition recorded, read as one JSON
# array (the policy writes `reasons`, admission and a reviewer one `reason`):
# `store.denial_category`'s `busy` and `limit`, exactly as it decides them, and its `withheld`
# split into a person's refusal (`HUMAN_DENIED` alone) and everything else.
DENIAL_KIND_SQL = (
    "(SELECT CASE WHEN c.codes = '[\"RESOURCE_BUSY\"]'::jsonb THEN 'busy' "
    "WHEN EXISTS (SELECT 1 FROM jsonb_array_elements_text(c.codes) AS code(value) "
    "WHERE code.value LIKE 'HARD\\_LIMIT:%') THEN 'limit' "
    "WHEN c.codes = '[\"HUMAN_DENIED\"]'::jsonb THEN 'person' "
    "ELSE 'policy' END FROM (SELECT coalesce((SELECT CASE "
    "WHEN jsonb_typeof(ev.payload -> 'reasons') = 'array' THEN ev.payload -> 'reasons' "
    "WHEN coalesce(ev.payload ->> 'reason', '') <> '' "
    "THEN jsonb_build_array(ev.payload ->> 'reason') ELSE '[]'::jsonb END "
    "FROM execbound.execution_events ev "
    "WHERE ev.tenant_id = e.tenant_id AND ev.execution_id = e.execution_id "
    "AND ev.to_state = 'DENIED' ORDER BY ev.created_at DESC LIMIT 1), '[]'::jsonb) "
    "AS codes) c)"
)

# A person's final decision, read from the decider's own row in `approval_decisions` rather
# than from `approvals.state`: an approved approval the agent never used later becomes
# `EXPIRED`, and it was still approved.
_DECIDED = (
    "EXISTS (SELECT 1 FROM execbound.approvals a JOIN execbound.approval_decisions d "
    "ON d.tenant_id = a.tenant_id AND d.approval_id = a.approval_id "
    "AND d.principal_id = a.decided_by "
    "WHERE a.tenant_id = e.tenant_id AND a.execution_id = e.execution_id "
    "AND a.decided_at IS NOT NULL AND d.decision = "
)

PREDICATES: dict[str, str] = {
    "refused_policy": "(e.state = 'DENIED' AND " + DENIAL_KIND_SQL + " = 'policy')",
    "refused_limit": "(e.state = 'DENIED' AND " + DENIAL_KIND_SQL + " = 'limit')",
    "refused_busy": "(e.state = 'DENIED' AND " + DENIAL_KIND_SQL + " = 'busy')",
    "approved": _DECIDED + "'APPROVE')",
    "refused_by_person": _DECIDED + "'DENY')",
    # Lapsed before a decision: recorded `EXPIRED` by the recovery run or a late touch, or
    # still `PENDING` past its deadline while the request waits for the sweep.
    "lapsed": (
        "EXISTS (SELECT 1 FROM execbound.approvals a "
        "WHERE a.tenant_id = e.tenant_id AND a.execution_id = e.execution_id "
        "AND a.decided_at IS NULL AND (a.state = 'EXPIRED' OR (a.state = 'PENDING' "
        "AND a.expires_at <= :now AND e.state = 'PENDING_APPROVAL')))"
    ),
    # Approved, but not used before the deadline: a person did decide it (AX6).
    "approved_unused": (
        "EXISTS (SELECT 1 FROM execbound.approvals a "
        "WHERE a.tenant_id = e.tenant_id AND a.execution_id = e.execution_id "
        "AND a.decided_at IS NOT NULL AND (a.state = 'EXPIRED' OR (a.state = 'APPROVED' "
        "AND a.expires_at <= :now AND e.state = 'PENDING_APPROVAL')))"
    ),
    # Closed without a decision: the request or its authority changed under it.
    "closed": (
        "EXISTS (SELECT 1 FROM execbound.approvals a "
        "WHERE a.tenant_id = e.tenant_id AND a.execution_id = e.execution_id "
        "AND a.decided_at IS NULL AND a.state = 'INVALIDATED')"
    ),
    # What a person can still decide, as `records(pending=True)` reads it.
    "waiting": (
        "(e.state = 'PENDING_APPROVAL' AND EXISTS (SELECT 1 FROM execbound.approvals a "
        "WHERE a.tenant_id = e.tenant_id AND a.execution_id = e.execution_id "
        "AND a.state = 'PENDING' AND a.expires_at > :now))"
    ),
    # An uncertain dispatch the kernel held as indeterminate that has since settled, a
    # correction of a reported failure included; a row still `FAILED_EFFECT_UNKNOWN` is not.
    "settled": (
        "(e.state IN ('EXECUTED', 'FAILED_NOT_EXECUTED', 'STALE_AUTHORIZATION') "
        "AND EXISTS (SELECT 1 FROM execbound.execution_events ev "
        "WHERE ev.tenant_id = e.tenant_id AND ev.execution_id = e.execution_id "
        "AND ev.from_state = 'INDETERMINATE'))"
    ),
    "unsettled_now": "(e.state IN ('DISPATCH_COMMITTED', 'INDETERMINATE'))",
    "effect_unknown": "(e.state = 'FAILED_EFFECT_UNKNOWN')",
    "would_refuse": "(e.state = 'OBSERVED' AND e.result -> 'observed' ->> 'effect' = 'DENY')",
    "would_refuse_by_limit": (
        "(e.state = 'OBSERVED' AND e.result -> 'observed' ->> 'effect' = 'DENY' "
        "AND jsonb_typeof(e.result -> 'observed' -> 'reasons') = 'array' "
        "AND EXISTS (SELECT 1 FROM jsonb_array_elements_text("
        "e.result -> 'observed' -> 'reasons') AS code(value) "
        "WHERE code.value LIKE 'HARD\\_LIMIT:%'))"
    ),
    "would_hold": (
        "(e.state = 'OBSERVED' AND e.result -> 'observed' ->> 'effect' = 'REQUIRE_APPROVAL')"
    ),
    "would_run": "(e.state = 'OBSERVED' AND e.result -> 'observed' ->> 'effect' = 'ELIGIBLE')",
}

# The keys a list may be filtered by; every key above opens its own list.
OUTCOMES: frozenset[str] = frozenset(PREDICATES)

# The clause `records()` appends: one guard that folds away when no outcome is asked for, and
# one literal alternative per key, the outcome itself a bound parameter.
OUTCOME_FILTER: str = (
    " AND (CAST(:outcome AS text) IS NULL OR "
    + " OR ".join(  # nosec B608 - module literals only
        f"(:outcome = '{key}' AND {sql})" for key, sql in PREDICATES.items()
    )
    + ")"
)

# The value read's columns: one count per key, named by the key.
COUNT_COLUMNS: str = ", ".join(  # nosec B608 - module literals only
    f"count(*) FILTER (WHERE {sql}) AS {key}" for key, sql in PREDICATES.items()
)

DenialKind = Literal["busy", "limit", "person", "policy"]


def denial_kind(payload: Mapping[str, Any]) -> DenialKind:
    """`store.denial_category`, with its `withheld` split into a person's and the rest.

    Used by the tests, which hold it equal to `DENIAL_KIND_SQL` and to the agent's category.
    """
    reasons = payload.get("reasons")
    if isinstance(reasons, list):
        codes = [str(code) for code in reasons]
    else:
        codes = [str(payload["reason"])] if payload.get("reason") else []
    if codes == ["RESOURCE_BUSY"]:
        return "busy"
    if any(code.startswith("HARD_LIMIT:") for code in codes):
        return "limit"
    if codes == ["HUMAN_DENIED"]:
        return "person"
    return "policy"
