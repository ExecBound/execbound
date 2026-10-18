# SPDX-License-Identifier: AGPL-3.0-only
"""Which actions a policy bundle can hold for a person, and how long a held request can wait.

Every answer here is a preview read from stored bundle content and the context catalog: nothing
assigns anyone, lengthens an approval or changes a deadline, a context setting or a destination,
and no decision, resume or consume path reads it. Each figure is an upper bound, because a
request's time starts when its facts were recorded, not when it was held, and a custom Cedar
policy that can hold an action is reported as unknown rather than guessed at (#678).
"""

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID

from sqlalchemy import Connection, text

from execbound import access_control
from execbound.contracts import Catalog, ContractError, SourceKind, effective_source
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.operations import CatalogError
from execbound.policy.models import BundleContent
from execbound.policy.store import PolicyStoreError
from execbound.spaces import Visibility, space_clause

if TYPE_CHECKING:
    from execbound.runtime import Runtime
    from execbound.surfaces.sessions import Session

# The most Spaces the settings and coverage reads list.
MAX_SPACES = 50
# Coverage looks back this far for requested and held targets; the unrouted read's "recently"
# looks back `RECENT_DAYS`.
COVERAGE_DAYS = 30
RECENT_DAYS = 7
# Each coverage list carries its true total and at most this many rows, newest first.
MAX_ROWS = 20
# The coverage scan reads at most this many (Space, action, target) groups, newest first.
MAX_GROUPS = 5000
# The unrouted read looks at no more than this many of the newest pending approvals.
PENDING_SCAN = 200

LimitedBy = Literal["deadline", "context", "unknown"]

# How many distinct people `store.scope_check` would let decide a request now, for its Space,
# canonical target and action. The `console.read` term mirrors `principal_allows` in
# `scope_check`; the view already requires `approvals.decide` in the same Space, which implies
# it, so the term changes no count and keeps the statement reading like the check it previews.
_ELIGIBLE = text(
    "SELECT count(DISTINCT s.approver_id) FROM execbound.effective_approval_scopes s "
    "WHERE s.tenant_id = :t AND s.space_id = :space AND s.canonical_target_id = :target "
    "AND s.action = :action AND s.active "
    "AND execbound.access_has_permission(s.approver_id, 'console.read', s.space_id, false)"
)


@dataclass(frozen=True)
class Hold:
    """One action a bundle can send to a person.

    `held_by` names what holds it: `rule:<id>` for a REVIEW rule, `limit:<id>` for a limit that
    asks for approval when exceeded, and `policy` for a custom bundle's own approval policies.
    `known` is false where custom Cedar may hold it and which requests it holds cannot be read.
    `required` is how many people must decide; with `upto`, it is the most the policy can ask.
    """

    action: str
    held_by: tuple[str, ...]
    known: bool
    required: int
    upto: bool


@dataclass(frozen=True)
class Window:
    """How long a held request for one action can wait at most.

    `bound_seconds` is the context figure capped by the deadline, `None` with the reason
    `unknown` when a mapping's contract is not in the catalog. `source_kinds` are the kinds of
    fact whose validity sets `context_seconds`.
    """

    action: str
    context_seconds: int | None
    bound_seconds: int | None
    limited_by: LimitedBy
    source_kinds: tuple[SourceKind, ...]
    known: bool


@dataclass(frozen=True)
class SpaceWindows:
    space_id: UUID
    name: str
    bundle_id: UUID | None
    windows: tuple[Window, ...]


def eligible_reviewers(
    conn: Connection, tenant: UUID, space: UUID, target: UUID, action: str
) -> int:
    """How many distinct people `store.scope_check` would let decide this now.

    A preview: admission records it beside a held approval, and the console reads it, but
    nothing that decides, resumes or consumes an approval reads it. Eligibility is checked
    again, from the live tables, when a person decides and before execution.
    """
    return int(
        conn.execute(
            _ELIGIBLE, {"t": tenant, "space": space, "target": target, "action": action}
        ).scalar_one()
    )


def _served(content: BundleContent) -> frozenset[str]:
    """Actions some mapping holds requests for; an observe-only mapping only observes."""
    return frozenset(m.action_name for m in content.mappings if not m.observe_only)


def holds(content: BundleContent) -> tuple[Hold, ...]:
    """Every action this bundle can hold, sorted by action.

    A bundle written as rules holds an action through a REVIEW rule (its quorum, else one) or
    through a limit whose `on_exceed` is `REQUIRE_APPROVAL`. A custom bundle's limits are read
    the same way, and if its approval policies are not empty every action it serves may be held,
    with the quorum "up to" the largest its quorum rules ask. Actions served only by an
    observe-only mapping are never listed: requests through it are observed, not held.
    """
    served = _served(content)
    quorum = {rule.obligation: rule.required for rule in content.quorum or ()}
    held_by: dict[str, list[str]] = {}
    required: dict[str, int] = {}

    def hold(action: str, name: str, needs: int) -> None:
        if action not in served:
            return
        held_by.setdefault(action, []).append(name)
        required[action] = max(required.get(action, 1), needs)

    if content.ruleset is not None:
        for rule in content.ruleset.rules:
            if rule.effect == "REVIEW":
                hold(rule.action, f"rule:{rule.id}", rule.quorum or 1)
    for limit in content.limits:
        if limit.on_exceed == "REQUIRE_APPROVAL":
            for action in limit.action_names:
                hold(action, f"limit:{limit.rule_id}", quorum.get(f"limit:{limit.rule_id}", 1))
    unknown: frozenset[str] = frozenset()
    if content.ruleset is None and content.approval_policies.strip():
        unknown = served
        most = max(
            (needs for name, needs in quorum.items() if name.startswith("policy:")), default=1
        )
        for action in sorted(served):
            hold(action, "policy", most)
    return tuple(
        Hold(
            action=action,
            held_by=tuple(held_by[action]),
            known=action not in unknown,
            required=required[action],
            upto=action in unknown and required[action] > 1,
        )
        for action in sorted(held_by)
    )


def _mapping_window(
    content: BundleContent, catalog: Catalog, version: str, deadline: int | None
) -> tuple[int, int, tuple[SourceKind, ...]] | None:
    """(context, bound, limiting kinds) for one mapping's contract, or None when unknown."""
    try:
        contract = catalog.contract(version)
        # The kinds resolution reads are those of the contract's facts.
        ages = {
            kind: effective_source(contract, content.context_settings, kind).max_age_seconds
            for kind in {spec.source_kind for spec in contract.facts}
        }
    except ContractError:
        return None
    if not ages:
        return None
    context = min(ages.values())
    bound = context if deadline is None else min(context, deadline)
    return context, bound, tuple(sorted(kind for kind, age in ages.items() if age == context))


def windows(content: BundleContent, catalog: Catalog, deadline: int | None) -> tuple[Window, ...]:
    """The upper bound on how long a held request can wait, for each action `holds` lists.

    Per mapping, the smallest effective `max_age_seconds` over the source kinds its contract
    resolves, read through the bundle's own context settings as admission reads them, capped by
    the deadline when there is one. An action several mappings serve takes the largest bound,
    because the figure is an upper bound; any mapping whose contract is unknown makes it unknown.
    """
    found: list[Window] = []
    for held in holds(content):
        figures = [
            _mapping_window(content, catalog, mapping.context_contract_version, deadline)
            for mapping in content.mappings
            if not mapping.observe_only and mapping.action_name == held.action
        ]
        known = [figure for figure in figures if figure is not None]
        if not known or len(known) != len(figures):
            found.append(Window(held.action, None, None, "unknown", (), held.known))
            continue
        context, bound, kinds = max(known, key=lambda figure: (figure[1], figure[0]))
        limited: LimitedBy = (
            "deadline" if deadline is not None and deadline < context else "context"
        )
        found.append(Window(held.action, context, bound, limited, kinds, held.known))
    return tuple(found)


def approval_windows(
    conn: Connection,
    tenant: UUID,
    catalog: Catalog,
    visibility: Visibility,
    deadline: int | None,
) -> tuple[SpaceWindows, ...]:
    """`windows` for the current Space, or for each visible non-archived Space, by name.

    Read inside the caller's transaction, beside the deadline it is computed against. A Space
    with no selection has no windows: admission fails closed there, so nothing is held.
    """
    space = space_clause(visibility, "s")
    rows = conn.execute(
        text(
            "SELECT s.space_id, s.name, p.bundle_id FROM execbound.spaces s "
            "LEFT JOIN execbound.space_policy_selection p "
            "ON p.tenant_id = s.tenant_id AND p.space_id = s.space_id "
            "WHERE s.tenant_id = :t AND s.archived_at IS NULL"
            + space.sql  # nosec B608 - one helper's predicate; values bound
            + " ORDER BY s.name, s.space_id LIMIT :limit"
        ),
        {"t": tenant, "limit": MAX_SPACES, **space.params},
    ).all()
    result: list[SpaceWindows] = []
    for space_id, name, bundle_id in rows:
        if bundle_id is None:
            result.append(SpaceWindows(space_id, str(name), None, ()))
            continue
        try:
            content = store.bundle(conn, tenant, bundle_id)
        except PolicyStoreError:
            raise ExecutionError() from None
        held = windows(content, catalog, deadline)
        result.append(SpaceWindows(space_id, str(name), bundle_id, held))
    return tuple(result)


class ApprovalRoutingError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _guard(conn: Connection, runtime: "Runtime", session: "Session") -> None:
    """A signed-in workspace administrator with workspace-wide `access.manage`.

    The checks `approval_rules` makes, without its fence: these reads are previews in their own
    snapshot and never wait behind a writer. An administrator narrowed to Spaces holds
    `access.manage` only with `any_scope`, so the workspace-wide test refuses them.
    """
    from execbound.surfaces.sessions import check_session

    identity = session.identity
    try:
        store.identity_check(conn, identity, runtime.clock, "ADMIN")
    except ExecutionError:
        raise ApprovalRoutingError("INVALID_ACTOR") from None
    check_session(conn, session, runtime.clock)
    if not access_control.has_permission(
        conn, identity.tenant_id, identity.principal_id, "access.manage"
    ):
        raise ApprovalRoutingError("INVALID_ACTOR")


def _label(catalog: Catalog, action: str) -> str:
    try:
        return catalog.actions.action(action).label
    except CatalogError:
        return action


# Every requested (Space, action, target) group in the window, newest first, whether any of its
# requests was held, and how many people can decide it now. The eligible side is the predicate
# `eligible_reviewers` counts, grouped.
_REQUESTED = text("""
WITH requested AS (
  SELECT e.space_id, e.frozen -> 'intent' ->> 'action' AS action, e.canonical_target_id,
         count(*) AS requests, max(e.created_at) AS last_requested_at,
         bool_or(a.approval_id IS NOT NULL) AS held
    FROM execbound.executions e
    LEFT JOIN execbound.approvals a
      ON a.tenant_id = e.tenant_id AND a.execution_id = e.execution_id
   WHERE e.tenant_id = :t AND e.created_at >= :since
     AND e.space_id = ANY(CAST(:spaces AS uuid[]))
   GROUP BY 1, 2, 3
   ORDER BY max(e.created_at) DESC, 1, 2, 3
   LIMIT :groups
), eligible AS (
  SELECT s.space_id, s.action, s.canonical_target_id, count(DISTINCT s.approver_id) AS n
    FROM execbound.effective_approval_scopes s
   WHERE s.tenant_id = :t AND s.active
     AND execbound.access_has_permission(s.approver_id, 'console.read', s.space_id, false)
   GROUP BY 1, 2, 3
)
SELECT r.space_id, r.action, r.canonical_target_id, r.requests, r.last_requested_at, r.held,
       coalesce(el.n, 0) AS reviewers
  FROM requested r
  LEFT JOIN eligible el USING (space_id, action, canonical_target_id)
 ORDER BY r.last_requested_at DESC, r.space_id, r.action, r.canonical_target_id
""")

# How many distinct people can decide each action on at least one target in each Space now.
_REVIEWERS = text("""
SELECT s.space_id, s.action, count(DISTINCT s.approver_id) AS n
  FROM execbound.effective_approval_scopes s
 WHERE s.tenant_id = :t AND s.active
   AND execbound.access_has_permission(s.approver_id, 'console.read', s.space_id, false)
 GROUP BY 1, 2
""")

# The provider identifiers that label each target in the answer, as the approvers page reads
# them; operator data, rendered as text.
_LABELS = text("""
SELECT ct.canonical_target_id,
       string_agg(r.provider_id, ', ' ORDER BY r.provider_id) AS labels
  FROM execbound.canonical_targets ct
  LEFT JOIN execbound.resource_identities ri
    ON ri.tenant_id = ct.tenant_id AND ri.canonical_target_id = ct.canonical_target_id
  LEFT JOIN execbound.resources r
    ON r.tenant_id = ri.tenant_id AND r.account_id = ri.account_id AND r.provider = ri.provider
   AND r.resource_type = ri.resource_type AND r.resource_id = ri.resource_id
 WHERE ct.tenant_id = :t AND ct.canonical_target_id = ANY(CAST(:targets AS uuid[]))
 GROUP BY ct.canonical_target_id
""")


def _bounded(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"total": len(rows), "rows": rows[:MAX_ROWS]}


def read_coverage(runtime: "Runtime", session: "Session") -> dict[str, Any]:
    """For each Space and each action its active policy can hold, who can decide it.

    A workspace administrator's whole-workspace view, read in one snapshot without the tenant
    fence. Counts only: no reviewer is named. `held_uncovered` are targets held in the window
    that fewer people can decide now than the action needs; `requested_uncovered` those
    requested and never held that would be short if they were; `thin` those held whose eligible
    count equals the quorum exactly. Every figure is a preview: eligibility is checked again
    when a request is reviewed and before execution.
    """
    identity = session.identity
    tenant = identity.tenant_id
    with runtime.db.transaction(tenant, snapshot=True) as conn:
        _guard(conn, runtime, session)
        now = store.now(runtime.clock)
        since = now - timedelta(days=COVERAGE_DAYS)
        found = conn.execute(
            text(
                "SELECT s.space_id, s.name, p.bundle_id FROM execbound.spaces s "
                "LEFT JOIN execbound.space_policy_selection p "
                "ON p.tenant_id = s.tenant_id AND p.space_id = s.space_id "
                "WHERE s.tenant_id = :t AND s.archived_at IS NULL "
                "ORDER BY s.name, s.space_id LIMIT :limit"
            ),
            {"t": tenant, "limit": MAX_SPACES + 1},
        ).all()
        truncated = len(found) > MAX_SPACES
        spaces: list[dict[str, Any]] = []
        held: dict[tuple[UUID, str], Hold] = {}
        for space_id, name, bundle_id in found[:MAX_SPACES]:
            entry: dict[str, Any] = {
                "space_id": space_id,
                "name": str(name),
                "bundle_id": bundle_id,
                "policy": "none",
                "actions": [],
            }
            spaces.append(entry)
            if bundle_id is None:
                continue
            try:
                content = store.bundle(conn, tenant, bundle_id)
            except PolicyStoreError:
                raise ExecutionError() from None
            entry["policy"] = "rules" if content.ruleset is not None else "custom"
            for hold in holds(content):
                held[(space_id, hold.action)] = hold
        reviewers = {
            (row.space_id, row.action): int(row.n)
            for row in conn.execute(_REVIEWERS, {"t": tenant})
        }
        groups = [
            dict(row)
            for row in conn.execute(
                _REQUESTED,
                {
                    "t": tenant,
                    "since": since,
                    "spaces": [entry["space_id"] for entry in spaces],
                    "groups": MAX_GROUPS + 1,
                },
            ).mappings()
        ]
        if len(groups) > MAX_GROUPS:
            truncated = True
            groups = groups[:MAX_GROUPS]
        lists: dict[tuple[UUID, str], dict[str, list[dict[str, Any]]]] = {
            key: {"held_uncovered": [], "requested_uncovered": [], "thin": []} for key in held
        }
        for group in groups:
            key = (group["space_id"], group["action"])
            holding = held.get(key)
            if holding is None:
                continue
            needs = holding.required if holding.known else 1
            count = int(group["reviewers"])
            if group["held"] and count < needs:
                which = "held_uncovered"
            elif not group["held"] and count < needs:
                which = "requested_uncovered"
            elif group["held"] and count == needs:
                which = "thin"
            else:
                continue
            lists[key][which].append(
                {
                    "canonical_target_id": group["canonical_target_id"],
                    "requests": int(group["requests"]),
                    "last_requested_at": group["last_requested_at"],
                    "reviewers": count,
                }
            )
        shown = {
            row["canonical_target_id"]
            for found_lists in lists.values()
            for rows in found_lists.values()
            for row in rows[:MAX_ROWS]
        }
        labels = (
            {
                row.canonical_target_id: row.labels
                for row in conn.execute(_LABELS, {"t": tenant, "targets": list(shown)})
            }
            if shown
            else {}
        )
        for entry in spaces:
            for (space_id, action), hold in sorted(held.items(), key=lambda item: item[0][1]):
                if space_id != entry["space_id"]:
                    continue
                found_lists = lists[(space_id, action)]
                for rows in found_lists.values():
                    for row in rows[:MAX_ROWS]:
                        row["labels"] = labels.get(row["canonical_target_id"])
                entry["actions"].append(
                    {
                        "action": action,
                        "action_label": _label(runtime.catalog, action),
                        "held_by": list(hold.held_by),
                        "known": hold.known,
                        "required": hold.required if hold.known else 1,
                        "upto": hold.required if hold.upto else None,
                        "reviewers": reviewers.get((space_id, action), 0),
                        **{name: _bounded(rows) for name, rows in found_lists.items()},
                    }
                )
        mode = store.enforcement_mode(conn, tenant)
        # Checked again at the end of the snapshot, as the rule pages check theirs.
        _guard(conn, runtime, session)
        return {
            "server_time": now,
            "since": since,
            "mode": mode,
            "truncated": truncated,
            "spaces": spaces,
        }


# The newest pending approvals that can still be decided, each with how many people can decide
# it now; the caller keeps those short of their quorum. One row past the scan says it was cut.
_PENDING = text("""
SELECT a.approval_id, a.execution_id, 'EB-' || e.request_number AS request_ref, a.space_id,
       a.expires_at AS at, a.state, a.required_approvers, eligible.n AS reviewers
  FROM execbound.approvals a
  JOIN execbound.executions e ON e.tenant_id = a.tenant_id AND e.execution_id = a.execution_id
  CROSS JOIN LATERAL (
    SELECT count(DISTINCT s.approver_id) AS n
      FROM execbound.effective_approval_scopes s
     WHERE s.tenant_id = e.tenant_id AND s.space_id = e.space_id
       AND s.canonical_target_id = e.canonical_target_id
       AND s.action = e.frozen -> 'intent' ->> 'action' AND s.active
       AND execbound.access_has_permission(s.approver_id, 'console.read', s.space_id, false)
  ) eligible
 WHERE a.tenant_id = :t AND a.state = 'PENDING' AND a.expires_at > :now
   AND e.state = 'PENDING_APPROVAL'
 ORDER BY a.created_at DESC, a.approval_id
 LIMIT :scan
""")

# Approvals held in the last `RECENT_DAYS` with fewer people who could decide them, as recorded
# when they were held, than they needed. Rows held before the record existed carry NULL and are
# never counted.
_RECENT = text("""
SELECT a.approval_id, a.execution_id, 'EB-' || e.request_number AS request_ref, a.space_id,
       a.created_at AS at, a.state, count(*) OVER () AS total
  FROM execbound.approvals a
  JOIN execbound.executions e ON e.tenant_id = a.tenant_id AND e.execution_id = a.execution_id
 WHERE a.tenant_id = :t AND a.created_at >= :since
   AND a.reviewers_at_hold IS NOT NULL AND a.reviewers_at_hold < a.required_approvers
 ORDER BY a.created_at DESC, a.approval_id
 LIMIT 1
""")


def _record(row: Any) -> dict[str, Any]:
    return {
        "approval_id": row.approval_id,
        "execution_id": row.execution_id,
        "request_ref": row.request_ref,
        "space_id": row.space_id,
        "at": row.at,
        "state": str(row.state),
    }


def read_unrouted(runtime: "Runtime", session: "Session") -> dict[str, Any]:
    """Held requests too few people can decide, now and over the last `RECENT_DAYS`.

    `pending` counts, of the newest `PENDING_SCAN` approvals still open, those fewer people can
    decide now than they need, and `pending_nobody` those nobody can; `recent` counts approvals
    held in the window whose hold-time record was below their quorum. The same workspace
    administrator's view as `read_coverage`, in its own snapshot, without the fence.
    """
    identity = session.identity
    tenant = identity.tenant_id
    with runtime.db.transaction(tenant, snapshot=True) as conn:
        _guard(conn, runtime, session)
        now = store.now(runtime.clock)
        scanned = conn.execute(_PENDING, {"t": tenant, "now": now, "scan": PENDING_SCAN + 1}).all()
        short = [
            row for row in scanned[:PENDING_SCAN] if int(row.reviewers) < row.required_approvers
        ]
        recent = conn.execute(
            _RECENT, {"t": tenant, "since": now - timedelta(days=RECENT_DAYS)}
        ).one_or_none()
        _guard(conn, runtime, session)
        return {
            "server_time": now,
            "pending": len(short),
            "pending_nobody": sum(1 for row in short if int(row.reviewers) == 0),
            "pending_truncated": len(scanned) > PENDING_SCAN,
            "pending_latest": _record(short[0]) if short else None,
            "recent": int(recent.total) if recent is not None else 0,
            "recent_latest": _record(recent) if recent is not None else None,
        }
