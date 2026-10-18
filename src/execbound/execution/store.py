# SPDX-License-Identifier: AGPL-3.0-only
"""Caller-owned transactions; tenant control then audit head is the global lock order.

All execution writers take this fence, including approval, dispatch and outcome
transitions. Other row writes follow without competing execution writers. Registry
evidence is a subsequent non-locking statement snapshot. Provider I/O never occurs here.
"""

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.audit import append_event, canonical_json
from execbound.db import check_runtime
from execbound.execution.models import (
    DEFAULT_APPROVAL_DEADLINE,
    UNSETTLED,
    DenialCategory,
    DispatchCommand,
    ExecutionError,
    ExecutionView,
    ObservedResult,
    StopState,
    transition_allowed,
)
from execbound.identity import Identity
from execbound.policy.approval import VerifiedApproval
from execbound.policy.models import (
    MAX_GROUPS,
    BundleContent,
    MappingRef,
    ProjectedUsage,
    UsageSnapshot,
)
from execbound.policy.store import _identity, _read
from execbound.resolution.models import Clock, ResolvedRequest, scalar_facts
from execbound.spaces import agent_space, default_space, narrowed, principal_allows


def now(clock: Clock) -> datetime:
    value = clock.now()
    if value.tzinfo is None or value.utcoffset() is None:
        raise ExecutionError("INVALID_CLOCK")
    return value.astimezone(UTC)


def fence(conn: Connection, tenant: UUID, clock: Clock) -> None:
    check_runtime(conn)
    conn.execute(
        text(
            "INSERT INTO execbound.tenant_policy_control(tenant_id,changed_at) "
            "VALUES (:t,:n) ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"t": tenant, "n": now(clock)},
    )
    conn.execute(
        text("SELECT tenant_id FROM execbound.tenant_policy_control WHERE tenant_id=:t FOR UPDATE"),
        {"t": tenant},
    ).one()
    conn.execute(
        text(
            "INSERT INTO execbound.audit_heads(tenant_id) VALUES (:t) "
            "ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"t": tenant},
    )
    conn.execute(
        text("SELECT tenant_id FROM execbound.audit_heads WHERE tenant_id=:t FOR UPDATE"),
        {"t": tenant},
    ).one()


def fixture_only(conn: Connection, tenant: UUID) -> bool:
    """Advanced demos may alter policy and budgets, so exclude any mixed/unknown data.

    Include inactive rows: deactivation does not make customer history synthetic.
    The fixed, read-only learning example does not need this permission.
    """
    return bool(
        conn.execute(
            text("""SELECT
        EXISTS (SELECT 1 FROM execbound.resources WHERE tenant_id=:t AND demo_fixture)
        AND NOT EXISTS (SELECT 1 FROM execbound.connector_accounts WHERE tenant_id=:t
            AND provider NOT IN ('mock_crowdstrike','mock_entra'))
        AND NOT EXISTS (SELECT 1 FROM execbound.resources WHERE tenant_id=:t
            AND (NOT demo_fixture OR provider NOT IN ('mock_crowdstrike','mock_entra')))
        AND NOT EXISTS (SELECT 1 FROM execbound.resource_facts WHERE tenant_id=:t
            AND NOT demo_fixture)
        AND NOT EXISTS (SELECT 1 FROM execbound.incidents WHERE tenant_id=:t
            AND NOT demo_fixture)
    """),
            {"t": tenant},
        ).scalar_one()
    )


def demo_check(conn: Connection, tenant: UUID, synthetic: bool) -> None:
    if synthetic and not fixture_only(conn, tenant):
        raise ExecutionError("DEMO_UNAVAILABLE")


def identity_check(conn: Connection, identity: Identity, clock: Clock, kind: str) -> None:
    # Anything that is not an Identity, a scheduled pass's actor above all (#503), is refused
    # here: it is admitted only where `execution.scheduled.actor_check` is asked instead.
    if not isinstance(identity, Identity) or identity.kind != kind:
        raise ExecutionError("INVALID_IDENTITY")
    _identity(conn, identity, clock, admin=kind == "ADMIN")


def workspace_admin_check(conn: Connection, identity: Identity, clock: Clock) -> None:
    """`identity_check` for an administrator who holds the whole workspace.

    The enforcement mode, the approval deadline, the emergency stop and the assistant switch
    are each one value for every space of the tenant, so only a workspace administrator
    changes them (decided 8 October 2026). The observe report and the rotation readiness
    read are every space's too, so only a workspace administrator reads them. An administrator
    narrowed to spaces is refused with the code any actor who is not an administrator gets
    here, `INVALID_IDENTITY`, asked with `spaces.narrowed`, which is the definer functions' own
    predicate in their words. Reading the settings stays `identity_check`'s.
    """
    identity_check(conn, identity, clock, "ADMIN")
    if narrowed(conn, identity.tenant_id, identity.principal_id):
        raise ExecutionError("INVALID_IDENTITY")


def active_bundle(conn: Connection, tenant: UUID, space: UUID | None = None) -> BundleContent:
    """The bundle the space selects, read under the fence admission already holds.

    A space with no selection fails closed exactly as a tenant with none did before
    spaces; a caller that names none reads the tenant's only space.
    """
    active = conn.execute(
        text(
            "SELECT bundle_id FROM execbound.space_policy_selection "
            "WHERE tenant_id=:t AND space_id=:s"
        ),
        {"t": tenant, "s": space if space is not None else default_space(conn, tenant)},
    ).scalar_one_or_none()
    if active is None:
        raise ExecutionError("NO_ACTIVE_BUNDLE")
    record = _read(conn, tenant, active, lock=False)
    if record.state != "ACTIVE":
        raise ExecutionError("INVALID_BUNDLE")
    # The selected mapping is checked by admission's offered check (`execution.offered`),
    # which refuses a request the bundle cannot serve before resolution, then by the coherent
    # resolver and evaluator.
    # Immutable policy content is reparsed/digest-checked; Cedar evaluates both sets.
    return record.content


def read(conn: Connection, tenant: UUID, execution: UUID) -> dict[str, Any]:
    row = (
        conn.execute(
            text("SELECT * FROM execbound.executions WHERE tenant_id=:t AND execution_id=:e"),
            {"t": tenant, "e": execution},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ExecutionError("NOT_FOUND")
    return dict(row)


def approval_row(conn: Connection, row: dict[str, Any]) -> dict[str, Any] | None:
    result = (
        conn.execute(
            text("SELECT * FROM execbound.approvals WHERE tenant_id=:t AND execution_id=:e"),
            {"t": row["tenant_id"], "e": row["execution_id"]},
        )
        .mappings()
        .one_or_none()
    )
    return dict(result) if result is not None else None


def denial_category(payload: Mapping[str, Any]) -> DenialCategory:
    """What a denied agent may be told of why, from its DENIED transition's recorded codes.

    Admission records a busy target alone, as `reason` `RESOURCE_BUSY`, and only after the
    policy decision allowed the request; the policy records its denials as `reasons`, where a
    shared limit is `HARD_LIMIT:<rule id>` and may sit beside a deny rule's `NOT_AUTHORIZED` or
    a context failure. `limit` is any recorded limit, whatever sits beside it:
    `policy/evaluate.py` records every applicable spent limit whatever the policy decided,
    so `limit` carries no per-target verdict, where a rule that needed every code to be a
    limit would have told `limit` from `withheld` exactly as the policy told an allowed
    target from a denied one. Everything else, a reviewer's refusal included, is `withheld`.
    The category names none of the codes.
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
    return "withheld"


def _denial(conn: Connection, row: dict[str, Any]) -> DenialCategory:
    """The category of a DENIED row, read from the one transition that recorded it.

    DENIED is terminal, so the row has exactly one; one read for a denial and none for any
    other state. A row whose transition cannot be found is told nothing more than withheld.
    """
    payload = conn.execute(
        text(
            "SELECT payload FROM execbound.execution_events "
            "WHERE tenant_id=:t AND execution_id=:e AND to_state='DENIED'"
        ),
        {"t": row["tenant_id"], "e": row["execution_id"]},
    ).scalar_one_or_none()
    return denial_category(payload) if isinstance(payload, dict) else "withheld"


def view(conn: Connection, row: dict[str, Any]) -> ExecutionView:
    approval = approval_row(conn, row)
    observed = None
    if row["state"] == "OBSERVED":
        result = row.get("result") or {}
        observed = ObservedResult.model_validate_json(canonical_json(result["observed"]))
    return ExecutionView(
        request_ref=f"EB-{row['request_number']}",
        execution_id=row["execution_id"],
        state=row["state"],
        plan_hash=row["plan_hash"],
        approval_id=approval["approval_id"] if approval else None,
        approval_state=approval["state"] if approval else None,
        observed=observed,
        denial=_denial(conn, row) if row["state"] == "DENIED" else None,
    )


def frozen(row: dict[str, Any]) -> ResolvedRequest:
    return ResolvedRequest.model_validate_json(canonical_json(row["frozen"]))


def command(row: dict[str, Any]) -> DispatchCommand:
    return DispatchCommand(
        execution_id=row["execution_id"],
        canonical_target_id=row["canonical_target_id"],
        operation_id=row["operation_id"],
        intent_hash=row["intent_hash"],
        plan_hash=row["plan_hash"],
        frozen=frozen(row),
    )


def event(
    conn: Connection,
    row: dict[str, Any],
    actor: UUID,
    before: str | None,
    after: str,
    clock: Clock,
    payload: dict[str, Any],
    *,
    semantic_time: datetime | None = None,
) -> None:
    observed = now(clock) if semantic_time is None else semantic_time
    payload = {**payload, "replay": {"version": 1, "semantic_time": observed.isoformat()}}
    if row.get("request_number") is not None:
        payload["request_ref"] = f"EB-{row['request_number']}"
    external_case = row["frozen"].get("request", {}).get("external_case")
    if before is None and external_case is not None:
        payload["external_case"] = external_case
    conn.execute(
        text("""
        INSERT INTO execbound.execution_events
          (tenant_id,event_id,execution_id,actor_id,from_state,to_state,created_at,payload)
        VALUES (:t,:v,:e,:a,:b,:s,:n,CAST(:p AS jsonb))
    """),
        {
            "t": row["tenant_id"],
            "v": uuid4(),
            "e": row["execution_id"],
            "a": actor,
            "b": before,
            "s": after,
            "n": observed,
            "p": canonical_json(payload),
        },
    )
    append_event(
        conn,
        row["tenant_id"],
        actor,
        "execution.transition",
        {
            "execution_id": str(row["execution_id"]),
            "from_state": before,
            "to_state": after,
            "intent_hash": row["intent_hash"],
            "plan_hash": row["plan_hash"],
            "operation_id": str(row["operation_id"]),
            **payload,
        },
    )


def transition(
    conn: Connection,
    row: dict[str, Any],
    actor: UUID,
    state: str,
    clock: Clock,
    *,
    semantic_time: datetime | None = None,
    **payload: Any,
) -> None:
    before = row["state"]
    if not transition_allowed(before, state):
        raise ExecutionError("INVALID_STATE")
    observed = now(clock) if semantic_time is None else semantic_time
    conn.execute(
        text(
            "UPDATE execbound.executions SET state=:s,changed_at=:n "
            "WHERE tenant_id=:t AND execution_id=:e"
        ),
        {"s": state, "n": observed, "t": row["tenant_id"], "e": row["execution_id"]},
    )
    event(conn, row, actor, before, state, clock, payload, semantic_time=observed)
    row["state"] = state


def approval_state(
    conn: Connection,
    row: dict[str, Any],
    approval: dict[str, Any],
    actor: UUID,
    state: str,
    clock: Clock,
    *,
    comment: str | None = None,
) -> None:
    conn.execute(
        text("UPDATE execbound.approvals SET state=:s WHERE tenant_id=:t AND approval_id=:a"),
        {"s": state, "t": row["tenant_id"], "a": approval["approval_id"]},
    )
    approvers = approval_decisions(conn, row["tenant_id"], approval["approval_id"])
    payload: dict[str, Any] = {
        "execution_id": str(row["execution_id"]),
        "approval_id": str(approval["approval_id"]),
        "from_state": approval["state"],
        "to_state": state,
        "plan_hash": row["plan_hash"],
        "binding": approval_binding(approval, approvers),
        "replay": {"version": 1, "semantic_time": now(clock).isoformat()},
    }
    if comment is not None:
        # A reviewer's bounded note; present only when one was given, so every
        # other transition payload is byte-identical to before.
        payload["comment"] = comment
    append_event(conn, row["tenant_id"], actor, "approval.transition", payload)
    approval["state"] = state


def approval_decisions(conn: Connection, tenant: UUID, approval_id: UUID) -> list[dict[str, Any]]:
    """Every recorded decision on an approval, oldest first; one per distinct principal."""
    rows = conn.execute(
        text(
            "SELECT principal_id, credential_id, decision, decided_at "
            "FROM execbound.approval_decisions WHERE tenant_id=:t AND approval_id=:a "
            "ORDER BY decided_at, principal_id"
        ),
        {"t": tenant, "a": approval_id},
    ).mappings()
    return [dict(row) for row in rows]


def record_decision(
    conn: Connection,
    tenant: UUID,
    approval: dict[str, Any],
    human: Identity,
    decision: str,
    now: datetime,
) -> list[dict[str, Any]]:
    """Insert one decision row; a second decision by the same principal is refused."""
    existing = approval_decisions(conn, tenant, approval["approval_id"])
    if any(row["principal_id"] == human.principal_id for row in existing):
        raise ExecutionError("INVALID_STATE")
    conn.execute(
        text(
            "INSERT INTO execbound.approval_decisions "
            "(tenant_id, approval_id, principal_id, credential_id, decision, decided_at) "
            "VALUES (:t, :a, :p, :c, :d, :now)"
        ),
        {
            "t": tenant,
            "a": approval["approval_id"],
            "p": human.principal_id,
            "c": human.credential_id,
            "d": decision,
            "now": now,
        },
    )
    return approval_decisions(conn, tenant, approval["approval_id"])


def approval_binding(
    approval: dict[str, Any], approvers: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Retain the authority required by a future immutable audit export/replay."""
    return {
        "required_approvers": int(approval.get("required_approvers", 1) or 1),
        "approvers": [
            {
                "principal_id": str(row["principal_id"]),
                "credential_id": str(row["credential_id"]),
                "decision": row["decision"],
                "decided_at": row["decided_at"].astimezone(UTC).isoformat(),
            }
            for row in (approvers or [])
        ],
        "approval_id": str(approval["approval_id"]),
        "principal_id": str(approval["principal_id"]),
        "bundle_id": str(approval["bundle_id"]),
        "plan_hash": approval["plan_hash"],
        "obligation_ids": approval["obligation_ids"],
        "expires_at": approval["expires_at"].astimezone(UTC).isoformat(),
        "created_at": approval["created_at"].astimezone(UTC).isoformat(),
        "decided_at": approval["decided_at"].astimezone(UTC).isoformat()
        if approval.get("decided_at")
        else None,
        "decided_by": str(approval["decided_by"]) if approval["decided_by"] else None,
        "decided_credential_id": str(approval["decided_credential_id"])
        if approval["decided_credential_id"]
        else None,
    }


def memberships(conn: Connection, tenant: UUID, principal: UUID) -> tuple[UUID, ...]:
    """The principal's groups as read inside the fence; owner-provisioned, never from input."""
    rows = (
        conn.execute(
            text(
                "SELECT group_id FROM execbound.principal_group_members "
                "WHERE tenant_id=:t AND principal_id=:p ORDER BY group_id LIMIT :bound"
            ),
            {"t": tenant, "p": principal, "bound": MAX_GROUPS + 1},
        )
        .scalars()
        .all()
    )
    if len(rows) > MAX_GROUPS:
        raise ExecutionError("INVALID_CONFIGURATION")
    return tuple(rows)


def space_of(conn: Connection, identity: Identity) -> UUID | None:
    """The space of the principal a decision is being made for; None for a human.

    Read inside the fence from the principal's own row: no request field, header or
    credential attribute names one.
    """
    if identity.kind != "AGENT":
        return None
    return agent_space(conn, identity.tenant_id, identity.principal_id)


def impact_attributes(
    frozen: ResolvedRequest, groups: tuple[UUID, ...], space: UUID | None = None
) -> dict[str, Any]:
    """The retained attributes a scope counts over; written once, never updated.

    The space is the agent's own, read inside the fence at reservation, exactly as the
    memberships are: moving an agent later must never rewrite what past impact counted
    for.
    """
    return {
        "account": frozen.intent.account_id,
        "groups": canonical_json([str(group) for group in groups]),
        "facts": canonical_json(scalar_facts(frozen)),
        "space": space,
    }


def usage(
    conn: Connection,
    identity: Identity,
    bundle: BundleContent,
    clock: Clock,
    *,
    frozen: ResolvedRequest,
    observed: bool = False,
) -> UsageSnapshot:
    """Retained impact for the limits, each rule counted in its own scope.

    ``observed`` adds the assumed-executed projection: observed decisions reserve nothing,
    so only an observe-mode evaluation counts them, as if each had executed when it was
    recorded, and an enforced evaluation never sees them. Membership, the account and the
    facts of a retained row are read from the row itself, never from current inventory
    or current membership, so a later provisioning change never rewrites history. A row
    without an attribute (recorded before this scope existed) never counts toward it.
    """
    measured_at = now(clock)
    groups = memberships(conn, identity.tenant_id, identity.principal_id)
    space = space_of(conn, identity)
    counts = []
    for rule in bundle.limits:
        # Python datetime bounds are narrower than the accepted integer rule domain.
        try:
            start = measured_at - timedelta(seconds=rule.window_seconds)
        except OverflowError:
            start = datetime.min.replace(tzinfo=UTC)
        selector = rule.selector
        row = (
            conn.execute(
                text("""
            SELECT count(*) FILTER (WHERE state='CONFIRMED' AND confirmed_at>:start
                                           AND confirmed_at<=:now) AS confirmed,
                   count(*) FILTER (WHERE state='UNRESOLVED') AS unresolved,
                   count(*) FILTER (WHERE state='OBSERVED' AND created_at>:start
                                           AND created_at<=:now) AS projected,
                   count(*) FILTER (WHERE confirmed_at>:now) AS future
            FROM execbound.execution_impact WHERE tenant_id=:t
              AND action = ANY(CAST(:actions AS text[]))
              AND (:scope<>'principal' OR principal_id=:p)
              AND (:scope<>'group' OR group_ids @> CAST(:group AS jsonb))
              AND (:scope<>'account' OR account_id=CAST(:account AS uuid))
              AND (:scope<>'space' OR space_id=CAST(:space AS uuid))
              AND (:scope<>'selector' OR facts -> CAST(:fact AS text) = CAST(:value AS jsonb))
              AND (:budget='total' OR NOT approved)
        """),
                {
                    "t": identity.tenant_id,
                    "p": identity.principal_id,
                    "actions": list(rule.action_names),
                    "scope": rule.scope,
                    "group": canonical_json([str(rule.group_id)]) if rule.group_id else None,
                    "account": str(rule.account_id) if rule.account_id else None,
                    "space": str(rule.space_id) if rule.space_id else None,
                    "fact": selector.fact if selector else None,
                    "value": canonical_json(selector.equals) if selector else None,
                    "budget": rule.budget,
                    "start": start,
                    "now": measured_at,
                },
            )
            .mappings()
            .one()
        )
        if row["future"]:
            raise ExecutionError("INVALID_CLOCK")
        counts.append(
            ProjectedUsage(
                rule_id=rule.rule_id,
                confirmed_targets=row["confirmed"] + (row["projected"] if observed else 0),
                unresolved_targets=row["unresolved"],
            )
        )
    return UsageSnapshot(
        tenant_id=identity.tenant_id,
        principal_id=identity.principal_id,
        bundle_id=bundle.bundle_id,
        account_id=frozen.intent.account_id,
        groups=groups,
        space_id=space,
        counts=tuple(counts),
    )


def review_identity_check(conn: Connection, human: Identity, clock: Clock) -> None:
    """Authenticate the person; the action/target assignment grants review authority."""
    if human.kind not in {"HUMAN_APPROVER", "ADMIN"}:
        raise ExecutionError("INVALID_IDENTITY")
    identity_check(conn, human, clock, human.kind)


def persisted_reviewer(
    conn: Connection, tenant: UUID, principal: UUID, credential: UUID, clock: Clock
) -> Identity:
    kind = conn.execute(
        text(
            "SELECT execbound.access_effective_kind(principal_id) "
            "FROM execbound.principals WHERE tenant_id=:t AND principal_id=:p"
        ),
        {"t": tenant, "p": principal},
    ).scalar_one_or_none()
    if kind not in {"HUMAN_APPROVER", "ADMIN"}:
        raise ExecutionError("INVALID_IDENTITY")
    return persisted_identity(conn, tenant, principal, credential, kind, clock)


def scope_check(conn: Connection, human: Identity, row: dict[str, Any], clock: Clock) -> None:
    review_identity_check(conn, human, clock)
    allowed = conn.execute(
        text(
            "SELECT 1 FROM execbound.effective_approval_scopes WHERE tenant_id=:t "
            "AND approver_id=:p AND canonical_target_id=:c "
            "AND action=:action AND space_id=:space AND active"
        ),
        {
            "t": row["tenant_id"],
            "p": human.principal_id,
            "c": row["canonical_target_id"],
            "action": frozen(row).intent.action,
            "space": row["space_id"],
        },
    ).scalar_one_or_none()
    if (
        row["tenant_id"] != human.tenant_id
        or allowed is None
        or not principal_allows(conn, human.tenant_id, human.principal_id, row["space_id"])
    ):
        raise ExecutionError("NOT_FOUND")


def persisted_identity(
    conn: Connection, tenant: UUID, principal: UUID, credential: UUID, kind: str, clock: Clock
) -> Identity:
    expiry = conn.execute(
        text(
            "SELECT expires_at FROM execbound.credentials "
            "WHERE tenant_id=:t AND principal_id=:p AND credential_id=:c"
        ),
        {"t": tenant, "p": principal, "c": credential},
    ).scalar_one_or_none()
    if expiry is None or kind not in {"AGENT", "HUMAN_APPROVER", "ADMIN"}:
        raise ExecutionError("INVALID_IDENTITY")
    identity = Identity(tenant, principal, credential, kind, expiry)  # type: ignore[arg-type]
    identity_check(conn, identity, clock, kind)
    return identity


def verify_approval(
    conn: Connection,
    row: dict[str, Any],
    approval: dict[str, Any],
    obligations: tuple[str, ...],
    clock: Clock,
) -> VerifiedApproval:
    if (
        approval["state"] != "APPROVED"
        or now(clock) >= approval["expires_at"]
        or approval["tenant_id"] != row["tenant_id"]
        or approval["principal_id"] != row["principal_id"]
        or approval["plan_hash"] != row["plan_hash"]
        or approval["bundle_id"] != row["bundle_id"]
        or tuple(approval["obligation_ids"]) != obligations
    ):
        raise ExecutionError("INVALID_APPROVAL")
    required = int(approval.get("required_approvers", 1) or 1)
    decisions = approval_decisions(conn, row["tenant_id"], approval["approval_id"])
    if decisions or required > 1:
        # Every counted approver must still be a current, assigned human at consumption.
        approving = [d for d in decisions if d["decision"] == "APPROVE"]
        if len(approving) != required or len(approving) != len(decisions):
            raise ExecutionError("INVALID_APPROVAL")
        for decided in approving:
            human = persisted_reviewer(
                conn,
                row["tenant_id"],
                decided["principal_id"],
                decided["credential_id"],
                clock,
            )
            scope_check(conn, human, row, clock)
    else:
        # Approvals recorded before decision rows existed keep the single-approver check.
        human = persisted_reviewer(
            conn,
            row["tenant_id"],
            approval["decided_by"],
            approval["decided_credential_id"],
            clock,
        )
        scope_check(conn, human, row, clock)
    return VerifiedApproval(
        approval["approval_id"],
        row["tenant_id"],
        row["principal_id"],
        row["bundle_id"],
        row["plan_hash"],
        obligations,
        approval["expires_at"],
    )


def ticket_digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def bundle(conn: Connection, tenant: UUID, bundle_id: UUID) -> BundleContent:
    """Read the immutable bundle an execution was frozen under."""
    return _read(conn, tenant, bundle_id, lock=False).content


def approval_deadline(conn: Connection, tenant: UUID) -> int | None:
    """The tenant's approval deadline in seconds, or None when it is off.

    Read inside the fence like the mode, so a change is ordered against every admission.
    A tenant without a control row has the default every tenant started with.
    """
    row = conn.execute(
        text(
            "SELECT approval_deadline_seconds FROM execbound.tenant_policy_control "
            "WHERE tenant_id=:t"
        ),
        {"t": tenant},
    ).one_or_none()
    if row is None:
        return DEFAULT_APPROVAL_DEADLINE
    return None if row[0] is None else int(row[0])


def approval_expiry(
    conn: Connection, tenant: UUID, valid_until: datetime, now: datetime
) -> datetime:
    """When a new approval expires: the plan's validity, capped by the tenant's deadline.

    Off means the plan clock alone; nothing here can outlive the frozen plan.
    """
    seconds = approval_deadline(conn, tenant)
    if seconds is None:
        return valid_until
    return min(valid_until, now + timedelta(seconds=seconds))


def enforcement_mode(conn: Connection, tenant: UUID) -> str:
    """The tenant's mode; admission reads it inside the fence, ordered against every change."""
    mode = conn.execute(
        text("SELECT enforcement_mode FROM execbound.tenant_policy_control WHERE tenant_id=:t"),
        {"t": tenant},
    ).scalar_one_or_none()
    return "ENFORCE" if mode is None else str(mode)


def checkpoint_mapping(frozen: ResolvedRequest, bundle: BundleContent) -> MappingRef | None:
    """The bundle's mapping for this plan when the operation is externally executed.

    Gate is owner-provisioned bundle content: no request field, header, credential
    attribute or client capability reaches this, and the caller cannot tell the kernel
    that its operation is externally executed. The evaluator checks the same mapping's
    account and versions against the frozen plan and denies INVALID_BUNDLE otherwise, so a
    grant never describes an operation the decision did not authorize.
    """
    for mapping in bundle.mappings:
        if mapping.operation_ref == frozen.request.operation_ref and mapping.external_executor:
            return mapping
    return None


def outstanding_grants(conn: Connection, tenant: UUID, principal: UUID) -> int:
    """Checkpoint grants this principal holds that nothing has settled.

    The unsettled set, not one state. The reservation that charges every limit scope is the
    UNRESOLVED impact row, which `usage` counts with no state filter, and the canonical
    claim is held until something releases it; neither ends when a grant leaves
    DISPATCH_COMMITTED for INDETERMINATE, which is where an asserted non-execution and the
    unreported sweep both put it deliberately. Counting one state would free a cap slot for
    a grant that is still charging and still holding its target, so the cap would stop
    binding in exactly the case it exists for.

    A report window is written once, at admission, and only for an operation the active
    bundle declared externally executed, so it marks a checkpoint and an ordinary dispatch
    never carries one. It is written before the decision, so it is paired with a state
    here: a DENIED row carries a window and is no grant.
    """
    return int(
        conn.execute(
            text(
                "SELECT count(*) FROM execbound.executions WHERE tenant_id=:t "
                "AND principal_id=:p AND state = ANY(CAST(:states AS text[])) "
                "AND report_expires_at IS NOT NULL"
            ),
            {"t": tenant, "p": principal, "states": list(UNSETTLED)},
        ).scalar_one()
    )


def executor_keys(conn: Connection, tenant: UUID) -> tuple[dict[str, Any], ...]:
    """Every executor key an administrator registered for the tenant, revoked ones included.

    A key retired after a grant was issued still attests that grant, one retired before it
    never does, and one registered after it never does either, so the ring a verifier
    weighs is every row and both of the row's own instants are what decide. The revocation
    reason is read with them because a key revoked as compromised attests nothing at all,
    whatever those instants say, and a row that arrived here without its reason would be
    weighed as an ordinary retirement. Rotation adds rows and rewrites none, so this grows
    with the tenant's rotations. The runtime holds SELECT on this table and nothing more,
    and the key material here is a public key: no signing material for this protocol is at
    rest.

    This is the one read behind both questions the composition boundary answers about a
    ring — whether a grant about to be issued could be attested, and whether this record
    attests one — so the two cannot come to disagree about which rows they are asking
    about. What a row must satisfy to be usable is decided there, over the model, and not
    here: the two shapes, the revocation at or after the registration and the reason
    present exactly when the row is revoked are the columns' own CHECK constraints, and
    what is left to the model is whether the material is a public key anybody could sign
    for, which no constraint can express.
    """
    rows = conn.execute(
        text(
            "SELECT key_id, algorithm, public_key, created_at, revoked_at, revocation_reason "
            "FROM execbound.executor_keys WHERE tenant_id=:t ORDER BY key_id"
        ),
        {"t": tenant},
    ).mappings()
    return tuple(dict(row) for row in rows)


def observed_by(
    conn: Connection, tenant: UUID, bundle: BundleContent, operation_ref: str
) -> str | None:
    """Why a request is only observed: the tenant's mode, the frozen mapping, or None."""
    if enforcement_mode(conn, tenant) == "OBSERVE":
        return "tenant"
    if any(m.operation_ref == operation_ref and m.observe_only for m in bundle.mappings):
        return "mapping"
    return None


def stop(conn: Connection, tenant: UUID) -> StopState | None:
    """The tenant's active emergency stop. Writers read it inside the fence, so activation
    and every admission, decision or dispatch attempt are totally ordered."""
    row = (
        conn.execute(
            text(
                "SELECT stop_id, stopped_at, stopped_by, stop_reason "
                "FROM execbound.tenant_policy_control WHERE tenant_id=:t"
            ),
            {"t": tenant},
        )
        .mappings()
        .one_or_none()
    )
    if row is None or row["stop_id"] is None:
        return None
    return StopState(row["stop_id"], row["stopped_at"], row["stopped_by"], row["stop_reason"])
