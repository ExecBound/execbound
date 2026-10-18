# SPDX-License-Identifier: AGPL-3.0-only
"""Idempotent admission: one committed dispatch claim per intent, and the agent's read."""

import secrets
from collections.abc import Sequence
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound import approval_routing
from execbound.audit import append_event, canonical_json
from execbound.contracts import PRODUCTION_CATALOG, Catalog
from execbound.db import Database
from execbound.execution import store
from execbound.execution.authority import _decision, _rejection, _stale, resolution_reason
from execbound.execution.models import (
    ACT_WINDOW,
    MAX_GRANTS,
    NO_PRECONDITIONS,
    REPORT_WINDOW,
    Admission,
    AttestableRing,
    CheckpointBinding,
    CheckpointGrant,
    DispatchTicket,
    ExecutionError,
    ExecutionView,
    ObservedResult,
    PreconditionClass,
    PreconditionConfig,
    wire_hash,
)
from execbound.execution.offered import bundle_operations
from execbound.execution.snapshot import attest_snapshot, resolve_snapshot
from execbound.identity import Identity
from execbound.notifications import Destination, queue_notifications
from execbound.policy.models import BundleContent, MappingRef, PolicyEvaluation, UsageSnapshot
from execbound.requests import ActionRequest, parse_request
from execbound.resolution.models import Clock, ResolvedRequest, SystemClock, intent_hash, plan_hash
from execbound.resolution.registry import ResolutionError
from execbound.secrets import find_secrets
from execbound.signals.resolve import SignalScope
from execbound.spaces import agent_space, is_archived


def _key(conn: Connection, identity: Identity, request: ActionRequest, row: dict[str, Any]) -> None:
    conn.execute(
        text("""
        INSERT INTO execbound.execution_keys
          (tenant_id,principal_id,idempotency_key,intent_hash,wire_hash,execution_id)
        VALUES (:t,:p,:k,:i,:w,:e) ON CONFLICT (tenant_id,principal_id,idempotency_key) DO NOTHING
    """),
        {
            "t": identity.tenant_id,
            "p": identity.principal_id,
            "k": request.idempotency_key,
            "i": row["intent_hash"],
            "w": wire_hash(request),
            "e": row["execution_id"],
        },
    )


def _precondition_class(
    preconditions: PreconditionConfig, resolved: ResolvedRequest
) -> PreconditionClass:
    """What the vendor the executor calls will do with the frozen expected version.

    Read from deployment configuration keyed by the provider binding the grant names, and
    from the frozen plan's own provider and provider operation rather than from anything
    the caller sent. A binding this deployment has not declared answers the class that
    promises nothing, so a missing declaration is honest rather than silent.

    Nothing here checks the configuration against the catalog: a declaration naming a
    binding no catalog entry binds is refused by ``Runtime`` construction, which is where
    the catalog and the configuration are held together, not by ``admit``.
    """
    return preconditions.declared(resolved.intent.provider, resolved.intent.provider_operation)


def _grant(
    conn: Connection,
    identity: Identity,
    row: dict[str, Any],
    resolved: ResolvedRequest,
    secret: str | None,
    clock: Clock,
    preconditions: PreconditionConfig,
) -> CheckpointGrant:
    """Describe the one act the executor may perform and store the digest that settles it.

    A secret is minted once per execution, by the admission that issued the grant, and is
    kept nowhere: only its digest is retained, in the column a dispatch ticket's digest
    occupies, because for an externally executed operation there is no dispatch the secret
    could authorize and settlement is all it opens. ``secret`` is None for every later
    answer, which describes the same act again and writes nothing: rewriting the digest
    would hand settlement authority to whoever asked last, which is any second live
    credential of the principal and any replay of the first request.

    The first answer also records the class it was issued under, in
    ``executions.precondition_class`` beside the digest, because the class decides what the
    outcome route admits as evidence: a grant under ``UNAVAILABLE`` carries no provider
    command, so the outcome route takes no journal for it (``outcomes._journal_admitted``).
    A later answer describes the grant under that recorded class rather than the declaration
    in force when it is asked, so a redeployment that changes the declaration never shows a
    retry a version or a provider command the grant was not issued with, and it writes
    nothing. A grant an earlier release issued recorded no class, and a later answer to it is
    described under the declaration in force, as every later answer was.
    """
    regranted = secret is None
    recorded = row.get("precondition_class")
    precondition = (
        recorded
        if regranted and recorded is not None
        else _precondition_class(preconditions, resolved)
    )
    command = store.command(row)
    grant = CheckpointGrant(
        operation_id=row["operation_id"],
        provider=resolved.intent.provider,
        provider_operation=resolved.intent.provider_operation,
        resource_provider_id=resolved.resource_provider_id,
        action=resolved.intent.action,
        arguments=resolved.intent.arguments,
        precondition_class=precondition,
        expected_version=None if precondition == "UNAVAILABLE" else resolved.resource_version,
        act_expires_at=min(
            store.now(clock) + ACT_WINDOW, resolved.valid_until, identity.expires_at
        ),
        report_expires_at=row["report_expires_at"],
        regranted=regranted,
        report_secret=secret,
        binding=CheckpointBinding(
            operation_id=command.operation_id,
            account_id=resolved.intent.account_id,
            intent_hash=command.intent_hash,
            plan_hash=command.plan_hash,
        ),
        command=command,
    )
    if secret is not None:
        # The column is the one the dispatch path records its own class in, and the runtime
        # already holds UPDATE on it (migration 0032). No page reads it for a grant: the
        # record shows an issued grant no class and points at its checkpoint_granted events,
        # which retain the class each answer carried and stay the record that cannot be
        # revised.
        conn.execute(
            text(
                "UPDATE execbound.executions SET owner_hash=:h, precondition_class=:c "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {
                "h": store.ticket_digest(secret),
                "c": precondition,
                "t": row["tenant_id"],
                "e": row["execution_id"],
            },
        )
        row["precondition_class"] = precondition
    # An ordinary capture in the tenant's hash chain, carrying identifiers and deadlines
    # and never the secret. It changes no decision, reservation or budget of its own.
    append_event(
        conn,
        row["tenant_id"],
        identity.principal_id,
        "execution.checkpoint_granted",
        {
            "execution_id": str(row["execution_id"]),
            "operation_id": str(row["operation_id"]),
            "plan_hash": row["plan_hash"],
            "precondition_class": precondition,
            "act_expires_at": grant.act_expires_at.isoformat(),
            "report_expires_at": grant.report_expires_at.isoformat(),
            "regranted": regranted,
        },
    )
    return grant


def _regrant(
    conn: Connection,
    identity: Identity,
    row: dict[str, Any],
    clock: Clock,
    preconditions: PreconditionConfig,
) -> CheckpointGrant | None:
    """Re-answer a committed grant, describing the same act and minting nothing.

    The frozen plan's validity is the only bound: a re-grant describes the same act under
    the same decision, so once the plan has expired the caller's recourse is a new request.
    The report window is not tested here because it never closes first while a retry is
    possible, which test_a_regrant_cannot_outlive_the_report_window pins; its enforcement
    point is the outcome route. The active bundle is deliberately not re-read, which
    test_a_retry_after_the_owner_stops_externally_executing_describes_the_same_grant pins:
    an issued grant cannot be recalled, and the re-answer confers nothing new.
    """
    resolved = store.frozen(row)
    if store.now(clock) >= resolved.valid_until:
        return None
    return _grant(conn, identity, row, resolved, None, clock, preconditions)


def _answer(
    conn: Connection,
    identity: Identity,
    row: dict[str, Any],
    clock: Clock,
    preconditions: PreconditionConfig,
) -> Admission:
    """The idempotent answer for an execution admission has already decided.

    A committed checkpoint is the one case that is not a bare view: it answers with the
    same grant described again, carrying no secret and writing nothing, so a caller whose
    response was lost learns what it was told it may do rather than stranding a reservation
    it never heard about, and the holder of the one secret this execution ever had keeps it.

    The report window is what says the execution is a checkpoint, and the state test is
    exactly DISPATCH_COMMITTED: the window is written before the decision, so a DENIED,
    stale or settled row carries one too, and anything weaker would hand a caller a grant
    for an execution that was refused, or that a report or the recovery sweep has settled.
    """
    store.demo_check(conn, identity.tenant_id, store.frozen(row).request.synthetic_demo)
    if row["state"] == "DISPATCH_COMMITTED" and row["report_expires_at"] is not None:
        # A tenant switched to OBSERVE grants nothing, including a second answer for a
        # grant issued under enforcement: the mode is a tenant property and it wins.
        # This is the shape the emergency stop already has one level up. The tenant mode is
        # the whole of observed_by for a checkpoint, because MappingRef's single_placement
        # refuses observe_only beside external_executor, so no checkpoint row can have been
        # observed by its mapping.
        if store.enforcement_mode(conn, row["tenant_id"]) != "OBSERVE":
            grant = _regrant(conn, identity, row, clock, preconditions)
            if grant is not None:
                return Admission(store.view(conn, row).model_copy(update={"checkpoint": grant}))
    return Admission(store.view(conn, row))


def _placement(
    frozen: ResolvedRequest,
    bundle: BundleContent,
    available_accounts: frozenset[tuple[UUID, str]] | None,
) -> MappingRef | None:
    """The bundle's externally executed mapping for this plan, once the deployment agrees.

    Read from owner-provisioned bundle content, never from the request: no field, header,
    credential attribute or client capability moves an operation into or out of Gate.

    An externally executed operation has no connector by construction: the executor holds
    the vendor credential and ExecBound will send nothing. Both halves are refusals, and
    the pairing is the premise the external checkpoint rests on. A Gate mapping on a
    connected account is a deployment that contradicts its own bundle, and admitting it
    would leave a checkpoint the connector paths treat as a lost dispatch: reconciliation
    would settle it FAILED_NOT_EXECUTED and release its claim on cancellation evidence with
    no executor report, which is the refund on absent evidence the contract forbids, and the
    recovery run would sweep it inside its report window. INVALID_BUNDLE is the code the
    kernel already uses when the active bundle cannot authorize the request, and it tells
    the caller nothing about the tenant's connector inventory.
    """
    gate_mapping = store.checkpoint_mapping(frozen, bundle)
    if available_accounts is not None:
        connected = (frozen.intent.account_id, frozen.intent.provider) in available_accounts
        if gate_mapping is None and not connected:
            raise ExecutionError("CONNECTOR_UNAVAILABLE")
        if gate_mapping is not None and connected:
            raise ExecutionError("INVALID_BUNDLE")
    return gate_mapping


def _account_in_space(conn: Connection, tenant: UUID, space: UUID, account: UUID) -> None:
    """Refuse a mapping whose connector account belongs to another space.

    What refuses a new request, or a changed one under a known key, is the offered check
    (`execution.offered`), before resolution and by the same rule. This stays as defence in
    depth for a request held for approval whose agent or account has since left the space:
    an unchanged re-send skips the offered check and meets this instead. An account offered
    tenant-wide is usable by every space of the tenant and owned, still, by one. Audited as
    `INVALID_CONFIGURATION`, answered as `EXECUTION_UNAVAILABLE` (`AUDIT_ONLY`), and refused
    before any provider contact.
    """
    allowed = conn.execute(
        text(
            "SELECT 1 FROM execbound.connector_accounts WHERE tenant_id=:t AND account_id=:a "
            "AND (space_id=:s OR offered_tenant_wide)"
        ),
        {"t": tenant, "a": account, "s": space},
    ).scalar_one_or_none()
    if allowed is None:
        raise ExecutionError("INVALID_CONFIGURATION")


def _attestable(conn: Connection, tenant: UUID, attestable: AttestableRing | None) -> None:
    """Refuse to issue a grant the tenant's key ring could not attest.

    Bundle validation already refuses an externally executed mapping for a tenant with no
    registered key, and `administration._keep_attestable` refuses to retire the last one
    while such a bundle is active, so this state used to be unreachable. Reporting a key
    as compromised deliberately bypasses that second guard — refusing to cut off a stolen
    key because it is the last one would be a refusal to perform the security action — so
    the state is reachable now and admission is what makes it safe. Admission reads the
    active bundle through `store.active_bundle`, which does not re-run component
    validation, so without this a tenant whose only key was just cut off would keep
    issuing grants nothing could attest and no administrator could settle.

    The question goes to the composition boundary, which is where the ring is loaded and
    therefore the only place that knows what a usable one is: `runtime.attestable_ring`
    answers it from the same rows and the same loader `runtime.executor_verifier` weighs a
    report against. Asking in SQL instead asked a weaker question — any row with no
    revocation — and a live row the ring loader refuses is not a key, so a tenant holding
    one was granted normally and then had no settlement path at all. A deployment that
    supplied no answer issues no grants, because the kernel cannot check the ring itself
    and a grant nothing can attest is the state this refusal exists for.

    The refusal is only for an operation that would be granted, and it runs where the cap
    on outstanding grants runs: after the decision, so a request a hard denial would
    refuse is still recorded as DENIED, and before anything is reserved, so the whole
    attempt rolls back leaving no execution, no reservation and no claim. An observing
    tenant reserves nothing and grants nothing, so it never reaches here and keeps its
    OBSERVED view, and an existing grant is re-described without asking, because a grant
    already issued cannot be recalled — docs/CHECKPOINT.md says as much of the
    emergency stop, and a key ring change is no stronger. INVALID_BUNDLE is the code the
    kernel already raises when the active bundle cannot authorize the request in the
    deployment it is running in.
    """
    if attestable is None or not attestable(conn, tenant):
        raise ExecutionError("INVALID_BUNDLE")


# Codes admission audits but never answers to an agent. `INVALID_CONFIGURATION` says another
# space's account is behind an operation, or that the agent's own group memberships are too
# many; either would tell the agent something about configuration it cannot see.
AUDIT_ONLY = frozenset({"INVALID_CONFIGURATION"})


def _admit(
    conn: Connection,
    identity: Identity,
    request: ActionRequest,
    clock: Clock,
    available_accounts: frozenset[tuple[UUID, str]] | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
    notifications: Sequence[Destination] = (),
    preconditions: PreconditionConfig = NO_PRECONDITIONS,
    attestable: AttestableRing | None = None,
) -> Admission:
    store.identity_check(conn, identity, clock, "AGENT")
    # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
    store.fence(conn, identity.tenant_id, clock)
    store.identity_check(conn, identity, clock, "AGENT")
    store.demo_check(conn, identity.tenant_id, request.synthetic_demo)
    # The agent's own space, one column of a row already read. Nothing the caller sent
    # names it, and it is the space every later read and write here uses.
    space = agent_space(conn, identity.tenant_id, identity.principal_id)
    key = (
        conn.execute(
            text(
                "SELECT * FROM execbound.execution_keys WHERE tenant_id=:t "
                "AND principal_id=:p AND idempotency_key=:k"
            ),
            {"t": identity.tenant_id, "p": identity.principal_id, "k": request.idempotency_key},
        )
        .mappings()
        .one_or_none()
    )
    if store.stop(conn, identity.tenant_id) is not None:
        # An emergency stop starts nothing new. A known key answers with its current
        # view, untouched; anything else is refused before resolution or policy work.
        if key is None:
            raise ExecutionError("TENANT_STOPPED")
        stopped_row = store.read(conn, identity.tenant_id, key["execution_id"])
        return Admission(store.view(conn, stopped_row).model_copy(update={"tenant_stopped": True}))
    if is_archived(conn, identity.tenant_id, space):
        # "Takes no new work" has one meaning and is checked where the emergency stop is
        # checked: refused before any dispatch, audited, and answered in the stop's shape.
        # An archived space is still fully readable, and a known key answers with its
        # current view exactly as it does under the stop.
        if key is None:
            raise ExecutionError("SPACE_ARCHIVED")
        archived_row = store.read(conn, identity.tenant_id, key["execution_id"])
        return Admission(store.view(conn, archived_row).model_copy(update={"tenant_stopped": True}))
    resolved: ResolvedRequest | None = None
    row = None
    bundle: BundleContent | None = None
    if key:
        row = store.read(conn, identity.tenant_id, key["execution_id"])
        if key["wire_hash"] != wire_hash(request):
            # A changed request under a known key is resolved again, so it is checked against
            # what the space offers first, as a new one is (T1.17).
            bundle = store.active_bundle(conn, identity.tenant_id, space)
            bundle_operations(conn, identity.tenant_id, space, bundle, catalog=catalog).check(
                request.operation_ref
            )
            resolved, _ = resolve_snapshot(
                conn,
                identity,
                request,
                clock,
                settings=bundle.context_settings,
                catalog=catalog,
                signals=SignalScope(bundle.signal_mappings, space),
            )
            if key["intent_hash"] != intent_hash(resolved.intent):
                raise ExecutionError("IDEMPOTENCY_CONFLICT")
        if row["state"] != "PENDING_APPROVAL":
            return _answer(conn, identity, row, clock, preconditions)
    else:
        bundle = store.active_bundle(conn, identity.tenant_id, space)
        # What the space offers is read before arguments are validated or a target is read,
        # so an operation outside it is refused exactly as an unknown one is: the same
        # statements, the same answer and no record (T1.17). Its cause is audited.
        bundle_operations(conn, identity.tenant_id, space, bundle, catalog=catalog).check(
            request.operation_ref
        )
        resolved, canonical = resolve_snapshot(
            conn,
            identity,
            request,
            clock,
            settings=bundle.context_settings,
            catalog=catalog,
            signals=SignalScope(bundle.signal_mappings, space),
        )
        pending = conn.execute(
            text(
                "SELECT execution_id FROM execbound.executions "
                "WHERE tenant_id=:t AND principal_id=:p AND intent_hash=:i "
                "AND state IN ('ATTEMPTED','PENDING_APPROVAL','RESERVED',"
                "'DISPATCH_COMMITTED','INDETERMINATE')"
            ),
            {
                "t": identity.tenant_id,
                "p": identity.principal_id,
                "i": intent_hash(resolved.intent),
            },
        ).scalar_one_or_none()
        if pending is not None:
            row = store.read(conn, identity.tenant_id, pending)
            _key(conn, identity, request, row)
            if row["state"] != "PENDING_APPROVAL":
                return _answer(conn, identity, row, clock, preconditions)
    selected = resolved if row is None else store.frozen(row)
    assert selected is not None
    store.demo_check(conn, identity.tenant_id, selected.request.synthetic_demo)
    if bundle is None:
        bundle = store.active_bundle(conn, identity.tenant_id, space)
    _account_in_space(conn, identity.tenant_id, space, selected.intent.account_id)
    gate_mapping = _placement(selected, bundle, available_accounts)
    observing = store.observed_by(conn, identity.tenant_id, bundle, selected.request.operation_ref)
    if row is None:
        assert resolved is not None
        # The report window is carried by the row, written once here because nothing may
        # update it afterwards. An observing tenant grants nothing, so it gets none.
        # It is written before the decision, so a row that is then DENIED or goes stale
        # keeps an unused window: the column marks "this execution would be a checkpoint",
        # never "this grant is live". Every reader must pair it with a state, which the
        # sweep, the uncertain queue and the console's labels all do.
        report_expires_at = None
        if gate_mapping is not None and observing is None:
            report_expires_at = min(store.now(clock) + REPORT_WINDOW, identity.expires_at)
        row = {
            "tenant_id": identity.tenant_id,
            # All execution writers hold the tenant fence. The unique index guards
            # allocation too; runtime grants permit neither renumbering nor deletion.
            "request_number": conn.execute(
                text(
                    "SELECT coalesce(max(request_number), 0) + 1 FROM execbound.executions "
                    "WHERE tenant_id=:t"
                ),
                {"t": identity.tenant_id},
            ).scalar_one(),
            "execution_id": uuid4(),
            "principal_id": identity.principal_id,
            "credential_id": identity.credential_id,
            "intent_hash": intent_hash(resolved.intent),
            "wire_hash": wire_hash(request),
            "plan_hash": plan_hash(resolved, bundle.security_versions),
            "canonical_target_id": canonical,
            "bundle_id": bundle.bundle_id,
            "frozen": resolved.model_dump(mode="json"),
            "state": "ATTEMPTED",
            "operation_id": uuid4(),
            "report_expires_at": report_expires_at,
            "space_id": space,
        }
        conn.execute(
            text("""
            INSERT INTO execbound.executions
              (tenant_id,execution_id,principal_id,credential_id,intent_hash,wire_hash,plan_hash,
               canonical_target_id,bundle_id,frozen,state,created_at,changed_at,operation_id,
               report_expires_at,space_id,request_number)
            VALUES (:tenant_id,:execution_id,:principal_id,:credential_id,:intent_hash,:wire_hash,
                    :plan_hash,:canonical_target_id,:bundle_id,CAST(:frozen AS jsonb),:state,:n,:n,
                    :operation_id,:report_expires_at,:space_id,:request_number)
        """),
            {**row, "frozen": resolved.model_dump_json(), "n": store.now(clock)},
        )
        _key(conn, identity, request, row)
        store.event(
            conn,
            row,
            identity.principal_id,
            None,
            "ATTEMPTED",
            clock,
            {
                "frozen": resolved.model_dump(mode="json", exclude={"request"}),
                "operation_ref": resolved.request.operation_ref,
                "canonical_target_id": str(canonical),
                "bundle_id": str(bundle.bundle_id),
            },
        )
    else:
        resolved = selected
    if observing is not None:
        if row["state"] == "PENDING_APPROVAL":
            # Admitted under enforcement before the mode changed: the view stays as it is,
            # and an observing tenant neither consumes nor creates an approval.
            return Admission(store.view(conn, row))
        decision, usage = _decision(
            conn, identity, bundle, resolved, clock, None, row=row, catalog=catalog, mode="OBSERVE"
        )
        return _observe(conn, identity, row, resolved, decision, usage, observing, clock)
    approval = store.approval_row(conn, row)
    if row["state"] == "PENDING_APPROVAL":
        try:
            if row["bundle_id"] != bundle.bundle_id:
                raise ResolutionError("STALE_AUTHORIZATION")
            attest_snapshot(
                conn,
                identity,
                resolved,
                row["canonical_target_id"],
                clock,
                settings=bundle.context_settings,
                catalog=catalog,
                signals=SignalScope(bundle.signal_mappings, space),
            )
            if approval is None or store.now(clock) >= approval["expires_at"]:
                raise ResolutionError("STALE_AUTHORIZATION")
        except ResolutionError:
            return _stale(conn, row, identity, clock, approval)
    verified = None
    if approval and approval["state"] == "APPROVED":
        try:
            verified = store.verify_approval(
                conn, row, approval, tuple(approval["obligation_ids"]), clock
            )
        except ValueError:
            return _stale(conn, row, identity, clock, approval, "INVALID_APPROVAL")
    decision, usage = _decision(
        conn, identity, bundle, resolved, clock, verified, row=row, catalog=catalog
    )
    if decision.effect == "DENY":
        if "INVALID_APPROVAL" in decision.reasons:
            return _stale(conn, row, identity, clock, approval, "CHANGED_OBLIGATIONS")
        if approval and approval["state"] in {"PENDING", "APPROVED"}:
            store.approval_state(conn, row, approval, identity.principal_id, "INVALIDATED", clock)
        store.transition(
            conn, row, identity.principal_id, "DENIED", clock, reasons=list(decision.reasons)
        )
        return Admission(store.view(conn, row))
    if approval:
        if tuple(approval["obligation_ids"]) != decision.obligation_ids:
            return _stale(conn, row, identity, clock, approval, "CHANGED_OBLIGATIONS")
        if approval["state"] not in {"APPROVED", "PENDING"}:
            return _stale(conn, row, identity, clock, approval, "INVALID_APPROVAL")
    if decision.effect == "REQUIRE_APPROVAL" and verified is None:
        if approval is None:
            # How many people could decide it as it is held, counted under this fence so no
            # rule, membership, grant or assignment change lands between the count and the
            # insert. A preview for the console only: no decision, resume or consume reads it.
            reviewers = approval_routing.eligible_reviewers(
                conn,
                identity.tenant_id,
                space,
                row["canonical_target_id"],
                resolved.intent.action,
            )
            conn.execute(
                text("""
                INSERT INTO execbound.approvals
                  (tenant_id,approval_id,execution_id,principal_id,plan_hash,bundle_id,
                   obligation_ids,expires_at,created_at,state,required_approvers,space_id,
                   reviewers_at_hold)
                VALUES (:t,:a,:e,:p,:h,:b,CAST(:o AS jsonb),:x,:n,'PENDING',:required,:space,
                        :reviewers)
            """),
                {
                    "t": identity.tenant_id,
                    "space": space,
                    "reviewers": reviewers,
                    "a": uuid4(),
                    "e": row["execution_id"],
                    "p": identity.principal_id,
                    "h": row["plan_hash"],
                    "b": bundle.bundle_id,
                    "o": canonical_json(list(decision.obligation_ids)),
                    "n": store.now(clock),
                    "x": store.approval_expiry(
                        conn, identity.tenant_id, resolved.valid_until, store.now(clock)
                    ),
                    "required": bundle.required_approvers(decision.obligation_ids),
                },
            )
            created_approval = store.approval_row(conn, row)
            assert created_approval is not None
            # Queued with the approval, inside the fence: no approval without its notices.
            queue_notifications(
                conn,
                identity.tenant_id,
                created_approval["approval_id"],
                row["canonical_target_id"],
                resolved.intent.action,
                store.now(clock),
                notifications,
            )
            store.transition(
                conn,
                row,
                identity.principal_id,
                "PENDING_APPROVAL",
                clock,
                obligations=list(decision.obligation_ids),
                approval=store.approval_binding(created_approval),
            )
        return Admission(store.view(conn, row))
    busy = conn.execute(
        text(
            "SELECT 1 FROM execbound.resource_claims WHERE tenant_id=:t "
            "AND canonical_target_id=:c AND released_at IS NULL"
        ),
        {"t": identity.tenant_id, "c": row["canonical_target_id"]},
    ).scalar_one_or_none()
    if busy:
        if approval:
            store.approval_state(conn, row, approval, identity.principal_id, "INVALIDATED", clock)
        store.transition(conn, row, identity.principal_id, "DENIED", clock, reason="RESOURCE_BUSY")
        return Admission(store.view(conn, row))
    if row["report_expires_at"] is not None:
        # The marker the cap below reads, and the same pairing: a window with a state.
        # Both refusals belong here rather than beside the placement that named the
        # mapping — after the decision, so a request a hard denial would refuse is
        # recorded as DENIED rather than answered with a deployment fault, and before
        # anything is reserved.
        _attestable(conn, identity.tenant_id, attestable)
    if (
        row["report_expires_at"] is not None
        and store.outstanding_grants(conn, identity.tenant_id, identity.principal_id) >= MAX_GRANTS
    ):
        # Every outstanding grant charges its scopes until something settles it (an UNKNOWN
        # report, an asserted non-execution and the sweep all leave it charged), so an
        # executor that takes grants and never reports can exhaust its own and any shared
        # ceiling. Refused inside the fence and before anything is reserved: the whole
        # attempt rolls back, leaving no execution, no reservation and no claim.
        #
        # Deliberately after the approval branch, so a capped principal can still open a
        # pending approval. An approval reserves nothing, holds no claim and charges no
        # scope, which is the ceiling this cap exists to bound, and every approved
        # candidate passes through here before it reserves. Refusing earlier would deny
        # work a human might approve once a slot frees; the volume of pending approvals is
        # a notification surface, bounded by the surfaces' own rate limits.
        raise ExecutionError("TOO_MANY_GRANTS")
    if verified:
        # The consuming evaluation's snapshot is the one the reservation records.
        settled, usage = _decision(
            conn, identity, bundle, resolved, clock, verified, row=row, catalog=catalog
        )
        if settled.effect != "ELIGIBLE":
            return _stale(conn, row, identity, clock, approval, "INVALID_APPROVAL")
        assert approval is not None
        store.approval_state(conn, row, approval, identity.principal_id, "CONSUMED", clock)
    conn.execute(
        text(
            "INSERT INTO execbound.execution_impact "
            "(tenant_id,execution_id,principal_id,action,approved,state,created_at,"
            "account_id,group_ids,facts,space_id) "
            "VALUES (:t,:e,:p,:action,:a,'UNRESOLVED',:n,"
            ":account,CAST(:groups AS jsonb),CAST(:facts AS jsonb),:space)"
        ),
        {
            "t": identity.tenant_id,
            "e": row["execution_id"],
            "p": identity.principal_id,
            "a": verified is not None,
            "action": resolved.intent.action,
            "n": store.now(clock),
            **store.impact_attributes(resolved, usage.groups, row["space_id"]),
        },
    )
    conn.execute(
        text(
            "INSERT INTO execbound.resource_claims "
            "(tenant_id,execution_id,canonical_target_id) VALUES (:t,:e,:c)"
        ),
        {"t": identity.tenant_id, "e": row["execution_id"], "c": row["canonical_target_id"]},
    )
    store.transition(
        conn, row, identity.principal_id, "RESERVED", clock, approved=verified is not None
    )
    # The row's report window is the one fact that says "checkpoint", here as in _answer,
    # take_dispatch and store.outstanding_grants: it is written once at the insert above,
    # under the bundle this admission read, and no runtime statement can change it.
    ticket = None
    if row["report_expires_at"] is None:
        ticket = DispatchTicket(identity.tenant_id, row["execution_id"], secrets.token_urlsafe(32))
        conn.execute(
            text(
                "UPDATE execbound.executions SET owner_hash=:h "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {
                "h": store.ticket_digest(ticket.secret),
                "t": identity.tenant_id,
                "e": row["execution_id"],
            },
        )
    else:
        # The single attempt is consumed by the grant itself: ExecBound sends nothing, and
        # the dispatch path refuses an execution that already carries the stamp.
        conn.execute(
            text(
                "UPDATE execbound.executions SET dispatch_attempted_at=:n "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"n": store.now(clock), "t": identity.tenant_id, "e": row["execution_id"]},
        )
    store.transition(conn, row, identity.principal_id, "DISPATCH_COMMITTED", clock)
    # Any delay in writes/audit/foreign-key locks must not extend authority.
    store.identity_check(conn, identity, clock, "AGENT")
    attest_snapshot(
        conn,
        identity,
        resolved,
        row["canonical_target_id"],
        clock,
        settings=bundle.context_settings,
        catalog=catalog,
        signals=SignalScope(bundle.signal_mappings, space),
    )
    if verified and store.now(clock) >= verified.expires_at:
        raise ExecutionError("INVALID_APPROVAL")
    if verified:
        # Recheck approver role/scope/revocation after every potentially blocking write.
        assert approval is not None
        store.verify_approval(
            conn, row, {**approval, "state": "APPROVED"}, decision.obligation_ids, clock
        )
    if row["report_expires_at"] is not None:
        # Minted last, after every authority recheck: nothing is told it may act unless
        # the authority that decided it still holds. This is the one place a report secret
        # is ever minted, and test_a_grant_is_minted_only_after_the_closing_rechecks holds
        # the order, because a mint before them would be a secret handed out on authority
        # that the rechecks were about to find gone.
        grant = _grant(
            conn, identity, row, resolved, secrets.token_urlsafe(32), clock, preconditions
        )
        return Admission(store.view(conn, row).model_copy(update={"checkpoint": grant}))
    return Admission(store.view(conn, row), ticket)


def _observe(
    conn: Connection,
    identity: Identity,
    row: dict[str, Any],
    resolved: ResolvedRequest,
    decision: PolicyEvaluation,
    usage: UsageSnapshot,
    observing: str,
    clock: Clock,
) -> Admission:
    """Record what would have happened and end the execution; nothing else is written.

    No ticket, approval, reservation or claim exists for an observed request. A decision
    that would have executed leaves an OBSERVED impact row, with the attributes the
    snapshot counted, so later observed evaluations can project the limits in every scope
    as if it had; enforced evaluations never count it.
    """
    observed = ObservedResult(
        effect=decision.effect,
        reasons=decision.reasons,
        obligation_ids=decision.obligation_ids,
        mode=observing,  # type: ignore[arg-type]
    )
    if decision.effect != "DENY":
        conn.execute(
            text(
                "INSERT INTO execbound.execution_impact "
                "(tenant_id,execution_id,principal_id,action,approved,state,created_at,"
                "account_id,group_ids,facts,space_id) "
                "VALUES (:t,:e,:p,:action,:a,'OBSERVED',:n,"
                ":account,CAST(:groups AS jsonb),CAST(:facts AS jsonb),:space)"
            ),
            {
                "t": identity.tenant_id,
                "e": row["execution_id"],
                "p": identity.principal_id,
                "a": decision.effect == "REQUIRE_APPROVAL",
                "action": resolved.intent.action,
                "n": store.now(clock),
                **store.impact_attributes(resolved, usage.groups, row["space_id"]),
            },
        )
    result = {"observed": observed.model_dump(mode="json")}
    conn.execute(
        text(
            "UPDATE execbound.executions SET result=CAST(:r AS jsonb) "
            "WHERE tenant_id=:t AND execution_id=:e"
        ),
        {"r": canonical_json(result), "t": identity.tenant_id, "e": row["execution_id"]},
    )
    row["result"] = result
    store.transition(
        conn, row, identity.principal_id, "OBSERVED", clock, observed=result["observed"]
    )
    store.identity_check(conn, identity, clock, "AGENT")
    return Admission(store.view(conn, row))


def admit(
    db: Database,
    identity: Identity,
    request: ActionRequest,
    clock: Clock | None = None,
    *,
    available_accounts: frozenset[tuple[UUID, str]] | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
    notifications: Sequence[Destination] = (),
    preconditions: PreconditionConfig = NO_PRECONDITIONS,
    attestable: AttestableRing | None = None,
) -> Admission:
    clock = clock or SystemClock()
    try:
        request = parse_request(request.model_dump_json().encode())
        # The case is the one text of the agent's own that the chain carries: the first
        # transition copies it in, before any decision, and an event the export's secret check
        # flags fails that tenant's export at its window for good. Screened here and not by
        # `ExternalCase`, because a stored plan is validated through that model on every read
        # and a validator added to it would make a plan already holding such text unreadable.
        case = request.external_case
        if case is not None and find_secrets(case.model_dump(mode="json"), limit=1):
            raise ExecutionError("INVALID_REQUEST")
        with db.transaction(identity.tenant_id) as conn:
            result = _admit(
                conn,
                identity,
                request,
                clock,
                available_accounts,
                catalog,
                notifications,
                preconditions,
                attestable,
            )
            store.identity_check(conn, identity, clock, "AGENT")
        # Never leak a ticket from a transaction whose commit failed.
        return result
    except ExecutionError as exc:
        _rejection(db, identity, "admit", exc.code, clock)
        if exc.code in AUDIT_ONLY:
            # Audited as what it is; answered as every refusal that names nothing (T1.17).
            raise ExecutionError() from None
        raise
    except ResolutionError as exc:
        if exc.code == "INVALID_ARGUMENTS":
            _rejection(db, identity, "admit", "INVALID_ARGUMENTS", clock)
            raise ExecutionError("INVALID_REQUEST") from None
        # The refusal's own cause, for a person reading the audit (#545): an unknown
        # action, an unknown target and stale facts are told apart there and nowhere else.
        # The agent is answered the same 503 whatever the cause, and the snapshot reads the
        # cause in the same round trip, so the answer does not say which. Only a code from
        # the closed list is recorded.
        _rejection(
            db,
            identity,
            "admit",
            resolution_reason(exc, "DEPENDENCY_OR_CONTEXT_UNAVAILABLE"),
            clock,
        )
        raise ExecutionError() from None
    except (SQLAlchemyError, ValueError):
        # An unexpected database or value error, not a resolution refusal, keeps the generic
        # reason; a refusal raised as an ExecutionError above keeps its own code.
        _rejection(db, identity, "admit", "DEPENDENCY_OR_CONTEXT_UNAVAILABLE", clock)
        raise ExecutionError() from None


def get_execution(
    db: Database, identity: Identity, execution_id: UUID, clock: Clock | None = None
) -> ExecutionView:
    clock = clock or SystemClock()
    try:
        with db.transaction(identity.tenant_id) as conn:
            store.identity_check(conn, identity, clock, "AGENT")
            row = store.read(conn, identity.tenant_id, execution_id)
            if row["principal_id"] != identity.principal_id:
                raise ExecutionError("NOT_FOUND")
            result = store.view(conn, row)
            store.identity_check(conn, identity, clock, "AGENT")
        return result
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None
