# SPDX-License-Identifier: AGPL-3.0-only
"""Administrator settlement of a retained uncertain operation from verified evidence."""

from typing import Any
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from execbound.db import Database
from execbound.execution import store
from execbound.execution.authority import _rejection
from execbound.execution.models import (
    UNSETTLED,
    AuthorityCheck,
    EvidenceVerifier,
    ExecutionError,
    ExecutionView,
    TerminalEvidence,
    VerifiedTier,
    VerifierFactory,
)
from execbound.execution.outcomes import (
    _correctable,
    _never_executor_evidence,
    _proof,
    _settle,
    _verified_tier,
    _verifier,
)
from execbound.execution.scheduled import RecoveryActor, actor_check
from execbound.resolution.models import Clock, SystemClock
from execbound.secrets import secret_shaped


def _executor_evidence_only(row: dict[str, Any], verifier: EvidenceVerifier) -> None:
    """Refuse to settle a checkpoint grant from anything but checkpoint evidence.

    Checkpoint evidence is what the runtime's ``provider.checkpoint_evidence``
    ``CheckpointVerifier`` checks: the executor's own record, or a provider's checkpoint
    journal verified under the journal key the operator configured for that Gate account.
    The dispatch path never accepts either, which is ``outcomes._never_executor_evidence``.

    This is the one connector-free path that reaches ``_settle``, and the connector paths
    arrive here: ``provider.gateway.reconcile_operation`` with ``cancel_if_missing`` hands
    this function ``connector.cancel`` evidence, which says what the vendor's own console
    was told and nothing about what the external executor did, and settling on it would
    record a non-execution and release the claim on absent executor evidence — the refund
    the execution contract forbids. A connector's journal verifier is refused here even
    though a checkpoint journal is a journal too: that verifier holds the connector
    account's key, which never speaks for a Gate account, and it declares that it attests no
    external execution.

    Admission refuses a Gate mapping whose account is in the runtime's connector
    inventory, but that is a fact about the inventory as it stood at admission: the human
    surface and the CLI both look the account up in the live inventory, so an operator who
    configures a connector for a Gate account afterwards reaches this function for every
    grant already outstanding. The refusal therefore lives here rather than resting on a
    configuration that can change. The row's report window is the marker, as it is in
    ``dispatch._never_a_checkpoint``; the verifier that checked the evidence is what says
    the evidence is checkpoint evidence, because only the composition boundary that built
    it knows. ``CheckpointVerifier`` and the ``ExecutorVerifier`` it composes are the
    verifiers that declare ``attests_external_execution``, and ``EvidenceVerifier``
    declares it so that any other is asked the same question. It is read by name rather
    than by ``isinstance`` because ``execution`` imports nothing from ``provider`` while
    ``provider.executor`` imports ``execution.store``, so the type test would invert that
    edge; ``getattr`` keeps its default here, so a verifier that answers nothing settles
    no grant.

    This is one direction of a pairing of the same two facts, and the other is
    ``outcomes._never_executor_evidence``, called beside it at both of this function's call
    sites: a row with no report window is never settled from an external executor's
    evidence either.
    """
    if row["report_expires_at"] is not None and not getattr(
        verifier, "attests_external_execution", False
    ):
        raise ExecutionError("INVALID_STATE")


def _unsettled_grant_only(row: dict[str, Any], proof: TerminalEvidence | None = None) -> None:
    """Refuse an administrator's evidence against a checkpoint that is already settled.

    One settled row is admitted, and only against one evidence class in one direction: a
    ``_correctable`` row — FAILED_EFFECT_UNKNOWN at tier ASSERTED whose retained reason is
    REPORTED_FAILURE, the one state no verifier can produce — against a verified
    non-execution. ``reconcile`` asks twice, as it already did: the unfenced call narrows on
    the row alone, because the proof does not exist yet, and the fenced call also takes the
    verified evidence, so what admits a correction is a row and a proof read under the fence
    together. An attested EXECUTED against the same row is refused there, because releasing
    the canonical claim before the act window is the promotion docs/CHECKPOINT.md refuses
    under "The claim an assertion left held".

    The claim an assertion settled may be released early by attested evidence or by an
    administrator, and the correction above is both of those at once: an administrator
    presents evidence a verifier returned, and ``_settle`` releases the claim on it because
    that evidence is verified — unless the recovery sweep released it first, which
    ``_settle``'s ``released_at IS NULL`` narrowing leaves as it was. What is not built is
    the wider route that rule can be read for: a later attested statement taken as a
    promotion of a settled row, leaving what the row says and raising its tier. The outcome
    route refuses attested evidence contradicting a settled row rather than promoting the
    tier, and the attested EXECUTED refused above is that promotion arriving here. Beyond
    the one correction the paragraph above bounds, a second settlement of one execution
    stays refused, which ExecBound enforces as single settlement and which the state machine
    expresses by having no edge out of a terminal state. For a settled grant this function
    refuses, the claim's exit is the recovery sweep, which releases it once the act window
    has passed. ``released_at`` has two writers, ``recovery_run.release_claim`` and
    ``_settle``, and ``_settle`` writes it below a terminal branch that answers a settled
    row which is not a correction, so the sweep is what such a row waits for.

    What this refuses is the answer that was worse than no exit at all. ``_settle`` returns
    the view when the state it would write is the one the row already holds, so a valid
    executor record against a row already EXECUTED at tier ASSERTED reported success while
    moving neither the tier, the claim nor the impact, and ``reconcile`` captures nothing
    of its own beforehand, so the attempt left no trace. A refusal is answered and audited
    by ``_rejection`` like every other refused request in the kernel. The refusal is
    checkpoint-only: an operation ExecBound dispatched keeps ``_settle``'s early return,
    which is the idempotent repeat a lost provider response wants.
    """
    if row["report_expires_at"] is not None and row["state"] not in UNSETTLED:
        if not _correctable(row) or (proof is not None and proof.outcome != "FAILED_NOT_EXECUTED"):
            raise ExecutionError("INVALID_STATE")


def reconcile(
    db: Database,
    admin: RecoveryActor,
    execution_id: UUID,
    *,
    reason: str,
    evidence: bytes,
    verifier: EvidenceVerifier,
    verifier_for: VerifierFactory | None = None,
    clock: Clock | None = None,
    authority_check: AuthorityCheck | None = None,
) -> ExecutionView:
    """Settle one retained uncertain operation from evidence a verifier attests.

    ``verifier`` checks the evidence outside the fence, which is what keeps the cost of a
    signature off the tenant's writers. ``verifier_for`` is the connector-free executor
    path's: a checkpoint settles against the tenant's key ring, the ring is not immutable
    the way the frozen command is, and a compromise is retroactive, so the settlement must
    rest on a ring read under the fence rather than on one read before it was taken. A
    connector's journal verifier carries no such state and passes none, leaving that path
    exactly as it was. A checkpoint settles at the tier the fenced verifier reports for the
    proof it returned: ATTESTED for an executor's record, PROVIDER_VERIFIED for a provider
    journal.
    """
    clock = clock or SystemClock()
    try:
        if (
            not isinstance(reason, str)
            or not 1 <= len(reason.strip()) <= 500
            or secret_shaped(reason)
        ):
            raise ExecutionError("INVALID_REASON")
        actor = admin.principal_id
        if actor is None:
            raise ExecutionError("INVALID_IDENTITY")
        with db.transaction(admin.tenant_id) as conn:
            actor_check(conn, admin, clock)
            if authority_check is not None:
                authority_check(conn)
            row = store.read(conn, admin.tenant_id, execution_id)
            _executor_evidence_only(row, verifier)
            _never_executor_evidence(row, verifier)
            _unsettled_grant_only(row)
            command = store.command(row)
        proof = _proof(command, evidence, verifier)
        with db.transaction(admin.tenant_id) as conn:
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, admin.tenant_id, clock)
            actor_check(conn, admin, clock)
            if authority_check is not None:
                authority_check(conn)
            row = store.read(conn, admin.tenant_id, execution_id)
            if verifier_for is not None:
                verifier = _verifier(conn, row, verifier_for)
                proof = _proof(store.command(row), evidence, verifier)
            _executor_evidence_only(row, verifier)
            _never_executor_evidence(row, verifier)
            _unsettled_grant_only(row, proof)
            # A checkpoint settles at the tier the verifier that checked this proof, under
            # the fence, says it establishes; an operation ExecBound dispatched has no tier
            # and is never asked, so its connector verifier's answer is never read.
            verified_tier: VerifiedTier = "ATTESTED"
            if row["report_expires_at"] is not None:
                verified_tier = _verified_tier(verifier, proof)
            result = _settle(
                conn,
                row,
                actor,
                proof,
                clock,
                reason.strip(),
                verified_tier=verified_tier,
            )
            actor_check(conn, admin, clock)
            if authority_check is not None:
                authority_check(conn)
        return result
    except ExecutionError as exc:
        _rejection(db, admin, "reconcile", exc.code, clock)
        raise
    except (SQLAlchemyError, ValueError):
        _rejection(db, admin, "reconcile", "DEPENDENCY_UNAVAILABLE", clock)
        raise ExecutionError() from None
