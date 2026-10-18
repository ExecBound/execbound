# SPDX-License-Identifier: AGPL-3.0-only
"""Terminal evidence verification and settlement of a committed operation.

Two paths reach settlement and neither may reach the other's executions. An operation
ExecBound dispatched settles from the provider's own journal, carried in by the holder of
the dispatch ticket this process minted and never released. An externally executed
operation settles from an authenticated report its executor sends to ``report_outcome``,
presenting the report secret its grant carried.

Each path is told apart from the other by a marker of its own, and the two markers are
different facts. ``report_outcome`` re-reads the owner-provisioned bundle the execution was
frozen under, inside the fence, and refuses any execution whose mapping does not declare an
external executor. The ticket paths read ``executions.report_expires_at``, the window
admission stamps at the insert on every execution a checkpoint mapping produced, a denied
or stale one included, which no runtime statement can change. Neither reads anything the
caller sent.

The two markers agree by construction, because the window is written under the mapping that
was read, and each is tested where they disagree: when they do, the mapping decides on the
report route and the column decides on the ticket paths. The refusals are not decoration —
a checkpoint's report secret is on the wire and its digest lives in the very column a
dispatch ticket's does, so the holder of a report secret holds a value the owner check
would otherwise accept.

A third fact is weighed against that column on the two paths that take a verifier from
their caller rather than building one: the kind of evidence the verifier attests.
``_never_executor_evidence`` refuses an external executor's evidence for a row with no
report window, and ``reconciliation._executor_evidence_only`` refuses anything but it for a
row with one.

The markers also decide how a row settles and not only which route may reach it, which is
this module's larger rule. An operation ExecBound dispatched settles from its provider's
journal at no tier and releases the canonical claim it held; a checkpoint settles at the
tier its evidence supports, and only evidence a verifier returned releases that claim, so
an executor's unverified word can settle the execution and confirm its impact but can
never free the target its grant took.
"""

import json
import secrets
from dataclasses import dataclass
from typing import Any, cast, get_args
from uuid import UUID

from execbound_protocol.executor import SignedOutcomeJws
from execbound_protocol.provider import ProviderError, parse_provider
from execbound_protocol.report import JwsToken as JwsToken
from execbound_protocol.report import OutcomeReport as OutcomeReport
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import append_event, canonical_json
from execbound.db import Database
from execbound.execution import store
from execbound.execution.authority import _rejection
from execbound.execution.dispatch import _never_a_checkpoint, _owner
from execbound.execution.models import (
    UNSETTLED,
    AssertedOutcome,
    AssertedReason,
    AssertedResult,
    DispatchCommand,
    DispatchTicket,
    EvidenceVerifier,
    ExecutionError,
    ExecutionView,
    ReportedResult,
    SettlementTier,
    TerminalEvidence,
    VerifiedTier,
    VerifierFactory,
)
from execbound.identity import Identity
from execbound.requests import (
    MAX_REQUEST_BYTES,
    _reject_number,
    _unique_object,
)
from execbound.resolution.models import Clock, SystemClock

# The report's body is the protocol's: `execbound_protocol.report` defines it, and its JSON
# Schema is published from that one definition, so the route validates with exactly what an
# executor is told to send (#37). It is named here, and parsed by `parse_report` below, as it
# always was.


def parse_report(raw: bytes) -> OutcomeReport:
    """Validate the report's own JSON as strictly as an action request is validated."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_REQUEST_BYTES:
        raise ExecutionError("INVALID_REQUEST")
    try:
        # Pydantic's parser accepts duplicate keys and nonfinite numbers. Check
        # syntax first, then validate the same bytes through its strict JSON path.
        json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
        return OutcomeReport.model_validate_json(raw)
    except (ValueError, RecursionError):
        pass
    # Raising outside the handler drops the context, whose validation details would
    # otherwise retain the report secret the caller sent.
    raise ExecutionError("INVALID_REQUEST")


@dataclass(frozen=True)
class ReportedOutcome:
    """An accepted report, as far as ExecBound can check it: a tier and its evidence.

    Either verified tier carries the ``TerminalEvidence`` a verifier returned. ATTESTED
    means the executor's statement is authenticated and non-repudiable and never that the
    vendor effect is proven; PROVIDER_VERIFIED means the provider's own journal for this
    exact command verified. ASSERTED carries the executor's own ``AssertedOutcome`` and
    nothing more. An unknown result carries neither and names no tier, because there is
    nothing to settle at any tier.
    """

    tier: SettlementTier | None
    proof: TerminalEvidence | None = None
    asserted: AssertedOutcome | None = None

    def __post_init__(self) -> None:
        verified = self.tier in get_args(VerifiedTier)
        if (self.proof is not None) != verified or (self.asserted is not None) != (
            self.tier == "ASSERTED"
        ):
            raise ValueError("A tier carries exactly its own evidence")

    @property
    def outcome(self) -> ReportedResult:
        if self.proof is not None:
            return self.proof.outcome
        return self.asserted.outcome if self.asserted is not None else "UNKNOWN"

    @property
    def reason(self) -> AssertedReason | None:
        if self.proof is not None:
            return self.proof.reason
        return self.asserted.reason if self.asserted is not None else None


def _proof(command: DispatchCommand, raw: bytes, verifier: EvidenceVerifier) -> TerminalEvidence:
    # Verification is outside the SQL transaction; future adapters may contact a journal.
    try:
        proof = verifier.verify(command, raw)
        if type(proof) is not TerminalEvidence:
            raise ValueError()
        proof = TerminalEvidence.model_validate_json(proof.model_dump_json())
        if (
            proof.operation_id != command.operation_id
            or proof.account_id != command.frozen.intent.account_id
            or proof.intent_hash != command.intent_hash
            or proof.plan_hash != command.plan_hash
        ):
            raise ValueError()
        return proof
    except Exception:
        raise ExecutionError("INVALID_EVIDENCE") from None


def _verified_tier(verifier: EvidenceVerifier, proof: TerminalEvidence) -> VerifiedTier:
    """The tier the verifier that checked this evidence says it establishes.

    Asked of the verifier because only the composition boundary that built it knows which
    envelope the opaque authenticated record holds; a verifier that answers nothing, or
    answers anything but a verified tier, settles no checkpoint.
    """
    answer = getattr(verifier, "verified_tier", None)
    tier = answer(proof) if callable(answer) else None
    if tier not in get_args(VerifiedTier):
        raise ExecutionError("INVALID_EVIDENCE")
    return cast(VerifiedTier, tier)


def _verifier(
    conn: Connection, row: dict[str, Any], verifier_for: VerifierFactory
) -> EvidenceVerifier:
    """The verifier for this row, or the refusal a ring that will not load deserves.

    A tenant whose key ring is empty or holds a row no current guard would accept has no
    attested reporting at all, and nothing about that changes until an administrator lists
    the ring and replaces the row. Raised as INVALID_KEY_RING rather than left to fall
    through as a bare ValueError, which every route here answers as an unavailable
    dependency and so invites a retry that can never succeed. Admission refuses to issue a
    grant a ring in that state could not attest, so what reaches this is a grant issued
    while the ring was usable.
    """
    try:
        return verifier_for(conn, row)
    except ValueError:
        raise ExecutionError("INVALID_KEY_RING") from None


def _claimed_tier(report: OutcomeReport) -> SettlementTier | None:
    """The most a report could amount to, from what it presented and not what it claims.

    Evidence is checked before it becomes a verified tier, so this is a claim and never a
    settlement: ``_reported`` returns the same answers once the evidence has been weighed,
    and evidence that does not verify, or verifies as a tier other than the field it
    arrived in names, is refused rather than demoted. The field names the kind: a journal
    claims PROVIDER_VERIFIED, and a record or an attestation, both an executor's own
    signature, claims ATTESTED. It is decided from the body alone so that a report against
    a settled execution can be refused before any signature is checked.
    """
    if report.outcome == "UNKNOWN":
        return None
    if report.journal is not None:
        return "PROVIDER_VERIFIED"
    return "ATTESTED" if report.signed else "ASSERTED"


def _terminal_state(outcome: AssertedResult, reason: AssertedReason) -> str:
    """The state a settlement of this outcome and reason leaves the execution in.

    A version mismatch is stale authority rather than an ordinary non-execution, because
    what failed is the precondition the plan was frozen under; every other reason settles
    at the outcome it names — which for REPORTED_FAILURE is FAILED_EFFECT_UNKNOWN.

    That this needs no branch for the new reason is a consequence of `models.TERMINAL_PAIRS`
    and not a property of this function: the table is what forbids FAILED_EFFECT_UNKNOWN
    beside VERSION_MISMATCH, which is the one pairing that would have needed one.

    Named once because two callers ask it and their answers have to agree. ``_settle``
    writes this state, and ``_state_after`` answers with it so that ``_settle_report``'s
    no-op guard compares the state a report would leave against the state settlement
    wrote. Spelled twice and drifted apart, a report restating a settled outcome would
    append a capture and then return the row untouched, and the two captures one grant is
    allowed would stop bounding anything.
    """
    return "STALE_AUTHORIZATION" if reason == "VERSION_MISMATCH" else outcome


def _state_after(reported: ReportedOutcome) -> str:
    """The state this report leaves the execution in.

    The state half of what a report settles (docs/CHECKPOINT.md, What each report settles);
    the claim half is in ``_settle``. An attested outcome settles exactly as a dispatch
    does, a version mismatch included, because the tenant has accepted that executor's
    signed word. An asserted execution settles too, since charging for an action that may
    have happened is the safe direction, and so does an asserted failure whose effect is not
    established: it confirms the same impact a reported success confirms and frees nothing.
    An asserted *non-execution* and an unknown result settle nothing and leave retained
    uncertainty: a caller that can free its own budget by claiming the vendor was never
    reached can exceed every limit, and an unknown result is the absence of terminal
    evidence rather than a kind of it.

    What a settlement settles *at* is ``_terminal_state``'s to say and is not restated
    here, so this and ``_settle`` cannot answer differently about the same report.

    It is restated once outside this module, and that copy cannot import this one:
    ``replay/verify.py:_asserted`` reads an exported settlement's bytes and refuses a tier
    ASSERTED transition whose state is not the outcome the assertion itself names, or whose
    outcome is FAILED_NOT_EXECUTED, or a tier-less one whose state is not INDETERMINATE,
    which is the set of answers this function gives for an assertion. A change here that
    let an assertion settle at some other state would make replay refuse histories the
    kernel wrote, so the two are cross-referenced rather than left to be found.
    """
    if reported.tier is None or (
        reported.tier == "ASSERTED" and reported.outcome == "FAILED_NOT_EXECUTED"
    ):
        return "INDETERMINATE"
    # A tier carries exactly its own evidence, and both evidence models validate
    # `consistent_terminal`, so anything reaching here names a terminal outcome with the
    # one reason that can accompany it. That is also why an executed outcome needs no arm
    # of its own: EXECUTED is the only reason `consistent_terminal` admits beside it, so
    # `_terminal_state` can never read a version mismatch out of one.
    assert reported.outcome != "UNKNOWN" and reported.reason is not None
    return _terminal_state(reported.outcome, reported.reason)


def _stored_attestation(evidence: bytes) -> bool:
    """Whether this evidence is an ES256 attestation in the form a settlement stores it.

    The form is the RFC 7515 flattened wrapper ``SignedOutcomeJws``, which an ATTESTED
    settlement retains for an attestation instead of the compact token. The executor
    verifier reads it as a JSON envelope, before an Ed25519 one, because an administrator's
    settlement and correction may present a stored record again (docs/CHECKPOINT.md, What a
    settled row is closed to). That verifier is the one the report route shares with them,
    and the route is the path that knows which field the evidence arrived in, so this is the
    question it asks of a ``record`` or a ``journal`` before handing the bytes over: the same
    parse as the verifier's first JSON branch, and nothing more.
    """
    try:
        parse_provider(evidence, SignedOutcomeJws)
    except ProviderError:
        return False
    return True


def _restates(row: dict[str, Any], report: OutcomeReport) -> bool:
    """Whether this report says exactly what the execution has already settled.

    Compared against the tier column and the retained evidence beside it, which
    ``_settle`` writes in one transaction, and not against the last report the chain
    holds: what a repeat may not do is change a settled execution, and two reports that
    alternate would each differ from the one before while changing nothing.
    """
    # A settled state does not imply a retained result. On this route it always does, since
    # only `_settle` writes a result and it writes the state in the same transaction, but
    # nothing here enforces that: `_reportable` asks this of whatever state it finds, and a
    # row moved to a terminal state without being settled would arrive with a NULL result.
    # `authority._stale` writes exactly that shape today and never reaches here only
    # because a stale row carries no owner secret, so the owner check refuses it first.
    # Without the guard that shape is an AttributeError rather than a refusal.
    retained = row["result"] if isinstance(row["result"], dict) else {}
    return (
        row["settlement_tier"] == _claimed_tier(report)
        and retained.get("outcome") == report.outcome
        and retained.get("reason") == report.reason
    )


def _reported(
    command: DispatchCommand, report: OutcomeReport, verifier: EvidenceVerifier | None
) -> ReportedOutcome:
    """What the report amounts to once its evidence has been checked against the command.

    The tier follows from what the executor presented and from nothing it claims: verified
    evidence is attested or provider-verified, the executor's bare word is asserted, and an
    unknown result is neither. No caller input promotes a tier. It is ``_claimed_tier``
    that decides here, so the tier ``_restates`` compares a settled row against and the
    tier this returns are one rule and cannot drift apart; what this adds is that a
    verified tier is returned only once the evidence behind it has verified, and only when
    the verifier that checked it says it establishes that same tier.

    ``_settle`` does not take the tier this returns. It derives whether there is one and
    whether it is verified from the evidence type it was handed and the row's report
    window, so that no path ExecBound dispatched acquires a tier and no caller can make an
    assertion verified. What it is handed is only *which* verified tier, and
    ``_settle_report`` hands it the tier this returned, which is the verifier's own answer
    by the check at the end below. On this route the two agree by construction rather than
    by sharing a line, and the asserts below are what bind them: each arm's evidence type
    is fixed to ``_claimed_tier``'s answer, so a report asserted here reaches ``_settle``
    as an ``AssertedOutcome`` and a verified one as a ``TerminalEvidence``. A reader who
    finds the second derivation is not looking at a bug. The runtime composes one
    ``CheckpointVerifier``, which answers ATTESTED for an executor's record and
    PROVIDER_VERIFIED for a provider journal, so evidence arriving in a field that claims
    the other tier is refused here rather than settled at a tier its field picked.

    The field also names the envelope, which the tier alone does not: a ``record`` and an
    ``attestation`` both claim ATTESTED, and the verifier reads an attestation's stored form
    as a JSON envelope for the administrator's sake. A ``record`` or a ``journal`` in that
    form is refused here, by ``_stored_attestation``, before the verifier sees it, so ES256
    reaches the verifier on this route only as an ``attestation``.
    """
    tier = _claimed_tier(report)
    if report.outcome == "UNKNOWN":
        assert tier is None
        return ReportedOutcome(None)
    assert report.reason is not None
    if verifier is None:
        # The caller builds a verifier exactly when evidence was presented, and the report
        # carries its reported time exactly when none was.
        assert tier == "ASSERTED"
        assert report.reported_at is not None
        # Every bound field comes from the frozen command, so an assertion names exactly
        # the operation ExecBound authorized whatever the executor sent.
        return ReportedOutcome(
            tier,
            asserted=AssertedOutcome(
                operation_id=command.operation_id,
                account_id=command.frozen.intent.account_id,
                intent_hash=command.intent_hash,
                plan_hash=command.plan_hash,
                outcome=report.outcome,
                reason=report.reason,
                reported_at=report.reported_at,
            ),
        )
    evidence = report.evidence
    assert evidence is not None and tier in get_args(VerifiedTier)
    if report.attestation is None and _stored_attestation(evidence):
        # Section 2.6 makes a `record` an Ed25519 signed outcome and a `journal` a provider's
        # signed journal, and the route takes ES256 only as an `attestation`. The stored form
        # is the same signed statement and would verify, so it is refused here, from the field
        # it arrived in, before any signature is checked: in a `record` it would otherwise
        # settle ATTESTED, and in a `journal` it would cost a verification before the tier
        # check refused it. The administrator's paths that share the verifier keep reading it.
        raise ExecutionError("INVALID_RECORD")
    try:
        proof = _proof(command, evidence, verifier)
        proved = _verified_tier(verifier, proof)
    except ExecutionError:
        # The same failure means different things on the two settlement paths: a provider
        # journal that will not verify on the dispatch path is a provider fault, and
        # evidence an executor presents that will not verify is the caller's own, so
        # INVALID_EVIDENCE keeps its meaning for the connector paths that raise it.
        raise ExecutionError("INVALID_RECORD") from None
    if proved != tier or (proof.outcome, proof.reason) != (report.outcome, report.reason):
        # The evidence is the statement, and the field it arrived in names its kind: a body
        # contradicting either would be audited as one thing and settled as another.
        raise ExecutionError("INVALID_RECORD")
    return ReportedOutcome(tier, proof=proof)


def _reportable(
    conn: Connection,
    identity: Identity,
    execution_id: UUID,
    report: OutcomeReport,
    clock: Clock,
) -> dict[str, Any]:
    """The granted checkpoint this report may settle, or the refusal that stops it.

    Every refusal that reads the execution row is here, so the fenced transaction re-runs
    exactly what the first read checked and the two cannot drift apart. It is not every
    refusal the route makes: a body that will not parse, an identity that is no longer a
    live agent and evidence that does not verify are each refused elsewhere, on facts this
    row cannot answer. A new refusal belongs here only when the row is what decides it.
    """
    row = store.read(conn, identity.tenant_id, execution_id)
    if row["principal_id"] != identity.principal_id:
        # Another principal's execution is not this one's to settle, and the answer says
        # nothing about whether it exists.
        raise ExecutionError("NOT_FOUND")
    if (
        store.checkpoint_mapping(
            store.frozen(row), store.bundle(conn, row["tenant_id"], row["bundle_id"])
        )
        is None
    ):
        # The refusal this route exists for, read from the owner-provisioned bundle the
        # execution was frozen under rather than from anything on the wire: an execution
        # id is a caller field, and an operation ExecBound dispatched settles from its
        # provider's journal alone. It is refused before the secret is compared, so a
        # dispatched execution is unreportable whether or not its owner secret matches.
        raise ExecutionError("INVALID_STATE")
    # The one thing that authenticates a report. What is stored and what is compared are
    # SHA-256 digests and never the secret itself, and the comparison is constant-time, so a
    # near miss costs the caller no timing signal. It sits after the mapping check, so a
    # dispatched execution is refused whether or not its owner secret matches, and before
    # the state and window checks, so neither of those answers anything to a caller that has
    # not authenticated. A row carrying no digest is refused outright rather than compared
    # against an empty string.
    if not row["owner_hash"] or not secrets.compare_digest(
        row["owner_hash"], store.ticket_digest(report.report_secret)
    ):
        raise ExecutionError("INVALID_REPORT")
    if row["state"] not in UNSETTLED and not _restates(row, report):
        # A settled execution has no edge back: the one secret it ever had settles it
        # once, and a report saying anything else is refused rather than quietly
        # discarded. A report restating what it settled is let through to be answered as
        # the no-op it is, so a lost response never strands the caller holding it.
        #
        # UNSETTLED is DISPATCH_COMMITTED and INDETERMINATE, so an uncertain execution
        # stays reportable: that is where settlement puts an outcome it cannot call
        # terminal, and closing it would punish the executor that honestly reported an
        # unknown result and make silence the better move. What bounds the repetition is
        # that a report is recorded exactly when it moves the execution (``_settle_report``).
        raise ExecutionError("INVALID_STATE")
    if row["report_expires_at"] is None or store.now(clock) >= row["report_expires_at"]:
        # The window is written once, at admission, and marks every execution that would
        # have been a checkpoint, so a row carrying none is no live grant. Past the
        # deadline the administrator exit is the remedy, not a report ExecBound accepts.
        raise ExecutionError("REPORT_WINDOW_CLOSED")
    _journal_admitted(row, report)
    return row


def _journal_admitted(row: dict[str, Any], report: OutcomeReport) -> None:
    """Refuse a provider journal for a grant that carried no provider command.

    Section 2.6 makes a journal the provider's signed record of exactly the grant's
    ``provider_command``, and a grant under ``UNAVAILABLE`` carries none (sections 2.2 and
    2.5). The command ExecBound would have sent still exists, frozen with the plan, and a
    provider that was handed it some other way signs a journal that verifies; the grant never
    described that command to anyone, so such a journal is refused as ``INVALID_RECORD``
    before any signature is checked and the grant is left as it was.

    The class is the one admission recorded at the first answer, read from the row here in
    both of the route's transactions, and never the deployment's declaration now: a later
    answer describes the grant under that same recorded class and records nothing, so a
    redeployment changes what this refuses for no grant already issued. The refusal is the
    route's alone. The administrator's settlement weighs a journal as before.

    A row with no recorded class is a grant an earlier release issued, before the class was
    recorded, and is admitted as it always was: an empty class cannot tell an
    ``ENFORCED_BY_PROVIDER`` grant, whose journal is legitimate, from an ``UNAVAILABLE`` one,
    so refusing it would refuse both. No such grant stays reportable for long: the report
    window is at most a day, so within a report window of the last grant an earlier release
    issued every one of them is past its window, and refused for that. That is a bound on the
    last grant such code issues, not on when this code was deployed: a rolling overlap, a
    rollback or a replica still running earlier code moves it.
    """
    if report.journal is not None and row["precondition_class"] == "UNAVAILABLE":
        raise ExecutionError("INVALID_RECORD")


def _correctable(row: dict[str, Any]) -> bool:
    """A settled grant whose only evidence is somebody's word.

    The one exception to single settlement, read from the row alone. The three facts are
    written by ``_settle`` in one transaction, and the redundancy among them is
    load-bearing rather than an alarm. The vocabulary split makes the state fact imply the
    other two of a row some *report* produced — FAILED_EFFECT_UNKNOWN is reachable from an
    ``AssertedOutcome``, which ``_reported`` builds — and that is as far as the type system
    reaches. ``store.transition`` takes a plain ``str``, so an in-process caller can write
    that state with no tier beside it and no statement retained, on a path where no
    evidence model is consulted; what refuses such a row here is the tier fact and the
    reason fact.
    The redundancy still fails in the safe direction — a state made reachable some other
    way stops being admitted rather than starts admitting the wrong thing — but it is not
    spare, and AL31 varies each of the three on its own while the other two hold.

    Its readers are ``_settle``'s terminal branch and
    ``reconciliation._unsettled_grant_only``, which is why it lives here rather than beside
    the second: ``reconciliation`` imports this module and not the other way round.
    """
    retained = row["result"] if isinstance(row["result"], dict) else {}
    return (
        row["state"] == "FAILED_EFFECT_UNKNOWN"
        and row["settlement_tier"] == "ASSERTED"
        and retained.get("reason") == "REPORTED_FAILURE"
    )


def _settle(
    conn: Connection,
    row: dict[str, Any],
    actor: UUID,
    evidence: TerminalEvidence | AssertedOutcome,
    clock: Clock,
    reason: str,
    *,
    verified_tier: VerifiedTier = "ATTESTED",
) -> ExecutionView:
    """Record a terminal outcome, at the tier the evidence handed here supports.

    ``TerminalEvidence`` is what a trusted verifier returned: a provider's journal on the
    path ExecBound dispatched, or, for a checkpoint, an executor's record checked against
    the keys the tenant registered or a provider's journal checked against the journal key
    the operator configured. ``AssertedOutcome`` is an external executor's authenticated
    word, built by ``_reported`` from the frozen command and reaching here only from the
    report route. The difference decides two things: this function releases the canonical
    claim exactly when the evidence was verified, and the tier written beside the retained
    result says which a reader is looking at.

    A checkpoint's tier is ``verified_tier`` for verified evidence, which is what the
    verifier that checked it reported: ATTESTED for an executor's record and
    PROVIDER_VERIFIED for a provider's journal. The two settlement paths that asked the
    verifier hand it in, ``_settle_report`` from the tier ``_reported`` already bound to the
    verifier's answer and ``reconciliation.reconcile`` from ``_verified_tier``; this
    function cannot ask, because ``execution`` imports nothing from ``provider`` and the
    authenticated record is opaque here. The executor's bare word is ASSERTED whatever is
    passed, and an operation ExecBound dispatched settles at no tier whatever is passed,
    so the keyword can say which verified tier and never whether there is one.

    One settled row is not closed to this: a ``_correctable`` one, against a **verified**
    non-execution, falls through into the ordinary settlement body below rather than being
    refused. Nothing in that body is special-cased for it — the impact is rewritten to
    NONEXECUTION with a null ``confirmed_at``, the claim is released because ``verified``
    is true, the correcting evidence replaces the asserted one, the tier becomes the one
    the correcting evidence verified at, ATTESTED or PROVIDER_VERIFIED, and the transition
    is appended out of the state the assertion settled at. What decides is the row and the
    proof read under the fence together, in ``reconciliation._unsettled_grant_only``; this
    arm is the defence in depth behind it.
    """
    verified = type(evidence) is TerminalEvidence
    if not verified and evidence.outcome == "FAILED_NOT_EXECUTED":
        # An assertion may not claim a non-execution. What the guard was always protecting
        # is the refund: reaching the NONEXECUTION impact below on the executor's bare word
        # would refund a reservation on absent evidence, which is the one thing a caller
        # must not be able to say its way to. It may now state a failure whose effect is
        # unknown, which reaches no NONEXECUTION write and releases nothing;
        # ``_settle_report`` routes an asserted non-execution to retained uncertainty.
        raise ExecutionError("INVALID_STATE")
    terminal_state = _terminal_state(evidence.outcome, evidence.reason)
    correcting = verified and evidence.outcome == "FAILED_NOT_EXECUTED" and _correctable(row)
    if row["state"] not in UNSETTLED and not correcting:
        if row["state"] == terminal_state:
            # Settling what the row already settled is the view and nothing else, which is
            # the idempotent repeat a lost provider response wants. A checkpoint is turned
            # away before each of the three call sites reaches it: ``record_outcome`` by
            # ``_never_a_checkpoint``, ``reconciliation.reconcile`` by
            # ``_unsettled_grant_only``, and ``_settle_report`` by answering a restatement
            # itself. For a grant this branch reported success while moving neither the
            # tier, the claim nor the impact, and appending no event at all.
            return store.view(conn, row)
        raise ExecutionError("INVALID_STATE")
    # What ExecBound could check about this settlement. A checkpoint is the row carrying a
    # report window, the marker admission stamps under a Gate mapping and no runtime
    # statement can change; an operation ExecBound dispatched settles at no tier at all,
    # because a tier is a statement about an external executor's word and a provider
    # journal is not one. What keeps that from being a tier this function failed to write
    # is `_never_executor_evidence`, which refuses an external executor's verifier against
    # a row with no window: the envelope kind is not a fact this function can read.
    tier: SettlementTier | None = None
    if row["report_expires_at"] is not None:
        tier = verified_tier if verified else "ASSERTED"
    # The NONEXECUTION state below — the refund — is written for exactly one outcome, and
    # the guard above means only a verifier can have returned it. A failure whose effect is
    # not established confirms the impact, which is the same charge a success writes.
    confirmed = evidence.outcome != "FAILED_NOT_EXECUTED"
    settled_at = store.now(clock)
    conn.execute(
        text(
            "UPDATE execbound.execution_impact SET state=:s,confirmed_at=:n "
            "WHERE tenant_id=:t AND execution_id=:e"
        ),
        {
            "s": "CONFIRMED" if confirmed else "NONEXECUTION",
            "n": settled_at if confirmed else None,
            "t": row["tenant_id"],
            "e": row["execution_id"],
        },
    )
    if verified:
        # The asymmetry settlement turns on: an executor that could free the target by
        # claiming success would take a grant, report without acting and re-request the same
        # target at once, with nothing detectable in the lie. An assertion therefore leaves
        # the claim standing until the act window has passed, when ``recovery_run.recover``
        # releases it. Nothing in this module does, and no later report promotes an
        # assertion: ``_reportable`` refuses every report against a settled row but its own
        # restatement.
        #
        # ``AND released_at IS NULL`` is for the correction alone: the recovery run may
        # already have released this claim at the act window and appended
        # ``execution.claim_released`` naming that instant, and a correction must not
        # rewrite when a target was freed. Against an unsettled row it is a no-op, because
        # ``release_claim`` refuses a row not settled at tier ASSERTED, so such a row's
        # claim is still held — and an unsettled row is what reached this line before the
        # correction existed.
        #
        # What it is not is a guard against a settled row arriving here with a released
        # claim, and the reason is not that none arrives. One does: ``reconcile`` hands this
        # function a settled row ExecBound *dispatched*, its claim released by its own
        # earlier settlement, because ``_unsettled_grant_only``'s predicate is a report
        # window *and* a settled state and such a row carries no window. What keeps that
        # harmless is the terminal branch above, which answers before this line — the view
        # for a restatement, INVALID_STATE otherwise. Measured by
        # ``test_a_settled_dispatched_row_reaches_settle_with_its_claim_already_released``.
        conn.execute(
            text(
                "UPDATE execbound.resource_claims SET released_at=:n "
                "WHERE tenant_id=:t AND execution_id=:e AND released_at IS NULL"
            ),
            {"n": settled_at, "t": row["tenant_id"], "e": row["execution_id"]},
        )
    if isinstance(evidence, TerminalEvidence) and evidence.window_ms is not None:
        # The gap a connector measured between the read it compared and the write that
        # followed. It is known only once the exchange has happened, which is here and not
        # at the attempt: `take_dispatch` commits the one send attempt *before* the
        # connector runs, so nothing at that point could have measured anything. The column
        # is a projection for the pages; the authority is the signed record retained in
        # `result` beside it, which is what an export carries into replay.
        conn.execute(
            text(
                "UPDATE execbound.executions SET precondition_window_ms=:w "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {
                "w": evidence.window_ms,
                "t": row["tenant_id"],
                "e": row["execution_id"],
            },
        )
    retained = evidence.model_dump(mode="json")
    conn.execute(
        text(
            "UPDATE execbound.executions SET result=CAST(:r AS jsonb),settlement_tier=:tier "
            "WHERE tenant_id=:t AND execution_id=:e"
        ),
        {
            # The result and the tier are written together in the one transaction that
            # settles the row, so no checkpoint can carry retained evidence without the
            # tier that says what it is worth, and a checkpoint's retained copy names that
            # tier inside the evidence object as well, so an export is self-describing.
            # An operation ExecBound dispatched has no tier to carry, because a tier is a
            # statement about an external executor's word: the column stays null and the
            # retained value is the evidence alone, which is the document this statement
            # wrote for it before a tier existed.
            "r": canonical_json(retained if tier is None else {**retained, "tier": tier}),
            "tier": tier,
            "t": row["tenant_id"],
            "e": row["execution_id"],
        },
    )
    # Replay treats the presence of terminal evidence as verification, so an assertion is
    # retained under a key of its own rather than as `evidence`. The tier is named beside
    # the evidence rather than inside it, because these are the bytes replay validates as
    # a TerminalEvidence and that model admits no extra field; it appears on exactly the
    # transitions whose settlement_tier column is written, so an operation ExecBound
    # dispatched keeps the payload it has always had.
    settlement: dict[str, Any] = {"evidence": retained} if verified else {"asserted": retained}
    if tier is not None:
        settlement["tier"] = tier
    store.transition(
        conn,
        row,
        actor,
        terminal_state,
        clock,
        semantic_time=settled_at,
        reason=reason,
        **settlement,
    )
    return store.view(conn, row)


def _never_executor_evidence(row: dict[str, Any], verifier: EvidenceVerifier) -> None:
    """Refuse checkpoint evidence for an operation ExecBound dispatched.

    The mirror of ``reconciliation._executor_evidence_only``, which refuses a grant settled
    from anything but checkpoint evidence. This refuses the other pairing of the same two
    facts: a row carrying no report window, settled from a verifier that declares it
    attests an external execution. The runtime's checkpoint side is one
    ``provider.checkpoint_evidence.CheckpointVerifier``, which checks either an executor's
    record or a provider's checkpoint journal and declares so of both, and the dispatch
    path never accepts either: a journal the provider signed for a checkpoint is refused
    here as an executor's record is, before a byte of it is read. Neither row is the
    other's, and a settlement that rests on the wrong kind of evidence for the row it names
    is refused rather than recorded.

    ``_settle`` cannot make this refusal itself. It is handed a ``TerminalEvidence`` whose
    ``authenticated_record`` is an opaque string, and ``execution`` imports nothing from
    ``provider``, so which envelope that string holds is knowable only to the verifier that
    parsed it — which is why the marker is a named attribute on the verifier rather than an
    ``isinstance``, exactly as it is in ``_executor_evidence_only``. ``getattr`` keeps its
    default, so a runtime duck type that answers nothing is treated as not attesting an
    external execution; ``EvidenceVerifier`` declares the member, so every verifier the
    composition boundary builds answers it and strict mypy says so at each call site.

    What leaving this pairing open costs is not only a wrong record retained. ``_settle``
    derives the tier from ``report_expires_at`` alone, so such a settlement writes an
    executor's ``SignedOutcome`` under ``evidence`` with no tier beside it, and
    ``replay/verify.py:_terminal`` reads the tier to choose which envelope to parse: it
    would parse that record as a ``SignedJournal``, raise, and end the tenant's history
    export. Audit events are append-only and the export covers the whole chain, so that is
    permanent and per tenant.

    Its callers are ``record_outcome`` below, in its first transaction, and
    ``reconciliation.reconcile`` in both of its two. ``record_outcome`` asks once because
    its fenced read cannot change the answer: the verifier is the caller's and is fixed for
    the call, and ``_never_a_checkpoint`` under the fence refuses the one row change that
    could matter, a report window appearing. ``reconcile`` asks twice because it rebuilds
    its verifier under the fence from ``verifier_for``, and because only the fenced read of
    the marker is ordered against every other writer. ``_settle``'s third caller,
    ``_settle_report``, needs no call of its own: ``_reportable`` refuses a row whose
    ``report_expires_at`` is null before any of it, so the report route reaches settlement
    for a checkpoint alone.
    """
    if row["report_expires_at"] is None and getattr(verifier, "attests_external_execution", False):
        raise ExecutionError("INVALID_STATE")


def record_outcome(
    db: Database,
    ticket: DispatchTicket,
    evidence: bytes,
    verifier: EvidenceVerifier,
    clock: Clock | None = None,
) -> ExecutionView:
    clock = clock or SystemClock()
    try:
        with db.transaction(ticket.tenant_id) as conn:
            row = _owner(conn, ticket)
            if row["dispatch_attempted_at"] is None:
                raise ExecutionError("INVALID_STATE")
            _never_a_checkpoint(row)
            # Before the evidence is verified, so an operation ExecBound dispatched never
            # has an external executor's record checked against its frozen command.
            _never_executor_evidence(row, verifier)
            command = store.command(row)
        proof = _proof(command, evidence, verifier)
        with db.transaction(ticket.tenant_id) as conn:
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, ticket.tenant_id, clock)
            row = _owner(conn, ticket)
            _never_a_checkpoint(row)
            result = _settle(conn, row, row["principal_id"], proof, clock, "PROVIDER_RESPONSE")
        return result
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None


def _accepted(
    conn: Connection,
    identity: Identity,
    row: dict[str, Any],
    report: OutcomeReport,
    reported: ReportedOutcome,
) -> None:
    """Capture that the executor reported, at the tier its evidence supports.

    An ordinary capture in the tenant's hash chain, carrying identifiers and the
    classification and never the report secret. ``reported_at`` is the executor's own
    clock and is null for a report carrying evidence, whose reported time is inside the
    bytes that were signed; it is never a confirmation time, which settlement stamps from
    the gateway's own clock. Appended by ``_settle_report`` alone, and only for a report
    that moves the execution, so the capture and what it did to the row are written
    together.

    ``tier`` here and the settlement's ``tier`` are different facts under one key,
    deliberately: this says what the report's evidence was worth, and the transition and
    the ``settlement_tier`` column say what a settlement was worth. They part company on an
    asserted non-execution, where this capture reads ASSERTED and the row that report
    leaves carries no tier at all, because that row is not a settled one. Anything reading
    both — the replay of the tier and the human pages among them — is reading two answers
    to two questions and not one answer twice.
    """
    append_event(
        conn,
        row["tenant_id"],
        identity.principal_id,
        "execution.outcome_reported",
        {
            "execution_id": str(row["execution_id"]),
            "operation_id": str(row["operation_id"]),
            "plan_hash": row["plan_hash"],
            "outcome": reported.outcome,
            "reason": reported.reason,
            "tier": reported.tier,
            "reported_at": None if report.reported_at is None else report.reported_at.isoformat(),
        },
    )


def _settle_report(
    conn: Connection,
    identity: Identity,
    row: dict[str, Any],
    report: OutcomeReport,
    reported: ReportedOutcome,
    clock: Clock,
) -> ExecutionView:
    """Apply what this report amounts to, or answer the row it did not move.

    A report is captured and applied exactly when it changes the execution, and a report
    that leaves the state it found is answered with that state and appends nothing. That
    is what bounds the accepted route: the state machine lets one grant move at most
    twice, once into retained uncertainty and once out of it, so however many times a
    leaked report secret is presented it buys a repeat of an answer and two captures. A
    refused report is audited as every refused request in the kernel is, by ``_rejection``,
    and that volume is bounded by the surfaces' own rate limits and by nothing here. A
    settled row reaches this function only restating its own settlement, because
    ``_reportable`` refuses every other report against one.
    """
    state = _state_after(reported)
    if state == row["state"]:
        return store.view(conn, row)
    _accepted(conn, identity, row, report, reported)
    settles: TerminalEvidence | AssertedOutcome | None = reported.proof
    if settles is None and state != "INDETERMINATE":
        # An assertion settles exactly when the state it leaves is not retained
        # uncertainty. INDETERMINATE is the rule, rather than an enumeration of the settled
        # states an assertion can reach, because what decides is whether anything is
        # settled at all; ``_settle``'s own guard is what refuses an assertion that would
        # settle a non-execution.
        settles = reported.asserted
    if settles is not None:
        # The tier ``_reported`` returned only once the verifier that checked the evidence
        # answered that same tier, so what reaches ``_settle`` is the verifier's answer.
        verified_tier: VerifiedTier = "ATTESTED"
        if reported.proof is not None and reported.tier == "PROVIDER_VERIFIED":
            verified_tier = "PROVIDER_VERIFIED"
        return _settle(
            conn,
            row,
            identity.principal_id,
            settles,
            clock,
            "EXECUTOR_REPORT",
            verified_tier=verified_tier,
        )
    # Retained uncertainty: the impact stays charged, the claim stays held and nothing is
    # settled, which is the treatment a lost provider response already gets. The executor's
    # word is retained where it can be read, never as terminal evidence and under no tier,
    # because the row this leaves behind is not a settled one.
    spoken: dict[str, Any] = {}
    if reported.asserted is not None:
        spoken["asserted"] = reported.asserted.model_dump(mode="json")
    store.transition(
        conn, row, identity.principal_id, state, clock, reason="EXECUTOR_REPORT", **spoken
    )
    return store.view(conn, row)


def report_outcome(
    db: Database,
    identity: Identity,
    execution_id: UUID,
    raw: bytes,
    *,
    verifier_for: VerifierFactory,
    clock: Clock | None = None,
) -> ExecutionView:
    """Accept an external executor's authenticated report of what it did with its grant.

    The caller is the principal the grant was issued to, authenticated as it was when it
    asked, and the report secret is what binds this report to that one execution. What the
    report amounts to is decided between the two transactions: verified evidence, an
    assertion, or an unknown result that is neither — and again under the fence, where the
    row that has just been re-read is what any of it applies to and where a settlement may
    rest on it.

    An unfenced verification first, so an executor cannot serialize a tenant's writers
    with the cost of checking a signature: evidence that does not verify is refused before
    the fenced transaction opens, so what a caller presenting it can make the tenant's
    writers wait for is unchanged. What the fenced answer adds is that the key ring the
    settlement rests on was read under the fence. A key's own instants are weighed against
    `dispatch_attempted_at`, which is stamped once, so a registration or a retirement
    landing between the two reads decides nothing either way; a compromise is retroactive
    by construction, and one committing in that window used to go unseen, settling
    ATTESTED on a stolen key and — for a signed non-execution — refunding the reservation
    and releasing the canonical claim.
    """
    clock = clock or SystemClock()
    try:
        report = parse_report(raw)
        with db.transaction(identity.tenant_id) as conn:
            store.identity_check(conn, identity, clock, "AGENT")
            row = _reportable(conn, identity, execution_id, report, clock)
            command = store.command(row)
            verifier = None if not report.signed else _verifier(conn, row, verifier_for)
        if verifier is not None:
            # Refused here, outside every transaction, so evidence that does not verify
            # never reaches the fence and checking a signature stays work no caller can
            # make a tenant's writers wait for. What this answers is thrown away: the
            # settlement below rests on the ring the fenced transaction read.
            _reported(command, report, verifier)
        with db.transaction(identity.tenant_id) as conn:
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, identity.tenant_id, clock)
            store.identity_check(conn, identity, clock, "AGENT")
            row = _reportable(conn, identity, execution_id, report, clock)
            fenced = None if not report.signed else _verifier(conn, row, verifier_for)
            reported = _reported(store.command(row), report, fenced)
            result = _settle_report(conn, identity, row, report, reported, clock)
            store.identity_check(conn, identity, clock, "AGENT")
        return result
    except ExecutionError as exc:
        _rejection(db, identity, "report", exc.code, clock)
        raise
    except (SQLAlchemyError, ValueError):
        _rejection(db, identity, "report", "DEPENDENCY_UNAVAILABLE", clock)
        raise ExecutionError() from None
