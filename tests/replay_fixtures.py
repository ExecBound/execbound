# SPDX-License-Identifier: AGPL-3.0-only
"""Pure replay histories with real policy results and independent synthetic journal bytes."""

import base64
import hashlib
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from execbound.audit import GENESIS, _event_hash, canonical_json
from execbound.execution.models import AssertedOutcome, DispatchCommand, TerminalEvidence
from execbound.policy.evaluate import evaluate
from execbound.provider.executor import ExecutorRecord, SignedOutcomeJws, sign_outcome
from execbound.provider.models import (
    CredentialState,
    CredentialTransition,
    EndpointState,
    EndpointTransition,
    IdentityState,
    IdentityTransition,
    JournalRecord,
    ProviderAccount,
    provider_command,
    sign_record,
)
from execbound.replay.models import (
    ApprovalCapture,
    AuditEvent,
    DecisionCapture,
    HistoricalIdentity,
    ReplayExport,
    TrustedHead,
)
from execbound.replay.verify import verify_export
from execbound.resolution.models import intent_hash, plan_hash


def replay_case(action="endpoint.isolate", production=False):
    if action != "endpoint.isolate":
        from test_identity_policy import scenario

        return scenario(action, production)
    from test_policy_evaluation import change_fact, scenario

    case = scenario.__wrapped__()
    if production:
        case["resolved"] = change_fact(case["resolved"], "environment", value="production")
        case["resolved"] = change_fact(case["resolved"], "is_production", value=True)
    return case


# Security versions of the bundle each capture was evaluated under, keyed by execution.
# Admission records the frozen plan hash on every transition event, including a denial
# that never bound a plan, so transition_event needs them when the decision has none.
_SECURITY_VERSIONS = {}


def make_capture(case=None, *, groups=(), **changes):
    """A capture of ``case``; ``groups`` is the membership the gateway recorded for the agent.

    The default is the known-empty membership every capture written since groups existed
    carries; ``None`` makes a legacy capture recorded before membership was captured.
    """
    case = replay_case() if case is None else case
    identity, now = case["identity"], case["clock"].now()
    historical = HistoricalIdentity(
        tenant_id=identity.tenant_id,
        principal_id=identity.principal_id,
        credential_id=identity.credential_id,
        kind=identity.kind,
        issued_at=now - timedelta(hours=1),
        expires_at=identity.expires_at,
        groups=groups,
    )
    values = dict(
        stage="ADMISSION",
        execution_id=uuid4(),
        operation_id=uuid4(),
        canonical_target_id=uuid4(),
        semantic_time=now,
        usage_time=now,
        finished_time=now,
        identity=historical,
        frozen=case["resolved"],
        bundle_id=case["bundle"].bundle_id,
        decision=evaluate(**case),
    )
    capture = DecisionCapture(**(values | changes))
    _SECURITY_VERSIONS[capture.execution_id] = case["bundle"].security_versions
    return capture


def transition_event(capture, before, after, *, semantic_time=None, **payload):
    binding = capture.decision.plan_hash
    if binding is None:
        versions = _SECURITY_VERSIONS.get(capture.execution_id)
        if versions is None:
            raise KeyError("Create captures with make_capture so their bundle versions are known")
        binding = plan_hash(capture.frozen, versions)
    return (
        "execution.transition",
        {
            "execution_id": str(capture.execution_id),
            "from_state": before,
            "to_state": after,
            "intent_hash": intent_hash(capture.frozen.intent),
            "plan_hash": binding,
            "operation_id": str(capture.operation_id),
            "replay": {
                "version": 1,
                "semantic_time": (semantic_time or capture.semantic_time).isoformat(),
            },
            **payload,
        },
    )


def chain_export(
    entries: Iterable,
    bundles=(),
    *,
    tenant_id: UUID | None = None,
    actor_id: UUID | None = None,
    wall_time: datetime | None = None,
):
    entries = list(entries)
    captures = [entry for entry in entries if isinstance(entry, DecisionCapture)]
    tenant = tenant_id or (
        captures[0].identity.tenant_id if captures else bundles[0].tenant_id if bundles else uuid4()
    )
    attempted = next(
        (
            entry[1]
            for entry in entries
            if not isinstance(entry, DecisionCapture)
            and entry[0] == "execution.transition"
            and "frozen" in entry[1]
        ),
        None,
    )
    actor = actor_id or (
        captures[0].identity.principal_id
        if captures
        else UUID(attempted["frozen"]["intent"]["principal_id"])
        if attempted
        else uuid4()
    )
    previous, events = GENESIS, []
    for sequence, entry in enumerate(entries, start=1):
        kind, payload = (
            ("execution.evaluated", entry.model_dump(mode="json"))
            if isinstance(entry, DecisionCapture)
            else entry
        )
        row = dict(
            tenant_id=tenant,
            sequence=sequence,
            event_id=uuid4(),
            actor_id=actor_id
            or (
                entry.reviewer.principal_id
                if isinstance(entry, DecisionCapture) and entry.reviewer is not None
                else entry.identity.principal_id
                if isinstance(entry, DecisionCapture)
                else UUID(payload["binding"]["decided_by"])
                if kind == "approval.transition"
                and payload["to_state"] in {"APPROVED", "DENIED"}
                and payload.get("binding", {}).get("decided_by")
                else actor
            ),
            kind=kind,
            occurred_at=wall_time or datetime.now(UTC),
            payload=payload,
            previous_hash=previous,
        )
        row["event_hash"] = _event_hash(row)
        events.append(AuditEvent(**row))
        previous = row["event_hash"]
    return ReplayExport(
        tenant_id=tenant,
        events=tuple(events),
        head=TrustedHead(tenant_id=tenant, sequence=len(events), event_hash=previous),
        bundles=tuple(bundles),
    )


def make_history(entries, bundles=(), **kwargs):
    export = chain_export(entries, bundles, **kwargs)
    return verify_export(export, export.head)


def terminal_evidence(capture, *, outcome="EXECUTED", occurred_at=None):
    command = provider_command(
        DispatchCommand(
            execution_id=capture.execution_id,
            canonical_target_id=capture.canonical_target_id,
            operation_id=capture.operation_id,
            intent_hash=intent_hash(capture.frozen.intent),
            plan_hash=capture.decision.plan_hash,
            frozen=capture.frozen,
        )
    )
    executed = outcome == "EXECUTED"
    transition_value = endpoint_value = credential_value = None
    if command.provider == "mock_entra" and executed:
        transition_value = IdentityTransition(
            before=IdentityState(account_enabled=True, session_generation=1),
            after=IdentityState(
                account_enabled=command.action != "identity.disable",
                session_generation=2 if command.action == "identity.revoke_sessions" else 1,
            ),
        )
    # Operation-specific evidence the journal contract requires of the new actions.
    if executed and command.action == "endpoint.lift_isolation":
        endpoint_value = EndpointTransition(
            before=EndpointState(contained=True), after=EndpointState(contained=False)
        )
    if executed and command.action == "identity.reset_password":
        credential_value = CredentialTransition(
            before=CredentialState(password_generation=0, must_change_password=False),
            after=CredentialState(
                password_generation=1,
                must_change_password=command.arguments.root["require_change_at_next_sign_in"],
            ),
        )
    record = JournalRecord(
        command=command,
        command_hash=command.command_hash,
        outcome=outcome,
        occurred_at=occurred_at or capture.semantic_time,
        resulting_version="result-v2" if executed or outcome == "VERSION_MISMATCH" else None,
        mutation_count=1 if executed else 0,
        identity_transition=transition_value,
        endpoint_transition=endpoint_value,
        credential_transition=credential_value,
    )
    account = ProviderAccount(
        command.tenant_id,
        command.account_id,
        "a" * 64,
        "b" * 64,
        b"fixture-only-provider-signing-key-32",
        provider=command.provider,
    )
    signed = sign_record(record, account).model_dump_json()
    return TerminalEvidence(
        operation_id=command.operation_id,
        account_id=command.account_id,
        intent_hash=command.intent_hash,
        plan_hash=command.plan_hash,
        outcome="EXECUTED" if outcome == "EXECUTED" else "FAILED_NOT_EXECUTED",
        reason=outcome,
        proof_digest=hashlib.sha256(signed.encode()).hexdigest(),
        authenticated_record=signed,
    )


def approved_entries(case):
    """A complete proposed human review, committed decision and one consumption."""
    first = make_capture(case)
    assert first.decision.effect == "REQUIRE_APPROVAL"
    # Only the agent's membership is recorded; a human identity carries no groups key.
    human = first.identity.model_copy(
        update={
            "principal_id": uuid4(),
            "credential_id": uuid4(),
            "kind": "HUMAN_APPROVER",
            "groups": None,
        }
    )
    approval = ApprovalCapture(
        status="PROPOSED",
        approval_id=uuid4(),
        tenant_id=first.identity.tenant_id,
        principal_id=first.identity.principal_id,
        bundle_id=first.bundle_id,
        plan_hash=first.decision.plan_hash,
        obligation_ids=first.decision.obligation_ids,
        expires_at=first.semantic_time + timedelta(seconds=120),
        approver=human,
        canonical_target_id=first.canonical_target_id,
        action=first.frozen.intent.action,
    )
    result = evaluate(**case, approval=approval.to_verified_approval())
    review = first.model_copy(
        update={
            "stage": "APPROVAL_REVIEW",
            "reviewer": human,
            "human_decision": "APPROVE",
            "approval": approval,
            "decision": result,
        }
    )
    admission = first.model_copy(
        update={"approval": approval.model_copy(update={"status": "VERIFIED"}), "decision": result}
    )
    binding = dict(
        approval_id=str(approval.approval_id),
        principal_id=str(first.identity.principal_id),
        bundle_id=str(first.bundle_id),
        plan_hash=approval.plan_hash,
        obligation_ids=list(approval.obligation_ids),
        expires_at=approval.expires_at.isoformat(),
        created_at=first.semantic_time.isoformat(),
        decided_at=None,
        decided_by=None,
        decided_credential_id=None,
    )
    approved = {
        **binding,
        "decided_by": str(human.principal_id),
        "decided_credential_id": str(human.credential_id),
        "decided_at": first.semantic_time.isoformat(),
    }

    def approval_event(before, after):
        return (
            "approval.transition",
            dict(
                execution_id=str(first.execution_id),
                approval_id=str(approval.approval_id),
                from_state=before,
                to_state=after,
                plan_hash=approval.plan_hash,
                binding=approved,
                replay={"version": 1, "semantic_time": first.semantic_time.isoformat()},
            ),
        )

    proof = terminal_evidence(admission)
    return [
        transition_event(
            first,
            None,
            "ATTEMPTED",
            frozen=first.frozen.model_dump(mode="json", exclude={"request"}),
            canonical_target_id=str(first.canonical_target_id),
            bundle_id=str(first.bundle_id),
        ),
        first,
        transition_event(first, "ATTEMPTED", "PENDING_APPROVAL", approval=binding),
        review,
        approval_event("PENDING", "APPROVED"),
        admission,
        approval_event("APPROVED", "CONSUMED"),
        transition_event(admission, "PENDING_APPROVAL", "RESERVED", approved=True),
        transition_event(admission, "RESERVED", "DISPATCH_COMMITTED"),
        transition_event(
            admission, "DISPATCH_COMMITTED", "EXECUTED", evidence=proof.model_dump(mode="json")
        ),
    ]


def executor_evidence(capture, *, outcome="EXECUTED", key_id="executor-v1", **changes):
    """What an attested checkpoint settlement retains: the external executor's own envelope.

    ExecBound verified this against a public key an administrator registered and retained
    what it verified, exactly as it retains a provider's signed journal for an operation it
    dispatched. The private half belongs to the executor, so one is generated here and
    thrown away: an export carries no public key and replay checks no signature.

    ``outcome`` is the terminal reason, as it is for ``terminal_evidence`` beside this.
    """
    record = ExecutorRecord(
        **{
            "operation_id": capture.operation_id,
            "account_id": capture.frozen.intent.account_id,
            "intent_hash": intent_hash(capture.frozen.intent),
            "plan_hash": capture.decision.plan_hash,
            "outcome": "EXECUTED" if outcome == "EXECUTED" else "FAILED_NOT_EXECUTED",
            "reason": outcome,
            "reported_at": capture.semantic_time,
            **changes,
        }
    )
    signed = sign_outcome(record, key_id, Ed25519PrivateKey.generate()).model_dump_json()
    return TerminalEvidence(
        operation_id=record.operation_id,
        account_id=record.account_id,
        intent_hash=record.intent_hash,
        plan_hash=record.plan_hash,
        outcome=record.outcome,
        reason=record.reason,
        proof_digest=hashlib.sha256(signed.encode()).hexdigest(),
        authenticated_record=signed,
    )


def _segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def attested_jws_evidence(capture, *, key_id="tines-jwt-2026", **changes):
    """What an ES256 attested settlement retains: the executor's JWS as its flattened wrapper.

    As `executor_evidence`, the private key is generated and thrown away. The claims are
    base64url inside the wrapper, so its identifiers are not text a reader of the export sees.
    """
    claims = {
        "domain": "execbound.executor.outcome",
        "version": 1,
        "operation_id": str(capture.operation_id),
        "account_id": str(capture.frozen.intent.account_id),
        "intent_hash": intent_hash(capture.frozen.intent),
        "plan_hash": capture.decision.plan_hash,
        "outcome": "EXECUTED",
        "reason": "EXECUTED",
        "reported_at": capture.semantic_time.isoformat().replace("+00:00", "Z"),
        **changes,
    }
    head = _segment(canonical_json({"alg": "ES256", "kid": key_id}).encode())
    body = _segment(canonical_json(claims).encode())
    der = ec.generate_private_key(ec.SECP256R1()).sign(
        f"{head}.{body}".encode("ascii"), ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(der)
    signed = SignedOutcomeJws(
        format="jws-es256",
        key_id=key_id,
        protected=head,
        payload=body,
        signature=_segment(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
    ).model_dump_json()
    return TerminalEvidence(
        operation_id=capture.operation_id,
        account_id=capture.frozen.intent.account_id,
        intent_hash=claims["intent_hash"],
        plan_hash=claims["plan_hash"],
        outcome=claims["outcome"],
        reason=claims["reason"],
        proof_digest=hashlib.sha256(signed.encode()).hexdigest(),
        authenticated_record=signed,
    )


def asserted_outcome(capture, *, outcome="EXECUTED", **changes):
    """What an asserted settlement retains: the executor's authenticated word and no proof."""
    return AssertedOutcome(
        **{
            "operation_id": capture.operation_id,
            "account_id": capture.frozen.intent.account_id,
            "intent_hash": intent_hash(capture.frozen.intent),
            "plan_hash": capture.decision.plan_hash,
            "outcome": "EXECUTED" if outcome == "EXECUTED" else "FAILED_NOT_EXECUTED",
            "reason": outcome,
            "reported_at": capture.semantic_time,
            **changes,
        }
    )
