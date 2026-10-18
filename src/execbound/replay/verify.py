# SPDX-License-Identifier: AGPL-3.0-only
"""Verify immutable replay inputs without network, signing keys or live state."""

import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any, Literal, cast, get_args
from uuid import UUID

from pydantic import AwareDatetime

from execbound.audit import canonical_json, verify_chain
from execbound.execution.models import (
    AssertedOutcome,
    DispatchCommand,
    PreconditionClass,
    SettlementTier,
    TerminalEvidence,
)
from execbound.policy.models import BundleContent
from execbound.provider.connector_record import ConnectorExchange, ConnectorRecord
from execbound.provider.executor import ExecutorRecord, recorded_outcome
from execbound.provider.models import (
    GRAPH_PROVIDER,
    ProviderCommand,
    SignedJournal,
    parse_provider,
    provider_command,
)
from execbound.replay.models import (
    MAX_EXPORT_BYTES,
    AuditEvent,
    DecisionCapture,
    ReplayExport,
    StopPeriod,
    TrustedHead,
    VerifiedEvent,
    VerifiedHistory,
    VersionedModel,
    plain_json,
)
from execbound.requests import _reject_number, _unique_object
from execbound.resolution.models import CanonicalIntent, intent_hash, plan_hash
from execbound.secrets import find_secrets

_INFORMATIONAL = frozenset(
    {
        "demo.provisioned",
        "execution.rejected",
        # A tenant changed how long new approvals may wait. Each approval records the
        # expiry it was created with, so this explains a later deadline and decides nothing.
        "tenant.approval_deadline_changed",
        "execution.dispatch_attempt",
        # A grant issued or re-issued for an externally executed operation. The decision,
        # the reservation and the claim are the transition events beside it; this one adds
        # the deadlines and the precondition class and changes nothing.
        "execution.checkpoint_granted",
        # An external executor's accepted report, at the tier its evidence supports. The
        # settlement it leads to is the transition event beside it.
        "execution.outcome_reported",
        # A control point reported on a call ExecBound denied, or on one whose own inputs
        # derive something other than the request the decision froze. Evidence of a
        # fail-open configuration or a bypass and never a proven one, and it decides
        # nothing a replay recomputes: the settlement beside it is what moved the row.
        "execution.control_point_contradiction",
        # The scheduled run releasing the canonical claim an asserted settlement held once
        # the act window closed. The execution stays settled at the tier and the impact it
        # already had, so this changes no decision of its own; what it frees is the target,
        # and a later request for it is its own admission with its own capture.
        "execution.claim_released",
        "approval.decision_recorded",
        "tenant.mode_changed",
        "execution.reconciliation_requested",
        "execution.cancellation_requested",
        "human_session.issued",
        "human_session.revoked",
        "workspace.entered",
        "account_security.signed_out",
        "account_security.other_devices_signed_out",
        "account_security.password_changed",
        # A first password on an account that had none (#593); it decides nothing replay reads.
        "account_security.password_set",
        # A password reset from an emailed link (#678). It explains later facts, a new password
        # and the sessions and tokens it ended, each recorded by its own informational event,
        # and decides nothing replay recomputes, the reasoning `tenant.provisioned` carries.
        "account_security.password_reset",
        "account_security.provider_link_started",
        "account_security.provider_linked",
        # Account administration and authentication evidence explain access to the console.
        # They do not authorize an agent action or settle provider effects; those decisions
        # retain their own captured policy, context and execution transitions.
        "account.profile",
        "account.preferences",
        "account.request",
        "account.resolve",
        "account_security.enrollment_started",
        "account_security.verification_failed",
        "account_security.code_reused",
        # A workspace switch carried the session's recent verification into the new session;
        # it records how and when the factor was verified and decides nothing replay recomputes.
        "account_security.assurance_carried",
        "account_security.factor_enabled",
        "account_security.recovery_used",
        "account_security.verified",
        "account_security.factor_disabled",
        "account_security.recovery_replaced",
        "account_security.requirement_changed",
        "account_security.passkey_added",
        "account_security.passkey_removed",
        # How a person proved who they were before the session was issued. A sign-in decides
        # nothing a replay recomputes: the session beside it is what carries the authority,
        # and the role came from the person's own row either way.
        "human_sign_in.password",
        "human_sign_in.google",
        "human_sign_in.github",
        "human_sign_in.microsoft",
        # The sign-in facts an administrator or the owner connection set: an address, a
        # one-time code, a password written or replaced, a directory account bound. None of
        # them is authority; each is how somebody reaches a session they already qualify for.
        "person.email_set",
        "password.reset_issued",
        "password.set",
        "password.changed",
        "identity.linked",
        # A customer's own identity provider (#177, #241). Registering, verifying, enabling
        # and disabling a provider, inviting and linking a person, and a sign-in through one
        # decide nothing a replay recomputes: what they change is who may open a page, and
        # every decision a replay checks is still the kernel's.
        "identity.unlinked",
        "identity.invited",
        "identity.invitation_revoked",
        "identity.recheck_refused",
        "identity_provider.registered",
        "identity_provider.verified",
        "identity_provider.enabled",
        "identity_provider.disabled",
        "human_sign_in.directory",
        # Owner-connection administration never changes a replayed decision.
        "approval_scope.assigned",
        "approval_scope.revoked",
        # Human roles and routing change who may review future or resumed work, as an
        # individual approval scope does. The resulting decisions and stale-authority
        # transitions are retained separately; replay never derives execution authority
        # or provider effects from these administrative events.
        "access.create_group",
        "access.update_group",
        "access.delete_group",
        "access.set_members",
        "access.group_member_added",
        "access.set_user_roles",
        "access.set_group_roles",
        "approval_rule.changed",
        "credential.issued",
        "credential.revoked",
        # A spent API key taken out of every list (0058). Its issue and revocation stay in
        # the chain; deleting changes nothing a decision or an execution relied on.
        "credential.deleted",
        # A personal access token minted, revoked or deleted from the console. The
        # identity it stands for is an ordinary credential-backed ADMIN identity, so these
        # add no execution authority a replay recomputes; they decide nothing.
        "personal_token.issued",
        "personal_token.revoked",
        "personal_token.deleted",
        "group.created",
        "group.assigned",
        "group.revoked",
        "executor_key.registered",
        "executor_key.rotated",
        "executor_key.revoked",
        # A key cut off as compromised. It is its own kind rather than a reason inside a
        # revocation's payload, because it is the one revocation the verifier reads
        # backwards and an incident should be one grep of the chain.
        "executor_key.compromised",
        "account.created",
        "mapping.created",
        "target.created",
        "resource.created",
        "principal.created",
        "context_source.created",
        "context_source.deactivated",
        # A signal source's registration, rotation and revocation decide nothing on their own:
        # a source counts only when a bundle's signal_mappings admits it, and every decision
        # that used one froze its records (#478).
        "signal_source.created",
        "signal_source.rotated",
        "signal_source.revoked",
        "context.imported",
        "policy.bundle_created",
        "policy.bundle_validated",
        "policy.bundle_activated",
        "policy.bundle_retired",
        # A bundle a space stopped selecting, which no other space still selects; it
        # decides nothing and is informational to replay, like every other lifecycle event.
        "policy.bundle_deselected",
        # Names the ruleset a bundle was compiled from, with counts; replay reads the bundle's
        # content from the export's own bundles, never from this payload.
        "policy.ruleset_compiled",
        # A draft's rules rewritten as a successor draft: it links the two, whose own
        # `policy.bundle_retired` and `policy.bundle_created` stand beside it. A draft decides
        # nothing until it is validated and selected, and every decision names the bundle and
        # content hash it used, which replay reads from the export's own bundles.
        "policy.rules_changed",
        # Space administration: ownership and view inside one tenant. None of it decides a
        # replayed decision; the chain is not split and the head is still one per tenant.
        "space.created",
        "space.renamed",
        "space.archived",
        "space.unarchived",
        "space.member_assigned",
        "space.member_unassigned",
        # A sandbox's provenance: seeded by the operator, then claimed by its first ADMIN,
        # or adopted as a slot after the fact. None of them decides anything.
        "sandbox.seeded",
        "sandbox.adopted",
        "tenant.claimed",
        # The operator's own record of a slot's invitation: minted, revoked and sent again. It
        # is appended to the operator's workspace, never to the slot's, and an invitation is
        # only a way to reach `tenant.claimed`, so none of them decides anything. They are
        # written only by a first-party plugin, through a helper that takes the kind as an
        # argument, so a scan for the kinds named in `append_event` calls cannot find them.
        "sandbox.invited",
        "sandbox.invitation_revoked",
        "sandbox.invitation_resent",
        # A workspace made by verified signup (#243). It records who was made its first
        # administrator and under which consent version; the tenant row, the principal and
        # its membership are facts in their own tables, so replay reads it and decides nothing.
        "tenant.provisioned",
        # Sample targets (#420): an administrator adding or removing a workspace's samples.
        # The registry rows are facts in their own tables and the starter bundle's lifecycle
        # events stand beside these, so replay reads them and decides nothing.
        "samples.installed",
        "samples.removed",
        # A plugin's sandbox lifecycle (#439): a sandbox's plan and lifecycle, and its agents'
        # dormancy. Each one only changes whether a *future* attempt can even be made — the
        # same shape as `credential.revoked` or `context_source.deactivated` above, both
        # already informational — and never touches an execution, approval or policy-bundle
        # decision already on the chain. `tenant.deactivated` and `tenant.expired` both set
        # `tenants.active = false`; nothing after that point can authenticate, so replay
        # simply finds nothing further for that tenant, exactly as a revoked credential
        # leaves nothing further for that principal. `tenant.fell_back` and
        # `tenant.converted` change `plan`, and `tenant.extended` changes the sandbox's end
        # date, the same way `tenant.approval_deadline_changed` above changes a deadline:
        # each explains a later fact and decides nothing itself. `agents.slept` and
        # `agents.woken` set and clear dormancy the same way `principal.created` grants
        # existence — a precondition for a future decision, never one itself. A sleeping
        # principal fails authentication before any decision event exists (the credential
        # check that would admit it runs first), the same way a revoked one does, so
        # `agents.slept` decides nothing already on the chain either.
        "tenant.fell_back",
        "tenant.deactivated",
        "tenant.expired",
        "tenant.converted",
        "tenant.extended",
        "agents.slept",
        "agents.woken",
        # A person switching a principal off by hand, and back on; the console's Reactivate
        # is also how an administrator wakes a sleeping agent (#439). Both change only
        # whether that principal can authenticate, by the same reasoning as `agents.slept`
        # and `agents.woken` above: a principal that cannot authenticate produces no
        # decision event, and one that can again carries its own capture into every later
        # decision, which is verified on its own terms. Neither is an input
        # `_verified_events` or `history.index_history` recomputes: no decision capture,
        # execution, approval or bundle transition reads a principal's active state, and the
        # credentials and sessions a deactivation ends are their own `credential.revoked`
        # and `human_session.revoked` events, already informational.
        "principal.deactivated",
        "principal.reactivated",
        # A principal's display name, set when the console adds a person or an agent and by
        # `person-invite`. Policy, captures and admission never read a label, so it decides
        # nothing; unknown to replay, it left every later decision unresolved (#478).
        "principal.labelled",
        # A discovered agent bound to a governed principal, or the binding withdrawn. Only
        # Monitoring and the Agents pages read a binding; no admission, policy or approval
        # does, and the principal's own requests carry their own captures either way.
        "agent.bound",
        "agent.unbound",
        # An administrator acknowledged a monitoring finding. It is a decision about the
        # finding, not about an action: only Monitoring reads `acknowledged_at`, and no
        # admission, policy, approval or bundle transition replay reconstructs does.
        "monitor.finding_acknowledged",
        # A monitoring connection created, its sealed key replaced, a collection asked for,
        # its schedule changed or the connection revoked (#678). Collection produces
        # observations and findings only; no admission, policy, approval or bundle
        # transition replay reconstructs reads a connection, so none of them decides anything.
        "monitor.connection_created",
        "monitor.key_replaced",
        "monitor.collection_requested",
        "monitor.schedule_changed",
        "monitor.connection_revoked",
        # A Tines tenant's egress addresses recorded on its connection (#355): what a
        # directory's sign-ins are matched against for driver evidence, which no decision reads.
        "monitor.egress_recorded",
        # A directory administrator's consent recorded on a Microsoft Entra connection (#678):
        # who started the attempt and which directory consented. Like the kinds above, it
        # decides nothing replay reconstructs.
        "monitor.consent_recorded",
        # The assistant switched on or off for a tenant. The assistant reads through the
        # asking person's session and writes nothing, so the switch decides nothing replay
        # reconstructs; the `replay` block its payload carries changes none of that.
        "tenant.assistant_changed",
        # The assistant's own record: a question asked, an explanation opened and a turn that
        # ended without an answer. It reads through the asking person's session and writes
        # nothing (B11), so none of them decides anything. They are written through the named
        # constants in `execbound.assistant`, which a scan of literal kinds cannot read.
        "assistant.asked",
        "assistant.explained",
        "assistant.refused",
        # Teammate invitations (#487): created, resent, revoked and accepted. None decides a
        # replayed execution, approval or policy-bundle transition. `invitation.created` and
        # `invitation.resent` only start or restart a delivery, the same shape as
        # `identity.invited`/`identity.recheck_refused` above; `invitation.revoked` only stops
        # one, the same shape as `identity.invitation_revoked`. `invitation.accepted` records
        # who joined and under which grants, but the grants themselves are applied through
        # `access_change` inside the same call, whose own `access.set_user_roles` decision is
        # retained as its own audit event; the membership and principal rows it creates are
        # facts in their own tables, exactly as `tenant.provisioned` above records a
        # signup's provisioning.
        "invitation.created",
        "invitation.resent",
        "invitation.revoked",
        "invitation.accepted",
        # The weekly summary (#678): a person turning their own opt-in on, or off from My
        # account or its one-click link (`via`). Neither decides an execution, an approval
        # or a bundle transition; the subscription is a fact in its own table, the same
        # shape as an invitation's start and stop above.
        "weekly_summary.subscribed",
        "weekly_summary.unsubscribed",
    }
)
_STOP_EVENTS = frozenset({"tenant.stop_activated", "tenant.stop_released"})
# Transitions only admission or a human decision can produce; settlement is always allowed.
_ADMISSION_STATES = frozenset(
    {"ATTEMPTED", "DENIED", "PENDING_APPROVAL", "RESERVED", "DISPATCH_COMMITTED", "OBSERVED"}
)
_DECISION_APPROVAL_STATES = frozenset({"APPROVED", "DENIED", "CONSUMED"})
_EXECUTION_STATES = frozenset(
    {
        "ATTEMPTED",
        "DENIED",
        "PENDING_APPROVAL",
        "RESERVED",
        "DISPATCH_COMMITTED",
        "EXECUTED",
        "FAILED_NOT_EXECUTED",
        "INDETERMINATE",
        "STALE_AUTHORIZATION",
        "OBSERVED",
        # Without this every export of a tenant holding one settled failure whose effect is
        # unknown would be UNSUPPORTED forever, since audit events are append-only: the
        # state is read here as one transition's `to_state` and as the correction's own
        # `from_state`.
        "FAILED_EFFECT_UNKNOWN",
    }
)
_APPROVAL_STATES = frozenset(
    {"PENDING", "APPROVED", "DENIED", "EXPIRED", "INVALIDATED", "CONSUMED"}
)


class _SemanticTime(VersionedModel):
    semantic_time: AwareDatetime


class ReplayValidationError(ValueError):
    def __init__(self, code: str = "INVALID_EXPORT") -> None:
        self.code = code
        super().__init__("Replay input unavailable")


def parse_export(raw: bytes) -> ReplayExport:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_EXPORT_BYTES:
            raise ValueError()
        json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        return ReplayExport.model_validate_json(raw)
    except (ValueError, TypeError, RecursionError):
        pass
    raise ReplayValidationError()


def referenced_bundle_ids(events: Iterable[AuditEvent]) -> frozenset[UUID]:
    refs: set[UUID] = set()

    def collect(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key == "bundle_id":
                    refs.add(_uuid(child, "INVALID_BUNDLE_REFERENCE"))
                else:
                    collect(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                collect(child)

    for event in events:
        collect(event.payload)
    return frozenset(refs)


def _uuid(value: Any, code: str = "INVALID_REFERENCE") -> UUID:
    if type(value) is str:
        try:
            result = UUID(value)
            if str(result) == value:
                return result
        except ValueError:
            pass
    raise ReplayValidationError(code)


def reject_secrets(value: Any) -> None:
    """Reject known credential/configuration fields; never redact hashed evidence.

    The definition lives in `execbound.secrets`. This guard only needs to know that one
    exists, so it stops the walk at the first finding, and it reports neither the path nor
    the kind: an export's refusal says `PRIVATE_DATA` and nothing more.
    """
    if find_secrets(value, limit=1):
        raise ReplayValidationError("PRIVATE_DATA")


def _capture(event: AuditEvent, bundles: dict[UUID, BundleContent]) -> DecisionCapture:
    capture = DecisionCapture.model_validate_json(canonical_json(plain_json(event.payload)))
    identity = capture.identity
    actor = identity if capture.stage == "ADMISSION" else capture.reviewer
    if (
        identity.tenant_id != event.tenant_id
        or actor is None
        or actor.principal_id != event.actor_id
    ):
        raise ReplayValidationError("INVALID_CAPTURE_SCOPE")
    if identity.issued_at > min(capture.usage_time, capture.semantic_time):
        raise ReplayValidationError("INVALID_CAPTURE_AUTHORITY")
    counted = list(capture.approval.approvers) if capture.approval else []
    for human in (
        capture.reviewer,
        capture.approval.approver if capture.approval else None,
        *counted,
    ):
        if human is not None and not (
            human.issued_at <= capture.semantic_time <= capture.finished_time < human.expires_at
        ):
            raise ReplayValidationError("INVALID_CAPTURE_AUTHORITY")
    bundle = bundles[capture.bundle_id]
    expected = plan_hash(capture.frozen, bundle.security_versions)
    if (
        capture.decision.content_hash != bundle.content_hash
        or (capture.decision.plan_hash is not None and capture.decision.plan_hash != expected)
        or (capture.decision.effect != "DENY" and capture.decision.plan_hash is None)
    ):
        raise ReplayValidationError("INVALID_CAPTURE_BINDING")
    approval = capture.approval
    if (
        approval is not None
        and capture.decision.effect != "DENY"
        and (
            approval.bundle_id != bundle.bundle_id
            or approval.plan_hash != expected
            or approval.obligation_ids != capture.decision.obligation_ids
        )
    ):
        raise ReplayValidationError("INVALID_APPROVAL_BINDING")
    return capture


def _capture_command(capture: DecisionCapture, bundle: BundleContent) -> ProviderCommand:
    return provider_command(
        DispatchCommand(
            execution_id=capture.execution_id,
            canonical_target_id=capture.canonical_target_id,
            operation_id=capture.operation_id,
            intent_hash=intent_hash(capture.frozen.intent),
            plan_hash=plan_hash(capture.frozen, bundle.security_versions),
            frozen=capture.frozen,
        )
    )


def _attempted_command(event: AuditEvent, bundles: dict[UUID, BundleContent]) -> ProviderCommand:
    payload = event.payload
    frozen = payload["frozen"]
    if not isinstance(frozen, Mapping):
        raise ReplayValidationError("INVALID_FROZEN_PLAN")
    intent = CanonicalIntent.model_validate_json(canonical_json(plain_json(frozen["intent"])))
    bundle = bundles[_uuid(payload["bundle_id"])]
    envelope = {
        key: plain_json(value)
        for key, value in frozen.items()
        if key not in {"request", "resolved_at"}
    }
    envelope.update(version=1, security_versions=bundle.security_versions.model_dump(mode="json"))
    expected_hash = hashlib.sha256(canonical_json(envelope).encode()).hexdigest()
    if (
        intent.tenant_id != event.tenant_id
        or intent.principal_id != event.actor_id
        or intent_hash(intent) != payload["intent_hash"]
        or expected_hash != payload["plan_hash"]
    ):
        raise ReplayValidationError("INVALID_FROZEN_PLAN")
    return ProviderCommand(
        tenant_id=intent.tenant_id,
        account_id=intent.account_id,
        canonical_target_id=_uuid(payload["canonical_target_id"]),
        provider=intent.provider,
        action=intent.action,
        provider_operation=intent.provider_operation,
        arguments=intent.arguments,
        resource_provider_id=frozen["resource_provider_id"],
        expected_version=frozen["resource_version"],
        operation_id=_uuid(payload["operation_id"]),
        execution_id=_uuid(payload["execution_id"]),
        intent_hash=payload["intent_hash"],
        plan_hash=payload["plan_hash"],
    )


def _bound(
    event: AuditEvent,
    command: ProviderCommand | None,
    recorded: ProviderCommand | ExecutorRecord | AssertedOutcome | ConnectorExchange,
    code: str,
) -> None:
    """The operation, the account and both hashes a retained record names, as settled.

    Every retained shape here names those four, because they are what settlement checked
    the evidence against before it wrote any of this. The transition carries three of
    them; the account comes from the frozen command, which is in this export whenever the
    execution's own authority capture is.
    """
    if (
        recorded.operation_id != _uuid(event.payload["operation_id"])
        or recorded.intent_hash != event.payload["intent_hash"]
        or recorded.plan_hash != event.payload["plan_hash"]
        or (
            command is not None
            and (recorded.operation_id, recorded.account_id)
            != (command.operation_id, command.account_id)
        )
    ):
        raise ReplayValidationError(code)


def _journal(
    event: AuditEvent, command: ProviderCommand | None, proof: TerminalEvidence
) -> tuple[ProviderCommand, str]:
    """A provider's own journal: the command it recorded and the reason it recorded.

    SignedJournal validates operation-specific state transitions and the exact command
    hash, and the whole frozen command it carries is compared against the one the capture
    froze. Its MAC is only retained gateway evidence, never reverified with a signing
    secret in this offline process.
    """
    recorded = parse_provider(proof.authenticated_record.encode(), SignedJournal).record
    if (
        command is not None
        and recorded.command != command
        or recorded.command.tenant_id != event.tenant_id
        or recorded.command.execution_id != _uuid(event.payload["execution_id"])
    ):
        raise ReplayValidationError("INVALID_TERMINAL_EVIDENCE")
    return recorded.command, recorded.outcome


def _executor(proof: TerminalEvidence) -> tuple[ExecutorRecord, str]:
    """An external executor's signed record: what it binds and the reason it states.

    ExecBound dispatched nothing here, so the retained record is the executor's own
    `SignedOutcome` envelope rather than a provider journal, and it carries no
    ProviderCommand to compare against: what it binds is the operation, the account and
    both hashes, which is the binding `outcomes._proof` checked before this evidence
    settled anything. It names no execution either, so what ties it to one is the
    operation the transition names and the record repeats; `executions` is UNIQUE on
    (tenant_id, operation_id), so inside one tenant's export that identifier names one
    execution.

    The signature is not rechecked, Ed25519 or ES256. Verifying it needs the public key an
    administrator registered, which `executor_keys` holds and no export carries, so the
    signature is retained provenance exactly as the journal's MAC is. An attested
    settlement is therefore evidence ExecBound verified and retained, and never proof that
    the vendor did anything.

    An ES256 attestation is retained as its `SignedOutcomeJws` wrapper rather than the
    Ed25519 envelope, and `recorded_outcome` is what reads either shape back into the same
    `ExecutorRecord`, exactly as the report route retains and reads it.
    """
    recorded = recorded_outcome(proof.authenticated_record)
    return recorded, recorded.reason


def _connector(proof: TerminalEvidence) -> tuple[ConnectorExchange, str]:
    """ExecBound's own signed account of a vendor exchange, for a vendor that co-signs none.

    Microsoft Graph returns no receipt and shares no secret, so what settled this execution
    is the record the connector made of its own read, comparison and write. Its MAC is not
    rechecked here for the same reason a journal's is not: the key is gateway configuration
    no export carries, so the signature is retained provenance.

    What this record uniquely carries is the measured window, and `_terminal` holds the
    retained evidence to it. That is the only place a window can enter a replay, which is
    what keeps a gap from ever being credited to a vendor that enforced the precondition
    itself: no other envelope has a field to carry one.
    """
    recorded = parse_provider(proof.authenticated_record.encode(), ConnectorRecord).record
    return recorded, recorded.outcome


def _terminal(
    event: AuditEvent, command: ProviderCommand | None, tier: str | None
) -> TerminalEvidence:
    """Retained terminal evidence, checked against the envelope its tier names.

    The tier says which envelope the authenticated record is, and there are now three
    answers rather than two: an external executor's `SignedOutcome`, Ed25519 or the ES256
    `SignedOutcomeJws` wrapper, at tier ATTESTED; a provider's `SignedJournal` of an
    operation performed for an external executor at tier PROVIDER_VERIFIED; and, where the
    settlement names no tier at all, either that same kind of `SignedJournal` for an
    operation ExecBound dispatched, or, when the captured command names the Graph provider,
    a `ConnectorExchange`. The tier is read before any parse, because these are different
    models and parsing one as another raises, which is the defect this reading fixes, one
    attested settlement having ended a tenant's whole history export and its bundle preview
    with it. No envelope stands in for another: a record that will not parse as the one its
    tier (and, for a no-tier settlement, its captured command) names is refused rather than
    tried as another, so a mislabelled settlement is a refused export and never evidence
    read as the wrong kind.
    """
    proof = TerminalEvidence.model_validate_json(
        canonical_json(plain_json(event.payload["evidence"]))
    )
    recorded: ExecutorRecord | ProviderCommand | ConnectorExchange
    if tier == "ATTESTED":
        recorded, reason = _executor(proof)
        measured = None
    elif tier == "PROVIDER_VERIFIED":
        # A checkpoint settled from its provider's journal: the same envelope a dispatched
        # operation's settlement carries, chosen from the tier and never from the bytes.
        recorded, reason = _journal(event, command, proof)
        measured = None
    elif command is not None and command.provider == GRAPH_PROVIDER:
        # The envelope is chosen from the captured command, never from the bytes about to
        # be parsed, which is the same rule the tier follows above. A settlement with no
        # captured command cannot reach this arm, and for this provider it never needs to:
        # the capture predates the first Graph binding, so no Graph settlement without one
        # exists or can be created.
        recorded, reason = _connector(proof)
        measured = recorded.window_ms
    else:
        recorded, reason = _journal(event, command, proof)
        measured = None
    _bound(event, command, recorded, "INVALID_TERMINAL_EVIDENCE")
    if (
        (proof.operation_id, proof.account_id, proof.intent_hash, proof.plan_hash)
        != (recorded.operation_id, recorded.account_id, recorded.intent_hash, recorded.plan_hash)
        or proof.reason != reason
        or proof.proof_digest != hashlib.sha256(proof.authenticated_record.encode()).hexdigest()
        # A window the retained evidence states but its own record does not, or one beside
        # an envelope that measures nothing at all, is refused rather than rendered.
        or proof.window_ms != measured
    ):
        raise ReplayValidationError("INVALID_TERMINAL_EVIDENCE")
    state = "STALE_AUTHORIZATION" if proof.reason == "VERSION_MISMATCH" else proof.outcome
    if event.payload["to_state"] != state:
        raise ReplayValidationError("INVALID_TERMINAL_STATE")
    return proof


def _asserted(
    event: AuditEvent, command: ProviderCommand | None, tier: str | None
) -> AssertedOutcome:
    """An external executor's retained word, and what a settlement at tier ASSERTED may be.

    An assertion is authenticated and unverifiable: it binds the same four fields a verifier
    would have checked and carries no proof digest and no signed record, so nothing here can
    be mistaken for evidence ExecBound checked. The settlement asymmetry is enforced over
    these bytes rather than assumed of them: an assertion settles an execution or a failure
    whose effect is not established, and never a non-execution, because refunding a
    reservation on the executor's bare word is what the contract forbids. So a settled
    assertion is an EXECUTED or FAILED_EFFECT_UNKNOWN row at the state its own outcome
    names, and an asserted FAILED_NOT_EXECUTED leaves the retained uncertainty an
    INDETERMINATE row records.

    The state check below is a third spelling of what `outcomes._state_after` decides for a
    live report and `outcomes._terminal_state` writes, and it is spelled again here because
    replay imports no kernel decision function and must read the bytes rather than re-ask.
    They can drift, and the direction that matters is this one: if the kernel ever lets an
    assertion settle at a state this does not name — the write-off docs/CHECKPOINT.md names
    as a mechanism ExecBound does not have would be one — this refuses histories the kernel
    wrote, which is the export failure this module's tier reading exists to remove.
    `_state_after` carries the same pointer back.
    """
    spoken = AssertedOutcome.model_validate_json(
        canonical_json(plain_json(event.payload["asserted"]))
    )
    _bound(event, command, spoken, "INVALID_ASSERTED_OUTCOME")
    if tier == "ASSERTED" and spoken.outcome == "FAILED_NOT_EXECUTED":
        raise ReplayValidationError("INVALID_ASSERTED_SETTLEMENT")
    if event.payload.get("to_state") != (spoken.outcome if tier == "ASSERTED" else "INDETERMINATE"):
        # A settled assertion's state is the outcome it names and never a mapped one:
        # `models.TERMINAL_PAIRS` forbids the pairing `_terminal_state` would have mapped,
        # FAILED_EFFECT_UNKNOWN beside VERSION_MISMATCH, so no assertion reaching a
        # settlement can name STALE_AUTHORIZATION.
        raise ReplayValidationError("INVALID_TERMINAL_STATE")
    return spoken


def _settlement(
    event: AuditEvent, command: ProviderCommand | None
) -> tuple[TerminalEvidence | None, AssertedOutcome | None, SettlementTier | None]:
    """What this transition settled and at what tier, from the payload settlement wrote.

    Two writers, not one. `outcomes._settle` writes the evidence under `evidence` when a
    verifier returned it and under `asserted` when it is the executor's word alone, and
    names the tier beside it on a checkpoint's settlement — but it raises for any assertion
    that is not EXECUTED, so the `asserted` key of an INDETERMINATE transition, the one
    payload the tier-None branch of `_asserted` exists for, is written by
    `outcomes._settle_report` instead, which retains the executor's word where nothing was
    settled. The tier is outside the evidence object because these bytes are validated as a
    TerminalEvidence, which admits no extra field; being outside it is what lets this choose
    an envelope before parsing one.

    A transition ExecBound dispatched carries no tier at all, so a tier without evidence,
    a tier naming the other kind of evidence and both kinds at once are each refused rather
    than read past: every one of them is a payload no settlement writes.
    """
    payload = event.payload
    tier = payload.get("tier")
    if "evidence" in payload and "asserted" in payload:
        raise ReplayValidationError("INVALID_TERMINAL_EVIDENCE")
    if tier is not None and tier not in get_args(SettlementTier):
        raise ReplayValidationError("INVALID_SETTLEMENT_TIER")
    if "evidence" in payload:
        if tier == "ASSERTED":
            raise ReplayValidationError("INVALID_SETTLEMENT_TIER")
        return _terminal(event, command, tier), None, tier
    if "asserted" in payload:
        if tier in {"ATTESTED", "PROVIDER_VERIFIED"}:
            raise ReplayValidationError("INVALID_SETTLEMENT_TIER")
        return None, _asserted(event, command, tier), tier
    if tier is not None:
        raise ReplayValidationError("INVALID_SETTLEMENT_TIER")
    return None, None, None


def _observed_effect(payload: Mapping[str, Any], capture: DecisionCapture | None) -> bool:
    """An observed execution that shows any effect, or an effect claimed without observation."""
    before, after = payload.get("from_state"), payload.get("to_state")
    observing = capture is not None and capture.mode == "OBSERVE"
    if before == "OBSERVED":
        return True
    if after == "OBSERVED":
        shown = payload.get("observed")
        return (
            not observing
            or capture is None
            or not isinstance(shown, Mapping)
            or shown.get("effect") != capture.decision.effect
        )
    return observing and after != "ATTEMPTED"


def _verified_events(
    export: ReplayExport, bundles: dict[UUID, BundleContent]
) -> tuple[VerifiedEvent, ...]:
    result: list[VerifiedEvent] = []
    commands: dict[UUID, ProviderCommand] = {}
    seen_captures: set[UUID] = set()
    latest: dict[UUID, DecisionCapture] = {}
    for event in export.events:
        capture = None
        semantic_time: datetime | None = None
        proof = None
        asserted = None
        tier: SettlementTier | None = None
        completeness: Literal["COMPLETE", "LEGACY", "UNSUPPORTED"] = "COMPLETE"
        issues: list[str] = []
        if event.kind == "execution.evaluated":
            capture = _capture(event, bundles)
            semantic_time = capture.semantic_time
            if capture.approval is not None and capture.approval.status == "VERIFIED":
                distinct = {human.principal_id for human in capture.approval.approvers} or {
                    capture.approval.approver.principal_id
                }
                if len(distinct) < capture.approval.required_approvers:
                    completeness = "UNSUPPORTED"
                    issues.append("INSUFFICIENT_QUORUM")
            expected = _capture_command(capture, bundles[capture.bundle_id])
            prior = commands.get(capture.execution_id)
            if prior is not None and any(
                getattr(prior, field) != getattr(expected, field)
                for field in (
                    "tenant_id",
                    "account_id",
                    "canonical_target_id",
                    "provider",
                    "action",
                    "provider_operation",
                    "resource_provider_id",
                    "expected_version",
                    "execution_id",
                    "operation_id",
                    "intent_hash",
                )
            ):
                raise ReplayValidationError("CHANGED_EXECUTION_BINDING")
            commands.setdefault(capture.execution_id, expected)
            seen_captures.add(capture.execution_id)
            latest[capture.execution_id] = capture
        elif event.kind == "execution.transition":
            execution = _uuid(event.payload["execution_id"])
            if _observed_effect(event.payload, latest.get(execution)):
                completeness = "UNSUPPORTED"
                issues.append("OBSERVED_WITH_EFFECT")
            if event.payload.get("to_state") == "ATTEMPTED" and "frozen" in event.payload:
                if execution in commands:
                    raise ReplayValidationError("DUPLICATE_EXECUTION")
                commands[execution] = _attempted_command(event, bundles)
            if "replay" in event.payload:
                timing = _SemanticTime.model_validate_json(
                    canonical_json(plain_json(event.payload["replay"]))
                )
                semantic_time = timing.semantic_time
            else:
                completeness = "LEGACY"
                issues.append("MISSING_SEMANTIC_TIME")
            command = commands.get(execution)
            if command is not None and any(
                event.payload.get(field) != getattr(command, field)
                for field in ("intent_hash", "plan_hash")
            ):
                raise ReplayValidationError("CHANGED_EXECUTION_BINDING")
            if command is not None and _uuid(event.payload["operation_id"]) != command.operation_id:
                raise ReplayValidationError("CHANGED_EXECUTION_BINDING")
            proof, asserted, tier = _settlement(event, command)
            if (proof is not None or asserted is not None) and command is None:
                completeness = "LEGACY"
                issues.append("MISSING_AUTHORITY_CAPTURE")
            if event.payload.get("to_state") != "ATTEMPTED" and execution not in seen_captures:
                completeness = "LEGACY"
                issues.append("MISSING_AUTHORITY_CAPTURE")
            if event.payload.get("to_state") not in _EXECUTION_STATES or event.payload.get(
                "from_state"
            ) not in {None, *_EXECUTION_STATES}:
                completeness = "UNSUPPORTED"
                issues.append("UNKNOWN_TRANSITION_SEMANTICS")
        elif event.kind == "approval.transition":
            bound = latest.get(_uuid(event.payload.get("execution_id")))
            if bound is not None and bound.mode == "OBSERVE":
                completeness = "UNSUPPORTED"
                issues.append("OBSERVED_WITH_EFFECT")
            if "replay" in event.payload:
                semantic_time = _SemanticTime.model_validate_json(
                    canonical_json(plain_json(event.payload["replay"]))
                ).semantic_time
            else:
                completeness = "LEGACY"
                issues.append("MISSING_SEMANTIC_TIME")
            if (
                event.payload.get("to_state") not in _APPROVAL_STATES
                or event.payload.get("from_state") not in _APPROVAL_STATES
            ):
                completeness = "UNSUPPORTED"
                issues.append("UNKNOWN_TRANSITION_SEMANTICS")
        elif event.kind in _STOP_EVENTS:
            _uuid(event.payload["stop_id"], "INVALID_STOP")
            if "replay" in event.payload:
                semantic_time = _SemanticTime.model_validate_json(
                    canonical_json(plain_json(event.payload["replay"]))
                ).semantic_time
            else:
                completeness = "LEGACY"
                issues.append("MISSING_SEMANTIC_TIME")
        elif event.kind not in _INFORMATIONAL:
            completeness = "UNSUPPORTED"
            issues.append("UNKNOWN_EVENT_SEMANTICS")
        if event.kind.startswith("policy.bundle_"):
            bundle = bundles[_uuid(event.payload["bundle_id"])]
            if event.payload.get("content_hash") != bundle.content_hash:
                raise ReplayValidationError("INVALID_BUNDLE_HASH")
        result.append(
            VerifiedEvent(
                event=event,
                capture=capture,
                semantic_time=semantic_time,
                terminal_evidence=proof,
                asserted_outcome=asserted,
                settlement_tier=tier,
                precondition_class=_precondition(event),
                # From the settled evidence, never from the attempt: the attempt is
                # committed before the connector runs, so nothing has measured a gap yet
                # when that event is written. `_terminal` has already held this value to
                # the signed record it came from.
                precondition_window_ms=proof.window_ms if proof is not None else None,
                completeness=completeness,
                issues=tuple(issues),
            )
        )
    return tuple(result)


def _precondition(event: AuditEvent) -> PreconditionClass | None:
    """What one dispatch attempt declared, from its own retained payload.

    Read here rather than from ``executions.precondition_class`` because the row is not
    available to an offline replay at all, and because the runtime holds UPDATE on that
    column while this chain is what cannot be quietly revised.

    An attempt with no class predates the recording of one and is left as ``None``; the
    pages say what that meant in its own words rather than back-filling a guarantee.

    The measured window is deliberately not read here. A class is known when the attempt is
    committed; a gap is not, because the connector's exchange has not happened yet and a
    dispatch is one-shot. The window arrives with the settlement instead, inside the signed
    record, and ``_terminal`` is what holds it to that record.
    """
    if event.kind != "execution.dispatch_attempt":
        return None
    declared = event.payload.get("precondition_class")
    if declared is None:
        return None
    if declared not in get_args(PreconditionClass):
        raise ReplayValidationError("INVALID_PRECONDITION_CLASS")
    return cast(PreconditionClass, declared)


def _flag(item: VerifiedEvent, issue: str) -> VerifiedEvent:
    return item.model_copy(update={"completeness": "UNSUPPORTED", "issues": (*item.issues, issue)})


def _is_decision(item: VerifiedEvent) -> bool:
    kind, payload = item.event.kind, item.event.payload
    if kind == "execution.evaluated":
        return True
    if kind == "execution.transition":
        return payload.get("to_state") in _ADMISSION_STATES
    if kind == "approval.transition":
        return payload.get("to_state") in _DECISION_APPROVAL_STATES
    return kind == "approval.decision_recorded"


def _stop_periods(
    events: tuple[VerifiedEvent, ...],
) -> tuple[tuple[StopPeriod, ...], tuple[VerifiedEvent, ...]]:
    """Reconstruct stop periods from matching activation and release pairs, then report any
    decision the gateway could not have produced inside one. Chain order settles ties: a
    decision recorded before the activation event at the same instant is not inside it."""
    flagged = list(events)
    periods: list[StopPeriod] = []
    spans: list[tuple[int, int | None]] = []
    open_period: StopPeriod | None = None
    opened_at = 0
    for index, item in enumerate(events):
        kind, payload = item.event.kind, item.event.payload
        if kind not in _STOP_EVENTS or item.semantic_time is None:
            continue
        stop_id = _uuid(payload["stop_id"], "INVALID_STOP")
        if kind == "tenant.stop_activated":
            if open_period is not None:
                flagged[index] = _flag(item, "OVERLAPPING_STOP")
                continue
            open_period = StopPeriod(
                stop_id=stop_id,
                activated_at=item.semantic_time,
                reason=str(payload.get("reason", ""))[:500],
            )
            opened_at = index
        elif open_period is None or open_period.stop_id != stop_id:
            flagged[index] = _flag(item, "UNMATCHED_STOP_RELEASE")
        else:
            periods.append(open_period.model_copy(update={"released_at": item.semantic_time}))
            spans.append((opened_at, index))
            open_period = None
    if open_period is not None:
        periods.append(open_period)
        spans.append((opened_at, None))
    for index, item in enumerate(events):
        if item.semantic_time is None or not _is_decision(item):
            continue
        inside = any(
            (start < index and (end is None or index < end))
            or (
                period.activated_at < item.semantic_time
                and (period.released_at is None or item.semantic_time < period.released_at)
            )
            for period, (start, end) in zip(periods, spans, strict=True)
        )
        if inside:
            flagged[index] = _flag(item, "DECISION_DURING_STOP")
    return tuple(periods), tuple(flagged)


def verify_export(export: ReplayExport, trusted_head: TrustedHead) -> VerifiedHistory:
    try:
        export = parse_export(export.model_dump_json().encode())
        reject_secrets(export.model_dump(mode="json"))
        trusted_head = TrustedHead.model_validate_json(trusted_head.model_dump_json())
        if export.tenant_id != trusted_head.tenant_id or export.head != trusted_head:
            raise ReplayValidationError("HEAD_MISMATCH")
        if not verify_chain(
            [event.audit_row() for event in export.events],
            export.tenant_id,
            trusted_head.sequence,
            trusted_head.event_hash,
        ):
            raise ReplayValidationError("INVALID_CHAIN")
        if len({event.event_id for event in export.events}) != len(export.events):
            raise ReplayValidationError("DUPLICATE_EVENT")
        bundles = {bundle.bundle_id: bundle for bundle in export.bundles}
        if len(bundles) != len(export.bundles) or any(
            bundle.tenant_id != export.tenant_id for bundle in export.bundles
        ):
            raise ReplayValidationError("INVALID_BUNDLE")
        if not referenced_bundle_ids(export.events) <= set(bundles):
            raise ReplayValidationError("MISSING_BUNDLE")
        stop_periods, events = _stop_periods(_verified_events(export, bundles))
        issues = tuple(sorted({issue for event in events for issue in event.issues}))
        return VerifiedHistory(
            export=export,
            events=events,
            complete=all(event.completeness == "COMPLETE" for event in events),
            issues=issues,
            stop_periods=stop_periods,
        )
    except ReplayValidationError:
        raise
    except (ValueError, TypeError, RecursionError, KeyError, AttributeError):
        pass
    raise ReplayValidationError()
