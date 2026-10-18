# SPDX-License-Identifier: AGPL-3.0-only
"""Internal execution contracts. Tickets and verified evidence are never wire authority."""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any, Literal, Protocol, Self, get_args
from uuid import UUID

from execbound_protocol.outcomes import TERMINAL_PAIRS as TERMINAL_PAIRS
from execbound_protocol.outcomes import TerminalOutcome as TerminalOutcome
from execbound_protocol.outcomes import TerminalReason as TerminalReason
from execbound_protocol.outcomes import consistent_terminal as consistent_terminal
from execbound_protocol.report import AssertedReason as AssertedReason
from execbound_protocol.report import ReportedResult as ReportedResult
from execbound_protocol.report import ReportSecret as ReportSecret
from execbound_protocol.strict import Digest as Digest
from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy.engine import Connection

from execbound.operations import NAME_PATTERN, ActionName, ProviderName, ProviderOperation
from execbound.requests import ActionRequest, Arguments, StrictModel
from execbound.resolution.models import ResolvedRequest, Version

ExecutionState = Literal[
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
    # Appended, so every existing member keeps its position in the enum a schema renders.
    # A settled row whose only evidence is somebody's word: the reporter states the call
    # did not succeed and whether the vendor's effect happened is not established. Its
    # name is its own disclosure wherever a state is shown.
    "FAILED_EFFECT_UNKNOWN",
]
ApprovalState = Literal["PENDING", "APPROVED", "DENIED", "EXPIRED", "INVALIDATED", "CONSUMED"]
# What a denied agent is told of why, and nothing finer (#545, THREAT_MODEL.md T1.16): `busy`
# when another request holds the target, `limit` when a shared limit covering the request is
# spent, whatever else was recorded beside it, and `withheld` for every other denial. The
# first two tell an agent when waiting is worth a new request; the rule, the limit, its
# window, a count, a fact and the other execution are never named. `store.denial_category`
# reads it from the recorded DENIED transition.
DenialCategory = Literal["busy", "limit", "withheld"]
AuthorityCheck = Callable[[Connection], None]
UNRESOLVED = ("ATTEMPTED", "PENDING_APPROVAL", "RESERVED", "DISPATCH_COMMITTED", "INDETERMINATE")
# The states in which a committed operation is still unsettled: the one attempt has been
# consumed and no terminal outcome has been recorded. The recovery verifier and the
# scheduled recovery run both select exactly this set and each used to spell it out again;
# it is named once here, beside the state machine that produces it, and bounds a
# principal's outstanding checkpoint grants for the same reason: a grant that leaves
# DISPATCH_COMMITTED for INDETERMINATE is still charging every scope and still holding its
# target, so it is still outstanding.
UNSETTLED: tuple[ExecutionState, ...] = ("DISPATCH_COMMITTED", "INDETERMINATE")
MODES = ("ENFORCE", "OBSERVE")
# The deadline every tenant had before it became a setting, and the range a setting may
# take; None is off, which leaves the frozen plan's validity as the only clock.
DEFAULT_APPROVAL_DEADLINE = 120
APPROVAL_DEADLINE_BOUNDS = (120, 3600)
_TRANSITIONS = {
    "ATTEMPTED": {"DENIED", "PENDING_APPROVAL", "RESERVED", "OBSERVED"},
    "PENDING_APPROVAL": {"DENIED", "STALE_AUTHORIZATION", "RESERVED"},
    "RESERVED": {"DISPATCH_COMMITTED"},
    "DISPATCH_COMMITTED": {
        "EXECUTED",
        "FAILED_NOT_EXECUTED",
        "INDETERMINATE",
        "STALE_AUTHORIZATION",
        "FAILED_EFFECT_UNKNOWN",
    },
    "INDETERMINATE": {
        "EXECUTED",
        "FAILED_NOT_EXECUTED",
        "STALE_AUTHORIZATION",
        "FAILED_EFFECT_UNKNOWN",
    },
    # The correction docs/CHECKPOINT.md describes under "What a settled row is closed to",
    # and the one edge out of a terminal state in this machine. Its source is the one state
    # no verifier can produce, and both of its targets are the states a verified
    # non-execution settles at. Neither target is a key of this map, so `transition_allowed`
    # answers False from either for every target and a corrected row is final; nothing here
    # adds an edge back into an unsettled state, so no execution is re-granted or
    # re-dispatched.
    "FAILED_EFFECT_UNKNOWN": {"FAILED_NOT_EXECUTED", "STALE_AUTHORIZATION"},
}


def transition_allowed(before: str, after: str) -> bool:
    return after in _TRANSITIONS.get(before, set())


class ExecutionError(ValueError):
    def __init__(self, code: str = "EXECUTION_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Execution unavailable")


class ObservedResult(StrictModel):
    """What an observed request would have decided; never authority for anything."""

    effect: Literal["DENY", "REQUIRE_APPROVAL", "ELIGIBLE"]
    reasons: tuple[str, ...] = ()
    obligation_ids: tuple[str, ...] = ()
    mode: Literal["tenant", "mapping"]


# How much a frozen expected version is worth at the vendor the executor calls, declared
# per provider binding as deployment configuration rather than catalog content, so no
# released action spec, provider binding or frozen plan changes. ENFORCED_BY_PROVIDER: the
# vendor offers a conditional write and the executor must use it. ASSERTED_BY_EXECUTOR: the
# vendor exposes a readable version but no conditional write, so a report under it is an
# assertion about a race the executor observed. CHECKED_BY_CONNECTOR: the vendor offers no
# conditional write and ExecBound's own connector read the state, froze it and compared it
# immediately before writing, so the check is ExecBound's own observation with both vendor
# responses retained and a measured window between them, not a third party's report and not
# atomicity. It belongs to the native dispatch path only: a checkpoint grant hands the act
# to somebody else's executor, so a grant carrying it would have ExecBound vouching for a
# check it never made, and CheckpointGrant refuses it. UNAVAILABLE: the vendor expresses no
# version at all, so a concurrent change is undetectable and the grant carries no version
# to pretend otherwise.
PreconditionClass = Literal[
    "ENFORCED_BY_PROVIDER", "ASSERTED_BY_EXECUTOR", "CHECKED_BY_CONNECTOR", "UNAVAILABLE"
]
# What a provider binding with no configured declaration answers. An operator who has
# declared nothing has told ExecBound nothing about the vendor, so the honest answer is
# the class that promises nothing and carries no version for the executor to check.
UNCONFIGURED_PRECONDITION: PreconditionClass = "UNAVAILABLE"
PRECONDITION_CLASSES: frozenset[str] = frozenset(get_args(PreconditionClass))
_BINDING_NAME = re.compile(NAME_PATTERN)


@dataclass(frozen=True)
class PreconditionConfig:
    """What each provider binding's vendor does with a frozen expected version.

    Deployment configuration, held on the runtime beside the connectors and the catalog
    and threaded to admission, keyed by the provider binding a grant names: the provider
    and the provider operation, never the account. A checkpoint account has no connection
    configuration at all, because the executor holds the vendor credential and ExecBound
    configures no connector for it, and the binding is also the truthful key on the
    merits: whether a version can be checked is a property of the vendor's API rather
    than of one tenant's account.

    No request field, header, credential attribute or client capability reaches this, and
    it stays outside the serialized operation composite, so released action specs and
    provider bindings stay immutable and no frozen plan or bundle hash moves.
    """

    classes: Mapping[tuple[str, str], PreconditionClass] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.classes, Mapping):
            raise ValueError("Invalid precondition configuration")
        copied = dict(self.classes)
        for binding, declared in copied.items():
            if (
                type(binding) is not tuple
                or len(binding) != 2
                or any(
                    type(name) is not str or not _BINDING_NAME.fullmatch(name) for name in binding
                )
                or declared not in PRECONDITION_CLASSES
            ):
                raise ValueError("Invalid precondition configuration")
        object.__setattr__(self, "classes", MappingProxyType(copied))

    def declared(
        self, provider: ProviderName, provider_operation: ProviderOperation
    ) -> PreconditionClass:
        """The class this deployment configured for the binding, or the honest default."""
        return self.classes.get((provider, provider_operation), UNCONFIGURED_PRECONDITION)


# A deployment that has declared nothing. Every binding answers UNCONFIGURED_PRECONDITION.
NO_PRECONDITIONS = PreconditionConfig()
# The act window is the continuation ceiling of surfaces.tokens; it is restated here
# rather than imported so the kernel does not depend on a surface, and
# test_the_act_window_is_exactly_what_a_continuation_can_carry pins the two together.
ACT_WINDOW = timedelta(minutes=15)
# Longer, carried by the execution row rather than by a token, and authenticated by the
# report secret: an executor whose vendor call is queued or retried must still be able to
# report after the act window closes. A grant older than this is uncertainty an
# administrator should see rather than a report ExecBound still accepts.
REPORT_WINDOW = timedelta(hours=24)
# Outstanding grants one principal may hold. Each charges its scopes until it is reported
# or swept, so the cap bounds how fast an executor that never reports can exhaust a
# ceiling. It interferes with no realistic story.
MAX_GRANTS = 8
# The report secret's shape is the checkpoint report's (`execbound_protocol.report`), imported
# at the top of this module and named here as it always was.


class CheckpointBinding(StrictModel):
    """The four fields an executor's record binds, copied from the frozen command.

    An executor signs these into its record and the verifier checks them against the
    frozen command, so handing them over is what lets an executor that holds only the grant
    produce a record that can settle this execution and no other.
    """

    operation_id: UUID
    account_id: UUID
    intent_hash: Digest
    plan_hash: Digest


class CheckpointGrant(StrictModel):
    """One act an external executor may perform, and the only way it may settle it.

    A grant confers no authority to execute, approve, dispatch or reconcile through
    ExecBound: its whole power is to settle the one execution it names. It is minted only
    after the reservation and the canonical claim are committed, so there is no state in
    which a caller has been told it may act without the budget having been charged.

    The secret is minted exactly once per execution, which is what makes "one report secret
    per execution" literally true. A re-grant describes the same act under the same decision
    and carries no secret at all: it says so with ``regranted``, and the holder of the
    original secret keeps the only thing that can settle the execution. A caller that lost
    its secret has no re-mint; the administrator exit is its remedy.
    """

    operation_id: UUID
    provider: ProviderName
    provider_operation: ProviderOperation
    resource_provider_id: str = Field(min_length=1, max_length=128)
    action: ActionName
    arguments: Arguments
    precondition_class: PreconditionClass
    # Present exactly when the class says the executor can do something with it.
    expected_version: Version | None = None
    act_expires_at: AwareDatetime
    report_expires_at: AwareDatetime
    # True on every answer after the first: the same act, described again, with no secret.
    regranted: bool = False
    # Returned once and never stored: only its digest is retained, so a lost response
    # leaves a grant nothing but the administrator exit can settle.
    report_secret: ReportSecret | None = Field(default=None, repr=False)
    binding: CheckpointBinding
    # The frozen dispatch command, never serialized. The runtime's presenter turns it into
    # the provider command a provider-protocol vendor accepts, because `provider` imports
    # `execution` and not the other way round, so this package cannot build one itself.
    command: "DispatchCommand | None" = Field(default=None, exclude=True, repr=False)

    @model_validator(mode="after")
    def one_operation(self) -> Self:
        # The binding and the command describe the operation this grant names and no other.
        if self.binding.operation_id != self.operation_id or (
            self.command is not None
            and (
                self.command.operation_id != self.operation_id
                or self.command.intent_hash != self.binding.intent_hash
                or self.command.plan_hash != self.binding.plan_hash
                or self.command.frozen.intent.account_id != self.binding.account_id
            )
        ):
            raise ValueError("A grant describes one operation")
        return self

    @model_validator(mode="after")
    def checkable_version(self) -> Self:
        # A class that promises nothing carries no version the executor could read as
        # something to check, and a class that promises something must carry one.
        if (self.expected_version is None) != (self.precondition_class == "UNAVAILABLE"):
            raise ValueError("An expected version accompanies exactly a checkable class")
        return self

    @model_validator(mode="after")
    def a_connector_check_is_not_grantable(self) -> Self:
        # CHECKED_BY_CONNECTOR describes a read and a comparison ExecBound's own connector
        # made on the native path, with both vendor responses retained. A grant hands the
        # act to somebody else's executor, so a grant carrying that class would have
        # ExecBound vouching for a check it never made, and an executor could reasonably
        # read it as permission to skip its own. A deployment that declares the class for a
        # binding reached through the Gate is misconfigured; refusing the grant is how that
        # surfaces, rather than being silently downgraded to a weaker class that would let
        # the act proceed under a quietly different promise.
        if self.precondition_class == "CHECKED_BY_CONNECTOR":
            raise ValueError("A checkpoint grant cannot claim a connector-side check")
        return self

    @model_validator(mode="after")
    def act_within_the_report_window(self) -> Self:
        # An act window outliving the report window would grant an act nothing can settle.
        if self.act_expires_at > self.report_expires_at:
            raise ValueError("The act window closes no later than the report window")
        return self

    @model_validator(mode="after")
    def one_mint_per_execution(self) -> Self:
        # A first grant carries its secret and a re-grant never does, so no path can hand
        # out a second secret or an unusable first grant.
        if (self.report_secret is None) != self.regranted:
            raise ValueError("A grant carries its secret exactly once, and a re-grant none")
        return self


class ExecutionView(StrictModel):
    request_ref: str | None = Field(default=None, exclude_if=lambda value: value is None)
    execution_id: UUID
    state: ExecutionState
    plan_hash: Digest
    approval_id: UUID | None = None
    approval_state: ApprovalState | None = None
    # Set on a view answered during an emergency stop. Never serialized, so every
    # existing response stays byte-identical; Runtime.present adds the flag.
    tenant_stopped: bool = Field(default=False, exclude=True)
    # Set only on an OBSERVED view; Runtime.present adds the object for that state alone.
    observed: ObservedResult | None = Field(default=None, exclude=True)
    # Set only on the admission that granted or re-granted a checkpoint, never on a status
    # read. Excluded like the two above, so no existing response body changes.
    checkpoint: CheckpointGrant | None = Field(default=None, exclude=True)
    # Set only on a DENIED view, from its recorded DENIED transition (`store.view`), so every
    # read of one execution carries the same category. Excluded like the three above;
    # Runtime.present adds it, with the sentence it selects, for that state alone.
    denial: DenialCategory | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def denial_only_on_a_denial(self) -> Self:
        if self.denial is not None and self.state != "DENIED":
            raise ValueError("Only a denied execution carries a denial category")
        return self


@dataclass(frozen=True)
class ModeChange:
    previous: str
    mode: str
    changed_at: datetime
    changed_by: UUID
    reason: str


@dataclass(frozen=True)
class DeadlineChange:
    previous: int | None
    seconds: int | None
    changed_at: datetime
    changed_by: UUID
    reason: str


@dataclass(frozen=True)
class StopState:
    stop_id: UUID
    stopped_at: datetime
    stopped_by: UUID
    reason: str


@dataclass(frozen=True)
class DispatchTicket:
    tenant_id: UUID
    execution_id: UUID
    secret: str = field(repr=False)


@dataclass(frozen=True)
class Admission:
    view: ExecutionView
    ticket: DispatchTicket | None = field(default=None, repr=False)


class DispatchCommand(StrictModel):
    execution_id: UUID
    canonical_target_id: UUID
    operation_id: UUID
    intent_hash: Digest
    plan_hash: Digest
    frozen: ResolvedRequest


# CheckpointGrant names DispatchCommand before it is defined; resolve the reference now.
CheckpointGrant.model_rebuild()


# The verified terminal vocabulary, TerminalOutcome and TerminalReason, and the pairing of
# outcome and reason, TERMINAL_PAIRS and consistent_terminal, are the protocol's: what a
# provider, a connector and an executor may state (`execbound_protocol.outcomes`, #496).
# They are imported at the top of this module and named here as they always were.

# What an unverifiable statement may say, which is the verified vocabulary plus one member
# on each side. FAILED_EFFECT_UNKNOWN is deliberately parallel to FAILED_NOT_EXECUTED,
# which states that the vendor did not act; this states that whether it acted is not
# established. REPORTED_FAILURE is the one reason that names a statement rather than an
# established fact. It refunds nothing, and that is a property of TERMINAL_PAIRS rather
# than of the reason: the table maps it to FAILED_EFFECT_UNKNOWN and to nothing else, so
# no outcome that refunds may accompany it. The reasons, AssertedReason, and what a report
# may say happened, ReportedResult, are the checkpoint report's and so the protocol's
# (`execbound_protocol.report`); both are imported at the top of this module.
AssertedResult = Literal["EXECUTED", "FAILED_NOT_EXECUTED", "FAILED_EFFECT_UNKNOWN"]
# What ExecBound was able to check about an executor's report. ATTESTED is a signature
# verified against a key an administrator registered, which makes the statement
# authenticated and non-repudiable and never proves the vendor effect. PROVIDER_VERIFIED is
# a journal the provider signed for this exact command, verified under a key the operator
# configured: a party other than the executor stating the vendor's own record. ASSERTED is
# the executor's authenticated word and nothing more. These are the values the
# settlement_tier column admits.
SettlementTier = Literal["ATTESTED", "ASSERTED", "PROVIDER_VERIFIED"]
# The tiers a verifier can establish, as against the one an unverified statement gets.
VerifiedTier = Literal["ATTESTED", "PROVIDER_VERIFIED"]


class TerminalEvidence(StrictModel):
    """Only a trusted provider verifier may construct an authoritative instance."""

    operation_id: UUID
    account_id: UUID
    intent_hash: Digest
    plan_hash: Digest
    outcome: TerminalOutcome
    reason: TerminalReason
    proof_digest: Digest
    authenticated_record: str = Field(min_length=1, max_length=8192)
    # The gap a connector measured between the read it compared and the write that
    # followed, where the evidence carries one. The kernel never parses
    # `authenticated_record` — it is an opaque string here, deliberately — so a verifier
    # that read a window out of its own envelope states it here or the settlement path
    # cannot retain it. None wherever the evidence establishes no such gap, which is every
    # provider journal and every executor record.
    window_ms: int | None = Field(default=None, ge=0, le=3_600_000)

    @model_validator(mode="after")
    def consistent_outcome(self) -> Self:
        if not consistent_terminal(self.outcome, self.reason):
            raise ValueError("Invalid terminal reason")
        return self


class AssertedOutcome(StrictModel):
    """An external executor's own word about what happened, and never proof of it.

    It binds the same operation, account, intent and plan a verifier checks, so an
    assertion still names exactly one authorized operation. It deliberately carries no
    proof digest and no authenticated record: replay treats the presence of terminal
    evidence as verification, so reusing TerminalEvidence for an unverifiable report
    would make an assertion structurally indistinguishable from provider proof. The
    executor's own clock is retained as `reported_at` and is never a confirmation time.
    """

    operation_id: UUID
    account_id: UUID
    intent_hash: Digest
    plan_hash: Digest
    # The asserted vocabulary, which TerminalEvidence and the provider envelopes do not
    # share: an assertion is the one thing that may state a failure whose effect is not
    # established, and this model is built by `outcomes._reported` alone.
    outcome: AssertedResult
    reason: AssertedReason
    reported_at: AwareDatetime

    @model_validator(mode="after")
    def consistent_outcome(self) -> Self:
        if not consistent_terminal(self.outcome, self.reason):
            raise ValueError("Invalid terminal reason")
        return self


class EvidenceVerifier(Protocol):
    # Whether the evidence this verifier checks says what an *external executor* did, as
    # against what a provider's own journal says about an operation ExecBound dispatched.
    # Two guards read it, one for each pairing of this answer with the row's report window:
    # `reconciliation._executor_evidence_only`, so an outstanding checkpoint grant never
    # settles from connector evidence, and `outcomes._never_executor_evidence`, so an
    # operation ExecBound dispatched never settles from an executor's record. It is
    # declared here so a new verifier is asked the question and mypy says so; both read it
    # with a default, because a verifier is a duck type and nothing makes an object
    # arriving at runtime carry the attribute at all.
    attests_external_execution: bool

    def verify(self, command: DispatchCommand, evidence: bytes) -> TerminalEvidence | None: ...

    # Which verified tier the evidence this verifier returned establishes, asked by
    # `outcomes._verified_tier` of a checkpoint settlement and of nothing else: only the
    # composition boundary that built the verifier knows which envelope the opaque
    # authenticated record holds. Declared here beside the marker above and for the same
    # reason, so a new verifier is asked the question and mypy says so; read with a
    # default too, since a verifier is a duck type at runtime and one that answers nothing
    # settles no checkpoint. The connector verifiers answer it without it ever being read,
    # because an operation ExecBound dispatched settles at no tier.
    def verified_tier(self, proof: TerminalEvidence) -> VerifiedTier: ...


# How a settlement path obtains the verifier for one execution. The kernel names no
# concrete verifier, exactly as reconciliation takes one rather than building it: the
# composition boundary decides what a tenant's evidence is checked against, and the kernel
# supplies the connection and the execution row so the ring and the grant instant are read
# on the connection that read the row they are weighed against.
VerifierFactory = Callable[[Connection, dict[str, Any]], EvidenceVerifier]

# Whether the tenant's executor key ring could attest a grant issued now, asked of the
# composition boundary for the same reason the verifier is: what a usable key ring is, is
# decided where the ring is loaded, and admission must ask the question settlement will
# ask rather than a weaker one the column happens to be able to express.
AttestableRing = Callable[[Connection, UUID], bool]


def wire_hash(request: ActionRequest) -> str:
    """Recognize original-body retries after the authority snapshot has expired."""
    import hashlib

    from execbound.audit import canonical_json

    # The reference is excluded as the key is: the key it derives is what scopes the row,
    # so the same intent hashes the same whether the caller sent the key or the ticket.
    value = request.model_dump(
        mode="json",
        exclude={"idempotency_key", "reference", "run_id", "claimed_context", "external_case"},
    )
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()
