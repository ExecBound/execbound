# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded immutable replay data, separate from live authority and configuration."""

from collections.abc import Mapping
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from execbound.audit import canonical_json
from execbound.execution.models import (
    AssertedOutcome,
    Digest,
    PreconditionClass,
    SettlementTier,
    TerminalEvidence,
)
from execbound.identity import Identity, PrincipalKind
from execbound.operations import ActionName
from execbound.policy.approval import VerifiedApproval
from execbound.policy.models import BundleContent, PolicyEvaluation
from execbound.requests import StrictModel
from execbound.resolution.models import ResolvedRequest

MAX_EXPORT_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 10000
MAX_BUNDLES = 256
MAX_EVENT_PAYLOAD_BYTES = 16384
MAX_JSON_DEPTH = 64
SequenceNumber = Annotated[int, Field(ge=0, le=2**63 - 1)]


def plain_json(value: Any) -> Any:
    """Copy frozen JSON to ordinary containers accepted by the existing audit codec."""
    if isinstance(value, Mapping):
        return {key: plain_json(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain_json(child) for child in value]
    return value


def _freeze(value: Any, depth: int = 0) -> Any:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("Replay JSON nesting exceeds the limit")
    if value is None or type(value) in (str, int, bool):
        return value
    if isinstance(value, Mapping) and all(type(key) is str for key in value):
        return MappingProxyType({key: _freeze(child, depth + 1) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child, depth + 1) for child in value)
    raise ValueError("Invalid replay JSON")


class ReplayModel(StrictModel):
    model_config = ConfigDict(revalidate_instances="always")


class VersionedModel(ReplayModel):
    version: Literal[1] = 1

    @field_validator("version", mode="before")
    @classmethod
    def integer_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Invalid replay version")
        return value


class AuditEvent(ReplayModel):
    # These are exactly the persisted audit row fields. The existing hash codec
    # adds its own envelope version; adding a row field here would alter exports.
    tenant_id: UUID
    sequence: int = Field(ge=1, le=2**63 - 1)
    event_id: UUID
    actor_id: UUID
    kind: str = Field(pattern=r"^[a-z][a-z0-9_.]{0,79}$")
    occurred_at: AwareDatetime
    payload: Mapping[str, Any]
    previous_hash: Digest
    event_hash: Digest

    @field_validator("occurred_at")
    @classmethod
    def utc_time(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator("payload")
    @classmethod
    def immutable_payload(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        frozen: Mapping[str, Any] = _freeze(value)
        if len(canonical_json(plain_json(frozen)).encode()) > MAX_EVENT_PAYLOAD_BYTES:
            raise ValueError("Replay event payload exceeds the limit")
        return frozen

    @field_serializer("payload")
    def serialize_payload(self, value: Mapping[str, Any]) -> Any:
        return plain_json(value)

    def audit_row(self) -> dict[str, Any]:
        return {**self.model_dump(), "payload": plain_json(self.payload)}


class TrustedHead(VersionedModel):
    tenant_id: UUID
    sequence: SequenceNumber
    event_hash: Digest


class HistoricalIdentity(ReplayModel):
    tenant_id: UUID
    principal_id: UUID
    credential_id: UUID
    kind: PrincipalKind
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    # Memberships the gateway counted for this decision. Absent on captures recorded
    # before groups existed, so replay can tell "none" from "unrecorded".
    groups: tuple[UUID, ...] | None = Field(
        default=None, max_length=64, exclude_if=lambda value: value is None
    )
    # The space the gateway read from this agent's own principal row for this decision.
    # Absent on every capture recorded before spaces existed, so replay can tell "this
    # space" from "unrecorded", and serialized only when set, so those captures stay
    # byte-identical.
    space: UUID | None = Field(default=None, exclude_if=lambda value: value is None)

    @field_validator("groups")
    @classmethod
    def canonical_groups(cls, value: tuple[UUID, ...] | None) -> tuple[UUID, ...] | None:
        if value is None:
            return None
        if len(set(value)) != len(value):
            raise ValueError("Duplicate group")
        if list(value) != sorted(value, key=str):
            raise ValueError("Unsorted groups")
        return value

    @model_validator(mode="after")
    def valid_interval(self) -> Self:
        if self.issued_at >= self.expires_at:
            raise ValueError("Invalid historical identity interval")
        return self

    def to_identity(self) -> Identity:
        """Pure policy input only; this snapshot cannot authenticate a live request."""
        return Identity(
            self.tenant_id, self.principal_id, self.credential_id, self.kind, self.expires_at
        )


class ApprovalCapture(ReplayModel):
    status: Literal["PROPOSED", "VERIFIED"]
    approval_id: UUID
    tenant_id: UUID
    principal_id: UUID
    bundle_id: UUID
    plan_hash: Digest
    obligation_ids: tuple[str, ...] = Field(max_length=1024)
    expires_at: AwareDatetime
    approver: HistoricalIdentity
    canonical_target_id: UUID
    action: ActionName
    # Additive for the quorum: retained captures parse unchanged with one approver.
    required_approvers: int = Field(default=1, ge=1, le=5)
    approvers: tuple[HistoricalIdentity, ...] = Field(default=(), max_length=5)

    @field_validator("obligation_ids")
    @classmethod
    def bounded_obligations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not 1 <= len(item) <= 160 for item in value) or value != tuple(sorted(set(value))):
            raise ValueError("Invalid captured obligations")
        return value

    @model_validator(mode="after")
    def human_scope(self) -> Self:
        if (
            self.approver.kind not in {"HUMAN_APPROVER", "ADMIN"}
            or self.approver.tenant_id != self.tenant_id
        ):
            raise ValueError("Invalid captured human scope")
        principals = [human.principal_id for human in self.approvers]
        if len(set(principals)) != len(principals) or any(
            human.kind not in {"HUMAN_APPROVER", "ADMIN"} or human.tenant_id != self.tenant_id
            for human in self.approvers
        ):
            raise ValueError("Invalid captured human scope")
        return self

    def to_verified_approval(self) -> VerifiedApproval:
        """Pure evaluator input; callers must separately require recorded approval events."""
        return VerifiedApproval(
            self.approval_id,
            self.tenant_id,
            self.principal_id,
            self.bundle_id,
            self.plan_hash,
            self.obligation_ids,
            self.expires_at,
        )


class DecisionCapture(VersionedModel):
    stage: Literal["ADMISSION", "APPROVAL_REVIEW"]
    execution_id: UUID
    operation_id: UUID
    canonical_target_id: UUID
    semantic_time: AwareDatetime
    usage_time: AwareDatetime
    finished_time: AwareDatetime
    identity: HistoricalIdentity
    frozen: ResolvedRequest
    bundle_id: UUID
    decision: PolicyEvaluation
    approval: ApprovalCapture | None = None
    reviewer: HistoricalIdentity | None = None
    human_decision: Literal["APPROVE", "DENY"] | None = None
    # Serialized only when observing, so every enforced capture is byte-identical.
    mode: Literal["ENFORCE", "OBSERVE"] = Field(
        default="ENFORCE", exclude_if=lambda value: value == "ENFORCE"
    )

    @model_validator(mode="after")
    def scope_and_stage(self) -> Self:
        intent, identity = self.frozen.intent, self.identity
        if self.mode == "OBSERVE" and (self.stage != "ADMISSION" or self.approval is not None):
            raise ValueError("An observed decision carries no approval or review")
        if (
            identity.kind != "AGENT"
            or intent.tenant_id != identity.tenant_id
            or intent.principal_id != identity.principal_id
            or self.bundle_id != self.decision.bundle_id
        ):
            raise ValueError("Invalid captured decision scope")
        if self.stage == "ADMISSION":
            if self.reviewer is not None or self.human_decision is not None:
                raise ValueError("Unexpected human review")
            if self.approval is not None and self.approval.status != "VERIFIED":
                raise ValueError("Proposed approval is not admission authority")
        else:
            if (
                self.reviewer is None
                or self.reviewer.kind not in {"HUMAN_APPROVER", "ADMIN"}
                or self.reviewer.tenant_id != identity.tenant_id
                or self.human_decision is None
            ):
                raise ValueError("Missing captured human review")
            if self.approval is not None and (
                self.approval.status != "PROPOSED"
                or self.human_decision != "APPROVE"
                or self.approval.approver != self.reviewer
            ):
                raise ValueError("Invalid proposed approval")
        if self.approval is not None:
            approval = self.approval
            if (
                approval.tenant_id != identity.tenant_id
                or approval.principal_id != identity.principal_id
                or approval.canonical_target_id != self.canonical_target_id
                or approval.action != intent.action
            ):
                raise ValueError("Invalid captured approval scope")
        return self


class ReplayExport(VersionedModel):
    tenant_id: UUID
    events: tuple[AuditEvent, ...] = Field(max_length=MAX_EVENTS)
    head: TrustedHead
    bundles: tuple[BundleContent, ...] = Field(max_length=MAX_BUNDLES)


class VerifiedEvent(ReplayModel):
    event: AuditEvent
    capture: DecisionCapture | None = None
    semantic_time: AwareDatetime | None = None
    terminal_evidence: TerminalEvidence | None = None
    # An external executor's retained word about a checkpoint, which is authenticated and
    # unverifiable. It is a field of its own rather than terminal evidence with a flag,
    # because a reader that has not learned about tiers sees no evidence here at all.
    asserted_outcome: AssertedOutcome | None = None
    # What ExecBound could check about a checkpoint's settlement, from the tier the
    # transition names beside its evidence. A settlement of an operation ExecBound
    # dispatched carries none: a tier is a statement about an external executor's word.
    settlement_tier: SettlementTier | None = None
    # What a dispatch ExecBound made itself carried, read from the attempt's own retained
    # payload rather than from a column the runtime can update. A settlement tier is a
    # statement about an external executor's word; this is a statement about the vendor's
    # API, and the two are never the same sentence. Absent on every other kind of event,
    # and absent on an attempt made before the class was recorded at all.
    precondition_class: PreconditionClass | None = None
    # The gap between the connector's read and its write, in milliseconds, for a class that
    # measures one. Evidence a reader weighs, never a gate: a wide window is not a refusal.
    precondition_window_ms: int | None = Field(default=None, ge=0, le=3_600_000)
    completeness: Literal["COMPLETE", "LEGACY", "UNSUPPORTED"] = "COMPLETE"
    issues: tuple[str, ...] = ()


class StopPeriod(ReplayModel):
    stop_id: UUID
    activated_at: AwareDatetime
    released_at: AwareDatetime | None = None
    reason: str = Field(max_length=500)


class VerifiedHistory(ReplayModel):
    export: ReplayExport
    events: tuple[VerifiedEvent, ...]
    complete: bool
    issues: tuple[str, ...] = ()
    stop_periods: tuple[StopPeriod, ...] = ()
