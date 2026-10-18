# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded external evidence and opaque source grants."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

Identifier = Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9._:-]+$")]
Action = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")]


# The status each monitoring refusal is answered with; every other code is 400. The error
# and refusal code reference lists every code at the status this gives it.
MONITOR_STATUS = {
    "INVALID_SOURCE": 401,
    "INVALID_ADMIN": 403,
    "SOURCE_RATE_LIMIT": 429,
    "SOURCE_CAPACITY": 429,
    "EVENT_CONFLICT": 409,
    "FINDING_UNAVAILABLE": 404,
    "MONITOR_UNAVAILABLE": 503,
    "RULE_UNAVAILABLE": 503,
}


# A connection's intervals when its row leaves them null. Entra: a full directory read every
# six hours. Tines: its audit records every fifteen minutes, and its inventory daily, which is
# not adjustable. The schedule (`due.py`) and the overdue rule (`store.py`) both read these.
DEFAULT_COLLECT_SECONDS = {"tines": 86400, "entra_agent_id": 21600}
DEFAULT_ACTIVITY_SECONDS = 900
# The states a finding delivery or intent can be in (#31): what `deliveries --state` offers and
# the listing takes. Here rather than in the worker, so building the command-line parser never
# loads the worker.
DELIVERY_STATES = ("PENDING", "ROUTED", "IN_FLIGHT", "DELIVERED", "FAILED")


class MonitorError(ValueError):
    """Only a stable code escapes; never include input or database diagnostics."""

    def __init__(self, code: str = "MONITOR_UNAVAILABLE", *, failure: object | None = None) -> None:
        self.code = code
        # A private authentication classification for the recorder; never part of a response.
        self.failure = failure
        super().__init__("Monitoring unavailable")


RestrictedTarget = Annotated[
    str, Field(min_length=1, max_length=97, pattern=r"^[A-Za-z0-9._:-]+\*?$")
]
ToolName = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")]


class DetectionProfile(BaseModel):
    """An immutable, versioned detection configuration set by a current ADMIN."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)

    sensitive_actions: tuple[Action, ...] = Field(max_length=256)
    restricted_targets: tuple[RestrictedTarget, ...] = Field(max_length=256)
    burst_threshold: int | None = Field(default=None, ge=2, le=10000)
    burst_window_seconds: int | None = Field(default=None, ge=60, le=86400)
    # Collected AI tool names an ADMIN states are a catalog action; an unmapped tool name
    # stays insufficient evidence rather than becoming a silent pass.
    ai_tool_actions: dict[ToolName, Action] = Field(default_factory=dict, max_length=64)

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if (self.burst_threshold is None) != (self.burst_window_seconds is None):
            raise ValueError("Burst threshold and window are set together")
        if len(set(self.sensitive_actions)) != len(self.sensitive_actions):
            raise ValueError("Duplicate sensitive action")
        if len(set(self.restricted_targets)) != len(self.restricted_targets):
            raise ValueError("Duplicate restricted target")
        return self

    def matches_target(self, target_ref: str | None) -> bool:
        if target_ref is None:
            return False
        for pattern in self.restricted_targets:
            if pattern.endswith("*"):
                if target_ref.startswith(pattern[:-1]):
                    return True
            elif target_ref == pattern:
                return True
        return False


@dataclass(frozen=True)
class ProfileRecord:
    profile_id: UUID
    version: int
    created_at: datetime
    created_by: UUID
    retired_at: datetime | None
    profile: DetectionProfile


@dataclass(frozen=True)
class SourceGrant:
    tenant_id: UUID
    source_id: UUID
    token: str = field(repr=False)
    # After a rotation, when the token it replaced stops reporting; None without a grace.
    previous_valid_until: datetime | None = None


class ObservationEvent(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)

    version: Literal[1] = 1
    event_id: Identifier
    story_id: Identifier
    occurred_at: AwareDatetime
    kind: Literal["tool_result", "heartbeat"]
    action: Action | None = None
    target_ref: Identifier | None = None
    outcome: Literal["success", "error", "unknown"] | None = None

    @field_validator("version", mode="before")
    @classmethod
    def integer_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Invalid version")
        return value

    @field_validator("occurred_at")
    @classmethod
    def utc_time(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def event_shape(self) -> Self:
        if self.kind == "tool_result" and (self.action is None or self.outcome is None):
            raise ValueError("Tool result requires action and outcome")
        if self.kind == "heartbeat" and any(
            value is not None for value in (self.action, self.target_ref, self.outcome)
        ):
            raise ValueError("Heartbeat cannot claim a tool result")
        return self


AI_MODEL_OPERATION = "AiModelRun"
AI_TOOL_OPERATION = "AiToolRun"
# A versioned mapping of Tines audit operation names to the change each one describes. The
# names are fixture-verified only: no live audit-log trial has confirmed them yet (see
# docs/TINES_MONITORING.md). An operation outside this mapping is never guessed into a
# match, and the collector records it as evidence whose meaning is not established.
TINES_OPERATIONS = {
    "StoryCreated": "story",
    "StoryUpdated": "story",
    "StoryDeleted": "story",
    "StoryImported": "story",
    "StoryEnabled": "story",
    "StoryDisabled": "story",
    "ActionCreated": "action",
    "ActionUpdated": "action",
    "ActionDeleted": "action",
    "CredentialCreated": "credential",
    "CredentialUpdated": "credential",
    "CredentialDeleted": "credential",
    "MemberInvited": "tenant",
    "MemberRemoved": "tenant",
    "TenantSettingUpdated": "tenant",
    AI_MODEL_OPERATION: "ai_model_run",
    AI_TOOL_OPERATION: "ai_tool_run",
}
CHANGE_CLASSES = frozenset({"story", "action", "credential", "tenant"})

# Action types that make an outbound request, and types that stay inside the platform.
# Neither list is confirmed complete against a live tenant; a type in neither is unknown
# coverage, never "no outbound".
OUTBOUND_ACTION_TYPES = frozenset(
    {"Agents::HTTPRequestAgent", "Agents::EmailAgent", "Agents::IMAPAgent"}
)
LOCAL_ACTION_TYPES = frozenset(
    {
        "Agents::EventTransformationAgent",
        "Agents::TriggerAgent",
        "Agents::WebhookAgent",
        "Agents::GroupAgent",
        "Agents::SendToStoryAgent",
    }
)
