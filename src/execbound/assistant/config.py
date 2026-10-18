# SPDX-License-Identifier: AGPL-3.0-only
"""What the operator configures, as one frozen value the rest of the package reads.

The block is optional in the private configuration; a deployment without it has no assistant
at all, and this object is never constructed for one. The key arrives through the environment
(`EXECBOUND_ASSISTANT_API_KEY`), as the mail password does, and is never written anywhere.
"""

from dataclasses import dataclass, field

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_BASE_URL = "https://api.anthropic.com"
API_VERSION = "2023-06-01"
KEY_VARIABLE = "EXECBOUND_ASSISTANT_API_KEY"
# Stated beside the tenant switch, on the page and in the CLI, so the person turning the
# assistant on reads it at that moment: the provider's retention of what is sent.
PROVIDER_RETENTION = (
    "Prompts and answers are kept by the model provider for up to 30 days under its "
    "commercial terms; zero retention is by separate agreement, and the provider's newest "
    "high-end models keep 30 days even under that agreement."
)


@dataclass(frozen=True)
class AssistantConfig:
    api_key: str = field(repr=False)
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL
    # The caps the operator sets; a tenant's ADMIN turns the feature on beneath them.
    tenant_daily_tokens: int = 200_000
    person_hourly_turns: int = 20
    # The bounds of one turn. Each ends the turn with its own reason and nothing is retried.
    max_tool_calls: int = 8
    time_limit_seconds: int = 60
    max_output_tokens: int = 2_000
    # An explanation is short and the cost is the tenant's: low effort, thinking left to the
    # model's default. The operator may raise it in the block.
    effort: str = "low"
    # A turn still running this long after creation reads as failed, which also covers a
    # process restart mid-turn.
    abandon_after_seconds: int = 90
    # Per provider call, inside the turn's time limit.
    call_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not self.api_key or not self.api_key.strip():
            raise ValueError("Invalid assistant configuration")
        if self.effort not in {"low", "medium", "high"}:
            raise ValueError("Invalid assistant configuration")
        for name in (
            "tenant_daily_tokens",
            "person_hourly_turns",
            "max_tool_calls",
            "time_limit_seconds",
            "max_output_tokens",
            "abandon_after_seconds",
        ):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError("Invalid assistant configuration")
        if not self.base_url.startswith("https://") and not self.base_url.startswith(
            "http://127.0.0.1"
        ):
            raise ValueError("Invalid assistant configuration")
