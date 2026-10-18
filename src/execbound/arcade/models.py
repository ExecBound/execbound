# SPDX-License-Identifier: AGPL-3.0-only
"""The hook messages this deployment accepts, and the one answer it gives back.

The shapes were read from Arcade's published beta schema rather than run against a
deployment, so each field here is validated on arrival rather than trusted: a body that does
not fit is a refusal, not a best effort. `StrictModel` forbids a field these messages do not
model, so a field the vendor adds to a hook message later is refused, and the governed tools
whose hooks carry it are blocked until an operator upgrades. That is the direction the tool
map takes for `inputs` and the rule it states in general (docs/ARCADE.md, The tool map) —
the default for anything undeclared is refusal — and the cost is written here rather than
discovered. `inputs` and the two `metadata` objects are the exceptions, because what they may
hold is the vendor's business rather than this deployment's: the map's allowlist bounds the
first and the map's `expect` comparison is the whole of what reads the others.

What a hook answer may carry is bounded for a different reason: `error_message` is read by
the agent whose tool call was refused, so it is inert text derived from ExecBound's own
vocabulary and from nothing the caller sent.
"""

import json
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import Field, ValidationError

from execbound.arcade.map import ToolkitName, ToolName, ToolVersion
from execbound.requests import StrictModel, _unique_object

# The three codes `PreHookResult` and `PostHookResult` admit. `override` is a fourth field
# of that message and this deployment never sets one, in either hook: the credential
# boundary (docs/ARCADE.md) forbids rewriting `inputs`, `secrets` or `output`, so an answer
# carries a code and, on a refusal, the text below.
HookCode = Literal["OK", "CHECK_FAILED", "RATE_LIMIT_EXCEEDED"]
# Long enough for a state literal, an execution id and the deployment's approvals page.
MAX_ERROR_MESSAGE = 256


class InvalidHook(ValueError):
    """A body that is not a hook this deployment can read; carries nothing the caller sent."""


class ToolInfo(StrictModel):
    """Arcade's identity for the tool it is about to run, and what it says about it.

    `metadata` is caller-supplied input, so `ToolMap` may only refuse on it. Nothing here
    reads it: it is passed through to the map's `expect` comparison and retained as inert
    text, which is the whole of what the tool map permits reported metadata to do.
    """

    name: ToolName
    toolkit: ToolkitName
    version: ToolVersion
    metadata: dict[str, Any] | None = None


class ToolContext(StrictModel):
    """Arcade's per-call context: attribution and names, never authority.

    `authorization` is absent from this model deliberately and is removed from the body
    before anything binds it (`parse_pre_hook`), because `authorization[].oauth2.at`
    carries access-token claims: ExecBound holds no key that could verify them, so they
    could never be authority, and this deployment has no reason to hold a third party's
    identity material. The published contract says `secrets` carries names and no values,
    so this integration hands ExecBound no token value it would have to refuse to store.

    `user_id` is Arcade's end user, reported per call. It is attribution and is retained as
    inert text; it is never an ExecBound identity, because identity comes from
    authentication, and it is never a limit scope, because a budget keyed on a string the
    caller chooses is a budget the caller can evade.
    """

    secrets: tuple[Annotated[str, Field(max_length=128)], ...] | None = Field(
        default=None, max_length=64
    )
    metadata: dict[str, Any] | None = None
    user_id: str | None = Field(default=None, min_length=1, max_length=256)


class PreHookRequest(StrictModel):
    """What Arcade asks before it runs a tool: which tool, with which inputs, for whom.

    `execution_id` is Arcade's own identifier for the tool call. It is bounded here and
    narrowed again where it becomes an idempotency key, because the kernel's key admits a
    smaller character class than this field does and a value outside it is refused rather
    than mangled into one.
    """

    execution_id: str = Field(min_length=1, max_length=256)
    tool: ToolInfo
    inputs: dict[str, Any] = Field(max_length=64)
    context: ToolContext


class PostHookRequest(StrictModel):
    """What Arcade says after it ran a tool, and how little of it is believed.

    `success` is **optional** in the published schema, and that is the most consequential
    correction to a first reading of it: its absence states no result and settles nothing, so it
    is modelled as three answers — true, false and nothing said — rather than as a flag with a
    default.

    `output` is absent from this model deliberately and is dropped from the body before
    anything binds it (`parse_post_hook`), so no field of any object this returns was ever
    bound from it: it is whatever the tool returned, for a platform whose published
    examples are mail and ERP queries, and treating it as a receipt would make a
    self-reported string structurally indistinguishable from a provider journal.

    Three fields carry no length rule of their own, and the reason is the body bound's: a
    refusal on this route settles nothing, is never retried and leaves the grant to the
    sweep, so a length rule that turned an otherwise readable report into silence would be a
    new silent case. `execution_code` and `execution_error` are free-form vendor text, and
    `inputs` — which the pre hook's own model bounds at sixty-four keys — is compared and
    never retained. Each is bounded by `post_bytes` on the way in, and the two strings again
    by the correlation row's column widths at rest, where the bound is a truncation rather
    than a refusal. `tool` and `context` keep the pre hook's models, because those shapes
    are the platform's own and neither selects an execution here.
    """

    execution_id: str = Field(min_length=1, max_length=256)
    tool: ToolInfo
    context: ToolContext
    inputs: dict[str, Any] | None = None
    success: bool | None = None
    execution_code: str | None = None
    execution_error: str | None = None


@dataclass(frozen=True)
class HookResult:
    """One hook answer: a code the platform acts on, and inert text for a person.

    `error_message` lands in the agent's context, so it is derived from a stable ExecBound
    code, the ExecBound execution id where one exists and, for a pending approval, the
    deployment's approvals page. It carries no input value, no vendor string, no policy
    rule body, no report secret and no continuation token. The bound below is the last
    guard on that: the approvals page is deployment configuration of no declared length,
    and an agent's context is not the place to discover how long an operator's origin is.
    """

    code: HookCode
    error_message: str | None = None

    def body(self) -> dict[str, str]:
        if self.error_message is None:
            return {"code": self.code}
        return {"code": self.code, "error_message": self.error_message[:MAX_ERROR_MESSAGE]}


def _reject(value: str) -> Any:
    """Refuse the JSON constants; `NaN` and the infinities are not values this reads."""
    raise ValueError("Unsupported JSON constant")


def _hook_object(raw: bytes) -> dict[str, Any]:
    """The hook body as a plain object, with the access token dropped before anything binds.

    Duplicate keys are refused rather than resolved, because which of two spellings of
    `inputs` a parser keeps would decide what the deployment governs. Ordinary JSON numbers
    are admitted: a float in a declared input that maps to an argument is refused by
    `Arguments` afterwards, and a float in any other declared input decides nothing here,
    which is limitation 1's residual rather than a new one.

    `context.authorization` carries access-token claims when the token is a JWT. It is
    dropped here rather than left to `extra="forbid"` so that the removal is a fact about
    what both parsers re-serialize, rather than a refusal of the hooks that send one. What
    each parser drops beyond this is its own message's, and only `parse_post_hook` drops
    anything more.
    """
    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject
    )
    if not isinstance(value, dict):
        raise ValueError("A hook is a JSON object")
    context = value.get("context")
    if isinstance(context, dict):
        context.pop("authorization", None)
    return value


def parse_pre_hook(raw: bytes) -> PreHookRequest:
    """The pre hook these bytes are, with the access token dropped before anything binds it.

    The model is validated through pydantic's strict JSON path, as `parse_request` is, over
    the object `_hook_object` re-serialized with the access token no longer in it, so no
    field of any object this returns was ever bound from one. What that function refuses
    before the model sees anything is written there.
    """
    try:
        return PreHookRequest.model_validate_json(json.dumps(_hook_object(raw)))
    except (ValueError, ValidationError, RecursionError):
        # Raised outside the handler so no validation detail carrying caller content is
        # retained on the exception this refusal is built from.
        pass
    raise InvalidHook("INVALID_HOOK")


def parse_post_hook(raw: bytes) -> PostHookRequest:
    """The post hook these bytes are, with the access token and `output` both dropped.

    `output` is removed before the model binds anything, so it is in no object this returns
    rather than in one nothing happens to read, and it is validated for nothing on the way
    past: what it holds is the vendor's business and this deployment reads none of it. The
    strict discipline this shares with the outcome route — duplicate keys refused,
    nonfinite numbers refused, bounded recursion — applies to the fields the post hook reads.

    A body this refuses is **silence** and not a refusal the platform sees: the route
    answers `OK`, settles nothing and leaves the execution where it found it. That is the
    caller's own rule rather than this function's, and `routes._post` is where it is made.
    """
    try:
        value = _hook_object(raw)
        value.pop("output", None)
        return PostHookRequest.model_validate_json(json.dumps(value))
    except (ValueError, ValidationError, RecursionError):
        pass
    raise InvalidHook("INVALID_HOOK")
