# SPDX-License-Identifier: AGPL-3.0-only
"""A fixture Arcade caller, and the wire contract ExecBound needs a deployment to meet.

The mirror image of :mod:`execbound_harness.fake_tines`. There the fixture is the vendor
and ExecBound is the client; here ExecBound is the server and Arcade is the client, so what
is fixtured is the **caller**. It builds the hook bodies Arcade's published schema
describes, posts them at a running hook surface over loopback, and records what came back as
the shape a platform can branch on. It is a caller and never a second decision point: it
holds no ExecBound state, reads no database, keeps no secret and decides nothing.

`HOOK_CONTRACT` is the reason the module exists. It is the contract **ExecBound requires of
Arcade**, written from Arcade's published hook schema and from the two tables docs/ARCADE.md
answers with (The pre hook, The post hook) — deliberately not from what
`execbound.arcade.models` happens to accept, because a caller that replays what the parser
already admits establishes nothing about whether this integration fits a platform nobody
here has run. Three of its entries are narrower than the published schema and each is a
question a real deployment answers rather than a preference:

* **`success` is optional on the published post hook, and it is the one field of a post
  hook that decides what settles.** A deployment that omits it leaves every governed call it
  granted in retained uncertainty, which is limitation 2 and the heaviest cost this
  integration carries. The settlement table below states that in the three rows that turn on
  it, so a walk asserting against it establishes the fit before a tenant does.
* **`execution_id` is an unconstrained string on the wire and a bounded one here**, because
  it becomes the kernel's idempotency key verbatim. An id outside `EXECUTION_ID_PATTERN` is
  refused rather than mangled into one, so a platform minting ids outside that class blocks
  every governed tool call.
* **The two `CONTENT_TYPES` spellings are what the hook surface frames on**, compared
  case-insensitively. A post hook framed otherwise is a 400 the published contract does not
  retry, which loses the settlement it carried.

The deployment's own `post_bytes` is a fourth bound of the same kind, and it is not in the
contract because it is configuration rather than a fixed shape: a report larger than it is
read as silence, which is the settlement table's `unreadable_body` row.

**Protected mock.** The client this is handed must address loopback, so the only origin it
posts to is the loopback one that client names; it holds no credential of its own beyond the
synthetic bearer a caller passes in; and it names no vendor origin.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

import httpx

# What the hook message shapes were read from. Beta, and public prose plus a schema rather
# than a contract anyone has run here, which is why the shapes below are a thing to validate
# on arrival rather than a promise.
CONTRACT_SOURCE: Final = (
    "Arcade logic_extensions/http/1.0/schema.yaml, info.version 1.1.1-beta, read 17 September 2026"
)

# The two paths a hook deployment serves. `GET /health` is the third route it answers and is
# not a hook, so it is not this caller's business.
PRE_PATH: Final = "/pre"
POST_PATH: Final = "/post"
PATHS: Final = {"pre": PRE_PATH, "post": POST_PATH}

# The framing the hook surface admits, compared case-insensitively. The charset spelling
# leads because it is what a platform ExecBound does not control is documented to send.
CONTENT_TYPES: Final = ("application/json; charset=utf-8", "application/json")

# `ActionRequest.idempotency_key`'s character class, which Arcade's `execution_id` is
# carried into verbatim.
EXECUTION_ID_PATTERN: Final = r"^[A-Za-z0-9._:-]{1,128}$"

# The settlement table's word for a report that moves no state at all: the row is left
# wherever the arrival found it.
UNCHANGED: Final = "UNCHANGED"

# Hosts a fixture caller may address. `testserver` is the loopback origin an ASGI transport
# names; the rest are the loopback names a socket server binds.
LOOPBACK: Final = frozenset({"testserver", "localhost", "127.0.0.1", "::1"})

# The contract, in one object, so the integration guide, a demo driver and the acceptance
# walk asserting against it all read the same thing and a change to any shape fails in one
# place.
#
# `messages` is each hook message's required and optional fields, as the schema lists them.
# `request` is what a deployment needs above the body. `answer` is what an evaluated hook is
# answered with — a hook the surface decided, which is every answer the pre and post hook
# tables describe; transport-level statuses a post hook may also meet (a refused frame, a
# capacity refusal, a dependency failure) are not answers and are not here. `settlement` is
# the post hook's settlement table: what each arrival leaves the execution as, and nothing
# about how it is answered, because each arrival it distinguishes is answered `OK` and its
# last row is no arrival at all.
HOOK_CONTRACT: Final[dict[str, Any]] = {
    "source": CONTRACT_SOURCE,
    "messages": {
        "pre": {"required": ("context", "execution_id", "inputs", "tool"), "optional": ()},
        "post": {
            "required": ("context", "execution_id", "tool"),
            "optional": ("execution_code", "execution_error", "inputs", "output", "success"),
        },
        "tool": {"required": ("name", "toolkit", "version"), "optional": ("metadata",)},
        "context": {
            "required": (),
            "optional": ("authorization", "metadata", "secrets", "user_id"),
        },
    },
    "request": {
        "method": "POST",
        "paths": dict(PATHS),
        "content_types": CONTENT_TYPES,
        "authorization": "Bearer",
        "execution_id": EXECUTION_ID_PATTERN,
    },
    "answer": {
        "status": 200,
        "required": ("code",),
        "optional": ("error_message",),
        "codes": ("CHECK_FAILED", "OK", "RATE_LIMIT_EXCEEDED"),
    },
    "settlement": {
        "reported_success": {
            "success": True,
            "state": "EXECUTED",
            "tier": "ASSERTED",
            "impact": "CONFIRMED",
            "claim_released": False,
        },
        "reported_failure": {
            "success": False,
            "state": "FAILED_EFFECT_UNKNOWN",
            "tier": "ASSERTED",
            "impact": "CONFIRMED",
            "claim_released": False,
        },
        "absent_success": {
            "success": None,
            "state": "INDETERMINATE",
            "tier": None,
            "impact": "UNRESOLVED",
            "claim_released": False,
        },
        "unreadable_body": {
            "success": None,
            "state": UNCHANGED,
            "tier": None,
            "impact": "UNRESOLVED",
            "claim_released": False,
        },
        "no_post_hook": {
            "success": None,
            "state": UNCHANGED,
            "tier": None,
            "impact": "UNRESOLVED",
            "claim_released": False,
            "swept_to": "INDETERMINATE",
        },
    },
}


class ContractError(ValueError):
    """A message or a destination this caller is not allowed to build or address."""


def _shaped(message: str, body: Mapping[str, Any]) -> dict[str, Any]:
    """One message, checked against its own row of `HOOK_CONTRACT["messages"]`.

    Refusing here is what makes this a caller of the published contract rather than of
    whatever the deployment's parser tolerates. A field the contract does not describe is one
    nothing establishes that a platform sends, so a branch driven by one would establish
    nothing about a real deployment either; a required field left out would be a hook no
    deployment has to answer.
    """
    fields = HOOK_CONTRACT["messages"][message]
    keys = set(body)
    missing = sorted(set(fields["required"]) - keys)
    unknown = sorted(keys - set(fields["required"]) - set(fields["optional"]))
    if missing or unknown:
        raise ContractError(f"{message}: missing {missing}, undocumented {unknown}")
    return dict(body)


def tool_info(**fields: Any) -> dict[str, Any]:
    """Arcade's identity for the tool a hook is about: `ToolInfo`, and its one optional."""
    return _shaped("tool", fields)


def tool_context(**fields: Any) -> dict[str, Any]:
    """Arcade's per-call context: `ToolContext`, every field of which is optional."""
    return _shaped("context", fields)


def pre_body(
    *,
    execution_id: str,
    tool: Mapping[str, Any],
    inputs: Mapping[str, Any],
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One `PreHookRequest`. All four of its fields are required and it has no optional one.

    `context` defaults to the empty object rather than to a populated one: the field is
    required and every field *inside* it is optional, so the empty object is the least a pre
    hook may carry, and a deployment refusing it would not fit a platform that sent one.
    """
    return _shaped(
        "pre",
        {
            "execution_id": execution_id,
            "tool": _shaped("tool", tool),
            "inputs": dict(inputs),
            "context": _shaped("context", context or {}),
        },
    )


def post_body(
    *,
    execution_id: str,
    tool: Mapping[str, Any],
    context: Mapping[str, Any] | None = None,
    **reported: Any,
) -> dict[str, Any]:
    """One `PostHookRequest`: three required fields, and whichever optionals were passed.

    `success` is passed like any other optional and defaulted to nothing, because the
    published schema makes it optional and a default here would hide the row of the settlement
    table that turns on its absence.
    """
    return _shaped(
        "post",
        {
            "execution_id": execution_id,
            "tool": _shaped("tool", tool),
            "context": _shaped("context", context or {}),
            **reported,
        },
    )


def answer_unfit(shape: Mapping[str, Any]) -> tuple[str, ...]:
    """Every way one recorded answer fails `HOOK_CONTRACT["answer"]`, named rather than counted.

    A platform branches on the status and the code, so each part is checked on its own and
    the caller is told which one moved rather than that something did. An empty tuple is an
    answer that fits.
    """
    answer = HOOK_CONTRACT["answer"]
    keys = set(shape["keys"])
    missing = sorted(set(answer["required"]) - keys)
    unknown = sorted(keys - set(answer["required"]) - set(answer["optional"]))
    found = []
    if shape["status"] != answer["status"]:
        found.append(f"status {shape['status']}")
    if missing:
        found.append(f"missing {missing}")
    if unknown:
        found.append(f"undocumented {unknown}")
    if shape["code"] not in answer["codes"]:
        found.append(f"code {shape['code']!r}")
    return tuple(found)


@dataclass(frozen=True)
class Answer:
    """One hook answer, and the shape of it a platform branches on.

    `shape` carries the code and whether a message came with it, and never the message
    itself: the text names the ExecBound execution a refusal is about, so a recorded shape
    holding one would differ between two runs of the same walk. A caller that wants to read
    it reads `error_message`.
    """

    branch: str
    hook: str
    status: int
    body: Mapping[str, Any]

    @property
    def code(self) -> str | None:
        value = self.body.get("code")
        return value if isinstance(value, str) else None

    @property
    def error_message(self) -> str | None:
        value = self.body.get("error_message")
        return value if isinstance(value, str) else None

    def shape(self) -> dict[str, Any]:
        return {
            "hook": self.hook,
            "status": self.status,
            "keys": tuple(sorted(self.body)),
            "code": self.code,
            "explained": "error_message" in self.body,
        }


class FakeArcade:
    """One Arcade project calling one ExecBound hook deployment, over loopback.

    The bearer is whatever synthetic credential the caller provisions; this holds none of
    its own and none that is real. `content_type` is the framing every call uses unless one
    passes its own, and a call **may** pass a spelling the deployment refuses: this is the
    platform's side of the wire, and what a platform sends is exactly the thing a fixture is
    for. What it may not do is build a body the published contract does not describe.
    """

    def __init__(
        self, client: httpx.Client, token: str, *, content_type: str = CONTENT_TYPES[0]
    ) -> None:
        host = client.base_url.host
        if host not in LOOPBACK:
            raise ContractError(f"A fixture caller addresses loopback and not {host!r}")
        self._client = client
        self._token = token
        self._content_type = content_type
        # Every answer in the order it arrived, and the shapes keyed by the branch that
        # asked for it. Held on the caller rather than in a module global, so one walk's
        # record is never another's.
        self.answers: list[Answer] = []
        self.shapes: dict[str, dict[str, Any]] = {}

    def pre(
        self,
        branch: str,
        *,
        execution_id: str,
        tool: Mapping[str, Any],
        inputs: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
        content_type: str | None = None,
    ) -> Answer:
        """One pre hook: which tool, with which inputs, for whom."""
        body = pre_body(execution_id=execution_id, tool=tool, inputs=inputs, context=context)
        return self._send(branch, "pre", body, content_type)

    def post(
        self,
        branch: str,
        *,
        execution_id: str,
        tool: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
        content_type: str | None = None,
        **reported: Any,
    ) -> Answer:
        """One post hook: what the platform says about the call it just ran."""
        body = post_body(execution_id=execution_id, tool=tool, context=context, **reported)
        return self._send(branch, "post", body, content_type)

    def unfit(self) -> dict[str, tuple[str, ...]]:
        """Every branch whose answer failed the contract, with what failed. Empty is a pass."""
        return {
            branch: failures
            for branch, shape in self.shapes.items()
            if (failures := answer_unfit(shape))
        }

    def _send(
        self, branch: str, hook: str, body: Mapping[str, Any], content_type: str | None
    ) -> Answer:
        if branch in self.shapes:
            raise ContractError(f"Branch {branch!r} is recorded already")
        response = self._client.post(
            PATHS[hook],
            content=json.dumps(body),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": self._content_type if content_type is None else content_type,
            },
        )
        answer = Answer(branch, hook, response.status_code, _parsed(response))
        self.answers.append(answer)
        self.shapes[branch] = answer.shape()
        return answer


def _parsed(response: httpx.Response) -> dict[str, Any]:
    """The answer as an object, and the empty object for anything that is not one.

    A hook answer is a JSON object; a deployment answering anything else has already failed
    the contract, and what records that is the empty shape rather than an exception here.
    """
    try:
        value = response.json()
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}
