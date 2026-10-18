# SPDX-License-Identifier: Apache-2.0
"""Wire contract, errors and helpers shared by the synchronous and asynchronous clients.

The gateway's contract is `docs/API_REFERENCE.md` in the ExecBound repository. The client
invents no fields, ignores unknown response fields, and never sends tenant, principal or
role: identity comes from the credential alone.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeGuard

import httpx

PENDING_STATES = frozenset({"PENDING_APPROVAL"})
UNCERTAIN_STATES = frozenset({"DISPATCH_COMMITTED", "INDETERMINATE"})
TERMINAL_STATES = frozenset(
    {"DENIED", "EXECUTED", "FAILED_NOT_EXECUTED", "STALE_AUTHORIZATION", "OBSERVED"}
)
# What a denial tells the agent of why: another request holds the target, a shared limit is
# spent, or nothing (the gateway's `DenialCategory`).
DENIAL_CATEGORIES = frozenset({"busy", "limit", "withheld"})
# What a listed action and each of its arguments carry, with the type of each (the gateway's
# `ListedAction` and `ListedArgument`); `strings` is a list of strings.
LISTED_FIELDS = {
    "operation_ref": "string",
    "action": "string",
    "label": "string",
    "arguments": "arguments",
    "target_kinds": "strings",
    "incident_required": "boolean",
}
ARGUMENT_FIELDS = {
    "name": "string",
    "type": "string",
    "values": "strings",
    "minimum": "integer",
    "maximum": "integer",
}
CONTINUATION_HEADER = "X-Execution-Continuation"
URL_VARIABLE = "EXECBOUND_URL"
CREDENTIAL_VARIABLE = "EXECBOUND_CREDENTIAL"  # nosec B105 - a variable name, not a secret
CREDENTIAL_FILE_VARIABLE = "EXECBOUND_CREDENTIAL_FILE"  # nosec B105 - a variable name
MAX_CREDENTIAL_BYTES = 162
KEY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
OPERATION_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
TARGET_KINDS = frozenset({"canonical", "hostname", "provider_id"})
_UNSAFE = re.compile(r"[^A-Za-z0-9._:-]+")


class ExecBoundError(Exception):
    """A refusal with the gateway's stable code; never contains the credential."""

    def __init__(self, status: int, code: str, retry_after: int | None = None) -> None:
        self.status, self.code, self.retry_after = status, code, retry_after
        super().__init__(f"ExecBound refused with {status} {code}")


class ExecBoundUncertain(Exception):
    """The gateway may have acted. Hand the execution to an administrator; never resend
    under a new key."""

    def __init__(self, view: dict[str, Any]) -> None:
        self.view = view
        super().__init__(f"Execution {view.get('execution_id')} is {view.get('state')}")


class ConfigurationError(Exception):
    """The client could not be configured; the message names a variable, never a value."""


@dataclass(frozen=True)
class Outcome:
    """The final view of one intent plus how the client got there."""

    view: dict[str, Any]
    polls: int = 0
    retries: int = 0

    @property
    def state(self) -> str:
        return str(self.view["state"])

    @property
    def execution_id(self) -> str | None:
        value = self.view.get("execution_id")
        return None if value is None else str(value)

    @property
    def request_ref(self) -> str | None:
        value = self.view.get("request_ref")
        return None if value is None else str(value)

    @property
    def approval_state(self) -> str | None:
        value = self.view.get("approval_state")
        return None if value is None else str(value)

    @property
    def approval_url(self) -> str | None:
        value = self.view.get("approval_url")
        return None if value is None else str(value)

    @property
    def pending(self) -> bool:
        return self.state in PENDING_STATES

    @property
    def uncertain(self) -> bool:
        return self.state in UNCERTAIN_STATES

    @property
    def expired(self) -> bool:
        """The approval ran out before a decision; this intent is over and a new key is needed."""
        return self.state == "STALE_AUTHORIZATION" and self.approval_state == "EXPIRED"


@dataclass(frozen=True)
class Settings:
    """Where the gateway is and what credential to present, read from the environment or
    a private file, never from command-line arguments."""

    url: str
    credential: str

    @classmethod
    def from_environment(cls, environment: dict[str, str] | None = None) -> Settings:
        env = os.environ if environment is None else environment
        url = env.get(URL_VARIABLE, "").strip()
        if not url.startswith(("https://", "http://")):
            raise ConfigurationError(f"{URL_VARIABLE} must be the gateway's HTTPS origin")
        credential = env.get(CREDENTIAL_VARIABLE, "")
        source = CREDENTIAL_VARIABLE
        if not credential and env.get(CREDENTIAL_FILE_VARIABLE):
            source = CREDENTIAL_FILE_VARIABLE
            try:
                credential = Path(env[CREDENTIAL_FILE_VARIABLE]).read_text(encoding="ascii")
            except (OSError, UnicodeDecodeError):
                raise ConfigurationError(f"{source} does not name a readable file") from None
        credential = credential.strip()
        if (
            not credential
            or len(credential.encode("ascii", "replace")) > MAX_CREDENTIAL_BYTES
            or any(character.isspace() for character in credential)
        ):
            raise ConfigurationError(f"{source} does not hold a credential")
        return cls(url.rstrip("/"), credential)


def interpret(response: httpx.Response) -> dict[str, Any]:
    """Turn a gateway response into an execution view or a refusal with a stable code."""
    if response.status_code in (200, 202):
        try:
            view = response.json()
        except ValueError:
            raise ExecBoundError(response.status_code, "UNEXPECTED_RESPONSE") from None
        if not isinstance(view, dict) or "state" not in view:
            raise ExecBoundError(response.status_code, "UNEXPECTED_RESPONSE")
        return view
    raise _refusal(response)


def interpret_listing(response: httpx.Response) -> dict[str, Any]:
    """Turn a gateway response into the listing of the agent's space or a refusal with a
    stable code."""
    if response.status_code == 200:
        try:
            listing = response.json()
        except ValueError:
            raise ExecBoundError(response.status_code, "UNEXPECTED_RESPONSE") from None
        if not is_listing(listing):
            raise ExecBoundError(response.status_code, "UNEXPECTED_RESPONSE")
        return listing
    raise _refusal(response)


def is_listing(listing: Any) -> TypeGuard[dict[str, Any]]:
    """Whether an answer is the listing of the agent's space, over HTTP or MCP: an object
    with an `actions` list, each listed action an object naming its `operation_ref`, with
    its `arguments`, when present, a list of objects."""
    if not isinstance(listing, dict):
        return False
    actions = listing.get("actions")
    return isinstance(actions, list) and all(_listed(action) for action in actions)


def _listed(action: Any) -> bool:
    if not isinstance(action, dict) or not isinstance(action.get("operation_ref"), str):
        return False
    arguments = action.get("arguments", [])
    return isinstance(arguments, list) and all(isinstance(argument, dict) for argument in arguments)


def _refusal(response: httpx.Response) -> ExecBoundError:
    code = "UNKNOWN"
    try:
        body = response.json()
        if isinstance(body, dict) and isinstance(body.get("code"), str):
            code = body["code"]
    except ValueError:
        pass
    retry_after = None
    if response.headers.get("Retry-After", "").isdigit():
        retry_after = int(response.headers["Retry-After"])
    if response.status_code == 503 and code == "UNKNOWN":
        # A 503 is not proof that nothing was done: after a send, reuse the same key later.
        code = "UNAVAILABLE"
    return ExecBoundError(response.status_code, code, retry_after)


def action_request(
    operation_ref: str,
    target_kind: str,
    target_value: str,
    idempotency_key: str,
    *,
    incident_id: str | None = None,
    arguments: dict[str, Any] | None = None,
    run_id: str | None = None,
    external_case: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the strict wire request for one intent.

    `claimed_context` carries only the incident the action responds to: a claim selects
    independently verified context and never grants authority.
    """
    if not OPERATION_PATTERN.fullmatch(operation_ref):
        raise ValueError("operation_ref is not an operation reference")
    if target_kind not in TARGET_KINDS:
        raise ValueError("target_kind must be canonical, hostname or provider_id")
    if not KEY_PATTERN.fullmatch(idempotency_key):
        raise ValueError("idempotency_key must be 1 to 128 characters of [A-Za-z0-9._:-]")
    request: dict[str, Any] = {
        "operation_ref": operation_ref,
        "target": {"kind": target_kind, "value": target_value},
        "arguments": dict(arguments or {}),
        "idempotency_key": idempotency_key,
    }
    if external_case is not None:
        request["external_case"] = dict(external_case)
    if run_id is not None:
        request["run_id"] = run_id
    if incident_id is not None:
        request["claimed_context"] = {"incident_id": incident_id}
    return request


def intent_key(operation_ref: str, target_kind: str, target_value: str, reference: str) -> str:
    """Derive the idempotency key from the intent: the action, the target and the ticket,
    case or run that motivates it. The same intent always yields the same key, so a retry
    can never act twice, and there is deliberately no way to generate a key without a
    reference: a fresh random key is how an agent acts twice.
    """
    if not isinstance(reference, str) or not reference.strip():
        raise ValueError("reference must name the ticket, case or run behind the intent")
    digest = hashlib.sha256(
        json.dumps([operation_ref, target_kind, target_value, reference.strip()]).encode()
    ).hexdigest()
    slug = _UNSAFE.sub("-", reference.strip()).strip("-")[:40] or "intent"
    return f"{slug}-{digest[:32]}"


def summarize(outcome: Outcome) -> dict[str, Any]:
    """A short, model-safe summary of an outcome: identifiers and states, and no free text
    except a denial's `notice`, which the gateway writes as one fixed sentence naming only
    the request's reference and its category, so a model is told where a person can look
    rather than why. The category, `denial`, is passed on only when it is one of the three
    the gateway defines: `busy` and `limit` say a new request later may be decided
    differently, and `withheld` says nothing more."""
    if outcome.pending:
        kind = "pending"
    elif outcome.expired:
        kind = "expired"
    else:
        kind = "final"
    summary: dict[str, Any] = {
        "outcome": kind,
        "execution_id": outcome.execution_id,
        "state": outcome.state,
        "approval_state": outcome.approval_state,
        "approval_url": outcome.approval_url,
    }
    if kind == "expired":
        summary["next"] = "The approval expired before a decision; a new key starts a new intent."
    if outcome.request_ref is not None:
        summary["request_ref"] = outcome.request_ref
    notice = outcome.view.get("notice")
    if outcome.state == "DENIED" and isinstance(notice, str):
        summary["notice"] = notice
    denial = outcome.view.get("denial")
    if outcome.state == "DENIED" and denial in DENIAL_CATEGORIES:
        summary["denial"] = denial
    return summary


def summarize_listing(listing: dict[str, Any]) -> dict[str, Any]:
    """The listing of the agent's space as a model should see it: each action's reference,
    catalog action and label, its arguments with the values or range each accepts, the
    target kinds it takes and whether an incident is required, and nothing else. A field is
    kept only when it has the type the gateway defines, so neither a field a later gateway
    adds nor a value of another type reaches a model. A listed action is not permission: the
    gateway still decides every request, and a listed action whose provider is not connected
    is still refused."""
    return {
        "outcome": "listed",
        "actions": [_fields(action, LISTED_FIELDS) for action in listing["actions"]],
    }


def _fields(item: dict[str, Any], fields: dict[str, str]) -> dict[str, Any]:
    kept: dict[str, Any] = {}
    for field, kind in fields.items():
        value = item.get(field)
        if kind == "arguments" and isinstance(value, list):
            kept[field] = [
                _fields(argument, ARGUMENT_FIELDS)
                for argument in value
                if isinstance(argument, dict)
            ]
        elif _typed(value, kind):
            kept[field] = value
    return kept


def _typed(value: Any, kind: str) -> bool:
    if kind == "strings":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "boolean":
        return isinstance(value, bool)
    return kind == "string" and isinstance(value, str)
