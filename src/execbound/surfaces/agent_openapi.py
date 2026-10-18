# SPDX-License-Identifier: AGPL-3.0-only
"""The agent API's OpenAPI document, written from the models the gateway validates with.

The agent routes in `surfaces/http.py` read and validate their own bodies, so FastAPI can
describe their paths but not what they accept or answer, and the application serves no
OpenAPI document at all. This module writes one for people building agents: each request body
is the pydantic model the route parses, the answer is `ExecutionView` plus what
`Runtime.present` adds to it, and the error statuses come from `ERROR_STATUS`, the table the
gateway answers with. `tests/test_agent_openapi.py` holds the paths to the routes the gateway
serves and the committed document to this builder; `scripts/agent_openapi.py` writes it.

The prose a caller reads before any route, from the introduction to MCP, is
`surfaces/agent_api_guide.py`. MCP at `/mcp/` is a protocol endpoint rather than a set of
paths, so that prose describes its three tools.
"""

from dataclasses import fields
from typing import Any, get_args

from pydantic import TypeAdapter
from pydantic.json_schema import models_json_schema

from execbound.execution.models import (
    CheckpointGrant,
    DenialCategory,
    ExecutionView,
    ObservedResult,
)
from execbound.execution.offered import ActionListing
from execbound.execution.outcomes import OutcomeReport
from execbound.identity import Identity
from execbound.requests import ActionRequest
from execbound.runtime import denial_notice
from execbound.surfaces.agent_api_guide import introduction
from execbound.surfaces.http import ERROR_STATUS

REF = "#/components/schemas/{model}"

# What each status means to a caller, and the codes it carries. A code the gateway does not
# list in ERROR_STATUS is answered 503; these are the ones admission raises today.
UNAVAILABLE_CODES = (
    "EXECUTION_UNAVAILABLE",
    "NO_ACTIVE_BUNDLE",
    "TOO_MANY_GRANTS",
    "CONNECTOR_UNAVAILABLE",
    "INVALID_APPROVAL",
    "INVALID_OWNER",
    "INVALID_CLOCK",
    "INVALID_EVIDENCE",
)
STATUS_TEXT = {
    400: "The request is malformed, or a continuation or record is not valid.",
    403: "The credential is not an agent's, or a report did not authenticate.",
    404: "No execution with this id belongs to this agent.",
    409: "The request conflicts with the execution's state or the workspace's configuration.",
    423: "The workspace is stopped, or the agent's space takes no new work.",
    429: "Too many requests; wait for `Retry-After` when it is present.",
    503: "Execution is unavailable. Unknown actions and targets are answered this way on purpose.",
}


def codes_by_status() -> dict[int, list[str]]:
    """Every execution error code, grouped by the status the gateway answers it with."""
    grouped: dict[int, list[str]] = {}
    for code, status in ERROR_STATUS.items():
        grouped.setdefault(status, []).append(code)
    grouped[503] = list(UNAVAILABLE_CODES)
    return {status: sorted(codes) for status, codes in sorted(grouped.items())}


def _schemas() -> dict[str, Any]:
    _, definitions = models_json_schema(
        [
            (ActionRequest, "validation"),
            (OutcomeReport, "validation"),
            (ExecutionView, "serialization"),
            (ObservedResult, "serialization"),
            (CheckpointGrant, "serialization"),
            (ActionListing, "serialization"),
        ],
        ref_template=REF,
    )
    schemas: dict[str, Any] = dict(definitions.get("$defs", {}))
    identity = TypeAdapter(Identity).json_schema(mode="serialization", ref_template=REF)
    identity["title"] = "Identity"
    identity["description"] = "The agent the API key authenticates."
    identity["required"] = [field.name for field in fields(Identity)]
    schemas["Identity"] = identity
    view = dict(schemas["ExecutionView"])
    properties = dict(view["properties"])
    properties.update(
        {
            "tenant_stopped": {
                "type": "boolean",
                "const": True,
                "description": "Present when the answer was given during an emergency stop.",
            },
            "observed": {
                "$ref": REF.format(model="ObservedResult"),
                "description": (
                    "Present only on an OBSERVED execution: what would have been decided."
                ),
            },
            "checkpoint": {"$ref": REF.format(model="Checkpoint")},
            "denial": {
                "type": "string",
                "enum": list(get_args(DenialCategory)),
                "description": (
                    "Present only on a DENIED execution: `busy` when another request holds "
                    "the target, `limit` when a shared limit covering the request is spent, "
                    "whatever else denied it, and `withheld` for every other denial. For "
                    "`busy` and `limit` a new request after the other request settles or the "
                    "limit resets is decided afresh; re-sending this request returns the same "
                    "answer. It never names the rule, the limit, a fact or another execution."
                ),
            },
            "notice": {
                "type": "string",
                "description": (
                    "Present only on a DENIED execution: one fixed sentence naming the "
                    "category and the request's reference and nothing else. The reason is "
                    "recorded for a person and never sent to the agent; relay `request_ref` "
                    "to a person rather than guessing why."
                ),
                "examples": [
                    denial_notice("EB-12", category) for category in get_args(DenialCategory)
                ],
            },
            "continuation": {
                "type": "string",
                "description": (
                    "Present only while an approval is pending. Send it as "
                    "`X-Execution-Continuation` to read the status; it lasts at most two "
                    "minutes, and re-sending the identical request renews it."
                ),
            },
            "approval_url": {
                "type": "string",
                "description": (
                    "Present only while an approval is pending: where a reviewer decides."
                ),
            },
        }
    )
    view["properties"] = properties
    view["title"] = "Execution"
    view["description"] = (
        "The state of one execution. 202 accompanies PENDING_APPROVAL, DISPATCH_COMMITTED and "
        "INDETERMINATE, which are not final; every other state is answered 200."
    )
    schemas["ExecutionView"] = view
    # A listed argument carries `values`, or `minimum` and `maximum`, only when its domain
    # has them; the answer omits the rest rather than sending null, so none is nullable.
    argument = dict(schemas["ListedArgument"])
    members = dict(argument["properties"])
    for name in ("values", "minimum", "maximum"):
        member = dict(members[name])
        [present] = [branch for branch in member.pop("anyOf") if branch != {"type": "null"}]
        member.pop("default")
        members[name] = {**present, **member}
    argument["properties"] = members
    schemas["ListedArgument"] = argument
    schemas["Checkpoint"] = {
        "title": "Checkpoint",
        "type": "object",
        "description": (
            "Present only on the answer that granted an external executor the act. ExecBound "
            "dispatched nothing: the executor performs the act and reports its outcome."
        ),
        "properties": {
            "grant": {
                "allOf": [{"$ref": REF.format(model="CheckpointGrant")}],
                "description": (
                    "The one act the executor may perform. When the vendor has a checkable "
                    "version it also carries `provider_command`, the command ExecBound would "
                    "have sent."
                ),
            },
            "act": {
                "type": ["string", "null"],
                "description": "A signed token for the act window, or null once it has closed.",
            },
        },
        "required": ["grant", "act"],
    }
    schemas["Error"] = {
        "title": "Error",
        "type": "object",
        "properties": {
            "detail": {"type": "string", "examples": ["Execution unavailable"]},
            "code": {
                "type": "string",
                "enum": sorted(code for codes in codes_by_status().values() for code in codes),
                "description": "Present on execution errors; absent on authentication errors.",
            },
        },
        "required": ["detail"],
    }
    return schemas


def _error(
    status: int, text: str | None = None, codes: tuple[str, ...] | None = None
) -> dict[str, Any]:
    """One error response: the status's own text and every code the gateway answers it with,
    or, for a route that can answer only some of them, that route's text and codes."""
    listed = list(codes) if codes is not None else codes_by_status().get(status, [])
    text = text if text is not None else STATUS_TEXT.get(status, "")
    if listed:
        text += " Codes: " + ", ".join(f"`{code}`" for code in listed) + "."
    response: dict[str, Any] = {
        "description": text.strip(),
        "content": {"application/json": {"schema": {"$ref": REF.format(model="Error")}}},
    }
    if status == 429:
        # BUSY is named only where it can arise: the listing is never busy.
        busy = ", not with BUSY" if "BUSY" in listed else ""
        response["headers"] = {
            "Retry-After": {
                "description": f"Seconds to wait. Sent with RATE_LIMITED{busy}.",
                "schema": {"type": "integer", "minimum": 1},
            }
        }
    return response


def _unauthorized() -> dict[str, Any]:
    return {
        "description": "The API key is missing, malformed, unknown, revoked or expired.",
        "headers": {"WWW-Authenticate": {"schema": {"type": "string", "const": "Bearer"}}},
        "content": {"application/json": {"schema": {"$ref": REF.format(model="Error")}}},
    }


def _execution(description: str) -> dict[str, Any]:
    return {
        "description": description,
        "content": {"application/json": {"schema": {"$ref": REF.format(model="ExecutionView")}}},
    }


def _responses() -> dict[str, Any]:
    responses: dict[str, Any] = {
        "200": _execution("A final or observed state: EXECUTED, DENIED, OBSERVED and the rest."),
        "202": _execution("Not final yet: PENDING_APPROVAL, DISPATCH_COMMITTED or INDETERMINATE."),
        "401": _unauthorized(),
    }
    for status in sorted({*ERROR_STATUS.values(), 503}):
        responses[str(status)] = _error(status)
    return dict(sorted(responses.items()))


# What `GET /v1/actions` can answer besides 200 and 401. It reads and changes nothing, so it
# is never busy, never conflicts with an execution and carries on through an emergency stop;
# only these codes reach it.
LISTING_ERRORS: dict[int, tuple[str, tuple[str, ...]]] = {
    400: ("A query string, an identity header or a body was sent.", ("INVALID_REQUEST",)),
    # `checked_request`'s refusal of a person's credential, which carries no code: a
    # deactivated agent is a 401, and one deactivated during the read a 503.
    403: ("The credential is not an agent's.", ()),
    409: ("The policy the agent's space selects is not active.", ("INVALID_BUNDLE",)),
    423: ("The agent's space is archived.", ("SPACE_ARCHIVED",)),
    429: ("Too many requests; wait for `Retry-After` when it is present.", ("RATE_LIMITED",)),
    503: ("The listing is unavailable; retry later.", ("EXECUTION_UNAVAILABLE",)),
}


def _listing_responses() -> dict[str, Any]:
    responses: dict[str, Any] = {
        "200": {
            "description": (
                "The operations the agent's space offers. A listed action is not permission."
            ),
            "content": {
                "application/json": {"schema": {"$ref": REF.format(model="ActionListing")}}
            },
        },
        "401": _unauthorized(),
    }
    for status, (text, codes) in LISTING_ERRORS.items():
        responses[str(status)] = _error(status, text, codes)
    return dict(sorted(responses.items()))


def _body(model: str) -> dict[str, Any]:
    return {
        "required": True,
        "content": {"application/json": {"schema": {"$ref": REF.format(model=model)}}},
    }


EXECUTION_ID = {
    "name": "execution_id",
    "in": "path",
    "required": True,
    "description": "The execution id, in lowercase canonical UUID form.",
    "schema": {"type": "string", "format": "uuid"},
}
REQUEST_ID = {
    "name": "X-Request-Id",
    "in": "header",
    "required": False,
    "description": "A UUID to correlate this call; any other value is replaced. Always echoed.",
    "schema": {"type": "string", "format": "uuid"},
}


def agent_api_document() -> dict[str, Any]:
    """The OpenAPI document of the agent API."""
    shared = _responses()
    me_responses = {
        "200": {
            "description": "The authenticated agent.",
            "content": {"application/json": {"schema": {"$ref": REF.format(model="Identity")}}},
        },
        "400": {
            "description": "A query string, an identity header or a body was sent.",
            "content": {"application/json": {"schema": {"$ref": REF.format(model="Error")}}},
        },
        "401": _unauthorized(),
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "ExecBound agent API",
            "version": "1",
            "description": introduction(codes_by_status()),
        },
        "servers": [{"url": "https://app.execbound.ai", "description": "Hosted"}],
        "security": [{"apiKey": []}],
        "tags": [
            {"name": "Execution", "description": "Propose an action and follow it to an outcome."},
            {"name": "Identity", "description": "Check which agent an API key belongs to."},
        ],
        "paths": {
            "/v1/actions": {
                "get": {
                    "tags": ["Execution"],
                    "operationId": "listActions",
                    "summary": "List the actions your space offers",
                    "description": (
                        "Each operation_ref this agent's space offers, with the catalog action, "
                        "its label, its arguments and their values, the target kinds it accepts "
                        "and whether an incident is required. A listed action is not permission: "
                        "every request is still decided. Targets, rules and limits are never "
                        "listed. An operation that is not listed is refused as an unknown one."
                    ),
                    "parameters": [REQUEST_ID],
                    "responses": _listing_responses(),
                }
            },
            "/v1/execute": {
                "post": {
                    "tags": ["Execution"],
                    "operationId": "execute",
                    "summary": "Propose one action",
                    "description": (
                        "Admission resolves the action and target, checks trusted context and "
                        "policy, and either executes, denies, observes, asks for approval or "
                        "grants an external executor the act."
                    ),
                    "parameters": [REQUEST_ID],
                    "requestBody": _body("ActionRequest"),
                    "responses": shared,
                }
            },
            "/v1/executions/{execution_id}": {
                "get": {
                    "tags": ["Execution"],
                    "operationId": "executionStatus",
                    "summary": "Read an execution's status",
                    "description": (
                        "Reads never dispatch. Only the agent that proposed it can read it."
                    ),
                    "parameters": [
                        EXECUTION_ID,
                        {
                            "name": "X-Execution-Continuation",
                            "in": "header",
                            "required": False,
                            "description": "The continuation from a pending approval's answer.",
                            "schema": {"type": "string", "maxLength": 4096},
                        },
                        REQUEST_ID,
                    ],
                    "responses": shared,
                }
            },
            "/v1/executions/{execution_id}/outcome": {
                "post": {
                    "tags": ["Execution"],
                    "operationId": "reportOutcome",
                    "summary": "Report an external executor's outcome",
                    "description": (
                        "Settles the checkpoint grant this execution holds. The report secret "
                        "names the grant; the API key is still required."
                    ),
                    "parameters": [EXECUTION_ID, REQUEST_ID],
                    "requestBody": _body("OutcomeReport"),
                    "responses": shared,
                }
            },
            "/v1/me": {
                "get": {
                    "tags": ["Identity"],
                    "operationId": "me",
                    "summary": "Check an API key",
                    "description": "Proposes nothing and records nothing. Useful to test a key.",
                    "parameters": [REQUEST_ID],
                    "responses": me_responses,
                }
            },
        },
        "components": {
            "securitySchemes": {
                "apiKey": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "eb1.<tenant>.<credential>.<secret>",
                    "description": "An agent's API key, shown once when it is issued.",
                }
            },
            "schemas": dict(sorted(_schemas().items())),
        },
    }
