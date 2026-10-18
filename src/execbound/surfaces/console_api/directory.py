# SPDX-License-Identifier: AGPL-3.0-only
"""What the directory areas of the console API share: Agents, People, Credentials, Approver scopes.

Each area wraps the functions its page calls today
(#333), so this module holds only what
the JSON shape needs: the body models every area takes (a label, a reason, a lifetime, nothing), the
credential row and the show-once credential every area returns, the map from a definer
function's refusal to the API's typed code, and the query parameters a list declares for the
document without letting FastAPI parse them, so a value outside the choices is refused with the
API's own code and never echoed back.
"""

from datetime import datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from execbound.administration import AdministrationError
from execbound.surfaces.admin_pages import LIFETIMES, IssuedSecret
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.sessions import Session

Lifetime = Literal["1", "8", "24", "168", "720", "2160"]
# An agent's API key may also never expire (0057); a person's credential and a set-password
# code keep `Lifetime`, so no route that issues one to a person accepts `never`.
KeyLifetime = Literal["1", "8", "24", "168", "720", "2160", "never"]
CredentialState = Literal["live", "expired", "revoked"]
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
LABEL_LIMIT = 80
REASON_LIMIT = 500
EMAIL_LIMIT = 254


class Empty(BaseModel):
    """A change that carries nothing but the request itself; `{}` and no other field."""

    model_config = ConfigDict(extra="forbid")


class LabelBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=LABEL_LIMIT)


class EmailBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=EMAIL_LIMIT)


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=REASON_LIMIT)


class LifetimeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lifetime: Lifetime


class KeyLifetimeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lifetime: KeyLifetime


class AgentKeyBody(KeyLifetimeBody):
    """An agent's key, optionally replacing a live key of the same agent (Rotate)."""

    model_config = ConfigDict(extra="forbid")

    # The old key's id in its one canonical spelling; the body is validated strictly.
    replaces: str | None = Field(default=None, pattern=UUID_PATTERN)


class Created(BaseModel):
    principal_id: UUID


class CredentialRow(BaseModel):
    credential_id: UUID
    # The key's counting number in its workspace (0058); `None` for a person's credential.
    number: int | None = None
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    state: CredentialState
    failures: int
    # When the key last authenticated, at most once a minute (0079); display only.
    last_used_at: datetime | None = None
    # A live key names this one as the key it replaces, through Rotate (0079).
    replaced: bool = False


class IssuedCode(BaseModel):
    """A one-time set-password code, with the page to open and nothing else.

    It comes back in the mutation response that minted it, which is `Cache-Control: no-store`
    like every console response; the client shows it once in the same dialog a credential is
    shown in. The code is not part of the address, so nothing carrying it is ever a link.
    """

    code: str
    address: str
    reset_id: UUID
    principal_id: UUID
    expires_at: datetime


class IssuedCredential(BaseModel):
    """The one-time secret with its identifiers.

    It comes back in the one mutation response that created it, which every console response
    already sends as `Cache-Control: no-store`; the client shows it once in a dialog and holds
    it nowhere else. The audit chain records the identifiers only.
    """

    token: str
    credential_id: UUID
    principal_id: UUID
    kind: str
    expires_at: datetime
    number: int | None = None


# A definer function's refusal, as the API's typed code and, for a body fault, its field.
REFUSALS: dict[str, tuple[str, list[str] | None]] = {
    "INVALID_LABEL": ("INVALID_BODY", ["label"]),
    # Rotate named a key that is not a live key of this agent, or that a live key replaces.
    "INVALID_REPLACEMENT": ("CONFLICT", None),
    "INVALID_EMAIL": ("INVALID_BODY", ["email"]),
    "EMAIL_TAKEN": ("CONFLICT", None),
    "INVALID_REASON": ("INVALID_BODY", ["reason"]),
    "INVALID_LIFETIME": ("INVALID_BODY", ["lifetime"]),
    "INVALID_TARGET": ("INVALID_BODY", ["target"]),
    "INVALID_ACTION": ("INVALID_BODY", ["action"]),
    "INVALID_KIND": ("INVALID_BODY", ["kind"]),
    "INVALID_PRINCIPAL": ("INVALID_PRINCIPAL", None),
    "INVALID_AGENT": ("CONFLICT", None),
    "INVALID_STATE": ("CONFLICT", None),
    "INVALID_CREDENTIAL": ("CONFLICT", None),
    "INVALID_SCOPE": ("CONFLICT", None),
    "INVALID_ACTOR": ("FORBIDDEN", None),
    "INVALID_TENANT": ("FORBIDDEN", None),
    "PLAN_LIMIT": ("PLAN_LIMIT", None),
    # A principal a re-invitation replaced is retired for good (0061); the person is managed
    # through the entry that replaced it, which "Something changed first" would not say.
    "PRINCIPAL_REPLACED": ("PRINCIPAL_REPLACED", None),
    # A tenant with several spaces and an administrator looking at all of them: which
    # space a new object belongs to has to be chosen rather than guessed.
    "INVALID_SPACE": ("SPACE_REQUIRED", None),
    "SPACE_ARCHIVED": ("SPACE_ARCHIVED", None),
}


def refused(exc: AdministrationError) -> ApiError:
    """The typed refusal for a function's code; anything unlisted is unavailability."""
    code, fields = REFUSALS.get(exc.code, ("UNAVAILABLE", None))
    return ApiError(code, fields=fields)


def admin(session: Session) -> Session:
    """The directory is the administrator's; an approver is refused as on the pages."""
    if session.identity.kind != "ADMIN":
        raise ApiError("FORBIDDEN")
    return session


def parse_uuid(value: str, status: int = 404) -> UUID:
    """A path or body identifier in its one canonical spelling, or the given refusal."""
    try:
        identifier = UUID(value)
    except ValueError:
        raise HTTPException(status, "Invalid request") from None
    if str(identifier) != value:
        raise HTTPException(status, "Invalid request")
    return identifier


def lifetime_of(value: Lifetime) -> timedelta:
    return LIFETIMES[value][0]


def key_lifetime_of(value: KeyLifetime) -> timedelta | None:
    """An API key's lifetime; `None` is a key that never expires."""
    return None if value == "never" else LIFETIMES[value][0]


def credential_rows(rows: list[dict[str, Any]]) -> list[CredentialRow]:
    return [CredentialRow.model_validate(row) for row in rows]


def issued_view(issued: IssuedSecret) -> IssuedCredential:
    return IssuedCredential(
        token=issued.token,
        credential_id=issued.credential_id,
        principal_id=issued.principal_id,
        kind=issued.kind,
        expires_at=issued.expires_at,
        number=issued.number,
    )


def _inlined(node: Any, defs: dict[str, Any]) -> Any:
    """A body schema with its `$defs` substituted in place, and none left to resolve.

    Pydantic writes a nested model as `$ref: "#/$defs/<name>"`, which is relative to the
    document root and so resolves to nothing once the schema is inlined under `requestBody`.
    A body model is small and never recursive, so substituting is exact and terminates; a flat
    model has no `$defs` and is returned unchanged.
    """
    if type(node) is dict:
        reference = node.get("$ref")
        if type(reference) is str and reference.startswith("#/$defs/"):
            return _inlined(defs[reference.removeprefix("#/$defs/")], defs)
        return {key: _inlined(value, defs) for key, value in node.items() if key != "$defs"}
    if type(node) is list:
        return [_inlined(item, defs) for item in node]
    return node


def body_of(model: type[BaseModel]) -> dict[str, Any]:
    """The `openapi_extra` block declaring a change's body for the generated client.

    The guard reads and validates the body itself (bounded, no duplicate key, a strict model),
    so FastAPI never parses it and a fault answers `INVALID_BODY` naming the field; the
    document still carries the model, so the client's body type is exact.
    """
    schema = model.model_json_schema()
    schema = _inlined(schema, schema.get("$defs", {}))
    schema.pop("title", None)
    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": schema}},
        }
    }


def query_parameters(
    choices: dict[str, tuple[str, ...]], *, cursor: bool = False
) -> dict[str, Any]:
    """The `openapi_extra` block declaring a list's query keys for the generated client.

    The handler reads `request.query_params` itself under the guard's allowlist, so FastAPI
    never parses these and a value outside the choices answers `INVALID_REQUEST` with nothing
    echoed back; the document still carries the choices, so the client's query type is exact.
    """
    parameters: list[dict[str, Any]] = [
        {
            "name": name,
            "in": "query",
            "required": False,
            "schema": {"type": "string", "enum": list(options), "default": options[0]},
        }
        for name, options in choices.items()
    ]
    if cursor:
        parameters.append(
            {"name": "cursor", "in": "query", "required": False, "schema": {"type": "string"}}
        )
    return {"parameters": parameters}


def filters_from(query: Any, choices: dict[str, tuple[str, ...]]) -> dict[str, str]:
    """Each declared key's value, its first choice by default; anything else is refused."""
    filters: dict[str, str] = {}
    for name, options in choices.items():
        value = query.get(name, options[0])
        if value not in options:
            raise ApiError("INVALID_REQUEST")
        filters[name] = value
    return filters
