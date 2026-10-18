# SPDX-License-Identifier: AGPL-3.0-only
"""The console's personal access token routes (design 2026-09-25): an administrator's own,
under `/settings/tokens`, and the workspace's, under `/tenant/tokens`. None is callable with a
token (`token_rules.TOKEN_REFUSED`); the store refuses a token session as well.

`revoke_token`/`delete_token` accept any token in the workspace because the definer functions
only require an administrator actor (migration 0063): `/settings/tokens/{token_id}/revoke` and
`/delete` narrow that to the caller's own tokens by checking the id with `token_exists` first,
answering `NOT_FOUND` for an id that is not the caller's own or does not exist at all. A
workspace administrator reaches any token in the tenant through
`/tenant/tokens/{token_id}/revoke`, which checks existence tenant-wide instead of ownership; an
administrator narrowed to spaces reaches their own and those of the people they administer
(migration 0072), and `GET /tenant/tokens` lists them the same tokens.
Either way, a token that exists but cannot take the action (deleting a live one, for one)
answers `CONFLICT` from the store's own refusal, never `NOT_FOUND`.
"""

from collections.abc import Callable
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound.personal_tokens import (
    TokenError,
    delete_token,
    issue_token,
    list_tokens,
    revoke_token,
    token_exists,
)
from execbound.runtime import Runtime
from execbound.surfaces.console_api.bodies import body
from execbound.surfaces.console_api.directory import (
    Empty,
    KeyLifetime,
    body_of,
    key_lifetime_of,
)
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session

TokenState = Literal["live", "expired", "revoked"]


class TokenRow(BaseModel):
    token_id: UUID
    credential_id: UUID = Field(
        description=(
            "The token's backing credential: every audit event the token caused names it as "
            "`actor_credential_id`, so this maps an event to the token's name."
        )
    )
    name: str
    owner_id: UUID
    owner_label: str | None
    created_at: str
    expires_at: str
    last_used_at: str | None
    state: TokenState


class TokensPage(BaseModel):
    tokens: list[TokenRow]


class IssueTokenBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    lifetime: KeyLifetime


class IssuedToken(BaseModel):
    token: str
    row: TokenRow


# A definer function's refusal, as the API's typed code and, for a body fault, its field.
# `INVALID_NAME` and `INVALID_LIFETIME` are raised only from `issue`, so naming the field
# is exact for every route this serves.
_REFUSALS: dict[str, tuple[str, list[str] | None]] = {
    "TOKEN_NOT_ALLOWED": ("TOKEN_NOT_ALLOWED", None),  # nosec B105 - An error code.
    "INVALID_ACTOR": ("FORBIDDEN", None),
    "DIRECTORY_REQUIRED": ("DIRECTORY_REQUIRED", None),
    "TOO_MANY_TOKENS": ("TOO_MANY_TOKENS", None),
    "INVALID_TOKEN": ("CONFLICT", None),  # nosec B105 - An error code.
    "INVALID_NAME": ("INVALID_BODY", ["name"]),
    "INVALID_LIFETIME": ("INVALID_BODY", ["lifetime"]),
}


def _code(error: TokenError) -> ApiError:
    code, fields = _REFUSALS.get(error.code, ("UNAVAILABLE", None))
    return ApiError(code, fields=fields)


def token_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    def page(current: Session, everyone: bool) -> TokensPage:
        rows = list_tokens(runtime.db, current, everyone=everyone, clock=runtime.clock)
        return TokensPage(tokens=[TokenRow.model_validate(row) for row in rows])

    @routes.get(
        "/settings/tokens",
        response_model=TokensPage,
        operation_id="listOwnTokens",
        summary="List your personal access tokens",
    )
    async def own(request: Request) -> TokensPage:
        current, _ = await guards.session(request, kind="ADMIN")
        try:
            return await run_in_threadpool(page, current, False)
        except TokenError as error:
            raise _code(error) from None

    @routes.post(
        "/settings/tokens/issue",
        response_model=IssuedToken,
        operation_id="issueToken",
        summary="Create a personal access token",
        openapi_extra=body(IssueTokenBody),
    )
    async def issue(request: Request) -> IssuedToken:
        current, parsed = await guards.mutation(request, IssueTokenBody, kind="ADMIN")
        lifetime = key_lifetime_of(parsed.lifetime)

        def run() -> IssuedToken:
            token, view = issue_token(
                runtime.db, current, parsed.name, lifetime, clock=runtime.clock
            )
            return IssuedToken(token=token, row=TokenRow(**view))

        try:
            return await run_in_threadpool(run)
        except TokenError as error:
            raise _code(error) from None

    for path, function, operation, summary in (
        (
            "/settings/tokens/{token_id}/revoke",
            revoke_token,
            "revokeOwnToken",
            "Revoke one of your tokens",
        ),
        (
            "/settings/tokens/{token_id}/delete",
            delete_token,
            "deleteOwnToken",
            "Delete one of your tokens",
        ),
        (
            "/tenant/tokens/{token_id}/revoke",
            revoke_token,
            "revokeWorkspaceToken",
            "Revoke a workspace token",
        ),
    ):
        everyone = path.startswith("/tenant/")

        def register(
            path: str = path,
            function: Callable[..., None] = function,
            operation: str = operation,
            summary: str = summary,
            everyone: bool = everyone,
        ) -> None:
            @routes.post(
                path,
                response_model=TokensPage,
                operation_id=operation,
                summary=summary,
                openapi_extra=body_of(Empty),
            )
            async def change(request: Request, token_id: UUID) -> TokensPage:
                current, _ = await guards.mutation(request, Empty, kind="ADMIN")

                def run() -> TokensPage:
                    # `revoke_token`/`delete_token` accept any token of the workspace (the
                    # definer functions require only an administrator actor), so existence
                    # (and, for an own-token route, ownership) is checked here first: an id
                    # that is not found this way is `NOT_FOUND`, never confused with the
                    # store's own `CONFLICT` for a token that exists but is in the wrong
                    # state for this action (deleting a live one, for one).
                    if not token_exists(
                        runtime.db, current, token_id, everyone=everyone, clock=runtime.clock
                    ):
                        raise ApiError("NOT_FOUND")
                    function(runtime.db, current, token_id, clock=runtime.clock)
                    return page(current, everyone)

                try:
                    return await run_in_threadpool(run)
                except TokenError as error:
                    raise _code(error) from None

        register()

    @routes.get(
        "/tenant/tokens",
        response_model=TokensPage,
        operation_id="listWorkspaceTokens",
        summary="List the workspace's personal access tokens",
    )
    async def workspace(request: Request) -> TokensPage:
        current, _ = await guards.session(request, kind="ADMIN")
        try:
            return await run_in_threadpool(page, current, True)
        except TokenError as error:
            raise _code(error) from None
