# SPDX-License-Identifier: AGPL-3.0-only
"""`POST /api/console/v1/session/verify`: the step-up asked in place (28 September 2026).

A console change behind the step-up (`guards.mutation`'s prefixes) answers `MFA_REQUIRED` once
the session's factor was verified more than `mfa.STEP_UP_WINDOW` ago. The console used to send
the person to Account security for a code, losing whatever they had open; now it asks for the
code in a dialog over the page, sends it here, and sends the refused change again once.

Nothing here verifies a factor a new way. The code goes to `mfa.verify_factor`, the call the
account security page's own verify form makes, so an authenticator code, an unused recovery
code, the replay check, the attempt count and its fifteen-minute lock and the audit events
(`account_security.verified`, `recovery_used`, `verification_failed`) are that function's. An
accepted code is followed by `mfa.rotate_verified_session`, as the page follows it, which
replaces the session token and the CSRF token; the answer sets both cookies and carries the new
CSRF token, which the console holds in memory as it holds the one `GET /session` hands over.
The change it resends must carry that new token: the old one is refused `INVALID_CSRF`.

The route is an ordinary mutation: the session cookie, the exact Origin, the CSRF header, JSON,
the workspace generation, and a personal access token refused (`token_rules.py`). A session
still at the second step of signing in has no verified factor and is refused `MFA_REQUIRED` by
the session guard before this runs, so signing in keeps its own page at `/mfa`.

A passkey satisfies it too, through two more session mutations beside this one (#678):
`/session/verify/passkey/options` calls `passkeys.begin(..., "authenticate")`, the account
security page's own, which stores a 32-byte challenge for this session for five minutes and
answers the WebAuthn request options; `/session/verify/passkey` hands the assertion to
`passkeys.complete(..., "authenticate")`. That function spends the session's challenge on every
attempt that finds one, before the factor or its lock is read, so each finish attempt, failed or
not, needs fresh options; an assertion that fails verification counts toward the five-attempt
lock and is audited, while a missing, spent or expired challenge and a locked factor are refused
without either. Success is followed by the same `mfa.rotate_verified_session` and answer as a
code. The RP ID and origin are the deployment's, user verification is required, and the
credential must be one saved to this account.
"""

from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response

from execbound import mfa, passkeys
from execbound.envelope import EnvelopeError
from execbound.runtime import Runtime
from execbound.surfaces.console_api.directory import Empty, body_of
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig, _session_cookies
from execbound.surfaces.sessions import Session


class StepUpBody(BaseModel):
    """A six-digit authenticator code or a recovery code, as the person typed it."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=64)


class StepUpResult(BaseModel):
    """The session's new CSRF token; the session cookie itself changed in the same answer."""

    csrf_token: str


class PasskeyOptions(BaseModel):
    """The WebAuthn request options, as `py_webauthn` serialises them, for this session's
    single-use challenge."""

    options: dict[str, Any]


class PasskeyResponse(BaseModel):
    """An authenticator's answer, base64url-encoded as `navigator.credentials.get` gives it."""

    model_config = ConfigDict(extra="forbid")

    clientDataJSON: str = Field(min_length=1, max_length=4096)  # noqa: N815 - WebAuthn's name
    authenticatorData: str = Field(min_length=1, max_length=4096)  # noqa: N815 - WebAuthn's name
    signature: str = Field(min_length=1, max_length=1024)
    userHandle: str | None = Field(default=None, max_length=512)  # noqa: N815 - WebAuthn's name


class PasskeyAssertion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=1024)
    rawId: str = Field(min_length=1, max_length=1024)  # noqa: N815 - WebAuthn's name
    type: Literal["public-key"]
    response: PasskeyResponse


class PasskeyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential: PasskeyAssertion


def step_up_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    async def rotated(request: Request, current: Session) -> Response:
        """The verified session rotated as the security page rotates it, answered with its new
        CSRF token and both cookies."""
        try:
            grant = await run_in_threadpool(
                mfa.rotate_verified_session, runtime.db, current, clock=runtime.clock
            )
        except mfa.MfaError as exc:
            # A factor removed since the change was refused is something that changed first.
            raise ApiError("CONFLICT" if exc.code == "NOT_ENROLLED" else "UNAVAILABLE") from None
        # The request's own cookies were just replaced: a renewal of the old session must not
        # write them back over the new ones on the way out.
        request.state.session_renewal = None
        return _session_cookies(
            JSONResponse(StepUpResult(csrf_token=grant.csrf_token).model_dump()),
            config,
            runtime,
            grant,
        )

    @routes.post(
        "/session/verify",
        response_model=StepUpResult,
        operation_id="verifyIdentity",
        openapi_extra=body_of(StepUpBody),
    )
    async def verify_identity(request: Request) -> Response:
        current, body = await guards.mutation(request, StepUpBody)
        ring = config.mfa
        if ring is None:
            raise ApiError("UNAVAILABLE")
        try:
            accepted = await run_in_threadpool(
                mfa.verify_factor, runtime.db, current, ring, body.code, clock=runtime.clock
            )
        except mfa.MfaError as exc:
            # A factor removed since the change was refused is something that changed first.
            raise ApiError("CONFLICT" if exc.code == "NOT_ENROLLED" else "UNAVAILABLE") from None
        except EnvelopeError:
            raise ApiError("UNAVAILABLE") from None
        if not accepted:
            raise ApiError("INVALID_FACTOR")
        return await rotated(request, current)

    @routes.post(
        "/session/verify/passkey/options",
        response_model=PasskeyOptions,
        operation_id="beginPasskeyStepUp",
        openapi_extra=body_of(Empty),
    )
    async def passkey_options(request: Request) -> PasskeyOptions:
        current, _ = await guards.mutation(request, Empty)
        if config.mfa is None:
            raise ApiError("UNAVAILABLE")
        try:
            options = await run_in_threadpool(
                passkeys.begin,
                runtime.db,
                current,
                config.origin,
                "authenticate",
                clock=runtime.clock,
            )
        except mfa.MfaError as exc:
            # No factor, or no passkey saved to this account.
            raise ApiError(
                "CONFLICT" if exc.code in {"NOT_ENROLLED", "FACTOR_LIMIT"} else "UNAVAILABLE"
            ) from None
        return PasskeyOptions(options=options)

    @routes.post(
        "/session/verify/passkey",
        response_model=StepUpResult,
        operation_id="verifyIdentityWithPasskey",
        openapi_extra=body_of(PasskeyBody),
    )
    async def verify_with_passkey(request: Request) -> Response:
        current, body = await guards.mutation(request, PasskeyBody)
        if config.mfa is None:
            raise ApiError("UNAVAILABLE")
        try:
            accepted = await run_in_threadpool(
                passkeys.complete,
                runtime.db,
                current,
                config.origin,
                "authenticate",
                body.credential.model_dump(exclude_none=True),
                clock=runtime.clock,
            )
        except mfa.MfaError:
            raise ApiError("UNAVAILABLE") from None
        if not accepted:
            raise ApiError("INVALID_FACTOR")
        return await rotated(request, current)
