# SPDX-License-Identifier: Apache-2.0
"""Separately authenticated, fixed-operation mock; no provisioning/control test routes.

A mock may also hold a sample key (#420, `EXECBOUND_MOCK_SAMPLE_KEY`). A request whose token
matches no configured account is then checked against the token the key derives for the tenant
and the account its own command names; a match is a sample account, signed for with the
derived journal key, and its target is created the first time a dispatch names it, at the
version ExecBound's sample facts record. The sample check never runs for a command naming any
tenant a configured account belongs to, whatever account id it names inside that tenant:
`resources` is keyed by `(tenant_id, canonical_target_id)` and dispatch joins any representation
in the tenant, so containment has to be per tenant, not per `(tenant, account)` pair, or a sample
token could still reach a configured tenant's own targets under a fresh account id. Configured
accounts behave exactly as before, and a token that matches neither answers 401 as it always did.
"""

import hashlib
import hmac
import json
import os
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Literal
from uuid import UUID

from execbound_protocol.catalog import PRODUCTION_ACTIONS, ProviderName
from execbound_protocol.provider import (
    MAX_PROVIDER_BYTES,
    ProviderCommand,
    ProviderError,
    parse_provider,
)
from execbound_protocol.strict import _unique_object
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from execbound_connectors.accounts import (
    ProviderAccount,
    sign_record,
)
from execbound_connectors.identity_store import IdentityStore
from execbound_connectors.mock_store import JournalStore, MockStore
from execbound_connectors.samples import (
    MAX_KEY_BYTES,
    MIN_KEY_BYTES,
    SAMPLE_PROVIDER,
    SAMPLE_RESOURCE_VERSION,
    parse_sample_key,
    sample_account,
)

_IDENTITY_HEADERS = {"x-tenant-id", "x-account-id", "x-principal-id", "x-role"}
SAMPLE_KEY_VARIABLE = "EXECBOUND_MOCK_SAMPLE_KEY"
Role = Literal["dispatch", "control", "either"]


def _accounts_from_environment() -> tuple[ProviderAccount, ...]:
    path = Path(os.environ["EXECBOUND_MOCK_ACCOUNTS_PATH"])
    raw = path.read_bytes()
    if not 0 < len(raw) <= 1024 * 1024:
        raise ValueError()
    content = json.loads(raw, object_pairs_hook=_unique_object)
    expected = {
        "tenant_id",
        "account_id",
        "dispatch_token_hash",
        "control_token_hash",
        "signing_key_hex",
        "key_id",
    }
    if not isinstance(content, list) or not content:
        raise ValueError()
    result = []
    for item in content:
        if not isinstance(item, dict) or set(item) not in (expected, expected | {"provider"}):
            raise ValueError()
        result.append(
            ProviderAccount(
                tenant_id=UUID(item["tenant_id"]),
                account_id=UUID(item["account_id"]),
                dispatch_token_hash=item["dispatch_token_hash"],
                control_token_hash=item["control_token_hash"],
                signing_key=bytes.fromhex(item["signing_key_hex"]),
                key_id=item["key_id"],
                provider=item.get("provider", "mock_crowdstrike"),
            )
        )
    return tuple(result)


def _sample_key_from_environment() -> bytes | None:
    """The mock's sample key, or None when the setting is absent or empty."""
    raw = os.environ.get(SAMPLE_KEY_VARIABLE, "")
    return parse_sample_key(raw) if raw else None


def _validate_accounts(accounts: tuple[ProviderAccount, ...]) -> None:
    hashes: set[str] = set()
    scopes: set[tuple[UUID, UUID]] = set()
    if not accounts:
        raise ValueError()
    for account in accounts:
        if not isinstance(account, ProviderAccount):
            raise ValueError()
        account.__post_init__()
        scope = (account.tenant_id, account.account_id)
        if scope in scopes:
            raise ValueError()
        scopes.add(scope)
        for token_hash in (account.dispatch_token_hash, account.control_token_hash):
            if token_hash in hashes:
                raise ValueError()
            hashes.add(token_hash)


def _presented_token_hash(request: Request) -> str | None:
    """The presented bearer token's SHA-256 hex digest, or None if it cannot be read.

    None for a missing, repeated or malformed Authorization header. Shared by the
    configured-account and the sample-account checks so both read the header one same way.
    """
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        return None
    match = re.fullmatch(r"Bearer ([!-~]{1,512})", values[0])
    if match is None:
        return None
    return hashlib.sha256(match[1].encode("ascii")).hexdigest()


def _matches_role(token_hash: str, account: ProviderAccount, role: Role) -> bool:
    """Whether the digest is this account's dispatch or control hash for the given role."""
    dispatch = hmac.compare_digest(token_hash, account.dispatch_token_hash)
    control = hmac.compare_digest(token_hash, account.control_token_hash)
    return (dispatch and role in {"dispatch", "either"}) or (
        control and role in {"control", "either"}
    )


def _account(
    token_hash: str,
    accounts: tuple[ProviderAccount, ...],
    role: Role,
) -> ProviderAccount | None:
    selected = None
    for account in accounts:
        if _matches_role(token_hash, account, role):
            selected = account
    return selected


def _sample(
    token_hash: str,
    raw: bytes,
    key: bytes,
    provider: ProviderName,
    role: Role,
    configured_tenants: frozenset[UUID],
) -> ProviderAccount | None:
    """The sample account whose derived token this request presents, or None.

    The tenant and the account are read from the command the request carries, the token they
    derive is compared with the presented one in constant time, and nothing else is trusted:
    a command naming another tenant or account derives another token and is refused. A command
    naming any tenant a configured account belongs to is refused too, whatever account id it
    names inside that tenant, and never reaches `sample_account`. Containment has to be per
    tenant: `resources` is keyed by `(tenant_id, canonical_target_id)` and dispatch joins any
    representation in the tenant, so refusing only the exact `(tenant, account)` pair of a
    configured account left a configured tenant's own targets reachable under a fresh,
    unconfigured account id in that same tenant (#420, tightened after review; a leaked sample
    key must let its holder act on a sample workspace's endpoint mock, and on nothing else).
    """
    try:
        command = parse_provider(raw, ProviderCommand)
    except ProviderError:
        return None
    if command.provider != provider:
        return None
    if command.tenant_id in configured_tenants:
        return None
    account = sample_account(key, command.tenant_id, command.account_id)
    return account if _matches_role(token_hash, account, role) else None


def create_mock_app(
    store: JournalStore | None = None,
    accounts: tuple[ProviderAccount, ...] | None = None,
    *,
    provider: ProviderName | None = None,
    sample_key: bytes | None = None,
) -> FastAPI:
    try:
        selected_provider = provider or os.environ.get(
            "EXECBOUND_MOCK_PROVIDER", "mock_crowdstrike"
        )
        if selected_provider not in {"mock_crowdstrike", "mock_entra"}:
            raise ValueError()
        configured_accounts = _accounts_from_environment() if accounts is None else accounts
        _validate_accounts(configured_accounts)
        if any(account.provider != selected_provider for account in configured_accounts):
            raise ValueError()
        # Sample accounts exist only for the endpoint mock in this unit, and a sample key is no
        # configured account's signing key.
        configured_sample = sample_key if sample_key is not None else _sample_key_from_environment()
        if configured_sample is not None and (
            selected_provider != SAMPLE_PROVIDER
            or type(configured_sample) is not bytes
            or not MIN_KEY_BYTES <= len(configured_sample) <= MAX_KEY_BYTES
            or any(account.signing_key == configured_sample for account in configured_accounts)
        ):
            raise ValueError()
        store_class = IdentityStore if selected_provider == "mock_entra" else MockStore
        configured_store = (
            store_class(Path(os.environ["EXECBOUND_MOCK_DATABASE_PATH"]))
            if store is None
            else store
        )
        if (
            not isinstance(configured_store, store_class)
            or configured_store.provider != selected_provider
        ):
            raise ValueError()
        # A catalog binding the configured store cannot execute must fail at startup
        # rather than expose a route that reaches an unreachable dispatch branch.
        if {
            binding.action for binding in PRODUCTION_ACTIONS.bindings_for(selected_provider)
        } != configured_store.dispatch_actions:
            raise ValueError()
    except Exception:
        raise ProviderError("INVALID_CONFIGURATION") from None

    # A sample token must never be checked against a tenant any configured account belongs to,
    # not only that account's own scope (#420, tightened after review).
    configured_tenants = frozenset(account.tenant_id for account in configured_accounts)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    def error(status: int) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
        return JSONResponse(
            status_code=status, content={"detail": "Provider request unavailable"}, headers=headers
        )

    @app.middleware("http")
    async def boundary(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if (
            len(request.headers.getlist("authorization")) > 1
            or request.query_params
            or any(header in request.headers for header in _IDENTITY_HEADERS)
        ):
            response: Response = error(400)
        else:
            try:
                response = await call_next(request)
            except Exception:
                response = error(503)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    async def operation(
        request: Request,
        method: Literal["dispatch", "lookup", "cancel"],
        expected_operation: str | None = None,
    ) -> Response:
        role: Role
        if method == "dispatch":
            role = "dispatch"
        elif method == "cancel":
            role = "control"
        else:
            role = "either"
        # A missing, repeated or malformed Authorization header is refused before the body is
        # ever read, for a configured account and a sample account alike.
        token_hash = _presented_token_hash(request)
        if token_hash is None:
            return error(401)
        account = _account(token_hash, configured_accounts, role)
        if account is None and configured_sample is None:
            return error(401)
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > MAX_PROVIDER_BYTES:
                return error(400)
            raw.extend(chunk)
        # A token no configured account holds may still be a sample account's, which only the
        # command can say: the key derives one token per tenant and account.
        sample = False
        if account is None and configured_sample is not None:
            account = _sample(
                token_hash,
                bytes(raw),
                configured_sample,
                selected_provider,
                role,
                configured_tenants,
            )
            sample = account is not None
        if account is None:
            return error(401)
        try:
            command = parse_provider(bytes(raw), ProviderCommand)
            if (
                command.tenant_id != account.tenant_id
                or command.account_id != account.account_id
                or command.provider != account.provider
            ):
                return error(403)
            if expected_operation is not None and command.provider_operation != expected_operation:
                return error(400)
            if sample and method == "dispatch" and isinstance(configured_store, MockStore):
                await run_in_threadpool(
                    configured_store.provision_sample, command, SAMPLE_RESOURCE_VERSION
                )
            record = await run_in_threadpool(getattr(configured_store, method), command)
            if record is None:
                return error(404)
            # Store methods return only after COMMIT has completed successfully.
            result = sign_record(record, account)
            return JSONResponse(content=result.model_dump(mode="json"))
        except ProviderError as exc:
            if exc.code == "INVALID_MESSAGE":
                return error(400)
            return error(409 if exc.code == "OPERATION_CONFLICT" else 503)

    def dispatch_route(expected_operation: str) -> Callable[[Request], Awaitable[Response]]:
        async def route(request: Request) -> Response:
            return await operation(request, "dispatch", expected_operation)

        return route

    for binding in PRODUCTION_ACTIONS.bindings_for(selected_provider):
        app.add_api_route(
            "/v1/" + binding.provider_operation,
            dispatch_route(binding.provider_operation),
            methods=["POST"],
        )

    @app.post("/v1/journal")
    async def journal(request: Request) -> Response:
        return await operation(request, "lookup")

    @app.post("/v1/cancel")
    async def cancel(request: Request) -> Response:
        return await operation(request, "cancel")

    return app
