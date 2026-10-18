# SPDX-License-Identifier: AGPL-3.0-only
"""Resolve authority evidence; this module never authorizes or dispatches actions."""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound.contracts import PRODUCTION_CATALOG, Catalog, SourceSetting
from execbound.db import Database, check_runtime
from execbound.identity import Identity
from execbound.requests import ActionRequest
from execbound.resolution import registry
from execbound.resolution.facts import resolve_facts
from execbound.resolution.models import (
    CanonicalIntent,
    Clock,
    ResolvedRequest,
    SystemClock,
    binding_hash,
)
from execbound.resolution.registry import ResolutionError

__all__ = ["ResolutionError", "issue_run", "resolve_request", "revalidate"]


def _now(clock: Clock) -> datetime:
    now = clock.now()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ResolutionError("INVALID_CLOCK")
    return now.astimezone(UTC)


def resolve_request(
    db: Database,
    identity: Identity,
    request: ActionRequest,
    clock: Clock | None = None,
    *,
    settings: Sequence[SourceSetting] | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> ResolvedRequest:
    clock = clock or SystemClock()
    now = _now(clock)
    try:
        with db.transaction(identity.tenant_id, snapshot=True) as conn:
            check_runtime(conn)
            registry.active_identity(conn, identity, now)
            expiry = identity.expires_at.astimezone(UTC)
            if request.run_id is not None:
                run_expiry = conn.execute(
                    text("""
                    SELECT expires_at FROM execbound.agent_runs
                    WHERE tenant_id = :tenant AND principal_id = :principal
                      AND run_id = :run AND issued_at <= :now AND expires_at > :now
                """),
                    {
                        "tenant": identity.tenant_id,
                        "principal": identity.principal_id,
                        "run": request.run_id,
                        "now": now,
                    },
                ).scalar_one_or_none()
                if run_expiry is None:
                    raise ResolutionError("INVALID_RUN")
                expiry = min(expiry, run_expiry.astimezone(UTC))
            mapping = registry.mapping(
                conn, identity.tenant_id, request.operation_ref, catalog=catalog
            )
            spec, contract = registry.mapping_context(
                mapping, catalog=catalog, arguments=request.arguments
            )
            resource, alias = registry.resource(conn, mapping, request, now)
            incident = (
                registry.incident(conn, mapping, request, resource["resource_id"])
                if contract.incident == "required"
                else None
            )
            facts = resolve_facts(
                contract,
                settings,
                resource=resource,
                fact_rows=registry.resource_facts(conn, mapping, resource["resource_id"]),
                incident=incident,
                now=now,
            )
            expiry = min(expiry, *(fact.valid_until for fact in facts))
            if alias:
                expiry = min(expiry, alias["expires_at"].astimezone(UTC))
            if _now(clock) >= expiry:
                raise ResolutionError()
            return ResolvedRequest(
                request=request,
                intent=CanonicalIntent(
                    tenant_id=identity.tenant_id,
                    principal_id=identity.principal_id,
                    account_id=mapping["account_id"],
                    provider=spec.provider,
                    provider_operation=spec.provider_operation,
                    action=spec.action,
                    resource_type=spec.resource_type,
                    target_id=resource["resource_id"],
                    arguments=request.arguments,
                ),
                resource_provider_id=resource["provider_id"],
                resource_version=resource["version"],
                mapping_version=mapping["mapping_version"],
                schema_version=spec.schema_version,
                context_contract_version=contract.version,
                facts=facts,
                resolved_at=now,
                valid_until=expiry,
                alias_id=alias["alias_id"] if alias else None,
            )
    except (SQLAlchemyError, ValidationError):
        pass
    raise ResolutionError("DEPENDENCY_UNAVAILABLE")


def issue_run(
    db: Database, identity: Identity, clock: Clock | None = None, *, lifetime_seconds: int = 300
) -> UUID:
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 300:
        raise ValueError("Run lifetime must be 1 to 300 seconds")
    now = _now(clock or SystemClock())
    with db.transaction(identity.tenant_id) as conn:
        check_runtime(conn)
        registry.active_identity(conn, identity, now)
        run_id = uuid4()
        expires = min(identity.expires_at, now + timedelta(seconds=lifetime_seconds))
        conn.execute(
            text("""
            INSERT INTO execbound.agent_runs(tenant_id, principal_id, run_id, issued_at, expires_at)
            VALUES (:tenant, :principal, :run, :now, :expires)
        """),
            {
                "tenant": identity.tenant_id,
                "principal": identity.principal_id,
                "run": run_id,
                "now": now,
                "expires": expires,
            },
        )
        return run_id


def revalidate(
    db: Database,
    identity: Identity,
    frozen: ResolvedRequest,
    clock: Clock | None = None,
    *,
    settings: Sequence[SourceSetting] | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> ResolvedRequest:
    clock = clock or SystemClock()
    try:
        ResolvedRequest.model_validate(frozen)
        if (
            frozen.intent.tenant_id != identity.tenant_id
            or frozen.intent.principal_id != identity.principal_id
            or _now(clock) >= frozen.valid_until
        ):
            raise ResolutionError()
        current = resolve_request(
            db, identity, frozen.request, clock, settings=settings, catalog=catalog
        )
        if (
            _now(clock) >= frozen.valid_until
            or current.valid_until < frozen.valid_until
            or binding_hash(current) != binding_hash(frozen)
            or any(current.fact(fact.name).observed_at < fact.observed_at for fact in frozen.facts)
        ):
            raise ResolutionError()
        return frozen
    except (ResolutionError, ValidationError):
        pass
    raise ResolutionError("STALE_AUTHORIZATION")
