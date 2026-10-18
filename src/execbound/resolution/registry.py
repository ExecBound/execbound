# SPDX-License-Identifier: AGPL-3.0-only
"""Read the tenant/account registry only inside the caller's snapshot transaction."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.contracts import PRODUCTION_CATALOG, Catalog, ContextContract, ContractError
from execbound.identity import Identity
from execbound.operations import CatalogError, OperationSpec
from execbound.requests import ActionRequest, Arguments

# Every code a resolution failure can carry: the audit records a refusal's own code only from
# this closed list (`execution.authority.resolution_reason`), so no caller string can become a
# reason, and `tests/test_denial_categories.py` fails if the kernel raises a code outside it.
# The agent is told none of them: every one is answered 503 `EXECUTION_UNAVAILABLE`, bad
# arguments aside.
RESOLUTION_CODES: frozenset[str] = frozenset(
    {
        "INVALID_OPERATION",
        "INVALID_ARGUMENTS",
        "INVALID_TARGET",
        "INVALID_CONTEXT",
        "INVALID_IDENTITY",
        "INVALID_CLOCK",
        "INVALID_RUN",
        "STALE_AUTHORIZATION",
        "DEPENDENCY_UNAVAILABLE",
        # An operation the space's bundle names through another space's account (#545).
        "INVALID_CONFIGURATION",
        # An operation the space's bundle names at a reference the tenant's mapping no longer
        # matches: the active bundle cannot authorize it (#545).
        "INVALID_BUNDLE",
    }
)


class ResolutionError(ValueError):
    def __init__(self, code: str = "INVALID_CONTEXT") -> None:
        self.code = code
        super().__init__("Resolution unavailable")


def mapping_contract(
    row: dict[str, Any], *, catalog: Catalog = PRODUCTION_CATALOG
) -> OperationSpec:
    try:
        return catalog.actions.validate_operation(
            **{
                field: row[field]
                for field in (
                    "provider",
                    "resource_type",
                    "action",
                    "provider_operation",
                    "schema_version",
                )
            }
        )
    except (KeyError, TypeError, CatalogError):
        pass
    raise ResolutionError("INVALID_OPERATION")


def mapping_context(
    row: dict[str, Any], *, catalog: Catalog, arguments: Arguments
) -> tuple[OperationSpec, ContextContract]:
    spec = mapping_contract(row, catalog=catalog)
    try:
        catalog.actions.normalize_arguments(spec.action, arguments.root)
    except CatalogError:
        raise ResolutionError("INVALID_ARGUMENTS") from None
    try:
        contract = catalog.for_operation(
            row["context_contract_version"], spec.action, spec.resource_type
        )
    except (KeyError, TypeError, ContractError):
        raise ResolutionError("INVALID_OPERATION") from None
    return spec, contract


def active_identity(conn: Connection, identity: Identity, now: datetime) -> None:
    if identity.kind != "AGENT" or identity.expires_at <= now:
        raise ResolutionError("INVALID_IDENTITY")
    row = conn.execute(
        text("""
        SELECT c.expires_at FROM execbound.credentials c
        JOIN execbound.principals p USING (tenant_id, principal_id)
        JOIN execbound.tenants t USING (tenant_id)
        WHERE c.tenant_id = :tenant AND c.principal_id = :principal
          AND c.credential_id = :credential AND c.revoked_at IS NULL
          AND c.expires_at > :now AND p.active AND t.active AND p.kind = 'AGENT'
    """),
        {
            "tenant": identity.tenant_id,
            "principal": identity.principal_id,
            "credential": identity.credential_id,
            "now": now,
        },
    ).scalar_one_or_none()
    if row is None or row != identity.expires_at:
        raise ResolutionError("INVALID_IDENTITY")


def mapping(
    conn: Connection, tenant: UUID, operation_ref: str, *, catalog: Catalog = PRODUCTION_CATALOG
) -> dict[str, Any]:
    row = (
        conn.execute(
            text("""
        SELECT m.* FROM execbound.operation_mappings m
        JOIN execbound.connector_accounts a USING (tenant_id, account_id, provider)
        WHERE m.tenant_id = :tenant AND m.operation_ref = :operation
          AND m.active AND a.active
    """),
            {"tenant": tenant, "operation": operation_ref},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ResolutionError("INVALID_OPERATION")
    mapping_contract(dict(row), catalog=catalog)
    return dict(row)


def scope(mapping: dict[str, Any]) -> dict[str, Any]:
    return {key: mapping[key] for key in ("tenant_id", "account_id", "provider", "resource_type")}


def resource(
    conn: Connection, mapping: dict[str, Any], request: ActionRequest, now: datetime
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    params = scope(mapping)
    selector = request.target
    # The row was validated against the caller's catalog when mapping() loaded it.
    if mapping["resource_type"] == "identity" and selector.kind == "hostname":
        raise ResolutionError("INVALID_TARGET")
    alias = None
    if selector.kind == "canonical":
        params["resource_id"] = UUID(selector.value)
        predicate = "r.resource_id = :resource_id"
    else:
        aliases = (
            conn.execute(
                text("""
            SELECT * FROM execbound.resource_aliases
            WHERE tenant_id = :tenant_id AND account_id = :account_id AND provider = :provider
              AND resource_type = :resource_type AND kind = :kind AND normalized_value = :value
              AND valid_from <= :now AND expires_at > :now
            LIMIT 2
        """),
                {**params, "kind": selector.kind, "value": selector.value, "now": now},
            )
            .mappings()
            .all()
        )
        if len(aliases) != 1:
            raise ResolutionError("INVALID_TARGET")
        alias = dict(aliases[0])
        params["resource_id"] = alias["resource_id"]
        predicate = "r.resource_id = :resource_id"
    # predicate is one of the literals above; values are bound parameters.
    row = (
        conn.execute(
            text(f"""
        SELECT r.*, s.kind AS source_kind, s.allowed_writers, s.active AS source_active
        FROM execbound.resources r JOIN execbound.context_sources s
          USING (tenant_id, account_id, source_id)
        WHERE r.tenant_id = :tenant_id AND r.account_id = :account_id AND r.provider = :provider
          AND r.resource_type = :resource_type AND {predicate} AND r.active
    """),  # nosec B608 - predicate is one of the literals above; values are bound
            params,
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ResolutionError("INVALID_TARGET")
    return dict(row), alias


def incident(
    conn: Connection, mapping: dict[str, Any], request: ActionRequest, target: UUID
) -> dict[str, Any]:
    incident_id = request.claimed_context.incident_id
    if incident_id is None:
        raise ResolutionError()
    row = (
        conn.execute(
            text("""
        SELECT i.*, s.kind AS source_kind, s.allowed_writers, s.active AS source_active
        FROM execbound.incidents i JOIN execbound.context_sources s
          USING (tenant_id, account_id, source_id)
        WHERE i.tenant_id = :tenant_id AND i.account_id = :account_id AND i.provider = :provider
          AND i.resource_type = :resource_type AND i.incident_id = :incident
          AND i.resource_id = :target
    """),
            {**scope(mapping), "incident": incident_id, "target": target},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ResolutionError()
    return dict(row)


def resource_facts(
    conn: Connection, mapping: dict[str, Any], resource_id: UUID
) -> list[dict[str, Any]]:
    rows = conn.execute(
        text("""
        SELECT f.*, s.kind AS source_kind, s.allowed_writers, s.active AS source_active
        FROM execbound.resource_facts f JOIN execbound.context_sources s
          USING (tenant_id, account_id, source_id)
        WHERE f.tenant_id = :tenant_id AND f.account_id = :account_id AND f.provider = :provider
          AND f.resource_type = :resource_type AND f.resource_id = :resource_id
        ORDER BY f.fact_name
    """),
        {**scope(mapping), "resource_id": resource_id},
    )
    return [dict(row) for row in rows.mappings().all()]
