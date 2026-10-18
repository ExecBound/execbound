# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic fixture generators shared by the validation seeder and the sandbox seeder.

Fixture identifiers are reproducible from a public seed label; authentication and signing
material are independently random and never derived from it. Everything here writes rows
the owner tooling would write, inside a transaction the caller owns and fences.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.audit import append_event, canonical_json
from execbound.bootstrap import provider_material as provider_material
from execbound.operations import PRODUCTION_ACTIONS
from execbound.policy.cedar import validate_policy_sets
from execbound.policy.models import BundleContent, ContextSetting
from execbound.resolution.registry import mapping
from execbound.spaces import default_space
from execbound_harness.demo import endpoint_bundle
from execbound_harness.identity_demo import identity_bundle
from execbound_harness.soc_demo import SOC_ACTIONS, soc_bundle, soc_ruleset_bundle

PROVIDERS = ("mock_crowdstrike", "mock_entra")
ENDPOINT_PROVIDER, IDENTITY_PROVIDER = PROVIDERS
RESOURCE_VERSION = "resource-v1"
ALIAS_DAYS = 365


def fixture_id(seed: str, label: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"https://execbound.invalid/validation/v1/{seed}/{label}")


def write_private(path: Path, value: Any, *, plain: bool = False) -> None:
    """Create a new owner-only file; an existing path is refused."""
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        path.chmod(0o600)
        handle.write(value if plain else json.dumps(value, indent=2))
        handle.write("\n")


def combined_bundle(seed: str, tenant: UUID, accounts: dict[str, str]) -> BundleContent:
    """The endpoint and identity demo policies in one bundle, as the validation demo uses."""
    endpoint = endpoint_bundle(tenant, UUID(accounts[ENDPOINT_PROVIDER]), mapping_version="map-v1")
    identity = identity_bundle(tenant, UUID(accounts[IDENTITY_PROVIDER]), mapping_version="map-v1")
    schema = json.loads(endpoint.cedar_schema)
    other = json.loads(identity.cedar_schema)["ExecBound"]
    schema["ExecBound"]["entityTypes"].update(other["entityTypes"])
    schema["ExecBound"]["actions"].update(other["actions"])
    result = BundleContent(
        tenant_id=tenant,
        bundle_id=fixture_id(seed, f"{tenant}/bundle"),
        cedar_schema=canonical_json(schema),
        authorization_policies=endpoint.authorization_policies + identity.authorization_policies,
        approval_policies=endpoint.approval_policies + identity.approval_policies,
        mappings=endpoint.mappings + identity.mappings,
        limits=endpoint.limits + identity.limits,
    )
    validate_policy_sets(
        schema=result.cedar_schema,
        authorization=result.authorization_policies,
        approval=result.approval_policies,
    )
    return result


def _with_max_age(result: BundleContent, max_age_seconds: int | None) -> BundleContent:
    """Both sources of every contract accept observations ``max_age_seconds`` old, as the pilot
    runbook configures; context settings are not compiled from rules, so a ruleset bundle
    keeps its ruleset and still passes the store's mismatch check."""
    if max_age_seconds is None:
        return result
    sources: list[tuple[Literal["inventory", "incident"], str]] = [
        ("inventory", "inventory_sync"),
        ("incident", "soc_analyst"),
    ]
    contracts = sorted(
        {
            PRODUCTION_ACTIONS.action(name).context_contract_version
            for name in PRODUCTION_ACTIONS.names
        }
    )
    result = result.model_copy(
        update={
            "context_settings": tuple(
                ContextSetting(
                    context_contract_version=contract,
                    source_kind=kind,
                    max_age_seconds=max_age_seconds,
                    permitted_writers=(writer,),
                )
                for contract in contracts
                for kind, writer in sources
            )
        }
    )
    return BundleContent.model_validate_json(result.model_dump_json())


def soc_bundle_for(
    seed: str, tenant: UUID, accounts: dict[str, str], *, max_age_seconds: int | None = None
) -> BundleContent:
    """The six-action SOC pack; with ``max_age_seconds`` both sources of every contract accept
    observations that old, as the pilot runbook configures."""
    result = soc_bundle(
        tenant,
        UUID(accounts[ENDPOINT_PROVIDER]),
        UUID(accounts[IDENTITY_PROVIDER]),
        mapping_version="map-v1",
        bundle_id=fixture_id(seed, f"{tenant}/soc-bundle"),
    )
    result = _with_max_age(result, max_age_seconds)
    validate_policy_sets(
        schema=result.cedar_schema,
        authorization=result.authorization_policies,
        approval=result.approval_policies,
    )
    return result


def sandbox_bundle_for(
    seed: str, tenant: UUID, accounts: dict[str, str], *, max_age_seconds: int | None = None
) -> BundleContent:
    """The six-action SOC pack as rules, for a hosted sandbox.

    The same pack ``soc_bundle_for`` builds by hand and the same bundle id, carrying the
    ruleset it compiles from, so the welcome page reads the rules over the fixture hosts and
    the candidate bundle the demo downloads is a ruleset bundle too. Fixtures that edit a
    component of the pack keep deriving from ``soc_bundle_for``; a ruleset bundle edited that
    way is exactly what validation refuses.
    """
    result = soc_ruleset_bundle(
        tenant,
        UUID(accounts[ENDPOINT_PROVIDER]),
        UUID(accounts[IDENTITY_PROVIDER]),
        mapping_version="map-v1",
        bundle_id=fixture_id(seed, f"{tenant}/soc-bundle"),
    )
    result = _with_max_age(result, max_age_seconds)
    validate_policy_sets(
        schema=result.cedar_schema,
        authorization=result.authorization_policies,
        approval=result.approval_policies,
    )
    return result


def install_bundle(
    conn: Connection, bundle: BundleContent, admin: UUID, now: datetime, *, activate: bool = True
) -> None:
    """Install a bundle with the same mapping validation and lifecycle audit records the
    store writes, inside the caller's fixture transaction."""
    for ref in bundle.mappings:
        current = mapping(conn, bundle.tenant_id, ref.operation_ref)
        if any(
            current[key] != getattr(ref, key)
            for key in (
                "account_id",
                "mapping_version",
                "schema_version",
                "context_contract_version",
            )
        ):
            raise ValueError("Invalid fixture mapping")
    params = {
        "t": bundle.tenant_id,
        "b": bundle.bundle_id,
        "h": bundle.content_hash,
        "c": bundle.model_dump_json(),
        "a": admin,
        "n": now,
    }
    params["s"] = default_space(conn, bundle.tenant_id)
    conn.execute(
        text("""INSERT INTO execbound.policy_bundle_contents
        (tenant_id,bundle_id,content_hash,content,created_at,created_by,space_id)
        VALUES (:t,:b,:h,CAST(:c AS jsonb),:n,:a,:s)"""),
        params,
    )
    conn.execute(
        text("""INSERT INTO execbound.policy_bundle_lifecycle
        (tenant_id,bundle_id,content_hash,state,changed_at) VALUES (:t,:b,:h,'DRAFT',:n)"""),
        params,
    )
    transitions = [("created", "DRAFT"), ("validated", "VALIDATED")]
    if activate:
        transitions.append(("activated", "ACTIVE"))
    for transition, state in transitions:
        conn.execute(
            text("""UPDATE execbound.policy_bundle_lifecycle SET state=:s
            WHERE tenant_id=:t AND bundle_id=:b"""),
            {**params, "s": state},
        )
        append_event(
            conn,
            bundle.tenant_id,
            admin,
            f"policy.bundle_{transition}",
            {"bundle_id": str(bundle.bundle_id), "content_hash": bundle.content_hash},
        )
    if activate:
        conn.execute(
            text("""INSERT INTO execbound.tenant_policy_control
            (tenant_id,changed_at) VALUES (:t,:n)
            ON CONFLICT (tenant_id) DO UPDATE SET changed_at=:n"""),
            params,
        )
        # The selection is per space since migration 0041; every space of the tenant
        # selects the fixture's bundle, so a fixture with two spaces admits under it in
        # both until a test changes one.
        conn.execute(
            text("""INSERT INTO execbound.space_policy_selection
            (tenant_id,space_id,bundle_id,changed_at,changed_by)
            SELECT :t, s.space_id, :b, :n, :a FROM execbound.spaces s WHERE s.tenant_id=:t
            ON CONFLICT (tenant_id,space_id)
            DO UPDATE SET bundle_id=:b, changed_at=:n, changed_by=:a"""),
            params,
        )


def insert_account(conn: Connection, seed: str, tenant: UUID, provider: str) -> str:
    """A connector account with its inventory and incident sources; the account id."""
    account = str(fixture_id(seed, f"{tenant}/{provider}/account"))
    conn.execute(
        text("""INSERT INTO execbound.connector_accounts
        (tenant_id,account_id,provider,space_id) VALUES (:t,:a,:p,:s)"""),
        {"t": tenant, "a": account, "p": provider, "s": default_space(conn, tenant)},
    )
    for label, kind, writer in (
        ("inventory", "inventory", "inventory_sync"),
        ("incident-source", "incident", "soc_analyst"),
    ):
        conn.execute(
            text("""INSERT INTO execbound.context_sources
            (tenant_id,account_id,source_id,kind,allowed_writers)
            VALUES (:t,:a,:s,:k,ARRAY[:w])"""),
            {
                "t": tenant,
                "a": account,
                "s": fixture_id(seed, f"{account}/{label}"),
                "k": kind,
                "w": writer,
            },
        )
    return account


def insert_mappings(conn: Connection, tenant: UUID, accounts: dict[str, str]) -> int:
    """One mapping per catalog binding this fixture has an account for; the number written.

    Not one per binding. Two things make that wrong now that a real provider is bound:

    A mapping names the account that serves an operation, so a binding whose provider this
    fixture does not configure has no account to name. The demo runs two mock providers and
    no Graph connector, and inventing an account for one it does not run would put a
    mapping in front of a provider nothing can dispatch to.

    And a mapping is keyed by ``operation_ref`` per tenant, so a tenant maps one action to
    one provider. ``identity.disable`` is bound by both ``mock_entra`` and ``graph``, and a
    tenant chooses between them by which account it holds — which is exactly how the
    account decides who serves a request. Writing both would collide on the key, and the
    collision is the schema saying the same thing.
    """
    count = 0
    for binding in PRODUCTION_ACTIONS.bindings:
        if binding.provider not in accounts:
            continue
        spec = PRODUCTION_ACTIONS.bound(binding.provider, binding.action)
        conn.execute(
            text("""INSERT INTO execbound.operation_mappings
            (tenant_id,operation_ref,account_id,provider,resource_type,action,provider_operation,
             mapping_version,schema_version,context_contract_version)
            VALUES (:t,:action,:account,:provider,:resource_type,:action,
                    :operation,'map-v1',:schema,:context)"""),
            {
                "t": tenant,
                "action": spec.action,
                "account": accounts[spec.provider],
                "provider": spec.provider,
                "resource_type": spec.resource_type,
                "operation": spec.provider_operation,
                "schema": spec.schema_version,
                "context": spec.context_contract_version,
            },
        )
        count += 1
    return count


def targets(seed: str, tenant: UUID, accounts: dict[str, str]) -> list[dict[str, Any]]:
    """Twenty-four development workstations, one production workstation, one domain
    controller and six identities, with reproducible identifiers."""
    specs: list[tuple[str, str, str | None, str | None, str]] = [
        (
            f"workstation-{index:02}",
            "endpoint",
            "workstation",
            None,
            "production" if index == 25 else "development",
        )
        for index in range(1, 26)
    ]
    specs += [("domain-controller", "endpoint", "domain_controller", None, "production")]
    specs += [
        (label, "identity", None, privilege, environment)
        for label, privilege, environment in (
            ("identity-disable", "standard", "development"),
            ("identity-enable", "standard", "development"),
            ("identity-revoke-sessions", "standard", "development"),
            ("identity-production", "standard", "production"),
            ("identity-privileged", "privileged", "production"),
            ("identity-tier0", "tier0", "production"),
        )
    ]
    return [
        {
            "label": label,
            "canonical_target_id": str(fixture_id(seed, f"{tenant}/{label}/canonical")),
            "resource_id": str(fixture_id(seed, f"{tenant}/{label}/resource")),
            "provider_id": label,
            "resource_type": resource_type,
            "provider": provider,
            "account_id": accounts[provider],
            "incident_id": str(fixture_id(seed, f"{tenant}/{label}/incident")),
            "role": role,
            "privilege_class": privilege,
            "environment": environment,
        }
        for label, resource_type, role, privilege, environment in specs
        for provider in [ENDPOINT_PROVIDER if resource_type == "endpoint" else IDENTITY_PROVIDER]
    ]


def insert_target(
    conn: Connection,
    seed: str,
    tenant: UUID,
    target: dict[str, Any],
    actors: dict[str, UUID],
    now: datetime,
    *,
    aliases: bool = False,
    hostname: str | None = None,
    approval_scope: bool = True,
) -> None:
    """The canonical target, resource, identity binding, open critical incident and, with
    ``approval_scope`` (the default), the fixture's generic human approver's scope for one
    fixture target; with ``aliases`` also the provider-id alias an operator-created resource
    gets, plus the hostname alias for an endpoint, so provider-id and hostname selectors
    resolve.

    ``approval_scope=False`` skips the generic grant below: a caller that assigns its own
    named reviewer through ``execbound.administration.assign_approver`` wants exactly the
    scopes it asks for, not this loop's blanket one over every action of the target's
    resource type.
    """
    account = target["account_id"]
    p = {
        **target,
        "t": tenant,
        "n": now,
        "inventory": fixture_id(seed, f"{account}/inventory"),
        "incident_source": fixture_id(seed, f"{account}/incident-source"),
        "version": RESOURCE_VERSION,
    }
    conn.execute(
        text("""INSERT INTO execbound.canonical_targets
        (tenant_id,canonical_target_id,created_at) VALUES (:t,:canonical_target_id,:n)"""),
        p,
    )
    conn.execute(
        text("""INSERT INTO execbound.resources
        (tenant_id,account_id,provider,resource_type,resource_id,provider_id,version,source_id,
         role,privilege_class,environment,criticality,observed_at,demo_fixture)
        VALUES (:t,:account_id,:provider,:resource_type,:resource_id,:provider_id,:version,
                :inventory,:role,:privilege_class,:environment,1,:n,true)"""),
        p,
    )
    conn.execute(
        text("""INSERT INTO execbound.resource_identities
        (tenant_id,account_id,provider,resource_type,resource_id,canonical_target_id)
        VALUES (:t,:account_id,:provider,:resource_type,:resource_id,:canonical_target_id)"""),
        p,
    )
    conn.execute(
        text("""INSERT INTO execbound.incidents
        (tenant_id,account_id,provider,resource_type,incident_id,resource_id,source_id,
         version,status,severity,observed_at,demo_fixture)
        VALUES (:t,:account_id,:provider,:resource_type,:incident_id,:resource_id,
                :incident_source,'incident-v1','OPEN','CRITICAL',:n,true)"""),
        p,
    )
    if aliases:
        names = {"provider_id": target["provider_id"]}
        if hostname is not None and target["resource_type"] == "endpoint":
            names["hostname"] = hostname.lower().removesuffix(".")
        for kind, value in names.items():
            conn.execute(
                text("""INSERT INTO execbound.resource_aliases
                (tenant_id,alias_id,account_id,provider,resource_type,kind,normalized_value,
                 resource_id,valid_from,expires_at)
                VALUES (:t,:alias,:account_id,:provider,:resource_type,:kind,:value,
                        :resource_id,:n,:expires)"""),
                {
                    **p,
                    "alias": uuid4(),
                    "kind": kind,
                    "value": value,
                    "expires": now.astimezone(UTC) + timedelta(days=ALIAS_DAYS),
                },
            )
    if not approval_scope:
        return
    human = "human_endpoint" if target["resource_type"] == "endpoint" else "human_identity"
    for action in SOC_ACTIONS:
        if PRODUCTION_ACTIONS.action(action).resource_type != target["resource_type"]:
            continue
        conn.execute(
            text("""INSERT INTO execbound.approval_scopes
            (tenant_id,approver_id,canonical_target_id,action,space_id)
            VALUES (:t,:human,:canonical_target_id,:action,:space)"""),
            {**p, "human": actors[human], "action": action, "space": default_space(conn, p["t"])},
        )
