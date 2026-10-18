# SPDX-License-Identifier: AGPL-3.0-only
"""A synthetic tenant for the live Tines Gate trial: one Execute path and one Gate path.

Both paths isolate endpoints under the same bundle, so the tenant-wide isolation limit is
shared between them. The Gate path has its own account (no connector), its own operation
ref, its own agent principal, a registered ES256 executor key and a journal key in the
gateway's `checkpoint_providers` block. The bundle also carries two Cedar forbids that keep
the Gate and Execute agent principals apart (see `CHECKPOINT.md` limitation 9): a Gate
credential cannot reach an Execute mapping and an Execute credential cannot reach the Gate
account. The reviewer is a signed-in HUMAN_APPROVER person, never a bearer credential,
seeded through `invite_person`/`assign_approver` with its one-time set-password code written
to `reviewer-code.txt`, holding approver scopes for exactly the two production targets.
The reviewer is seeded in its own transactions after the main seed transaction commits, so
a failure part-way through leaves a partly seeded tenant behind; `seed_gate` never reuses a
namespace, so retrying after such a failure needs a new `--seed` name.
Everything is synthetic, reproducible from a public seed, and written to one new private
directory; nothing here depends on a hosted sandbox.
"""

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import create_engine, text

from execbound.administration import assign_approver, invite_person
from execbound.connection import connect_args, local_database_url, local_databases
from execbound.identity import new_token
from execbound.policy.models import BundleContent, MappingRef
from execbound.provider.mock_store import MockStore
from execbound_harness.demo import endpoint_bundle
from execbound_harness.fixtures import (
    ENDPOINT_PROVIDER,
    _with_max_age,
    fixture_id,
    insert_account,
    insert_mappings,
    insert_target,
    install_bundle,
    provider_material,
    write_private,
)

GATE_REF = "gate.endpoint.isolate"
KEY_ID = "tines-gate-v1"
REVIEWER_LABEL = "Gate trial reviewer"
REVIEWER_ACTION = "endpoint.isolate"
ACTORS = (
    ("execute-agent", "AGENT"),
    ("gate-agent", "AGENT"),
    ("admin", "ADMIN"),
)
# Twelve development workstations per path fill the shared twenty-target tenant limit
# with room to show the overflow; one production workstation per path needs approval, and
# one domain controller per path is denied outright.
SHAPES = [(f"workstation-{i:02}", "workstation", "development") for i in range(1, 13)]
SHAPES += [
    ("production", "workstation", "production"),
    ("domain-controller", "domain_controller", "production"),
]


def _gate_account(conn: Any, seed: str, tenant: UUID) -> str:
    """A second endpoint account, for the Gate path, with its own context sources."""
    account = str(fixture_id(seed, f"{tenant}/gate/account"))
    conn.execute(
        text(
            "INSERT INTO execbound.connector_accounts (tenant_id,account_id,provider,space_id) "
            "VALUES (:t,:a,:p,(SELECT space_id FROM execbound.spaces WHERE tenant_id=:t))"
        ),
        {"t": tenant, "a": account, "p": ENDPOINT_PROVIDER},
    )
    for label, kind, writer in (
        ("inventory", "inventory", "inventory_sync"),
        ("incident-source", "incident", "soc_analyst"),
    ):
        conn.execute(
            text(
                "INSERT INTO execbound.context_sources "
                "(tenant_id,account_id,source_id,kind,allowed_writers) "
                "VALUES (:t,:a,:s,:k,ARRAY[:w])"
            ),
            {
                "t": tenant,
                "a": account,
                "s": fixture_id(seed, f"{account}/{label}"),
                "k": kind,
                "w": writer,
            },
        )
    conn.execute(
        text(
            "INSERT INTO execbound.operation_mappings "
            "(tenant_id,operation_ref,account_id,provider,"
            "resource_type,action,provider_operation,mapping_version,"
            "schema_version,context_contract_version) "
            "VALUES (:t,:ref,:a,:p,'endpoint','endpoint.isolate','contain',"
            "'map-v1','action.v1','endpoint-isolation.v1')"
        ),
        {"t": tenant, "ref": GATE_REF, "a": account, "p": ENDPOINT_PROVIDER},
    )
    return account


def reviewer_email(seed: str) -> str:
    """The reviewer's address, distinct per seed so that re-seeding a fresh trial run never
    collides with an earlier one's reviewer: the principal email index is global across
    tenants (``execbound.administration._person_for``), unlike every other fixture identifier
    here, which is a per-tenant UUID derived from ``fixture_id``."""
    return f"reviewer+{seed}@gate-trial.invalid"


def _targets(seed: str, tenant: UUID, path: str, account: str) -> list[dict[str, Any]]:
    return [
        {
            "label": f"{path}-{label}",
            "canonical_target_id": str(fixture_id(seed, f"{tenant}/{path}/{label}/canonical")),
            "resource_id": str(fixture_id(seed, f"{tenant}/{path}/{label}/resource")),
            "provider_id": f"{path}-{label}",
            "resource_type": "endpoint",
            "provider": ENDPOINT_PROVIDER,
            "account_id": account,
            "incident_id": str(fixture_id(seed, f"{tenant}/{path}/{label}/incident")),
            "role": role,
            "privilege_class": None,
            "environment": environment,
        }
        for label, role, environment in SHAPES
    ]


def seed_gate(
    owner_url: str, output: Path, *, seed: str, gateway_port: int = 8100, endpoint_port: int = 8101
) -> None:
    """Create a fresh private Gate fixture or fail; never reuse a namespace."""
    parsed = local_database_url(owner_url, databases=local_databases(), username="execbound_owner")
    output = output.absolute()
    if output.exists():
        raise ValueError("Gate fixture already exists")
    output.mkdir(mode=0o700, parents=True)
    now = datetime.now(UTC)
    tenant = fixture_id(seed, "gate/tenant")
    engine = create_engine(parsed, hide_parameters=True, connect_args=connect_args(parsed))
    try:
        with engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)}
            )
            conn.execute(
                text("INSERT INTO execbound.tenants(tenant_id,name) VALUES (:t,:n)"),
                {"t": tenant, "n": f"Synthetic Gate trial {seed}"},
            )
            space = fixture_id(seed, f"{tenant}/space")
            conn.execute(
                text(
                    "INSERT INTO execbound.spaces (tenant_id,space_id,name,created_at,created_by) "
                    "VALUES (:t,:s,'Default',now(),:t)"
                ),
                {"t": tenant, "s": space},
            )
            actors: dict[str, UUID] = {}
            tokens: dict[str, str] = {}
            for label, kind in ACTORS:
                principal = fixture_id(seed, f"{tenant}/{label}/principal")
                credential = fixture_id(seed, f"{tenant}/{label}/credential")
                actors[label] = principal
                token, digest = new_token(tenant, credential)
                tokens[label] = token
                conn.execute(
                    text(
                        "INSERT INTO execbound.principals (tenant_id,principal_id,kind,space_id) "
                        "VALUES (:t,:p,:k,:s)"
                    ),
                    {
                        "t": tenant,
                        "p": principal,
                        "k": kind,
                        "s": space if kind == "AGENT" else None,
                    },
                )
                # The Gate agent outlives its grants' report window; the rest last a trial day.
                lifetime = timedelta(hours=48) if label == "gate-agent" else timedelta(hours=12)
                conn.execute(
                    text(
                        "INSERT INTO execbound.credentials "
                        "(tenant_id,credential_id,principal_id,token_hash,issued_at,expires_at) "
                        "VALUES (:t,:c,:p,:h,:n,:e)"
                    ),
                    {
                        "t": tenant,
                        "c": credential,
                        "p": principal,
                        "h": digest,
                        "n": now,
                        "e": now + lifetime,
                    },
                )
            execute_account = insert_account(conn, seed, tenant, ENDPOINT_PROVIDER)
            insert_mappings(conn, tenant, {ENDPOINT_PROVIDER: execute_account})
            gate_account = _gate_account(conn, seed, tenant)
            store = MockStore(output / "endpoint.sqlite3")
            targets = _targets(seed, tenant, "execute", execute_account) + _targets(
                seed, tenant, "gate", gate_account
            )
            for target in targets:
                insert_target(
                    conn,
                    seed,
                    tenant,
                    target,
                    actors,
                    now,
                    aliases=True,
                    hostname=target["provider_id"],
                    approval_scope=False,
                )
                canonical = UUID(target["canonical_target_id"])
                store.provision_resource(tenant, canonical, "resource-v1")
                store.provision_representation(
                    tenant, UUID(target["account_id"]), target["provider_id"], canonical
                )
            base = endpoint_bundle(
                tenant,
                UUID(execute_account),
                mapping_version="map-v1",
                bundle_id=fixture_id(seed, f"{tenant}/bundle"),
            )
            gate_ref = MappingRef(
                operation_ref=GATE_REF,
                account_id=UUID(gate_account),
                mapping_version="map-v1",
                schema_version="action.v1",
                context_contract_version="endpoint-isolation.v1",
                external_executor=True,
            )
            bundle = BundleContent.model_validate_json(
                base.model_copy(update={"mappings": (*base.mappings, gate_ref)}).model_dump_json()
            )
            # A Gate principal serves Gate mappings only, and an Execute principal never
            # reaches a Gate account; nothing else in the kernel keeps the two apart
            # (checkpoint guide, limitation 9), so the seed provisions the separation as
            # bundle content. Cedar entities carry the reserved `account` attribute and
            # principals are `ExecBound::Agent::"<tenant>/<principal>"` (policy/evaluate.py).
            separation = (
                f'forbid(principal == ExecBound::Agent::"{tenant}/{actors["gate-agent"]}", '
                "action, resource)\n"
                f'unless {{ resource.account == "{gate_account}" }};\n'
                f'forbid(principal == ExecBound::Agent::"{tenant}/{actors["execute-agent"]}", '
                "action, resource)\n"
                f'when {{ resource.account == "{gate_account}" }};\n'
            )
            bundle = BundleContent.model_validate_json(
                bundle.model_copy(
                    update={
                        "authorization_policies": bundle.authorization_policies + "\n" + separation
                    }
                ).model_dump_json()
            )
            bundle = _with_max_age(bundle, 3600)
            # `_with_max_age` writes a setting for every catalog contract; this bundle maps
            # only the endpoint contract, and a setting naming an unused contract fails the
            # policy store's own validation (`validate_bundle_contracts`), which
            # `install_bundle` below never runs. Keep only the settings for contracts this
            # bundle's own mappings actually use.
            mapped_contracts = {ref.context_contract_version for ref in bundle.mappings}
            bundle = BundleContent.model_validate_json(
                bundle.model_copy(
                    update={
                        "context_settings": tuple(
                            setting
                            for setting in bundle.context_settings or ()
                            if setting.context_contract_version in mapped_contracts
                        )
                    }
                ).model_dump_json()
            )
            signing = ec.generate_private_key(ec.SECP256R1())
            conn.execute(
                text(
                    "INSERT INTO execbound.executor_keys "
                    "(tenant_id,key_id,algorithm,public_key,created_at) "
                    "VALUES (:t,:k,'ES256',:pk,:n)"
                ),
                {
                    "t": tenant,
                    "k": KEY_ID,
                    "pk": signing.public_key()
                    .public_bytes(
                        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
                    )
                    .hex(),
                    "n": now,
                },
            )
            install_bundle(conn, bundle, actors["admin"], now)
            origin = f"http://127.0.0.1:{endpoint_port}"
            execute_connector, execute_record = provider_material(
                ENDPOINT_PROVIDER, tenant, execute_account, origin, key_id="execute-journal-v1"
            )
            gate_connector, gate_record = provider_material(
                ENDPOINT_PROVIDER, tenant, gate_account, origin, key_id="gate-journal-v1"
            )
        # The reviewer is a signed-in person, never a bearer credential: reviewer tokens
        # went after the live trial. Seeded through the same library functions
        # `person-invite` and `approver-assign` call, in their own transactions against the
        # tenant the block above just committed, exactly as the live trial's operator
        # commands ran them.
        reviewer = invite_person(
            engine,
            tenant,
            reviewer_email(seed),
            "HUMAN_APPROVER",
            label=REVIEWER_LABEL,
            actor=actors["admin"],
            origin=f"http://127.0.0.1:{gateway_port}",
            output=output / "reviewer-code.txt",
            now=now,
        )
        production = {target["label"]: UUID(target["canonical_target_id"]) for target in targets}
        for path_label in ("execute-production", "gate-production"):
            assign_approver(
                engine,
                tenant,
                reviewer.principal_id,
                production[path_label],
                REVIEWER_ACTION,
                actors["admin"],
            )
        config = {
            "origin": f"http://127.0.0.1:{gateway_port}",
            "active_key_id": "continuation-v1",
            "continuation_keys": {"continuation-v1": secrets.token_hex(32)},
            "connectors": [execute_connector],
            "checkpoint_providers": [
                {
                    "tenant_id": str(tenant),
                    "account_id": gate_account,
                    "provider": ENDPOINT_PROVIDER,
                    "evidence_keys": gate_connector["evidence_keys"],
                }
            ],
            "preconditions": [
                {
                    "provider": ENDPOINT_PROVIDER,
                    "provider_operation": op,
                    "precondition_class": "ENFORCED_BY_PROVIDER",
                }
                for op in ("contain", "lift_containment")
            ],
        }
        write_private(output / "gateway.json", config)
        write_private(output / "endpoint-accounts.json", [execute_record, gate_record])
        write_private(output / "credentials.json", {label: tokens[label] for label, _ in ACTORS})
        write_private(
            output / "tines-gate-signing.pem",
            signing.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
            plain=True,
        )
        write_private(
            output / "tines.json",
            {
                "execbound_gate": tokens["gate-agent"],
                "execbound_execute": tokens["execute-agent"],
                "execbound_gate_vendor": gate_connector["dispatch_token"],
                "execbound_gate_key_id": KEY_ID,
                "gate_operation_ref": GATE_REF,
                "targets": [t["provider_id"] for t in targets],
            },
        )
        write_private(
            output / "fixture.json",
            {
                "version": 1,
                "seed": seed,
                "tenant_id": str(tenant),
                "ports": {"gateway": gateway_port, "endpoint": endpoint_port},
                "accounts": {"execute": execute_account, "gate": gate_account},
                "incidents": {t["provider_id"]: t["incident_id"] for t in targets},
                "reviewer": {
                    "principal_id": str(reviewer.principal_id),
                    "email": reviewer.email,
                },
            },
        )
    finally:
        engine.dispose()


def refresh_context(owner_url: str, tenant: UUID) -> int:
    """Re-stamp the synthetic tenant's observations as fresh; the rows touched."""
    parsed = local_database_url(owner_url, databases=local_databases(), username="execbound_owner")
    engine = create_engine(parsed, hide_parameters=True, connect_args=connect_args(parsed))
    try:
        with engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)}
            )
            touched = 0
            for table in ("resources", "incidents"):
                touched += conn.execute(
                    text(
                        f"UPDATE execbound.{table} "  # nosec B608 - fixed tuple of table names
                        "SET observed_at=now() WHERE tenant_id=:t AND demo_fixture"
                    ),
                    {"t": tenant},
                ).rowcount
            return touched
    finally:
        engine.dispose()
