# SPDX-License-Identifier: AGPL-3.0-only
"""Exclusive, loopback-only synthetic namespaces for the reproducible validation demo.

Fixture IDs are reproducible from a public seed. Authentication and signing material
are independently random, private, and never derived from that seed. Provisioning
uses one new directory and one database transaction; it never updates existing data.
"""

import json
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import create_engine, text

from execbound.connection import connect_args, local_database_url, local_databases
from execbound.identity import new_token
from execbound.policy.models import BundleContent
from execbound.provider.identity_store import IdentityStore
from execbound.provider.mock_store import MockStore
from execbound_harness.fixtures import (
    PROVIDERS,
    combined_bundle,
    fixture_id,
    insert_account,
    insert_mappings,
    insert_target,
    install_bundle,
    provider_material,
    soc_bundle_for,
    targets,
    write_private,
)

_PROVIDERS = PROVIDERS
_ACTORS = (
    ("agent-0", "AGENT"),
    ("agent-1", "AGENT"),
    ("human_endpoint", "HUMAN_APPROVER"),
    ("human_identity", "HUMAN_APPROVER"),
    ("admin", "ADMIN"),
)
_id = fixture_id
_write = write_private
_bundle = combined_bundle
_soc_bundle = soc_bundle_for
_install_bundle = install_bundle
_targets = targets
_insert_target = insert_target


def seed_validation(
    owner_url: str,
    output: Path,
    *,
    seed: str = "synthetic-validation-v1",
    gateway_port: int = 8100,
    endpoint_port: int = 8101,
    identity_port: int = 8102,
) -> None:
    """Create a fresh private fixture or fail safely; never truncate or reuse a namespace."""
    parsed = local_database_url(owner_url, databases=local_databases(), username="execbound_owner")
    ports = {"gateway": gateway_port, "endpoint": endpoint_port, "identity": identity_port}
    if (
        not isinstance(seed, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{1,80}", seed) is None
        or any(type(port) is not int or not 1024 <= port <= 65535 for port in ports.values())
        or len(set(ports.values())) != 3
    ):
        raise ValueError("Invalid validation fixture options")
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Validation fixture already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    output = output.parent.resolve() / output.name
    try:
        output.mkdir(mode=0o700)
    except OSError:
        raise ValueError("Validation fixture unavailable") from None
    engine = None
    try:
        now = datetime.now(UTC)
        expiry = now + timedelta(hours=8)
        fixture: dict[str, Any] = {
            "version": 1,
            "seed": seed,
            "created_at": now.isoformat(),
            "expires_at": expiry.isoformat(),
            "context_expires_at": (now + timedelta(seconds=300)).isoformat(),
            "ports": ports,
            "tenants": [],
        }
        credentials: dict[str, list[dict[str, str]]] = {}
        config: dict[str, Any] = {
            "origin": f"http://127.0.0.1:{gateway_port}",
            "active_key_id": "continuation-v1",
            "continuation_keys": {"continuation-v1": secrets.token_hex(32)},
            "connectors": [],
            # Both mocks refuse a mutation whose expected version has moved, so the honest
            # declaration for their bindings is ENFORCED_BY_PROVIDER. Without it every
            # dispatch records UNAVAILABLE, which is what an undeclared binding means and
            # which would understate on the pages exactly what these providers do.
            "preconditions": [
                {
                    "provider": provider,
                    "provider_operation": operation,
                    "precondition_class": "ENFORCED_BY_PROVIDER",
                }
                for provider, operation in (
                    ("mock_crowdstrike", "contain"),
                    ("mock_crowdstrike", "lift_containment"),
                    ("mock_entra", "disable"),
                    ("mock_entra", "enable"),
                    ("mock_entra", "revoke_sessions"),
                    ("mock_entra", "reset_password"),
                )
            ],
        }
        provider_accounts: dict[str, list[dict[str, str]]] = {
            provider: [] for provider in _PROVIDERS
        }
        endpoint_store, identity_store = (
            MockStore(output / "endpoint.sqlite3"),
            IdentityStore(output / "identity.sqlite3"),
        )
        engine = create_engine(parsed, hide_parameters=True, connect_args=connect_args(parsed))
        with engine.begin() as conn:
            for index in range(2):
                tenant = _id(seed, f"tenant/{index}")
                conn.execute(
                    text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)}
                )
                name = f"Synthetic Validation {seed} {'North' if index == 0 else 'South'}"
                conn.execute(
                    text("INSERT INTO execbound.tenants(tenant_id,name) VALUES (:t,:n)"),
                    {"t": tenant, "n": name},
                )
                space = _id(seed, f"{tenant}/space")
                conn.execute(
                    text("""INSERT INTO execbound.spaces
                    (tenant_id,space_id,name,created_at,created_by)
                    VALUES (:t,:s,'Default',now(),:t)"""),
                    {"t": tenant, "s": space},
                )
                actors, public_actors = {}, []
                credentials[str(tenant)] = []
                for label, kind in _ACTORS:
                    principal, credential = (
                        _id(seed, f"{tenant}/{label}/principal"),
                        _id(seed, f"{tenant}/{label}/credential"),
                    )
                    actors[label] = principal
                    token, digest = new_token(tenant, credential)
                    conn.execute(
                        text("""INSERT INTO execbound.principals
                        (tenant_id,principal_id,kind,space_id) VALUES (:t,:p,:k,:s)"""),
                        {
                            "t": tenant,
                            "p": principal,
                            "k": kind,
                            "s": space if kind == "AGENT" else None,
                        },
                    )
                    if kind == "HUMAN_APPROVER":
                        # An approver is a member of the space, as migration 0041 seats
                        # every approver that already existed; an administrator gets no
                        # membership, which is what makes them a tenant administrator.
                        conn.execute(
                            text("""INSERT INTO execbound.space_members
                            (tenant_id,space_id,principal_id,role,assigned_at)
                            VALUES (:t,:s,:p,'HUMAN_APPROVER',now())"""),
                            {"t": tenant, "s": space, "p": principal},
                        )
                    conn.execute(
                        text("""INSERT INTO execbound.credentials
                        (tenant_id,credential_id,principal_id,token_hash,issued_at,expires_at)
                        VALUES (:t,:c,:p,:h,:n,:e)"""),
                        {
                            "t": tenant,
                            "c": credential,
                            "p": principal,
                            "h": digest,
                            "n": now,
                            "e": expiry,
                        },
                    )
                    actor = {
                        "label": label,
                        "kind": kind,
                        "principal_id": str(principal),
                        "credential_id": str(credential),
                    }
                    public_actors.append(actor)
                    credentials[str(tenant)].append({**actor, "token": token})
                    if kind == "ADMIN":
                        _write(output / f"admin-{index}.token", token, plain=True)
                accounts = {
                    provider: insert_account(conn, seed, tenant, provider)
                    for provider in _PROVIDERS
                }
                for provider, account in accounts.items():
                    key_id = (
                        "endpoint-journal-v1"
                        if provider == _PROVIDERS[0]
                        else "identity-journal-v1"
                    )
                    provider_port = endpoint_port if provider == _PROVIDERS[0] else identity_port
                    connector, record = provider_material(
                        provider,
                        tenant,
                        account,
                        f"http://127.0.0.1:{provider_port}",
                        key_id=key_id,
                    )
                    config["connectors"].append(connector)
                    provider_accounts[provider].append(record)
                insert_mappings(conn, tenant, accounts)
                targets = _targets(seed, tenant, accounts)
                for target in targets:
                    _insert_target(conn, seed, tenant, target, actors, now)
                    canonical = UUID(target["canonical_target_id"])
                    target_account = UUID(target["account_id"])
                    if target["resource_type"] == "endpoint":
                        endpoint_store.provision_resource(tenant, canonical, "resource-v1")
                        endpoint_store.provision_representation(
                            tenant, target_account, target["provider_id"], canonical
                        )
                    else:
                        identity_store.provision_resource(
                            tenant,
                            canonical,
                            "resource-v1",
                            account_enabled=target["label"] != "identity-enable",
                        )
                        identity_store.provision_representation(
                            tenant, target_account, target["provider_id"], canonical
                        )
                bundle = _bundle(seed, tenant, accounts)
                _install_bundle(conn, bundle, actors["admin"], now)
                _write(output / f"bundle-{index}.json", bundle.model_dump(mode="json"))
                soc = _soc_bundle(seed, tenant, accounts)
                _install_bundle(conn, soc, actors["admin"], now, activate=False)
                _write(output / f"soc-bundle-{index}.json", soc.model_dump(mode="json"))
                candidate_data = bundle.model_dump(mode="json")
                candidate_data["bundle_id"] = str(_id(seed, f"{tenant}/candidate"))
                for rule in candidate_data["limits"]:
                    rule["max_targets"] = 1
                candidate = BundleContent.model_validate_json(json.dumps(candidate_data))
                _write(output / f"candidate-{index}.json", candidate.model_dump(mode="json"))
                fixture["tenants"].append(
                    {
                        "tenant_id": str(tenant),
                        "name": name,
                        "accounts": accounts,
                        "actors": public_actors,
                        "targets": targets,
                    }
                )
            _write(output / "credentials.json", credentials)
            _write(output / "gateway.json", config)
            _write(output / "endpoint-accounts.json", provider_accounts[_PROVIDERS[0]])
            _write(output / "identity-accounts.json", provider_accounts[_PROVIDERS[1]])
            for store_file in (output / "endpoint.sqlite3", output / "identity.sqlite3"):
                store_file.chmod(0o600)
            _write(output / "fixture.pending.json", fixture)
        # Publish a complete manifest only after a successful database commit. Leave
        # staging material private; another process may have added or replaced files.
        os.link(output / "fixture.pending.json", output / "fixture.json")
    except BaseException as exc:
        # The directory pathname is not ownership proof. Retain partial private
        # artifacts rather than deleting foreign files or a replacement directory.
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise ValueError("Validation fixture unavailable") from None
    finally:
        if engine is not None:
            engine.dispose()
