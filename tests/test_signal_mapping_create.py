# SPDX-License-Identifier: AGPL-3.0-only
"""Choosing a contract version at mapping creation."""

import pytest
from sqlalchemy import text
from test_context_provisioning import audit_payloads, refused_cli, run_cli
from test_context_provisioning import cli_env as cli_env
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_resolution import registry as registry

from execbound.administration import AdministrationError, create_mapping


def contract_of(admin_engine, tenant, ref):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text(
                "SELECT context_contract_version FROM execbound.operation_mappings "
                "WHERE tenant_id = :t AND operation_ref = :r"
            ),
            {"t": tenant, "r": ref},
        ).scalar_one()


def row_count(admin_engine, tenant, ref):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text(
                "SELECT count(*) FROM execbound.operation_mappings "
                "WHERE tenant_id = :t AND operation_ref = :r"
            ),
            {"t": tenant, "r": ref},
        ).scalar_one()


def test_the_default_stays_v1_and_v2_is_chosen_by_name(world, admin_engine):
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    default_summary = create_mapping(
        admin_engine,
        tenant,
        world["account"],
        "endpoint.isolate",
        actor,
        operation_ref="isolate.default",
    )
    corroborated_summary = create_mapping(
        admin_engine,
        tenant,
        world["account"],
        "endpoint.isolate",
        actor,
        operation_ref="isolate.corroborated",
        context_contract_version="endpoint-isolation.v2",
    )
    assert contract_of(admin_engine, tenant, "isolate.default") == "endpoint-isolation.v1"
    assert contract_of(admin_engine, tenant, "isolate.corroborated") == "endpoint-isolation.v2"
    assert default_summary.context_contract_version == "endpoint-isolation.v1"
    assert corroborated_summary.context_contract_version == "endpoint-isolation.v2"
    events = audit_payloads(admin_engine, tenant, "mapping.created")
    default_payload = next(p for _, p in events if p["operation_ref"] == "isolate.default")
    corroborated_payload = next(
        p for _, p in events if p["operation_ref"] == "isolate.corroborated"
    )
    assert default_payload["context_contract_version"] == "endpoint-isolation.v1"
    assert corroborated_payload["context_contract_version"] == "endpoint-isolation.v2"


@pytest.mark.parametrize(
    "version", ["endpoint-recovery.v1", "identity-control.v1", "endpoint-isolation.v9", ""]
)
def test_a_version_that_does_not_serve_the_action_is_refused(world, admin_engine, version):
    with pytest.raises(AdministrationError) as caught:
        create_mapping(
            admin_engine,
            world["identity"].tenant_id,
            world["account"],
            "endpoint.isolate",
            world["admin"].principal_id,
            operation_ref="isolate.refused",
            context_contract_version=version,
        )
    assert caught.value.code == "INVALID_CONTRACT"


def test_v2_named_for_another_action_is_refused(world, admin_engine):
    """A real contract version that does not serve the action named is refused the same way."""
    with pytest.raises(AdministrationError) as caught:
        create_mapping(
            admin_engine,
            world["identity"].tenant_id,
            world["account"],
            "endpoint.lift_isolation",
            world["admin"].principal_id,
            operation_ref="lift.refused",
            context_contract_version="endpoint-isolation.v2",
        )
    assert caught.value.code == "INVALID_CONTRACT"


def test_the_cli_names_the_version(cli_env, monkeypatch, capsys, world, admin_engine):
    tenant = world["identity"].tenant_id
    mapping = run_cli(
        monkeypatch,
        capsys,
        "mapping-create",
        "--tenant", str(tenant),
        "--account", str(world["account"]),
        "--action", "endpoint.isolate",
        "--ref", "isolate.cli",
        "--contract-version", "endpoint-isolation.v2",
        "--actor", str(world["admin"].principal_id),
    )  # fmt: skip
    assert mapping["context_contract_version"] == "endpoint-isolation.v2"
    assert contract_of(admin_engine, tenant, "isolate.cli") == "endpoint-isolation.v2"


def test_the_cli_refuses_a_version_naming_another_action(
    cli_env, monkeypatch, capsys, world, admin_engine
):
    tenant = world["identity"].tenant_id
    err = refused_cli(
        monkeypatch,
        capsys,
        "mapping-create",
        "--tenant", str(tenant),
        "--account", str(world["account"]),
        "--action", "endpoint.lift_isolation",
        "--ref", "lift.cli.refused",
        "--contract-version", "endpoint-isolation.v2",
        "--actor", str(world["admin"].principal_id),
    )  # fmt: skip
    assert "Administration refused: INVALID_CONTRACT." in err
    assert row_count(admin_engine, tenant, "lift.cli.refused") == 0
