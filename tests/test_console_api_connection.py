# SPDX-License-Identifier: AGPL-3.0-only
"""`GET /api/console/v1/connection`: the "Connect this agent" card's own data, core-served.

Connecting an agent is core, so the console's card must not depend on a plugin: this route
answers the gateway origin, every recipe `welcome` also offers, and (once a workspace has
installed sample targets with an open incident) the sample development workstation's hint,
with the `operation_ref` the samples' own active mapping answers to, so the example request
names the whole request (#545). An approver is refused before anything is read, exactly as
`/welcome` refuses one (the plugin's own welcome tests); a hosted sandbox's own fixture
workstation stays the plugin's welcome view and is not this route's concern.
"""

from uuid import UUID, uuid4

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, refusals
from sample_fixtures import empty_workspace, offline_runtime
from sample_fixtures import sample_key as sample_key
from sqlalchemy import text
from test_human_surface import human_config as human_config
from test_migration_without_bypass import fenced
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound import administration, samples
from execbound.surfaces.recipes import RECIPES

pytestmark = pytest.mark.integration

ROUTE = (API + "/connection", "GET")


def test_the_connection_route_is_an_administrators(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        refused = approver.get(ROUTE[0])
        assert refused.status_code == 403 and refused.json()["code"] == "FORBIDDEN"


def test_the_connection_route_refuses_a_bearer_credential_and_a_missing_session(
    db, runtime, seeded, admin_engine, world
):
    results = refusals(db, runtime, seeded, admin_engine, world, ROUTE[0], ROUTE[1])
    assert results["bearer"].status_code == 403 and results["audited"] == 1
    assert results["no_session"].status_code == 401


def test_an_administrator_reads_the_origin_and_every_recipe_with_no_workstation(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(ROUTE[0])
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        view = response.json()
        assert view["origin"] == "http://127.0.0.1"
        assert set(view["recipes"]) == set(RECIPES)
        assert "claude mcp add" in view["recipes"]["claude_code.sh"]
        assert view["workstation"] is None
        assert view["samples_state"] == "absent"
        assert view["operation_ref"] is None


def test_a_workspace_with_sample_targets_installed_names_its_development_workstation(
    db, admin_engine, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    samples.install(db, workspace.admin, available=True)
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        response = admin.get(ROUTE[0])
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        view = response.json()
        assert view["samples_state"] == "removable"
        assert view["workstation"]["value"] == "ws-dev-01.sample.invalid"
        assert view["workstation"]["kind"] == "hostname"
        assert view["workstation"]["incident_id"]
    assert view["operation_ref"] == mapped_operation(admin_engine, workspace.tenant_id)
    assert view["operation_ref"] == "endpoint.isolate"


def mapped_operation(admin_engine, tenant) -> str:
    """The operation_ref of the workspace's one active mapping, read as the owner."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return str(
            conn.execute(
                text(
                    "SELECT operation_ref FROM execbound.operation_mappings "
                    "WHERE tenant_id = :t AND active"
                ),
                {"t": tenant},
            ).scalar_one()
        )


def test_the_operation_ref_leaves_with_the_samples(db, admin_engine, sample_key):
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    samples.install(db, workspace.admin, available=True)
    samples.remove(db, workspace.admin, available=True)
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        view = admin.get(ROUTE[0]).json()
    assert (view["samples_state"], view["workstation"], view["operation_ref"]) == (
        "absent",
        None,
        None,
    )


def with_others_mapped(admin_engine, workspace, account) -> UUID:
    """Beside the samples' own `endpoint.isolate`, four mappings that sort before it and that
    the starter bundle does not name: the owner command's own second mapping of the isolation
    action to the sample account, an inactive one, another action on the sample account, and
    the isolation action on a connection of a person's own, whose account this returns."""
    administration.create_mapping(
        admin_engine,
        workspace.tenant_id,
        account,
        samples.SAMPLE_ACTION,
        workspace.admin.principal_id,
        operation_ref="contain.host",
    )
    persons = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) VALUES (:t, :a, 'mock_crowdstrike', :s)"
            ),
            {"t": workspace.tenant_id, "a": persons, "s": workspace.space_id},
        )
        for ref, owner, action, active in (
            ("a.inactive", account, samples.SAMPLE_ACTION, False),
            ("a.release", account, "endpoint.lift_isolation", True),
            ("a.isolate", persons, samples.SAMPLE_ACTION, True),
        ):
            conn.execute(
                text(
                    "INSERT INTO execbound.operation_mappings (tenant_id, operation_ref, "
                    "account_id, provider, resource_type, action, provider_operation, "
                    "mapping_version, schema_version, context_contract_version, active) "
                    "SELECT tenant_id, :r, :a, provider, resource_type, :action, "
                    "provider_operation, mapping_version, schema_version, "
                    "context_contract_version, :active FROM execbound.operation_mappings "
                    "WHERE tenant_id = :t AND operation_ref = 'endpoint.isolate'"
                ),
                {
                    "t": workspace.tenant_id,
                    "r": ref,
                    "a": owner,
                    "action": action,
                    "active": active,
                },
            )
    return persons


def test_the_operation_ref_is_the_samples_mapping_row_never_the_catalog_action(
    db, admin_engine, sample_key
):
    """A tenant's operation_ref is its own key, which only happens to equal the catalog action
    for the samples, so the route answers the one the samples' starter bundle names, and no
    other mapping, however it sorts: not a second mapping of the isolation action to the
    sample account, which the starter does not offer, nor an inactive one, another action or
    another account's."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    with_others_mapped(admin_engine, workspace, installed.account_id)
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        response = admin.get(ROUTE[0])
        assert response.status_code == 200, response.text
    assert response.json()["operation_ref"] == "endpoint.isolate"


@pytest.mark.parametrize(
    "change",
    [
        "operation_ref = 'sample.contain'",
        "active = false",
        "action = 'endpoint.lift_isolation'",
        "account_id = :persons",
    ],
)
def test_the_operation_ref_is_null_while_the_starters_own_mapping_is_not_live(
    db, admin_engine, sample_key, change
):
    """Where the tenant's mapping of what the starter names is renamed, switched off, bound to
    another action or moved to another account, the route names no operation, never the
    catalog action and never the owner's other mapping of the isolation action, and the
    console words the request without one. None of these is reachable through a command:
    only the definer functions write the samples' mapping."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    persons = with_others_mapped(admin_engine, workspace, installed.account_id)
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        conn.execute(
            text(
                f"UPDATE execbound.operation_mappings SET {change} "
                "WHERE tenant_id = :t AND operation_ref = 'endpoint.isolate'"
            ),
            {"t": workspace.tenant_id, "persons": persons},
        )
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        response = admin.get(ROUTE[0])
        assert response.status_code == 200, response.text
    view = response.json()
    assert (view["samples_state"], view["operation_ref"]) == ("removable", None)
    assert view["workstation"]["value"] == "ws-dev-01.sample.invalid"
