# SPDX-License-Identifier: AGPL-3.0-only
"""Policy starts honor the selected Space and its current administration authority."""

from uuid import UUID, uuid4

import pytest
from console_api_fixtures import console_client
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.contracts import PRODUCTION_CATALOG
from execbound.policy.models import MappingRef
from execbound.policy.store import (
    PolicyStoreError,
    activate_bundle,
    create_bundle,
    read_bundle,
    validate_bundle,
)
from execbound.surfaces.console_api.policy_starters import first_policy

POLICY = "/api/console/v1/policy"


def second_space(admin_engine, world, *, offered=False):
    tenant = world["identity"].tenant_id
    account = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer B")
        conn.execute(
            text(
                "UPDATE execbound.connector_accounts SET offered_tenant_wide=false "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        )
        conn.execute(
            text(
                "UPDATE execbound.policy_bundle_contents SET offered_tenant_wide=false "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts "
                "(tenant_id, account_id, provider, active, space_id, offered_tenant_wide) "
                "VALUES (:t,:a,'mock_crowdstrike',true,:s,:offered)"
            ),
            {"t": tenant, "a": account, "s": second, "offered": offered},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id,operation_ref,account_id,provider,resource_type,action,provider_operation,"
                "mapping_version,schema_version,context_contract_version) "
                "VALUES (:t,'endpoint.lift_isolation',:a,'mock_crowdstrike','endpoint',"
                "'endpoint.lift_isolation','lift_containment','map-v1','action.v1','endpoint-recovery.v1')"
            ),
            {"t": tenant, "a": account},
        )
    mapping = MappingRef(
        operation_ref="endpoint.lift_isolation",
        account_id=account,
        mapping_version="map-v1",
        schema_version="action.v1",
        context_contract_version="endpoint-recovery.v1",
    )
    return first, second, mapping


def select_bundle(db, world, space, content):
    create_bundle(db, world["admin"], content, world["clock"], space=space)
    validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], content.bundle_id, world["clock"], space=space)


@pytest.mark.parametrize("offered", [False, True])
def test_first_start_excludes_private_space_mappings_and_ignores_other_active_policy(
    db, runtime, admin_engine, world, offered
):
    first, second, mapping = second_space(admin_engine, world, offered=offered)
    tenant = world["identity"].tenant_id
    private = first_policy(tenant, (mapping,), PRODUCTION_CATALOG)
    select_bundle(db, world, second, private)
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        seat(conn, tenant, first, world["admin"].principal_id, "ADMIN")
        conn.execute(
            text("DELETE FROM execbound.space_policy_selection WHERE tenant_id=:t AND space_id=:s"),
            {"t": tenant, "s": first},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(POLICY)
        assert page.status_code == 200, page.text
        assert page.json()["active"] is None and page.json()["starter_available"]
        assert str(private.bundle_id) not in {row["bundle_id"] for row in page.json()["bundles"]}
        assert client.get(f"{POLICY}/{private.bundle_id}").status_code == 404
        for source in ("bundle", "template"):
            refused = client.post(
                POLICY,
                {
                    "source": source,
                    "bundle_id": str(private.bundle_id),
                    **({"template": "current-protections"} if source == "template" else {}),
                },
            )
            assert refused.status_code == 404, refused.text
        made = client.post(POLICY, {"source": "template", "template": "security-response"})
        assert made.status_code == 200, made.text
        expected = {world["account"]} | ({mapping.account_id} if offered else set())
        assert {UUID(row["account_id"]) for row in made.json()["mappings"]} == expected
        with admin_engine.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT space_id FROM execbound.policy_bundle_contents WHERE bundle_id=:b"
                    ),
                    {"b": UUID(made.json()["bundle_id"])},
                ).scalar_one()
                == first
            )
        with admin_engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)}
            )
            conn.execute(
                text(
                    "UPDATE execbound.policy_bundle_contents SET offered_tenant_wide=true "
                    "WHERE tenant_id=:t AND bundle_id=:b"
                ),
                {"t": tenant, "b": private.bundle_id},
            )
        shared = client.post(POLICY, {"source": "bundle", "bundle_id": str(private.bundle_id)})
        # Offering a policy does not implicitly offer the private connector it references.
        assert shared.status_code == (200 if offered else 409), shared.text


@pytest.mark.parametrize("source", ["document", "active", "bundle", "template"])
def test_reviewer_space_role_cannot_create_a_policy_even_with_admin_principal_kind(
    db, runtime, admin_engine, world, source
):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        space = default_space(conn, tenant)
        seat(conn, tenant, space, world["admin"].principal_id, "HUMAN_APPROVER")
    body = {"source": source}
    if source == "document":
        body["document"] = world["bundle"].model_dump_json()
    if source == "bundle":
        body["bundle_id"] = str(world["bundle"].bundle_id)
    if source == "template":
        body["template"] = "current-protections"
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(POLICY, body)
        assert refused.status_code == 403, refused.text
    with pytest.raises(PolicyStoreError) as refusal:
        create_bundle(
            db,
            world["admin"],
            world["bundle"].model_copy(update={"bundle_id": uuid4()}),
            world["clock"],
            space=space,
        )
    assert refusal.value.code == "INVALID_IDENTITY"


def test_copy_uses_selected_nondefault_active_policy_and_preserves_its_space(
    db, runtime, admin_engine, world
):
    first, second, mapping = second_space(admin_engine, world)
    tenant = world["identity"].tenant_id
    active = first_policy(tenant, (mapping,), PRODUCTION_CATALOG)
    select_bundle(db, world, second, active)
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        seat(conn, tenant, first, world["admin"].principal_id, "ADMIN")
        seat(conn, tenant, second, world["admin"].principal_id, "ADMIN")
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        all_spaces = client.get(POLICY).json()
        assert all_spaces["active"] is None and not all_spaces["starter_available"]
        assert "Choose a Space" in all_spaces["starter_hint"]
        ambiguous = client.post(POLICY, {"source": "active"})
        assert ambiguous.status_code == 409, ambiguous.text
        assert (
            client.post("/api/console/v1/session/space", {"space_id": str(second)}).status_code
            == 200
        )
        page = client.get(POLICY).json()
        assert page["active"] == str(active.bundle_id)
        for source in ("active", "template"):
            made = client.post(
                POLICY,
                {
                    "source": source,
                    **({"template": "current-protections"} if source == "template" else {}),
                },
            )
            assert made.status_code == 200, made.text
            copied_id = UUID(made.json()["bundle_id"])
            stored = read_bundle(db, world["admin"], copied_id, world["clock"])
            assert stored.content.mappings == active.mappings
            with admin_engine.connect() as conn:
                assert (
                    conn.execute(
                        text(
                            "SELECT space_id FROM execbound.policy_bundle_contents "
                            "WHERE bundle_id=:b"
                        ),
                        {"b": copied_id},
                    ).scalar_one()
                    == second
                )
        refused = client.post(
            POLICY, {"source": "bundle", "bundle_id": str(world["bundle"].bundle_id)}
        )
        assert refused.status_code == 404, refused.text
        assert client.post(f"{POLICY}/{copied_id}/validate", {"confirm": True}).status_code == 200
        activated = client.post(
            f"{POLICY}/{copied_id}/activate", {"confirm": True, "reason": "Test rollout"}
        )
        assert activated.status_code == 200, activated.text
        assert client.get(POLICY).json()["active"] == str(copied_id)
        with admin_engine.connect() as conn:
            selections = dict(
                conn.execute(
                    text(
                        "SELECT space_id, bundle_id FROM execbound.space_policy_selection "
                        "WHERE tenant_id=:t"
                    ),
                    {"t": tenant},
                ).all()
            )
        assert selections == {first: world["bundle"].bundle_id, second: copied_id}
