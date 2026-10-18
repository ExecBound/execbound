# SPDX-License-Identifier: AGPL-3.0-only
"""The setup check reports persisted evidence, scoped exactly like Monitoring."""

from datetime import timedelta
from uuid import uuid4

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, refusals
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_console_api_monitoring import seed_agent, seed_tines
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.monitoring import store
from execbound.monitoring.models import MonitorError

pytestmark = pytest.mark.integration
PATH = API + "/monitor/setup/verify"


def register(db, world, **changes):
    settings = {
        "label": "Pending source",
        "base_url": "https://fixture.tines.com",
        "key_fingerprint": "0" * 64,
        "clock": world["clock"],
        **changes,
    }
    return store.create_connection(
        db,
        world["admin"],
        **settings,
    )


def check(client, connection, provider="tines", **kwargs):
    return client.post(PATH, {"provider": provider, "connection_id": str(connection)}, **kwargs)


def test_setup_verification_requires_admin_session_origin_and_csrf(
    db, runtime, seeded, admin_engine, world
):
    refused = refusals(db, runtime, seeded, admin_engine, world, PATH, "POST")
    assert refused["bearer"].status_code == 403 and refused["audited"] == 1
    assert refused["no_session"].status_code == 401
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        assert check(approver, uuid4()).status_code == 403
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert check(admin, uuid4(), csrf=None).status_code == 403
        assert check(admin, uuid4(), csrf="wrong").status_code == 403
        assert check(admin, uuid4(), origin="https://elsewhere.invalid").status_code == 403
        assert check(admin, uuid4()).status_code == 404
        for extra in ({"api_key": "must-not-be-accepted"}, {"url": "http://localhost"}):
            response = admin.post(
                PATH, {"provider": "tines", "connection_id": str(uuid4()), **extra}
            )
            assert response.status_code == 400
        assert check(admin, uuid4(), provider="unsupported").status_code == 400


def test_registration_is_awaiting_data_and_never_an_assumed_success(
    db, runtime, admin_engine, world
):
    connection = register(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = check(admin, connection)
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        body = response.json()
        assert body["state"] == "awaiting_sync"
        assert body["last_run_at"] is None and body["last_sync_at"] is None
        assert body["recent_observations"] == 0 and body["latest_observation_at"] is None
        assert check(admin, connection, provider="entra_agent_id").status_code == 404
        store.record_run_outcome(
            db,
            world["admin"],
            connection,
            outcome="AUTH_LOST",
            run_id=uuid4(),
            error_code="AUTH_LOST",
            clock=world["clock"],
        )
        assert check(admin, connection).json()["state"] == "attention"
        store.revoke_connection(db, world["admin"], connection, clock=world["clock"])
        assert check(admin, connection).json()["state"] == "inactive"


@pytest.mark.parametrize("provider", ["tines", "entra_agent_id"])
def test_reporting_requires_a_real_persisted_collection_and_old_evidence_is_attention(
    db, runtime, admin_engine, world, provider
):
    connection = seed_tines(db, world) if provider == "tines" else seed_agent(db, world)[0]
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = check(admin, connection, provider)
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        body = response.json()
        assert body["state"] == "reporting"
        assert body["last_run_at"] is not None and body["last_sync_at"] is not None
        assert body["capabilities"]
        if provider == "tines":
            assert body["recent_observations"] > 0 and body["latest_observation_at"]
        else:
            # Entra's inventory-only collector has no execution observations to invent.
            assert body["recent_observations"] == 0 and body["latest_observation_at"] is None
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET last_run_at=:old "
                    "WHERE tenant_id=:t AND connection_id=:c"
                ),
                {
                    "t": world["admin"].tenant_id,
                    "c": connection,
                    "old": world["clock"].now() - timedelta(days=2),
                },
            )
        assert check(admin, connection, provider).json()["state"] == "attention"


def test_verification_never_reads_another_space_or_tenant(db, runtime, admin_engine, world, seeded):
    tenant = world["admin"].tenant_id
    connection = register(db, world)
    with admin_engine.begin() as conn:
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Other customer")
        foreign = uuid4()
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_connections "
                "(tenant_id,connection_id,label,base_url,key_fingerprint,created_at,"
                "created_by,space_id) VALUES (:t,:c,'Foreign','https://foreign.tines.com',"
                "repeat('0',64),now(),:p,:s)"
            ),
            {
                "t": seeded["tenants"][1],
                "c": foreign,
                "p": seeded["principals"][1],
                "s": seeded["spaces"][1],
            },
        )
    other_connection = register(db, world, space=second)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        changed = admin.post(API + "/session/space", {"space_id": str(first)})
        assert changed.status_code == 200
        assert check(admin, connection).status_code == 200
        assert check(admin, other_connection).status_code == 404
        assert check(admin, foreign).status_code == 404
        with admin_engine.begin() as conn:
            seat(conn, tenant, first, world["admin"].principal_id, "ADMIN")
        # Even "All spaces" may only see current memberships.
        changed = admin.post(API + "/session/space", {"space_id": None})
        assert changed.status_code == 200
        assert check(admin, other_connection).status_code == 404
        assert check(admin, uuid4()).status_code == 404


def test_registration_rechecks_named_space_membership_and_archive_in_its_transaction(
    db, admin_engine, world
):
    tenant = world["admin"].tenant_id
    with admin_engine.begin() as conn:
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Other customer")
        seat(conn, tenant, first, world["admin"].principal_id, "ADMIN")
    for invalid in (second, uuid4()):
        with pytest.raises(MonitorError) as error:
            register(db, world, space=invalid)
        assert error.value.code == "INVALID_SPACE"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.spaces SET archived_at=now() WHERE tenant_id=:t AND space_id=:s"
            ),
            {"t": tenant, "s": first},
        )
    with pytest.raises(MonitorError) as error:
        register(db, world)
    assert error.value.code == "INVALID_SPACE"


@pytest.mark.parametrize("provider", ["tines", "entra_agent_id"])
def test_registration_requires_an_admin_membership_when_the_operator_is_space_scoped(
    db, admin_engine, world, provider
):
    tenant = world["admin"].tenant_id
    actor = world["admin"].principal_id
    with admin_engine.begin() as conn:
        restricted = default_space(conn, tenant)
        allowed = make_space(conn, tenant, "Collector administrators")
        seat(conn, tenant, restricted, actor, "HUMAN_APPROVER")
        seat(conn, tenant, allowed, actor, "ADMIN")
    settings = {"kind": provider}
    if provider == "entra_agent_id":
        settings.update(
            base_url=store.GRAPH_ORIGIN,
            directory_ref=str(uuid4()),
            client_ref=str(uuid4()),
        )
    # A tenant-level ADMIN may only review in this Space, including when the CLI
    # chooses the default implicitly. Neither provider registration may elevate it.
    for placement in ({}, {"space": restricted}):
        with pytest.raises(MonitorError) as error:
            register(db, world, **settings, **placement)
        assert error.value.code == "INVALID_SPACE"
    connection = register(db, world, **settings, space=allowed)
    with admin_engine.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT connection_id,space_id FROM execbound.monitor_connections "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        ).all()
    assert rows == [(connection, allowed)]
