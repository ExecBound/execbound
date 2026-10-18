# SPDX-License-Identifier: AGPL-3.0-only
"""The guard in `tenant_fence` finds an owner read whose tenant fence limited nothing.

Each test reads through `admin_engine` after fencing to the first seeded tenant. `seeded`
gives both tenants a principal, so a read of `principals` that does not name its tenant
returns both, which is what the guard exists to catch. The tests that expect a finding take
it themselves, so the autouse fixture that would fail them on it finds nothing left.
"""

import pytest
import tenant_fence
from sqlalchemy import text


@pytest.fixture(autouse=True)
def bypassing_owner(admin_engine):
    with admin_engine.connect() as conn:
        bypasses = conn.execute(
            text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).scalar_one()
    if not bypasses:
        pytest.skip("the test owner does not bypass here, so a fence on it limits what it reads")
    tenant_fence.take()


def fenced(conn, tenant):
    # On the owner's connection this limits nothing, which is the point of this module.
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def test_a_fenced_read_that_counts_every_tenant_is_found(admin_engine, seeded):
    with admin_engine.begin() as conn:
        fenced(conn, seeded["tenants"][0])
        counted = conn.execute(text("SELECT count(*) FROM execbound.principals")).scalar_one()
    # The owner bypasses row security, so the fence did not stop the second tenant's row.
    assert counted == 2
    [found] = tenant_fence.take()
    assert found.startswith("tests/test_tenant_fence.py:")


def test_a_read_that_names_its_tenant_is_not_read_again(admin_engine, seeded):
    with admin_engine.begin() as conn:
        fenced(conn, seeded["tenants"][0])
        counted = conn.execute(
            text("SELECT count(*) FROM execbound.principals WHERE tenant_id = :t"),
            {"t": seeded["tenants"][0]},
        ).scalar_one()
    assert counted == 1
    assert tenant_fence.take() == []


def test_a_join_on_tenant_id_is_not_a_fence(admin_engine, seeded):
    with admin_engine.begin() as conn:
        fenced(conn, seeded["tenants"][0])
        counted = conn.execute(
            text(
                "SELECT count(*) FROM execbound.principals a "
                "JOIN execbound.principals b ON a.tenant_id = b.tenant_id"
            )
        ).scalar_one()
    assert counted == 2
    assert len(tenant_fence.take()) == 1


def test_a_read_the_fence_would_not_change_is_not_found(admin_engine, seeded):
    with admin_engine.begin() as conn:
        fenced(conn, seeded["tenants"][0])
        kind = conn.execute(
            text("SELECT kind FROM execbound.principals WHERE principal_id = :p"),
            {"p": seeded["principals"][0]},
        ).scalar_one()
    assert kind == "AGENT"
    assert tenant_fence.take() == []


def test_an_unfenced_or_cleared_read_is_not_checked(admin_engine, seeded):
    with admin_engine.begin() as conn:
        counted = conn.execute(text("SELECT count(*) FROM execbound.principals")).scalar_one()
    with admin_engine.begin() as conn:
        fenced(conn, seeded["tenants"][0])
        conn.execute(text("SELECT set_config('execbound.tenant_id', '', true)"))
        cleared = conn.execute(text("SELECT count(*) FROM execbound.principals")).scalar_one()
    assert counted == cleared == 2
    assert tenant_fence.take() == []


def test_a_statement_that_could_act_twice_is_never_run_again(admin_engine, seeded):
    with admin_engine.begin() as conn:
        conn.execute(text("CREATE TEMPORARY SEQUENCE tenant_fence_probe"))
        fenced(conn, seeded["tenants"][0])
        drawn = conn.execute(
            text("SELECT nextval('tenant_fence_probe') FROM execbound.principals")
        ).all()
        # Two rows drew two values; a second run of the statement would have drawn more,
        # and a sequence does not give them back when a savepoint rolls back.
        assert len(drawn) == 2
        assert conn.execute(text("SELECT last_value FROM tenant_fence_probe")).scalar_one() == 2
    assert tenant_fence.take() == []


def test_the_second_reads_leave_the_transaction_as_they_found_it(admin_engine, seeded):
    tenant, other = seeded["tenants"]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.principals SET active = false WHERE tenant_id = :t"),
            {"t": other},
        )
        result = conn.execute(text("SELECT tenant_id, active FROM execbound.principals"))
        rows = {row.tenant_id: row.active for row in result}
        # The cursor the test holds is the one it executed, unconsumed by the second reads,
        # and the transaction's own write, role and fence are all still in place.
        assert rows == {tenant: True, other: False}
        assert conn.execute(text("SELECT current_user")).scalar_one() == tenant_fence.OWNER
        assert conn.execute(
            text("SELECT current_setting('execbound.tenant_id')")
        ).scalar_one() == str(tenant)
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.principals WHERE NOT active")
            ).scalar_one()
            == 1
        )
    assert len(tenant_fence.take()) == 2
