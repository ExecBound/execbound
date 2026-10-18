# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0060 (#420): the `sample` flag and the two definer functions (SM8, and the
function halves of SM1, SM2 and SM6).

`samples_install` and `samples_remove` are called here directly over the runtime role, the way
`execbound.samples` calls them, and every row they write is read back over an owner connection
under the tenant's own fence, so a zero is isolation and never absence. The hosted owner's case
runs against the `restricted` fixture's database, whose owner is no superuser and does not
bypass row-level security: a statement inside a function that forgot its tenant would find or
write nothing there rather than pass.
"""

import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from alembic import command
from signup_fixtures import stack as stack
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted

from execbound.db import FUNCTIONS, check_runtime

pytestmark = pytest.mark.integration

NEW_FUNCTIONS = {"samples_install", "samples_remove"}
TARGETS = (
    ("sample-ws-dev-01", "ws-dev-01.sample.invalid", "workstation", "development", 1),
    ("sample-ws-prod-01", "ws-prod-01.sample.invalid", "workstation", "production", 2),
    ("sample-dc-01", "dc-01.sample.invalid", "domain_controller", "production", 3),
)
REGISTRY = (
    "connector_accounts",
    "context_sources",
    "operation_mappings",
    "canonical_targets",
    "resources",
    "resource_identities",
    "resource_aliases",
    "incidents",
    "approval_scopes",
)


def targets() -> str:
    """The shape `execbound.samples` sends: facts from the product module, fresh identifiers."""
    return json.dumps(
        [
            {
                "provider_id": provider_id,
                "hostname": hostname,
                "role": role,
                "environment": environment,
                "criticality": criticality,
                "version": "sample-resource-v1",
                "canonical_target_id": str(uuid4()),
                "resource_id": str(uuid4()),
                "incident_id": str(uuid4()),
            }
            for provider_id, hostname, role, environment, criticality in TARGETS
        ]
    )


def workspace(engine):
    """An active tenant with one Default space and one ADMIN, written as the owner, fenced."""
    tenant, space, admin = uuid4(), uuid4(), uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name, active) VALUES (:t, :n, true)"),
            {"t": tenant, "n": f"sample-{tenant.hex[:8]}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Default', now(), :a)"
            ),
            {"t": tenant, "s": space, "a": admin},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :p, 'ADMIN')"
            ),
            {"t": tenant, "p": admin},
        )
    return tenant, space, admin


def select_policy(engine, tenant, space, actor):
    """An active selection a person made: content, lifecycle and selection, as the owner."""
    bundle, digest = uuid4(), secrets.token_hex(32)
    params = {"t": tenant, "b": bundle, "h": digest, "a": actor, "s": space}
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.policy_bundle_contents "
                "(tenant_id, bundle_id, content_hash, content, created_at, created_by, space_id) "
                "VALUES (:t, :b, :h, CAST('{}' AS jsonb), now(), :a, :s)"
            ),
            params,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.policy_bundle_lifecycle "
                "(tenant_id, bundle_id, content_hash, state, changed_at) "
                "VALUES (:t, :b, :h, 'ACTIVE', now())"
            ),
            params,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.space_policy_selection "
                "(tenant_id, space_id, bundle_id, changed_at, changed_by) "
                "VALUES (:t, :s, :b, now(), :a)"
            ),
            params,
        )
    return bundle


def install(db, tenant, space, actor, account=None, payload=None):
    with db.transaction(tenant) as conn:
        return conn.execute(
            text(
                "SELECT execbound.samples_install(:actor, :account, :space, "
                "CAST(:targets AS jsonb), :now)"
            ),
            {
                "actor": actor,
                "account": account or uuid4(),
                "space": space,
                "targets": payload or targets(),
                "now": datetime.now(UTC),
            },
        ).scalar_one()


def remove(db, tenant, actor, account, bundle=None):
    with db.transaction(tenant) as conn:
        return conn.execute(
            text("SELECT execbound.samples_remove(:actor, :account, :bundle, :now)"),
            {"actor": actor, "account": account, "bundle": bundle, "now": datetime.now(UTC)},
        ).scalar_one()


def refused(call, *args, **kwargs) -> str:
    """The code a function refused with; its message is the code and nothing else."""
    with pytest.raises(DBAPIError) as caught:
        call(*args, **kwargs)
    return caught.value.orig.diag.message_primary


def counts(engine, tenant) -> dict[str, int]:
    with engine.begin() as conn:
        fenced(conn, tenant)
        return {
            table: conn.execute(
                text(f"SELECT count(*) FROM execbound.{table} WHERE tenant_id = :t"),
                {"t": tenant},
            ).scalar_one()
            for table in REGISTRY
        }


def snapshot(engine, tenant) -> dict[str, list[str]]:
    with engine.begin() as conn:
        fenced(conn, tenant)
        return {
            table: sorted(
                str(dict(row))
                for row in conn.execute(
                    text(f"SELECT * FROM execbound.{table} WHERE tenant_id = :t"), {"t": tenant}
                ).mappings()
            )
            for table in (*REGISTRY, "tenant_policy_control")
        }


def test_sm8_revision_catalog_and_privileges(db, admin_engine, seeded):
    assert NEW_FUNCTIONS <= {name for name, _ in FUNCTIONS}
    with db.engine.begin() as conn:
        check_runtime(conn)
    with admin_engine.begin() as conn:
        column = conn.execute(
            text(
                "SELECT data_type, is_nullable, column_default FROM information_schema.columns "
                "WHERE table_schema = 'execbound' AND table_name = 'connector_accounts' "
                "AND column_name = 'sample'"
            )
        ).one()
        assert tuple(column) == ("boolean", "NO", "false")
        for name in NEW_FUNCTIONS:
            granted = conn.execute(
                text(
                    "SELECT has_function_privilege('execbound_app', p.oid, 'EXECUTE'), "
                    "has_function_privilege('public', p.oid, 'EXECUTE'), p.prosecdef "
                    "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'execbound' AND p.proname = :name"
                ),
                {"name": name},
            ).one()
            assert tuple(granted) == (True, False, True), name
        # Only the install function sets the flag: the runtime writes no connector account.
        for privilege in ("INSERT", "UPDATE", "DELETE"):
            assert not conn.execute(
                text("SELECT has_table_privilege('execbound_app', :t, :p)"),
                {"t": "execbound.connector_accounts", "p": privilege},
            ).scalar_one(), privilege


def test_sm8b_the_migration_goes_down_and_up_and_never_drops_a_sample_account(restricted):
    engine, config, _ = restricted
    command.upgrade(config, "0059_workspace_invitations")
    command.upgrade(config, "0060_sample_targets")
    tenant, space, _ = workspace(engine)
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts"
                "(tenant_id, account_id, provider, space_id, sample) "
                "VALUES (:t, :a, 'mock_crowdstrike', :s, true)"
            ),
            {"t": tenant, "a": uuid4(), "s": space},
        )
    with pytest.raises(RuntimeError, match="sample connector accounts"):
        command.downgrade(config, "0059_workspace_invitations")
    with engine.begin() as conn:
        fenced(conn, tenant)
        assert (
            conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
            == "0060_sample_targets"
        )
        conn.execute(
            text("UPDATE execbound.connector_accounts SET sample = false WHERE tenant_id = :t"),
            {"t": tenant},
        )
    command.downgrade(config, "0059_workspace_invitations")
    with engine.begin() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM information_schema.columns "
                    "WHERE table_schema = 'execbound' AND table_name = 'connector_accounts' "
                    "AND column_name = 'sample'"
                )
            ).scalar_one()
            == 0
        )
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM pg_proc p JOIN pg_namespace n "
                    "ON n.oid = p.pronamespace WHERE n.nspname = 'execbound' "
                    "AND p.proname IN ('samples_install', 'samples_remove')"
                )
            ).scalar_one()
            == 0
        )
    command.upgrade(config, "head")


def test_sm1a_the_install_function_writes_every_registry_row_without_bypass(stack):
    engine, db = stack
    tenant, space, admin = workspace(engine)
    account = uuid4()

    result = install(db, tenant, space, admin, account)

    assert result == {"outcome": "INSTALLED", "account_id": str(account)}
    assert counts(engine, tenant) == {
        "connector_accounts": 1,
        "context_sources": 2,
        "operation_mappings": 1,
        "canonical_targets": 3,
        "resources": 3,
        "resource_identities": 3,
        "resource_aliases": 6,
        "incidents": 3,
        "approval_scopes": 3,
    }
    with engine.begin() as conn:
        fenced(conn, tenant)
        row = conn.execute(
            text(
                "SELECT provider, active, sample, space_id FROM execbound.connector_accounts "
                "WHERE tenant_id = :t"
            ),
            {"t": tenant},
        ).one()
        mapping = conn.execute(
            text(
                "SELECT account_id, provider_operation, mapping_version, schema_version, "
                "context_contract_version, active FROM execbound.operation_mappings "
                "WHERE tenant_id = :t AND operation_ref = 'endpoint.isolate'"
            ),
            {"t": tenant},
        ).one()
        hosts = sorted(
            tuple(found)
            for found in conn.execute(
                text(
                    "SELECT provider_id, role, environment, criticality, version, demo_fixture, "
                    "active FROM execbound.resources WHERE tenant_id = :t"
                ),
                {"t": tenant},
            )
        )
        aliases = sorted(
            conn.execute(
                text(
                    "SELECT kind || ':' || normalized_value FROM execbound.resource_aliases "
                    "WHERE tenant_id = :t"
                ),
                {"t": tenant},
            ).scalars()
        )
        incidents = set(
            conn.execute(
                text(
                    "SELECT status || '/' || severity || '/' || demo_fixture "
                    "FROM execbound.incidents WHERE tenant_id = :t"
                ),
                {"t": tenant},
            ).scalars()
        )
        writers = sorted(
            tuple(found)
            for found in conn.execute(
                text(
                    "SELECT kind, allowed_writers FROM execbound.context_sources "
                    "WHERE tenant_id = :t"
                ),
                {"t": tenant},
            )
        )
        reviewers = set(
            conn.execute(
                text(
                    "SELECT approver_id::text || '/' || action || '/' || active "
                    "FROM execbound.approval_scopes WHERE tenant_id = :t"
                ),
                {"t": tenant},
            ).scalars()
        )
    assert tuple(row) == ("mock_crowdstrike", True, True, space)
    assert tuple(mapping) == (
        account,
        "contain",
        "sample-v1",
        "action.v1",
        "endpoint-isolation.v1",
        True,
    )
    assert hosts == sorted(
        (provider_id, role, environment, criticality, "sample-resource-v1", False, True)
        for provider_id, _hostname, role, environment, criticality in TARGETS
    )
    assert aliases == sorted(
        [f"provider_id:{target[0]}" for target in TARGETS]
        + [f"hostname:{target[1]}" for target in TARGETS]
    )
    assert incidents == {"OPEN/CRITICAL/false"}
    assert writers == [("incident", ["soc_analyst"]), ("inventory", ["inventory_sync"])]
    assert reviewers == {f"{admin}/endpoint.isolate/true"}
    before = snapshot(engine, tenant)
    assert install(db, tenant, space, admin) == {"outcome": "PRESENT", "account_id": str(account)}
    assert snapshot(engine, tenant) == before


def test_sm2a_the_install_function_refuses_anyone_but_a_live_administrator_of_the_tenant(
    db, admin_engine, seeded
):
    tenant, space, _ = workspace(admin_engine)
    approver = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :p, 'HUMAN_APPROVER')"
            ),
            {"t": tenant, "p": approver},
        )
    _, _, other_admin = workspace(admin_engine)
    assert refused(install, db, tenant, space, approver) == "INVALID_ACTOR"
    assert refused(install, db, tenant, space, uuid4()) == "INVALID_ACTOR"
    # Another workspace's administrator is nobody here.
    assert refused(install, db, tenant, space, other_admin) == "INVALID_ACTOR"
    assert counts(admin_engine, tenant)["connector_accounts"] == 0


def test_sm2b_the_install_function_refuses_a_workspace_someone_built_and_a_bad_target(
    db, admin_engine, seeded
):
    tenant, space, admin = workspace(admin_engine)
    assert refused(install, db, tenant, uuid4(), admin) == "INVALID_SPACE"
    for field, value in (
        ("hostname", "ws-dev-01.example.com"),
        ("provider_id", "ws-dev-01"),
        ("criticality", "3"),
        ("resource_id", "not-a-uuid"),
    ):
        bad = json.loads(targets())
        bad[0][field] = value
        assert refused(install, db, tenant, space, admin, payload=json.dumps(bad)) == (
            "INVALID_TARGETS"
        ), field
    assert counts(admin_engine, tenant)["connector_accounts"] == 0

    selected = workspace(admin_engine)
    select_policy(admin_engine, *selected)
    assert refused(install, db, *selected) == "POLICY_PRESENT"

    connected = workspace(admin_engine)
    with admin_engine.begin() as conn:
        fenced(conn, connected[0])
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) VALUES (:t, :a, 'mock_entra', :s)"
            ),
            {"t": connected[0], "a": uuid4(), "s": connected[1]},
        )
    assert refused(install, db, *connected) == "ACCOUNT_PRESENT"

    # A mapping a person made stays theirs, even with its account switched off.
    mapped = workspace(admin_engine)
    theirs = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, mapped[0])
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id, active) VALUES (:t, :a, 'mock_crowdstrike', :s, false)"
            ),
            {"t": mapped[0], "a": theirs, "s": mapped[1]},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings (tenant_id, operation_ref, account_id, "
                "provider, resource_type, action, provider_operation, mapping_version, "
                "schema_version, context_contract_version, active) VALUES (:t, "
                "'endpoint.isolate', :a, 'mock_crowdstrike', 'endpoint', 'endpoint.isolate', "
                "'contain', 'map-v1', 'action.v1', 'endpoint-isolation.v1', false)"
            ),
            {"t": mapped[0], "a": theirs},
        )
    assert refused(install, db, *mapped) == "MAPPING_PRESENT"


def blocked_on_a_lock(engine, *, within=4.0, waiting=1):
    """Wait until `waiting` backends of this database, one unless named, are waiting on another
    transaction's lock.

    Inside the five seconds `Database.transaction` allows a lock wait, so the holder commits
    while the call is still waiting rather than after it has timed out."""
    deadline = time.monotonic() + within
    with engine.connect() as conn:
        while time.monotonic() < deadline:
            found = conn.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                    "AND state = 'active' AND wait_event_type = 'Lock'"
                )
            ).scalar_one()
            conn.rollback()
            if found >= waiting:
                return
            time.sleep(0.02)
    raise AssertionError("the function never waited on the tenant fence")


@pytest.mark.parametrize("function", ["install", "remove"])
def test_sm2c_an_administrator_deactivated_while_a_function_waits_on_the_fence_is_refused(
    db, admin_engine, seeded, function
):
    """The actor is checked after the fence is taken, not before the wait. An administrator
    switched off by a transaction that holds the fence and commits while the call waits on it
    is refused, and the call writes nothing; checked before the wait, the call went ahead on
    authority that had already ended."""
    tenant, space, admin = workspace(admin_engine)
    account = uuid4()
    if function == "remove":
        install(db, tenant, space, admin, account)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.tenant_policy_control(tenant_id, changed_at) "
                "VALUES (:t, now()) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant},
        )
    before = snapshot(admin_engine, tenant)

    def call():
        try:
            if function == "install":
                return install(db, tenant, space, admin, account)
            return remove(db, tenant, admin, account)
        except DBAPIError as exc:
            return exc.orig.diag.message_primary

    with admin_engine.connect() as holder:
        holding = holder.begin()
        fenced(holder, tenant)
        holder.execute(
            text("SELECT 1 FROM execbound.tenant_policy_control WHERE tenant_id = :t FOR UPDATE"),
            {"t": tenant},
        )
        holder.execute(
            text(
                "UPDATE execbound.principals SET active = false "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": admin},
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(call)
            try:
                blocked_on_a_lock(admin_engine)
            finally:
                holding.commit()
            outcome = pending.result(timeout=30)

    assert outcome == "INVALID_ACTOR"
    after = snapshot(admin_engine, tenant)
    del before["tenant_policy_control"], after["tenant_policy_control"]
    assert after == before


def test_sm6a_the_remove_function_deactivates_deletes_nothing_and_lets_install_return(
    db, admin_engine, seeded
):
    tenant, space, admin = workspace(admin_engine)
    account = uuid4()
    install(db, tenant, space, admin, account)
    before = counts(admin_engine, tenant)
    assert refused(remove, db, tenant, uuid4(), account) == "INVALID_ACTOR"

    result = remove(db, tenant, admin, account)

    assert result == {
        "outcome": "REMOVED",
        "account_id": str(account),
        "retired": False,
        "spaces": [],
    }
    assert counts(admin_engine, tenant) == before
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        for table in (
            "connector_accounts",
            "context_sources",
            "operation_mappings",
            "resources",
            "approval_scopes",
        ):
            assert set(
                conn.execute(
                    text(f"SELECT active FROM execbound.{table} WHERE tenant_id = :t"),
                    {"t": tenant},
                ).scalars()
            ) == {False}, table
    assert remove(db, tenant, admin, account) == {"outcome": "ABSENT"}
    second = uuid4()
    assert install(db, tenant, space, admin, second) == {
        "outcome": "INSTALLED",
        "account_id": str(second),
    }
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        mappings = conn.execute(
            text(
                "SELECT account_id, active FROM execbound.operation_mappings WHERE tenant_id = :t"
            ),
            {"t": tenant},
        ).all()
    assert [tuple(found) for found in mappings] == [(second, True)]
