# SPDX-License-Identifier: AGPL-3.0-only
"""The agent limit (#257, #496): `tenants.max_agents`, enforced where an allowance is taken.

Real PostgreSQL throughout. The limit is set directly, as an operator would, with no plan
involved. What the cap counts is what Hosted Free defined, live and sleeping agent principals
and never one a person deactivated by hand; the plugin's own tests prove the same cap through
its plans.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from execbound.db import Database, check_runtime

pytestmark = pytest.mark.integration

CREATE = "SELECT execbound.admin_create_principal(:a, :k, :s)"
DEACTIVATE = "SELECT execbound.admin_deactivate_principal(:a, :p, :r)"
REACTIVATE = "SELECT execbound.admin_reactivate_principal(:a, :p)"


def fenced(conn, tenant):
    # Limits nothing on an `admin_engine` connection, whose owner bypasses row security
    # (see tenant_fence).
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def workspace(engine, limit):
    """An active tenant holding ``limit``, with its Default space and one administrator."""
    tenant, space, admin = uuid4(), uuid4(), uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.tenants(tenant_id, name, active, max_agents) "
                "VALUES (:t, :n, true, :limit)"
            ),
            {"t": tenant, "n": f"capacity-{tenant.hex[:8]}", "limit": limit},
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
                "VALUES (:t, :a, 'ADMIN')"
            ),
            {"t": tenant, "a": admin},
        )
    return tenant, space, admin


def refusal(error):
    return getattr(getattr(error.orig, "diag", None), "message_primary", None)


def create(db, tenant, space, admin, kind="AGENT"):
    """The new principal's id, or the code the definer function refused with."""
    try:
        with db.transaction(tenant) as conn:
            return conn.execute(
                text(CREATE), {"a": admin, "k": kind, "s": space if kind == "AGENT" else None}
            ).scalar_one()
    except DBAPIError as error:
        return refusal(error)


def call(db, tenant, statement, params):
    try:
        with db.transaction(tenant) as conn:
            conn.execute(text(statement), params)
    except DBAPIError as error:
        return refusal(error)
    return "ok"


def waiting(engine, fragment, count, timeout=4.0):
    """Block until ``count`` backends of this database running ``fragment`` wait on a lock
    (`tests/test_teammate_invitations.py`'s `waiting_on_lock`, for more than one). The timeout
    sits inside the five-second `lock_timeout` every runtime transaction sets."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with engine.connect() as conn:
            blocked = conn.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                    "AND wait_event_type = 'Lock' AND query LIKE :q"
                ),
                {"q": f"%{fragment}%"},
            ).scalar_one()
        if blocked >= count:
            return
        time.sleep(0.02)
    raise AssertionError(f"{count} calls to {fragment} never waited on a lock together")


def held(engine, tenant):
    with engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text(
                "SELECT count(*) FROM execbound.principals WHERE tenant_id = :t "
                "AND kind = 'AGENT' AND (active OR dormant_at IS NOT NULL)"
            ),
            {"t": tenant},
        ).scalar_one()


def test_ac1_no_limit_is_uncapped(db, admin_engine):
    tenant, space, admin = workspace(admin_engine, None)
    assert all(isinstance(create(db, tenant, space, admin), UUID) for _ in range(6))


@pytest.mark.parametrize("limit", [0, 1, 3, 5])
def test_ac2_a_limit_refuses_exactly_the_agent_past_it(db, admin_engine, limit):
    tenant, space, admin = workspace(admin_engine, limit)
    assert all(isinstance(create(db, tenant, space, admin), UUID) for _ in range(limit))
    assert create(db, tenant, space, admin) == "PLAN_LIMIT"


def test_ac3_what_the_limit_counts(db, admin_engine):
    tenant, space, admin = workspace(admin_engine, 3)
    agents = [create(db, tenant, space, admin) for _ in range(3)]
    # A sleeping agent still holds its allowance, and waking it is never refused.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, dormant_at = now() "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": agents[0]},
        )
    assert create(db, tenant, space, admin) == "PLAN_LIMIT"
    assert call(db, tenant, REACTIVATE, {"a": admin, "p": agents[0]}) == "ok"
    # A person switching one off frees its allowance; switching it back on at the limit
    # would take one back, and is refused.
    assert call(db, tenant, DEACTIVATE, {"a": admin, "p": agents[1], "r": "by hand"}) == "ok"
    assert isinstance(create(db, tenant, space, admin), UUID)
    assert call(db, tenant, REACTIVATE, {"a": admin, "p": agents[1]}) == "PLAN_LIMIT"
    # People are never counted.
    assert isinstance(create(db, tenant, space, admin, kind="HUMAN_APPROVER"), UUID)
    # A limit lowered below what the workspace holds stops nothing already running.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.tenants SET max_agents = 1 WHERE tenant_id = :t"), {"t": tenant}
        )
    assert held(admin_engine, tenant) == 3
    assert create(db, tenant, space, admin) == "PLAN_LIMIT"


def test_ac4_two_creations_race_the_last_allowance_and_one_wins(db, admin_engine):
    """Both creations are held at the same lock and released together, so the race is real
    rather than left to scheduling. A third connection holds the tenant's fence row, which the
    function locks first (0047), and the tenant row the cap check locks, so the creations meet
    whichever of the two serializes them."""
    tenant, space, admin = workspace(admin_engine, 3)
    for _ in range(2):
        assert isinstance(create(db, tenant, space, admin), UUID)
    shared = Database(os.environ["TEST_DATABASE_URL"], pool_size=4, max_overflow=0)
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        holder = admin_engine.connect()
        hold = holder.begin()
        try:
            fenced(holder, tenant)
            holder.execute(
                text(
                    "SELECT 1 FROM execbound.tenant_policy_control WHERE tenant_id = :t FOR UPDATE"
                ),
                {"t": tenant},
            ).one()
            holder.execute(
                text("SELECT 1 FROM execbound.tenants WHERE tenant_id = :t FOR NO KEY UPDATE"),
                {"t": tenant},
            ).one()
            futures = [pool.submit(create, shared, tenant, space, admin) for _ in range(2)]
            waiting(admin_engine, "admin_create_principal", 2)
        finally:
            hold.rollback()
            holder.close()
        # Each creation runs under the runtime's own lock and statement timeouts, so neither
        # can outlive this.
        outcomes = [future.result(timeout=60) for future in futures]
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        shared.close()
    assert sorted(isinstance(outcome, UUID) for outcome in outcomes) == [False, True]
    assert "PLAN_LIMIT" in outcomes
    assert held(admin_engine, tenant) == 3


def test_ac5_a_negative_limit_is_refused_by_the_schema(admin_engine):
    with pytest.raises(IntegrityError, match="tenants_max_agents"):
        workspace(admin_engine, -1)


def test_ac12_the_runtime_reads_the_limit_and_holds_nothing_that_writes_it(db, admin_engine):
    """The runtime reads `max_agents` through the table-wide SELECT that `0001_foundation`
    granted on `tenants`, which covers a column added later, and holds nothing that writes it:
    no core path sets a limit, and `check_runtime` refuses any INSERT or UPDATE on `tenants`.
    A column-level grant here would have to change with the `check_runtime` catalog."""
    tenant, _, _ = workspace(admin_engine, 4)
    with db.transaction(tenant) as conn:
        check_runtime(conn)
        assert (
            conn.execute(
                text("SELECT max_agents FROM execbound.tenants WHERE tenant_id = :t"),
                {"t": tenant},
            ).scalar_one()
            == 4
        )
    with admin_engine.connect() as conn:
        held = dict(
            conn.execute(
                text(
                    "SELECT p, has_column_privilege('execbound_app', "
                    "'execbound.tenants'::regclass, 'max_agents', p) "
                    "FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p"
                )
            ).all()
        )
        column_grants = conn.execute(
            text(
                "SELECT count(*) FROM pg_attribute WHERE attrelid = 'execbound.tenants'::regclass "
                "AND attnum > 0 AND attacl IS NOT NULL"
            )
        ).scalar_one()
    assert held == {"SELECT": True, "INSERT": False, "UPDATE": False, "REFERENCES": False}
    assert column_grants == 0
    with pytest.raises(ProgrammingError, match="permission denied"):
        with db.transaction(tenant) as conn:
            conn.execute(
                text("UPDATE execbound.tenants SET max_agents = 9 WHERE tenant_id = :t"),
                {"t": tenant},
            )


def test_ac9_nothing_on_the_request_path_reads_the_agent_limit():
    """The limit is administrative (T5.20): a module that takes, decides or dispatches a
    request never names it, checked as source text so a new reference fails here.

    The walk covers where a request enters (`surfaces.http`, `surfaces.mcp`, the Arcade hooks
    in `execbound.arcade`), who makes it (`identity`, `runtime`), what it is (`requests`), how
    it is resolved, decided and executed (every module of `execbound.resolution`,
    `execbound.policy` and `execbound.execution`), how it reaches a provider (every module of
    `execbound.provider`), and how a person decides it (`surfaces.console_api.approvals`,
    `surfaces.human`). `db.py` is not walked, though `check_runtime` runs on the request path:
    its `SCHEMA_REVISION` was `0066_max_agents` when this was written, the migration's name,
    not a read of the limit."""
    import importlib
    import pkgutil
    from pathlib import Path

    import execbound.arcade
    import execbound.execution
    import execbound.identity
    import execbound.policy
    import execbound.provider
    import execbound.requests
    import execbound.resolution
    import execbound.runtime
    import execbound.surfaces.console_api.approvals
    import execbound.surfaces.http
    import execbound.surfaces.human
    import execbound.surfaces.mcp

    modules = [
        execbound.requests,
        execbound.identity,
        execbound.runtime,
        execbound.surfaces.http,
        execbound.surfaces.mcp,
        execbound.surfaces.console_api.approvals,
        execbound.surfaces.human,
    ]
    for package in (
        execbound.execution,
        execbound.policy,
        execbound.resolution,
        execbound.arcade,
        execbound.provider,
    ):
        modules.append(package)
        for info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            modules.append(importlib.import_module(info.name))
    for module in modules:
        source = Path(module.__file__).read_text(encoding="utf-8")
        for name in ("max_agents", "agent_capacity", "execbound.capacity"):
            assert name not in source, (module.__name__, name)


def test_ac10_core_reads_the_limit_and_no_plan(db, admin_engine):
    import importlib

    from execbound.capacity import agent_capacity

    tenant, space, admin = workspace(admin_engine, 2)
    first = create(db, tenant, space, admin)
    with db.transaction(tenant) as conn:
        capacity = agent_capacity(conn, tenant)
    assert (capacity.agent_limit, capacity.agents_held, capacity.agents_dormant) == (2, 1, 0)
    # It counts what the cap counts: a sleeping agent is held, and one a person switched off
    # by hand is not, the same rows as this file's own `held` reads.
    second = create(db, tenant, space, admin)
    assert call(db, tenant, DEACTIVATE, {"a": admin, "p": second, "r": "by hand"}) == "ok"
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, dormant_at = now() "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": first},
        )
    with db.transaction(tenant) as conn:
        capacity = agent_capacity(conn, tenant)
    assert capacity.agents_held == held(admin_engine, tenant) == 1
    assert capacity.agents_dormant == 1
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("execbound.plans")
    assert not hasattr(importlib.import_module("execbound.administration"), "plan_summary")


def test_ac13_the_scheduler_principal_is_never_counted(db, admin_engine):
    """A workspace's scheduler (#540), the `SYSTEM` principal its scheduled jobs act as, is
    not an agent: the capacity leaves it out exactly as the cap does, so the count a page shows
    and the refusal agree on a workspace whose scheduled jobs have run."""
    from execbound.capacity import AgentCapacity, agent_capacity

    tenant, space, admin = workspace(admin_engine, 1)
    with db.transaction(tenant) as conn:
        made = conn.execute(text("SELECT execbound.scheduler_actor()")).scalar_one()
    assert made["created"] is True
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        kinds = conn.execute(
            text(
                "SELECT kind, active FROM execbound.principals WHERE tenant_id = :t ORDER BY kind"
            ),
            {"t": tenant},
        ).all()
    assert [tuple(row) for row in kinds] == [("ADMIN", True), ("SYSTEM", True)]
    with db.transaction(tenant) as conn:
        assert agent_capacity(conn, tenant) == AgentCapacity(1, 0, 0)
    # The cap leaves it out too: the one allowance is still free, and then it is taken.
    assert isinstance(create(db, tenant, space, admin), UUID)
    with db.transaction(tenant) as conn:
        assert agent_capacity(conn, tenant) == AgentCapacity(1, 1, 0)
    assert create(db, tenant, space, admin) == "PLAN_LIMIT"
