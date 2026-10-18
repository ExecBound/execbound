# SPDX-License-Identifier: AGPL-3.0-only
"""The scheduled pass's actor (#503): the scheduled check, enlistment, SJ8 at the application,
and SJ9's pin of the call sites that may accept a `ScheduledActor`.
"""

import ast
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from console_api_fixtures import API, console_client
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import administration
from execbound.administration import AdministrationError
from execbound.execution import scheduled, store
from execbound.execution.models import ExecutionError
from execbound.execution.scheduled import ScheduledActor, enlist, scheduled_check, tenant_active
from execbound.resolution.models import SystemClock

pytestmark = pytest.mark.integration


def fenced(conn, tenant):
    # Limits nothing on an `admin_engine` connection, whose owner bypasses row security
    # (see tenant_fence).
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def scheduler_created(engine, tenant):
    with engine.begin() as conn:
        fenced(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT actor_id FROM execbound.audit_events WHERE tenant_id = :t "
                    "AND kind = 'principal.created' AND payload ->> 'kind' = 'SYSTEM'"
                ),
                {"t": tenant},
            )
            .scalars()
            .all()
        )


def test_identity_check_refuses_a_scheduled_actor(db, seeded):
    tenant = seeded["tenants"][0]
    # The last is a lookalike whose kind is ADMIN: only the check that it is an `Identity`
    # refuses it, where the kind comparison would let it through to the credential lookup.
    for actor, kind in (
        (ScheduledActor(tenant), "ADMIN"),
        (ScheduledActor(tenant), "SYSTEM"),
        (ScheduledActor(tenant, uuid4(), "ADMIN"), "ADMIN"),
    ):
        with pytest.raises(ExecutionError) as refused:
            with db.transaction(tenant) as conn:
                store.identity_check(conn, actor, SystemClock(), kind)
        assert refused.value.code == "INVALID_IDENTITY"


def test_the_scheduled_check_admits_an_active_workspace_and_only_its_own_scheduler(
    db, admin_engine, seeded
):
    tenant, other = seeded["tenants"]
    clock = SystemClock()
    assert tenant_active(db, tenant)
    actor = enlist(db, ScheduledActor(tenant), clock)
    assert actor.principal_id is not None
    assert enlist(db, actor, clock) == actor
    assert enlist(db, ScheduledActor(tenant), clock) == actor
    with db.transaction(tenant) as conn:
        scheduled_check(conn, actor)
    theirs = enlist(db, ScheduledActor(other), clock)
    for stranger in (
        ScheduledActor(tenant, uuid4()),
        ScheduledActor(tenant, seeded["principals"][0]),
        ScheduledActor(tenant, theirs.principal_id),
    ):
        with pytest.raises(ExecutionError) as refused:
            with db.transaction(tenant) as conn:
                scheduled_check(conn, stranger)
        assert refused.value.code == "INVALID_IDENTITY"
    # Made once, and recorded once, by the scheduler itself.
    assert scheduler_created(admin_engine, tenant) == [actor.principal_id]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"), {"t": tenant}
        )
    assert not tenant_active(db, tenant)
    with pytest.raises(ExecutionError) as inactive:
        with db.transaction(tenant) as conn:
            scheduled_check(conn, actor)
    assert inactive.value.code == "INVALID_IDENTITY"


def test_enlistment_refuses_an_inactive_workspace(db, admin_engine, seeded):
    tenant = seeded["tenants"][1]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"), {"t": tenant}
        )
    with pytest.raises(ExecutionError) as refused:
        enlist(db, ScheduledActor(tenant), SystemClock())
    assert refused.value.code == "INVALID_IDENTITY"
    assert scheduler_created(admin_engine, tenant) == []


def test_enlistment_maps_the_databases_own_refusal_of_an_inactive_workspace(
    db, admin_engine, seeded, monkeypatch
):
    """A workspace deactivated between the check and `scheduler_actor`: the function's own
    INVALID_TENANT is the same refusal as the check's, not the database being unavailable."""
    tenant = seeded["tenants"][1]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"), {"t": tenant}
        )
    monkeypatch.setattr(scheduled, "scheduled_check", lambda conn, actor: None)
    with pytest.raises(ExecutionError) as refused:
        enlist(db, ScheduledActor(tenant), SystemClock())
    assert refused.value.code == "INVALID_IDENTITY"
    assert scheduler_created(admin_engine, tenant) == []


def test_the_scheduled_check_is_bound_to_the_transactions_own_fence(db, admin_engine, seeded):
    """The owner here is a superuser, which bypasses row security: only the check's own
    comparison with the fence refuses an actor for another workspace."""
    tenant, other = seeded["tenants"]
    enlisted = enlist(db, ScheduledActor(tenant), SystemClock())
    for actor in (ScheduledActor(tenant), enlisted):
        with pytest.raises(ExecutionError) as refused:
            with admin_engine.begin() as conn:
                fenced(conn, other)
                scheduled_check(conn, actor)
        assert refused.value.code == "INVALID_IDENTITY"
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        scheduled_check(conn, enlisted)


def test_sj8_the_owner_cli_and_the_console_refuse_the_scheduler_principal(
    db, runtime, admin_engine, world, tmp_path
):
    tenant = world["identity"].tenant_id
    system = enlist(db, ScheduledActor(tenant), SystemClock()).principal_id
    with pytest.raises(AdministrationError) as cli:
        administration.issue_credential(
            admin_engine,
            tenant,
            system,
            world["admin"].principal_id,
            lifetime=timedelta(hours=1),
            output=tmp_path / "never.token",
        )
    assert cli.value.code == "INVALID_PRINCIPAL"
    assert not (tmp_path / "never.token").exists()
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(API + "/credentials")
        assert page.status_code == 200, page.text
        assert str(system) not in {row["principal_id"] for row in page.json()["principals"]}
        issued = client.post(
            API + "/credentials/issue", {"principal": str(system), "lifetime": "8"}
        )
        assert issued.status_code == 400, issued.text
        assert issued.json()["code"] == "INVALID_PRINCIPAL"
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        held = conn.execute(
            text("SELECT count(*) FROM execbound.credentials WHERE principal_id = :p"),
            {"p": system},
        ).scalar_one()
    assert held == 0


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT execbound.admin_issue_credential(:a, :p, :c, :h, now(), now() + interval '1 hour')",
        "SELECT execbound.admin_label_principal(:a, :p, 'Me')",
        "SELECT execbound.admin_deactivate_principal(:a, :p, 'Testing the guard')",
    ],
)
def test_sj8_each_administration_function_refuses_the_scheduler_principal(db, world, statement):
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    system = enlist(db, ScheduledActor(tenant), SystemClock()).principal_id
    with pytest.raises(DBAPIError) as refused:
        with db.transaction(tenant) as conn:
            conn.execute(text(statement), {"a": actor, "p": system, "c": uuid4(), "h": "b" * 64})
    assert "SYSTEM_PRINCIPAL" in str(refused.value.orig)


def test_sj8_every_console_list_answers_with_the_scheduler_present(
    db, runtime, admin_engine, world
):
    """The console's lists enumerate principals; one that met a kind it does not know would
    fail the whole page, as the API Keys page did before `credentials_overview` filtered it."""
    from execbound.surfaces.console_api import console_api_document

    system = enlist(db, ScheduledActor(world["identity"].tenant_id), SystemClock()).principal_id
    paths = [
        path
        for path, item in console_api_document()["paths"].items()
        if "get" in item and "{" not in path and not path.endswith("/stream")
    ]
    assert len(paths) > 20
    refused = set()
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        for path in paths:
            answered = client.get(path)
            assert answered.status_code < 500, (path, answered.text)
            assert "ExecBound scheduler" not in answered.text, path
            # Some lists show a principal's id without its label.
            assert str(system) not in answered.text, path
            if answered.status_code != 200:
                refused.add((path.removeprefix(API), answered.status_code))
    # The lists that do not answer this client at all, each for its own reason and none for
    # the scheduler principal's: the workspace switcher needs an account's sign-in, not a
    # credential's; this console enables no assistant; search needs a query; and the demo
    # configuration answers only while the workspace's sample targets are present and the
    # demo can run on them, and this workspace has added none. The sandbox downloads and the
    # invitation pool are areas a plugin adds (#496), so core's document does not list them.
    # A list missing here has started answering, and one added has stopped, so neither
    # passes unnoticed.
    assert refused == {
        ("/session/workspaces", 401),
        ("/assistant/turns", 404),
        ("/assistant/settings", 404),
        ("/search", 400),
        ("/samples/demo-configuration", 404),
    }


def test_sj8_reactivation_never_reaches_the_scheduler_principal(db, admin_engine, world):
    """`admin_reactivate_principal` updates only an inactive row and otherwise refuses with
    INVALID_STATE, so the scheduler principal is made inactive first, past its own guard, for
    the reactivation to reach `principals_system_frozen` at all."""
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    system = enlist(db, ScheduledActor(tenant), SystemClock()).principal_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("ALTER TABLE execbound.principals DISABLE TRIGGER principals_system_frozen")
        )
        conn.execute(
            text("UPDATE execbound.principals SET active = false WHERE principal_id = :p"),
            {"p": system},
        )
        conn.execute(
            text("ALTER TABLE execbound.principals ENABLE TRIGGER principals_system_frozen")
        )
    with pytest.raises(DBAPIError) as refused:
        with db.transaction(tenant) as conn:
            conn.execute(
                text("SELECT execbound.admin_reactivate_principal(:a, :p)"),
                {"a": actor, "p": system},
            )
    assert "SYSTEM_PRINCIPAL" in str(refused.value.orig)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        row = conn.execute(
            text("SELECT kind, active FROM execbound.principals WHERE principal_id = :p"),
            {"p": system},
        ).one()
    assert tuple(row) == ("SYSTEM", False)


NAMES = {"ScheduledActor", "RecoveryActor", "actor_check", "scheduled_check"}

# Every function in src/ that names the scheduled actor or its checks, in an annotation, a
# call or a construction (#503). A new one fails this test until someone decides
# it may accept an actor with no credential.
PINNED = {
    "execbound/execution/scheduled.py": {
        "scheduled_check",
        "actor_check",
        "tenant_active",
        "enlist",
    },
    "execbound/execution/authority.py": {"_rejection", "_still", "_stale"},
    "execbound/provider/gateway.py": {"reconcile_operation"},
    "execbound/execution/reconciliation.py": {"reconcile"},
    "execbound/recovery_run.py": {
        "select_unsettled",
        "select_held_claims",
        "select_lapsed_approvals",
        "expire_approval",
        "sweep_grant",
        "release_claim",
        "_attempted",
        "_current",
        "recover",
        "recover_scheduled",
    },
    "execbound/notifications.py": {
        "_admin",
        "deliver_pending",
        "settle_orphaned",
        "notify_scheduled",
    },
    "execbound/assistant/turns.py": {"retire_due_turns"},
    # Scheduled monitoring collection (#678): the actor check, every step a collection run
    # takes (each writes inside the run's lease and refuses a scheduled actor without one),
    # the two runs, and the lease's own claim and release.
    "execbound/monitoring/store.py": {
        "_check_actor",
        "load_connection",
        "record_capabilities",
        "apply_inventory",
        "reconcile_coverage",
        "ingest_collected_page",
        "apply_agents",
        "apply_agent_detail",
        "evaluate_agents",
        "record_run_outcome",
        # A delta pass between full collections (#355): what the store holds of the principals
        # it lists, its changes and its link, each inside the run's lease.
        "held_agents",
        "apply_agent_changes",
        "record_delta",
        # What a run reads of the directory's audit log, and the episode a run that does not
        # read it ends, inside the run's lease (#355).
        "apply_directory_audit",
        "end_audit_episode",
        # The scheduled evaluation, which appends no event and writes no principal, and its last
        # step, the purge of the directory audit observations no rule reads any more, one batch
        # of it a transaction (#355).
        "evaluate_pending",
        "evaluate_health",
        "derive_reach",
        "evaluate_actions",
        "purge_audit_observations",
        "_purge_batch",
    },
    # The scheduled evaluation, and findings delivery's router and drain (#31), which append no
    # event.
    "execbound/monitoring/worker.py": {
        "evaluate_scheduled",
        "route_findings",
        "deliver_findings",
        "deliver_scheduled",
    },
    "execbound/monitoring/collection.py": {"run", "_collect_audit"},
    # A run's read of the directory's service principal sign-ins (#355), which writes only
    # through the three driver steps below, each inside the run's lease.
    "execbound/monitoring/graph.py": {"run", "run_delta", "collect_audit", "collect_sign_ins"},
    # Driver evidence (#355): the Space's recorded egress and the sign-in cursor read beside it,
    # the declared rows derived from what the store holds, and the sign-in matches written. Each
    # takes `store._check_actor` with `collecting=True`, so a scheduled actor without the run's
    # lease is refused, and locks the connection under that lease.
    "execbound/monitoring/drivers.py": {"space_egress", "derive_declared", "apply_sign_ins"},
    "execbound/monitoring/due.py": {
        "claim",
        "claim_delta",
        "release",
        "claim_and_run",
        # `collect-due`: one workspace's due connections, the pass over every workspace, and
        # the read of a connection's credential under the run's lease, which writes nothing.
        "collect_workspace",
        "collect_due",
        "_credential",
        # `collector-reseal`: one workspace's sealed keys moved to a new collector key, and the
        # pass over every workspace. Neither appends an event or writes a principal.
        "reseal_workspace",
        "reseal_due",
    },
}


def _names(node: ast.AST) -> set[str]:
    """Every name a function uses in code or annotations. Docstrings are not scanned, so a
    function may mention the scheduled actor in prose without being pinned; none of the pinned
    modules writes these names as string annotations."""
    found = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.add(child.id)
        elif isinstance(child, ast.Attribute):
            found.add(child.attr)
    return found


def test_sj9_only_the_pinned_functions_accept_a_scheduled_actor():
    """A review tripwire, not the enforcement. It reads names, so it cannot see an actor
    reached another way: through a name bound outside any function, a `getattr`, or a
    parameter whose annotation does not name it. What refuses a scheduled actor that reaches
    any other check is `store.identity_check`, which admits only an `Identity`
    (`test_identity_check_refuses_a_scheduled_actor`)."""
    # Resolved from this file, so the scan never depends on where pytest was started.
    root = Path(__file__).resolve().parents[1] / "src"
    found: dict[str, set[str]] = {}
    aliased: list[str] = []
    for path in root.rglob("*.py"):
        relative = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                # An alias hides every use of the name from `_names`, so none is allowed.
                aliased += [
                    f"{relative}: {alias.name} as {alias.asname}"
                    for alias in node.names
                    if alias.name in NAMES and alias.asname is not None
                ]
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and NAMES & _names(node):
                found.setdefault(relative, set()).add(node.name)
    assert aliased == []
    assert found == PINNED
