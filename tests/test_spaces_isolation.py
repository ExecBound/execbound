# SPDX-License-Identifier: AGPL-3.0-only
"""SP1 and SP2: nothing of another space is returned, for every space-carrying table.

**Forced row-level security does not catch a missing space predicate.** A store function
that forgets its tenant predicate returns nothing because the database refuses it; one
that forgets its space predicate returns another customer's rows, and there is no second
line (docs/THREAT_MODEL.md T2.9, residual risk R25). The tables `0041_spaces.py` gave a space
are parametrized over the migration's own list and read through the one helper's predicate.
Every table that carries a space is then read from the **catalog**, and each one has to be in
that list, name the negative tests that read a row of another space through its own readers,
or say why its space is not a customer's row: a table given a space by a later migration
fails here until it does one of the three.
"""

import ast
import importlib.util
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from console_api_fixtures import API, console_client
from space_fixtures import default_space, make_space, seat, unseat
from sqlalchemy import text
from test_approval_group_rules import remove_individual_scope, rule, setup_group
from test_console_api_approvals import detail
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_human_surface import pending
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError
from execbound.spaces import Visibility, set_current_space, space_clause, visible_spaces
from execbound.surfaces import dashboard, human
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration


def load_migration():
    path = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0041_spaces.py"
    spec = importlib.util.spec_from_file_location("spaces_migration_isolation", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MIGRATION = load_migration()
OWNED_TABLES = MIGRATION.OWNED_TABLES
# The primary key each table is addressed by, for the fixture that plants one row in the
# second space. Every owned table appears, so a table added to the migration's list
# without a key here fails this file rather than skipping its case.
KEYS = {
    "connector_accounts": "account_id",
    "policy_bundle_contents": "bundle_id",
    "approval_scopes": "approver_id",
    "executions": "execution_id",
    "approvals": "approval_id",
    "execution_impact": "execution_id",
    "monitor_sources": "source_id",
    "monitor_connections": "connection_id",
    "monitor_observations": "observation_id",
    "monitor_findings": "finding_id",
}


# Every table of the schema that carries a space: a `space_id` column, or a foreign key into
# `spaces` under any column name. Read from the catalog, so a table given a space by any later
# migration is in this set whether or not anybody remembered this file.
SPACE_CARRYING = """
SELECT c.relname FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'execbound' AND c.relkind IN ('r', 'p') AND (
    EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid = c.oid
            AND a.attname = 'space_id' AND a.attnum > 0 AND NOT a.attisdropped)
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conrelid = c.oid
               AND k.contype = 'f' AND k.confrelid = 'execbound.spaces'::regclass))
ORDER BY c.relname
"""


# The tables given a space after 0041, or not counted among its owned tables, whose rows a
# reader of another space must not reach. The helper's cases above do not cover them, so each
# names the negative tests that plant a row in another space and read it through the table's
# own readers, every one a test node this check resolves. These tests hold the readers they
# name, not every reader a table has: R25 says which readers are not held.
READER_CASES: dict[str, tuple[str, ...]] = {
    # 0047. A role's space bounds what it grants; a null space is Workspace scope.
    "access_role_grants": (
        "tests/test_spaces_isolation.py::test_a_role_granted_in_another_space_reaches_nothing_in_this_one",
        "tests/test_access_read_spaces.py::test_a_group_role_only_widens_reads_in_its_assigned_space",
        "tests/test_access_control.py::test_policy_manager_lifecycle_is_bound_to_authorized_space",
    ),
    # 0048. A rule routes review in its own space; its space is never null.
    "approval_rules": (
        "tests/test_spaces_isolation.py::test_a_review_rule_in_another_space_routes_nothing_in_this_one",
        "tests/test_approval_notification_spaces.py::test_another_spaces_group_neither_receives_nor_counts_for_this_approval",
    ),
    # 0068. A source applies in its own space, or in every space once offered tenant-wide, and
    # the pages name it by its label to the readers of those spaces alone.
    "signal_sources": (
        "tests/test_signal_resolution.py::test_a_source_of_another_space_does_not_apply_unless_offered",
        "tests/test_signal_resolution.py::test_the_statement_never_reads_a_source_of_another_space",
        "tests/test_signal_bundle_validation.py::test_a_source_of_another_space_is_refused_unless_offered",
        "tests/test_signal_bundle_validation.py::test_activation_in_another_space_needs_a_source_that_space_can_use",
        "tests/test_signal_views.py::test_a_label_of_another_spaces_source_is_withheld_from_a_reader_of_this_one",
    ),
    # 0041, beside its owned tables: an agent's space, null for a person. Admission reads it
    # from the agent's own row, and an agent of another space reaches nothing that space owns.
    # The credentials page lists another space's agent and keys to no administrator of it,
    # and the console's agent routes answer 404 for it before any change runs.
    "principals": (
        "tests/test_spaces_kernel.py::test_sp5_a_mapping_on_another_spaces_account_is_refused_before_any_provider_contact",
        "tests/test_action_listing.py::test_la6_what_a_space_lists_follows_the_space_and_what_it_is_offered",
        "tests/test_spaces_credentials.py::test_sp15_the_credentials_page_lists_a_space_administrator_their_own_spaces_agents_alone",
        "tests/test_spaces_credentials.py::test_sp15_the_console_api_refuses_and_hides_another_spaces_agent",
        "tests/test_spaces_principals.py::test_sp16_the_console_api_answers_404_for_another_spaces_agent",
    ),
    # 0041: the bundle each space selects; an agent is admitted under its own space's alone.
    "space_policy_selection": (
        "tests/test_spaces_kernel.py::test_sp6_each_space_is_admitted_under_its_own_selection",
        "tests/test_spaces_kernel.py::test_sp6_a_space_with_no_selection_fails_closed",
    ),
}
# The tables whose space is not a row a customer owns, with what it is instead.
NOT_OWNED: dict[str, str] = {
    "spaces": "The space itself. Which spaces a person reads is `visible_spaces`, the visible "
    "set every case in this file reads.",
    "space_members": "The membership `visible_spaces` computes the visible set from; the SP2 "
    "cases seat and unseat a person.",
    "human_sessions": "A session's current space, which is a view and never an owner: "
    "`visible_spaces` narrows it to the visible set on every read.",
    "audit_events": "The space an event concerns, or null: an attribution beside the chain, "
    "never the owner of a row, which 0041 left out of its owned tables.",
    "monitor_connect_attempts": "The space a Microsoft Entra consent attempt will create its "
    "connection in (0088). An attempt is read only by the principal who started it (their "
    "latest, `consent.last_attempt`) and by Microsoft's callbacks through its own state, never "
    "listed or read by space; the connection it creates is a `monitor_connections` row, which "
    "holds to that table's cases.",
}


def defined(node: str) -> bool:
    """Whether a `tests/<file>::<name>` names a test function that file defines."""
    module, _, name = node.partition("::")
    path = Path(__file__).resolve().parents[1] / module
    if not path.is_file():
        return False
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(isinstance(item, ast.FunctionDef) and item.name == name for item in tree.body)


def test_every_space_carrying_table_has_a_case(admin_engine):
    """The catalog's list, not a copy that can drift from it: a table given a space by a
    later migration fails here until it names the case that keeps another space's rows out,
    or why its space owns nothing.
    """
    with admin_engine.connect() as conn:
        catalog = set(conn.execute(text(SPACE_CARRYING)).scalars())
    assert set(KEYS) == set(OWNED_TABLES)
    classified = (set(KEYS), set(READER_CASES), set(NOT_OWNED))
    assert sum(len(group) for group in classified) == len(set().union(*classified))
    assert catalog == set().union(*classified)
    for table, nodes in READER_CASES.items():
        assert nodes, table
        for node in nodes:
            assert defined(node), (table, node)
    assert all(reason.strip() for reason in NOT_OWNED.values())


def session_for(db, identity, clock=None):
    """A session on the test's own clock, so `check_session` reads the same instant the
    surfaces read; a session issued on the wall clock is a second in the future to them."""
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


@pytest.fixture
def two_spaces(db, runtime, admin_engine, world):
    """The tenant's default space, a second one, and one row of every owned table in it.

    Every table gets a real row rather than a skipped case: the execution, its approval
    and its impact come from one admission carried to a decision, and the four monitoring
    tables are seeded directly. A row is then placed in the second space on the owner
    connection; production has no path that moves a row between spaces, so this exists to
    build a fixture and nowhere else.
    """
    tenant = world["identity"].tenant_id
    admitted = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], admitted.view.approval_id, "APPROVE", world["clock"])
    admit(db, world["identity"], request(world), world["clock"])
    planted: dict[str, UUID] = {}
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer B")
        seed_monitoring(conn, tenant, first, world["admin"].principal_id)
        for table in OWNED_TABLES:
            key = KEYS[table]
            row = conn.execute(
                text(  # nosec B608 - the table and its key are this file's own literals
                    f"SELECT {key} FROM execbound.{table} WHERE tenant_id=:t ORDER BY {key} LIMIT 1"
                ),
                {"t": tenant},
            ).scalar_one_or_none()
            assert row is not None, f"no seeded row in {table}"
            conn.execute(
                text(  # nosec B608 - the table and its key are this file's own literals
                    f"UPDATE execbound.{table} SET space_id=:s WHERE tenant_id=:t AND {key}=:i"
                ),
                {"t": tenant, "s": second, "i": row},
            )
            planted[table] = row
    return {"tenant": tenant, "first": first, "second": second, "planted": planted}


def seed_monitoring(conn, tenant: UUID, space: UUID, actor: UUID) -> None:
    """One row in each of the four monitoring tables, so no case is ever skipped."""
    source, connection, observation, finding = (uuid4() for _ in range(4))
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_sources (tenant_id, source_id, label, story_id, "
            "token_hash, created_at, expires_at, heartbeat_seconds, rate_window_at, space_id) "
            "VALUES (:t, :s, 'Fixture source', 'story-1', repeat('0', 64), now(), "
            "now() + interval '1 day', 300, now(), :space)"
        ),
        {"t": tenant, "s": source, "space": space},
    )
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, label, "
            "base_url, key_fingerprint, created_at, created_by, space_id) "
            "VALUES (:t, :c, 'Fixture connection', 'https://fixture.tines.com', "
            "repeat('0', 64), now(), :by, :space)"
        ),
        {"t": tenant, "c": connection, "by": actor, "space": space},
    )
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_observations (tenant_id, observation_id, source_id, "
            "event_id, story_id, version, occurred_at, received_at, kind, evidence, "
            "content_hash, rule_version, space_id) "
            "VALUES (:t, :o, :s, 'event-1', 'story-1', 1, now(), now(), 'heartbeat', "
            "'reported', repeat('0', 64), 'sensitive-action.v2', :space)"
        ),
        {"t": tenant, "o": observation, "s": source, "space": space},
    )
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_findings (tenant_id, finding_id, source_id, "
            "observation_id, rule_version, title, created_at, space_id) "
            "VALUES (:t, :f, :s, :o, 'sensitive-action.v2', 'Fixture finding', now(), :space)"
        ),
        {"t": tenant, "f": finding, "s": source, "o": observation, "space": space},
    )


def rows_visible(db, tenant, visibility: Visibility, table: str) -> set[UUID]:
    """Every row of one table the helper's predicate admits, and nothing else."""
    key = KEYS[table]
    space = space_clause(visibility, "e")
    with db.transaction(tenant) as conn:
        found = conn.execute(
            text(  # nosec B608 - the table and its key are this file's own literals
                f"SELECT e.{key} FROM execbound.{table} e WHERE e.tenant_id=:t" + space.sql
            ),
            {"t": tenant, **space.params},
        ).scalars()
        return set(found)


@pytest.mark.parametrize("table", OWNED_TABLES)
def test_sp1_a_member_of_one_space_reads_nothing_of_the_other(db, world, two_spaces, table):
    tenant = two_spaces["tenant"]
    planted = two_spaces["planted"][table]
    approver = session_for(db, world["human"], world["clock"])
    with db.transaction(tenant) as conn:
        member = visible_spaces(conn, approver)
    assert member.spaces == (two_spaces["first"],)
    assert planted not in rows_visible(db, tenant, member, table)


@pytest.mark.parametrize("table", OWNED_TABLES)
def test_sp2_a_member_of_both_spaces_reads_the_union_and_nothing_else(
    db, admin_engine, world, two_spaces, table
):
    tenant = two_spaces["tenant"]
    planted = two_spaces["planted"][table]
    approver = session_for(db, world["human"], world["clock"])
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        seat(conn, tenant, two_spaces["second"], world["human"].principal_id)
    with db.transaction(tenant) as conn:
        member = visible_spaces(conn, approver)
    assert sorted(member.spaces) == sorted((two_spaces["first"], two_spaces["second"]))
    assert planted in rows_visible(db, tenant, member, table)
    # And a person seated in neither reads nothing at all.
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        for space in (two_spaces["first"], two_spaces["second"]):
            unseat(conn, tenant, space, world["human"].principal_id)
    with db.transaction(tenant) as conn:
        nobody = visible_spaces(conn, approver)
    assert rows_visible(db, tenant, nobody, table) == set()


@pytest.mark.parametrize("table", OWNED_TABLES)
def test_sp2_a_tenant_administrator_sees_both(db, world, two_spaces, table):
    tenant = two_spaces["tenant"]
    planted = two_spaces["planted"][table]
    administrator = session_for(db, world["admin"], world["clock"])
    with db.transaction(tenant) as conn:
        everything = visible_spaces(conn, administrator)
    assert everything.everything
    assert planted in rows_visible(db, tenant, everything, table)


def test_sp1_the_activity_read_behind_every_page_drops_the_other_space(
    db, runtime, admin_engine, world, two_spaces
):
    """`records()` is the one read behind Activity, Home, the approval queue, the board
    and the drawer, so a case on it is a case on all five."""
    tenant = two_spaces["tenant"]
    administrator = session_for(db, world["admin"], world["clock"])
    with db.transaction(tenant) as conn:
        set_current_space(conn, administrator, two_spaces["first"])
    moved = two_spaces["planted"]["executions"]
    rows = human.records(runtime, administrator, limit=50)
    assert all(row["execution_id"] != moved for row in rows)
    # And the same administrator looking at the other space sees it and nothing of the first.
    with db.transaction(tenant) as conn:
        set_current_space(conn, administrator, two_spaces["second"])
    other = human.records(runtime, administrator, limit=50)
    assert [row["execution_id"] for row in other] == [moved]


def test_sp1_home_counts_follow_the_space(db, runtime, world, two_spaces):
    tenant = two_spaces["tenant"]
    administrator = session_for(db, world["admin"], world["clock"])
    whole = dashboard.overview(runtime, administrator)
    with db.transaction(tenant) as conn:
        set_current_space(conn, administrator, two_spaces["second"])
    narrowed = dashboard.overview(runtime, administrator)
    assert sum(narrowed["counts"].values()) <= sum(whole["counts"].values())


def test_sp8_the_canonical_target_claim_stays_tenant_wide(db, admin_engine, world, two_spaces):
    """One claim per tenant and target, named as a cross-space channel rather than closed. A
    claim held in one space refuses the other's execution on the same canonical target with
    today's conflict and nothing about the first on the wire."""
    tenant = two_spaces["tenant"]
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        claims = conn.execute(
            text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_schema='execbound' AND table_name='resource_claims' "
                "AND column_name='space_id'"
            )
        ).scalar_one()
        targets = conn.execute(
            text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_schema='execbound' AND table_name='canonical_targets' "
                "AND column_name='space_id'"
            )
        ).scalar_one()
    assert (claims, targets) == (0, 0)


def test_an_unknown_space_in_a_visible_set_matches_nothing(db, world, two_spaces):
    """A forged set is still only a `WHERE` clause over this tenant's own rows."""
    tenant = two_spaces["tenant"]
    forged = Visibility(everything=False, spaces=(uuid4(),), current=None, roles={})
    for table in OWNED_TABLES:
        assert rows_visible(db, tenant, forged, table) == set()


def test_a_role_granted_in_another_space_reaches_nothing_in_this_one(
    db, runtime, admin_engine, world
):
    """`access_role_grants` (0047). A role's space is where it reaches, and nowhere else.

    An approver role granted in the second space opens neither the queue, the approval, the
    Activity record, Home's count nor the decision of an approval in the first, and the person's
    visible set names the second space alone. The same grant in the approval's own space, and
    with no space at all (Workspace scope, which the grant's null means), opens all of them,
    so what refused it was the space and nothing else.
    """
    tenant = world["identity"].tenant_id
    reviewer = world["human"]
    view = pending(runtime, world)
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer B")

    def grant(space: UUID | None) -> None:
        with console_client(db, runtime, admin_engine, world["admin"]) as client:
            response = client.post(
                API + f"/access/users/{reviewer.principal_id}/roles",
                {
                    "grants": [{"role": "approver", "space_id": space and str(space)}],
                    "reason": "Route this person's reviews",
                },
            )
            assert response.status_code == 200, response.text

    # One signed-in console and one session for the whole test: a role of the same kind
    # changes what they reach and ends neither.
    session = session_for(db, reviewer, world["clock"])
    with console_client(db, runtime, admin_engine, reviewer) as client:

        def reach() -> tuple[list[str], int, int, set[UUID], Visibility]:
            queue = [item["approval_id"] for item in client.get(API + "/approvals").json()["items"]]
            opened = detail(client, view.approval_id).status_code
            waiting = client.get(API + "/overview").json()["pending_approvals"]
            recorded = {row["execution_id"] for row in human.records(runtime, session)}
            with db.transaction(tenant) as conn:
                seen = visible_spaces(conn, session)
            return queue, opened, waiting, recorded, seen

        grant(second)
        queue, opened, waiting, recorded, seen = reach()
        assert (queue, opened, waiting) == ([], 404, 0)
        assert view.execution_id not in recorded
        assert not seen.everything and seen.spaces == (second,)
        with pytest.raises(ExecutionError) as refused:
            decide_approval(db, reviewer, view.approval_id, "APPROVE", world["clock"])
        assert refused.value.code == "NOT_FOUND"
        for space in (first, None):
            grant(space)
            queue, opened, waiting, recorded, seen = reach()
            assert (queue, opened, waiting) == ([str(view.approval_id)], 200, 1), space
            assert view.execution_id in recorded
            assert seen.everything is (space is None)


def test_a_review_rule_in_another_space_routes_nothing_in_this_one(
    db, runtime, admin_engine, world
):
    """`approval_rules` (0048). A rule routes review in its own space, and nowhere else.

    The reviewer's own assignments are removed and their group holds the approver role at
    Workspace scope, so the rule's space is the only thing that can refuse them. A rule in the
    second space over the very target and action of a pending approval in the first puts it in
    nobody's queue and lets nobody decide it; the same rule moved to the approval's own space
    does both, so the space is what refused it. A rule's space is never null.
    """
    tenant = world["identity"].tenant_id
    remove_individual_scope(admin_engine, world)
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer B")
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        group = setup_group(client, world)
        saved = rule(client, world, group, space_id=str(second))
        assert saved.status_code == 200, saved.text
        rule_id = saved.json()["rule_id"]

    def reach() -> tuple[list[str], int]:
        with console_client(db, runtime, admin_engine, world["human"]) as client:
            queue = [item["approval_id"] for item in client.get(API + "/approvals").json()["items"]]
            return queue, detail(client, view.approval_id).status_code

    assert reach() == ([], 404)
    with pytest.raises(ExecutionError) as refused:
        decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    assert refused.value.code == "NOT_FOUND"
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        moved = client.post(
            API + f"/approval-rules/{rule_id}",
            {
                "name": "Endpoint response",
                "group_id": group,
                "space_id": str(first),
                "actions": ["endpoint.isolate"],
                "targets": [str(world["canonical"])],
                "reason": "Route the first space's requests to the response team",
            },
        )
        assert moved.status_code == 200, moved.text
    assert reach() == ([str(view.approval_id)], 200)
    decided = decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    assert decided.execution_id == view.execution_id
