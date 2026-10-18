# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0029's correlation table on real PostgreSQL: AL26.

The Arcade carrier's rows are written here through the runtime connection rather than the
owner's, because what this file is about is the privilege the migration grants: the
extension inserts a row before it calls the kernel, completes it with the kernel's answer,
and moves a bounded set of columns afterwards. A row written over the owner connection
would prove nothing about any of that.

These rows are written directly rather than through the extension, so the executions they
correlate are produced by the routes that produce them — a grant settled by an
executor-signed record, one settled by the bare word, an unreported grant, a platform-stated
failure and the correction of one.
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from arcade_fixtures import CORRECTIONS, correct, stated_failure
from checkpoint_fixtures import checkpoint, impact_rows, scoped, settled_gate_world
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_checkpoint_schema import (
    assert_frozen_bytes,
    assert_schema_intact,
    migration_config,
    retained_frozen_bytes,
    revision,
)
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world

from execbound.db import TABLES, UPDATE_COLUMNS, check_runtime
from execbound.replay.export import export_history
from execbound.replay.ledger import Ledger
from execbound.replay.simulate import simulate
from execbound.replay.verify import verify_export

pytestmark = pytest.mark.integration

# 0029's parent: the walk this file drives down and back is one revision long, because the
# correlation table and the new settled state are the one revision's two halves.
PREVIOUS = "0028_onboarding"
REPORTED_FAILURE = "FAILED_EFFECT_UNKNOWN"
CORRELATION_HELD = "arcade correlation row is retained"
REPORTED_FAILURE_HELD = "reported failure is retained"
# A report secret as `ReportSecret` admits one. The correlation row holds a usable one at
# rest until something clears it, which is the trust boundary this carrier introduces.
SECRET = "Yy7_e3PsBqR-2nVtKcLdW1xZaHgJfMnOpQrStUvWxYz"
INSERT = (
    "INSERT INTO execbound.arcade_hooks "
    "(tenant_id, arcade_execution_id, principal_id, idempotency_key, toolkit, tool_name, "
    "tool_version, reported_metadata, reported_user_id, created_at) "
    "VALUES (:t, :a, :p, :a, 'endpoint_mock', 'ContainDevice', '1.0', CAST(:m AS jsonb), "
    ":u, now())"
)
METADATA = json.dumps({"behavior": {"destructive": True, "read_only": False}})
# What the runtime may not move once the row exists: its tenant and principal, the Arcade
# execution it correlates, the key that reached admission, the tool the platform named,
# what the platform said about that tool, the end user it attributed the call to, and when
# the row was opened.
FIXED = (
    "tenant_id = tenant_id",
    "arcade_execution_id = 'other'",
    "principal_id = principal_id",
    "idempotency_key = 'other'",
    "toolkit = 'gmail'",
    "tool_name = 'SendEmail'",
    "tool_version = '2.0'",
    "reported_metadata = '{}'::jsonb",
    "reported_user_id = 'someone-else'",
    "created_at = now()",
)


def open_row(conn, tenant, principal, arcade_id, *, user_id="user-1"):
    """One correlation row as the pre path opens it: the hook body's facts and nothing else.

    No decision, no execution, no operation and no secret, because the kernel has not been
    called yet. That is also the shape a crash between the kernel's commit and the
    correlation write leaves behind.
    """
    conn.execute(
        text(INSERT),
        {"t": tenant, "a": arcade_id, "p": principal, "m": METADATA, "u": user_id},
    )


def complete_row(conn, tenant, arcade_id, assignments, parameters=None):
    """The writes that follow the insert: the kernel's answer, then the platform's report."""
    updated = conn.execute(
        text(
            f"UPDATE execbound.arcade_hooks SET {assignments} "
            "WHERE tenant_id = :t AND arcade_execution_id = :a"
        ),
        {"t": tenant, "a": arcade_id, **(parameters or {})},
    ).rowcount
    assert updated == 1


def hook_rows(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT arcade_execution_id, decision, execution_id, report_secret, "
                    "reported_success, settled_at, denial_contradiction_at, "
                    "inputs_contradiction_at FROM execbound.arcade_hooks "
                    "WHERE tenant_id = :t ORDER BY arcade_execution_id"
                ),
                {"t": tenant},
            ).mappings()
        ]


def assert_downgrade_refused(db, engine, tenant, match):
    """One refused walk down from the head, and the schema afterwards.

    The upgrade in `finally` is what `test_checkpoint_schema`'s twin leaves out, and it is
    for the mutation sweep rather than for the passing run: a refused walk rolls back and
    leaves the head where it is, so the upgrade is a no-op, while a guard removed lets the
    walk succeed and every later test in the file would otherwise run against a downgraded
    schema instead of this assertion failing on its own.
    """
    try:
        with pytest.raises(RuntimeError, match=match):
            command.downgrade(migration_config(), PREVIOUS)
    finally:
        command.upgrade(migration_config(), "head")
    assert_schema_intact(db, engine, tenant)


def test_al26_the_downgrade_refuses_while_a_correlation_row_alone_is_retained(
    db, seeded, admin_engine
):
    """The correlation guard with nothing standing behind it.

    The round trip below retains a settled statement as well, so the state guard would
    refuse that walk even with this one deleted; here the tenant holds one correlation row
    and no execution at all, so this refusal is the only thing between the walk and a
    dropped table.
    """
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    with db.transaction(tenant) as conn:
        open_row(conn, tenant, principal, "arcade-exec-1")
    assert_downgrade_refused(db, admin_engine, tenant, CORRELATION_HELD)
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        assert conn.execute(text("DELETE FROM execbound.arcade_hooks")).rowcount == 1
    config = migration_config()
    try:
        command.downgrade(config, PREVIOUS)
        assert revision(admin_engine) == PREVIOUS
        with admin_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('execbound.arcade_hooks')")).scalar_one()
                is None
            )
    finally:
        command.upgrade(config, "head")
    assert_schema_intact(db, admin_engine, tenant)


def test_al26_the_runtime_catalog_names_the_correlation_table_and_its_bounded_update(db, seeded):
    assert "arcade_hooks" in TABLES
    # The pre path completes the row with the kernel's answer, the post path records what
    # the platform reported and the two contradiction marks, and settlement and the
    # opportunistic clearing null the secret. Everything the hook body carried at the
    # insert is outside the set.
    assert UPDATE_COLUMNS["arcade_hooks"] == {
        "decision",
        "execution_id",
        "operation_id",
        "report_secret",
        "reported_success",
        "reported_code",
        "reported_error",
        "denial_contradiction_at",
        "inputs_contradiction_at",
        "settled_at",
    }
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)


def test_al26_the_correlation_key_is_the_project_and_not_the_tenant(db, seeded, admin_engine):
    """One Arcade execution id, two projects of one tenant: two rows and no collision.

    `arcade_execution_id` is Arcade's own string and one Arcade project is one ExecBound
    principal, so two projects of a tenant can choose the same one with no misbehaviour from
    either. The key is `(tenant_id, principal_id, arcade_execution_id)` — `execution_keys`'
    own scope with Arcade's id in the place of the derived key — so each project opens a row
    of its own, and a redelivery **within** one project is the duplicate the key refuses.
    Keyed on the tenant alone, the second project inserted nothing and went on to complete,
    decide and read the first project's row.
    """
    tenant, first = seeded["tenants"][0], seeded["principals"][0]
    second = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, space_id) "
                "VALUES (:t, :p, 'AGENT', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "p": second},
        )
    with db.transaction(tenant) as conn:
        open_row(conn, tenant, first, "arcade-exec-1")
        open_row(conn, tenant, second, "arcade-exec-1")
    # Within one project the id is unique, which is what the store's own
    # `ON CONFLICT DO NOTHING` turns a redelivery into. Inserted bare, it is refused.
    with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
        open_row(conn, tenant, first, "arcade-exec-1")
    with db.transaction(tenant) as conn:
        held = (
            conn.execute(
                text(
                    "SELECT principal_id FROM execbound.arcade_hooks "
                    "WHERE tenant_id = :t AND arcade_execution_id = 'arcade-exec-1' "
                    "ORDER BY principal_id"
                ),
                {"t": tenant},
            )
            .scalars()
            .all()
        )
    assert held == sorted([first, second])


def test_al26_the_runtime_writes_a_correlation_row_and_settles_it(db, seeded):
    """Three writes the extension makes, over the privilege the migration grants."""
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    with db.transaction(tenant) as conn:
        open_row(conn, tenant, principal, "arcade-exec-1")
        complete_row(
            conn,
            tenant,
            "arcade-exec-1",
            "decision = 'OK', operation_id = gen_random_uuid(), report_secret = :s",
            {"s": SECRET},
        )
        complete_row(
            conn,
            tenant,
            "arcade-exec-1",
            "reported_success = false, reported_code = 'tool_error', "
            "reported_error = 'the device was not reachable', settled_at = now(), "
            "report_secret = NULL",
        )
    with db.transaction(tenant) as conn:
        row = conn.execute(text("SELECT * FROM execbound.arcade_hooks")).mappings().one()
    assert (row["decision"], row["reported_success"], row["report_secret"]) == ("OK", False, None)
    assert row["idempotency_key"] == "arcade-exec-1"
    assert row["reported_metadata"] == {"behavior": {"destructive": True, "read_only": False}}


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM execbound.arcade_hooks",
        "TRUNCATE execbound.arcade_hooks",
        *(f"UPDATE execbound.arcade_hooks SET {assignment}" for assignment in FIXED),
    ],
)
def test_al26_the_runtime_cannot_delete_or_move_what_the_insert_wrote(db, seeded, statement):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    with db.transaction(tenant) as conn:
        open_row(conn, tenant, principal, "arcade-exec-1")
    with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
        conn.execute(text(statement))
    # The row the runtime could neither remove nor rewrite is still there, and still says
    # what the hook said.
    with db.transaction(tenant) as conn:
        assert (
            conn.execute(text("SELECT toolkit FROM execbound.arcade_hooks")).scalar_one()
            == "endpoint_mock"
        )


def test_al26_the_correlation_table_forces_rls_and_excludes_the_api_roles(admin_engine):
    """Forced for the owner too, and revoked from PUBLIC and the three Supabase API roles.

    `check_runtime` reads the two flags but nothing about who else holds a privilege, so
    the grantee half is asserted here and not inherited from the catalog.
    """
    with admin_engine.connect() as conn:
        flags = (
            conn.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE relnamespace = 'execbound'::regnamespace AND relname = 'arcade_hooks'"
                )
            )
            .mappings()
            .one()
        )
        assert (flags["relrowsecurity"], flags["relforcerowsecurity"]) == (True, True)
        assert (
            conn.execute(
                text("""
                SELECT acl.grantee FROM pg_class c
                CROSS JOIN LATERAL aclexplode(c.relacl) acl
                WHERE c.relnamespace = 'execbound'::regnamespace
                  AND c.relname = 'arcade_hooks'
                  AND (acl.grantee = 0 OR acl.grantee IN (
                      SELECT oid FROM pg_roles
                      WHERE rolname IN ('anon', 'authenticated', 'service_role')
                  ))
            """)
            ).all()
            == []
        )


def test_al26_each_tenant_reads_only_its_own_correlation_rows(db, seeded, admin_engine):
    """The policy body, which `check_runtime` never reads: it inspects the flags alone.

    A `tenant_isolation` policy with a widened USING clause would leave every flag the
    catalog checks exactly where it is, so nothing in `check_runtime` would notice.
    """
    first, second = seeded["tenants"]
    principals = dict(zip(seeded["tenants"], seeded["principals"], strict=True))
    for index, tenant in enumerate(seeded["tenants"]):
        with db.transaction(tenant) as conn:
            open_row(conn, tenant, principals[tenant], f"arcade-exec-{index}")
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.arcade_hooks")).scalar_one() == 2
    for index, tenant in enumerate(seeded["tenants"]):
        other = second if tenant == first else first
        with db.transaction(tenant) as conn:
            rows = (
                conn.execute(
                    text("SELECT tenant_id, arcade_execution_id FROM execbound.arcade_hooks")
                )
                .mappings()
                .all()
            )
            assert [(row["tenant_id"], row["arcade_execution_id"]) for row in rows] == [
                (tenant, f"arcade-exec-{index}")
            ]
            # Naming the other tenant explicitly fails the same way, so a widened USING
            # clause cannot hide behind a query that never asked for the foreign row.
            assert (
                conn.execute(
                    text("SELECT count(*) FROM execbound.arcade_hooks WHERE tenant_id = :o"),
                    {"o": other},
                ).scalar_one()
                == 0
            )
            # Nor can it be written across the fence: the policy's WITH CHECK refuses the
            # insert the USING clause would otherwise have let it read back.
            with pytest.raises(DBAPIError):
                open_row(conn, other, principals[other], "arcade-exec-foreign")


def test_al26_a_round_trip_with_a_correlation_row_of_each_kind_and_a_corrected_execution(
    db, gate_world, admin_engine
):
    """The guarded round trip: six correlation rows, five executions, two refusals.

    The correlation rows are a settled success, a settled reported failure, a live grant
    whose secret is still at rest, a refusal, a row opened and never completed, and one
    carrying both contradiction marks. The executions are an attested settlement, an
    asserted one, an unreported grant, a platform-stated failure and a corrected row —
    whose own state is `FAILED_NOT_EXECUTED` while its retained `execution_events` pair
    names `FAILED_EFFECT_UNKNOWN`, which is the case a check of `executions.state` alone
    would let through.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    principal = world["identity"].principal_id
    settled = settled_gate_world(db, world, admin_engine)
    fourth, fifth = targets(admin_engine, world, count=2)
    stated, _ = stated_failure(db, world, admin_engine, action=fourth)
    corrected, _ = stated_failure(db, world, admin_engine, action=fifth)
    assert correct(db, world, corrected, CORRECTIONS[0][0]).state == "FAILED_NOT_EXECUTED"
    with db.transaction(tenant) as conn:
        for arcade_id in (
            "arc-success",
            "arc-failure",
            "arc-granted",
            "arc-refused",
            "arc-abandoned",
            "arc-contradicted",
        ):
            open_row(conn, tenant, principal, arcade_id)
        # Settled by the platform's word that the call succeeded: the secret was nulled at
        # settlement, which is where the stored life of a reported grant's secret ends.
        complete_row(
            conn,
            tenant,
            "arc-success",
            "decision = 'OK', execution_id = :e, reported_success = true, settled_at = now()",
            {"e": settled.asserted},
        )
        complete_row(
            conn,
            tenant,
            "arc-failure",
            "decision = 'OK', execution_id = :e, reported_success = false, "
            "reported_code = 'tool_error', settled_at = now()",
            {"e": stated},
        )
        # A grant answered OK that nothing has reported, so its secret is still at rest:
        # the exposure limitation 8 states, retained here so the downgrade meets one.
        complete_row(
            conn,
            tenant,
            "arc-granted",
            "decision = 'OK', execution_id = :e, report_secret = :s",
            {"e": settled.unreported, "s": SECRET},
        )
        # A refusal reaches no execution worth naming and holds no secret.
        complete_row(conn, tenant, "arc-refused", "decision = 'CHECK_FAILED'")
        complete_row(
            conn,
            tenant,
            "arc-contradicted",
            "decision = 'OK', execution_id = :e, denial_contradiction_at = now(), "
            "inputs_contradiction_at = now()",
            {"e": corrected},
        )
    rows = hook_rows(admin_engine, tenant)
    assert [row["arcade_execution_id"] for row in rows] == [
        "arc-abandoned",
        "arc-contradicted",
        "arc-failure",
        "arc-granted",
        "arc-refused",
        "arc-success",
    ]
    assert [row["decision"] for row in rows] == [None, "OK", "OK", "OK", "CHECK_FAILED", "OK"]
    assert [row["report_secret"] for row in rows] == [None, None, None, SECRET, None, None]
    assert [row["execution_id"] is None for row in rows] == [
        True,
        False,
        False,
        False,
        True,
        False,
    ]
    assert_schema_intact(db, admin_engine, tenant)
    frozen = retained_frozen_bytes()
    assert_frozen_bytes(frozen)
    # 0028 has nowhere to put a correlation row, so the table refuses to be dropped while
    # one is retained, above the state guard below it.
    assert_downgrade_refused(db, admin_engine, tenant, CORRELATION_HELD)
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        assert conn.execute(text("DELETE FROM execbound.arcade_hooks")).rowcount == 6
    # With the correlation gone, the settled statement still refuses: its own state holds
    # the value the ten-member constraint has no room for.
    assert_downgrade_refused(db, admin_engine, tenant, REPORTED_FAILURE_HELD)
    assert correct(db, world, stated, CORRECTIONS[1][0]).state == "STALE_AUTHORIZATION"
    with admin_engine.begin() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.executions WHERE state = :s"),
                {"s": REPORTED_FAILURE},
            ).scalar_one()
            == 0
        )
    # And with no `executions` row left in that state, the retained transitions of the two
    # corrected rows are what refuse it.
    assert_downgrade_refused(db, admin_engine, tenant, REPORTED_FAILURE_HELD)
    with admin_engine.begin() as conn:
        events = conn.execute(
            text(
                "DELETE FROM execbound.execution_events "
                "WHERE tenant_id = :t AND (from_state = :s OR to_state = :s) "
                "RETURNING execution_id"
            ),
            {"t": tenant, "s": REPORTED_FAILURE},
        ).scalars()
        assert sorted(events) == sorted([stated, stated, corrected, corrected])
    config = migration_config()
    try:
        command.downgrade(config, PREVIOUS)
        assert revision(admin_engine) == PREVIOUS
        with admin_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('execbound.arcade_hooks')")).scalar_one()
                is None
            )
            # The state vocabulary is back to the ten 0019 left, on all three columns.
            constraints = conn.execute(
                text(
                    "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname IN ('executions_state_check', "
                    "'execution_events_from_state_check', 'execution_events_to_state_check')"
                )
            ).all()
            assert len(constraints) == 3
            assert not any(REPORTED_FAILURE in definition for _, definition in constraints)
        # The executions themselves survive: what the guards protect is the correlation and
        # the vocabulary, not the history either belongs to.
        with admin_engine.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM execbound.executions WHERE tenant_id = :t"),
                    {"t": tenant},
                ).scalar_one()
                == 5
            )
    finally:
        command.upgrade(config, "head")
    assert_schema_intact(db, admin_engine, tenant)
    assert_frozen_bytes(frozen)
    with db.transaction(tenant) as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.arcade_hooks")).scalar_one() == 0


def test_al26_an_export_charges_a_stated_failure_and_reconstructs_its_correction(
    db, gate_world, admin_engine
):
    """The replay clause: what an offline reader makes of the two settlements.

    A stated failure confirms the impact, because charging for an action that may have
    happened is the safe direction; the correction of one writes the non-execution, and
    `Ledger.settle` refuses that move, so `Ledger.correct` is what reaches `NONEXECUTION`
    over a confirmed unit. Both are read back through the counts the replay recomputed for
    a later decision, which is the ledger's reconstruction rather than a column the export
    copied.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    first, second, third = targets(admin_engine, world, count=3)
    stated, _ = stated_failure(db, world, admin_engine, action=first)
    corrected, _ = stated_failure(db, world, admin_engine, action=second)
    assert correct(db, world, corrected, CORRECTIONS[0][0]).state == "FAILED_NOT_EXECUTED"
    probe = checkpoint(db, world, action=third).view
    assert {row["execution_id"]: row["state"] for row in impact_rows(admin_engine, tenant)} == {
        stated: "CONFIRMED",
        corrected: "NONEXECUTION",
        probe.execution_id: "UNRESOLVED",
    }
    history = export_history(db, world["admin"], world["clock"])
    replayed = simulate(verify_export(history, history.head))
    assert replayed.complete, replayed.issues
    rows = {item.execution_id: item for item in replayed.decisions}
    assert all(item.baseline.effect == item.recorded_effect for item in replayed.decisions)
    # Settled, and reported as what settled them rather than as unresolved or uncertain.
    assert (rows[stated].baseline.outcome, rows[stated].settlement_tier) == (
        REPORTED_FAILURE,
        "ASSERTED",
    )
    assert (rows[corrected].baseline.outcome, rows[corrected].settlement_tier) == (
        "FAILED_NOT_EXECUTED",
        "ATTESTED",
    )
    # The probe was decided after both settled, so its recomputed counts are the ledger's
    # answer: the stated failure is charged and the corrected one is not counted at all.
    counts = {item.rule_id: item for item in rows[probe.execution_id].baseline.counts}
    assert (
        counts["tenant-total-isolation"].confirmed_targets,
        counts["tenant-total-isolation"].unresolved_targets,
    ) == (1, 0)


def test_al26_the_replay_correction_admits_a_confirmed_unit_once(db, seeded):
    """`Ledger.correct` is the narrow method the export's refund bound rests on.

    `settle` is left exactly as narrow as it is, so a widened correction is what an export
    would need to claim a refund the kernel never wrote. It takes a CONFIRMED unit and
    writes NONEXECUTION with no confirmation time; a state that is not CONFIRMED, a unit it
    does not hold, a backward clock and a second call are each refused below.
    """
    tenant, principal, execution = seeded["tenants"][0], seeded["principals"][0], uuid4()
    now = datetime.now(UTC)
    attributes = {"account_id": uuid4(), "facts": {}, "groups": ()}

    def reserved():
        ledger = Ledger(tenant)
        ledger.reserve(execution, principal, "endpoint.isolate", uuid4(), False, now, **attributes)
        return ledger

    unresolved = reserved()
    with pytest.raises(ValueError, match="Invalid replay correction"):
        unresolved.correct(execution, now)
    assert unresolved.impacts[execution].state == "UNRESOLVED"
    missing = reserved()
    with pytest.raises(ValueError, match="Invalid replay correction"):
        missing.correct(uuid4(), now)
    early = reserved()
    early.settle(execution, True, now)
    with pytest.raises(ValueError, match="Invalid replay correction"):
        early.correct(execution, now - timedelta(seconds=1))
    refunded = reserved()
    refunded.settle(execution, False, now)
    with pytest.raises(ValueError, match="Invalid replay correction"):
        refunded.correct(execution, now)
    ledger = reserved()
    ledger.settle(execution, True, now)
    assert ledger.impacts[execution].confirmed_at == now
    ledger.correct(execution, now)
    assert ledger.impacts[execution].state == "NONEXECUTION"
    assert ledger.impacts[execution].confirmed_at is None
    with pytest.raises(ValueError, match="Invalid replay correction"):
        ledger.correct(execution, now)
    assert ledger.impacts[execution].state == "NONEXECUTION"
