# SPDX-License-Identifier: AGPL-3.0-only
"""Migrations 0025 and 0026: the executor key table, the settlement columns, the revocation
reason that cuts a compromised key off, both guarded downgrades, and GC17's round trip."""

import hashlib
import json
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from arcade_fixtures import CORRECTIONS, correct, stated_failure
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from checkpoint_fixtures import settled_gate_world
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_execution_database import execution_storage as execution_storage

from execbound.audit import canonical_json
from execbound.db import SCHEMA_REVISION, TABLES, UPDATE_COLUMNS, check_runtime
from execbound.execution.models import DispatchCommand
from execbound.policy.models import BundleContent
from execbound.provider.models import provider_command
from execbound.resolution.models import plan_hash

pytestmark = pytest.mark.integration

PREVIOUS = "0024_monitor_rls_initplan"
CHECKPOINT = "0025_checkpoint"
# The state 0028 admits, and what its downgrade says while any of the three constrained
# columns still holds it anywhere in the database.
REPORTED_FAILURE = "FAILED_EFFECT_UNKNOWN"
REPORTED_FAILURE_HELD = "reported failure is retained"
PUBLIC_KEY = "a1" * 32
KEY_INSERT = (
    "INSERT INTO execbound.executor_keys (tenant_id, key_id, algorithm, public_key, created_at) "
    "VALUES (:t, 'executor-v1', 'ED25519', :k, now())"
)
# Exactly the raw 32 bytes of an Ed25519 public key, lowercase hex and nothing else.
CANDIDATES = [
    (PUBLIC_KEY, True),
    ("a" * 63, False),
    ("a" * 65, False),
    ("A1" * 32, False),
    ("z" + "a" * 63, False),
    ("", False),
    (PUBLIC_KEY + "\n", False),
]
FIXTURES = Path(__file__).parent / "fixtures"
IDENTITY_CONTRACT = json.loads((FIXTURES / "identity-contract-v1.json").read_text("utf-8"))
UNFORCED = (
    "SELECT count(*) FROM pg_class WHERE relnamespace='execbound'::regnamespace "
    "AND relkind='r' AND relname<>'alembic_version' "
    "AND (NOT relrowsecurity OR NOT relforcerowsecurity)"
)


def migration_config():
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    return config


def revision(engine):
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()


def assert_schema_intact(db, engine, tenant):
    assert revision(engine) == SCHEMA_REVISION
    with engine.connect() as conn:
        assert conn.execute(text(UNFORCED)).scalar_one() == 0
    with db.transaction(tenant) as conn:
        check_runtime(conn)


def assert_downgrade_refused(db, engine, tenant, match="executor keys or checkpoints"):
    """One refused walk down from the head, and the schema afterwards.

    The message is a parameter because the walk passes through more than one guarded
    revision and the first to refuse decides which one is raised: 0028's reported-failure
    clause stands above 0025's, so a tenant holding the new state anywhere never reaches
    the key-ring and checkpoint guard below it.
    """
    with pytest.raises(RuntimeError, match=match):
        command.downgrade(migration_config(), PREVIOUS)
    assert_schema_intact(db, engine, tenant)


def test_runtime_catalog_includes_executor_keys_and_settlement_columns(db, seeded):
    assert "executor_keys" in TABLES
    # The tier is the only new projection column; the report window is written once at
    # admission, so no grant lets the runtime move a deadline it is already past.
    assert "settlement_tier" in UPDATE_COLUMNS["executions"]
    assert "report_expires_at" not in UPDATE_COLUMNS["executions"]
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO execbound.executor_keys "
        "(tenant_id, key_id, algorithm, public_key, created_at) "
        "VALUES (:t, 'forged', 'ED25519', :k, now())",
        "UPDATE execbound.executor_keys SET public_key = :k",
        "UPDATE execbound.executor_keys SET revoked_at = NULL",
        # The reason is what the verifier reads to refuse a compromised key outright, so
        # the runtime being unable to write it is the same statement as the rest.
        "UPDATE execbound.executor_keys SET revocation_reason = 'RETIRED'",
        "DELETE FROM execbound.executor_keys",
    ],
)
def test_runtime_cannot_write_executor_keys(db, seeded, admin_engine, statement):
    tenant = seeded["tenants"][0]
    with admin_engine.begin() as conn:
        conn.execute(text(KEY_INSERT), {"t": tenant, "k": PUBLIC_KEY})
    with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
        conn.execute(text(statement), {"t": tenant, "k": "b2" * 32})
    # The key the runtime could not rewrite is still readable, which is all it needs.
    with db.transaction(tenant) as conn:
        assert (
            conn.execute(text("SELECT public_key FROM execbound.executor_keys")).scalar_one()
            == PUBLIC_KEY
        )


def test_each_tenant_reads_only_its_own_executor_key(db, seeded, admin_engine):
    """The policy body, which check_runtime never reads: only the flags are in the catalog."""
    first, second = seeded["tenants"]
    keys = {first: PUBLIC_KEY, second: "b2" * 32}
    with admin_engine.begin() as conn:
        for index, (tenant, key) in enumerate(keys.items()):
            conn.execute(
                text(
                    "INSERT INTO execbound.executor_keys "
                    "(tenant_id, key_id, algorithm, public_key, created_at) "
                    "VALUES (:t, :i, 'ED25519', :k, now())"
                ),
                {"t": tenant, "i": f"executor-v{index}", "k": key},
            )
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.executor_keys")).scalar_one() == 2
    for tenant, key in keys.items():
        other = second if tenant == first else first
        with db.transaction(tenant) as conn:
            rows = (
                conn.execute(text("SELECT tenant_id, public_key FROM execbound.executor_keys"))
                .mappings()
                .all()
            )
            assert [(row["tenant_id"], row["public_key"]) for row in rows] == [(tenant, key)]
            # Naming the other tenant explicitly fails the same way, so a widened USING
            # clause cannot hide behind a query that never asked for the foreign row.
            assert (
                conn.execute(
                    text("SELECT count(*) FROM execbound.executor_keys WHERE tenant_id = :o"),
                    {"o": other},
                ).scalar_one()
                == 0
            )


@pytest.mark.parametrize(("candidate", "accepted"), CANDIDATES)
def test_public_key_admits_only_thirty_two_lowercase_hex_bytes(
    seeded, admin_engine, candidate, accepted
):
    """PostgreSQL validates the pattern at insert, not at definition, so each form is tried."""
    tenant = seeded["tenants"][0]
    if not accepted:
        with pytest.raises(DBAPIError), admin_engine.begin() as conn:
            conn.execute(text(KEY_INSERT), {"t": tenant, "k": candidate})
        return
    with admin_engine.begin() as conn:
        conn.execute(text(KEY_INSERT), {"t": tenant, "k": candidate})
    with admin_engine.connect() as conn:
        assert (
            conn.execute(text("SELECT public_key FROM execbound.executor_keys")).scalar_one()
            == candidate
        )


@pytest.mark.parametrize(
    ("revoked_at", "reason", "accepted"),
    [
        ("NULL", "NULL", True),
        ("now()", "'RETIRED'", True),
        ("now()", "'COMPROMISED'", True),
        # A revocation with no reason would be weighed as an ordinary retirement, which is
        # the permissive answer, and a reason with no revocation would claim a key is cut
        # off while it is still live. Both are refused by the column rather than by the
        # writers alone, so no future statement can leave one of them behind.
        ("now()", "NULL", False),
        ("NULL", "'RETIRED'", False),
        ("NULL", "'COMPROMISED'", False),
        ("now()", "'ROTATED'", False),
        ("now()", "'compromised'", False),
    ],
)
def test_a_revocation_carries_exactly_one_of_the_two_reasons(
    seeded, admin_engine, revoked_at, reason, accepted
):
    """PostgreSQL validates a CHECK at insert, not at definition, so each form is tried."""
    tenant = seeded["tenants"][0]
    statement = text(
        "INSERT INTO execbound.executor_keys "
        "(tenant_id, key_id, algorithm, public_key, created_at, revoked_at, revocation_reason) "
        f"VALUES (:t, 'executor-v1', 'ED25519', :k, now(), {revoked_at}, {reason})"
    )
    if not accepted:
        with pytest.raises(DBAPIError), admin_engine.begin() as conn:
            conn.execute(statement, {"t": tenant, "k": PUBLIC_KEY})
        return
    with admin_engine.begin() as conn:
        conn.execute(statement, {"t": tenant, "k": PUBLIC_KEY})
    with admin_engine.connect() as conn:
        assert conn.execute(
            text("SELECT revocation_reason FROM execbound.executor_keys")
        ).scalar_one() == (None if reason == "NULL" else reason.strip("'"))


def test_downgrade_refuses_while_a_compromised_key_is_retained(db, seeded, admin_engine):
    """0025 has no way to say a key was cut off, and every revocation it can express is
    backward-permissive, so dropping the column would hand a stolen key back its authority
    over every grant it covered. A retirement carries no such meaning and downgrades."""
    tenant = seeded["tenants"][0]
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.executor_keys "
                "(tenant_id, key_id, algorithm, public_key, created_at, "
                "revoked_at, revocation_reason) "
                "VALUES (:t, 'executor-v1', 'ED25519', :k, now(), now(), 'COMPROMISED')"
            ),
            {"t": tenant, "k": PUBLIC_KEY},
        )
    with pytest.raises(RuntimeError, match="compromised executor key"):
        command.downgrade(migration_config(), CHECKPOINT)
    assert_schema_intact(db, admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.executor_keys SET revocation_reason = 'RETIRED'"))
    config = migration_config()
    try:
        command.downgrade(config, CHECKPOINT)
        assert revision(admin_engine) == CHECKPOINT
        with admin_engine.connect() as conn:
            columns = conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='execbound' AND table_name='executor_keys'"
                )
            ).scalars()
            assert "revocation_reason" not in columns.all()
            # The key itself survives the downgrade, and 0026 reads its revocation as the
            # ordinary retirement it is: the backfill is what makes the round trip lossless.
            assert (
                conn.execute(text("SELECT count(*) FROM execbound.executor_keys")).scalar_one() == 1
            )
    finally:
        command.upgrade(config, "head")
    assert_schema_intact(db, admin_engine, tenant)
    with admin_engine.connect() as conn:
        assert (
            conn.execute(text("SELECT revocation_reason FROM execbound.executor_keys")).scalar_one()
            == "RETIRED"
        )


def test_downgrade_refuses_while_a_key_or_a_checkpoint_is_retained(
    db, seeded, admin_engine, execution_storage
):
    tenant = seeded["tenants"][0]
    with admin_engine.begin() as conn:
        conn.execute(text(KEY_INSERT), {"t": tenant, "k": PUBLIC_KEY})
    assert_downgrade_refused(db, admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM execbound.executor_keys"))
    # Only the two tiers exist, so a settled row can never lose its evidence class to a typo.
    with pytest.raises(DBAPIError), admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.executions SET settlement_tier = 'TRUSTED'"))
    for assignment in ("settlement_tier = 'ASSERTED'", "report_expires_at = now()"):
        with admin_engine.begin() as conn:
            conn.execute(
                text(f"UPDATE execbound.executions SET {assignment} WHERE tenant_id = :t"),
                {"t": tenant},
            )
        assert_downgrade_refused(db, admin_engine, tenant)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.executions "
                    "SET settlement_tier = NULL, report_expires_at = NULL"
                )
            )
    config = migration_config()
    try:
        command.downgrade(config, PREVIOUS)
        assert revision(admin_engine) == PREVIOUS
        with admin_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('execbound.executor_keys')")).scalar_one()
                is None
            )
            columns = conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='execbound' AND table_name='executions'"
                )
            ).scalars()
            assert {"settlement_tier", "report_expires_at"}.isdisjoint(columns.all())
    finally:
        command.upgrade(config, "head")
    assert_schema_intact(db, admin_engine, tenant)


# GC17: the migration round trip with a settled checkpoint of each tier and an unreported
# grant retained. The rows the guards are read against are produced by the routes that
# produce them — an executor-signed record, the executor's bare word, and a grant nobody
# reported — rather than written over the owner connection, because what the downgrade
# must refuse is the evidence a real deployment holds.


def retained_frozen_bytes():
    """The identity contract's frozen bytes, recomputed through the models at this revision.

    The serialized form of a released plan, its command and its bundle is what
    `tests/test_identity_compatibility.py` pins; recomputing it here is what says a
    migration in either direction left those bytes alone, and the file digests beside it
    say no fixture was regenerated to make that true.
    """
    bundle = BundleContent.model_validate_json(json.dumps(IDENTITY_CONTRACT["bundle"]))
    disable = IDENTITY_CONTRACT["actions"]["identity.disable"]
    command = DispatchCommand.model_validate_json(json.dumps(disable["dispatch"]))
    return {
        "bundle": (canonical_json(bundle.model_dump(mode="json")), bundle.content_hash),
        "plan": (
            canonical_json(command.frozen.model_dump(mode="json")),
            plan_hash(command.frozen, bundle.security_versions),
        ),
        "command": canonical_json(provider_command(command).model_dump(mode="json")),
        "files": {
            name: hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
            for name in (
                "endpoint-contract-v1.json",
                "identity-contract-v1.json",
                "context-contracts-v1-parity.json",
            )
        },
    }


def assert_frozen_bytes(expected):
    recomputed = retained_frozen_bytes()
    assert recomputed == expected
    disable = IDENTITY_CONTRACT["actions"]["identity.disable"]
    assert recomputed["bundle"] == (
        IDENTITY_CONTRACT["bundle_canonical"],
        IDENTITY_CONTRACT["bundle_hash"],
    )
    assert recomputed["plan"][0] == disable["resolved_canonical"]
    assert recomputed["command"] == disable["command_canonical"]


def test_gc17_a_round_trip_with_a_settled_checkpoint_of_each_tier_and_an_unreported_grant(
    db, gate_world, admin_engine
):
    """The round trip, extended past the point where it could not fail.

    As written it round-tripped a tenant holding no row in the state 0028 admits, so that
    revision's downgrade guard had nothing to refuse and the walk would have succeeded with
    the guard deleted. Two rows are added for it: a settled statement, which
    `executions.state` itself holds, and a corrected row, whose own state is one 0027
    already admits and which leaves the new state in its retained `execution_events` pair —
    the case a guard reading `executions` would let through. The refusal is asserted for
    each, the second time with the statement corrected too, so that no `executions` row
    holds the value anywhere and the event rows are what refuse.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    settled = settled_gate_world(db, world, admin_engine)
    fourth, fifth = targets(admin_engine, world, count=2)
    stated, _ = stated_failure(db, world, admin_engine, action=fourth)
    corrected, _ = stated_failure(db, world, admin_engine, action=fifth)
    assert correct(db, world, corrected, CORRECTIONS[0][0]).state == "FAILED_NOT_EXECUTED"
    assert_schema_intact(db, admin_engine, tenant)
    frozen = retained_frozen_bytes()
    assert_frozen_bytes(frozen)
    # The settled statement refuses the walk at its head, above the key ring and the tiers.
    assert_downgrade_refused(db, admin_engine, tenant, match=REPORTED_FAILURE_HELD)
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
    # corrected rows still refuse it.
    assert_downgrade_refused(db, admin_engine, tenant, match=REPORTED_FAILURE_HELD)
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
    # Each of the three retained things refuses the downgrade on its own, in turn: the
    # tenant's key ring, the tiers its settlements wrote, and the report windows its
    # grants carry, the unreported one included.
    assert_downgrade_refused(db, admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM execbound.executor_keys"))
    assert_downgrade_refused(db, admin_engine, tenant)
    with admin_engine.begin() as conn:
        tiers = conn.execute(
            text(
                "UPDATE execbound.executions SET settlement_tier = NULL "
                "WHERE tenant_id = :t AND settlement_tier IS NOT NULL RETURNING execution_id"
            ),
            {"t": tenant},
        ).scalars()
        assert sorted(tiers) == sorted([settled.attested, settled.asserted, stated, corrected])
    assert_downgrade_refused(db, admin_engine, tenant)
    with admin_engine.begin() as conn:
        windows = conn.execute(
            text(
                "UPDATE execbound.executions SET report_expires_at = NULL "
                "WHERE tenant_id = :t AND report_expires_at IS NOT NULL RETURNING execution_id"
            ),
            {"t": tenant},
        ).scalars()
        assert set(windows) == {
            settled.attested,
            settled.asserted,
            settled.unreported,
            stated,
            corrected,
        }
    config = migration_config()
    try:
        command.downgrade(config, PREVIOUS)
        assert revision(admin_engine) == PREVIOUS
        with admin_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('execbound.executor_keys')")).scalar_one()
                is None
            )
        # The executions themselves survive the downgrade: what the guards protect is the
        # evidence a checkpoint added, not the history it belongs to.
        with admin_engine.connect() as conn:
            kept = conn.execute(
                text("SELECT count(*) FROM execbound.executions WHERE tenant_id = :t"),
                {"t": tenant},
            ).scalar_one()
        assert kept == 5
    finally:
        command.upgrade(config, "head")
    assert_schema_intact(db, admin_engine, tenant)
    assert_frozen_bytes(frozen)
