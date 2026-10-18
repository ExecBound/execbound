# SPDX-License-Identifier: AGPL-3.0-only
"""The signal schema (docs/DATA_MODEL.md): two tables, one fenced writer, SELECT-only runtime."""

import json
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from alembic import command as alembic
from alembic.config import Config
from pydantic import TypeAdapter, ValidationError
from signal_fixtures import ADMIT, admit_params, admit_raw, insert_source, signal_fields
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted

from execbound.db import FUNCTIONS, SCHEMA_REVISION, TABLES, UnsafeDatabaseRole, check_runtime
from execbound.resolution.models import Verdict


def migration_config():
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    return config


ADMIT_ARGUMENTS = (
    "p_source uuid, p_token_hash text, p_now timestamp with time zone, p_event_id text, "
    "p_record_digest text, p_producer_name text, p_producer_version text, p_capability text, "
    "p_verdict text, p_confidence integer, p_severity text, p_subject_kind text, "
    "p_subject_account uuid, p_subject_provider text, p_subject_resource_type text, "
    "p_subject_provider_id text, p_action text, p_request_reference text, "
    "p_observed_at timestamp with time zone, p_expires_at timestamp with time zone, "
    "p_attributes jsonb, p_evidence_ref text, p_evidence_digest text"
)
# The producer token's digests: `signal_admit` takes a digest, so at the database layer a
# digest is the credential, and the runtime never reads one (0042's precedent).
DIGESTS = {"token_hash", "previous_token_hash"}


@pytest.fixture
def registered(seeded, admin_engine):
    """One connector account and one source in the first seeded tenant, written as the owner."""
    tenant, actor = seeded["tenants"][0], seeded["principals"][0]
    now, account = datetime.now(UTC), uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts (tenant_id, account_id, provider, "
                "active, space_id) VALUES (:t, :a, 'mock_crowdstrike', true, :s)"
            ),
            {"t": tenant, "a": account, "s": seeded["spaces"][0]},
        )
        source, token = insert_source(conn, tenant, actor, now)
    return {
        "tenant": tenant,
        "actor": actor,
        "account": account,
        "source": source,
        "token": token,
        "now": now,
    }


def health(admin_engine, registered):
    with admin_engine.begin() as conn:
        fenced(conn, registered["tenant"])
        return dict(
            conn.execute(
                text(
                    "SELECT rate_count, record_count, last_refusal_code, "
                    "(SELECT count(*) FROM execbound.security_signals g "
                    " WHERE g.source_id = s.source_id) AS stored "
                    "FROM execbound.signal_sources s WHERE s.source_id = :s"
                ),
                {"s": registered["source"]},
            )
            .mappings()
            .one()
        )


def test_the_catalog_names_both_tables_and_the_one_writer(db, seeded):
    assert {"signal_sources", "security_signals"} <= set(TABLES)
    assert ("signal_admit", ADMIT_ARGUMENTS) in FUNCTIONS
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)


def test_the_writer_is_a_pinned_definer_only_the_runtime_calls(admin_engine):
    with admin_engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT has_function_privilege('execbound_app', p.oid, 'EXECUTE') AS runtime, "
                    "has_function_privilege('public', p.oid, 'EXECUTE') AS public, "
                    "p.prosecdef, p.proconfig FROM pg_proc p "
                    "WHERE p.pronamespace = 'execbound'::regnamespace "
                    "AND p.proname = 'signal_admit'"
                )
            )
            .mappings()
            .one()
        )
    assert (row["runtime"], row["public"], row["prosecdef"]) == (True, False, True)
    assert row["proconfig"] == ["search_path=pg_catalog, pg_temp"]


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO execbound.security_signals (tenant_id) VALUES (:t)",
        "UPDATE execbound.signal_sources SET active = false WHERE tenant_id = :t",
        "DELETE FROM execbound.security_signals WHERE tenant_id = :t",
        "UPDATE execbound.signal_sources SET record_count = 0 WHERE tenant_id = :t",
    ],
)
def test_the_runtime_role_cannot_write_either_table(db, seeded, statement):
    with pytest.raises(DBAPIError, match="permission denied"):
        with db.transaction(seeded["tenants"][0]) as conn:
            conn.execute(text(statement), {"t": seeded["tenants"][0]})


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT token_hash FROM execbound.signal_sources",
        "SELECT previous_token_hash FROM execbound.signal_sources",
        "SELECT source_id FROM execbound.signal_sources WHERE token_hash = :h",
        "SELECT * FROM execbound.signal_sources",
    ],
)
def test_the_runtime_never_reads_a_producer_digest(db, registered, statement):
    with pytest.raises(DBAPIError, match="permission denied"):
        with db.transaction(registered["tenant"]) as conn:
            conn.execute(text(statement), {"h": "a" * 64})


def test_the_runtime_reads_every_other_source_column(db, admin_engine, registered):
    with admin_engine.connect() as conn:
        columns = conn.execute(
            text(
                "SELECT a.attname, "
                "has_column_privilege('execbound_app', a.attrelid, a.attnum, 'SELECT') "
                "FROM pg_attribute a "
                "WHERE a.attrelid = 'execbound.signal_sources'::regclass "
                "AND a.attnum > 0 AND NOT a.attisdropped"
            )
        ).all()
        whole = conn.execute(
            text(
                "SELECT has_table_privilege('execbound_app', 'execbound.signal_sources', 'SELECT')"
            )
        ).scalar_one()
    assert whole is False
    readable = {name for name, granted in columns if granted}
    assert DIGESTS <= {name for name, _ in columns}
    assert readable == {name for name, _ in columns} - DIGESTS
    with db.transaction(registered["tenant"]) as conn:
        row = (
            conn.execute(
                text(f"SELECT {', '.join(sorted(readable))} FROM execbound.signal_sources")
            )
            .mappings()
            .one()
        )
    assert row["source_id"] == registered["source"]


SOURCES = "execbound.signal_sources"


@pytest.mark.parametrize("grant", [*(f"SELECT ({name})" for name in sorted(DIGESTS)), "SELECT"])
def test_check_runtime_refuses_a_runtime_that_can_read_a_producer_digest(admin_engine, grant):
    """The column grants 0068 leaves out are checked on every runtime transaction, beside the
    UPDATE columns, so an accidental grant, a table-wide one included, fails closed rather
    than exposing the credential.

    Each grant is made and checked as the runtime role inside one transaction that is rolled
    back, because revoking a table-wide SELECT would also take away 0068's column grants.
    """
    for granted in (False, True):
        with admin_engine.connect() as conn:
            transaction = conn.begin()
            try:
                if granted:
                    conn.execute(text(f"GRANT {grant} ON {SOURCES} TO execbound_app"))
                conn.execute(text("SET LOCAL ROLE execbound_app"))
                if granted:
                    with pytest.raises(UnsafeDatabaseRole, match="column"):
                        check_runtime(conn)
                else:
                    check_runtime(conn)
            finally:
                transaction.rollback()


def test_a_tenant_never_reads_another_tenants_sources(db, seeded, admin_engine):
    now = datetime.now(UTC)
    first, second = seeded["tenants"][:2]
    with admin_engine.begin() as conn:
        fenced(conn, first)
        source, _ = insert_source(conn, first, seeded["principals"][0], now)
    with db.transaction(second) as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.signal_sources")).scalar_one() == 0
    with db.transaction(first) as conn:
        assert (
            conn.execute(text("SELECT source_id FROM execbound.signal_sources")).scalar_one()
            == source
        )


# Stands for the seeded principal in a case below, which is only known inside the test.
ACTOR = object()
WHEN = datetime(2026, 9, 28, tzinfo=UTC)


@pytest.mark.parametrize(
    "changes,constraint",
    [
        ({"principal_ids": None}, "signal_sources_one_scope"),
        ({"principal_ids": []}, "signal_sources_principal_ids_check"),
        (
            {"principal_ids": [str(uuid4()) for _ in range(65)]},
            "signal_sources_principal_ids_check",
        ),
        ({"principal_ids": [str(uuid4()), None]}, "signal_sources_no_null_principal"),
        ({"capabilities": ["content_integrity.v1"]}, "signal_sources_capabilities_check"),
        ({"subject_kinds": ["run"]}, "signal_sources_subject_kinds_check"),
        ({"input_path": "sideways"}, "signal_sources_input_path_check"),
        ({"placement": "in_process"}, "signal_sources_placement_check"),
        (
            {"producer_version_min": "1.0.0", "producer_version_max": "0.9.9"},
            "signal_sources_version_order",
        ),
        ({"token_hash": "not-a-digest"}, "signal_sources_token_hash_check"),
        (
            {"token_hash": "b" * 64, "previous_token_hash": "b" * 64, "previous_valid_until": WHEN},
            "signal_sources_previous_distinct",
        ),
        ({"revoked_at": WHEN, "revoked_by": ACTOR}, "signal_sources_revoked_inactive"),
        ({"rotated_at": WHEN}, "signal_sources_rotation_together"),
    ],
)
def test_the_table_refuses_a_malformed_registration(seeded, admin_engine, changes, constraint):
    now, actor = datetime.now(UTC), seeded["principals"][0]
    changes = {name: actor if value is ACTOR else value for name, value in changes.items()}
    with pytest.raises(IntegrityError, match=f'check constraint "{constraint}"'):
        with admin_engine.begin() as conn:
            fenced(conn, seeded["tenants"][0])
            insert_source(conn, seeded["tenants"][0], actor, now, **changes)


@pytest.mark.parametrize(
    "changes,key",
    [
        ({"rotated_at": WHEN, "rotated_by": uuid4()}, "signal_sources_tenant_id_rotated_by_fkey"),
        (
            {"active": False, "revoked_at": WHEN, "revoked_by": uuid4()},
            "signal_sources_tenant_id_revoked_by_fkey",
        ),
    ],
)
def test_a_rotation_or_revocation_names_a_principal_of_the_tenant(
    seeded, admin_engine, changes, key
):
    now, actor = datetime.now(UTC), seeded["principals"][0]
    with pytest.raises(IntegrityError, match=key):
        with admin_engine.begin() as conn:
            fenced(conn, seeded["tenants"][0])
            insert_source(conn, seeded["tenants"][0], actor, now, **changes)


RECORD = text(
    "INSERT INTO execbound.security_signals (tenant_id, source_id, source_event_id, "
    "record_digest, registration_version, producer_name, producer_version, capability, "
    "verdict, confidence, subject_kind, subject_account_id, subject_provider, "
    "subject_resource_type, subject_provider_id, observed_at, received_at) VALUES (:t, :s, "
    "'device-01:1', :d, 1, 'execbound-mde-producer', '0.1.0', 'resource_compromise.v1', "
    ":v, 1000, 'resource', :a, 'mock_crowdstrike', 'endpoint', 'device-01', :n, :n)"
)


@pytest.mark.parametrize(
    "verdict",
    ["Medium", "M", "No detection", "a" * 64, "a" * 65, " Medium", "Medium ", " ", "", "Médium"],
)
def test_the_verdict_check_is_the_models_pattern(admin_engine, registered, verdict):
    """A row the model would refuse is never stored, and one it accepts always is."""
    try:
        TypeAdapter(Verdict).validate_python(verdict)
    except ValidationError:
        model_accepts = False
    else:
        model_accepts = True
    params = {
        "t": registered["tenant"],
        "s": registered["source"],
        "d": "a" * 64,
        "v": verdict,
        "a": registered["account"],
        "n": registered["now"],
    }
    with admin_engine.begin() as conn:
        fenced(conn, registered["tenant"])
        if model_accepts:
            conn.execute(RECORD, params)
        else:
            with pytest.raises(IntegrityError, match="security_signals_verdict_check"):
                with conn.begin_nested():
                    conn.execute(RECORD, params)


def admit(db, registered, **changes):
    fields = signal_fields(registered["account"], registered["now"], **changes)
    return admit_raw(
        db,
        registered["tenant"],
        registered["source"],
        registered["token"],
        registered["now"],
        **fields,
    )


def test_a_well_formed_record_is_stored(db, admin_engine, registered):
    assert admit(db, registered)["accepted"] is True
    assert health(admin_engine, registered) == {
        "rate_count": 1,
        "record_count": 1,
        "last_refusal_code": None,
        "stored": 1,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"verdict": "Medium "},
        {"verdict": None},
        {"confidence": 1001},
        {"confidence": None},
        {"attributes": [1]},
        {"severity": ""},
        {"subject_resource_type": None},
        {"subject_resource_type": "Endpoint"},
        {"subject_provider_id": ""},
        {"action": "Isolate Now"},
        {"request_reference": ""},
        {"evidence_digest": "short"},
    ],
)
def test_a_field_the_table_refuses_is_a_recorded_refusal(db, admin_engine, registered, changes):
    """Refused, not raised: the rate count and the refusal code commit, and nothing is stored."""
    assert admit(db, registered, **changes) == {"refused": "INVALID_SIGNAL"}
    assert health(admin_engine, registered) == {
        "rate_count": 1,
        "record_count": 0,
        "last_refusal_code": "INVALID_SIGNAL",
        "stored": 0,
    }


def test_a_caller_without_the_token_never_waits_for_the_sources_lock(db, registered):
    tenant, source, token, now = (registered[key] for key in ("tenant", "source", "token", "now"))
    forged = token[:-1] + ("A" if token[-1] != "A" else "B")

    def call(conn, token, event_id):
        conn.execute(text("SELECT set_config('lock_timeout', '200ms', true)"))
        fields = signal_fields(registered["account"], now, event_id=event_id)
        return conn.execute(ADMIT, admit_params(source, token, now, **fields)).scalar_one()

    with db.transaction(tenant) as holder:
        # A genuine admission, not yet committed, holds the source row's lock.
        assert call(holder, token, "first")["accepted"] is True
        with db.transaction(tenant) as caller:
            assert call(caller, forged, "forged") == {
                "refused": "INVALID_SOURCE",
                "reason": "MISMATCH",
            }
        # The genuine token does wait for the lock, so the refusal above did not.
        with pytest.raises(DBAPIError, match="lock timeout"):
            with db.transaction(tenant) as caller:
                call(caller, token, "second")


def test_the_signal_failure_surface_is_admitted(admin_engine, seeded):
    with admin_engine.begin() as conn:
        fenced(conn, seeded["tenants"][0])
        conn.execute(
            text(
                "INSERT INTO execbound.authentication_failures (failure_id, surface, reason, "
                "window_start, tenant_id, subject_kind, subject_id, count, first_at, last_at) "
                "VALUES (:f, 'signal', 'MISMATCH', now(), :t, 'source', :s, 1, now(), now())"
            ),
            {"f": uuid4(), "t": seeded["tenants"][0], "s": uuid4()},
        )


def test_the_migration_runs_without_bypass_and_refuses_a_lossy_downgrade(restricted):
    engine, config, _ = restricted
    alembic.upgrade(config, "head")
    tenant, admin = uuid4(), uuid4()
    now = datetime.now(UTC)
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
            {"t": tenant, "n": f"tenant-{tenant.hex[:8]}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :p, 'ADMIN')"
            ),
            {"t": tenant, "p": admin},
        )
        # `spaces.created_by` is NOT NULL (0041), so the principal comes first.
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Default', :n, :p)"
            ),
            {"t": tenant, "s": uuid4(), "n": now, "p": admin},
        )
        source, _ = insert_source(conn, tenant, admin, now)
    with pytest.raises(RuntimeError, match="lossy downgrade refused"):
        alembic.downgrade(config, "0067_step_up_window")
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("DELETE FROM execbound.signal_sources WHERE source_id = :s"), {"s": source}
        )
    alembic.downgrade(config, "0067_step_up_window")
    alembic.upgrade(config, "head")


def test_downgrade_refuses_a_mapping_naming_v2(admin_engine, seeded):
    """0009's rule, restated for the one contract this migration backs (#478).

    No source or record is written here: `registered` would plant a `signal_sources`
    row of its own, and the pre-existing checks on that table would refuse the downgrade
    for an unrelated reason, leaving this test unable to tell the new check apart from
    the old ones.
    """
    tenant, account = seeded["tenants"][0], uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) VALUES (:t, :a, 'mock_crowdstrike', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "a": account},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, context_contract_version) "
                "VALUES (:t, 'isolate.v2', :a, 'mock_crowdstrike', 'endpoint', "
                "'endpoint.isolate', 'contain', 'map-v1', 'action.v1', 'endpoint-isolation.v2')"
            ),
            {"t": tenant, "a": account},
        )
    config = migration_config()
    try:
        with pytest.raises(RuntimeError, match="lossy downgrade refused"):
            alembic.downgrade(config, "0067_step_up_window")
    finally:
        alembic.upgrade(config, "head")
    with admin_engine.begin() as conn:
        revision = conn.execute(text("SELECT version_num FROM execbound.alembic_version"))
        assert revision.scalar_one() == SCHEMA_REVISION


@pytest.mark.parametrize(
    "content",
    [
        *(
            pytest.param(
                {field: [{"context_contract_version": "endpoint-isolation.v2"}]},
                id=f"{field}-v2",
            )
            for field in ("mappings", "context_settings", "signal_mappings")
        ),
        # Content naming only v1 that 0067's strict models still cannot parse: its
        # `BundleContent` has no `signal_mappings` field, and its `ContextSetting` admits
        # only an inventory or incident source.
        pytest.param(
            {"signal_mappings": [{"context_contract_version": "endpoint-isolation.v1"}]},
            id="signal_mappings-v1",
        ),
        pytest.param(
            {
                "context_settings": [
                    {"context_contract_version": "endpoint-isolation.v1", "source_kind": "signal"}
                ]
            },
            id="signal-setting-v1",
        ),
        # A ruleset carries its own context settings, of the same model, and nothing
        # requires them to match the top-level ones.
        pytest.param(
            {
                "ruleset": {
                    "context": [
                        {
                            "context_contract_version": "endpoint-isolation.v1",
                            "source_kind": "signal",
                        }
                    ]
                }
            },
            id="ruleset-signal-setting-v1",
        ),
        pytest.param(
            {"ruleset": {"context": [{"context_contract_version": "endpoint-isolation.v2"}]}},
            id="ruleset-setting-v2",
        ),
        # A mapping naming the action its ref serves: 0067's strict `MappingRef` has no
        # such field, whatever contract the mapping names.
        pytest.param(
            {
                "mappings": [
                    {
                        "operation_ref": "isolate.corroborated",
                        "action": "endpoint.isolate",
                        "context_contract_version": "endpoint-isolation.v1",
                    }
                ]
            },
            id="mappings-action",
        ),
    ],
)
def test_downgrade_refuses_a_bundle_0067_cannot_parse(admin_engine, seeded, content):
    """The same rule reading a bundle's content instead of a mapping row (#478)."""
    tenant, space, actor = seeded["tenants"][0], seeded["spaces"][0], seeded["principals"][0]
    content = json.dumps(content)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.policy_bundle_contents "
                "(tenant_id, space_id, bundle_id, content_hash, content, created_at, created_by) "
                "VALUES (:t, :sp, :b, :h, CAST(:c AS jsonb), now(), :p)"
            ),
            {"t": tenant, "sp": space, "b": uuid4(), "h": "a" * 64, "c": content, "p": actor},
        )
    config = migration_config()
    try:
        with pytest.raises(RuntimeError, match="lossy downgrade refused"):
            alembic.downgrade(config, "0067_step_up_window")
    finally:
        alembic.upgrade(config, "head")
    with admin_engine.begin() as conn:
        revision = conn.execute(text("SELECT version_num FROM execbound.alembic_version"))
        assert revision.scalar_one() == SCHEMA_REVISION
