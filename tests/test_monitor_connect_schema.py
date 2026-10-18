# SPDX-License-Identifier: AGPL-3.0-only
"""MC1: the schema behind scheduled monitoring collection and sealed keys (#678), on real
PostgreSQL.

A connection's credential mode, its two intervals, a collection request and a run's lease are
columns of `monitor_connections` that only definer functions write. The runtime inserts only
the columns that existed before them and updates none of them, `check_runtime` holds the
database to exactly that, and the downgrade refuses while a connection records an interrupted
run, which the schema below cannot express.

A `sealed` Tines connection keeps its key as ciphertext only the collector's private key opens
(`sealed_ct`, `sealed_key_id`). Three definer functions are its only writers: creating one,
replacing its key, and re-sealing it to a new collector key. The runtime inserts and updates
neither column, and the downgrade refuses while a sealed connection exists.

A `platform_app` Entra connection is one a directory administrator consented to, read with the
deployment's own app: it holds no key fingerprint and always a consent. Every attempt to connect
one is a row of `monitor_connect_attempts`, which the runtime only reads; four definer functions
start, sign in, complete and refuse an attempt. `monitor_directory_claims` holds one digest per
active Entra connection with no tenant column and no runtime privilege at all, and a unique
index keeps one active Entra connection per directory across every tenant.
"""

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from alembic import command
from space_fixtures import make_space, seat
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from test_dormant_catalog import alembic_config, empty_schema
from test_migration_without_bypass import restricted as restricted

import execbound.db as catalog
from execbound.db import UnsafeDatabaseRole, check_runtime
from execbound.identity import authenticate
from execbound.monitoring import store
from execbound.principal_columns import GUARDED

pytestmark = pytest.mark.integration

BEFORE = "0085_account_recovery"
TARGET = "0086_monitor_collect_schedule"
NEW_COLUMNS = (
    "credential_mode",
    "collect_interval_seconds",
    "activity_interval_seconds",
    "collect_requested_at",
    "collect_requested_by",
    "collecting_until",
    "collecting_lease",
)
SIGNATURES = {
    "admin_request_collection": "p_actor uuid, p_connection uuid",
    "admin_set_collection_schedule": (
        "p_actor uuid, p_connection uuid, p_collect integer, p_activity integer"
    ),
    "collector_claim": "p_connection uuid, p_lease uuid, p_seconds integer",
    "collector_release": "p_connection uuid, p_lease uuid",
}
TINES = "https://fixture.tines.com"
GRAPH = "https://graph.microsoft.com"
DIRECTORY = "11111111-2222-3333-4444-555555555555"
CLIENT = "66666666-7777-8888-9999-aaaaaaaaaaaa"


def fenced(conn, tenant):
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def insert(conn, seeded, index=0, **columns):
    """One connection row written by the owner, with `columns` on top of a valid Tines row."""
    tenant, principal, space = (
        seeded["tenants"][index],
        seeded["principals"][index],
        seeded["spaces"][index],
    )
    row = {
        "tenant_id": tenant,
        "connection_id": uuid4(),
        "label": "Synthetic",
        "base_url": TINES,
        "key_fingerprint": "0" * 64,
        "created_at": datetime.now(UTC),
        "created_by": principal,
        "space_id": space,
        "active": False,
        **columns,
    }
    names = ", ".join(row)
    values = ", ".join(f":{name}" for name in row)
    fenced(conn, tenant)
    conn.execute(
        text(f"INSERT INTO execbound.monitor_connections ({names}) VALUES ({values})"),  # nosec B608 - test literals
        row,
    )
    return row["connection_id"]


ENTRA = {
    "kind": "entra_agent_id",
    "base_url": GRAPH,
    "directory_ref": DIRECTORY,
    "client_ref": CLIENT,
}


@pytest.mark.parametrize(
    "columns",
    [
        # A sealed connection carries its ciphertext and key id, and only an Entra connection
        # is platform_app (with a consent and no key): the Tines row here is neither.
        {"credential_mode": "sealed"},
        {"credential_mode": "platform_app"},
        # A request is a moment and a person, never one without the other.
        {"collect_requested_at": datetime.now(UTC)},
        {"collect_requested_by": "principal"},
        # A lease is an end and a holder, never one without the other.
        {"collecting_until": datetime.now(UTC)},
        {"collecting_lease": uuid4()},
        # Tines reads its inventory daily, and nothing else.
        {"collect_interval_seconds": 3600},
        {"collect_interval_seconds": 86401},
        {"activity_interval_seconds": 299},
        {"activity_interval_seconds": 3601},
        # Entra collects every one to twenty-four hours and has no activity interval.
        {**ENTRA, "collect_interval_seconds": 3599},
        {**ENTRA, "collect_interval_seconds": 86401},
        {**ENTRA, "activity_interval_seconds": 900},
    ],
)
def test_mc1_each_new_check_refuses_its_violation(admin_engine, seeded, columns):
    if columns.get("collect_requested_by") == "principal":
        columns = {**columns, "collect_requested_by": seeded["principals"][0]}
    with pytest.raises(IntegrityError):
        with admin_engine.begin() as conn:
            insert(conn, seeded, **columns)


def test_mc1_the_new_columns_accept_their_ranges_and_an_interrupted_run(admin_engine, seeded):
    now = datetime.now(UTC)
    with admin_engine.begin() as conn:
        tines = insert(
            conn,
            seeded,
            collect_interval_seconds=86400,
            activity_interval_seconds=300,
            collect_requested_at=now,
            collect_requested_by=seeded["principals"][0],
            collecting_until=now,
            collecting_lease=uuid4(),
        )
        insert(conn, seeded, **ENTRA, collect_interval_seconds=3600)
        insert(conn, seeded, **ENTRA, collect_interval_seconds=86400)
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET last_outcome = 'INTERRUPTED' "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": seeded["tenants"][0], "c": tines},
        )
        mode = conn.execute(
            text(
                "SELECT credential_mode FROM execbound.monitor_connections "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": seeded["tenants"][0], "c": tines},
        ).scalar_one()
    # Every row there was before is the operator's key file.
    assert mode == "key_file"


def test_mc1_the_runtime_inserts_only_the_columns_there_were_and_updates_none_of_the_new(
    db, admin_engine, seeded
):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id = NULL"))
    admin = authenticate(db, seeded["tokens"][0])
    # The operator's path still inserts.
    connection = store.create_connection(
        db, admin, label="Synthetic", base_url=TINES, key_fingerprint="ab" * 32
    )
    tenant = admin.tenant_id
    for column, value in (
        ("credential_mode", "key_file"),
        ("collect_requested_at", datetime.now(UTC)),
        ("collecting_lease", uuid4()),
    ):
        with pytest.raises(ProgrammingError) as refused:
            with db.transaction(tenant) as conn:
                conn.execute(
                    text(
                        "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, "
                        "label, base_url, key_fingerprint, created_at, created_by, space_id, "
                        f"{column}) VALUES (:t, :c, 'x', :u, :k, now(), :p, :s, :v)"  # nosec B608 - test literals
                    ),
                    {
                        "t": tenant,
                        "c": uuid4(),
                        "u": TINES,
                        "k": "cd" * 32,
                        "p": admin.principal_id,
                        "s": seeded["spaces"][0],
                        "v": value,
                    },
                )
        assert "permission denied" in str(refused.value.orig)
    for column in NEW_COLUMNS:
        with pytest.raises(ProgrammingError) as refused:
            with db.transaction(tenant) as conn:
                conn.execute(
                    text(
                        f"UPDATE execbound.monitor_connections SET {column} = NULL "  # nosec B608 - test literals
                        "WHERE tenant_id = :t AND connection_id = :c"
                    ),
                    {"t": tenant, "c": connection},
                )
        assert "permission denied" in str(refused.value.orig)


def test_mc1_check_runtime_holds_the_insert_columns_exactly(db, admin_engine):
    assert set(catalog.INSERT_COLUMNS) == {"monitor_connections"}
    assert not set(NEW_COLUMNS) & catalog.INSERT_COLUMNS["monitor_connections"]
    with db.engine.connect() as conn:
        check_runtime(conn)
    for grant, revoke in (
        # One column too many, and every column at once.
        (
            "GRANT INSERT (collecting_lease) ON execbound.monitor_connections TO execbound_app",
            "REVOKE INSERT (collecting_lease) ON execbound.monitor_connections FROM execbound_app",
        ),
        (
            "GRANT INSERT ON execbound.monitor_connections TO execbound_app",
            "REVOKE INSERT ON execbound.monitor_connections FROM execbound_app",
        ),
        # One column too few.
        (
            "REVOKE INSERT (label) ON execbound.monitor_connections FROM execbound_app",
            "GRANT INSERT (label) ON execbound.monitor_connections TO execbound_app",
        ),
    ):
        try:
            with admin_engine.begin() as conn:
                conn.execute(text(grant))
            with pytest.raises(UnsafeDatabaseRole, match="column privileges"):
                with db.engine.connect() as conn:
                    check_runtime(conn)
        finally:
            with admin_engine.begin() as conn:
                conn.execute(text(revoke))
                # Revoking the table-level grant takes every column grant with it.
                columns = ", ".join(sorted(catalog.INSERT_COLUMNS["monitor_connections"]))
                conn.execute(
                    text(
                        f"GRANT INSERT ({columns}) ON execbound.monitor_connections "  # nosec B608 - catalog names
                        "TO execbound_app"
                    )
                )
    with db.engine.connect() as conn:
        check_runtime(conn)


def test_mc1_the_four_functions_are_definers_the_runtime_alone_may_call(admin_engine):
    for name, arguments in SIGNATURES.items():
        assert (name, arguments) in catalog.FUNCTIONS
    with admin_engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS arguments, "
                    "p.prosecdef, p.proconfig, "
                    "has_function_privilege('execbound_app', p.oid, 'EXECUTE') AS runtime, "
                    "EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', "
                    "p.proowner))) a WHERE a.grantee = 0) AS public "
                    "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
                ),
                {"names": list(SIGNATURES)},
            )
            .mappings()
            .all()
        )
    assert {row["proname"]: row["arguments"] for row in rows} == SIGNATURES
    for row in rows:
        assert row["prosecdef"] is True, row["proname"]
        assert row["proconfig"] == ["search_path=pg_catalog, pg_temp"], row["proname"]
        assert row["runtime"] is True and row["public"] is False, row["proname"]


def privileges(acl):
    """The privilege letters an ACL grants the runtime role."""
    return "".join(
        item.split("=", 1)[1].split("/", 1)[0]
        for item in acl.strip("{}").split(",")
        if item.startswith("execbound_app=")
    )


def shape(conn):
    """Every definition this migration changes, as the catalog holds it."""
    constraints = dict(
        conn.execute(
            text(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'execbound.monitor_connections'::regclass"
            )
        ).all()
    )
    indexes = dict(
        conn.execute(
            text(
                "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'execbound' "
                "AND tablename = 'monitor_connections'"
            )
        ).all()
    )
    columns = conn.execute(
        text(
            "SELECT a.attname, CAST(a.attacl AS text) FROM pg_attribute a "
            "WHERE a.attrelid = 'execbound.monitor_connections'::regclass AND a.attnum > 0 "
            "AND NOT a.attisdropped ORDER BY a.attnum"
        )
    ).all()
    table = conn.execute(
        text(
            "SELECT CAST(relacl AS text), relforcerowsecurity FROM pg_class "
            "WHERE oid = 'execbound.monitor_connections'::regclass"
        )
    ).one()
    functions = set(
        conn.execute(
            text(
                "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": [*SIGNATURES, "monitor_connections_revoked_unleased"]},
        ).scalars()
    )
    triggers = set(
        conn.execute(
            text(
                "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal "
                "AND tgrelid = 'execbound.monitor_connections'::regclass"
            )
        ).scalars()
    )
    return constraints, indexes, tuple(columns), tuple(table), functions, triggers


def test_mc1_downgrade_refuses_an_interrupted_run_and_otherwise_round_trips(admin_engine, seeded):
    config = alembic_config()
    with admin_engine.connect() as conn:
        head = shape(conn)
    empty_schema(admin_engine)
    command.downgrade(config, TARGET)
    try:
        with admin_engine.connect() as conn:
            upgraded = shape(conn)
        with admin_engine.begin() as conn:
            # `seeded` was emptied above; a tenant of this test's own.
            tenant, principal, space = uuid4(), uuid4(), uuid4()
            fenced(conn, tenant)
            conn.execute(
                text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
                {"t": tenant, "n": f"Migration {tenant}"},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, "
                    "created_by) VALUES (:t, :s, 'Default', now(), :p)"
                ),
                {"t": tenant, "s": space, "p": principal},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                    "VALUES (:t, :p, 'ADMIN')"
                ),
                {"t": tenant, "p": principal},
            )
            connection = insert(
                conn,
                {"tenants": [tenant], "principals": [principal], "spaces": [space]},
                last_outcome="INTERRUPTED",
            )
        with pytest.raises(RuntimeError, match="interrupted collection run"):
            command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert shape(conn) == upgraded
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET last_outcome = 'ERROR' "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": tenant, "c": connection},
            )
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            before = shape(conn)
        constraints, _, columns, table, functions, triggers = before
        assert functions == set()
        assert "monitor_connections_revoked_unleased" not in triggers
        assert {name for name, _ in columns}.isdisjoint(NEW_COLUMNS)
        assert "INTERRUPTED" not in constraints["monitor_connections_last_outcome_check"]
        # The table-level insert grant is back and no column carries one of its own (the
        # update grants of earlier revisions stay on their columns).
        assert "execbound_app=ar/" in table[0] and table[1] is True
        assert [name for name, acl in columns if acl is not None and "a" in privileges(acl)] == []
        # The upgrade then the downgrade again leave exactly the definitions found below it.
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            assert shape(conn) == upgraded
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert shape(conn) == before
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
    with admin_engine.connect() as conn:
        assert shape(conn) == head


def test_mc1_the_request_and_schedule_functions_refuse_what_they_must(db, admin_engine, seeded):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id = NULL"))
    admin = authenticate(db, seeded["tokens"][0])
    tenant = admin.tenant_id
    tines = store.create_connection(
        db, admin, label="Synthetic", base_url=TINES, key_fingerprint="ab" * 32
    )

    def call(statement, **values):
        try:
            with db.transaction(tenant) as conn:
                conn.execute(text(statement), {"a": admin.principal_id, "c": tines, **values})
        except DBAPIError as exc:
            return exc.orig.diag.message_primary
        return None

    request = "SELECT execbound.admin_request_collection(:a, :c)"
    schedule = "SELECT execbound.admin_set_collection_schedule(:a, :c, :collect, :activity)"
    assert call(request) is None
    with db.transaction(tenant) as conn:
        first = conn.execute(
            text(
                "SELECT collect_requested_at, collect_requested_by "
                "FROM execbound.monitor_connections WHERE connection_id = :c"
            ),
            {"c": tines},
        ).one()
    assert first[1] == admin.principal_id
    # A second request changes nothing: the first is the one the next pass answers.
    assert call(request) is None
    with db.transaction(tenant) as conn:
        assert (
            conn.execute(
                text(
                    "SELECT collect_requested_at, collect_requested_by "
                    "FROM execbound.monitor_connections WHERE connection_id = :c"
                ),
                {"c": tines},
            ).one()
            == first
        )
    assert call(schedule, collect=None, activity=300) is None
    assert call(schedule, collect=86400, activity=3600) is None
    for collect, activity in ((3600, None), (None, 299), (None, 3601), (86401, None)):
        assert call(schedule, collect=collect, activity=activity) == "INVALID_SCHEDULE"
    # A principal the workspace does not have is no actor; every other refused actor is the
    # next test's.
    assert call(request, a=uuid4()) == "INVALID_ACTOR"
    assert call(schedule, a=uuid4(), collect=None, activity=None) == "INVALID_ACTOR"
    assert call(request, c=uuid4()) == "INVALID_STATE"
    store.revoke_connection(db, admin, tines)
    assert call(request) == "INVALID_STATE"
    assert call(schedule, collect=None, activity=None) == "INVALID_STATE"


# Who may ask for a collection or set a schedule, each beside the reason the database refuses
# them: the functions are the in-database check whatever a route checked before calling them.
REFUSED_ACTORS = (
    # An agent, and the workspace's scheduler principal, are never administrators.
    "agent",
    "scheduler",
    # A person who is not an administrator, and an administrator who was deactivated.
    "approver",
    "deactivated",
    # A membership narrows an administrator: one who administers only another space, and one
    # who only reviews in the connection's space, administer nothing here.
    "narrowed_elsewhere",
    "reviewer_here",
    # The other workspace's administrator.
    "other_workspace",
)


def test_mc1_only_an_active_administrator_of_the_connections_space_may_request_or_schedule(
    db, admin_engine, seeded
):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id = NULL"))
    admin = authenticate(db, seeded["tokens"][0])
    tenant, space = admin.tenant_id, seeded["spaces"][0]
    tines = store.create_connection(
        db, admin, label="Synthetic", base_url=TINES, key_fingerprint="ab" * 32
    )
    actors = {"other_workspace": seeded["principals"][1]}
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        elsewhere = make_space(conn, tenant, "Another customer", created_by=admin.principal_id)
        for name, kind, active in (
            ("agent", "AGENT", True),
            ("approver", "HUMAN_APPROVER", True),
            ("deactivated", "ADMIN", False),
            ("narrowed_elsewhere", "ADMIN", True),
            ("reviewer_here", "ADMIN", True),
            ("seated_here", "ADMIN", True),
        ):
            actors[name] = uuid4()
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id, principal_id, kind, space_id, "
                    "active) VALUES (:t, :p, :k, :s, :a)"
                ),
                {
                    "t": tenant,
                    "p": actors[name],
                    "k": kind,
                    "s": space if kind == "AGENT" else None,
                    "a": active,
                },
            )
        seat(conn, tenant, elsewhere, actors["narrowed_elsewhere"], "ADMIN")
        seat(conn, tenant, elsewhere, actors["reviewer_here"], "ADMIN")
        seat(conn, tenant, space, actors["reviewer_here"], "HUMAN_APPROVER")
        seat(conn, tenant, space, actors["seated_here"], "ADMIN")
        made = conn.execute(text("SELECT execbound.scheduler_actor()")).scalar_one()
        actors["scheduler"] = UUID(made["principal_id"])

    def call(statement, actor):
        try:
            with db.transaction(tenant) as conn:
                conn.execute(text(statement), {"a": actor, "c": tines})
        except DBAPIError as exc:
            return exc.orig.diag.message_primary
        return None

    def asked():
        with admin_engine.connect() as conn:
            return tuple(
                conn.execute(
                    text(
                        "SELECT collect_requested_by, activity_interval_seconds "
                        "FROM execbound.monitor_connections "
                        "WHERE tenant_id = :t AND connection_id = :c"
                    ),
                    {"t": tenant, "c": tines},
                ).one()
            )

    request = "SELECT execbound.admin_request_collection(:a, :c)"
    schedule = "SELECT execbound.admin_set_collection_schedule(:a, :c, NULL, 600)"
    # Every actor's two answers at once, so a failure names each actor admitted.
    answers = {
        name: (call(request, actors[name]), call(schedule, actors[name])) for name in REFUSED_ACTORS
    }
    assert answers == dict.fromkeys(REFUSED_ACTORS, ("INVALID_ACTOR", "INVALID_ACTOR"))
    assert asked() == (None, None)
    # An administrator seated as one in the connection's space is admitted, membership and all.
    assert call(request, actors["seated_here"]) is None
    assert call(schedule, actors["seated_here"]) is None
    assert asked() == (actors["seated_here"], 600)
    # A deactivated workspace admits no one, its own administrator included.
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"),
            {"t": tenant},
        )
    for actor in (admin.principal_id, actors["seated_here"]):
        assert (call(request, actor), call(schedule, actor)) == (
            "INVALID_TENANT",
            "INVALID_TENANT",
        )


def test_mc1_a_claim_holds_a_connection_one_to_fifteen_minutes_by_the_databases_clock(
    db, admin_engine, seeded
):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id = NULL"))
    admin = authenticate(db, seeded["tokens"][0])
    tines = store.create_connection(
        db, admin, label="Synthetic", base_url=TINES, key_fingerprint="ab" * 32
    )

    def claim(seconds):
        try:
            with db.transaction(admin.tenant_id) as conn:
                return conn.execute(
                    text("SELECT execbound.collector_claim(:c, :l, :s)"),
                    {"c": tines, "l": uuid4(), "s": seconds},
                ).scalar_one()
        except DBAPIError as exc:
            return exc.orig.diag.message_primary

    for seconds in (59, 901, None):
        assert claim(seconds) == "INVALID_LEASE"
    assert claim(900) == {"claimed": True}
    with db.transaction(admin.tenant_id) as conn:
        held = conn.execute(
            text(
                "SELECT collecting_until - now() FROM execbound.monitor_connections "
                "WHERE connection_id = :c"
            ),
            {"c": tines},
        ).scalar_one()
    assert held.total_seconds() <= 900


SEALED_BEFORE = TARGET
SEALED_TARGET = "0087_monitor_sealed_keys"
SEALED_SIGNATURES = {
    "admin_create_sealed_connection": (
        "p_actor uuid, p_space uuid, p_connection uuid, p_label text, p_base_url text, "
        "p_team text, p_fingerprint text, p_sealed_ct bytea, p_key_id text"
    ),
    "admin_replace_sealed_key": (
        "p_actor uuid, p_connection uuid, p_fingerprint text, p_sealed_ct bytea, p_key_id text"
    ),
    "collector_reseal": (
        "p_connection uuid, p_old_key_id text, p_old_ct bytea, p_sealed_ct bytea, p_key_id text"
    ),
}
KEY_ID = "ck1-0123456789abcdef"
SEALED = {"credential_mode": "sealed", "sealed_ct": b"\x01" * 48, "sealed_key_id": KEY_ID}


@pytest.mark.parametrize(
    "columns",
    [
        # A sealed connection holds both halves, never one.
        {"credential_mode": "sealed", "sealed_ct": b"\x01" * 48},
        {"credential_mode": "sealed", "sealed_key_id": KEY_ID},
        # Only a sealed connection holds either.
        {"sealed_ct": b"\x01" * 48, "sealed_key_id": KEY_ID},
        {"sealed_ct": b"\x01" * 48},
        {"sealed_key_id": KEY_ID},
        # Only Tines keys are pasted; Entra connects by consent or an operator's file.
        {**ENTRA, **SEALED},
        # A ciphertext of a sealed box is at least its 48 bytes of overhead, and bounded.
        {**SEALED, "sealed_ct": b"\x01" * 47},
        {**SEALED, "sealed_ct": b"\x01" * 8193},
        # The key id is derived from the collector's public key, in one spelling.
        {**SEALED, "sealed_key_id": "ck1-0123456789ABCDEF"},
        {**SEALED, "sealed_key_id": "ck2-0123456789abcdef"},
        {**SEALED, "sealed_key_id": "ck1-0123456789abcde"},
        # Every connection keeps the fingerprint of its key, sealed or on file.
        {"key_fingerprint": None},
        {**SEALED, "key_fingerprint": None},
    ],
)
def test_mc1_each_sealed_check_refuses_its_violation(admin_engine, seeded, columns):
    with pytest.raises(IntegrityError):
        with admin_engine.begin() as conn:
            insert(conn, seeded, **columns)


def test_mc1_a_sealed_tines_row_is_admitted(admin_engine, seeded):
    with admin_engine.begin() as conn:
        connection = insert(conn, seeded, **{**SEALED, "sealed_ct": b"\x02" * 8192})
        mode = conn.execute(
            text(
                "SELECT credential_mode FROM execbound.monitor_connections "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": seeded["tenants"][0], "c": connection},
        ).scalar_one()
    assert mode == "sealed"


def test_mc1_the_runtime_neither_inserts_nor_updates_a_sealed_key(db, admin_engine, seeded):
    assert not {"sealed_ct", "sealed_key_id"} & catalog.INSERT_COLUMNS["monitor_connections"]
    assert not {"sealed_ct", "sealed_key_id"} & set(catalog.UPDATE_COLUMNS["monitor_connections"])
    with admin_engine.begin() as conn:
        connection = insert(conn, seeded, **SEALED, active=True)
    tenant = seeded["tenants"][0]
    for column, value in (("sealed_ct", b"\x03" * 48), ("sealed_key_id", KEY_ID)):
        with pytest.raises(ProgrammingError) as refused:
            with db.transaction(tenant) as conn:
                conn.execute(
                    text(
                        "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, "
                        "label, base_url, key_fingerprint, created_at, created_by, space_id, "
                        f"{column}) VALUES (:t, :c, 'x', :u, :k, now(), :p, :s, :v)"  # nosec B608 - test literals
                    ),
                    {
                        "t": tenant,
                        "c": uuid4(),
                        "u": TINES,
                        "k": "cd" * 32,
                        "p": seeded["principals"][0],
                        "s": seeded["spaces"][0],
                        "v": value,
                    },
                )
        assert "permission denied" in str(refused.value.orig)
        with pytest.raises(ProgrammingError) as refused:
            with db.transaction(tenant) as conn:
                conn.execute(
                    text(
                        f"UPDATE execbound.monitor_connections SET {column} = :v "  # nosec B608 - test literals
                        "WHERE tenant_id = :t AND connection_id = :c"
                    ),
                    {"t": tenant, "c": connection, "v": value},
                )
        assert "permission denied" in str(refused.value.orig)
    with db.engine.connect() as conn:
        check_runtime(conn)


def test_mc1_the_three_sealed_functions_are_definers_the_runtime_alone_may_call(admin_engine):
    for name, arguments in SEALED_SIGNATURES.items():
        assert (name, arguments) in catalog.FUNCTIONS
    with admin_engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS arguments, "
                    "p.prosecdef, p.proconfig, "
                    "has_function_privilege('execbound_app', p.oid, 'EXECUTE') AS runtime, "
                    "EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', "
                    "p.proowner))) a WHERE a.grantee = 0) AS public "
                    "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
                ),
                {"names": list(SEALED_SIGNATURES)},
            )
            .mappings()
            .all()
        )
    assert {row["proname"]: row["arguments"] for row in rows} == SEALED_SIGNATURES
    for row in rows:
        assert row["prosecdef"] is True, row["proname"]
        assert row["proconfig"] == ["search_path=pg_catalog, pg_temp"], row["proname"]
        assert row["runtime"] is True and row["public"] is False, row["proname"]


def sealed_shape(conn):
    """Every definition the sealed-keys migration changes, as the catalog holds it."""
    constraints, indexes, columns, table, _, triggers = shape(conn)
    functions = set(
        conn.execute(
            text(
                "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(SEALED_SIGNATURES)},
        ).scalars()
    )
    return constraints, indexes, columns, table, functions, triggers


def test_mc1_the_sealed_downgrade_refuses_a_sealed_row_and_otherwise_round_trips(
    admin_engine, seeded
):
    config = alembic_config()
    with admin_engine.connect() as conn:
        head = sealed_shape(conn)
    empty_schema(admin_engine)
    command.downgrade(config, SEALED_TARGET)
    try:
        with admin_engine.connect() as conn:
            upgraded = sealed_shape(conn)
        with admin_engine.begin() as conn:
            tenant, principal, space = uuid4(), uuid4(), uuid4()
            fenced(conn, tenant)
            conn.execute(
                text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
                {"t": tenant, "n": f"Migration {tenant}"},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, "
                    "created_by) VALUES (:t, :s, 'Default', now(), :p)"
                ),
                {"t": tenant, "s": space, "p": principal},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                    "VALUES (:t, :p, 'ADMIN')"
                ),
                {"t": tenant, "p": principal},
            )
            connection = insert(
                conn,
                {"tenants": [tenant], "principals": [principal], "spaces": [space]},
                **SEALED,
            )
        with pytest.raises(RuntimeError, match="sealed collection key"):
            command.downgrade(config, SEALED_BEFORE)
        with admin_engine.connect() as conn:
            assert sealed_shape(conn) == upgraded
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "DELETE FROM execbound.monitor_connections "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": tenant, "c": connection},
            )
        command.downgrade(config, SEALED_BEFORE)
        with admin_engine.connect() as conn:
            before = sealed_shape(conn)
        constraints, _, columns, _, functions, _ = before
        assert functions == set()
        assert {name for name, _ in columns}.isdisjoint({"sealed_ct", "sealed_key_id"})
        assert "sealed" not in constraints["monitor_connections_credential_mode_check"]
        command.upgrade(config, SEALED_TARGET)
        with admin_engine.connect() as conn:
            assert sealed_shape(conn) == upgraded
        command.downgrade(config, SEALED_BEFORE)
        with admin_engine.connect() as conn:
            assert sealed_shape(conn) == before
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
    with admin_engine.connect() as conn:
        assert sealed_shape(conn) == head


def sealed_call(db, tenant, statement, **values):
    """A definer function's answer: None, or the code it raised."""
    try:
        with db.transaction(tenant) as conn:
            conn.execute(text(statement), values)
    except DBAPIError as exc:
        return exc.orig.diag.message_primary
    return None


CREATE_SEALED = (
    "SELECT execbound.admin_create_sealed_connection(:a, :s, :c, :label, :url, :team, :k, "
    ":ct, :kid)"
)


def sealed_values(admin, space, **overrides):
    return {
        "a": admin.principal_id,
        "s": space,
        "c": uuid4(),
        "label": "Sealed",
        "url": TINES,
        "team": None,
        "k": "ab" * 32,
        "ct": b"\x05" * 64,
        "kid": KEY_ID,
        **overrides,
    }


def connection_row(admin_engine, tenant, connection):
    with admin_engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_connections "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": tenant, "c": connection},
            )
            .mappings()
            .one_or_none()
        )


def test_mc1_creating_a_sealed_connection_applies_the_stores_rules_in_the_database(
    db, admin_engine, seeded
):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id = NULL"))
    admin = authenticate(db, seeded["tokens"][0])
    tenant, space = admin.tenant_id, seeded["spaces"][0]
    # The capacity the store holds every tenant to is the one the function holds.
    assert store.MAX_CONNECTIONS == 20
    values = sealed_values(admin, space, team="team-1")
    assert sealed_call(db, tenant, CREATE_SEALED, **values) is None
    row = connection_row(admin_engine, tenant, values["c"])
    assert row["credential_mode"] == "sealed" and row["kind"] == "tines"
    assert bytes(row["sealed_ct"]) == values["ct"] and row["sealed_key_id"] == KEY_ID
    assert row["key_fingerprint"] == values["k"] and row["team_id"] == "team-1"
    assert row["space_id"] == space and row["active"] is True
    assert row["created_by"] == admin.principal_id
    # The kind's default intervals, and a collection asked for by whoever connected it.
    assert row["collect_interval_seconds"] is None and row["activity_interval_seconds"] is None
    assert row["collect_requested_at"] is not None
    assert row["collect_requested_by"] == admin.principal_id
    # One active connection per platform per space.
    assert sealed_call(db, tenant, CREATE_SEALED, **sealed_values(admin, space)) == (
        "CONNECTION_EXISTS"
    )
    # Each shape a row could not hold is refused before anything is written.
    for field, value in (
        ("url", "https://evil.example.com"),
        ("url", "http://fixture.tines.com"),
        ("label", ""),
        ("label", "x" * 97),
        ("label", "line\nbreak"),
        ("team", "has space"),
        ("k", "AB" * 32),
        ("ct", b"\x05" * 47),
        ("kid", "ck1-short"),
    ):
        answer = sealed_call(
            db, tenant, CREATE_SEALED, **sealed_values(admin, space, **{field: value})
        )
        assert answer == "INVALID_INPUT", (field, answer)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
        archived = make_space(conn, tenant, "Archived", created_by=admin.principal_id)
        conn.execute(
            text(
                "UPDATE execbound.spaces SET archived_at = now() "
                "WHERE tenant_id = :t AND space_id = :s"
            ),
            {"t": tenant, "s": archived},
        )
    assert sealed_call(db, tenant, CREATE_SEALED, **sealed_values(admin, archived)) == (
        "SPACE_ARCHIVED"
    )
    assert sealed_call(db, tenant, CREATE_SEALED, **sealed_values(admin, uuid4())) == (
        "INVALID_SPACE"
    )
    # Another space takes its own connection.
    assert sealed_call(db, tenant, CREATE_SEALED, **sealed_values(admin, other)) is None
    # A membership narrows an administrator to the spaces they administer.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        third = make_space(conn, tenant, "Customer C", created_by=admin.principal_id)
        seat(conn, tenant, other, admin.principal_id, "ADMIN")
    assert sealed_call(db, tenant, CREATE_SEALED, **sealed_values(admin, third)) == (
        "INVALID_ACTOR"
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.space_members WHERE tenant_id = :t"), {"t": tenant}
        )
    # Not an administrator, and not this workspace's.
    for actor in (uuid4(), seeded["principals"][1]):
        assert (
            sealed_call(db, tenant, CREATE_SEALED, **sealed_values(admin, third, a=actor))
            == "INVALID_ACTOR"
        )
    # A full workspace takes no more, revoked connections counted as the store counts them.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        present = conn.execute(
            text("SELECT count(*) FROM execbound.monitor_connections WHERE tenant_id = :t"),
            {"t": tenant},
        ).scalar_one()
        for _ in range(store.MAX_CONNECTIONS - present):
            insert(conn, seeded)
    assert sealed_call(db, tenant, CREATE_SEALED, **sealed_values(admin, third)) == (
        "CONNECTION_CAPACITY"
    )


REPLACE_SEALED = "SELECT execbound.admin_replace_sealed_key(:a, :c, :k, :ct, :kid)"
RESEAL = "SELECT execbound.collector_reseal(:c, :old, :oldct, :ct, :kid)"


def test_mc1_replacing_and_resealing_a_key_touch_only_a_sealed_connection(db, admin_engine, seeded):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id = NULL"))
    admin = authenticate(db, seeded["tokens"][0])
    tenant, space = admin.tenant_id, seeded["spaces"][0]
    values = sealed_values(admin, space)
    assert sealed_call(db, tenant, CREATE_SEALED, **values) is None
    sealed = values["c"]
    # Answer the request the connection was created with, as a claim would.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET collect_requested_at = NULL, "
                "collect_requested_by = NULL WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": tenant, "c": sealed},
        )
    new_id = "ck1-fedcba9876543210"
    replace = {"a": admin.principal_id, "c": sealed, "k": "cd" * 32, "ct": b"\x06" * 80}
    assert sealed_call(db, tenant, REPLACE_SEALED, **replace, kid=new_id) is None
    row = connection_row(admin_engine, tenant, sealed)
    assert bytes(row["sealed_ct"]) == b"\x06" * 80 and row["sealed_key_id"] == new_id
    assert row["key_fingerprint"] == "cd" * 32
    # A replaced key is collected with next.
    assert row["collect_requested_by"] == admin.principal_id
    # A re-seal changes the ciphertext and the key id only, and only from the key it names.
    reseal = {"c": sealed, "ct": b"\x07" * 80, "kid": KEY_ID, "oldct": b"\x06" * 80}
    assert sealed_call(db, tenant, RESEAL, **reseal, old=KEY_ID) == "INVALID_STATE"
    # Nor from a ciphertext the row no longer holds: a key replaced after the re-seal read the
    # row is never overwritten with the key it replaced, whichever collector key sealed it.
    stale = {**reseal, "oldct": b"\x05" * 80}
    assert sealed_call(db, tenant, RESEAL, **stale, old=new_id) == "INVALID_STATE"
    assert bytes(connection_row(admin_engine, tenant, sealed)["sealed_ct"]) == b"\x06" * 80
    assert sealed_call(db, tenant, RESEAL, **reseal, old=new_id) is None
    resealed = connection_row(admin_engine, tenant, sealed)
    assert bytes(resealed["sealed_ct"]) == b"\x07" * 80 and resealed["sealed_key_id"] == KEY_ID
    assert resealed["key_fingerprint"] == "cd" * 32
    # Neither touches a connection that is not sealed.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
        filed = insert(conn, seeded, active=True, space_id=other)
    before = connection_row(admin_engine, tenant, filed)
    assert (
        sealed_call(db, tenant, REPLACE_SEALED, **{**replace, "c": filed}, kid=new_id)
        == "INVALID_STATE"
    )
    assert sealed_call(db, tenant, RESEAL, **{**reseal, "c": filed}, old=KEY_ID) == (
        "INVALID_STATE"
    )
    assert connection_row(admin_engine, tenant, filed) == before
    # A revoked sealed connection takes no new key from an administrator.
    store.revoke_connection(db, admin, sealed)
    assert sealed_call(db, tenant, REPLACE_SEALED, **replace, kid=new_id) == "INVALID_STATE"
    # Only an administrator replaces a key.
    assert (
        sealed_call(db, tenant, REPLACE_SEALED, **{**replace, "a": uuid4()}, kid=new_id)
        == "INVALID_ACTOR"
    )
    # Without the tenant fence nothing is written.
    with pytest.raises(DBAPIError) as refused:
        with db.engine.begin() as conn:
            conn.execute(text(RESEAL), {**reseal, "old": KEY_ID})
    assert refused.value.orig.diag.message_primary == "INVALID_TENANT"


CONSENT_BEFORE = SEALED_TARGET
CONSENT_TARGET = "0088_monitor_entra_consent"
CONSENT_SIGNATURES = {
    "admin_start_connect": (
        "p_actor uuid, p_space uuid, p_attempt uuid, p_connection uuid, p_label text, "
        "p_state_hash text, p_binding_hash text, p_nonce_hash text"
    ),
    "admin_record_signin": (
        "p_attempt uuid, p_state_hash text, p_binding_hash text, p_nonce_hash text, "
        "p_directory text"
    ),
    "admin_complete_consent": (
        "p_attempt uuid, p_state_hash text, p_binding_hash text, p_directory text, "
        "p_client_ref text"
    ),
    "admin_refuse_connect": "p_attempt uuid, p_state_hash text, p_step text, p_code text",
}
CONSENT_TABLES = ("monitor_connect_attempts", "monitor_directory_claims")
# A directory spelled with letters, so a check that folds case is never vacuous.
LETTERED = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
CONSENTING = {**ENTRA, "directory_ref": LETTERED}
PLATFORM = {**CONSENTING, "credential_mode": "platform_app", "key_fingerprint": None}


def consented(principal, **columns):
    """A consented Entra row's columns, consented by `principal`."""
    return {**PLATFORM, "consented_at": datetime.now(UTC), "consented_by": principal, **columns}


@pytest.mark.parametrize(
    "columns",
    [
        # A consented connection is read with the deployment's own app, so it holds no key.
        {**PLATFORM, "key_fingerprint": "0" * 64, "consented_at": "now", "consented_by": "p"},
        # Only an Entra directory consents; a Tines connection is never one.
        {"credential_mode": "platform_app", "key_fingerprint": None, "consented_at": "now"},
        # Every other connection keeps its key's fingerprint.
        {**ENTRA, "key_fingerprint": None},
        # A consent is a moment and a person, never one without the other ...
        {**PLATFORM, "consented_at": "now"},
        {**PLATFORM, "consented_by": "p"},
        # ... a consented connection always records one, and no other connection does.
        PLATFORM,
        {**ENTRA, "consented_at": "now", "consented_by": "p"},
    ],
)
def test_mc1_each_consent_check_refuses_its_violation(admin_engine, seeded, columns):
    columns = {
        **columns,
        **({"consented_at": datetime.now(UTC)} if "consented_at" in columns else {}),
        **({"consented_by": seeded["principals"][0]} if "consented_by" in columns else {}),
    }
    with pytest.raises(IntegrityError):
        with admin_engine.begin() as conn:
            insert(conn, seeded, **columns)


def test_mc1_a_consented_entra_row_is_admitted_with_no_key(admin_engine, seeded):
    with admin_engine.begin() as conn:
        connection = insert(conn, seeded, **consented(seeded["principals"][0]), active=True)
        row = (
            conn.execute(
                text(
                    "SELECT credential_mode, key_fingerprint, consented_by "
                    "FROM execbound.monitor_connections WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": seeded["tenants"][0], "c": connection},
            )
            .mappings()
            .one()
        )
    assert dict(row) == {
        "credential_mode": "platform_app",
        "key_fingerprint": None,
        "consented_by": seeded["principals"][0],
    }


def attempt(conn, seeded, index=0, **columns):
    """One attempt row written by the owner, `columns` on top of a valid started attempt."""
    tenant = seeded["tenants"][index]
    now = datetime.now(UTC)
    row = {
        "tenant_id": tenant,
        "attempt_id": uuid4(),
        "principal_id": seeded["principals"][index],
        "space_id": seeded["spaces"][index],
        "connection_id": None,
        "label": "Directory",
        "state_hash": uuid4().hex * 2,
        "binding_hash": "b" * 64,
        "nonce_hash": "c" * 64,
        "state": "started",
        "directory_ref": None,
        "created_at": now,
        "expires_at": now + timedelta(minutes=10),
        "consumed_at": None,
        "refusal_code": None,
        "refused_step": None,
        **columns,
    }
    names = ", ".join(row)
    values = ", ".join(f":{name}" for name in row)
    fenced(conn, tenant)
    conn.execute(
        text(f"INSERT INTO execbound.monitor_connect_attempts ({names}) VALUES ({values})"),  # nosec B608 - test literals
        row,
    )
    return row["attempt_id"]


DONE = {"consumed_at": datetime.now(UTC)}


@pytest.mark.parametrize(
    "columns",
    [
        pytest.param({"state": "waiting"}, id="an unknown state"),
        # A directory is known only once a sign-in verified it, and always after.
        pytest.param({"directory_ref": LETTERED}, id="a directory before sign-in"),
        pytest.param({"state": "signed_in"}, id="a sign-in without a directory"),
        pytest.param({**DONE, "state": "consented"}, id="a consent without a directory"),
        pytest.param(
            {"state": "signed_in", "directory_ref": "not-a-directory"}, id="a malformed directory"
        ),
        # A refusal records its code, and only a refusal records a code or a step.
        pytest.param({**DONE, "state": "refused"}, id="a refusal without a code"),
        pytest.param({"refusal_code": "NONCE_MISMATCH"}, id="a code without a refusal"),
        pytest.param({"refused_step": "signed_in"}, id="a step without a refusal"),
        pytest.param(
            {**DONE, "state": "refused", "refusal_code": "x"}, id="a code that is not a code"
        ),
        pytest.param(
            {**DONE, "state": "refused", "refusal_code": "X", "refused_step": "started"},
            id="a step that is not a callback",
        ),
        # A live attempt is unconsumed, and an ended one consumed.
        pytest.param({"consumed_at": datetime.now(UTC)}, id="a live attempt consumed"),
        pytest.param({"state": "expired"}, id="an ended attempt unconsumed"),
        # Ten minutes, never more.
        pytest.param(
            {"expires_at": datetime.now(UTC) + timedelta(minutes=11)}, id="a longer attempt"
        ),
        # A new connection's label, or an existing connection to update, never neither.
        pytest.param({"label": None}, id="neither a label nor a connection"),
        pytest.param({"label": "x" * 97}, id="a long label"),
        pytest.param({"label": "line\nbreak"}, id="a label with a control character"),
        pytest.param({"state_hash": "A" * 64}, id="a hash that is not a digest"),
        pytest.param({"binding_hash": "b" * 63}, id="a short binding digest"),
        pytest.param({"nonce_hash": None}, id="no nonce digest"),
    ],
)
def test_mc1_each_attempt_check_refuses_its_violation(admin_engine, seeded, columns):
    with pytest.raises(IntegrityError):
        with admin_engine.begin() as conn:
            attempt(conn, seeded, **columns)


def test_mc1_an_attempt_keeps_its_state_hash_once_across_the_deployment(admin_engine, seeded):
    digest = "d" * 64
    with admin_engine.begin() as conn:
        attempt(conn, seeded, state_hash=digest)
    with pytest.raises(IntegrityError):
        with admin_engine.begin() as conn:
            attempt(conn, seeded, index=1, state_hash=digest)


def relation_privileges(conn, table, role="execbound_app"):
    """Every table and column privilege `role` holds on `table`, by name."""
    held = set()
    for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
        if conn.execute(
            text("SELECT has_table_privilege(:r, :t, :p)"),
            {"r": role, "t": f"execbound.{table}", "p": privilege},
        ).scalar_one():
            held.add(privilege)
    for privilege in ("SELECT", "INSERT", "UPDATE", "REFERENCES"):
        if conn.execute(
            text("SELECT has_any_column_privilege(:r, :t, :p)"),
            {"r": role, "t": f"execbound.{table}", "p": privilege},
        ).scalar_one():
            held.add(f"column {privilege}")
    return held


def test_mc1_attempts_are_tenant_fenced_and_only_read_by_the_runtime(db, admin_engine, seeded):
    assert set(CONSENT_TABLES) <= set(catalog.TABLES)
    with admin_engine.connect() as conn:
        flags = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = 'execbound.monitor_connect_attempts'::regclass"
            )
        ).one()
        assert tuple(flags) == (True, True)
        policies = (
            conn.execute(
                text(
                    "SELECT policyname, cmd, qual, with_check FROM pg_policies "
                    "WHERE schemaname = 'execbound' AND tablename = 'monitor_connect_attempts'"
                )
            )
            .mappings()
            .all()
        )
        assert [row["policyname"] for row in policies] == ["tenant_isolation"]
        # The initplan form: the setting is read once per statement, not once per row.
        assert "SELECT current_setting" in policies[0]["qual"]
        assert "SELECT current_setting" in policies[0]["with_check"]
        assert relation_privileges(conn, "monitor_connect_attempts") == {
            "SELECT",
            "column SELECT",
        }
    with admin_engine.begin() as conn:
        mine = attempt(conn, seeded)
        attempt(conn, seeded, index=1)
    with db.transaction(seeded["tenants"][0]) as conn:
        seen = conn.execute(
            text("SELECT attempt_id FROM execbound.monitor_connect_attempts")
        ).scalars()
        assert list(seen) == [mine]
    for statement in (
        "UPDATE execbound.monitor_connect_attempts SET state = 'consented'",
        "DELETE FROM execbound.monitor_connect_attempts",
    ):
        with pytest.raises(ProgrammingError) as refused:
            with db.transaction(seeded["tenants"][0]) as conn:
                conn.execute(text(statement))
        assert "permission denied" in str(refused.value.orig)


def test_mc1_directory_claims_grant_the_runtime_nothing_and_check_runtime_holds_it(
    db, admin_engine
):
    assert "monitor_directory_claims" in catalog.PRIVILEGELESS_TABLES
    with admin_engine.connect() as conn:
        assert relation_privileges(conn, "monitor_directory_claims") == set()
        columns = set(
            conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'execbound' AND table_name = 'monitor_directory_claims'"
                )
            ).scalars()
        )
    # No tenant column: a claim names no workspace.
    assert columns == {"directory_key", "claimed_at"}
    with db.engine.connect() as conn:
        check_runtime(conn)
    for grant in (
        "SELECT ON execbound.monitor_directory_claims",
        "SELECT (directory_key) ON execbound.monitor_directory_claims",
        "REFERENCES ON execbound.monitor_directory_claims",
    ):
        try:
            with admin_engine.begin() as conn:
                conn.execute(text(f"GRANT {grant} TO execbound_app"))
            with pytest.raises(UnsafeDatabaseRole, match="^Unsafe runtime table privileges$"):
                with db.engine.connect() as conn:
                    check_runtime(conn)
        finally:
            with admin_engine.begin() as conn:
                conn.execute(text(f"REVOKE {grant} FROM execbound_app"))
    with db.engine.connect() as conn:
        check_runtime(conn)


def claims(admin_engine):
    with admin_engine.connect() as conn:
        return set(
            conn.execute(text("SELECT directory_key FROM execbound.monitor_directory_claims"))
            .scalars()
            .all()
        )


def claim_of(directory: str) -> str:
    return hashlib.sha256(directory.lower().encode()).hexdigest()


def test_mc1_one_active_entra_connection_per_directory_across_every_tenant(admin_engine, seeded):
    with admin_engine.begin() as conn:
        insert(conn, seeded, **CONSENTING, active=True)
    # Another workspace, the same directory spelled in another case: refused by the index,
    # which row security does not limit.
    with pytest.raises(IntegrityError, match="monitor_connections_directory_once"):
        with admin_engine.begin() as conn:
            insert(
                conn,
                seeded,
                index=1,
                **{**CONSENTING, "directory_ref": LETTERED.upper()},
                active=True,
            )
    with pytest.raises(IntegrityError, match="monitor_connections_directory_once"):
        with admin_engine.begin() as conn:
            insert(conn, seeded, index=1, **consented(seeded["principals"][1]), active=True)
    # A revoked connection to it beside the active one, and another directory, are admitted.
    with admin_engine.begin() as conn:
        insert(conn, seeded, index=1, **CONSENTING, active=False, revoked_at=datetime.now(UTC))
        insert(
            conn,
            seeded,
            index=1,
            **consented(seeded["principals"][1], directory_ref=str(uuid4())),
            active=True,
        )


def test_mc1_the_claims_are_the_active_entra_connections(db, admin_engine, seeded):
    other = str(uuid4())
    with admin_engine.begin() as conn:
        # A Tines connection and an inactive Entra connection claim nothing.
        insert(conn, seeded, active=True)
        insert(conn, seeded, **{**ENTRA, "directory_ref": other}, active=False)
    assert claims(admin_engine) == set()
    with admin_engine.begin() as conn:
        held = insert(
            conn, seeded, **{**CONSENTING, "directory_ref": LETTERED.upper()}, active=True
        )
    assert claims(admin_engine) == {claim_of(LETTERED)}
    # Revoking removes the claim in the same statement, and the directory is free.
    with admin_engine.begin() as conn:
        fenced(conn, seeded["tenants"][0])
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET active = false, revoked_at = now() "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": seeded["tenants"][0], "c": held},
        )
    assert claims(admin_engine) == set()
    with admin_engine.begin() as conn:
        insert(conn, seeded, index=1, **consented(seeded["principals"][1]), active=True)
    assert claims(admin_engine) == {claim_of(LETTERED)}
    # Activated again while another workspace holds the directory: refused, claims unchanged.
    with pytest.raises(IntegrityError, match="monitor_connections_directory_once"):
        with admin_engine.begin() as conn:
            fenced(conn, seeded["tenants"][0])
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET active = true, revoked_at = NULL "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": seeded["tenants"][0], "c": held},
            )
    assert claims(admin_engine) == {claim_of(LETTERED)}


def test_mc1_the_runtime_claims_and_frees_a_directory_through_the_trigger(db, admin_engine, seeded):
    """The runtime registers an operator's Entra connection and revokes it with no privilege
    on the claims, which the trigger writes as its owner."""
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id = NULL"))
    admin = authenticate(db, seeded["tokens"][0])
    connection = store.create_connection(
        db,
        admin,
        label="Directory",
        base_url=GRAPH,
        key_fingerprint="ab" * 32,
        kind="entra_agent_id",
        directory_ref=LETTERED,
        client_ref=CLIENT,
    )
    assert claims(admin_engine) == {claim_of(LETTERED)}
    store.revoke_connection(db, admin, connection)
    assert claims(admin_engine) == set()


def test_mc1_the_consent_principal_columns_are_guarded_against_the_scheduler(admin_engine, seeded):
    assert ("monitor_connect_attempts", "principal_id") in GUARDED
    assert ("monitor_connections", "consented_by") in GUARDED
    tenant = seeded["tenants"][0]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        system = UUID(
            conn.execute(text("SELECT execbound.scheduler_actor()")).scalar_one()["principal_id"]
        )
    with pytest.raises(DBAPIError, match="SYSTEM_PRINCIPAL"):
        with admin_engine.begin() as conn:
            attempt(conn, seeded, principal_id=system)
    with admin_engine.begin() as conn:
        connection = insert(conn, seeded, **consented(seeded["principals"][0]), active=True)
    with pytest.raises(DBAPIError, match="SYSTEM_PRINCIPAL"):
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET consented_by = :s "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"s": system, "t": tenant, "c": connection},
            )


def test_mc1_the_consent_functions_are_definers_the_runtime_alone_may_call(admin_engine):
    for name, arguments in CONSENT_SIGNATURES.items():
        assert (name, arguments) in catalog.FUNCTIONS
    with admin_engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS arguments, "
                    "p.prosecdef, p.proconfig, p.prorettype = 'trigger'::regtype AS trigger, "
                    "has_function_privilege('execbound_app', p.oid, 'EXECUTE') AS runtime, "
                    "EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', "
                    "p.proowner))) a WHERE a.grantee = 0) AS public "
                    "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
                ),
                {"names": [*CONSENT_SIGNATURES, "monitor_directory_claim_sync"]},
            )
            .mappings()
            .all()
        )
    by_name = {row["proname"]: row for row in rows}
    assert {
        name: row["arguments"] for name, row in by_name.items() if not row["trigger"]
    } == CONSENT_SIGNATURES
    for name in CONSENT_SIGNATURES:
        row = by_name[name]
        assert row["prosecdef"] is True, name
        assert row["proconfig"] == ["search_path=pg_catalog, pg_temp"], name
        assert row["runtime"] is True and row["public"] is False, name
    # The claims' one writer runs as its owner and is fired, never called.
    sync = by_name["monitor_directory_claim_sync"]
    assert sync["trigger"] and sync["prosecdef"]
    assert sync["proconfig"] == ["search_path=pg_catalog, pg_temp"]
    assert sync["runtime"] is False and sync["public"] is False
    assert catalog.TRIGGER_DEFINERS == frozenset({"monitor_directory_claim_sync"})


def test_mc1_check_runtime_refuses_a_definer_trigger_it_does_not_name(db, admin_engine):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "CREATE FUNCTION execbound.stray_definer_trigger() RETURNS trigger "
                "LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp "
                "AS $$ BEGIN RETURN NEW; END $$"
            )
        )
        conn.execute(text("REVOKE ALL ON FUNCTION execbound.stray_definer_trigger() FROM PUBLIC"))
    try:
        with pytest.raises(UnsafeDatabaseRole, match="^Unsafe administration functions$"):
            with db.engine.connect() as conn:
                check_runtime(conn)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text("DROP FUNCTION execbound.stray_definer_trigger()"))
    with db.engine.connect() as conn:
        check_runtime(conn)


def consent_shape(conn):
    """Every definition the consent migration changes, as the catalog holds it."""
    constraints, indexes, columns, table, _, triggers = shape(conn)
    functions = set(
        conn.execute(
            text(
                "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": [*CONSENT_SIGNATURES, "monitor_directory_claim_sync"]},
        ).scalars()
    )
    tables = set(
        conn.execute(
            text(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'execbound' "
                "AND tablename = ANY(:names)"
            ),
            {"names": list(CONSENT_TABLES)},
        ).scalars()
    )
    nullable = conn.execute(
        text(
            "SELECT NOT attnotnull FROM pg_attribute WHERE attname = 'key_fingerprint' "
            "AND attrelid = 'execbound.monitor_connections'::regclass"
        )
    ).scalar_one()
    return constraints, indexes, columns, table, functions, triggers, tables, nullable


def migration_tenant(admin_engine):
    """A tenant, its space and an ADMIN, written by the owner on an emptied schema."""
    tenant, principal, space = uuid4(), uuid4(), uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
            {"t": tenant, "n": f"Migration {tenant}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, "
                "created_by) VALUES (:t, :s, 'Default', now(), :p)"
            ),
            {"t": tenant, "s": space, "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :p, 'ADMIN')"
            ),
            {"t": tenant, "p": principal},
        )
    return {"tenants": [tenant], "principals": [principal], "spaces": [space]}


def test_mc1_the_consent_downgrade_refuses_what_it_cannot_express_and_otherwise_round_trips(
    admin_engine,
):
    config = alembic_config()
    with admin_engine.connect() as conn:
        head = consent_shape(conn)
    empty_schema(admin_engine)
    command.downgrade(config, CONSENT_TARGET)
    try:
        with admin_engine.connect() as conn:
            upgraded = consent_shape(conn)
        made = migration_tenant(admin_engine)
        tenant = made["tenants"][0]
        with admin_engine.begin() as conn:
            connection = insert(conn, made, **consented(made["principals"][0]), active=True)
        with pytest.raises(RuntimeError, match="consented Microsoft Entra connection"):
            command.downgrade(config, CONSENT_BEFORE)
        with admin_engine.connect() as conn:
            assert consent_shape(conn) == upgraded
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "DELETE FROM execbound.monitor_connections "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": tenant, "c": connection},
            )
            conn.execute(text("DELETE FROM execbound.monitor_directory_claims"))
            attempt(conn, made)
        with pytest.raises(RuntimeError, match="connection attempt"):
            command.downgrade(config, CONSENT_BEFORE)
        with admin_engine.connect() as conn:
            assert consent_shape(conn) == upgraded
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text("DELETE FROM execbound.monitor_connect_attempts WHERE tenant_id = :t"),
                {"t": tenant},
            )
        command.downgrade(config, CONSENT_BEFORE)
        with admin_engine.connect() as conn:
            before = consent_shape(conn)
        constraints, indexes, columns, _, functions, triggers, tables, nullable = before
        assert functions == set() and tables == set()
        assert "monitor_directory_claim_sync" not in triggers
        assert "system_guard_consented_by" not in triggers
        assert "monitor_connections_directory_once" not in indexes
        assert {name for name, _ in columns}.isdisjoint({"consented_at", "consented_by"})
        assert "platform_app" not in constraints["monitor_connections_credential_mode_check"]
        # The key's fingerprint is required again.
        assert nullable is False
        command.upgrade(config, CONSENT_TARGET)
        with admin_engine.connect() as conn:
            assert consent_shape(conn) == upgraded
        command.downgrade(config, CONSENT_BEFORE)
        with admin_engine.connect() as conn:
            assert consent_shape(conn) == before
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
    with admin_engine.connect() as conn:
        assert consent_shape(conn) == head


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


START = "SELECT execbound.admin_start_connect(:a, :s, :at, :c, :label, :sh, :bh, :nh)"
SIGNIN = "SELECT execbound.admin_record_signin(:at, :sh, :bh, :nh, :dir)"
COMPLETE = "SELECT execbound.admin_complete_consent(:at, :sh, :bh, :dir, :client)"
REFUSE = "SELECT execbound.admin_refuse_connect(:at, :sh, :step, :code)"


def answer(db, tenant, statement, **values):
    """A definer function's result (None for one that returns nothing), or the code it
    raised."""
    try:
        with db.transaction(tenant) as conn:
            result = conn.execute(text(statement), values).scalar_one()
    except DBAPIError as exc:
        return exc.orig.diag.message_primary
    # The driver reads `void` as an empty string.
    return None if result == "" else result


class Flow:
    """One connect attempt's secrets, its start values and its callbacks' values."""

    def __init__(self, admin, space, *, label="Directory", connection=None):
        self.attempt = uuid4()
        secret = uuid4().hex
        self.state = f"mc1.{admin.tenant_id}.{self.attempt}.{secret}"
        self.binding = f"binding-{secret}"
        self.nonce = f"nonce-{secret}"
        self.start = {
            "a": admin.principal_id,
            "s": space,
            "at": self.attempt,
            "c": connection,
            "label": label,
            "sh": digest(self.state),
            "bh": digest(self.binding),
            "nh": digest(self.nonce),
        }

    def signin(self, directory=LETTERED, **overrides):
        return {
            "at": self.attempt,
            "sh": digest(self.state),
            "bh": digest(self.binding),
            "nh": digest(self.nonce),
            "dir": directory,
            **overrides,
        }

    def complete(self, directory=LETTERED, **overrides):
        return {
            "at": self.attempt,
            "sh": digest(self.state),
            "bh": digest(self.binding),
            "dir": directory,
            "client": CLIENT,
            **overrides,
        }


def the_attempt(admin_engine, tenant, attempt_id):
    with admin_engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_connect_attempts "
                    "WHERE tenant_id = :t AND attempt_id = :a"
                ),
                {"t": tenant, "a": attempt_id},
            )
            .mappings()
            .one()
        )


def age(admin_engine, tenant, *, minutes, attempt_id=None):
    """Move attempts' creation back, keeping each one's ten minutes."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connect_attempts "
                "SET created_at = created_at - make_interval(mins => :m), "
                "expires_at = expires_at - make_interval(mins => :m) "
                "WHERE tenant_id = :t AND (CAST(:a AS uuid) IS NULL OR attempt_id = :a)"
            ),
            {"m": minutes, "t": tenant, "a": attempt_id},
        )


@pytest.fixture
def admins(db, admin_engine, seeded):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id = NULL"))
    return [authenticate(db, token) for token in seeded["tokens"]]


def test_mc1_starting_a_connect_applies_the_connection_rules_before_microsoft(
    db, admin_engine, seeded, admins
):
    admin = admins[0]
    tenant, space = admin.tenant_id, seeded["spaces"][0]
    flow = Flow(admin, space)
    assert answer(db, tenant, START, **flow.start) is None
    row = the_attempt(admin_engine, tenant, flow.attempt)
    assert row["state"] == "started" and row["principal_id"] == admin.principal_id
    assert row["space_id"] == space and row["label"] == "Directory"
    assert row["state_hash"] == digest(flow.state) and row["directory_ref"] is None
    assert row["expires_at"] - row["created_at"] == timedelta(minutes=10)
    # Shapes the row could not hold are refused before anything is written.
    for field, value in (
        ("sh", "A" * 64),
        ("bh", None),
        ("nh", "c" * 63),
        ("label", None),
        ("label", "x" * 97),
        ("label", "line\nbreak"),
    ):
        refused = Flow(admin, space)
        assert answer(db, tenant, START, **{**refused.start, field: value}) == "INVALID_INPUT"
    # Not an administrator, and not this workspace's.
    for actor in (uuid4(), seeded["principals"][1]):
        refused = Flow(admin, space)
        assert answer(db, tenant, START, **{**refused.start, "a": actor}) == "INVALID_ACTOR"
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
        archived = make_space(conn, tenant, "Archived", created_by=admin.principal_id)
        conn.execute(
            text(
                "UPDATE execbound.spaces SET archived_at = now() "
                "WHERE tenant_id = :t AND space_id = :s"
            ),
            {"t": tenant, "s": archived},
        )
    assert answer(db, tenant, START, **Flow(admin, archived).start) == "SPACE_ARCHIVED"
    assert answer(db, tenant, START, **Flow(admin, uuid4()).start) == "INVALID_SPACE"
    # A space that already has an active Entra connection, of any mode, takes no second.
    with admin_engine.begin() as conn:
        insert(conn, seeded, **ENTRA, active=True, space_id=other)
    assert answer(db, tenant, START, **Flow(admin, other).start) == "CONNECTION_EXISTS"
    # A membership narrows an administrator to the spaces they administer.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        seat(conn, tenant, other, admin.principal_id, "ADMIN")
    assert answer(db, tenant, START, **Flow(admin, space).start) == "INVALID_ACTOR"
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.space_members WHERE tenant_id = :t"), {"t": tenant}
        )
    # Nothing refused above was written.
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.monitor_connect_attempts WHERE tenant_id=:t"),
                {"t": tenant},
            ).scalar_one()
            == 1
        )


def test_mc1_a_workspace_holds_five_live_attempts_and_twenty_a_day(
    db, admin_engine, seeded, admins
):
    admin = admins[0]
    tenant, space = admin.tenant_id, seeded["spaces"][0]
    for _ in range(5):
        assert answer(db, tenant, START, **Flow(admin, space).start) is None
    assert answer(db, tenant, START, **Flow(admin, space).start) == "ATTEMPT_CAPACITY"
    # Once they lapse they are recorded as expired and no longer live.
    age(admin_engine, tenant, minutes=11)
    assert answer(db, tenant, START, **Flow(admin, space).start) is None
    with admin_engine.connect() as conn:
        states = conn.execute(
            text(
                "SELECT state, count(*), count(consumed_at) "
                "FROM execbound.monitor_connect_attempts "
                "WHERE tenant_id = :t GROUP BY state ORDER BY state"
            ),
            {"t": tenant},
        ).all()
    assert [tuple(row) for row in states] == [("expired", 5, 5), ("started", 1, 0)]
    # Twenty in a rolling day, whatever became of them.
    for _ in range(14):
        age(admin_engine, tenant, minutes=11)
        assert answer(db, tenant, START, **Flow(admin, space).start) is None
    assert answer(db, tenant, START, **Flow(admin, space).start) == "ATTEMPT_CAPACITY"
    age(admin_engine, tenant, minutes=24 * 60)
    assert answer(db, tenant, START, **Flow(admin, space).start) is None


def test_mc1_a_full_workspace_starts_no_connect(db, admin_engine, seeded, admins):
    admin = admins[0]
    tenant = admin.tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        empty = make_space(conn, tenant, "Empty", created_by=admin.principal_id)
        for _ in range(store.MAX_CONNECTIONS):
            insert(conn, seeded)
    assert answer(db, tenant, START, **Flow(admin, empty).start) == "CONNECTION_CAPACITY"


def test_mc1_updating_consent_starts_only_for_an_active_consented_connection(
    db, admin_engine, seeded, admins
):
    admin = admins[0]
    tenant, space = admin.tenant_id, seeded["spaces"][0]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
        filed = insert(conn, seeded, **{**ENTRA, "directory_ref": str(uuid4())}, active=True)
        platform = insert(
            conn, seeded, **consented(admin.principal_id), active=True, space_id=other
        )
    # An operator's key file is replaced on its host, not consented to.
    update = Flow(admin, space, label=None, connection=filed)
    assert answer(db, tenant, START, **update.start) == "INVALID_STATE"
    # An update names no label, and its connection's own space.
    labelled = Flow(admin, other, connection=platform)
    assert answer(db, tenant, START, **labelled.start) == "INVALID_INPUT"
    elsewhere = Flow(admin, space, label=None, connection=platform)
    assert answer(db, tenant, START, **elsewhere.start) == "INVALID_INPUT"
    update = Flow(admin, other, label=None, connection=platform)
    assert answer(db, tenant, START, **update.start) is None
    row = the_attempt(admin_engine, tenant, update.attempt)
    assert row["connection_id"] == platform and row["label"] is None


def test_mc1_a_sign_in_and_a_consent_follow_their_attempt(db, admin_engine, seeded, admins):
    admin = admins[0]
    tenant, space = admin.tenant_id, seeded["spaces"][0]
    flow = Flow(admin, space)
    assert answer(db, tenant, START, **flow.start) is None
    # Consent before a sign-in is out of order.
    assert answer(db, tenant, COMPLETE, **flow.complete()) == "OUT_OF_ORDER"
    for overrides, code in (
        ({"sh": digest("mc1.other")}, "INVALID_STATE"),
        ({"at": uuid4()}, "INVALID_STATE"),
        ({"bh": digest("another browser")}, "BINDING_MISMATCH"),
        ({"nh": digest("another nonce")}, "NONCE_MISMATCH"),
        ({"dir": "not-a-directory"}, "INVALID_INPUT"),
    ):
        assert answer(db, tenant, SIGNIN, **flow.signin(**overrides)) == code, overrides
    assert the_attempt(admin_engine, tenant, flow.attempt)["state"] == "started"
    # The directory is kept in one spelling.
    assert answer(db, tenant, SIGNIN, **flow.signin(LETTERED.upper())) is None
    row = the_attempt(admin_engine, tenant, flow.attempt)
    assert row["state"] == "signed_in" and row["directory_ref"] == LETTERED
    assert answer(db, tenant, SIGNIN, **flow.signin()) == "OUT_OF_ORDER"
    for overrides, code in (
        ({"dir": str(uuid4())}, "DIRECTORY_MISMATCH"),
        ({"bh": digest("another browser")}, "BINDING_MISMATCH"),
        ({"client": "not-a-client"}, "INVALID_INPUT"),
    ):
        assert answer(db, tenant, COMPLETE, **flow.complete(**overrides)) == code, overrides
    made = answer(db, tenant, COMPLETE, **flow.complete(LETTERED.upper()))
    assert isinstance(made, UUID)
    connection = connection_row(admin_engine, tenant, made)
    assert {
        key: connection[key]
        for key in (
            "kind",
            "credential_mode",
            "base_url",
            "directory_ref",
            "client_ref",
            "key_fingerprint",
            "label",
            "space_id",
            "created_by",
            "consented_by",
            "collect_requested_by",
            "active",
        )
    } == {
        "kind": "entra_agent_id",
        "credential_mode": "platform_app",
        "base_url": GRAPH,
        "directory_ref": LETTERED,
        "client_ref": CLIENT,
        "key_fingerprint": None,
        "label": "Directory",
        "space_id": space,
        "created_by": admin.principal_id,
        "consented_by": admin.principal_id,
        "collect_requested_by": admin.principal_id,
        "active": True,
    }
    assert connection["consented_at"] is not None
    row = the_attempt(admin_engine, tenant, flow.attempt)
    assert row["state"] == "consented" and row["consumed_at"] is not None
    assert row["connection_id"] == made
    assert claims(admin_engine) == {claim_of(LETTERED)}
    # A reused state completes nothing, and a refusal cannot rewrite how the attempt ended.
    assert answer(db, tenant, COMPLETE, **flow.complete()) == "ATTEMPT_USED"
    assert answer(db, tenant, SIGNIN, **flow.signin()) == "ATTEMPT_USED"
    refusal = {"at": flow.attempt, "sh": digest(flow.state), "step": "consented", "code": "X"}
    assert answer(db, tenant, REFUSE, **refusal) is False
    assert the_attempt(admin_engine, tenant, flow.attempt)["state"] == "consented"


def test_mc1_a_directory_connected_anywhere_is_refused_at_sign_in_and_at_consent(
    db, admin_engine, seeded, admins
):
    first, second = admins
    a = Flow(first, seeded["spaces"][0])
    b = Flow(second, seeded["spaces"][1])
    for admin, flow in ((first, a), (second, b)):
        assert answer(db, admin.tenant_id, START, **flow.start) is None
    # Both sign in before either consents; the first to consent holds the directory.
    for admin, flow in ((first, a), (second, b)):
        assert answer(db, admin.tenant_id, SIGNIN, **flow.signin()) is None
    assert isinstance(answer(db, second.tenant_id, COMPLETE, **b.complete()), UUID)
    assert answer(db, first.tenant_id, COMPLETE, **a.complete()) == "DIRECTORY_UNAVAILABLE"
    # And once it is held, a sign-in for it never reaches consent.
    again = Flow(first, seeded["spaces"][0])
    assert answer(db, first.tenant_id, START, **again.start) is None
    assert answer(db, first.tenant_id, SIGNIN, **again.signin()) == "DIRECTORY_UNAVAILABLE"


def waiting_on_a_lock(admin_engine, *, within=4.0):
    """Wait until a backend of this database waits on another transaction's lock, inside the
    five seconds `Database.transaction` allows a lock wait."""
    deadline = time.monotonic() + within
    with admin_engine.connect() as conn:
        while time.monotonic() < deadline:
            found = conn.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                    "AND state = 'active' AND wait_event_type = 'Lock'"
                )
            ).scalar_one()
            conn.rollback()
            if found:
                return
            time.sleep(0.02)
    raise AssertionError("the second consent never waited on the first")


def test_mc1_two_workspaces_consenting_for_one_directory_at_once_connect_it_once(
    db, admin_engine, seeded, admins
):
    """Two workspaces complete consent for the same directory at the same moment, each on its
    own connection. Neither sees the other's claim, which is not yet committed, so the unique
    index decides: the second waits on the first, and once the first commits it is refused
    `DIRECTORY_UNAVAILABLE`, not a database error, and its attempt can be ended with that code."""
    first, second = admins
    a = Flow(first, seeded["spaces"][0])
    b = Flow(second, seeded["spaces"][1])
    for admin, flow in ((first, a), (second, b)):
        assert answer(db, admin.tenant_id, START, **flow.start) is None
        assert answer(db, admin.tenant_id, SIGNIN, **flow.signin()) is None
    with ThreadPoolExecutor(max_workers=1) as pool:
        with db.transaction(first.tenant_id) as conn:
            made = conn.execute(text(COMPLETE), a.complete()).scalar_one()
            racing = pool.submit(answer, db, second.tenant_id, COMPLETE, **b.complete())
            waiting_on_a_lock(admin_engine)
            assert not racing.done()
        # The first has committed while the second still waits on it.
        assert racing.result(timeout=10) == "DIRECTORY_UNAVAILABLE"
    with admin_engine.connect() as conn:
        active = conn.execute(
            text(
                "SELECT tenant_id, connection_id FROM execbound.monitor_connections "
                "WHERE kind = 'entra_agent_id' AND active"
            )
        ).all()
    assert [tuple(row) for row in active] == [(first.tenant_id, made)]
    assert claims(admin_engine) == {claim_of(LETTERED)}
    assert the_attempt(admin_engine, second.tenant_id, b.attempt)["state"] == "signed_in"
    refusal = {
        "at": b.attempt,
        "sh": digest(b.state),
        "step": "consented",
        "code": "DIRECTORY_UNAVAILABLE",
    }
    assert answer(db, second.tenant_id, REFUSE, **refusal) is True
    ended = the_attempt(admin_engine, second.tenant_id, b.attempt)
    assert (ended["state"], ended["refusal_code"], ended["refused_step"]) == (
        "refused",
        "DIRECTORY_UNAVAILABLE",
        "consented",
    )


def test_mc1_an_attempt_ends_after_ten_minutes_and_a_refusal_records_its_step(
    db, admin_engine, seeded, admins
):
    admin = admins[0]
    tenant, space = admin.tenant_id, seeded["spaces"][0]
    flow = Flow(admin, space)
    assert answer(db, tenant, START, **flow.start) is None
    age(admin_engine, tenant, minutes=10, attempt_id=flow.attempt)
    assert answer(db, tenant, SIGNIN, **flow.signin()) == "ATTEMPT_EXPIRED"
    refusal = {"at": flow.attempt, "sh": digest(flow.state), "step": "signed_in"}
    for code in ("lower", "X" * 49):
        assert answer(db, tenant, REFUSE, **refusal, code=code) == "INVALID_INPUT"
    assert answer(db, tenant, REFUSE, **{**refusal, "step": "started"}, code="X") == (
        "INVALID_INPUT"
    )
    # Only the holder of the state refuses an attempt.
    assert answer(db, tenant, REFUSE, **{**refusal, "sh": digest("x")}, code="X") is False
    assert answer(db, tenant, REFUSE, **refusal, code="ATTEMPT_EXPIRED") is True
    row = the_attempt(admin_engine, tenant, flow.attempt)
    assert (row["state"], row["refusal_code"], row["refused_step"]) == (
        "refused",
        "ATTEMPT_EXPIRED",
        "signed_in",
    )
    assert row["consumed_at"] is not None
    assert answer(db, tenant, REFUSE, **refusal, code="X") is False
    # Without the tenant fence nothing is read or written.
    with pytest.raises(DBAPIError) as refused:
        with db.engine.begin() as conn:
            conn.execute(text(REFUSE), {**refusal, "code": "X"})
    assert refused.value.orig.diag.message_primary == "INVALID_TENANT"


def test_mc1_the_attempts_principal_must_still_administer_its_space_at_each_step(
    db, admin_engine, seeded, admins
):
    admin = admins[0]
    tenant, space = admin.tenant_id, seeded["spaces"][0]
    before_signin, before_consent = Flow(admin, space), Flow(admin, space)
    for flow in (before_signin, before_consent):
        assert answer(db, tenant, START, **flow.start) is None
    assert answer(db, tenant, SIGNIN, **before_consent.signin()) is None
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": admin.principal_id},
        )
    assert answer(db, tenant, SIGNIN, **before_signin.signin()) == "INVALID_ACTOR"
    assert answer(db, tenant, COMPLETE, **before_consent.complete()) == "INVALID_ACTOR"
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.monitor_connections WHERE tenant_id = :t"),
                {"t": tenant},
            ).scalar_one()
            == 0
        )


def test_mc1_updating_consent_keeps_the_connection_and_its_directory(
    db, admin_engine, seeded, admins
):
    admin = admins[0]
    tenant, space = admin.tenant_id, seeded["spaces"][0]
    first = Flow(admin, space)
    assert answer(db, tenant, START, **first.start) is None
    assert answer(db, tenant, SIGNIN, **first.signin()) is None
    made = answer(db, tenant, COMPLETE, **first.complete())
    before = connection_row(admin_engine, tenant, made)
    # Another directory cannot take over the connection.
    other = Flow(admin, space, label=None, connection=made)
    assert answer(db, tenant, START, **other.start) is None
    assert answer(db, tenant, SIGNIN, **other.signin(str(uuid4()))) == "DIRECTORY_MISMATCH"
    update = Flow(admin, space, label=None, connection=made)
    assert answer(db, tenant, START, **update.start) is None
    # Its own directory's claim is its own, not another workspace's.
    assert answer(db, tenant, SIGNIN, **update.signin()) is None
    assert answer(db, tenant, COMPLETE, **update.complete()) == made
    after = connection_row(admin_engine, tenant, made)
    assert after["consented_at"] >= before["consented_at"]
    assert after["directory_ref"] == LETTERED and after["active"] is True
    assert the_attempt(admin_engine, tenant, update.attempt)["connection_id"] == made
    # Revoked, it takes no new consent.
    store.revoke_connection(db, admin, made)
    assert answer(db, tenant, COMPLETE, **update.complete()) == "ATTEMPT_USED"
    late = Flow(admin, space, label=None, connection=made)
    assert answer(db, tenant, START, **late.start) == "INVALID_STATE"


def test_mc1_the_directory_rule_waits_for_shared_directories_to_be_resolved_without_bypass(
    restricted,
):
    """Run as an owner without BYPASSRLS, as the hosted database's is: under FORCE an unlifted
    count would see no tenant and let the index fail on the first shared directory, or create
    no claim for any connection."""
    engine, config, _role = restricted
    command.upgrade(config, CONSENT_BEFORE)
    made = []
    directories = (LETTERED, LETTERED.upper(), str(uuid4()))
    for directory in directories:
        tenant, principal, space = uuid4(), uuid4(), uuid4()
        with engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
                {"t": tenant, "n": f"Directory {tenant}"},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, "
                    "created_by) VALUES (:t, :s, 'Default', now(), :p)"
                ),
                {"t": tenant, "s": space, "p": principal},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                    "VALUES (:t, :p, 'ADMIN')"
                ),
                {"t": tenant, "p": principal},
            )
            connection = insert(
                conn,
                {"tenants": [tenant], "principals": [principal], "spaces": [space]},
                **{**ENTRA, "directory_ref": directory},
                active=True,
            )
        made.append((tenant, connection))
    with pytest.raises(RuntimeError) as refused:
        command.upgrade(config, CONSENT_TARGET)
    message = str(refused.value)
    assert "1 directory" in message
    # The sentence names a count, never a workspace or a connection.
    for tenant, connection in made:
        assert str(tenant) not in message and str(connection) not in message
    with engine.connect() as conn:
        assert (
            conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
            == CONSENT_BEFORE
        )
    tenant, connection = made[1]
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET active = false, revoked_at = now() "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": tenant, "c": connection},
        )
    command.upgrade(config, CONSENT_TARGET)
    with engine.connect() as conn:
        held = set(
            conn.execute(text("SELECT directory_key FROM execbound.monitor_directory_claims"))
            .scalars()
            .all()
        )
        forced = conn.execute(
            text(
                "SELECT relforcerowsecurity FROM pg_class "
                "WHERE oid = 'execbound.monitor_connections'::regclass"
            )
        ).scalar_one()
    # One claim per active Entra connection, backfilled across every tenant.
    assert held == {claim_of(LETTERED), claim_of(directories[2])}
    assert forced is True


def test_mc1_an_operator_cannot_register_a_directory_another_workspace_has_connected(
    db, admin_engine, seeded, admins
):
    """`create-connection` for a directory any workspace already reads is refused by name,
    never as a database failure, and says nothing of the workspace that holds it."""
    first, second = admins

    def register(admin):
        return store.create_connection(
            db,
            admin,
            label="Directory",
            base_url=GRAPH,
            key_fingerprint="ab" * 32,
            kind="entra_agent_id",
            directory_ref=LETTERED,
            client_ref=CLIENT,
        )

    held = register(first)
    with pytest.raises(store.MonitorError) as refused:
        register(second)
    assert refused.value.code == "DIRECTORY_UNAVAILABLE"
    assert str(first.tenant_id) not in str(refused.value)
    assert str(held) not in str(refused.value)
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.monitor_connections WHERE tenant_id = :t"),
                {"t": second.tenant_id},
            ).scalar_one()
            == 0
        )


CREATOR_BEFORE = "0089_assurance_carry"
CREATOR_TARGET = "0090_monitor_source_creator"


def source(conn, seeded, index=0, **columns):
    """One reporting source written by the owner, with `columns` on top of a valid row."""
    tenant, space = seeded["tenants"][index], seeded["spaces"][index]
    now = datetime.now(UTC)
    row = {
        "tenant_id": tenant,
        "source_id": uuid4(),
        "label": "Synthetic story",
        "story_id": f"story-{uuid4().hex[:8]}",
        "token_hash": hashlib.sha256(uuid4().bytes).hexdigest(),
        "created_at": now,
        "expires_at": now + timedelta(days=1),
        "heartbeat_seconds": 300,
        "rate_window_at": now,
        "space_id": space,
        **columns,
    }
    names = ", ".join(row)
    values = ", ".join(f":{name}" for name in row)
    fenced(conn, tenant)
    conn.execute(
        text(f"INSERT INTO execbound.monitor_sources ({names}) VALUES ({values})"),  # nosec B608 - test literals
        row,
    )
    return row["source_id"]


def creator_shape(conn):
    """Every definition the creator migration changes, as the catalog holds it."""
    constraints = dict(
        conn.execute(
            text(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'execbound.monitor_sources'::regclass"
            )
        ).all()
    )
    indexes = dict(
        conn.execute(
            text(
                "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'execbound' "
                "AND tablename = 'monitor_sources'"
            )
        ).all()
    )
    columns = conn.execute(
        text(
            "SELECT a.attname, CAST(a.attacl AS text), a.attnotnull FROM pg_attribute a "
            "WHERE a.attrelid = 'execbound.monitor_sources'::regclass AND a.attnum > 0 "
            "AND NOT a.attisdropped ORDER BY a.attnum"
        )
    ).all()
    table = conn.execute(
        text(
            "SELECT CAST(relacl AS text), relforcerowsecurity FROM pg_class "
            "WHERE oid = 'execbound.monitor_sources'::regclass"
        )
    ).one()
    return constraints, indexes, tuple(columns), tuple(table)


def test_mc1_a_source_records_who_minted_it_and_nobody_may_change_that(db, admin_engine, seeded):
    """`created_by` names a principal of the source's own tenant or nobody (a source minted
    before the column existed), and the runtime writes it once, at insert, and never again."""
    with admin_engine.connect() as conn:
        constraints, indexes, columns, _ = creator_shape(conn)
    assert ("created_by", None, False) in columns
    assert constraints["monitor_sources_created_by_fkey"] == (
        "FOREIGN KEY (tenant_id, created_by) REFERENCES execbound.principals(tenant_id, "
        "principal_id)"
    )
    assert "monitor_sources_created_by" in indexes
    principal = seeded["principals"][0]
    with admin_engine.begin() as conn:
        minted = source(conn, seeded, created_by=principal)
        earlier = source(conn, seeded)
    with admin_engine.connect() as conn:
        fenced(conn, seeded["tenants"][0])
        by = dict(
            conn.execute(text("SELECT source_id, created_by FROM execbound.monitor_sources")).all()
        )
    assert by == {minted: principal, earlier: None}
    # Another tenant's principal is nobody here.
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        source(conn, seeded, created_by=seeded["principals"][1])
    tenant = seeded["tenants"][0]
    with pytest.raises(ProgrammingError, match="permission denied"):
        with db.transaction(tenant) as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_sources SET created_by = NULL "
                    "WHERE tenant_id = :t AND source_id = :s"
                ),
                {"t": tenant, "s": minted},
            )
    assert "created_by" not in catalog.UPDATE_COLUMNS["monitor_sources"]
    with db.transaction(tenant) as conn:
        check_runtime(conn)


def test_mc1_the_creator_downgrade_round_trips_and_keeps_every_source(admin_engine):
    config = alembic_config()
    with admin_engine.connect() as conn:
        head = creator_shape(conn)
    empty_schema(admin_engine)
    command.downgrade(config, CREATOR_TARGET)
    try:
        with admin_engine.connect() as conn:
            upgraded = creator_shape(conn)
        made = migration_tenant(admin_engine)
        with admin_engine.begin() as conn:
            kept = source(conn, made, created_by=made["principals"][0])
        command.downgrade(config, CREATOR_BEFORE)
        with admin_engine.connect() as conn:
            before = creator_shape(conn)
        constraints, indexes, columns, _ = before
        assert "created_by" not in {column[0] for column in columns}
        assert "monitor_sources_created_by_fkey" not in constraints
        assert "monitor_sources_created_by" not in indexes
        command.upgrade(config, CREATOR_TARGET)
        with admin_engine.connect() as conn:
            assert creator_shape(conn) == upgraded
            fenced(conn, made["tenants"][0])
            # The source is kept; who minted it is not something the schema below could hold.
            assert conn.execute(
                text("SELECT created_by FROM execbound.monitor_sources WHERE source_id = :s"),
                {"s": kept},
            ).one() == (None,)
        command.downgrade(config, CREATOR_BEFORE)
        with admin_engine.connect() as conn:
            assert creator_shape(conn) == before
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
    with admin_engine.connect() as conn:
        assert creator_shape(conn) == head
