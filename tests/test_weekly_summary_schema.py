# SPDX-License-Identifier: AGPL-3.0-only
"""The weekly summary's tables and definer functions (#678): HV11.

Forced row security and the tenant policy on both tables, the runtime role's exact grants,
the enqueue fenced to one tenant, the three owner-only reads across tenants returning
identifiers or a count, the unsubscribe that ends only a matching active subscription, and the
downgrade. Every definer function is proven twice: as the local owner, which bypasses row
security and so would pass a cross-tenant write vacuously, and as the `restricted` owner, which
does not, as a managed host's owner does not.
"""

import hashlib
import os
import secrets
from datetime import UTC, date, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_dormant_catalog import alembic_config, empty_schema
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted  # noqa: F401
from test_teammate_invitations import workspace

from execbound.connection import with_database_name
from execbound.db import Database, check_runtime

TABLES = ("weekly_summary_subscriptions", "weekly_summary_messages")
FUNCTIONS = (
    "weekly_summary_tenants(timestamptz)",
    "weekly_summary_enqueue(date, timestamptz)",
    "weekly_summary_due(timestamptz, integer)",
    "weekly_summary_sent(timestamptz)",
    "weekly_summary_unsubscribe(uuid, text, timestamptz)",
)


def now() -> datetime:
    return datetime.now(UTC)


def monday(moment: datetime) -> date:
    day = moment.date()
    return day - timedelta(days=day.weekday())


def principal(engine, tenant: UUID, kind: str = "ADMIN", *, space: UUID | None = None) -> UUID:
    """A principal of the tenant; an agent belongs to a space, as the schema requires."""
    found = uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, space_id) "
                "VALUES (:t, :p, :k, :s)"
            ),
            {"t": tenant, "p": found, "k": kind, "s": space},
        )
    return found


def subscribe(db, tenant: UUID, who: UUID, at: datetime | None = None) -> None:
    """The runtime role's own insert, inside the tenant's fence, as the settings route makes it."""
    with db.transaction(tenant) as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.weekly_summary_subscriptions "
                "(tenant_id, principal_id, subscribed_at) VALUES (:t, :p, :n)"
            ),
            {"t": tenant, "p": who, "n": at or now()},
        )


def end(db, tenant: UUID, who: UUID) -> None:
    with db.transaction(tenant) as conn:
        conn.execute(
            text(
                "UPDATE execbound.weekly_summary_subscriptions SET ended_at=:n, "
                "ended_via='SETTINGS' WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "p": who, "n": now()},
        )


def enqueue(db, tenant: UUID | None, week: date, at: datetime | None = None) -> int:
    with db.transaction(tenant if tenant is not None else uuid4()) as conn:
        if tenant is None:
            conn.execute(text("SELECT set_config('execbound.tenant_id', '', true)"))
        return int(
            conn.execute(
                text("SELECT execbound.weekly_summary_enqueue(:w, :n)"),
                {"w": week, "n": at or now()},
            ).scalar_one()
        )


def messages(engine, tenant: UUID) -> list[dict]:
    with engine.begin() as conn:
        fenced(conn, tenant)
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT * FROM execbound.weekly_summary_messages WHERE tenant_id=:t "
                    "ORDER BY principal_id"
                ),
                {"t": tenant},
            ).mappings()
        ]


def keyed(db, tenant: UUID, message: UUID) -> str:
    """A message's unsubscribe secret minted and its hash stored, as the drain stores it."""
    secret = secrets.token_urlsafe(32)
    digest = hashlib.sha256(secret.encode()).hexdigest()
    with db.transaction(tenant) as conn:
        conn.execute(
            text(
                "UPDATE execbound.weekly_summary_messages SET unsubscribe_hash=:h "
                "WHERE tenant_id=:t AND message_id=:m"
            ),
            {"t": tenant, "m": message, "h": digest},
        )
    return digest


def unsubscribe(db, tenant: UUID, message: UUID, digest: str):
    with db.transaction(tenant) as conn:
        return conn.execute(
            text("SELECT execbound.weekly_summary_unsubscribe(:m, :h, :n)"),
            {"m": message, "h": digest, "n": now()},
        ).scalar_one()


def active(engine, tenant: UUID, who: UUID) -> bool:
    with engine.begin() as conn:
        fenced(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT ended_at IS NULL FROM execbound.weekly_summary_subscriptions "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": tenant, "p": who},
            ).scalar_one()
            is True
        )


def test_hv11_both_tables_force_row_security_under_the_tenant_policy(admin_engine):
    with admin_engine.connect() as conn:
        for table in TABLES:
            row = conn.execute(
                text(
                    "SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid=c.relnamespace "
                    "WHERE n.nspname='execbound' AND c.relname=:t"
                ),
                {"t": table},
            ).one()
            assert tuple(row) == (True, True), table
            policies = dict(
                conn.execute(
                    text(
                        "SELECT polname, polcmd FROM pg_policy p JOIN pg_class c "
                        "ON c.oid=p.polrelid WHERE c.relname=:t"
                    ),
                    {"t": table},
                ).all()
            )
            assert policies == {"tenant_isolation": "*", "owner_drain": "r"}, table
        # The rejection index the value report counts with (0077).
        assert conn.execute(
            text("SELECT 1 FROM pg_indexes WHERE indexname='audit_events_rejected'")
        ).scalar_one_or_none()


def test_hv11b_the_runtime_role_holds_exactly_its_grants(admin_engine):
    with admin_engine.connect() as conn:

        def table(name: str, privilege: str) -> bool:
            return bool(
                conn.execute(
                    text("SELECT has_table_privilege('execbound_app', :t, :p)"),
                    {"t": f"execbound.{name}", "p": privilege},
                ).scalar_one()
            )

        def column(name: str, column: str, privilege: str) -> bool:
            return bool(
                conn.execute(
                    text("SELECT has_column_privilege('execbound_app', :t, :c, :p)"),
                    {"t": f"execbound.{name}", "c": column, "p": privilege},
                ).scalar_one()
            )

        def columns(name: str) -> list[str]:
            return list(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema='execbound' AND table_name=:t"
                    ),
                    {"t": name},
                ).scalars()
            )

        subscriptions, outbox = TABLES
        assert table(subscriptions, "SELECT") and table(subscriptions, "INSERT")
        assert {c for c in columns(subscriptions) if column(subscriptions, c, "UPDATE")} == {
            "subscribed_at",
            "ended_at",
            "ended_via",
        }
        assert table(outbox, "SELECT") and not table(outbox, "INSERT")
        assert {c for c in columns(outbox) if column(outbox, c, "UPDATE")} == {
            "state",
            "attempts",
            "next_attempt_at",
            "lease_until",
            "lease_token",
            "delivered_at",
            "last_error",
            "unsubscribe_hash",
        }
        for name in TABLES:
            assert not table(name, "DELETE") and not table(name, "TRUNCATE"), name
        for signature in FUNCTIONS:
            assert conn.execute(
                text("SELECT has_function_privilege('execbound_app', :f, 'EXECUTE')"),
                {"f": f"execbound.{signature}"},
            ).scalar_one(), signature
            assert not conn.execute(
                text("SELECT has_function_privilege('public', :f, 'EXECUTE')"),
                {"f": f"execbound.{signature}"},
            ).scalar_one(), signature


def test_hv11c_enqueue_makes_one_message_per_subscriber_and_week(db, admin_engine):
    here = workspace(admin_engine, name="Summaries")
    there = workspace(admin_engine, name="Elsewhere")
    asleep = workspace(admin_engine, name="Closed")
    tenant = here["tenant_id"]
    approver = principal(admin_engine, tenant, "HUMAN_APPROVER")
    ended = principal(admin_engine, tenant)
    inactive = principal(admin_engine, tenant)
    agent = principal(admin_engine, tenant, "AGENT", space=here["space"])
    for who in (here["admin"], approver, ended, inactive, agent):
        subscribe(db, tenant, who)
    end(db, tenant, ended)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.principals SET active=false "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "p": inactive},
        )
    subscribe(db, there["tenant_id"], there["admin"])
    subscribe(db, asleep["tenant_id"], asleep["admin"])
    with admin_engine.begin() as conn:
        fenced(conn, asleep["tenant_id"])
        conn.execute(
            text("UPDATE execbound.tenants SET active=false WHERE tenant_id=:t"),
            {"t": asleep["tenant_id"]},
        )
    week = monday(now())
    assert enqueue(db, tenant, week) == 2
    assert {row["principal_id"] for row in messages(admin_engine, tenant)} == {
        here["admin"],
        approver,
    }
    assert all(row["state"] == "PENDING" for row in messages(admin_engine, tenant))
    # Another tenant's subscriber gets nothing from this tenant's call, and a second call adds none.
    assert messages(admin_engine, there["tenant_id"]) == []
    assert enqueue(db, tenant, week) == 0
    assert enqueue(db, asleep["tenant_id"], week) == 0
    assert enqueue(db, there["tenant_id"], week) == 1
    for refused, call in (
        ("TENANT_REQUIRED", lambda: enqueue(db, None, week)),
        ("INVALID_WEEK", lambda: enqueue(db, tenant, week + timedelta(days=1))),
        ("INVALID_WEEK", lambda: enqueue(db, tenant, week + timedelta(days=7))),
        ("INVALID_CLOCK", lambda: enqueue(db, tenant, week, now() + timedelta(minutes=10))),
    ):
        with pytest.raises(DBAPIError) as raised:
            call()
        assert refused in str(raised.value), refused


def cross_tenant_reads(db, tenants: list[UUID], due_in: list[UUID]) -> None:
    """What the three owner-only reads answer: identifiers and a count, every tenant."""
    with db.transaction(uuid4()) as conn:
        listed = conn.execute(
            text("SELECT * FROM execbound.weekly_summary_tenants(:n)"), {"n": now()}
        )
        assert list(listed.keys()) == ["tenant_id"]
        assert set(tenants) <= set(listed.scalars())
        due = conn.execute(text("SELECT * FROM execbound.weekly_summary_due(:n, 50)"), {"n": now()})
        assert list(due.keys()) == ["tenant_id", "message_id"]
        assert set(due_in) <= {row[0] for row in due.all()}
        sent = conn.execute(
            text("SELECT * FROM execbound.weekly_summary_sent(:s)"),
            {"s": now() - timedelta(days=1)},
        )
        assert list(sent.keys()) == ["weekly_summary_sent"]
        assert sent.scalar_one() >= 1
        # The runtime role reads none of these rows itself outside a tenant's fence.
        for table in TABLES:
            assert conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 0


def deliver_one(db, tenant: UUID) -> None:
    with db.transaction(tenant) as conn:
        conn.execute(
            text(
                "UPDATE execbound.weekly_summary_messages SET state='DELIVERED', "
                "delivered_at=:n, attempts=1 WHERE tenant_id=:t AND message_id = "
                "(SELECT message_id FROM execbound.weekly_summary_messages WHERE tenant_id=:t "
                "ORDER BY message_id LIMIT 1)"
            ),
            {"t": tenant, "n": now()},
        )


def test_hv11d_due_sent_and_tenants_reach_every_tenant(db, admin_engine):
    first = workspace(admin_engine, name="First")
    second = workspace(admin_engine, name="Second")
    week = monday(now())
    for where in (first, second):
        subscribe(db, where["tenant_id"], where["admin"])
        approver = principal(admin_engine, where["tenant_id"], "HUMAN_APPROVER")
        subscribe(db, where["tenant_id"], approver)
        assert enqueue(db, where["tenant_id"], week) == 2
    deliver_one(db, first["tenant_id"])
    both = [first["tenant_id"], second["tenant_id"]]
    cross_tenant_reads(db, both, both)


def test_hv11e_unsubscribe_ends_only_a_matching_active_subscription(db, admin_engine):
    here = workspace(admin_engine, name="Unsubscribing")
    there = workspace(admin_engine, name="Other")
    tenant = here["tenant_id"]
    subscribe(db, tenant, here["admin"], now() - timedelta(minutes=2))
    subscribe(db, there["tenant_id"], there["admin"])
    week = monday(now())
    enqueue(db, tenant, week, now() - timedelta(minutes=1))
    enqueue(db, there["tenant_id"], week)
    [message] = messages(admin_engine, tenant)
    [foreign] = messages(admin_engine, there["tenant_id"])
    digest = keyed(db, tenant, message["message_id"])
    foreign_digest = keyed(db, there["tenant_id"], foreign["message_id"])
    wrong = hashlib.sha256(b"not the secret").hexdigest()
    assert unsubscribe(db, tenant, message["message_id"], wrong) is None
    assert unsubscribe(db, tenant, foreign["message_id"], foreign_digest) is None
    assert unsubscribe(db, tenant, message["message_id"], "not-a-digest") is None
    assert active(admin_engine, tenant, here["admin"]) and active(
        admin_engine, there["tenant_id"], there["admin"]
    )
    assert unsubscribe(db, tenant, message["message_id"], digest) == here["admin"]
    assert not active(admin_engine, tenant, here["admin"])
    # Already ended: nothing more happens.
    assert unsubscribe(db, tenant, message["message_id"], digest) is None
    # Started again later: the old message's link cannot end the new subscription.
    with db.transaction(tenant) as conn:
        conn.execute(
            text(
                "UPDATE execbound.weekly_summary_subscriptions SET subscribed_at=:n, "
                "ended_at=NULL, ended_via=NULL WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "p": here["admin"], "n": now()},
        )
    assert unsubscribe(db, tenant, message["message_id"], digest) is None
    assert active(admin_engine, tenant, here["admin"])
    with pytest.raises(DBAPIError, match="TENANT_REQUIRED"):
        with db.transaction(uuid4()) as conn:
            conn.execute(text("SELECT set_config('execbound.tenant_id', '', true)"))
            conn.execute(
                text("SELECT execbound.weekly_summary_unsubscribe(:m, :h, :n)"),
                {"m": message["message_id"], "h": digest, "n": now()},
            )


def test_hv11c_restricted_enqueue_works_per_tenant_as_an_owner_without_bypass(restricted):  # noqa: F811
    """A managed host's posture: the owner does not bypass row security.

    A single enqueue across every tenant would see no principal there and insert nothing,
    while a run as the local bypassing owner passed. Here the enqueue runs inside each
    tenant's own fence, the three reads cross tenants only through `owner_drain`, and the
    unsubscribe ends a subscription in its own tenant.
    """
    engine, config, _ = restricted
    command.upgrade(config, "head")
    runtime_url = with_database_name(os.environ["TEST_DATABASE_URL"], engine.url.database)
    db = Database(runtime_url, pool_size=1)
    try:
        with db.transaction(uuid4()) as conn:
            check_runtime(conn)
        first = workspace(engine, name="First")
        second = workspace(engine, name="Second")
        week = monday(now())
        for where in (first, second):
            subscribe(db, where["tenant_id"], where["admin"])
        tenants = [first["tenant_id"], second["tenant_id"]]
        with db.transaction(uuid4()) as conn:
            listed = set(
                conn.execute(
                    text("SELECT tenant_id FROM execbound.weekly_summary_tenants(:n)"),
                    {"n": now()},
                ).scalars()
            )
        assert listed == set(tenants)
        for where in (first, second):
            assert enqueue(db, where["tenant_id"], week) == 1
            [only] = messages(engine, where["tenant_id"])
            assert only["principal_id"] == where["admin"]
        with pytest.raises(DBAPIError, match="TENANT_REQUIRED"):
            enqueue(db, None, week)
        deliver_one(db, first["tenant_id"])
        cross_tenant_reads(db, tenants, [second["tenant_id"]])
        [message] = messages(engine, first["tenant_id"])
        digest = keyed(db, first["tenant_id"], message["message_id"])
        assert unsubscribe(db, first["tenant_id"], message["message_id"], digest) == first["admin"]
        assert not active(engine, first["tenant_id"], first["admin"])
        assert active(engine, second["tenant_id"], second["admin"])
        with pytest.raises(RuntimeError, match="lossy downgrade refused"):
            command.downgrade(config, "0077_rejection_index")
    finally:
        db.engine.dispose()


def test_hv11f_downgrade_refuses_with_a_subscription_and_round_trips_without_one(db, admin_engine):
    config = alembic_config()
    here = workspace(admin_engine, name="Downgrading")
    subscribe(db, here["tenant_id"], here["admin"])
    with pytest.raises(RuntimeError, match="lossy downgrade refused"):
        command.downgrade(config, "0077_rejection_index")
    empty_schema(admin_engine)
    try:
        command.downgrade(config, "0075_workspace_requests_admin")
        with admin_engine.connect() as conn:
            assert not conn.execute(
                text("SELECT 1 FROM pg_indexes WHERE indexname='audit_events_rejected'")
            ).scalar_one_or_none()
            assert not conn.execute(
                text("SELECT 1 FROM pg_tables WHERE tablename='weekly_summary_messages'")
            ).scalar_one_or_none()
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
    with db.transaction(uuid4()) as conn:
        check_runtime(conn)
