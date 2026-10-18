# SPDX-License-Identifier: AGPL-3.0-only
"""Account, session and signup test helpers shared by core and hosted tests.

`tests/test_teammate_invitations.py` and `tests/test_demo_command.py` are core tests
(teammate invitations are core) that need the same account/session/signup shapes a plugin's
own tests build, so the shapes live here, where a core test can import them (#496). Nothing
here is plugin-specific, and nothing here imports a plugin's code.
"""

import hashlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from smtp_double import PASSWORD as RELAY_PASSWORD
from smtp_double import USERNAME as RELAY_USER
from smtp_double import relay
from sqlalchemy import text
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted

from execbound.audit import read_events, verify_chain
from execbound.connection import with_database_name
from execbound.db import TABLES, Database, grant_dormant, honoured_claims
from execbound.identity import new_token
from execbound.passwords import sign_in_with_password
from execbound.surfaces.sessions import issue_session, load_session
from execbound.transports import MailConfig

ROOT = Path(__file__).resolve().parents[1]

# The password `test_workspace_accounts.enroll` gives a legacy human.
RETAINED = "a retained example passphrase"

CONSENT = "2026-09-20"

# A verification link's fragment (#243), which is the whole token.
VERIFY = re.compile(r"#(ebs1\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43})")

# The relay double's sender and the local origin `signup_client`/verified-request tests answer
# under; both are Open sandbox signups (#243) shapes several of a plugin's test files need.
SENDER = "sandbox@example.com"
ORIGIN = "http://127.0.0.1"

# The one frontend copy table proven reachable from a `PLAN_LIMIT` refusal: the three
# creation dialogs (`AgentsList`'s NewAgent, `PeopleList`'s approver, `CredentialsList`'s
# issue) all render through `ConfirmDialog` -> `forms.Problem` -> this module's `explain()`,
# and so does `AgentDetail`'s Reactivate dialog, which can receive `PLAN_LIMIT` because
# reactivating a hand-deactivated agent counts against the cap.
# `console/src/lib/errors.ts` and `console/src/lib/refusal.ts` carry the same pattern but
# are wired only to Assistant, Monitoring and Tenant-settings dialogs (AskPage, DescribeRule,
# Explain, Findings, PersonalSettings, AssistantDialog, DeadlineDialog, ModeDialog,
# StopDialog, ReconcileDialog), none of which can reach `admin_create_principal`, so neither
# table needs the entry and neither is checked here.
DIRECTORY_COPY = ROOT / "console" / "src" / "components" / "directory" / "errors.ts"


def make_slot(engine, *, seed="so", number=1, active=False, claimed=None, tenant=None):
    """An inactive tenant with a slot row, the shape the seeder leaves behind."""
    tenant = tenant or uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        if not conn.execute(
            text("SELECT 1 FROM execbound.tenants WHERE tenant_id = :t"), {"t": tenant}
        ).scalar():
            conn.execute(
                text("INSERT INTO execbound.tenants(tenant_id, name, active) VALUES (:t, :n, :a)"),
                {"t": tenant, "n": f"sandbox-{seed}-{number:02}", "a": active},
            )
        conn.execute(
            text(
                "INSERT INTO execbound.onboarding_slots(tenant_id, slot, seed, seeded_at, "
                "claimed_at) VALUES (:t, :s, :seed, :n, :c)"
            ),
            {
                "t": tenant,
                "s": number,
                "seed": seed,
                "n": datetime.now(UTC) - timedelta(days=1),
                "c": claimed,
            },
        )
    return tenant


def operator_tenant(engine, name="operator"):
    """The ordinary tenant the requests live in, with its own jobs ADMIN and credential."""
    tenant, principal, credential_id = uuid4(), uuid4(), uuid4()
    token, digest = new_token(tenant, credential_id)
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name, active) VALUES (:t, :n, true)"),
            {"t": tenant, "n": f"{name}-{tenant.hex[:8]}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :p, 'ADMIN')"
            ),
            {"t": tenant, "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.credentials"
                "(tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at) "
                "VALUES (:t, :c, :p, :h, :i, :e)"
            ),
            {
                "t": tenant,
                "c": credential_id,
                "p": principal,
                "h": digest,
                "i": datetime.now(UTC) - timedelta(minutes=5),
                "e": datetime.now(UTC) + timedelta(hours=8),
            },
        )
    return {"tenant_id": tenant, "principal_id": principal, "token": token}


def slots_file(tmp_path, tenants, *, seed="su"):
    path = tmp_path / f"slots-{seed}.json"
    path.write_text(
        json.dumps(
            {
                "seed": seed,
                "slots": [
                    {"slot": index + 1, "tenant_id": str(tenant)}
                    for index, tenant in enumerate(tenants)
                ],
            }
        )
    )
    return path


def sent_verification(mail):
    """The newest verification link token in the relay's messages."""
    found = None
    for message in mail.messages():
        match = VERIFY.search(message.get_content())
        if match:
            found = match.group(1)
    return found


def legacy_holder(engine, email, *, active):
    """An ADMIN principal set up before accounts existed, holding `email` in its own tenant.

    Written as the restricted owner, inside that tenant's own fence, the way every other
    tenant row in this suite is written.
    """
    tenant, principal = uuid4(), uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name, active) VALUES (:t, :n, true)"),
            {"t": tenant, "n": f"legacy-{tenant.hex[:8]}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, active, email) "
                "VALUES (:t, :p, 'ADMIN', :active, :email)"
            ),
            {"t": tenant, "p": principal, "active": active, "email": email},
        )
    return tenant, principal


def mfa_gated_session(db, admin_engine, tenant, principal, email, *, clock=None):
    """A workspace session for a tenant whose security policy requires MFA of everyone,
    loaded pending: `mfa_required` is True, the way `test_workspace_switching`'s own MFA case
    gates one. An `account_security_policy` row rather than an enrolled factor, so no key
    ring is needed to prove the refusal. `clock` defaults to `SystemClock()` for a
    Python-level caller; an HTTP-level one passes `runtime.clock`, the clock the running
    application checks the session against (`test_vs12e`'s own reasoning for `signed_in`).
    """
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.account_security_policy "
                "(tenant_id, requirement, changed_at, changed_by) VALUES (:t, 'all', now(), :p)"
            ),
            {"t": tenant, "p": principal},
        )
    grant = issue_session(db, sign_in_with_password(db, email, RETAINED, clock=clock), clock=clock)
    assert grant.mfa_required
    pending = load_session(db, grant.token, clock=clock, allow_pending_mfa=True)
    assert pending.mfa_required
    return grant, pending


def rows_of(admin_engine, tenant):
    """Every row a workspace is made of, compared whole before and after."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return {
            table: sorted(
                (
                    dict(r)
                    for r in conn.execute(
                        text(f"SELECT * FROM execbound.{table} WHERE tenant_id = :t"),
                        {"t": tenant},
                    ).mappings()
                ),
                key=str,
            )
            for table in (
                "tenants",
                "principals",
                "spaces",
                "workspace_memberships",
                "community_allocations",
            )
        }


def session_cookie_value(response, human_config):
    """The `eb_session` (or `__Host-eb_session`) cookie a response set, or None.

    `response.headers["set-cookie"]` only ever returns the *first* Set-Cookie header on a
    multi-cookie response, so a check for the session cookie specifically has to walk
    `get_list` and match the real name `HumanConfig.cookie("session")` computes, not a
    literal guess, or it is checking for a header that can never appear either way.
    """
    name = human_config.cookie("session")
    prefix = f"{name}="
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(prefix):
            return header[len(prefix) :].split(";", 1)[0]
    return None


def fingerprint(engine, tenant, tables=None):
    """Keep private row material out of assertion reports; compare every application table."""
    result = {}
    with engine.begin() as conn:
        fenced(conn, tenant)
        if tables is None:
            tables = (
                conn.execute(
                    text(
                        "SELECT c.table_name FROM information_schema.columns c "
                        "JOIN information_schema.tables t USING(table_schema,table_name) "
                        "WHERE c.table_schema='execbound' AND c.column_name='tenant_id' "
                        "AND t.table_type='BASE TABLE' ORDER BY c.table_name"
                    )
                )
                .scalars()
                .all()
            )
        for table in tables:
            assert table in TABLES
            value = "to_jsonb(r)"
            if table == "tenants":
                # 0053's community transition moves `sandbox` tenants to `free` on purpose, and
                # 0066 adds `max_agents` with the limit each tenant's plan gave, so a reading
                # taken before either upgrade matches on neither; 0055 adds `slug` and
                # `provisioned_at`, both NULL on rows that predate it.
                value += " - 'plan' - 'max_agents' - 'slug' - 'provisioned_at'"
            if table == "onboarding_slots":
                value += " - 'community_at'"
            if table in ("resources", "incidents", "resource_facts"):
                value += " - 'demo_fixture'"
            if table in ("principals", "credentials"):
                # 0058 numbers the agents and keys that exist, and adds `credentials.deleted_at`;
                # 0061 adds `principals.replaced_by`, NULL on every row that predates it.
                value += " - 'number' - 'deleted_at' - 'replaced_by'"
            rows = sorted(
                str(r[0])
                for r in conn.execute(
                    text(f"SELECT {value} FROM execbound.{table} r WHERE tenant_id=:t"),
                    {"t": tenant},
                )
            )
            result[table] = (len(rows), hashlib.sha256("\n".join(rows).encode()).hexdigest())
    return result


def relay_mail(running):
    """A `MailConfig` pointed at a `mail` fixture's already-running relay double."""
    return MailConfig("localhost", running.port, "tls", RELAY_USER, RELAY_PASSWORD, SENDER)


@pytest.fixture
def mail(tmp_path):
    directory = tmp_path / "relay"
    directory.mkdir(parents=True, exist_ok=True)
    with relay(directory) as running:
        yield running


@pytest.fixture
def operator(admin_engine, seeded):
    return operator_tenant(admin_engine)


@pytest.fixture
def pool(admin_engine):
    """Two free slots, the shape `sandbox-seed --count 2` leaves behind."""
    return [make_slot(admin_engine, seed="su", number=index) for index in (1, 2)]


def chain(admin_engine, tenant):
    """The tenant's own events, verified against its retained head before anything is read."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        events = read_events(conn, tenant)
        head = conn.execute(
            text("SELECT sequence, event_hash FROM execbound.audit_heads WHERE tenant_id = :t"),
            {"t": tenant},
        ).one()
    assert verify_chain(events, tenant, int(head[0]), str(head[1]))
    return events


@pytest.fixture
def stack(restricted):
    """The restricted database migrated to head: the owner's engine and the runtime's db.

    `command.upgrade` runs as the restricted owner, exactly as the hosted project's own
    deploy does; the runtime `Database` below is a second connection, over the runtime role,
    built the same way `tests/conftest.py` builds `db`: the same server, the runtime role's
    own credentials, only the database name changed.
    """
    engine, config, role = restricted
    command.upgrade(config, "head")
    # This restricted database was migrated just now, so it holds no dormant grant; a test
    # under a plugin's directory runs with that plugin's (#496), and a core test
    # with none, exactly as the worker's own database does.
    with engine.begin() as conn:
        grant_dormant(conn, honoured_claims())
    runtime_url = with_database_name(os.environ["TEST_DATABASE_URL"], engine.url.database)
    db = Database(runtime_url, pool_size=1)
    try:
        yield engine, db
    finally:
        db.close()
