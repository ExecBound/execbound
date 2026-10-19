# SPDX-License-Identifier: AGPL-3.0-only
"""Teammate invitations (#487): the TI cases of docs/ACCEPTANCE_TESTS.md.

Migration 0059 adds two tenant tables and seven definer functions. TI1 and its lettered
cases call the functions over the runtime role exactly as the service will, and read every
fact back over the owner connection under the tenant's own fence, so a zero is isolation and
never absence: the SQL itself has to hold before anything is built on top of it.

TI2 onward exercise the Python service (`src/execbound/invitations.py`) built on that SQL:
create, resend, revoke, list, delivery through the TLS relay double, and the tenant-agnostic
drain.

TI8 onward are the recipient's own path: inspecting a link, and accepting it as a new
address with a password or as an existing account that has signed in, in one transaction under
the inviter's current authority.
"""

import hashlib
import importlib.util
import json
import os
import re
import secrets
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from console_api_fixtures import API as CONSOLE_API
from console_api_fixtures import ConsoleClient, assert_no_secrets, console_config
from fastapi.testclient import TestClient
from signup_fixtures import (
    DIRECTORY_COPY,
    RETAINED,
    legacy_holder,
    mfa_gated_session,
    session_cookie_value,
)
from smtp_double import PASSWORD as RELAY_PASSWORD
from smtp_double import USERNAME as RELAY_USER
from smtp_double import relay
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from test_execution import provision_credential
from test_human_surface import form_values
from test_human_surface import human_config as human_config
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted
from test_notification_transports import NON_LATIN_WORKSPACE
from test_structured_logging import captured as captured
from test_workspace_accounts import enroll

from execbound import invitations as invitations_module
from execbound import user_accounts
from execbound.access_control import capabilities, has_permission, set_user_roles
from execbound.administration import AdministrationError
from execbound.app import create_app
from execbound.audit import read_events, verify_chain
from execbound.connection import with_database_name
from execbound.db import (
    FUNCTIONS,
    TABLES,
    UPDATE_COLUMNS,
    Database,
    check_runtime,
)
from execbound.identity import UNATTRIBUTED_CONTEXT, authenticate
from execbound.invitations import (
    Accepted,
    Inspected,
    InvitationError,
    _validate_grants,
    accept_invitation,
    create_invitation,
    deliver_invitations,
    deliver_one,
    inspect_invitation,
    invitation_selectors,
    list_invitations,
    new_invitation_token,
    resend_invitation,
    revoke_invitation,
    sign_in_invited_account,
)
from execbound.passwords import PasswordError, issue_reset, set_email, sign_in_with_password
from execbound.runtime import Runtime
from execbound.surfaces import invite_pages, people_pages
from execbound.surfaces.sessions import issue_session, load_session
from execbound.transports import MailConfig, render_teammate_invitation

pytestmark = pytest.mark.integration

ORIGIN = "http://127.0.0.1"
SENDER = "workspace@example.com"
INVITE_TOKEN = re.compile(r"ebt1\.[0-9a-f-]{36}\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}")

INVITATION_TABLES = ("workspace_invitations", "workspace_invitation_messages")
INVITATION_FUNCTIONS = {
    "workspace_invitation_create",
    "workspace_invitation_revoke",
    "workspace_invitation_resend",
    "workspace_invitation_due",
    "workspace_invitation_rekey",
    "workspace_invitation_check",
    "workspace_invitation_accept",
}
DELIVERY = {
    "state",
    "attempts",
    "next_attempt_at",
    "lease_until",
    "lease_token",
    "delivered_at",
    "last_error",
}
ADDRESS = "casey@example.org"
VIEWER = [{"role": "viewer", "space_id": None}]
# A well-formed scrypt record: the functions store it, nothing here verifies against it.
PASSWORD = {
    "algorithm": "scrypt",
    "n": 16384,
    "r": 8,
    "p": 1,
    "dklen": 32,
    "salt": "0" * 32,
    "hash": "ab" * 32,
}


def now():
    return datetime.now(UTC)


def digest():
    return hashlib.sha256(secrets.token_urlsafe(32).encode()).hexdigest()


def workspace(engine, *, name="Inviting"):
    """An active tenant with a Default space and one unmanaged ADMIN, who may invite."""
    tenant, admin, space = uuid4(), uuid4(), uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name, active) VALUES (:t, :n, true)"),
            {"t": tenant, "n": f"{name}-{tenant.hex[:8]}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Default', now(), :p)"
            ),
            {"t": tenant, "s": space, "p": admin},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, label) "
                "VALUES (:t, :p, 'ADMIN', 'Robin Admin')"
            ),
            {"t": tenant, "p": admin},
        )
    return {"tenant_id": tenant, "admin": admin, "space": space}


def scalar(db, tenant, sql, params=None, *, account=None):
    """One runtime call under the tenant's fence (and an account, when one is signed in)."""
    with db.transaction(tenant) as conn:
        if account is not None:
            conn.execute(
                text("SELECT set_config('execbound.account_id', :a, true)"), {"a": str(account)}
            )
        return conn.execute(text(sql), params or {}).scalar_one()


def invite(db, where, email=ADDRESS, grants=None):
    invitation, message = uuid4(), uuid4()
    expires = scalar(
        db,
        where["tenant_id"],
        "SELECT execbound.workspace_invitation_create(:a, :i, :e, CAST(:g AS jsonb), :m, :n)",
        {
            "a": where["admin"],
            "i": invitation,
            "e": email,
            "g": json.dumps(VIEWER if grants is None else grants),
            "m": message,
            "n": now(),
        },
    )
    assert expires is not None
    return invitation, message


def rekey(db, tenant, invitation):
    token_hash = digest()
    scalar(
        db,
        tenant,
        "SELECT execbound.workspace_invitation_rekey(:i, :h, :n)",
        {"i": invitation, "h": token_hash, "n": now()},
    )
    return token_hash


def accept(db, tenant, invitation, token_hash, *, principal=None, account=None, signed_in=None):
    """New address: a password and a fresh account id. Existing: the signed-in account only."""
    password = None if signed_in is not None else PASSWORD
    account = account if signed_in is None else None
    if signed_in is None and account is None:
        account = uuid4()
    return scalar(
        db,
        tenant,
        "SELECT execbound.workspace_invitation_accept("
        ":i, :h, :p, CAST(:a AS uuid), CAST(:pw AS jsonb), :n)",
        {
            "i": invitation,
            "h": token_hash,
            "p": principal or uuid4(),
            "a": account,
            "pw": None if password is None else json.dumps(password),
            "n": now(),
        },
        account=signed_in,
    )


def owner_rows(engine, tenant, sql, params=None, *, account=None):
    with engine.begin() as conn:
        fenced(conn, tenant)
        if account is not None:
            conn.execute(
                text("SELECT set_config('execbound.account_id', :a, true)"), {"a": str(account)}
            )
        return [dict(row) for row in conn.execute(text(sql), params or {}).mappings()]


def invitation_row(engine, tenant, invitation):
    return owner_rows(
        engine,
        tenant,
        "SELECT * FROM execbound.workspace_invitations WHERE invitation_id = :i",
        {"i": invitation},
    )[0]


def message_row(engine, tenant, invitation):
    return owner_rows(
        engine,
        tenant,
        "SELECT * FROM execbound.workspace_invitation_messages WHERE invitation_id = :i",
        {"i": invitation},
    )[0]


def existing_account(engine, email):
    """An account that owns its own workspace, where its principal holds `email`.

    The unique `principals_email` index then keeps that address on the home principal, so a
    principal made for it in another workspace falls back to a label.
    """
    home = workspace(engine, name="Home")
    account = uuid4()
    with engine.begin() as conn:
        fenced(conn, home["tenant_id"])
        conn.execute(
            text("SELECT set_config('execbound.account_id', :a, true)"), {"a": str(account)}
        )
        conn.execute(
            text("UPDATE execbound.principals SET email = :e WHERE principal_id = :p"),
            {"e": email, "p": home["admin"]},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.user_accounts(account_id, email, email_verified_at) "
                "VALUES (:a, :e, now())"
            ),
            {"a": account, "e": email},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.workspace_memberships(account_id, tenant_id, principal_id) "
                "VALUES (:a, :t, :p)"
            ),
            {"a": account, "t": home["tenant_id"], "p": home["admin"]},
        )
    return home, account


def set_active(engine, tenant, principal, active):
    """Removal is principal deactivation; the membership row is left as it was."""
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = :a, "
                "deactivated_at = CASE WHEN :a THEN NULL ELSE now() END "
                "WHERE principal_id = :p"
            ),
            {"a": active, "p": principal},
        )


def membership(engine, tenant, account):
    return owner_rows(
        engine,
        tenant,
        "SELECT principal_id, active, version FROM execbound.workspace_memberships "
        "WHERE account_id = :a AND tenant_id = :t",
        {"a": account, "t": tenant},
        account=account,
    )


# --- Helpers for the Python service, TI2 onward ----------------------------------------------


def bare_runtime(db):
    """Nothing beyond `.db` and `.clock` the console calls need; no connector, no keys."""
    return Runtime(db, [])


def session_for(db, admin_engine, tenant, principal):
    """A signed-in session for an existing principal, with a fresh credential of its own."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        token = provision_credential(conn, tenant, principal, now(), timedelta(hours=2))
    identity = authenticate(db, token)
    return load_session(db, issue_session(db, identity).token)


def admin_session(db, admin_engine, where):
    return session_for(db, admin_engine, where["tenant_id"], where["admin"])


def member_session(db, admin_engine, where):
    """A signed-in session for an ordinary member of this workspace: no `access.manage`."""
    principal = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, where["tenant_id"])
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, label) "
                "VALUES (:t, :p, 'HUMAN_APPROVER', 'Member')"
            ),
            {"t": where["tenant_id"], "p": principal},
        )
    return session_for(db, admin_engine, where["tenant_id"], principal)


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


def relay_mail(running):
    return MailConfig("localhost", running.port, "tls", RELAY_USER, RELAY_PASSWORD, SENDER)


@pytest.fixture
def mail(tmp_path):
    directory = tmp_path / "relay"
    directory.mkdir(parents=True, exist_ok=True)
    with relay(directory) as running:
        yield running


def test_ti1_migration_catalog_privileges_and_isolation(db, admin_engine, seeded):
    assert set(INVITATION_TABLES) <= set(TABLES)
    assert INVITATION_FUNCTIONS <= {name for name, _ in FUNCTIONS}
    assert UPDATE_COLUMNS["workspace_invitation_messages"] == DELIVERY
    assert "workspace_invitations" not in UPDATE_COLUMNS
    with db.engine.begin() as conn:
        check_runtime(conn)
    with admin_engine.begin() as conn:
        for table in INVITATION_TABLES:
            forced = conn.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE oid = CAST(:t AS regclass)"
                ),
                {"t": f"execbound.{table}"},
            ).one()
            assert tuple(forced) == (True, True), table
            for privilege in ("INSERT", "DELETE", "TRUNCATE"):
                assert not conn.execute(
                    text("SELECT has_table_privilege('execbound_app', :t, :p)"),
                    {"t": f"execbound.{table}", "p": privilege},
                ).scalar_one(), (table, privilege)
            assert not conn.execute(
                text("SELECT has_any_column_privilege('execbound_app', :t, 'INSERT')"),
                {"t": f"execbound.{table}"},
            ).scalar_one(), table
            updatable = set(
                conn.execute(
                    text(
                        "SELECT a.attname FROM pg_attribute a "
                        "WHERE a.attrelid = CAST(:t AS regclass) AND a.attnum > 0 "
                        "AND NOT a.attisdropped "
                        "AND has_column_privilege('execbound_app', a.attrelid, a.attnum, 'UPDATE')"
                    ),
                    {"t": f"execbound.{table}"},
                ).scalars()
            )
            expected = DELIVERY if table == "workspace_invitation_messages" else set()
            assert updatable == expected, table
        for name in INVITATION_FUNCTIONS:
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
        # The drain's cross-tenant read belongs to the role that owns the definer functions
        # and to nobody else: a SELECT-only policy naming exactly that role.
        drain = conn.execute(
            text(
                "SELECT pol.polcmd, pol.polpermissive, "
                "ARRAY(SELECT pg_get_userbyid(r) FROM unnest(pol.polroles) r) AS roles, "
                "(SELECT pg_get_userbyid(p.proowner) FROM pg_proc p "
                " WHERE p.proname = 'workspace_invitation_due') AS owner "
                "FROM pg_policy pol "
                "WHERE pol.polrelid = CAST('execbound.workspace_invitation_messages' AS regclass) "
                "AND pol.polname = 'owner_drain'"
            )
        ).one()
        assert drain.polcmd == "r" and drain.polpermissive
        assert drain.roles == [drain.owner] and "execbound_app" not in drain.roles

    where = workspace(admin_engine)
    invitation, message = invite(db, where)
    other = uuid4()
    with db.transaction(other) as conn:
        for table in INVITATION_TABLES:
            assert (
                conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 0
            ), table
        due = conn.execute(
            text("SELECT tenant_id, message_id FROM execbound.workspace_invitation_due(:n, 50)"),
            {"n": now()},
        ).all()
    assert (where["tenant_id"], message) in [tuple(row) for row in due]
    # The same runtime read under the inviting tenant's own fence finds the rows, so the
    # zeros above are isolation and not absence.
    with db.transaction(where["tenant_id"]) as conn:
        for table in INVITATION_TABLES:
            assert (
                conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 1
            ), table
    row = invitation_row(admin_engine, where["tenant_id"], invitation)
    assert (row["state"], row["sends"], row["generation"], row["token_hash"]) == (
        "PENDING",
        1,
        0,
        None,
    )
    assert row["expires_at"] - row["created_at"] == timedelta(days=7)


def test_ti1a_create_refuses_bad_input_and_a_second_pending_invitation(db, admin_engine, seeded):
    where = workspace(admin_engine)
    invite(db, where)
    cases = (
        ({"email": ADDRESS}, "INVITATION_PENDING"),
        ({"email": "Casey@Example.org"}, "INVALID_EMAIL"),
        ({"email": "not-an-address"}, "INVALID_EMAIL"),
        ({"email": "a@example.org", "grants": []}, "INVALID_ROLES"),
        ({"email": "a@example.org", "grants": [{"role": "owner"}]}, "INVALID_ROLE"),
        (
            {"email": "a@example.org", "grants": [{"role": "viewer", "extra": 1}]},
            "INVALID_ROLE",
        ),
        (
            {
                "email": "a@example.org",
                "grants": [{"role": "administrator", "space_id": str(where["space"])}],
            },
            "INVALID_ROLE_SCOPE",
        ),
        (
            {"email": "a@example.org", "grants": [{"role": "viewer", "space_id": str(uuid4())}]},
            "INVALID_SPACE",
        ),
        ({"email": "a@example.org", "grants": VIEWER + VIEWER}, "INVALID_ROLES"),
    )
    for kwargs, code in cases:
        with pytest.raises(DBAPIError, match=code):
            invite(db, where, **kwargs)
    # A principal of this workspace already holds the address.
    with admin_engine.begin() as conn:
        fenced(conn, where["tenant_id"])
        conn.execute(
            text("UPDATE execbound.principals SET email = :e WHERE principal_id = :p"),
            {"e": "robin@example.org", "p": where["admin"]},
        )
    with pytest.raises(DBAPIError, match="ALREADY_MEMBER"):
        invite(db, where, email="robin@example.org")
    # A principal of another workspace may not invite into this one.
    with pytest.raises(DBAPIError, match="FORBIDDEN"):
        invite(db, {**where, "admin": seeded["principals"][0]}, email="b@example.org")


def test_ti1b_a_new_address_accepts_without_a_personal_workspace(db, admin_engine, seeded):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    grants = [
        {"role": "viewer", "space_id": None},
        {"role": "approver", "space_id": str(where["space"])},
    ]
    invitation, _ = invite(db, where, grants=grants)
    token_hash = rekey(db, tenant, invitation)

    seen = scalar(
        db,
        tenant,
        "SELECT execbound.workspace_invitation_check(:i, :h, :n)",
        {"i": invitation, "h": token_hash, "n": now()},
    )
    assert seen["state"] == "PENDING" and seen["email"] == ADDRESS
    assert seen["workspace"].startswith("Inviting-") and seen["inviter_label"] == "Robin Admin"
    assert seen["grants"] == grants
    assert seen["space_names"] == {str(where["space"]): "Default"}

    principal, account = uuid4(), uuid4()
    result = accept(db, tenant, invitation, token_hash, principal=principal, account=account)
    assert result["outcome"] == "ACCEPTED"
    assert (result["principal_id"], result["account_id"]) == (str(principal), str(account))
    assert result["inviter_id"] == str(where["admin"]) and result["grants"] == grants
    assert result["account_version"] == 1
    assert result["changed"]["subject_id"] == str(principal)

    people = owner_rows(
        admin_engine,
        tenant,
        "SELECT kind, email, label, active FROM execbound.principals WHERE principal_id = :p",
        {"p": principal},
    )
    assert people == [{"kind": "HUMAN_APPROVER", "email": ADDRESS, "label": None, "active": True}]
    assert owner_rows(
        admin_engine,
        tenant,
        "SELECT principal_id FROM execbound.access_principals WHERE principal_id = :p",
        {"p": principal},
    ) == [{"principal_id": principal}]
    applied = owner_rows(
        admin_engine,
        tenant,
        "SELECT role, space_id FROM execbound.access_role_grants WHERE principal_id = :p "
        "ORDER BY role",
        {"p": principal},
    )
    assert applied == [
        {"role": "approver", "space_id": where["space"]},
        {"role": "viewer", "space_id": None},
    ]
    assert owner_rows(
        admin_engine,
        tenant,
        "SELECT account_id, active FROM execbound.workspace_memberships WHERE principal_id = :p",
        {"p": principal},
    ) == [{"account_id": account, "active": True}]
    made = owner_rows(
        admin_engine,
        tenant,
        "SELECT email, email_verified_at IS NOT NULL AS verified FROM execbound.user_accounts "
        "WHERE account_id = :a",
        {"a": account},
        account=account,
    )
    assert made == [{"email": ADDRESS, "verified": True}]
    assert (
        owner_rows(
            admin_engine,
            tenant,
            "SELECT 1 FROM execbound.user_passwords WHERE account_id = :a",
            {"a": account},
            account=account,
        )
        != []
    )
    # An invited-only account has no Community allocation anywhere.
    with admin_engine.begin() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.community_allocations WHERE account_id = :a"),
                {"a": account},
            ).scalar_one()
            == 0
        )
    row = invitation_row(admin_engine, tenant, invitation)
    assert (row["state"], row["accepted_principal_id"], row["accepted_account_id"]) == (
        "ACCEPTED",
        principal,
        account,
    )
    sent = message_row(admin_engine, tenant, invitation)
    assert (sent["state"], sent["last_error"]) == ("FAILED", "ACCEPTED")

    # A retried completion answers ALREADY and makes nothing more.
    again = accept(db, tenant, invitation, token_hash)
    assert again == {"outcome": "ALREADY"}
    assert (
        len(
            owner_rows(
                admin_engine,
                tenant,
                "SELECT 1 FROM execbound.workspace_memberships WHERE account_id = :a",
                {"a": account},
            )
        )
        == 1
    )


def test_ti1c_a_digest_mismatch_commits_its_failure_and_five_lock_the_link(
    db, admin_engine, seeded
):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    invitation, _ = invite(db, where)
    token_hash = rekey(db, tenant, invitation)
    principal = uuid4()
    assert accept(db, tenant, invitation, digest(), principal=principal) is None
    assert invitation_row(admin_engine, tenant, invitation)["failures"] == 1
    assert (
        scalar(
            db,
            tenant,
            "SELECT execbound.workspace_invitation_check(:i, :h, :n)",
            {"i": invitation, "h": digest(), "n": now()},
        )
        is None
    )
    assert invitation_row(admin_engine, tenant, invitation)["failures"] == 2
    for _ in range(3):
        assert accept(db, tenant, invitation, digest()) is None
    assert invitation_row(admin_engine, tenant, invitation)["failures"] == 5
    # Locked: even the real link answers nothing now, and nothing was created.
    assert accept(db, tenant, invitation, token_hash, principal=principal) is None
    assert (
        owner_rows(
            admin_engine,
            tenant,
            "SELECT 1 FROM execbound.principals WHERE principal_id = :p",
            {"p": principal},
        )
        == []
    )
    # An unknown invitation is the same NULL, with nothing to count.
    assert accept(db, tenant, uuid4(), token_hash) is None
    # A new send rekeys and resets the count; the older link stays dead.
    fresh = rekey(db, tenant, invitation)
    row = invitation_row(admin_engine, tenant, invitation)
    assert (row["failures"], row["generation"]) == (0, 2)
    assert accept(db, tenant, invitation, token_hash) is None
    assert accept(db, tenant, invitation, fresh)["outcome"] == "ACCEPTED"


def test_ti1d_a_revoked_invitation_refuses_acceptance(db, admin_engine, seeded):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    invitation, _ = invite(db, where)
    token_hash = rekey(db, tenant, invitation)
    scalar(
        db,
        tenant,
        "SELECT execbound.workspace_invitation_revoke(:a, :i, :n)",
        {"a": where["admin"], "i": invitation, "n": now()},
    )
    row = invitation_row(admin_engine, tenant, invitation)
    assert (row["state"], row["revoked_by"]) == ("REVOKED", where["admin"])
    sent = message_row(admin_engine, tenant, invitation)
    assert (sent["state"], sent["last_error"]) == ("FAILED", "REVOKED")
    principal = uuid4()
    with pytest.raises(DBAPIError, match="INVITATION_REVOKED"):
        accept(db, tenant, invitation, token_hash, principal=principal)
    assert (
        scalar(
            db,
            tenant,
            "SELECT execbound.workspace_invitation_check(:i, :h, :n) ->> 'state'",
            {"i": invitation, "h": token_hash, "n": now()},
        )
        == "REVOKED"
    )
    with pytest.raises(DBAPIError, match="INVALID_STATE"):
        scalar(
            db,
            tenant,
            "SELECT execbound.workspace_invitation_revoke(:a, :i, :n)",
            {"a": where["admin"], "i": invitation, "n": now()},
        )
    with pytest.raises(DBAPIError, match="NOT_FOUND"):
        scalar(
            db,
            tenant,
            "SELECT execbound.workspace_invitation_revoke(:a, :i, :n)",
            {"a": where["admin"], "i": uuid4(), "n": now()},
        )
    with pytest.raises(DBAPIError, match="INVALID_STATE"):
        rekey(db, tenant, invitation)
    assert (
        owner_rows(
            admin_engine,
            tenant,
            "SELECT 1 FROM execbound.principals WHERE principal_id = :p",
            {"p": principal},
        )
        == []
    )


def test_ti1e_an_inviter_who_lost_access_manage_is_refused(db, admin_engine, seeded):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    invitation, _ = invite(db, where)
    token_hash = rekey(db, tenant, invitation)
    # The inviter becomes a managed principal holding only Viewer: no access.manage.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.access_principals(tenant_id, principal_id) VALUES (:t, :p)"
            ),
            {"t": tenant, "p": where["admin"]},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.access_role_grants"
                "(tenant_id, grant_id, principal_id, role) VALUES (:t, :g, :p, 'viewer')"
            ),
            {"t": tenant, "g": uuid4(), "p": where["admin"]},
        )
    principal, account = uuid4(), uuid4()
    with pytest.raises(DBAPIError, match="FORBIDDEN"):
        accept(db, tenant, invitation, token_hash, principal=principal, account=account)
    assert (
        owner_rows(
            admin_engine,
            tenant,
            "SELECT 1 FROM execbound.principals WHERE principal_id = :p",
            {"p": principal},
        )
        == []
    )
    with admin_engine.begin() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.user_accounts WHERE account_id = :a"),
                {"a": account},
            ).scalar_one()
            == 0
        )
    assert invitation_row(admin_engine, tenant, invitation)["state"] == "PENDING"
    # The same refusal meets revoke and resend: they need current authority too.
    for function in ("revoke", "resend"):
        with pytest.raises(DBAPIError, match="FORBIDDEN"):
            scalar(
                db,
                tenant,
                f"SELECT execbound.workspace_invitation_{function}(:a, :i, :n)",
                {"a": where["admin"], "i": invitation, "n": now()},
            )


def test_ti1f_an_existing_account_keeps_its_workspace_and_gains_a_second(db, admin_engine, seeded):
    home, account = existing_account(admin_engine, ADDRESS)
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    invitation, _ = invite(db, where)
    token_hash = rekey(db, tenant, invitation)

    # A password for an address an account already holds is refused.
    with pytest.raises(DBAPIError, match="ACCOUNT_EXISTS"):
        accept(db, tenant, invitation, token_hash)
    # A different signed-in account is refused, not reassigned.
    _, stranger = existing_account(admin_engine, "someone-else@example.org")
    with pytest.raises(DBAPIError, match="ACCOUNT_MISMATCH"):
        accept(db, tenant, invitation, token_hash, signed_in=stranger)
    # Both proofs, or neither, is not a request.
    with pytest.raises(DBAPIError, match="INVALID_REQUEST"):
        scalar(
            db,
            tenant,
            "SELECT execbound.workspace_invitation_accept(:i, :h, :p, :a, CAST(:pw AS jsonb), :n)",
            {
                "i": invitation,
                "h": token_hash,
                "p": uuid4(),
                "a": uuid4(),
                "pw": json.dumps(PASSWORD),
                "n": now(),
            },
            account=account,
        )

    principal = uuid4()
    result = accept(db, tenant, invitation, token_hash, principal=principal, signed_in=account)
    assert result["outcome"] == "ACCEPTED" and result["account_id"] == str(account)
    # The address stays on the home principal; the new one is named by its label.
    assert owner_rows(
        admin_engine,
        tenant,
        "SELECT email, label FROM execbound.principals WHERE principal_id = :p",
        {"p": principal},
    ) == [{"email": None, "label": ADDRESS}]
    memberships = owner_rows(
        admin_engine,
        tenant,
        "SELECT tenant_id, active FROM execbound.workspace_memberships WHERE account_id = :a",
        {"a": account},
        account=account,
    )
    assert {row["tenant_id"] for row in memberships} == {home["tenant_id"], tenant}
    assert all(row["active"] for row in memberships)
    assert owner_rows(
        admin_engine,
        home["tenant_id"],
        "SELECT email FROM execbound.principals WHERE principal_id = :p",
        {"p": home["admin"]},
    ) == [{"email": ADDRESS}]

    assert accept(db, tenant, invitation, token_hash, signed_in=account) == {"outcome": "ALREADY"}
    with pytest.raises(DBAPIError, match="INVALID_TOKEN"):
        accept(db, tenant, invitation, token_hash, signed_in=stranger)
    # Already a member here: a second invitation for the address is refused, which needs the
    # cross-tenant account lookup because the local principal carries no email.
    with pytest.raises(DBAPIError, match="ALREADY_MEMBER"):
        invite(db, where)


def test_ti1g_resend_is_bounded_and_returns_the_message_to_the_outbox(db, admin_engine, seeded):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    invitation, message = invite(db, where)
    resend = (
        "SELECT execbound.workspace_invitation_resend(:a, :i, :n)",
        {"a": where["admin"], "i": invitation},
    )
    # The first send is still waiting.
    with pytest.raises(DBAPIError, match="RESEND_LIMIT"):
        scalar(db, tenant, resend[0], {**resend[1], "n": now()})
    # The runtime settles its own delivery columns: delivered three minutes ago.
    with db.transaction(tenant) as conn:
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitation_messages "
                "SET state = 'DELIVERED', attempts = 1, delivered_at = :d "
                "WHERE message_id = :m"
            ),
            {"d": now() - timedelta(minutes=3), "m": message},
        )
    scalar(db, tenant, resend[0], {**resend[1], "n": now()})
    assert invitation_row(admin_engine, tenant, invitation)["sends"] == 2
    sent = message_row(admin_engine, tenant, invitation)
    assert (sent["state"], sent["attempts"], sent["delivered_at"], sent["lease_until"]) == (
        "PENDING",
        0,
        None,
        None,
    )
    # Just delivered: too soon to send again.
    with db.transaction(tenant) as conn:
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitation_messages "
                "SET state = 'DELIVERED', delivered_at = :d WHERE message_id = :m"
            ),
            {"d": now() - timedelta(seconds=30), "m": message},
        )
    with pytest.raises(DBAPIError, match="RESEND_LIMIT"):
        scalar(db, tenant, resend[0], {**resend[1], "n": now()})
    # Five sends in all.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.workspace_invitations SET sends = 5 WHERE invitation_id = :i"),
            {"i": invitation},
        )
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitation_messages "
                "SET delivered_at = now() - interval '1 hour' WHERE message_id = :m"
            ),
            {"m": message},
        )
    with pytest.raises(DBAPIError, match="RESEND_LIMIT"):
        scalar(db, tenant, resend[0], {**resend[1], "n": now()})
    with pytest.raises(DBAPIError, match="NOT_FOUND"):
        scalar(db, tenant, resend[0], {"a": where["admin"], "i": uuid4(), "n": now()})
    # The runtime cannot write anything but the delivery columns.
    for statement in (
        "UPDATE execbound.workspace_invitation_messages SET invitation_id = :i",
        "UPDATE execbound.workspace_invitations SET state = 'ACCEPTED' WHERE invitation_id = :i",
        "DELETE FROM execbound.workspace_invitations WHERE invitation_id = :i",
    ):
        with pytest.raises(DBAPIError, match="permission denied"), db.transaction(tenant) as conn:
            conn.execute(text(statement), {"i": invitation})


def test_ti1h_the_drain_reaches_another_tenant_as_an_owner_without_bypass(restricted):
    """The drain's owner-only policy, proven where the owner is NOBYPASSRLS.

    Locally the owner is a superuser, so a definer function would see every tenant however
    its policies were written. The `restricted` database's owner does not bypass row
    security, so the drain lists a message across tenants only because `owner_drain`
    admits that role, and the runtime role, which that policy does not name, sees nothing
    outside its fence. The rest of the test runs an acceptance and the refused downgrade as
    that owner, so every `set_config` switch the definer bodies rely on is exercised under
    forced row-level security.
    """
    engine, config, _ = restricted
    command.upgrade(config, "head")
    runtime_url = with_database_name(os.environ["TEST_DATABASE_URL"], engine.url.database)
    db = Database(runtime_url, pool_size=1)
    try:
        where = workspace(engine)
        tenant = where["tenant_id"]
        invitation, message = uuid4(), uuid4()
        with engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "INSERT INTO execbound.workspace_invitations"
                    "(tenant_id, invitation_id, email, inviter_id, grants, created_at, "
                    " expires_at) "
                    "VALUES (:t, :i, 'drain@example.org', :a, CAST(:g AS jsonb), now(), "
                    " now() + interval '7 days')"
                ),
                {"t": tenant, "i": invitation, "a": where["admin"], "g": json.dumps(VIEWER)},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.workspace_invitation_messages"
                    "(tenant_id, message_id, invitation_id, created_at, next_attempt_at) "
                    "VALUES (:t, :m, :i, now(), now())"
                ),
                {"t": tenant, "m": message, "i": invitation},
            )
        with db.transaction(uuid4()) as conn:
            check_runtime(conn)
            # The drain's policy preflight, cheaply proven under this restricted posture: the
            # runtime role can read `pg_policy` and `pg_proc` here exactly as it can locally.
            invitations_module._check_drain_policy(conn)
            due = conn.execute(
                text(
                    "SELECT tenant_id, message_id FROM execbound.workspace_invitation_due(:n, 50)"
                ),
                {"n": now()},
            ).all()
            assert [tuple(row) for row in due] == [(tenant, message)]
            for table in INVITATION_TABLES:
                assert (
                    conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 0
                ), table
        with db.transaction(tenant) as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM execbound.workspace_invitation_messages")
                ).scalar_one()
                == 1
            )

        with pytest.raises(RuntimeError, match="lossy downgrade refused"):
            command.downgrade(config, "0058_api_key_numbers")

        # A new address accepts end to end as this owner.
        token_hash = rekey(db, tenant, invitation)
        principal, account = uuid4(), uuid4()
        result = accept(db, tenant, invitation, token_hash, principal=principal, account=account)
        assert result["outcome"] == "ACCEPTED"
        assert owner_rows(
            engine,
            tenant,
            "SELECT p.kind, p.email, m.account_id FROM execbound.principals p "
            "JOIN execbound.workspace_memberships m USING (tenant_id, principal_id) "
            "WHERE p.principal_id = :p",
            {"p": principal},
        ) == [{"kind": "HUMAN_APPROVER", "email": "drain@example.org", "account_id": account}]
        assert owner_rows(
            engine,
            tenant,
            "SELECT role FROM execbound.access_role_grants WHERE principal_id = :p",
            {"p": principal},
        ) == [{"role": "viewer"}]
        assert owner_rows(
            engine,
            tenant,
            "SELECT email FROM execbound.user_accounts WHERE account_id = :a",
            {"a": account},
            account=account,
        ) == [{"email": "drain@example.org"}]

        # An existing account whose address a principal elsewhere holds: the label fallback,
        # then the create-time membership lookup across tenants, both as this owner.
        home, member = existing_account(engine, "held@example.org")
        second, _ = invite(db, where, email="held@example.org")
        second_hash = rekey(db, tenant, second)
        joined = uuid4()
        assert (
            accept(db, tenant, second, second_hash, principal=joined, signed_in=member)["outcome"]
            == "ACCEPTED"
        )
        assert owner_rows(
            engine,
            tenant,
            "SELECT email, label FROM execbound.principals WHERE principal_id = :p",
            {"p": joined},
        ) == [{"email": None, "label": "held@example.org"}]
        with pytest.raises(DBAPIError, match="ALREADY_MEMBER"):
            invite(db, where, email="held@example.org")
        assert owner_rows(
            engine,
            home["tenant_id"],
            "SELECT email FROM execbound.principals WHERE principal_id = :p",
            {"p": home["admin"]},
        ) == [{"email": "held@example.org"}]

        # Removed, then invited back: the membership moves to the new principal, read and
        # written through its tenant arm as this owner.
        set_active(engine, tenant, joined, False)
        third, _ = invite(db, where, email="held@example.org")
        third_hash = rekey(db, tenant, third)
        rejoined = uuid4()
        assert (
            accept(db, tenant, third, third_hash, principal=rejoined, signed_in=member)["outcome"]
            == "ACCEPTED"
        )
        assert membership(engine, tenant, member) == [
            {"principal_id": rejoined, "active": True, "version": 2}
        ]
    finally:
        db.close()


def test_ti1i_a_removed_member_is_invited_back_under_a_new_principal(db, admin_engine, seeded):
    """Removal stays principal deactivation, and re-invitation re-points the account's one
    membership in this workspace at the new principal."""
    _, account = existing_account(admin_engine, ADDRESS)
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    first, _ = invite(db, where)
    old = uuid4()
    joined = accept(db, tenant, first, rekey(db, tenant, first), principal=old, signed_in=account)
    assert joined["outcome"] == "ACCEPTED"
    assert membership(admin_engine, tenant, account) == [
        {"principal_id": old, "active": True, "version": 1}
    ]
    # A member whose principal is active is present.
    with pytest.raises(DBAPIError, match="ALREADY_MEMBER"):
        invite(db, where)

    set_active(admin_engine, tenant, old, False)
    grants = [{"role": "approver", "space_id": str(where["space"])}]
    second, _ = invite(db, where, grants=grants)
    second_hash = rekey(db, tenant, second)
    # Reactivated before the link is used: present again, so acceptance refuses too.
    set_active(admin_engine, tenant, old, True)
    with pytest.raises(DBAPIError, match="ALREADY_MEMBER"):
        accept(db, tenant, second, second_hash, principal=uuid4(), signed_in=account)
    assert invitation_row(admin_engine, tenant, second)["state"] == "PENDING"

    set_active(admin_engine, tenant, old, False)
    new = uuid4()
    result = accept(db, tenant, second, second_hash, principal=new, signed_in=account)
    assert result["outcome"] == "ACCEPTED" and result["principal_id"] == str(new)
    assert membership(admin_engine, tenant, account) == [
        {"principal_id": new, "active": True, "version": 2}
    ]
    people = owner_rows(
        admin_engine,
        tenant,
        "SELECT principal_id, active FROM execbound.principals "
        "WHERE principal_id IN (:old, :new) ORDER BY active",
        {"old": old, "new": new},
    )
    assert people == [
        {"principal_id": old, "active": False},
        {"principal_id": new, "active": True},
    ]
    applied = owner_rows(
        admin_engine,
        tenant,
        "SELECT principal_id, role, space_id FROM execbound.access_role_grants "
        "WHERE principal_id IN (:old, :new) ORDER BY role",
        {"old": old, "new": new},
    )
    # The new principal holds the new invitation's grants; the old one keeps its history.
    assert applied == [
        {"principal_id": new, "role": "approver", "space_id": where["space"]},
        {"principal_id": old, "role": "viewer", "space_id": None},
    ]


def test_ti1j_a_space_id_is_canonical_or_refused(db, admin_engine, seeded):
    """A grant's `space_id` is absent, null or a UUID string in the 8-4-4-4-12 form (any
    case), stored lowercase; anything else is INVALID_SPACE, never a raw cast error."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    space = where["space"]
    for bad in (
        5,
        True,
        "not-a-uuid",
        "",
        space.hex,
        "{" + str(space) + "}",
        str(space) + " ",
        {"id": str(space)},
    ):
        with pytest.raises(DBAPIError, match="INVALID_SPACE"):
            invite(db, where, email="bad@example.org", grants=[{"role": "viewer", "space_id": bad}])
    # The same Space in two cases is one pair.
    with pytest.raises(DBAPIError, match="INVALID_ROLES"):
        invite(
            db,
            where,
            email="bad@example.org",
            grants=[
                {"role": "viewer", "space_id": str(space)},
                {"role": "viewer", "space_id": str(space).upper()},
            ],
        )

    shouted = [{"role": "approver", "space_id": str(space).upper()}, {"role": "viewer"}]
    invitation, _ = invite(db, where, grants=shouted)
    assert invitation_row(admin_engine, tenant, invitation)["grants"] == [
        {"role": "approver", "space_id": str(space)},
        {"role": "viewer", "space_id": None},
    ]
    token_hash = rekey(db, tenant, invitation)
    seen = scalar(
        db,
        tenant,
        "SELECT execbound.workspace_invitation_check(:i, :h, :n)",
        {"i": invitation, "h": token_hash, "n": now()},
    )
    assert seen["space_names"] == {str(space): "Default"}
    assert seen["grants"][0]["space_id"] in seen["space_names"]
    principal = uuid4()
    assert accept(db, tenant, invitation, token_hash, principal=principal)["outcome"] == "ACCEPTED"
    assert owner_rows(
        admin_engine,
        tenant,
        "SELECT role, space_id FROM execbound.access_role_grants WHERE principal_id = :p "
        "ORDER BY role",
        {"p": principal},
    ) == [{"role": "approver", "space_id": space}, {"role": "viewer", "space_id": None}]


# --- TI2: create_invitation ------------------------------------------------------------------


def test_ti2_create_invitation_writes_a_row_and_a_chain_event_without_an_address(
    db, admin_engine, seeded, captured
):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)

    result = create_invitation(runtime, session, ADDRESS, None)
    assert result["email"] == ADDRESS and result["grants"] == VIEWER
    assert result["expires_at"] - datetime.now(UTC) < timedelta(days=7)
    row = invitation_row(admin_engine, tenant, result["invitation_id"])
    assert row["state"] == "PENDING" and row["grants"] == VIEWER
    message = message_row(admin_engine, tenant, result["invitation_id"])
    assert message["state"] == "PENDING"

    events = chain(admin_engine, tenant)
    created = [e for e in events if e["kind"] == "invitation.created"]
    assert len(created) == 1 and created[0]["actor_id"] == where["admin"]
    payload = created[0]["payload"]
    assert payload["invitation_id"] == str(result["invitation_id"])
    assert payload["email_domain"] == "example.org"
    assert payload["grants"] == VIEWER
    assert ADDRESS not in json.dumps(payload)

    # A non-administrator is refused.
    member = member_session(db, admin_engine, where)
    with pytest.raises(InvitationError) as excinfo:
        create_invitation(runtime, member, "other@example.org", None)
    assert excinfo.value.code == "FORBIDDEN"

    # A second invitation for the same, still-pending address is refused.
    with pytest.raises(InvitationError) as excinfo:
        create_invitation(runtime, session, ADDRESS, None)
    assert excinfo.value.code == "INVITATION_PENDING"

    # An existing active member's address is refused.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.principals SET email = :e WHERE principal_id = :p"),
            {"e": "robin@example.org", "p": where["admin"]},
        )
    with pytest.raises(InvitationError) as excinfo:
        create_invitation(runtime, session, "robin@example.org", None)
    assert excinfo.value.code == "ALREADY_MEMBER"

    # A grant naming an archived Space is refused.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.spaces SET archived_at = now() WHERE space_id = :s"),
            {"s": where["space"]},
        )
    with pytest.raises(InvitationError) as excinfo:
        create_invitation(
            runtime,
            session,
            "casey2@example.org",
            [{"role": "viewer", "space_id": str(where["space"])}],
        )
    assert excinfo.value.code == "INVALID_SPACE"

    # Every refusal above logged `invitation.refused` with its code, never the address.
    lines = [json.loads(line) for line in captured.getvalue().splitlines() if line.strip()]
    refusals = [line for line in lines if line.get("event") == "invitation.refused"]
    assert [line["code"] for line in refusals] == [
        "FORBIDDEN",
        "INVITATION_PENDING",
        "ALREADY_MEMBER",
        "INVALID_SPACE",
    ]
    assert ADDRESS not in captured.getvalue()
    assert "robin@example.org" not in captured.getvalue()


def test_ti2b_an_expired_pending_invitation_does_not_block_a_new_one(db, admin_engine, seeded):
    """An expired pending invitation is revoked and replaced in one transaction; an unexpired
    one still refuses `INVITATION_PENDING` (checked first, above)."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)

    first = create_invitation(runtime, session, ADDRESS, None)
    with pytest.raises(InvitationError) as excinfo:
        create_invitation(runtime, session, ADDRESS, None)
    assert excinfo.value.code == "INVITATION_PENDING"

    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitations SET created_at = :c, expires_at = :e "
                "WHERE invitation_id = :i"
            ),
            {
                "c": now() - timedelta(days=6, hours=23),
                "e": now() - timedelta(minutes=1),
                "i": first["invitation_id"],
            },
        )
    second = create_invitation(runtime, session, ADDRESS, None)
    assert second["invitation_id"] != first["invitation_id"]

    assert invitation_row(admin_engine, tenant, first["invitation_id"])["state"] == "REVOKED"
    assert invitation_row(admin_engine, tenant, second["invitation_id"])["state"] == "PENDING"

    events = chain(admin_engine, tenant)
    kinds = [e["kind"] for e in events]
    assert kinds.count("invitation.created") == 2
    assert kinds.count("invitation.revoked") == 1
    revoked = next(e for e in events if e["kind"] == "invitation.revoked")
    assert revoked["payload"] == {"invitation_id": str(first["invitation_id"]), "reason": "EXPIRED"}
    assert revoked["actor_id"] == where["admin"]


def test_ti2c_python_side_grant_validation_matches_sql():
    """Grants are validated before any database round trip; SQL checks again."""
    assert _validate_grants(None) == VIEWER
    space = uuid4()
    assert _validate_grants([{"role": "viewer", "space_id": str(space).upper()}]) == [
        {"role": "viewer", "space_id": str(space)}
    ]
    # Python's own `UUID()` accepts more spellings than SQL's regex does and normalizes all
    # of them to the same canonical form before SQL ever sees the value.
    assert _validate_grants([{"role": "viewer", "space_id": space.hex}]) == [
        {"role": "viewer", "space_id": str(space)}
    ]
    for bad_shape in ([], [{"role": "viewer"}] * 21, [{"role": "viewer", "extra": 1}], "nope"):
        with pytest.raises(InvitationError) as excinfo:
            _validate_grants(bad_shape)
        assert excinfo.value.code == "INVALID_ROLES"
    for bad_space in (5, True, "not-a-uuid", ""):
        with pytest.raises(InvitationError) as excinfo:
            _validate_grants([{"role": "viewer", "space_id": bad_space}])
        assert excinfo.value.code == "INVALID_SPACE"


def test_ti2d_list_invitations_requires_access_manage_and_shows_the_address(
    db, admin_engine, seeded
):
    where = workspace(admin_engine)
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)
    created = create_invitation(runtime, session, ADDRESS, None)

    rows = list_invitations(runtime, session)
    assert len(rows) == 1
    row = rows[0]
    assert row["invitation_id"] == created["invitation_id"]
    assert row["email"] == ADDRESS
    assert row["state"] == "PENDING"
    assert row["sends"] == 1
    assert row["delivered_at"] is None and row["last_error"] is None

    member = member_session(db, admin_engine, where)
    with pytest.raises(InvitationError) as excinfo:
        list_invitations(runtime, member)
    assert excinfo.value.code == "FORBIDDEN"


def invitation_email(workspace, inviter):
    """A teammate invitation rendered with no database, for what it says about two names."""
    return render_teammate_invitation(
        MailConfig("localhost", 2525, "tls", RELAY_USER, RELAY_PASSWORD, SENDER),
        "jane@example.com",
        uuid4(),
        workspace,
        inviter,
        "http://127.0.0.1/join",
        f"ebt1.{uuid4()}.{uuid4()}.zYx-Wvu_TsrqPon987654321zYx-Wvu_TsrqPon9876",
        datetime(2026, 10, 20, 12, 0, tzinfo=UTC),
    )


def test_ti3_an_invitation_leaves_out_a_name_nothing_of_which_survives():
    """A workspace or inviter name in a script `safe_label` drops would read "unknown". The
    invitee is not a member yet, so a tenant id would tell them nothing: the email says "a
    workspace" and "An administrator", as the page the link opens does without an inviter's
    name, and that page names the workspace in full."""
    email = invitation_email(NON_LATIN_WORKSPACE, "\u0418\u0432\u0430\u043d")
    body = email.get_content()
    assert "unknown" not in str(email["Subject"]) + body
    assert email["Subject"] == "[ExecBound] An administrator invited you to a workspace"
    assert body.startswith("An administrator invited you to join a workspace on ExecBound.\n")
    assert invitation_email("Synthetic SOC", None)["Subject"] == (
        "[ExecBound] An administrator invited you to Synthetic SOC"
    )
    assert invitation_email("Synthetic SOC", "Robin Admin")["Subject"] == (
        "[ExecBound] Robin Admin invited you to Synthetic SOC"
    )


@pytest.mark.parametrize(
    "name",
    [
        "example.com",
        "Verify at evil.example now",
        "https://evil.example",
        "Acme: urgent",
        "Acme/Security",
        # An inviter with no label is named by their address, which reads as a host.
        "robin@example.com",
    ],
)
def test_ti3_an_invitation_leaves_out_a_name_a_mail_client_could_link(name):
    """On the hosted service anyone who signs up names the workspace and themselves, and the
    invitee is not a member yet, so neither name may carry a web address a mail client turns
    into a link inside a message sent from ExecBound's own address."""
    email = invitation_email(name, name)
    body = email.get_content()
    assert email["Subject"] == "[ExecBound] An administrator invited you to a workspace"
    assert body.startswith("An administrator invited you to join a workspace on ExecBound.\n")
    # The only link left is the invitation's own.
    assert body.count("http") == 1 and "http://127.0.0.1/join#ebt1." in body


@pytest.mark.parametrize("name", ["Acme Inc.", "Acme_Prod", "SOC (EU) - East"])
def test_ti3_an_invitation_keeps_a_name_no_mail_client_would_link(name):
    """A full stop that ends a word, an underscore or a hyphen links nothing in an email."""
    email = invitation_email(name, name)
    assert email["Subject"] == f"[ExecBound] {name} invited you to {name}"


def test_ti_invitation_token_round_trips_and_refuses_a_bad_code():
    tenant, invitation = uuid4(), uuid4()
    token, digest = new_invitation_token(tenant, invitation)
    assert token.startswith("ebt1.")
    assert hashlib.sha256(token.encode("ascii")).hexdigest() == digest
    assert invitation_selectors(token) == (tenant, invitation)
    for bad in ("not-a-token", "ebt1." + str(tenant), "ebs1." + token.split(".", 1)[1]):
        with pytest.raises(InvitationError) as excinfo:
            invitation_selectors(bad)
        assert excinfo.value.code == "INVALID_TOKEN"


# --- TI3: deliver_invitations against the relay double ---------------------------------------


def test_ti3_deliver_invitations_sends_one_message_with_the_expected_link(
    db, admin_engine, seeded, mail, captured
):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)
    created = create_invitation(runtime, session, ADDRESS, None)
    invitation_id = created["invitation_id"]

    counts = deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)
    assert counts == {"delivered": 1, "failed": 0, "deferred": 0}

    messages = mail.messages()
    assert len(messages) == 1
    message = messages[0]
    assert message["To"] == ADDRESS
    body = message.get_content()
    match = INVITE_TOKEN.search(body)
    assert match is not None
    token = match.group(0)
    assert f"{ORIGIN}/join#{token}" in body
    _, tenant_text, invitation_text, _ = token.split(".")
    assert tenant_text == str(tenant) and invitation_text == str(invitation_id)

    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    row = invitation_row(admin_engine, tenant, invitation_id)
    assert row["token_hash"] == digest and row["generation"] == 1

    workspace_name = f"Inviting-{tenant.hex[:8]}"
    assert "Robin Admin" in message["Subject"] and workspace_name in message["Subject"]
    assert "Robin Admin" in body and workspace_name in body

    # No address or token reached a log line.
    produced = captured.getvalue()
    assert ADDRESS not in produced
    assert token not in produced
    assert digest not in produced
    assert "invitation.sent" in produced


def test_ti3b_deliver_one_is_a_best_effort_first_send_that_never_raises(
    db, admin_engine, seeded, mail
):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)
    created = create_invitation(runtime, session, ADDRESS, None)
    message = message_row(admin_engine, tenant, created["invitation_id"])

    delivered = deliver_one(
        db,
        tenant,
        message["message_id"],
        mail=relay_mail(mail),
        origin=ORIGIN,
        tls_context=mail.context,
    )
    assert delivered is True
    assert len(mail.messages()) == 1
    assert message_row(admin_engine, tenant, created["invitation_id"])["state"] == "DELIVERED"

    # A message that is not due (or does not exist) is a quiet `False`, never a raise.
    assert deliver_one(db, tenant, uuid4(), mail=relay_mail(mail), origin=ORIGIN) is False


def test_ti5_resend_is_bounded_by_spacing_and_by_five_sends(db, admin_engine, seeded, mail):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)
    created = create_invitation(runtime, session, ADDRESS, None)
    invitation_id = created["invitation_id"]

    # The first send is still on its way.
    with pytest.raises(InvitationError) as excinfo:
        resend_invitation(runtime, session, invitation_id)
    assert excinfo.value.code == "RESEND_LIMIT"

    deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)
    first_digest = invitation_row(admin_engine, tenant, invitation_id)["token_hash"]
    assert first_digest is not None

    # Just delivered: too soon.
    with pytest.raises(InvitationError) as excinfo:
        resend_invitation(runtime, session, invitation_id)
    assert excinfo.value.code == "RESEND_LIMIT"

    # Past the two-minute spacing: resend succeeds and returns the message to the outbox.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitation_messages "
                "SET delivered_at = :d WHERE invitation_id = :i"
            ),
            {"d": now() - timedelta(minutes=3), "i": invitation_id},
        )
    resend_invitation(runtime, session, invitation_id)
    assert invitation_row(admin_engine, tenant, invitation_id)["sends"] == 2
    mail.raw.clear()
    deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)
    second_digest = invitation_row(admin_engine, tenant, invitation_id)["token_hash"]
    assert second_digest != first_digest

    events = chain(admin_engine, tenant)
    assert sum(1 for e in events if e["kind"] == "invitation.resent") == 1

    # Five sends in all.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.workspace_invitations SET sends = 5 WHERE invitation_id = :i"),
            {"i": invitation_id},
        )
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitation_messages "
                "SET delivered_at = now() - interval '1 hour' WHERE invitation_id = :i"
            ),
            {"i": invitation_id},
        )
    with pytest.raises(InvitationError) as excinfo:
        resend_invitation(runtime, session, invitation_id)
    assert excinfo.value.code == "RESEND_LIMIT"


def test_ti6_revoke_stops_delivery(db, admin_engine, seeded, mail):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)
    created = create_invitation(runtime, session, ADDRESS, None)
    invitation_id = created["invitation_id"]

    revoke_invitation(runtime, session, invitation_id)
    assert invitation_row(admin_engine, tenant, invitation_id)["state"] == "REVOKED"
    message = message_row(admin_engine, tenant, invitation_id)
    assert (message["state"], message["last_error"]) == ("FAILED", "REVOKED")

    counts = deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)
    assert counts == {"delivered": 0, "failed": 0, "deferred": 0}
    assert mail.messages() == []

    events = chain(admin_engine, tenant)
    assert sum(1 for e in events if e["kind"] == "invitation.revoked") == 1

    with pytest.raises(InvitationError) as excinfo:
        revoke_invitation(runtime, session, invitation_id)
    assert excinfo.value.code == "INVALID_STATE"

    with pytest.raises(InvitationError) as excinfo:
        revoke_invitation(runtime, session, uuid4())
    assert excinfo.value.code == "NOT_FOUND"


def test_ti7_a_transient_failure_stays_pending_and_an_invalid_state_settles_failed(
    db, admin_engine, seeded, tmp_path
):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)
    refused = create_invitation(runtime, session, ADDRESS, None)
    moved = create_invitation(runtime, session, "moved@example.org", None)

    revoke_invitation(runtime, session, moved["invitation_id"])
    # `revoke` already marks its own message FAILED `REVOKED` directly; put it back to
    # PENDING to exercise a different race instead: the invitation moves out from under an
    # already-leased message before the rekey that follows the lease runs.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitation_messages "
                "SET state = 'PENDING', last_error = NULL, next_attempt_at = now() "
                "WHERE invitation_id = :i"
            ),
            {"i": moved["invitation_id"]},
        )

    directory = tmp_path / "relay"
    directory.mkdir(parents=True, exist_ok=True)
    with relay(directory, refuse=(ADDRESS,)) as running:
        counts = deliver_invitations(
            db, mail=relay_mail(running), origin=ORIGIN, tls_context=running.context, limit=10
        )
    assert counts == {"delivered": 0, "failed": 1, "deferred": 1}

    transient = message_row(admin_engine, tenant, refused["invitation_id"])
    assert (transient["state"], transient["attempts"], transient["last_error"]) == (
        "PENDING",
        1,
        "MAIL_REFUSED",
    )
    terminal = message_row(admin_engine, tenant, moved["invitation_id"])
    assert (terminal["state"], terminal["last_error"]) == ("FAILED", "INVALID_STATE")
    # Terminal on the first attempt, not spent through retries.
    assert terminal["attempts"] == 1


# --- TI27 to TI29: a bad stored address never stalls the drain -------------------------------


def test_ti27_create_invitation_refuses_an_address_sql_accepts_but_is_address_refuses(
    db, admin_engine, seeded
):
    """SQL's own regex (`^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$`) is looser than
    `transports.is_address` and would accept both of these; `create_invitation` must refuse
    them before either ever reaches a row."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)
    for bad in ("o'brien@example.org", "a!b@example.org"):
        with pytest.raises(InvitationError) as excinfo:
            create_invitation(runtime, session, bad, None)
        assert excinfo.value.code == "INVALID_EMAIL"
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        count = conn.execute(
            text("SELECT count(*) FROM execbound.workspace_invitations WHERE tenant_id = :t"),
            {"t": tenant},
        ).scalar_one()
    assert count == 0

    # The happy path normalizes (strip, lowercase) before anything is stored, the same shape
    # `signups.py`'s own `normalized_address` uses.
    created = create_invitation(runtime, session, " Casey@Example.ORG ", None)
    assert created["email"] == ADDRESS
    assert invitation_row(admin_engine, tenant, created["invitation_id"])["email"] == ADDRESS


def test_ti28_a_bad_stored_address_settles_failed_and_never_stalls_another_tenant(
    db, admin_engine, seeded, mail
):
    """A row `create_invitation` would now refuse can still exist (legacy data, or anything
    written outside it), so it is inserted directly as the owner, inside its own fence,
    bypassing `workspace_invitation_create` entirely. Before this fix, `render_teammate_
    invitation`'s bare `ValueError` escaped `_send` uncaught and aborted `deliver_invitations`
    for every tenant still to come; the row stayed `IN_FLIGHT` with its old `next_attempt_at`,
    so every later run hit it first and aborted again. Now it settles FAILED
    `INVALID_ADDRESS` on its own first attempt, and the drain moves on.
    """
    legacy = workspace(admin_engine, name="Legacy")
    valid = workspace(admin_engine, name="Valid")
    bad_invitation, bad_message = uuid4(), uuid4()
    created_at = now()
    with admin_engine.begin() as conn:
        fenced(conn, legacy["tenant_id"])
        conn.execute(
            text(
                "INSERT INTO execbound.workspace_invitations"
                "(tenant_id, invitation_id, email, inviter_id, grants, created_at, expires_at) "
                "VALUES (:t, :i, :e, :p, CAST(:g AS jsonb), :c, :x)"
            ),
            {
                "t": legacy["tenant_id"],
                "i": bad_invitation,
                "e": "o'brien@example.org",
                "p": legacy["admin"],
                "g": json.dumps(VIEWER),
                "c": created_at,
                "x": created_at + timedelta(days=7),
            },
        )
        conn.execute(
            text(
                "INSERT INTO execbound.workspace_invitation_messages"
                "(tenant_id, message_id, invitation_id, created_at, next_attempt_at) "
                "VALUES (:t, :m, :i, :c, :c)"
            ),
            {"t": legacy["tenant_id"], "m": bad_message, "i": bad_invitation, "c": created_at},
        )

    runtime = bare_runtime(db)
    valid_session = admin_session(db, admin_engine, valid)
    good = create_invitation(runtime, valid_session, ADDRESS, None)

    counts = deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)
    assert counts == {"delivered": 1, "failed": 1, "deferred": 0}

    bad_row = message_row(admin_engine, legacy["tenant_id"], bad_invitation)
    assert (bad_row["state"], bad_row["last_error"], bad_row["attempts"]) == (
        "FAILED",
        "INVALID_ADDRESS",
        1,
    )
    good_row = message_row(admin_engine, valid["tenant_id"], good["invitation_id"])
    assert good_row["state"] == "DELIVERED"
    messages = mail.messages()
    assert len(messages) == 1
    assert messages[0]["To"] == ADDRESS


def test_ti29_deliver_one_logs_and_returns_false_on_an_unexpected_failure(
    db, admin_engine, seeded, mail, captured, monkeypatch
):
    """`deliver_one`'s own contract is that it never raises. Its `except` used to swallow a
    genuine fault with no trace at all; it must now log `invitation.refused` naming the
    tenant, with no exception text, before returning `False`."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]

    def _boom(*args, **kwargs):
        raise SQLAlchemyError("boom, and this text must never reach a log line")

    monkeypatch.setattr(invitations_module, "_lease", _boom)
    result = deliver_one(
        db, tenant, uuid4(), mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context
    )
    assert result is False

    lines = [json.loads(line) for line in captured.getvalue().splitlines() if line.strip()]
    refusals = [line for line in lines if line.get("event") == "invitation.refused"]
    assert len(refusals) == 1
    assert refusals[0]["code"] == "INVITATION_UNAVAILABLE"
    assert refusals[0]["tenant_id"] == str(tenant)
    assert refusals[0]["level"] == "WARNING"
    assert "boom" not in captured.getvalue()


# --- TI30 to TI36: faults contained, resend, the logged state and the list's bounds ----------


def test_ti30_a_settle_fault_counts_failed_and_a_second_tenants_message_still_delivers(
    db, admin_engine, seeded, mail, monkeypatch
):
    """`_settle` used to have no guard of its own: a database fault while settling one message
    escaped `deliver_invitations` uncaught and ended the run for every other due message. It is
    now guarded the same way `_lease` and `_send` already are, and counts the message as failed
    rather than raising; the row itself is left exactly as `_lease` set it (`IN_FLIGHT`, one
    attempt spent), so it is retried once that lease expires and nothing is lost."""
    first = workspace(admin_engine, name="First")
    second = workspace(admin_engine, name="Second")
    runtime = bare_runtime(db)
    a = create_invitation(runtime, admin_session(db, admin_engine, first), "a@example.org", None)
    b = create_invitation(runtime, admin_session(db, admin_engine, second), "b@example.org", None)

    # `a`'s message sorts first in the due list regardless of the real clock's own timing.
    with admin_engine.begin() as conn:
        fenced(conn, first["tenant_id"])
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitation_messages "
                "SET next_attempt_at = next_attempt_at - INTERVAL '1 hour' "
                "WHERE invitation_id = :i"
            ),
            {"i": a["invitation_id"]},
        )

    real_check_runtime = invitations_module.check_runtime
    calls = {"n": 0}

    def flaky(conn):
        calls["n"] += 1
        # 1 = `_due`, 2 = `_lease`(a), 3 = `_send`(a), 4 = `_settle`(a): fail exactly there,
        # so every other call (including `b`'s own lease, send and settle) sees the real one.
        if calls["n"] == 4:
            raise SQLAlchemyError("settle fault, must never reach a log line")
        real_check_runtime(conn)

    monkeypatch.setattr(invitations_module, "check_runtime", flaky)
    counts = deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)
    monkeypatch.undo()

    assert counts == {"delivered": 1, "failed": 1, "deferred": 0}
    a_row = message_row(admin_engine, first["tenant_id"], a["invitation_id"])
    assert (a_row["state"], a_row["attempts"]) == ("IN_FLIGHT", 1)
    b_row = message_row(admin_engine, second["tenant_id"], b["invitation_id"])
    assert b_row["state"] == "DELIVERED"


def test_ti30b_a_settle_fault_reaches_the_cli_as_a_fixed_exit_2_sentence(monkeypatch, capsys):
    """The CLI used to catch only `InvitationError`, `KeyError`, `OSError` and `ValueError` for
    `invitations-run`, so a `SQLAlchemyError` that still escapes `_settle`'s own guard (from
    `_due`, for instance) produced a traceback rather than a fixed sentence at exit 2. Driven
    through the real CLI entry point, `test_admin_cli.py`'s own `refused` idiom (`sys.argv` and
    `main()`), since `run_invitations_command` reads its database and runtime configuration from
    the environment before this test's own substitution ever runs."""
    from execbound import cli

    def boom(args):
        raise SQLAlchemyError("must never reach the printed sentence")

    monkeypatch.setattr(cli, "run_invitations_command", boom)
    monkeypatch.setattr(sys, "argv", ["execbound", cli.INVITATIONS_COMMAND])
    with pytest.raises(SystemExit) as exited:
        cli.main()
    assert exited.value.code == 2
    printed = capsys.readouterr()
    assert "database error" in printed.err.lower()
    assert "must never reach the printed sentence" not in printed.err


def test_ti31_the_exchange_answers_retry_for_our_own_fault(
    invite_client, db, admin_engine, monkeypatch, seeded
):
    """`POST /join` used to answer every `InvitationError` with `invalid`, so a transient fault
    on our own side told the person their still-good link was bad. `INVITATION_UNAVAILABLE` now
    answers `retry` (503), the same recoverable page `/join/accept` and `/join/confirm` already
    show; every other code, proven by TI19's own forged-token case, still answers `invalid`."""
    where = workspace(admin_engine)
    _, token = link(db, where, email="unavailable@example.org")

    def raiser(*args, **kwargs):
        raise InvitationError("INVITATION_UNAVAILABLE")

    monkeypatch.setattr(invite_pages, "inspect_invitation", raiser)
    shown = open_join(invite_client, token)
    monkeypatch.undo()
    assert shown.status_code == 503
    assert "Something went wrong on our side." in shown.text


def test_ti32_a_fault_signing_in_after_acceptance_still_says_joined(
    invite_client, db, admin_engine, human_config, monkeypatch, seeded
):
    """`sign_in_invited_account` used to run outside the route's own `try`: a fault there, after
    the acceptance already committed, answered a bare 500 although the membership existed. It is
    now guarded the same way `issue_session` already is, and answers `result("ready")`, the same
    "You have joined." page a retried acceptance of an already-accepted link shows (TI17)."""
    where = workspace(admin_engine)
    invitation, token = link(db, where, email="signinfault@example.org")
    shown = open_join(invite_client, token)
    _, values = form_values(shown.text, "/join/accept")
    values.update(password=CHOSEN, confirm=CHOSEN)

    def raiser(*args, **kwargs):
        raise InvitationError("INVALID_REQUEST")

    monkeypatch.setattr(invite_pages, "sign_in_invited_account", raiser)
    made = invite_client.post("/join/accept", data=values, headers={"Origin": ORIGIN})
    monkeypatch.undo()

    assert made.status_code == 200
    assert "You have joined." in made.text
    assert session_cookie_value(made, human_config) is None
    assert invitation_row(admin_engine, where["tenant_id"], invitation)["state"] == "ACCEPTED"


def test_ti33_resend_gets_the_same_fast_first_send_as_create(
    db, admin_engine, seeded, mail, monkeypatch
):
    """Resend is usually pressed because the first message never arrived, which is exactly when
    a wait for the scheduled drain is felt most: the resend route now schedules the same
    best-effort `deliver_one` background task create's own route already gets (TI23), using the
    message id `resend_invitation` now returns from the same transaction that returns the
    message to the outbox."""
    import ssl

    monkeypatch.setattr(ssl, "create_default_context", lambda *args, **kwargs: mail.context)
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = Runtime(db, [], mail=relay_mail(mail))
    with console_client_for(db, runtime, admin_engine, tenant, where["admin"]) as admin:
        created = admin.post(CONSOLE_API + "/teammate-invitations", {"email": ADDRESS})
        assert created.status_code == 200, created.text
        invitation_id = UUID(created.json()["invitation_id"])
        mail.raw.clear()
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.workspace_invitation_messages "
                    "SET delivered_at = :d WHERE invitation_id = :i"
                ),
                {"d": now() - timedelta(minutes=3), "i": invitation_id},
            )
        resent = admin.post(f"{CONSOLE_API}/teammate-invitations/{invitation_id}/resend")
        assert resent.status_code == 200, resent.text

    messages = mail.messages()
    assert len(messages) == 1
    assert messages[0]["To"] == ADDRESS
    message = message_row(admin_engine, tenant, invitation_id)
    assert message["state"] == "DELIVERED"
    assert message["attempts"] == 1


def test_ti34_invitation_sent_logs_the_state_actually_written(
    db, admin_engine, seeded, mail, captured
):
    """`invitation.sent` used to derive `state` from `result.delivered` alone, so a message that
    just settled `FAILED` was logged `PENDING`, misleading an operator reading the log for a
    stuck invitation. It now logs the state `_settle` actually wrote, proven here on the same
    terminal `INVALID_STATE` race TI7 already exercises."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)
    created = create_invitation(runtime, session, ADDRESS, None)

    revoke_invitation(runtime, session, created["invitation_id"])
    # `revoke` already marks its own message FAILED `REVOKED` directly; put it back to
    # PENDING so the drain actually attempts it and finds the invitation moved out from
    # under it, terminal on the first attempt, the same race TI7 exercises.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitation_messages "
                "SET state = 'PENDING', last_error = NULL, next_attempt_at = now() "
                "WHERE invitation_id = :i"
            ),
            {"i": created["invitation_id"]},
        )

    deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)

    row = message_row(admin_engine, tenant, created["invitation_id"])
    assert row["state"] == "FAILED"

    sent = logged(captured, "invitation.sent")
    assert len(sent) == 1
    assert sent[0]["state"] == "FAILED"
    assert sent[0]["code"] == "INVALID_STATE"


def test_ti35_list_invitations_filters_and_bounds_in_sql(db, admin_engine, seeded):
    """The thirty-day window used to be read unbounded and filtered afterward in Python, in the
    console route. It is now `created_at >= :cutoff` with a `LIMIT` in the SQL
    `list_invitations` itself runs, so the filtering has moved out of the route: a direct call
    to the service, exactly as the console route makes, already excludes an old row rather than
    relying on the route to drop it. TI26 proves the boundary semantics (dropped/kept by
    `created_at` alone, `state` ignored) are unchanged through the console route itself."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)

    old = create_invitation(runtime, session, "old@example.org", None)
    kept = create_invitation(runtime, session, "kept@example.org", None)
    backdated = now() - timedelta(days=31)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitations SET created_at = :c, expires_at = :e "
                "WHERE invitation_id = :i"
            ),
            {"c": backdated, "e": backdated + timedelta(days=7), "i": old["invitation_id"]},
        )

    rows = list_invitations(runtime, session)
    ids = {row["invitation_id"] for row in rows}
    assert old["invitation_id"] not in ids
    assert kept["invitation_id"] in ids
    assert len(rows) == 1


def test_ti36_the_drain_refuses_the_run_when_owner_drain_is_missing(
    db, admin_engine, seeded, mail, monkeypatch
):
    """`check_runtime` proves tables, grants, columns and functions but not policies, so a later
    migration that recreated the messages table without `owner_drain`, or one applied under a
    role other than the function owner, would leave a local superuser owner still seeing every
    row while a deployment whose owner does not bypass row security silently delivered nothing.
    `_check_drain_policy` now reads `pg_policy` itself, before the batch drain lists anything
    due, and refuses the whole run with a fixed code instead of delivering nothing.

    The policy is proven missing by dropping it inside one connection's own open
    transaction and reading it back there, never committed, so the shared test schema is
    untouched; the migrated database's own policy is then proven to still pass the same
    check. `deliver_invitations` refusing the whole run before anything is leased is proven
    separately, by substituting the check itself for the one call this test makes, which
    never touches the database either.
    """
    with admin_engine.connect() as conn:
        try:
            conn.execute(text("DROP POLICY owner_drain ON execbound.workspace_invitation_messages"))
            with pytest.raises(InvitationError) as refused:
                invitations_module._check_drain_policy(conn)
            assert refused.value.code == "UNSAFE_DRAIN_POLICY"
        finally:
            conn.rollback()

    with admin_engine.begin() as conn:
        invitations_module._check_drain_policy(conn)

    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    created = create_invitation(
        bare_runtime(db), admin_session(db, admin_engine, where), ADDRESS, None
    )

    def refuse(conn):
        raise InvitationError("UNSAFE_DRAIN_POLICY")

    monkeypatch.setattr(invitations_module, "_check_drain_policy", refuse)
    with pytest.raises(InvitationError) as run_refused:
        deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)
    monkeypatch.undo()
    assert run_refused.value.code == "UNSAFE_DRAIN_POLICY"

    row = message_row(admin_engine, tenant, created["invitation_id"])
    assert (row["state"], row["attempts"]) == ("PENDING", 0)


# --- Helpers for acceptance, TI8 onward ------------------------------------------------------

# A new address's own choice; `RETAINED` is the password `test_workspace_accounts.enroll` gives
# a person set up before accounts existed.
CHOSEN = "correct horse battery staple"


def send(db, tenant, invitation):
    """One send's rekey with a real link, exactly as `_send` mints it: the token and nothing
    else leaves this helper, and the database keeps only its digest."""
    token, token_hash = new_invitation_token(tenant, invitation)
    scalar(
        db,
        tenant,
        "SELECT execbound.workspace_invitation_rekey(:i, :h, :n)",
        {"i": invitation, "h": token_hash, "n": now()},
    )
    return token


def link(db, where, email=ADDRESS, grants=None):
    """An invitation made through its definer function and sent once."""
    invitation, _ = invite(db, where, email=email, grants=grants)
    return invitation, send(db, where["tenant_id"], invitation)


def delivered_token(running):
    """The newest invitation link token in the relay's messages."""
    found = None
    for message in running.messages():
        match = INVITE_TOKEN.search(message.get_content())
        if match:
            found = match.group(0)
    return found


def code_of(call, *args, **kwargs):
    """The code a call is refused with. An `InvitationError`'s message is fixed, never the code."""
    with pytest.raises(InvitationError) as refused:
        call(*args, **kwargs)
    return refused.value.code


def signed_in(db, email, password=RETAINED):
    """A workspace session and its account cookie from a normal password sign-in."""
    grant = issue_session(db, sign_in_with_password(db, email, password))
    return grant, load_session(db, grant.token)


def account_holder(db, admin_engine, email, *, name="Home"):
    """A person set up before accounts existed in a home workspace of their own, adopted into
    an account by their first password sign-in and signed in with its account cookie."""
    home = workspace(admin_engine, name=name)
    principal, _ = enroll(admin_engine, home["tenant_id"], email=email, kind="ADMIN")
    grant, session = signed_in(db, email)
    assert session.account_id is not None and session.identity.tenant_id == home["tenant_id"]
    return home, principal, grant, session


def second_admin(db, admin_engine, where):
    """Another unmanaged ADMIN of the same workspace, signed in: the inviter's peer."""
    principal = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, where["tenant_id"])
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, label) "
                "VALUES (:t, :p, 'ADMIN', 'Sam Admin')"
            ),
            {"t": where["tenant_id"], "p": principal},
        )
    return principal, session_for(db, admin_engine, where["tenant_id"], principal)


def people(engine, tenant):
    """Every principal of one tenant. Named by tenant as well as fenced: the local owner is a
    superuser, whose reads no policy narrows."""
    rows = owner_rows(
        engine,
        tenant,
        "SELECT principal_id FROM execbound.principals WHERE tenant_id = :t",
        {"t": tenant},
    )
    return sorted(row["principal_id"] for row in rows)


def members(engine, tenant):
    """Every membership row of one tenant, named by tenant for the same reason."""
    return owner_rows(
        engine,
        tenant,
        "SELECT account_id, principal_id, active FROM execbound.workspace_memberships "
        "WHERE tenant_id = :t",
        {"t": tenant},
    )


def accounts_for(admin_engine, email):
    with admin_engine.begin() as conn:
        return (
            conn.execute(
                text("SELECT account_id FROM execbound.user_accounts WHERE email = :e"),
                {"e": email},
            )
            .scalars()
            .all()
        )


def workspaces_of(db, account):
    with db.transaction(UNATTRIBUTED_CONTEXT) as conn:
        return {m["tenant_id"]: m["principal_id"] for m in user_accounts.memberships(conn, account)}


def logged(stream, event):
    lines = (json.loads(raw) for raw in stream.getvalue().splitlines() if raw.strip())
    return [line for line in lines if line.get("event") == event]


# --- TI8 and TI9: a new address, and an existing account -------------------------------------


def test_ti8_a_new_address_accepts_with_a_password_and_signs_in_once(
    db, admin_engine, seeded, mail, captured
):
    """CS05: the whole new-address path, from the administrator's invitation through the
    delivered link to one signed-in session, with no personal workspace or allocation."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    grants = [
        {"role": "viewer", "space_id": None},
        {"role": "approver", "space_id": str(where["space"])},
    ]
    created = create_invitation(runtime, admin_session(db, admin_engine, where), ADDRESS, grants)
    invitation = created["invitation_id"]
    deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)
    token = delivered_token(mail)
    assert token is not None

    seen = inspect_invitation(db, token)
    assert seen == Inspected(
        invitation_id=invitation,
        tenant_id=tenant,
        email=ADDRESS,
        state="PENDING",
        workspace=f"Inviting-{tenant.hex[:8]}",
        grants=grants,
        space_names={str(where["space"]): "Default"},
        inviter="Robin Admin",
        account="new",
    )

    accepted = accept_invitation(db, token, password=CHOSEN)
    assert (accepted.outcome, accepted.tenant_id, accepted.account_version) == (
        "ACCEPTED",
        tenant,
        1,
    )
    principal, account = accepted.principal_id, accepted.account_id
    assert principal is not None and account is not None

    # One account for the address, verified by the link, with a password and no allocation.
    assert accounts_for(admin_engine, ADDRESS) == [account]
    with admin_engine.begin() as conn:
        verified, has_password, allocations = conn.execute(
            text(
                "SELECT a.email_verified_at IS NOT NULL, "
                "EXISTS (SELECT 1 FROM execbound.user_passwords w "
                "        WHERE w.account_id = a.account_id), "
                "(SELECT count(*) FROM execbound.community_allocations c "
                " WHERE c.account_id = a.account_id) "
                "FROM execbound.user_accounts a WHERE a.account_id = :a"
            ),
            {"a": account},
        ).one()
    assert (verified, has_password, allocations) == (True, True, 0)
    # One managed HUMAN_APPROVER holding exactly the invitation's grants, and one membership.
    assert owner_rows(
        admin_engine,
        tenant,
        "SELECT kind, email, label, active FROM execbound.principals WHERE principal_id = :p",
        {"p": principal},
    ) == [{"kind": "HUMAN_APPROVER", "email": ADDRESS, "label": None, "active": True}]
    assert owner_rows(
        admin_engine,
        tenant,
        "SELECT principal_id FROM execbound.access_principals WHERE principal_id = :p",
        {"p": principal},
    ) == [{"principal_id": principal}]
    assert owner_rows(
        admin_engine,
        tenant,
        "SELECT role, space_id FROM execbound.access_role_grants WHERE principal_id = :p "
        "ORDER BY role",
        {"p": principal},
    ) == [
        {"role": "approver", "space_id": where["space"]},
        {"role": "viewer", "space_id": None},
    ]
    assert members(admin_engine, tenant) == [
        {"account_id": account, "principal_id": principal, "active": True}
    ]
    row = invitation_row(admin_engine, tenant, invitation)
    assert (row["state"], row["accepted_principal_id"], row["accepted_account_id"]) == (
        "ACCEPTED",
        principal,
        account,
    )

    # The tenant's chain after the invitation: the principal, the inviter's grant decision,
    # the acceptance. (The administrator's own sign-in comes before it.)
    events = chain(admin_engine, tenant)
    kinds = [e["kind"] for e in events]
    events = events[kinds.index("invitation.created") :]
    assert [e["kind"] for e in events] == [
        "invitation.created",
        "principal.created",
        "access.set_user_roles",
        "invitation.accepted",
    ]
    made, granted, joined = events[1:]
    assert made["actor_id"] == principal
    assert made["payload"] == {"principal_id": str(principal), "kind": "HUMAN_APPROVER"}
    assert granted["actor_id"] == where["admin"]
    assert granted["payload"] == {
        "subject_id": str(principal),
        "reason": f"invitation {invitation} accepted",
        "change": {"grants": grants},
        "revoked_password_resets": [],
    }
    assert joined["actor_id"] == principal
    assert joined["payload"] == {"invitation_id": str(invitation), "principal_id": str(principal)}
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    written = json.dumps([e["payload"] for e in events])
    assert ADDRESS not in written and token not in written and digest not in written

    # The one session this acceptance may mint, in that workspace, bound to the account.
    identity = sign_in_invited_account(db, accepted)
    assert (identity.tenant_id, identity.principal_id, identity.kind) == (
        tenant,
        principal,
        "HUMAN_APPROVER",
    )
    grant = issue_session(db, identity)
    assert grant.account_token is not None
    assert load_session(db, grant.token).account_id == account
    # The password it chose is the account's own from now on.
    assert sign_in_with_password(db, ADDRESS, CHOSEN).principal_id == principal

    # A retried completion finds the committed outcome and mints nothing.
    again = accept_invitation(db, token, password=CHOSEN)
    assert again == Accepted("ALREADY", tenant)
    assert code_of(sign_in_invited_account, db, again) == "INVALID_REQUEST"
    assert len(members(admin_engine, tenant)) == 1

    [line] = logged(captured, "invitation.accepted")
    assert (line["tenant_id"], line["principal_id"], line["invitation_id"]) == (
        str(tenant),
        str(principal),
        str(invitation),
    )
    produced = captured.getvalue()
    assert ADDRESS not in produced and token not in produced and digest not in produced


def test_ti8b_acceptance_writes_every_row_without_bypass(restricted, monkeypatch):
    """The Python acceptance path as an owner that does not bypass row security, so every
    `set_config` switch the definer bodies rely on is exercised under forced row-level security.
    It covers a `workspace_invitation_check` call (through `inspect_invitation`), a new-address
    acceptance end to end with every row read back fenced, and an `ACCOUNT_EXISTS` that only the
    SQL's own cross-tenant check can raise.
    """
    engine, config, _ = restricted
    command.upgrade(config, "head")
    runtime_url = with_database_name(os.environ["TEST_DATABASE_URL"], engine.url.database)
    db = Database(runtime_url, pool_size=1)
    try:
        where = workspace(engine)
        tenant = where["tenant_id"]
        invitation, token = link(db, where)

        # 1. The check, as this owner: every field comes back through the tenant fence.
        seen = inspect_invitation(db, token)
        assert (seen.state, seen.email, seen.inviter, seen.account) == (
            "PENDING",
            ADDRESS,
            "Robin Admin",
            "new",
        )
        assert seen.workspace == f"Inviting-{tenant.hex[:8]}" and seen.grants == VIEWER

        # 2. A new address, end to end.
        accepted = accept_invitation(db, token, password=CHOSEN)
        assert accepted.outcome == "ACCEPTED"
        principal, account = accepted.principal_id, accepted.account_id
        identity = sign_in_invited_account(db, accepted)
        assert (identity.tenant_id, identity.principal_id) == (tenant, principal)
        assert owner_rows(
            engine,
            tenant,
            "SELECT kind, email, active FROM execbound.principals WHERE principal_id = :p",
            {"p": principal},
        ) == [{"kind": "HUMAN_APPROVER", "email": ADDRESS, "active": True}]
        assert owner_rows(
            engine,
            tenant,
            "SELECT 1 AS managed FROM execbound.access_principals WHERE principal_id = :p",
            {"p": principal},
        ) == [{"managed": 1}]
        assert owner_rows(
            engine,
            tenant,
            "SELECT role, space_id FROM execbound.access_role_grants WHERE principal_id = :p",
            {"p": principal},
        ) == [{"role": "viewer", "space_id": None}]
        assert members(engine, tenant) == [
            {"account_id": account, "principal_id": principal, "active": True}
        ]
        row = invitation_row(engine, tenant, invitation)
        assert (row["state"], row["accepted_principal_id"], row["accepted_account_id"]) == (
            "ACCEPTED",
            principal,
            account,
        )
        assert message_row(engine, tenant, invitation)["last_error"] == "ACCEPTED"
        assert owner_rows(
            engine,
            tenant,
            "SELECT a.email, a.email_verified_at IS NOT NULL AS verified, "
            "w.account_id IS NOT NULL AS has_password FROM execbound.user_accounts a "
            "LEFT JOIN execbound.user_passwords w USING (account_id) WHERE a.account_id = :a",
            {"a": account},
            account=account,
        ) == [{"email": ADDRESS, "verified": True, "has_password": True}]
        assert [e["kind"] for e in chain(engine, tenant)] == [
            "principal.created",
            "access.set_user_roles",
            "invitation.accepted",
            "human_sign_in.password",
        ]

        # 3. An active legacy holder in another tenant. `inspect_invitation` is told to say
        #    `new`, so only the SQL's own check, reading every tenant through the
        #    `sign_in_email` marker as this owner, can refuse.
        legacy_holder(engine, "legacy@example.org", active=True)
        held, held_token = link(db, where, email="legacy@example.org")
        real = invitations_module.inspect_invitation
        assert real(db, held_token).account == "legacy"
        monkeypatch.setattr(
            invitations_module,
            "inspect_invitation",
            lambda *args, **kwargs: replace(real(*args, **kwargs), account="new"),
        )
        # `_accept_once` draws the principal id, then the account id, in this order.
        predicted_principal, predicted_account = uuid4(), uuid4()
        predicted = iter((predicted_principal, predicted_account))
        monkeypatch.setattr(invitations_module, "uuid4", lambda: next(predicted))
        assert code_of(accept_invitation, db, held_token, password=CHOSEN) == "ACCOUNT_EXISTS"
        monkeypatch.undo()
        assert invitation_row(engine, tenant, held)["state"] == "PENDING"
        assert (
            owner_rows(
                engine,
                tenant,
                "SELECT 1 FROM execbound.principals WHERE principal_id = :p",
                {"p": predicted_principal},
            )
            == []
        )
        assert (
            owner_rows(
                engine,
                tenant,
                "SELECT 1 FROM execbound.user_accounts WHERE account_id = :a",
                {"a": predicted_account},
                account=predicted_account,
            )
            == []
        )
    finally:
        db.close()


# --- TI10 to TI12: refusals -------------------------------------------------------------------


def test_ti10_the_wrong_account_pending_mfa_and_a_held_address_are_refused(
    db, admin_engine, seeded, captured, monkeypatch
):
    home, principal, grant, session = account_holder(db, admin_engine, ADDRESS)
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    invitation, token = link(db, where)

    # 1. A password for an address an account holds: the link is never a way to set one.
    assert inspect_invitation(db, token).account == "existing"
    assert code_of(accept_invitation, db, token, password=CHOSEN) == "ACCOUNT_EXISTS"
    # 2. A different signed-in account is refused, not reassigned.
    _, _, other_grant, other = account_holder(
        db, admin_engine, "someone-else@example.org", name="Elsewhere"
    )
    refused = code_of(
        accept_invitation, db, token, session=other, account_token=other_grant.account_token
    )
    assert refused == "ACCOUNT_MISMATCH"
    # 3. The right session without its own account cookie proves no account.
    for cookie in (None, "as1.not-this-account", other_grant.account_token):
        refused = code_of(accept_invitation, db, token, session=session, account_token=cookie)
        assert refused == "ACCOUNT_MISMATCH"
    # 4. Exactly one proof of the person.
    assert code_of(accept_invitation, db, token) == "INVALID_REQUEST"
    refused = code_of(
        accept_invitation,
        db,
        token,
        password=CHOSEN,
        session=session,
        account_token=grant.account_token,
    )
    assert refused == "INVALID_REQUEST"
    # 5. A session still waiting for its MFA is not signed in yet.
    pending_grant, pending = mfa_gated_session(
        db, admin_engine, home["tenant_id"], principal, ADDRESS
    )
    refused = code_of(
        accept_invitation, db, token, session=pending, account_token=pending_grant.account_token
    )
    assert refused == "ACCOUNT_MISMATCH"
    row = invitation_row(admin_engine, tenant, invitation)
    assert (row["state"], row["failures"]) == ("PENDING", 0)

    # 6. An address an active person set up before accounts existed holds: they sign in first.
    legacy = workspace(admin_engine, name="Legacy")
    enroll(admin_engine, legacy["tenant_id"], email="legacy@example.org", kind="ADMIN")
    held, held_token = link(db, where, email="legacy@example.org")
    assert inspect_invitation(db, held_token).account == "legacy"
    assert code_of(accept_invitation, db, held_token, password=CHOSEN) == "ACCOUNT_EXISTS"

    # 7. A holder who appears after inspection is still refused, by the SQL (#498).
    late, late_token = link(db, where, email="late@example.org")
    real = invitations_module.inspect_invitation

    def then_enrolled(*args, **kwargs):
        seen = real(*args, **kwargs)
        assert seen.account == "new"
        enroll(admin_engine, legacy["tenant_id"], email="late@example.org")
        return seen

    monkeypatch.setattr(invitations_module, "inspect_invitation", then_enrolled)
    assert code_of(accept_invitation, db, late_token, password=CHOSEN) == "ACCOUNT_EXISTS"
    monkeypatch.undo()

    for waiting in (invitation, held, late):
        assert invitation_row(admin_engine, tenant, waiting)["state"] == "PENDING"
    assert people(admin_engine, tenant) == [where["admin"]]
    assert accounts_for(admin_engine, "legacy@example.org") == []
    assert accounts_for(admin_engine, "late@example.org") == []

    codes = {line["code"] for line in logged(captured, "invitation.refused")}
    assert {"ACCOUNT_EXISTS", "ACCOUNT_MISMATCH", "INVALID_REQUEST"} <= codes
    produced = captured.getvalue()
    for secret in (ADDRESS, "legacy@example.org", "late@example.org", token, late_token):
        assert secret not in produced


def test_ti11_revoked_expired_forged_and_superseded_links_are_refused(
    db, admin_engine, seeded, mail, captured
):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    admin = admin_session(db, admin_engine, where)
    _, _, holder_grant, holder = account_holder(db, admin_engine, "revoked@example.org")
    proof = {"session": holder, "account_token": holder_grant.account_token}

    # Revoked: the page can say so, and neither proof of the person gets past it.
    revoked, revoked_token = link(db, where, email="revoked@example.org")
    revoke_invitation(runtime, admin, revoked)
    assert inspect_invitation(db, revoked_token).state == "REVOKED"
    assert code_of(accept_invitation, db, revoked_token, password=CHOSEN) == "INVITATION_REVOKED"
    assert code_of(accept_invitation, db, revoked_token, **proof) == "INVITATION_REVOKED"

    # Expired: seven days after it was created, whatever was sent since.
    expired, expired_token = link(db, where, email="expired@example.org")
    created_at = now() - timedelta(days=8)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitations SET created_at = :c, expires_at = :e "
                "WHERE invitation_id = :i"
            ),
            {"c": created_at, "e": created_at + timedelta(days=7), "i": expired},
        )
    assert inspect_invitation(db, expired_token).state == "EXPIRED"
    assert code_of(accept_invitation, db, expired_token, password=CHOSEN) == "INVALID_TOKEN"

    # Forged: every wrong guess commits its count before the refusal, on both paths, and
    # five of them lock the real link out.
    forged_id, real_token = link(db, where, email="forged@example.org")
    forged = real_token[:-4] + ("AAAA" if not real_token.endswith("AAAA") else "BBBB")
    for _ in range(3):
        assert code_of(inspect_invitation, db, forged) == "INVALID_TOKEN"
    assert code_of(accept_invitation, db, forged, password=CHOSEN) == "INVALID_TOKEN"
    assert code_of(accept_invitation, db, forged, **proof) == "INVALID_TOKEN"
    assert invitation_row(admin_engine, tenant, forged_id)["failures"] == 5
    assert code_of(inspect_invitation, db, real_token) == "INVALID_TOKEN"
    assert code_of(accept_invitation, db, real_token, password=CHOSEN) == "INVALID_TOKEN"
    assert invitation_row(admin_engine, tenant, forged_id)["state"] == "PENDING"
    # A malformed code never reaches the database at all.
    for bad in ("not-a-token", real_token + "x", real_token.replace("ebt1", "ebs1", 1), 5):
        assert code_of(inspect_invitation, db, bad) == "INVALID_TOKEN"
        assert code_of(accept_invitation, db, bad, password=CHOSEN) == "INVALID_TOKEN"

    # Superseded: a resend mints a new link and the older one dies.
    created = create_invitation(runtime, admin, "resent@example.org", None)
    deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)
    first = delivered_token(mail)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitation_messages SET delivered_at = :d "
                "WHERE invitation_id = :i"
            ),
            {"d": now() - timedelta(minutes=3), "i": created["invitation_id"]},
        )
    resend_invitation(runtime, admin, created["invitation_id"])
    mail.raw.clear()
    deliver_invitations(db, mail=relay_mail(mail), origin=ORIGIN, tls_context=mail.context)
    second = delivered_token(mail)
    assert None not in (first, second) and first != second
    assert code_of(accept_invitation, db, first, password=CHOSEN) == "INVALID_TOKEN"
    assert accept_invitation(db, second, password=CHOSEN).outcome == "ACCEPTED"

    joined = invitation_row(admin_engine, tenant, created["invitation_id"])
    assert people(admin_engine, tenant) == sorted([where["admin"], joined["accepted_principal_id"]])
    produced = captured.getvalue()
    for secret in (real_token, forged, first, second, revoked_token, expired_token):
        assert secret not in produced
        assert hashlib.sha256(secret.encode("ascii")).hexdigest() not in produced
    for address in ("revoked@example.org", "expired@example.org", "resent@example.org"):
        assert address not in produced


def test_ti12_an_inviter_who_lost_authority_admits_nobody(db, admin_engine, seeded):
    """The inviter's authority is read at acceptance, not when they clicked Invite."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    peer, peer_session = second_admin(db, admin_engine, where)
    demoted, demoted_token = link(db, where, email="demoted@example.org")
    removed, removed_token = link(db, where, email="removed@example.org")

    # Moved to Viewer by another administrator.
    viewer = [{"role": "viewer", "space_id": None}]
    set_user_roles(runtime, peer_session, where["admin"], viewer, "read-only now")
    assert code_of(accept_invitation, db, demoted_token, password=CHOSEN) == "FORBIDDEN"
    # Given the role back, then removed from the workspace altogether: removal is principal
    # deactivation. `people_pages.deactivate` refuses any administrator as its target, so
    # the owner makes the same change the TI1 cases make.
    administrator = [{"role": "administrator", "space_id": None}]
    set_user_roles(runtime, peer_session, where["admin"], administrator, "restored")
    set_active(admin_engine, tenant, where["admin"], False)
    assert code_of(accept_invitation, db, removed_token, password=CHOSEN) == "FORBIDDEN"

    assert people(admin_engine, tenant) == sorted([where["admin"], peer])
    assert members(admin_engine, tenant) == []
    for email, invitation in (("demoted@example.org", demoted), ("removed@example.org", removed)):
        assert accounts_for(admin_engine, email) == []
        row = invitation_row(admin_engine, tenant, invitation)
        assert (row["state"], row["failures"]) == ("PENDING", 0)
    kinds = [e["kind"] for e in chain(admin_engine, tenant)]
    assert "principal.created" not in kinds and "invitation.accepted" not in kinds


def test_ti12b_a_space_archived_after_the_invitation_refuses_acceptance(db, admin_engine, seeded):
    """`access_change` re-checks every Space at acceptance, so a Space archived after the
    invitation was made refuses it, on either path, and nothing is made."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    in_space = [{"role": "approver", "space_id": str(where["space"])}]
    fresh, fresh_token = link(db, where, grants=in_space)
    _, _, grant, session = account_holder(db, admin_engine, "held@example.org")
    held, held_token = link(db, where, email="held@example.org", grants=in_space)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.spaces SET archived_at = now() WHERE space_id = :s"),
            {"s": where["space"]},
        )
    assert code_of(accept_invitation, db, fresh_token, password=CHOSEN) == "INVALID_SPACE"
    refused = code_of(
        accept_invitation, db, held_token, session=session, account_token=grant.account_token
    )
    assert refused == "INVALID_SPACE"
    assert people(admin_engine, tenant) == [where["admin"]]
    assert accounts_for(admin_engine, ADDRESS) == []
    assert members(admin_engine, tenant) == []
    assert workspaces_of(db, session.account_id).keys() == {session.identity.tenant_id}
    for invitation in (fresh, held):
        assert invitation_row(admin_engine, tenant, invitation)["state"] == "PENDING"


# --- TI13: races, real threads meeting inside open transactions ------------------------------


def in_step(monkeypatch, *modules, parties=2):
    """Make concurrent calls meet inside their transactions, before either takes a lock.

    `check_runtime` is the first statement of every transaction these modules open, so each
    party waits there for the others: once in the inspection a password acceptance or a
    signup completion makes first, and once more with its accepting transaction open. Without
    it the second thread spends its first tens of milliseconds opening an overflow connection
    and the "race" runs one after the other.
    """
    barrier = threading.Barrier(parties, timeout=10)
    for module in modules:
        real = module.check_runtime

        def meet(conn, real=real):
            real(conn)
            barrier.wait()

        monkeypatch.setattr(module, "check_runtime", meet)
    return barrier


def outcome_of(call, *args, **kwargs):
    try:
        return call(*args, **kwargs).outcome
    except InvitationError as exc:
        return exc.code


def test_ti13a_two_acceptances_of_one_link_make_one_account(db, admin_engine, seeded, monkeypatch):
    """A new address, twice at once: the second waits on the first and finds its outcome."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    invitation, token = link(db, where)
    in_step(monkeypatch, invitations_module)
    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = [pool.submit(outcome_of, accept_invitation, db, token, password=CHOSEN)]
        attempts.append(pool.submit(outcome_of, accept_invitation, db, token, password=CHOSEN))
        outcomes = sorted(attempt.result(timeout=30) for attempt in attempts)
    monkeypatch.undo()
    assert outcomes == ["ACCEPTED", "ALREADY"]
    assert len(accounts_for(admin_engine, ADDRESS)) == 1
    principal = invitation_row(admin_engine, tenant, invitation)["accepted_principal_id"]
    assert people(admin_engine, tenant) == sorted([where["admin"], principal])
    assert len(members(admin_engine, tenant)) == 1


def test_ti13b_one_account_accepting_twice_at_once_makes_one_membership(
    db, admin_engine, seeded, monkeypatch
):
    """One signed-in account, twice at once (a double click): the account lock orders them."""
    home, _, grant, session = account_holder(db, admin_engine, ADDRESS)
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    _, token = link(db, where)
    proof = {"session": session, "account_token": grant.account_token}
    in_step(monkeypatch, invitations_module)
    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = [pool.submit(outcome_of, accept_invitation, db, token, **proof)]
        attempts.append(pool.submit(outcome_of, accept_invitation, db, token, **proof))
        outcomes = sorted(attempt.result(timeout=30) for attempt in attempts)
    monkeypatch.undo()
    assert outcomes == ["ACCEPTED", "ALREADY"]
    assert workspaces_of(db, session.account_id).keys() == {home["tenant_id"], tenant}
    assert len(people(admin_engine, tenant)) == 2 and len(members(admin_engine, tenant)) == 1


def test_ti13c_acceptance_against_a_concurrent_revoke_has_one_outcome(
    db, admin_engine, seeded, monkeypatch
):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    admin = admin_session(db, admin_engine, where)
    invitation, token = link(db, where)
    barrier = in_step(monkeypatch, invitations_module)

    def revoking():
        # The acceptance meets the barrier once more than a revoke does (in its inspection),
        # so this thread stands in for that meeting before opening its own transaction.
        barrier.wait()
        try:
            revoke_invitation(runtime, admin, invitation)
            return "REVOKED"
        except InvitationError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        accepting = pool.submit(outcome_of, accept_invitation, db, token, password=CHOSEN)
        revoke = pool.submit(revoking)
        outcomes = {accepting.result(timeout=30), revoke.result(timeout=30)}
    monkeypatch.undo()
    state = invitation_row(admin_engine, tenant, invitation)["state"]
    assert outcomes in ({"ACCEPTED", "INVALID_STATE"}, {"INVITATION_REVOKED", "REVOKED"})
    if "ACCEPTED" in outcomes:
        assert state == "ACCEPTED" and len(people(admin_engine, tenant)) == 2
        assert len(accounts_for(admin_engine, ADDRESS)) == 1
    else:
        assert state == "REVOKED" and people(admin_engine, tenant) == [where["admin"]]
        assert accounts_for(admin_engine, ADDRESS) == []


# --- TI14: the account and membership boundary (CS09) -----------------------------------------


def test_ti14a_the_inviting_administrator_cannot_reach_the_members_account(
    db, admin_engine, seeded
):
    home, _, grant, session = account_holder(db, admin_engine, ADDRESS)
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    _, token = link(db, where)
    joined = accept_invitation(db, token, session=session, account_token=grant.account_token)
    member = joined.principal_id

    # The workspace's own reads see its one membership row and nothing of the account.
    with db.transaction(tenant) as conn:
        check_runtime(conn)
        visible = conn.execute(text("SELECT tenant_id FROM execbound.workspace_memberships"))
        assert visible.scalars().all() == [tenant]
        for table in (
            "user_accounts",
            "user_passwords",
            "user_factors",
            "user_passkeys",
            "user_identities",
            "account_sessions",
        ):
            count = conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one()
            assert count == 0, table
    # Nor can it write the account's password or factors directly.
    for statement in (
        "UPDATE execbound.user_passwords SET updated_at = now()",
        "DELETE FROM execbound.user_passwords",
        "DELETE FROM execbound.user_factors",
        "DELETE FROM execbound.user_passkeys",
    ):
        with pytest.raises(DBAPIError, match="permission denied"), db.transaction(tenant) as conn:
            conn.execute(text(statement))
    # And its administrator's own doors to a person's password and address refuse an account.
    for call, args in (
        (issue_reset, (db, tenant, where["admin"], member)),
        (set_email, (db, tenant, where["admin"], member, "taken-over@example.org")),
    ):
        with pytest.raises(PasswordError) as refused:
            call(*args)
        assert refused.value.code == "ACCOUNT_OWNER_REQUIRED"
    assert workspaces_of(db, session.account_id).keys() == {home["tenant_id"], tenant}


# --- TI15: an administrator invitation ------------------------------------------------------


def test_ti15_an_administrator_invitation_is_applied_through_access_change(
    db, admin_engine, seeded
):
    """`access_change`'s promotion handling runs for the new principal: it revokes whatever
    credentials, sessions, resets and identity invitations that principal held before it
    became an administrator, which for a principal this call just made is nothing."""
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    administrator = [{"role": "administrator", "space_id": None}]
    invitation, token = link(db, where, grants=administrator)
    accepted = accept_invitation(db, token, password=CHOSEN)
    principal = accepted.principal_id
    with db.transaction(tenant) as conn:
        assert has_permission(conn, tenant, principal, "access.manage")
        assert capabilities(conn, tenant, principal)["roles"] == ["administrator"]
    credentials = owner_rows(
        admin_engine,
        tenant,
        "SELECT 1 FROM execbound.credentials WHERE principal_id = :p",
        {"p": principal},
    )
    assert credentials == []
    events = chain(admin_engine, tenant)
    assert [e["kind"] for e in events] == [
        "principal.created",
        "access.set_user_roles",
        "invitation.accepted",
    ]
    assert events[1]["actor_id"] == where["admin"]
    assert events[1]["payload"] == {
        "subject_id": str(principal),
        "reason": f"invitation {invitation} accepted",
        "change": {"grants": administrator},
        "revoked_password_resets": [],
    }
    assert sign_in_invited_account(db, accepted).kind == "ADMIN"
    assert isinstance(accepted.account_id, UUID)


# --- TI16 to TI19: the acceptance pages over HTTP --------------------------------------------


@pytest.fixture
def invite_app(db, human_config):
    return create_app(db, runtime=bare_runtime(db), human=human_config)


@pytest.fixture
def invite_client(invite_app):
    with TestClient(invite_app, base_url=ORIGIN, follow_redirects=False) as client:
        yield client


def open_join(client, token):
    """What the page's script does: GET the page, then POST the fragment in the form body."""
    page = client.get("/join")
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["referrer-policy"] == "same-origin"
    assert '<script src="/assets/invite.js"' in page.text
    _, values = form_values(page.text, "/join")
    values["token"] = token
    return client.post("/join", data=values, headers={"Origin": ORIGIN})


def test_ti16_a_scanner_gets_change_nothing_and_a_query_string_is_refused(
    invite_client, db, admin_engine, seeded
):
    where = workspace(admin_engine)
    invitation, token = link(db, where)
    before = invitation_row(admin_engine, where["tenant_id"], invitation)
    for _ in range(3):
        page = invite_client.get("/join")
        assert page.status_code == 200
        assert page.headers["cache-control"] == "no-store"
    # A query string is refused outright: the secret is never accepted from a URL.
    assert invite_client.get(f"/join?token={token}").status_code == 400
    shown = open_join(invite_client, token)
    assert shown.status_code == 200
    after = invitation_row(admin_engine, where["tenant_id"], invitation)
    assert (after["state"], after["failures"]) == (before["state"], before["failures"])
    assert after["state"] == "PENDING"


def test_ti17_the_new_address_flow_over_http_signs_the_person_in_once(
    invite_client, db, admin_engine, human_config, seeded
):
    where = workspace(admin_engine)
    invitation, token = link(db, where)
    shown = open_join(invite_client, token)
    assert shown.status_code == 200
    assert "Robin Admin" in shown.text
    assert f"Inviting-{where['tenant_id'].hex[:8]}" in shown.text
    assert "Viewer in all Spaces" in shown.text
    assert 'name="password"' in shown.text and 'name="confirm"' in shown.text
    _, values = form_values(shown.text, "/join/accept")
    values.update(password=CHOSEN, confirm=CHOSEN)
    made = invite_client.post("/join/accept", data=values, headers={"Origin": ORIGIN})
    assert made.status_code == 303
    assert made.headers["referrer-policy"] == "same-origin"
    minted = session_cookie_value(made, human_config)
    assert minted is not None and minted != ""

    # Reopening the same link after acceptance finds the workspace ready and signs nobody in.
    invite_client.cookies.clear()
    again = open_join(invite_client, token)
    assert again.status_code == 200
    assert "You have joined." in again.text
    assert session_cookie_value(again, human_config) is None
    assert invitation_row(admin_engine, where["tenant_id"], invitation)["state"] == "ACCEPTED"


def test_ti18_the_existing_account_flow_over_http_joins_pending_mfa_and_mismatch(
    invite_client, db, admin_engine, human_config, seeded
):
    """The existing-account flow joins over HTTP; a pending-MFA session is refused at
    `/join/confirm` and sent to `/mfa` rather than ever shown the invalid or mismatch page;
    and a different signed-in account is refused with `mismatch`, 403.
    """
    home, principal, grant, session = account_holder(db, admin_engine, "dana@example.org")
    where = workspace(admin_engine)
    invitation, token = link(db, where, email="dana@example.org")
    invite_client.cookies.set(human_config.cookie("session"), grant.token)
    invite_client.cookies.set(human_config.cookie("csrf"), grant.csrf_token)
    invite_client.cookies.set(human_config.cookie("account"), grant.account_token)

    shown = open_join(invite_client, token)
    assert shown.status_code == 200
    assert 'name="password"' not in shown.text
    assert "Robin Admin" in shown.text
    _, values = form_values(shown.text, "/join/confirm")
    assert values["csrf"] == grant.csrf_token
    answer = invite_client.post("/join/confirm", data=values, headers={"Origin": ORIGIN})
    assert answer.status_code == 200
    assert "You have joined" in answer.text
    assert f"Inviting-{where['tenant_id'].hex[:8]}" in answer.text
    # Switching between workspaces is core, so the joined page points at the menu.
    assert "Choose it from the workspace menu." in answer.text
    assert "cannot switch between workspaces" not in answer.text
    assert invitation_row(admin_engine, where["tenant_id"], invitation)["state"] == "ACCEPTED"

    # A session still waiting for its MFA is never signed in yet: the exchange treats it as
    # signed out, and `/join/confirm` behind it refuses and sends the browser to `/mfa`
    # without provisioning anything.
    other_home, other_principal, _, _ = account_holder(
        db, admin_engine, "fay@example.org", name="Elsewhere"
    )
    pending_grant, _ = mfa_gated_session(
        db, admin_engine, other_home["tenant_id"], other_principal, "fay@example.org"
    )
    pending_invitation, pending_token = link(db, where, email="fay@example.org")
    invite_client.cookies.clear()
    invite_client.cookies.set(human_config.cookie("session"), pending_grant.token)
    invite_client.cookies.set(human_config.cookie("csrf"), pending_grant.csrf_token)
    invite_client.cookies.set(human_config.cookie("account"), pending_grant.account_token)
    pending_shown = open_join(invite_client, pending_token)
    assert pending_shown.status_code == 200
    assert (
        "This address already has an ExecBound account. Sign in, then open the link again."
        in pending_shown.text
    )
    confirm_answer = invite_client.post(
        "/join/confirm",
        data={"csrf": pending_grant.csrf_token, "token": pending_token},
        headers={"Origin": ORIGIN},
    )
    assert confirm_answer.status_code == 303
    assert confirm_answer.headers["location"] == "/mfa"
    assert (
        invitation_row(admin_engine, where["tenant_id"], pending_invitation)["state"] == "PENDING"
    )

    # A different signed-in account is refused, not reassigned. The invited address needs an
    # account of its own too, or the exchange classifies it `new` and shows the create form
    # rather than ever reaching the signed-in check.
    account_holder(db, admin_engine, "gina@example.org", name="Ginas home")
    mismatch_invitation, mismatch_token = link(db, where, email="gina@example.org")
    invite_client.cookies.clear()
    invite_client.cookies.set(human_config.cookie("session"), grant.token)
    invite_client.cookies.set(human_config.cookie("csrf"), grant.csrf_token)
    invite_client.cookies.set(human_config.cookie("account"), grant.account_token)
    mismatched = open_join(invite_client, mismatch_token)
    assert mismatched.status_code == 403
    assert "You are signed in as a different account." in mismatched.text
    assert (
        invitation_row(admin_engine, where["tenant_id"], mismatch_invitation)["state"] == "PENDING"
    )


def test_ti19_each_result_kind_carries_its_own_status(
    invite_client, db, admin_engine, human_config, monkeypatch, seeded
):
    """`RESULT_STATUS` pinned both ways: every kind `invite_result.html` can show answers with
    that kind's one status, whichever route shows it."""
    where = workspace(admin_engine)

    # invalid, 403: a forged token.
    _, real_token = link(db, where, email="forged@example.org")
    forged = real_token[:-4] + ("AAAA" if not real_token.endswith("AAAA") else "BBBB")
    shown = open_join(invite_client, forged)
    assert shown.status_code == 403
    assert "This invitation is not valid or has expired." in shown.text

    # revoked, 403: a real revoke.
    revoked_invitation, revoked_token = link(db, where, email="revoked@example.org")
    revoke_invitation(bare_runtime(db), admin_session(db, admin_engine, where), revoked_invitation)
    shown = open_join(invite_client, revoked_token)
    assert shown.status_code == 403
    assert "This invitation was withdrawn." in shown.text

    # ready, 200: already accepted.
    _, ready_token = link(db, where, email="ready@example.org")
    accepted = accept_invitation(db, ready_token, password=CHOSEN)
    assert accepted.outcome == "ACCEPTED"
    shown = open_join(invite_client, ready_token)
    assert shown.status_code == 200
    assert "You have joined." in shown.text

    # sign_in_first, 200: an existing account, no session.
    home, principal, grant, session = account_holder(db, admin_engine, "signfirst@example.org")
    _, signfirst_token = link(db, where, email="signfirst@example.org")
    invite_client.cookies.clear()
    shown = open_join(invite_client, signfirst_token)
    assert shown.status_code == 200
    assert "This address already has an ExecBound account." in shown.text

    # mismatch, 403: a different signed-in account. The invited address needs an account of
    # its own too, or the exchange classifies it `new` and never reaches the signed-in check.
    account_holder(db, admin_engine, "mismatched@example.org", name="Mismatched home")
    _, mismatch_token = link(db, where, email="mismatched@example.org")
    invite_client.cookies.set(human_config.cookie("session"), grant.token)
    invite_client.cookies.set(human_config.cookie("csrf"), grant.csrf_token)
    invite_client.cookies.set(human_config.cookie("account"), grant.account_token)
    shown = open_join(invite_client, mismatch_token)
    assert shown.status_code == 403
    assert "You are signed in as a different account." in shown.text

    # joined, 200: the same signed-in account, the same invitation `sign_in_first` showed it.
    shown = open_join(invite_client, signfirst_token)
    _, values = form_values(shown.text, "/join/confirm")
    answer = invite_client.post("/join/confirm", data=values, headers={"Origin": ORIGIN})
    assert answer.status_code == 200
    assert "You have joined" in answer.text

    # retry, 503: our own side fails, and the link is still good.
    _, retry_token = link(db, where, email="retry@example.org")
    shown = open_join(invite_client, retry_token)
    _, values = form_values(shown.text, "/join/accept")
    values.update(password=CHOSEN, confirm=CHOSEN)

    def raiser(*args, **kwargs):
        raise InvitationError("INVITATION_UNAVAILABLE")

    monkeypatch.setattr(invite_pages, "accept_invitation", raiser)
    answer = invite_client.post("/join/accept", data=values, headers={"Origin": ORIGIN})
    assert answer.status_code == 503
    assert "Something went wrong on our side." in answer.text
    monkeypatch.undo()

    assert set(invite_pages.RESULT_STATUS) == {
        "joined",
        "ready",
        "sign_in_first",
        "mismatch",
        "revoked",
        "invalid",
        "retry",
    }


# --- TI22 to TI24: the console API -----------------------------------------------------------


@contextmanager
def console_client_for(db, runtime, admin_engine, tenant, principal):
    """A signed-in console session for an existing principal of `tenant`, over the human
    surface's own `/login` -> `/session` form, the same path a browser takes, with a fresh
    credential this call provisions and nobody else ever sees. Distinct from `admin_session`
    and `member_session` above (the service tests' direct `Session` objects): this is the
    console API over real HTTP, cookies and CSRF, the way `console_api_fixtures.console_client`
    signs a `world` fixture's principal in, adapted to this file's own `workspace()` tenants."""
    app = create_app(db, runtime=runtime, human=console_config())
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            token = provision_credential(conn, tenant, principal, now(), timedelta(hours=2))
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = token
        signed_in = client.post("/session", data=values, headers={"Origin": ORIGIN})
        assert signed_in.status_code == 303, signed_in.text
        opened = client.get(CONSOLE_API + "/session")
        assert opened.status_code == 200, opened.text
        yield ConsoleClient(client, opened.json()["csrf_token"])


def test_ti22_the_console_api_creates_lists_resends_and_revokes_as_an_administrator(
    db, admin_engine, seeded
):
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    with console_client_for(db, runtime, admin_engine, tenant, where["admin"]) as admin:
        created = admin.post(CONSOLE_API + "/teammate-invitations", {"email": ADDRESS})
        assert created.status_code == 200, created.text
        assert_no_secrets(created)
        invitation_id = UUID(created.json()["invitation_id"])
        assert created.json()["expires_at"] is not None
        row = invitation_row(admin_engine, tenant, invitation_id)
        assert row["state"] == "PENDING" and row["grants"] == VIEWER

        listed = admin.get(CONSOLE_API + "/teammate-invitations")
        assert listed.status_code == 200, listed.text
        assert_no_secrets(listed)
        rows = {item["invitation_id"]: item for item in listed.json()["invitations"]}
        assert rows[str(invitation_id)]["email"] == ADDRESS
        assert rows[str(invitation_id)]["grants"] == VIEWER
        assert rows[str(invitation_id)]["state"] == "PENDING"

        # A resend is bounded by spacing (TI5): the freshly created message is still on its
        # way, so it has to look already delivered a while ago before a resend is allowed.
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.workspace_invitation_messages "
                    "SET state = 'DELIVERED', delivered_at = :d WHERE invitation_id = :i"
                ),
                {"d": now() - timedelta(minutes=3), "i": invitation_id},
            )
        resent = admin.post(f"{CONSOLE_API}/teammate-invitations/{invitation_id}/resend")
        assert resent.status_code == 200, resent.text
        assert invitation_row(admin_engine, tenant, invitation_id)["sends"] == 2

        revoked = admin.post(f"{CONSOLE_API}/teammate-invitations/{invitation_id}/revoke")
        assert revoked.status_code == 200, revoked.text
        assert invitation_row(admin_engine, tenant, invitation_id)["state"] == "REVOKED"

        # A second revoke of the same, now-revoked invitation is a typed conflict, not a 500.
        again = admin.post(f"{CONSOLE_API}/teammate-invitations/{invitation_id}/revoke")
        assert again.status_code == 409, again.text
        assert again.json()["code"] == "CONFLICT"

    # A Viewer (an ordinary member with no `access.manage`) is refused on every route.
    other = create_invitation(
        runtime, admin_session(db, admin_engine, where), "other@example.org", None
    )
    viewer_principal = member_session(db, admin_engine, where).identity.principal_id
    with console_client_for(db, runtime, admin_engine, tenant, viewer_principal) as viewer:
        refusals = [
            viewer.get(CONSOLE_API + "/teammate-invitations"),
            viewer.post(CONSOLE_API + "/teammate-invitations", {"email": "third@example.org"}),
            viewer.post(f"{CONSOLE_API}/teammate-invitations/{other['invitation_id']}/resend"),
            viewer.post(f"{CONSOLE_API}/teammate-invitations/{other['invitation_id']}/revoke"),
        ]
        for response in refusals:
            assert response.status_code == 403, response.text
            assert response.json()["code"] == "FORBIDDEN"
    # None of the Viewer's refused attempts changed anything.
    assert invitation_row(admin_engine, tenant, other["invitation_id"])["state"] == "PENDING"


def test_ti23_create_schedules_exactly_one_best_effort_send(
    db, admin_engine, seeded, mail, monkeypatch
):
    """The relay double proves the background task really ran: `TestClient` drives the ASGI
    app in-process and awaits `response.background` before `.post()` returns to us, so the
    message is already `DELIVERED` by the time we look, with no drain or poll in between.

    Production never threads a `tls_context` through `deliver_one` (`cli.py`'s own
    `invitations-run` does not either): a real relay's certificate is trusted by the system
    store, and `smtp_double`'s never is on purpose (see its own docstring). The console route
    under test calls `deliver_one` exactly that production way, with no test-only parameter to
    carry the double's CA through, so this test stands `ssl.create_default_context` in for
    the one attempt the background task makes, scoped to this test alone, rather than adding
    a way for a real deployment to skip verification.
    """
    import ssl

    monkeypatch.setattr(ssl, "create_default_context", lambda *args, **kwargs: mail.context)
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = Runtime(db, [], mail=relay_mail(mail))
    with console_client_for(db, runtime, admin_engine, tenant, where["admin"]) as admin:
        created = admin.post(CONSOLE_API + "/teammate-invitations", {"email": ADDRESS})
        assert created.status_code == 200, created.text
        invitation_id = UUID(created.json()["invitation_id"])

    messages = mail.messages()
    assert len(messages) == 1
    assert messages[0]["To"] == ADDRESS
    message = message_row(admin_engine, tenant, invitation_id)
    assert message["state"] == "DELIVERED"
    assert message["attempts"] == 1


def test_ti24_every_new_console_code_has_a_browser_sentence():
    """The three business-specific codes teammate invitations add to `console_api/errors.py`'s
    closed list (`INVITATION_PENDING`, `ALREADY_MEMBER`, `RESEND_LIMIT`) each have a sentence
    in `components/directory/errors.ts`'s `COPY` table, and every code
    `teammate_invitations.REFUSALS` can answer with is one `errors.py` actually declares.
    """
    from execbound.surfaces.console_api.errors import CODES
    from execbound.surfaces.console_api.teammate_invitations import REFUSALS

    new_codes = {"INVITATION_PENDING", "ALREADY_MEMBER", "RESEND_LIMIT"}
    assert new_codes <= set(CODES)
    assert {target for target, _ in REFUSALS.values()} <= set(CODES)

    source = DIRECTORY_COPY.read_text(encoding="utf-8")
    match = re.search(r"const COPY: Record<string, string> = \{(.*?)\n\};", source, re.DOTALL)
    assert match is not None, "COPY table not found; has directory/errors.ts been restructured?"
    keys = set(re.findall(r"^\s*([A-Z][A-Z0-9_]*):", match.group(1), re.MULTILINE))
    assert new_codes <= keys


# --- TI25 and TI26: step-up for the console mutations, and the list's window -----------------


def test_ti25_the_console_mutations_require_the_same_recent_mfa(db, admin_engine, seeded):
    """`set_user_roles` is stepped up by `guards.mutation`'s `/api/console/v1/access/` prefix,
    and the pool's own invitations by its `/api/console/v1/invitations` prefix;
    `/api/console/v1/teammate-invitations` did not start with either, so create, resend and
    revoke all skipped step-up despite a grant being able to name `administrator`. Modelled on
    `test_account_api.py`'s `test_credential_issuance_routes_require_the_same_recent_mfa`:
    enrol, age the session's own assurance record past the thirty-minute window, and expect
    every mutation to refuse; a GET stays unstepped, since `guards.session` (never
    `guards.mutation`) gates it; a fresh factor (the same step-up `/mfa` itself performs,
    `mfa.verify_factor`) lets create succeed again.

    The assurance row (`execbound.session_assurance.verified_at`) is backdated directly rather
    than the clock: `workspace_invitation_create`'s own `ACTOR_CHECK` refuses a `p_now` more
    than five minutes from the database's real clock, so moving `runtime.clock` forward far
    enough to go MFA-stale would also make the very next `create` call fail its own clock check
    for an unrelated reason.
    """
    from execbound import mfa
    from execbound.envelope import KeyRing

    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    existing = create_invitation(
        runtime, admin_session(db, admin_engine, where), "existing@example.org", None
    )

    with console_client_for(db, runtime, admin_engine, tenant, where["admin"]) as client:
        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        ring = KeyRing("test", {"test": b"m" * 32})
        seed = mfa.begin_enrollment(db, session, ring, clock=runtime.clock)
        recovery_codes = mfa.confirm_enrollment(
            db,
            session,
            ring,
            mfa.totp(seed, int(runtime.clock.now().timestamp() // 30)),
            clock=runtime.clock,
        )

        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.session_assurance SET verified_at = :v "
                    "WHERE tenant_id = :t AND session_id = :s"
                ),
                {"v": now() - timedelta(minutes=31), "t": tenant, "s": session.session_id},
            )

        listed = client.get(CONSOLE_API + "/teammate-invitations")
        assert listed.status_code == 200, listed.text

        created = client.post(CONSOLE_API + "/teammate-invitations", {"email": "new@example.org"})
        resent = client.post(
            f"{CONSOLE_API}/teammate-invitations/{existing['invitation_id']}/resend"
        )
        revoked = client.post(
            f"{CONSOLE_API}/teammate-invitations/{existing['invitation_id']}/revoke"
        )
        for response in (created, resent, revoked):
            assert response.status_code == 401, response.text
            assert response.json()["code"] == "MFA_REQUIRED"

        # Nothing changed: no row for the address `create` tried, and `existing` is untouched.
        assert (
            owner_rows(
                admin_engine,
                tenant,
                "SELECT 1 FROM execbound.workspace_invitations WHERE tenant_id = :t AND email = :e",
                {"t": tenant, "e": "new@example.org"},
            )
            == []
        )
        row = invitation_row(admin_engine, tenant, existing["invitation_id"])
        assert row["state"] == "PENDING" and row["sends"] == 1

        # A fresh factor lets create succeed. A recovery code, not another TOTP code, so this
        # does not depend on real time having moved into a new thirty-second step since
        # `confirm_enrollment` minted its own.
        assert mfa.verify_factor(db, session, ring, recovery_codes[0], clock=runtime.clock)
        retried = client.post(CONSOLE_API + "/teammate-invitations", {"email": "new@example.org"})
        assert retried.status_code == 200, retried.text


def test_ti26_the_list_window_is_a_pure_thirty_day_cutoff(db, admin_engine, seeded):
    """The list used to keep every `PENDING` row forever (`row["state"] == "PENDING" or ...`).
    Resend never extends `expires_at`, so any still-open invitation is already under 7 days old
    and well inside 30; the fix filters on `created_at` alone. Three rows, each backdated by a
    direct `UPDATE` the way TI5 backdates `delivered_at` (`workspace_invitation_create`'s own
    `ACTOR_CHECK` refuses a `p_now` more than five minutes from the database's real clock, so a
    definer-function call cannot mint a 30-day-old row directly): a resolved (here, revoked) row
    just past the cutoff is dropped, a pending row well inside it is kept, and a
    pending-but-expired row past the cutoff is dropped: `state` alone would have kept that last
    one forever."""
    from soc_fixtures import Clock

    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    session = admin_session(db, admin_engine, where)

    revoked = create_invitation(runtime, session, "old-revoked@example.org", None)
    revoke_invitation(runtime, session, revoked["invitation_id"])
    kept = create_invitation(runtime, session, "kept@example.org", None)
    expired = create_invitation(runtime, session, "old-expired@example.org", None)

    def backdate(invitation_id, created_at):
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.workspace_invitations "
                    "SET created_at = :c, expires_at = :e WHERE invitation_id = :i"
                ),
                {"c": created_at, "e": created_at + timedelta(days=7), "i": invitation_id},
            )

    with console_client_for(db, runtime, admin_engine, tenant, where["admin"]) as client:
        # The console session's own credential was just real-time-stamped by the login above;
        # only now is it safe to pin `runtime.clock` and backdate against it, so the cutoff the
        # route computes and the deltas below agree on what "now" is.
        moment = now()
        runtime.clock = Clock(moment)
        backdate(revoked["invitation_id"], moment - timedelta(days=30, seconds=1))
        backdate(kept["invitation_id"], moment - timedelta(days=29))
        backdate(expired["invitation_id"], moment - timedelta(days=31))
        listed = client.get(CONSOLE_API + "/teammate-invitations")
    assert listed.status_code == 200, listed.text
    ids = {row["invitation_id"] for row in listed.json()["invitations"]}
    assert str(revoked["invitation_id"]) not in ids
    assert str(kept["invitation_id"]) in ids
    assert str(expired["invitation_id"]) not in ids


# --- TI37 onward: a principal a re-invitation replaced is retired for good (0061) ------------

REPLACED_COPY = (
    "This person rejoined through an invitation and now has a new entry in this workspace. "
    "Manage their access there."
)
REACTIVATE = "SELECT execbound.admin_reactivate_principal(:a, :p)"
REPLACED_FUNCTIONS = ("admin_reactivate_principal", "workspace_invitation_accept")
REPLACED_MIGRATION = (
    Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0061_replaced_principals.py"
)


def removed(db, engine, *, grants=None):
    """A member who joined through an invitation, was removed, and has been sent a second
    invitation to the same address: the moment just before the re-point TI1i makes."""
    _, account = existing_account(engine, ADDRESS)
    where = workspace(engine)
    tenant = where["tenant_id"]
    first, _ = invite(db, where, grants=grants)
    old = uuid4()
    accept(db, tenant, first, rekey(db, tenant, first), principal=old, signed_in=account)
    set_active(engine, tenant, old, False)
    second, _ = invite(db, where)
    return where, account, old, second, rekey(db, tenant, second)


def rejoined(db, engine, *, grants=None):
    """The same member after the second acceptance: the membership moved from `old` to `new`."""
    where, account, old, second, second_hash = removed(db, engine, grants=grants)
    new = uuid4()
    result = accept(db, where["tenant_id"], second, second_hash, principal=new, signed_in=account)
    assert result["outcome"] == "ACCEPTED"
    return where, account, old, new


def principal_rows(engine, tenant, *principals):
    """Whole principal rows, read by the owner under the tenant's fence."""
    rows = owner_rows(
        engine,
        tenant,
        "SELECT * FROM execbound.principals WHERE principal_id = ANY(CAST(:p AS uuid[]))",
        {"p": [str(principal) for principal in principals]},
    )
    return {row["principal_id"]: row for row in rows}


def event_kinds(engine, tenant):
    """The kinds of every audit event of one tenant, oldest first."""
    rows = owner_rows(
        engine,
        tenant,
        "SELECT kind FROM execbound.audit_events WHERE tenant_id = :t ORDER BY sequence",
        {"t": tenant},
    )
    return [row["kind"] for row in rows]


def refusal(call, *args, **kwargs):
    """The code a definer function refused with, or `None` when it did not refuse at all."""
    try:
        call(*args, **kwargs)
    except DBAPIError as exc:
        return exc.orig.diag.message_primary
    return None


def functions_of(engine):
    """Each function 0061 patches as the catalog holds it: its text, owner, grants, definer."""
    with engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT p.proname, pg_get_functiondef(p.oid) AS body, "
                    "pg_get_userbyid(p.proowner) AS owner, CAST(p.proacl AS text) AS acl, "
                    "p.prosecdef FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
                ),
                {"names": list(REPLACED_FUNCTIONS)},
            )
            .mappings()
            .all()
        )
    return {row["proname"]: dict(row) for row in rows}


def replacement_catalog(engine):
    """Whether `principals.replaced_by` exists, the constraints 0061 names, and its index."""
    with engine.connect() as conn:
        index = conn.execute(
            text("SELECT to_regclass('execbound.principals_replacement') IS NOT NULL")
        ).scalar_one()
        column = conn.execute(
            text(
                "SELECT count(*) FROM pg_attribute "
                "WHERE attrelid = CAST('execbound.principals' AS regclass) "
                "AND attname = 'replaced_by' AND NOT attisdropped"
            )
        ).scalar_one()
        constraints = conn.execute(
            text(
                "SELECT conname FROM pg_constraint "
                "WHERE conrelid = CAST('execbound.principals' AS regclass) "
                "AND conname LIKE 'principals_replaced%' ORDER BY conname"
            )
        ).scalars()
        return column, list(constraints), index


def principals_forced(engine) -> bool:
    """Whether `principals` still forces row security, which 0061's downgrade lifts and restores."""
    with engine.connect() as conn:
        forced = conn.execute(
            text(
                "SELECT relforcerowsecurity FROM pg_class "
                "WHERE oid = CAST('execbound.principals' AS regclass)"
            )
        )
        return forced.scalar_one()


def replaced_migration():
    """The 0061 module itself, so a test reads the fragments it patches rather than copies."""
    spec = importlib.util.spec_from_file_location("replaced_principals", REPLACED_MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def waiting_on_lock(engine, fragment, timeout=10.0):
    """Block until a backend of this database running `fragment` waits on a lock."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with engine.connect() as conn:
            waiting = conn.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                    "AND wait_event_type = 'Lock' AND query LIKE :q"
                ),
                {"q": f"%{fragment}%"},
            ).scalar_one()
        if waiting:
            return
        time.sleep(0.02)
    raise AssertionError(f"no call to {fragment} ever waited on a lock")


def test_ti37_a_reinvitation_marks_the_principal_it_replaced(db, admin_engine, seeded):
    """The re-point names the new principal on the old one, so the old one is retired rather
    than merely deactivated. The new principal is active and replaces nobody, nobody else in the
    workspace is marked, and a first acceptance replaces nobody."""
    where, account, old, new = rejoined(db, admin_engine)
    tenant = where["tenant_id"]
    rows = principal_rows(admin_engine, tenant, old, new)
    assert (rows[old]["active"], rows[old]["replaced_by"]) == (False, new)
    assert (rows[new]["active"], rows[new]["replaced_by"]) == (True, None)
    assert membership(admin_engine, tenant, account) == [
        {"principal_id": new, "active": True, "version": 2}
    ]
    marked = owner_rows(
        admin_engine,
        tenant,
        "SELECT principal_id FROM execbound.principals "
        "WHERE tenant_id = :t AND replaced_by IS NOT NULL",
        {"t": tenant},
    )
    assert marked == [{"principal_id": old}]

    fresh, _ = invite(db, where, email="fresh@example.org")
    joined = uuid4()
    accept(db, tenant, fresh, rekey(db, tenant, fresh), principal=joined)
    assert principal_rows(admin_engine, tenant, joined)[joined]["replaced_by"] is None


def test_ti38_a_replaced_principal_is_refused_reactivation_and_nothing_moves(
    db, admin_engine, seeded
):
    """The old principal held Administrator. Reactivated, it would be a second live
    administrator that no membership points at, counted by `access_has_permission` and by the
    `LAST_ADMINISTRATOR` check. `admin_reactivate_principal` refuses `PRINCIPAL_REPLACED`, the
    rows are as they were, and both answers stay where they were."""
    administrator = [{"role": "administrator", "space_id": None}]
    where, account, old, new = rejoined(db, admin_engine, grants=administrator)
    tenant = where["tenant_id"]

    def answers():
        with db.transaction(tenant) as conn:
            return {
                "old": {
                    permission: has_permission(conn, tenant, old, permission)
                    for permission in ("access.manage", "approvals.decide", "console.read")
                },
                "managers": sorted(
                    conn.execute(
                        text(
                            "SELECT p.principal_id FROM execbound.principals p WHERE p.active "
                            "AND execbound.access_has_permission("
                            "p.principal_id, 'access.manage', NULL, false)"
                        )
                    ).scalars()
                ),
            }

    def snapshot():
        return (
            principal_rows(admin_engine, tenant, old, new),
            membership(admin_engine, tenant, account),
            owner_rows(
                admin_engine,
                tenant,
                "SELECT principal_id, role, space_id FROM execbound.access_role_grants "
                "WHERE principal_id IN (:o, :n) ORDER BY principal_id, role",
                {"o": old, "n": new},
            ),
        )

    before, asked = snapshot(), answers()
    assert asked == {
        "old": {"access.manage": False, "approvals.decide": False, "console.read": False},
        "managers": [where["admin"]],
    }
    code = refusal(scalar, db, tenant, REACTIVATE, {"a": where["admin"], "p": old})
    assert code == "PRINCIPAL_REPLACED"
    assert snapshot() == before
    assert answers() == asked
    # The workspace's own administrator is still its last one.
    with pytest.raises(DBAPIError, match="LAST_ADMINISTRATOR"), admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, deactivated_at = now() "
                "WHERE principal_id = :p"
            ),
            {"p": where["admin"]},
        )


def test_ti39_every_reactivation_surface_refuses_and_shows_the_replacement(
    db, admin_engine, seeded
):
    """The People function the console route wraps (the server-rendered People page it once
    served now redirects to the console) refuses with the code and appends no
    `principal.reactivated`; the console route answers 409 with the code and its sentence; the
    person and the list both name the replacement; and the console's copy table carries the same
    sentence."""
    from execbound.surfaces.console_api.errors import BY_STATUS, CODES

    where, _, old, new = rejoined(db, admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    before = principal_rows(admin_engine, tenant, old, new)

    with pytest.raises(AdministrationError) as refused:
        people_pages.reactivate(runtime, admin_session(db, admin_engine, where), old)
    assert refused.value.code == "PRINCIPAL_REPLACED"

    with console_client_for(db, runtime, admin_engine, tenant, where["admin"]) as client:
        answer = client.post(f"{CONSOLE_API}/people/{old}/reactivate", {})
        assert answer.status_code == 409, answer.text
        assert answer.json() == {"code": "PRINCIPAL_REPLACED", "detail": REPLACED_COPY}
        person = client.get(f"{CONSOLE_API}/people/{old}")
        assert person.status_code == 200, person.text
        assert person.json()["person"]["replaced_by"] == str(new)
        assert person.json()["person"]["active"] is False
        rejoined_person = client.get(f"{CONSOLE_API}/people/{new}").json()["person"]
        assert rejoined_person["replaced_by"] is None
        listed = client.get(f"{CONSOLE_API}/people?state=all")
        assert listed.status_code == 200, listed.text
        rows = {row["principal_id"]: row for row in listed.json()["people"]}
        assert rows[str(old)]["replaced_by"] == str(new)
        assert rows[str(new)]["replaced_by"] is None

    assert principal_rows(admin_engine, tenant, old, new) == before
    assert "principal.reactivated" not in event_kinds(admin_engine, tenant)
    assert CODES["PRINCIPAL_REPLACED"] == (409, REPLACED_COPY)
    # A plain 409 from a shared guard never reads as this named cause.
    assert "PRINCIPAL_REPLACED" not in BY_STATUS.values()
    source = DIRECTORY_COPY.read_text(encoding="utf-8")
    table = re.search(r"const COPY: Record<string, string> = \{(.*?)\n\};", source, re.DOTALL)
    assert table is not None, "COPY table not found; has directory/errors.ts been restructured?"
    assert re.search(
        r"^\s*PRINCIPAL_REPLACED: PRINCIPAL_REPLACED_SENTENCE,$", table.group(1), re.MULTILINE
    )
    sentence = re.search(r'export const PRINCIPAL_REPLACED_SENTENCE =\s*"([^"]*)";', source)
    assert sentence is not None and sentence.group(1) == REPLACED_COPY


def test_ti40_the_check_refuses_every_write_that_would_revive_a_replaced_principal(
    db, admin_engine, seeded
):
    """The database check is the backstop: even the owner, inside the fence, cannot make a
    replaced principal active, name a principal as its own replacement, or mark an active one;
    and a replacement is always a principal of the same workspace."""
    where, _, old, new = rejoined(db, admin_engine)
    tenant = where["tenant_id"]
    for statement, params in (
        (
            "UPDATE execbound.principals SET active = true, deactivated_at = NULL "
            "WHERE principal_id = :p",
            {"p": old},
        ),
        (
            "UPDATE execbound.principals SET replaced_by = principal_id WHERE principal_id = :p",
            {"p": old},
        ),
        (
            "UPDATE execbound.principals SET replaced_by = :r WHERE principal_id = :p",
            {"p": new, "r": old},
        ),
    ):
        with pytest.raises(DBAPIError) as failure, admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(text(statement), params)
        assert failure.value.orig.sqlstate == "23514", statement
        assert failure.value.orig.diag.constraint_name == "principals_replaced_retired"

    elsewhere = workspace(admin_engine, name="Elsewhere")
    with pytest.raises(DBAPIError) as failure, admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.principals SET replaced_by = :r WHERE principal_id = :p"),
            {"p": old, "r": elsewhere["admin"]},
        )
    assert failure.value.orig.sqlstate == "23503"
    assert failure.value.orig.diag.constraint_name == "principals_replaced_by"

    rows = principal_rows(admin_engine, tenant, old, new)
    assert (rows[old]["active"], rows[old]["replaced_by"]) == (False, new)
    assert (rows[new]["active"], rows[new]["replaced_by"]) == (True, None)


def test_ti41_a_reactivation_racing_the_reinvitation_has_exactly_one_winner(
    db, admin_engine, seeded, monkeypatch
):
    """The People page's Reactivate and the member's own acceptance of a re-invitation,
    started together on two threads and two connections, each inside its open transaction
    before either reaches the tenant fence (TI13c's recipe). Whichever commits first wins:
    the acceptance, and the reactivation is `PRINCIPAL_REPLACED`; or the reactivation, and
    the acceptance is `ALREADY_MEMBER`. Neither side ever sees a raw constraint violation,
    which the services would report as unavailability."""
    _, _, grant, session = account_holder(db, admin_engine, ADDRESS)
    where = workspace(admin_engine)
    tenant = where["tenant_id"]
    runtime = bare_runtime(db)
    admin = admin_session(db, admin_engine, where)
    proof = {"session": session, "account_token": grant.account_token}
    _, first_token = link(db, where)
    old = accept_invitation(db, first_token, **proof).principal_id
    people_pages.deactivate(runtime, admin, old, "left the team")
    created = create_invitation(runtime, admin, ADDRESS, None)
    token = send(db, tenant, created["invitation_id"])

    barrier = threading.Barrier(2, timeout=10)
    real_check = invitations_module.check_runtime
    real_admin = people_pages._admin
    met = []

    def meet_check(conn):
        real_check(conn)
        barrier.wait()

    def meet_admin(conn, runtime, session):
        # The reactivation's first `_admin` takes the fence; meet before it, once.
        if not met:
            met.append(True)
            barrier.wait()
        real_admin(conn, runtime, session)

    monkeypatch.setattr(invitations_module, "check_runtime", meet_check)
    monkeypatch.setattr(people_pages, "_admin", meet_admin)

    def accepting():
        try:
            return accept_invitation(db, token, **proof).outcome
        except InvitationError as exc:
            return exc.code

    def reactivating():
        try:
            people_pages.reactivate(runtime, admin, old)
            return "REACTIVATED"
        except AdministrationError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        accepted = pool.submit(accepting)
        reactivated = pool.submit(reactivating)
        outcomes = (accepted.result(timeout=30), reactivated.result(timeout=30))
    monkeypatch.undo()

    assert outcomes in (("ACCEPTED", "PRINCIPAL_REPLACED"), ("ALREADY_MEMBER", "REACTIVATED"))
    invitation = invitation_row(admin_engine, tenant, created["invitation_id"])
    kinds = [event["kind"] for event in chain(admin_engine, tenant)]
    if outcomes[0] == "ACCEPTED":
        new = invitation["accepted_principal_id"]
        rows = principal_rows(admin_engine, tenant, old, new)
        assert (rows[old]["active"], rows[old]["replaced_by"]) == (False, new)
        assert rows[new]["active"]
        assert membership(admin_engine, tenant, session.account_id)[0]["principal_id"] == new
        assert "principal.reactivated" not in kinds
    else:
        assert invitation["state"] == "PENDING"
        rows = principal_rows(admin_engine, tenant, old)
        assert (rows[old]["active"], rows[old]["replaced_by"]) == (True, None)
        assert membership(admin_engine, tenant, session.account_id)[0]["principal_id"] == old
        assert kinds.count("principal.reactivated") == 1


@pytest.mark.parametrize("first", ["reactivation", "acceptance"])
def test_ti42_the_lock_order_holds_when_both_queue_behind_the_tenant_fence(
    db, admin_engine, seeded, first
):
    """The two definer functions called directly, with no service fence in front of them. A
    third connection holds the tenant fence; `first` queues on it, then the other does, and
    the holder lets go. The acceptance takes the fence before the old principal's row lock,
    in the documented order, so whichever queued first commits and the other refuses with its
    own code. Taking the row lock first instead deadlocks here the moment the reactivation,
    holding the fence, asks for the row the acceptance already holds."""
    where, account, old, second, second_hash = removed(db, admin_engine)
    tenant = where["tenant_id"]
    new = uuid4()

    def reactivating():
        code = refusal(scalar, db, tenant, REACTIVATE, {"a": where["admin"], "p": old})
        return code or "REACTIVATED"

    def accepting():
        try:
            return accept(db, tenant, second, second_hash, principal=new, signed_in=account)[
                "outcome"
            ]
        except DBAPIError as exc:
            return exc.orig.diag.message_primary

    calls = {
        "reactivation": (reactivating, "admin_reactivate_principal"),
        "acceptance": (accepting, "workspace_invitation_accept"),
    }
    order = [first, *(name for name in calls if name != first)]
    futures = {}
    holder = admin_engine.connect()
    held = holder.begin()
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        fenced(holder, tenant)
        holder.execute(
            text(
                "SELECT tenant_id FROM execbound.tenant_policy_control "
                "WHERE tenant_id = :t FOR UPDATE"
            ),
            {"t": tenant},
        ).one()
        for name in order:
            call, fragment = calls[name]
            futures[name] = pool.submit(call)
            waiting_on_lock(admin_engine, fragment)
    finally:
        held.rollback()
        holder.close()
        pool.shutdown(wait=True)
    outcomes = {name: future.result(timeout=30) for name, future in futures.items()}

    rows = principal_rows(admin_engine, tenant, old, new)
    if first == "reactivation":
        assert outcomes == {"reactivation": "REACTIVATED", "acceptance": "ALREADY_MEMBER"}
        assert (rows[old]["active"], rows[old]["replaced_by"]) == (True, None)
        assert new not in rows
        assert invitation_row(admin_engine, tenant, second)["state"] == "PENDING"
    else:
        assert outcomes == {"acceptance": "ACCEPTED", "reactivation": "PRINCIPAL_REPLACED"}
        assert (rows[old]["active"], rows[old]["replaced_by"]) == (False, new)
        assert rows[new]["active"]
        assert membership(admin_engine, tenant, account)[0]["principal_id"] == new


def test_ti43_the_migration_keeps_a_replacement_or_restores_both_bodies_exactly(
    db, admin_engine, seeded
):
    """Upgrade patches exactly its three fragments and keeps each function's owner, grants
    and definer. A membership re-pointed while 0059 was the head records nothing and needs no
    backfill. The downgrade refuses while any principal names its replacement, and once none
    does it restores both bodies byte for byte."""
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    migration = replaced_migration()
    head = functions_of(admin_engine)
    try:
        # `0066_max_agents` patches `admin_reactivate_principal` again, so what this revision
        # leaves is read at 0061 itself rather than at the head.
        command.downgrade(config, "0061_replaced_principals")
        at_0061 = functions_of(admin_engine)
        command.downgrade(config, "0060_sample_targets")
        before = functions_of(admin_engine)
        assert replacement_catalog(admin_engine) == (0, [], False)
        patched = {name: dict(row) for name, row in before.items()}
        for name, fragment, replacement in migration.PATCHES:
            assert patched[name]["body"].count(fragment) == 1, name
            patched[name]["body"] = patched[name]["body"].replace(fragment, replacement)
        assert patched == at_0061

        where, account, old, new = rejoined(db, admin_engine)
        tenant = where["tenant_id"]
        command.upgrade(config, "0061_replaced_principals")
        assert functions_of(admin_engine) == at_0061
        rows = principal_rows(admin_engine, tenant, old, new)
        assert (rows[old]["active"], rows[old]["replaced_by"]) == (False, None)
        assert rows[new]["replaced_by"] is None

        set_active(admin_engine, tenant, new, False)
        third_invitation, _ = invite(db, where)
        third = uuid4()
        third_hash = rekey(db, tenant, third_invitation)
        accept(db, tenant, third_invitation, third_hash, principal=third, signed_in=account)
        assert principal_rows(admin_engine, tenant, new)[new]["replaced_by"] == third
        with pytest.raises(RuntimeError, match="lossy downgrade refused"):
            command.downgrade(config, "0060_sample_targets")
        with admin_engine.connect() as conn:
            version = conn.execute(text("SELECT version_num FROM execbound.alembic_version"))
            assert version.scalar_one() == "0061_replaced_principals"
        assert principal_rows(admin_engine, tenant, new)[new]["replaced_by"] == third

        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text("UPDATE execbound.principals SET replaced_by = NULL WHERE tenant_id = :t"),
                {"t": tenant},
            )
        command.downgrade(config, "0060_sample_targets")
        assert functions_of(admin_engine) == before
        assert replacement_catalog(admin_engine) == (0, [], False)
        assert principals_forced(admin_engine) is True
    finally:
        command.upgrade(config, "head")
    assert functions_of(admin_engine) == head
    assert replacement_catalog(admin_engine) == (
        1,
        ["principals_replaced_by", "principals_replaced_retired"],
        True,
    )


def test_ti44_the_replacement_and_the_downgrade_count_hold_without_bypass(restricted):
    """The same walk as an owner that does not bypass row security. The acceptance writes
    `replaced_by` through the tenant arm, the check binds this owner too, and the downgrade's
    count sees a retained replacement although, unfenced, this owner sees no principal at all:
    0061 lifts FORCE around the count and puts it back."""
    engine, config, _ = restricted
    command.upgrade(config, "0060_sample_targets")
    runtime_url = with_database_name(os.environ["TEST_DATABASE_URL"], engine.url.database)
    db = Database(runtime_url, pool_size=1)
    try:
        before = functions_of(engine)
        where, account, old, new = rejoined(db, engine)
        tenant = where["tenant_id"]
        command.upgrade(config, "head")
        assert principal_rows(engine, tenant, old)[old]["replaced_by"] is None

        set_active(engine, tenant, new, False)
        third_invitation, _ = invite(db, where)
        third = uuid4()
        third_hash = rekey(db, tenant, third_invitation)
        accept(db, tenant, third_invitation, third_hash, principal=third, signed_in=account)
        assert principal_rows(engine, tenant, new)[new]["replaced_by"] == third
        code = refusal(scalar, db, tenant, REACTIVATE, {"a": where["admin"], "p": new})
        assert code == "PRINCIPAL_REPLACED"
        with pytest.raises(DBAPIError) as failure, engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.principals SET active = true, deactivated_at = NULL "
                    "WHERE principal_id = :p"
                ),
                {"p": new},
            )
        assert failure.value.orig.diag.constraint_name == "principals_replaced_retired"

        with engine.connect() as conn:
            unfenced = conn.execute(text("SELECT count(*) FROM execbound.principals"))
            assert unfenced.scalar_one() == 0
        with pytest.raises(RuntimeError, match="lossy downgrade refused"):
            command.downgrade(config, "0060_sample_targets")
        assert principals_forced(engine) is True
        assert principal_rows(engine, tenant, new)[new]["replaced_by"] == third

        with engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text("UPDATE execbound.principals SET replaced_by = NULL WHERE tenant_id = :t"),
                {"t": tenant},
            )
        command.downgrade(config, "0060_sample_targets")
        assert functions_of(engine) == before
        assert replacement_catalog(engine) == (0, [], False)
        # The successful downgrade lifted FORCE itself, so only its own restore puts it back;
        # the refused one above was restored by its rollback whatever the migration did.
        assert principals_forced(engine) is True
    finally:
        db.close()
