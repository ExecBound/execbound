# SPDX-License-Identifier: AGPL-3.0-only
"""SP20: only a workspace administrator configures the tenant's own identity provider.

A provider signs people in to the whole tenant, not to a space: registering an issuer decides
whose accounts can be linked, enabling it lets every linked account sign in, and disabling it
ends every directory session in the tenant at once. An administrator narrowed to spaces (an
actor without workspace-wide `access.manage` who holds any membership, as 0071 and 0072 ask
it) administers their spaces' agents and people, and none of that.

On 8 October 2026 it was decided that `directory_register` and `directory_set_state` take
workspace administrators alone. A narrowed administrator gets the code an actor who is not an
administrator already gets, `INVALID_ACTOR`, whatever the provider, so nothing about the
provider is disclosed. A sign-in through a provider that is not enabled is the test that
verifies a registration, so `directory_link_self` links through a draft or a verified provider
for a workspace administrator alone and answers `INVALID_PROVIDER` to anybody else, the code
the store already gave an approver there. Linking one's own account through an enabled provider
is a person's own act and stays open to everyone. A workspace administrator is unchanged.

The console asks the same before the write: the registration and state routes answer 403, as
the access page does for a setting only a workspace administrator holds, before a discovery
document is fetched, and the self-link route answers a narrowed administrator 404 for a
provider that is not enabled, as it answers an approver.
"""

import importlib.util
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from console_api_fixtures import API, console_client
from idp_fixtures import CLIENT_ID, CLIENT_SECRET, ISSUER, NAME, SUBJECT, USERNAME
from space_fixtures import default_space, seat, unseat
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_console_api_directory_identity import config as config
from test_console_api_directory_identity import (
    enabled,
    flow_cookies,
    links_of,
    registered,
    state_of,
    verified,
)
from test_console_api_directory_identity import key as key
from test_console_api_directory_identity import settings as settings
from test_console_api_directory_identity import stand_in as stand_in
from test_dormant_catalog import alembic_config, empty_schema
from test_execution import provision_identity
from test_execution import world as world
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime

from execbound import directory_store as store
from execbound.directory import DirectoryAccount
from execbound.surfaces.sessions import SessionError, issue_session, load_session

pytestmark = pytest.mark.integration

SIGN_IN = API + "/tenant/sign-in"
NARROWED_SUBJECT = "77777777-0000-4000-8000-0000000000dd"
APPROVER_SUBJECT = "77777777-0000-4000-8000-0000000000ee"
UNSEATED_SUBJECT = "77777777-0000-4000-8000-0000000000ff"
LINK_SELF = "SELECT execbound.directory_link_self(:a, :v, :s, 'Name', 'name@example.com', now())"
SET_STATE = "SELECT execbound.directory_set_state(:a, :v, :s, now())"


def fenced(conn, tenant):
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def refused_by(admin_engine, tenant, statement, params) -> str:
    """The code one definer function raises, called under the tenant fence as the store does."""
    with pytest.raises(DBAPIError) as failure, admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(text(statement), params)
    return failure.value.orig.diag.message_primary


def called(admin_engine, tenant, statement, params):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(text(statement), params).scalar_one()


def providers(admin_engine, tenant: UUID) -> int:
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT count(*) FROM execbound.identity_providers WHERE tenant_id = :t"),
                {"t": tenant},
            ).scalar_one()
        )


def events(admin_engine, tenant: UUID, prefix: str) -> int:
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.audit_events "
                    "WHERE tenant_id = :t AND kind LIKE :k"
                ),
                {"t": tenant, "k": prefix + "%"},
            ).scalar_one()
        )


@pytest.fixture
def narrowed(db, admin_engine, world):
    """An administrator seated as `ADMIN` in the tenant's one space: narrowed to it.

    The world's own administrator holds no membership, so they are a workspace administrator,
    and the world's approver is seated in the same space.
    """
    tenant = world["admin"].tenant_id
    identity = provision_identity(admin_engine, db, tenant, "ADMIN", world["clock"].now())
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        seat(conn, tenant, default_space(conn, tenant), identity.principal_id, "ADMIN")
    return identity


def register_as(db, runtime, settings, identity) -> UUID:
    return registered(db, runtime, settings, identity.tenant_id, identity.principal_id)


def account(subject: str) -> DirectoryAccount:
    return DirectoryAccount(subject, NAME, USERNAME, "refresh")


# The definer functions.


def test_sp20_a_space_administrator_registers_no_provider(
    db, runtime, admin_engine, world, settings, narrowed
):
    tenant = world["admin"].tenant_id
    registrations = events(admin_engine, tenant, "identity_provider.")
    with pytest.raises(store.DirectoryError) as refused:
        register_as(db, runtime, settings, narrowed)
    assert refused.value.code == "INVALID_ACTOR"
    assert providers(admin_engine, tenant) == 0
    assert events(admin_engine, tenant, "identity_provider.") == registrations
    # The workspace administrator registers as before.
    provider = register_as(db, runtime, settings, world["admin"])
    assert state_of(admin_engine, provider) == "draft"


def test_sp20_a_space_administrator_neither_enables_nor_disables_the_provider(
    db, runtime, admin_engine, world, settings, narrowed
):
    tenant, clock = world["admin"].tenant_id, runtime.clock
    workspace = world["admin"].principal_id
    provider = verified(db, runtime, settings, world)
    # The same answer for a provider that does not exist: the actor is refused first.
    for target in (provider, uuid4()):
        with pytest.raises(store.DirectoryError) as refused:
            store.set_state(db, tenant, narrowed.principal_id, target, "enabled", clock=clock)
        assert refused.value.code == "INVALID_ACTOR"
    assert state_of(admin_engine, provider) == "verified"
    store.set_state(db, tenant, workspace, provider, "enabled", clock=clock)

    # A person signs in through the enabled provider and holds a session.
    approver = world["human"].principal_id
    store.link_person(db, tenant, workspace, approver, provider, APPROVER_SUBJECT, clock=clock)
    row = store.locate_provider(db, provider)
    identity = store.sign_in(db, settings, row, account(APPROVER_SUBJECT), clock=clock)
    granted = issue_session(db, identity, clock=clock)
    changes = events(admin_engine, tenant, "identity_provider.")

    with pytest.raises(store.DirectoryError) as refused:
        store.set_state(db, tenant, narrowed.principal_id, provider, "disabled", clock=clock)
    assert refused.value.code == "INVALID_ACTOR"
    assert (
        refused_by(
            admin_engine,
            tenant,
            SET_STATE,
            {"a": narrowed.principal_id, "v": provider, "s": "disabled"},
        )
        == "INVALID_ACTOR"
    )
    assert state_of(admin_engine, provider) == "enabled"
    assert events(admin_engine, tenant, "identity_provider.") == changes
    # Nothing it would have ended has ended.
    assert load_session(db, granted.token, clock=clock).session_id == granted.session_id

    store.set_state(db, tenant, workspace, provider, "disabled", clock=clock)
    assert state_of(admin_engine, provider) == "disabled"
    with pytest.raises(SessionError):
        load_session(db, granted.token, clock=clock)
    # And enabling it again is the workspace administrator's alone too.
    with pytest.raises(store.DirectoryError) as refused:
        store.set_state(db, tenant, narrowed.principal_id, provider, "enabled", clock=clock)
    assert refused.value.code == "INVALID_ACTOR"
    assert state_of(admin_engine, provider) == "disabled"


@pytest.mark.parametrize("state", ["draft", "verified"])
def test_sp20_a_space_administrator_cannot_sign_in_through_a_provider_that_is_not_enabled(
    db, runtime, admin_engine, world, settings, narrowed, state
):
    """The test sign-in verifies a draft, and a verified provider is still being configured:
    a narrowed administrator links through neither, as an approver does not."""
    tenant = world["admin"].tenant_id
    provider = (
        register_as(db, runtime, settings, world["admin"])
        if state == "draft"
        else verified(db, runtime, settings, world)
    )
    with pytest.raises(store.DirectoryError) as refused:
        store.link_self(
            db,
            tenant,
            narrowed.principal_id,
            provider,
            account(NARROWED_SUBJECT),
            clock=runtime.clock,
        )
    assert refused.value.code == "INVALID_PROVIDER"
    assert state_of(admin_engine, provider) == state
    assert links_of(admin_engine, tenant, narrowed.principal_id) == 0


def test_sp20_the_definer_function_links_through_a_draft_for_a_workspace_administrator_alone(
    db, runtime, admin_engine, world, settings, narrowed
):
    """`directory_link_self` itself, with no store in front of it: before 0073 it accepted any
    active administrator or approver through a draft and marked the draft verified.

    An approver seated nowhere is not narrowed to spaces and is refused all the same, because
    they are not an administrator at all."""
    tenant = world["admin"].tenant_id
    unseated = provision_identity(admin_engine, db, tenant, "HUMAN_APPROVER", world["clock"].now())
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        unseat(conn, tenant, default_space(conn, tenant), unseated.principal_id)
    provider = register_as(db, runtime, settings, world["admin"])
    for actor, subject in (
        (narrowed.principal_id, NARROWED_SUBJECT),
        (world["human"].principal_id, APPROVER_SUBJECT),
        (unseated.principal_id, UNSEATED_SUBJECT),
    ):
        assert (
            refused_by(admin_engine, tenant, LINK_SELF, {"a": actor, "v": provider, "s": subject})
            == "INVALID_PROVIDER"
        )
        assert links_of(admin_engine, tenant, actor) == 0
    assert state_of(admin_engine, provider) == "draft"
    linked = called(
        admin_engine,
        tenant,
        LINK_SELF,
        {"a": world["admin"].principal_id, "v": provider, "s": SUBJECT},
    )
    assert linked["verified"] is True
    assert state_of(admin_engine, provider) == "verified"


def test_sp20_a_space_administrator_links_their_own_account_through_the_enabled_provider(
    db, runtime, admin_engine, world, settings, narrowed
):
    """Linking oneself is a person's own act, not configuration, and is unchanged."""
    tenant = world["admin"].tenant_id
    provider = enabled(db, runtime, settings, world)
    linked = store.link_self(
        db, tenant, narrowed.principal_id, provider, account(NARROWED_SUBJECT), clock=runtime.clock
    )
    assert linked["verified"] is False
    assert links_of(admin_engine, tenant, narrowed.principal_id) == 1
    assert state_of(admin_engine, provider) == "enabled"


# The console.


def test_sp20_the_console_refuses_a_space_administrator_before_the_write(
    db, runtime, admin_engine, world, settings, config, stand_in, narrowed
):
    tenant = world["admin"].tenant_id
    body = {
        "name": "Contoso",
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "subject_claim": "oid",
    }
    with console_client(db, runtime, admin_engine, narrowed, config=config) as client:
        # They still read the provider, which their people's invitations stand on.
        assert client.get(SIGN_IN).status_code == 200
        answer = client.post(SIGN_IN, body)
        assert answer.status_code == 403, answer.text
        assert answer.json()["code"] == "FORBIDDEN"
        # Refused before the directory was asked anything, and nothing is saved.
        assert stand_in.seen == []
        assert providers(admin_engine, tenant) == 0
    provider = verified(db, runtime, settings, world)
    with console_client(db, runtime, admin_engine, narrowed, config=config) as client:
        for state, kept in (("enabled", "verified"), ("disabled", "verified")):
            answer = client.post(f"{SIGN_IN}/{provider}/state", {"state": state})
            assert answer.status_code == 403, answer.text
            assert answer.json()["code"] == "FORBIDDEN"
            assert state_of(admin_engine, provider) == kept
        # The route refuses before it reads which provider was named, so a name that is not
        # one is the same 403 rather than the 404 an administrator who configures gets.
        answer = client.post(f"{SIGN_IN}/not-a-provider/state", {"state": "enabled"})
        assert answer.status_code == 403, answer.text
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as client:
        assert client.post(f"{SIGN_IN}/not-a-provider/state", {"state": "enabled"}).status_code == (
            404
        )
        answer = client.post(f"{SIGN_IN}/{provider}/state", {"state": "enabled"})
        assert answer.status_code == 200, answer.text
    with console_client(db, runtime, admin_engine, narrowed, config=config) as client:
        answer = client.post(f"{SIGN_IN}/{provider}/state", {"state": "disabled"})
        assert answer.status_code == 403, answer.text
    assert state_of(admin_engine, provider) == "enabled"


def test_sp20_a_workspace_administrator_registers_through_the_console_as_before(
    db, runtime, admin_engine, world, config
):
    body = {
        "name": "Contoso",
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "subject_claim": "oid",
    }
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as client:
        answer = client.post(SIGN_IN, body)
        assert answer.status_code == 200, answer.text
        assert answer.json()["provider"]["state"] == "draft"


@pytest.mark.parametrize("state", ["draft", "verified", "enabled"])
def test_sp20_the_test_sign_in_is_not_started_for_a_space_administrator(
    db, runtime, admin_engine, world, settings, config, stand_in, narrowed, state
):
    tenant = world["admin"].tenant_id
    provider = {
        "draft": lambda: register_as(db, runtime, settings, world["admin"]),
        "verified": lambda: verified(db, runtime, settings, world),
        "enabled": lambda: enabled(db, runtime, settings, world),
    }[state]()
    with console_client(db, runtime, admin_engine, narrowed, config=config) as client:
        started = client.client.get(f"/login/directory/{provider}/link")
    if state == "enabled":
        # Their own account, through the enabled provider, as anybody may.
        assert started.status_code == 303, started.text
    else:
        assert started.status_code == 404, started.headers.get("location")
        assert flow_cookies(started) == []
    assert state_of(admin_engine, provider) == state
    assert links_of(admin_engine, tenant, narrowed.principal_id) == 0
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as client:
        assert client.client.get(f"/login/directory/{provider}/link").status_code == 303


# Migration 0073: three functions gain the check in place, and the downgrade takes it away.

BEFORE = "0072_space_principal_scope"
TARGET = "0073_directory_workspace_admin"
_FILE = Path(__file__).resolve().parents[1] / "migrations" / "versions" / f"{TARGET}.py"


def _migration():
    spec = importlib.util.spec_from_file_location("directory_workspace_admin_migration", _FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def definitions(conn, names):
    return {
        row.proname: (row.body, row.acl, row.owner, row.prosecdef, row.proconfig, row.args)
        for row in conn.execute(
            text(
                "SELECT p.proname, pg_get_functiondef(p.oid) AS body, "
                "CAST(p.proacl AS text) AS acl, CAST(p.proowner AS regrole) AS owner, "
                "p.prosecdef, CAST(p.proconfig AS text) AS proconfig, "
                "pg_get_function_identity_arguments(p.oid) AS args FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(names)},
        )
    }


def test_sp20_the_upgrade_adds_the_check_and_the_downgrade_restores_each_function(admin_engine):
    migration = _migration()
    names = tuple(migration.PATCHES)
    assert set(names) == {"directory_register", "directory_set_state", "directory_link_self"}
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            old = definitions(conn, names)
        assert set(old) == set(names)
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            new = definitions(conn, names)
        for name in names:
            body, *kept = new[name]
            # Signature, owner, grants, SECURITY DEFINER and search_path are as they were.
            assert kept == list(old[name][1:]), name
            assert "execbound_app=X/execbound_owner" in kept[0], name
            expected = old[name][0]
            for before, after in migration.PATCHES[name]:
                assert expected.count(before) == 1, name
                expected = expected.replace(before, after)
            assert body == expected and body != old[name][0], name
            assert "(0073)" in body and "'access.manage',NULL,false" in body, name
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert definitions(conn, names) == old
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            assert definitions(conn, names) == new
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
