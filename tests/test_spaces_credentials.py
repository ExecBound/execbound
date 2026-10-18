# SPDX-License-Identifier: AGPL-3.0-only
"""SP15: an administrator narrowed to spaces administers the keys of those spaces' agents alone.

An agent is owned by one space, and its keys hang off its principal row, so a key of an agent
acts in that agent's space. A person with at least one membership has no authority outside
their spaces. Before migration 0071 the three credential functions checked only that the actor
was an effective administrator and that the target was not one: an administrator seated as
`ADMIN` in one space was still an effective administrator through `access_has_permission`'s
`p_any` branch, and was issued a key for an agent of another space, which then acted as an
agent of a space they do not belong to (#662). The credentials page listed every principal and
key of the tenant to them too.

The space check is the one `admin_create_principal` and `admin_assign_approver` already make:
an administrator with no workspace-wide `access.manage` who holds a membership acts only where
that membership is `ADMIN`. A refusal is the code the function already answers for a principal
or credential the actor may not act on, so it says nothing a nonexistent one would not.

A person belongs to no space. 0071 left a person's credential outside the check and a test
here pinned that; since 0072 people are scoped to the administrator's spaces (decided 8 October
2026), and the person test below pins the new rule instead.
`tests/test_spaces_principals.py` holds the rule for every other write on an agent or a person.
"""

import importlib.util
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from console_api_fixtures import API, console_client
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_dormant_catalog import alembic_config, empty_schema
from test_execution import provision_credential, provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.administration import AdministrationError
from execbound.identity import authenticate
from execbound.spaces import set_current_space
from execbound.surfaces import admin_pages
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration

HOUR = timedelta(hours=1)


def fenced(conn, tenant):
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def session_for(db, identity, clock):
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


def spent_key(admin_engine, tenant, principal, now):
    """A revoked key of one agent, the only kind `admin_delete_credential` takes."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        token = provision_credential(conn, tenant, principal, now, HOUR)
        credential = UUID(token.split(".")[2])
        conn.execute(
            text(
                "UPDATE execbound.credentials SET revoked_at = :n "
                "WHERE tenant_id = :t AND credential_id = :c"
            ),
            {"t": tenant, "c": credential, "n": now},
        )
    return credential


def key_state(admin_engine, tenant, credential):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT revoked_at, deleted_at FROM execbound.credentials "
                    "WHERE tenant_id = :t AND credential_id = :c"
                ),
                {"t": tenant, "c": credential},
            )
            .mappings()
            .one()
        )


def keys_of(admin_engine, tenant, principal):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text(
                "SELECT count(*) FROM execbound.credentials "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": principal},
        ).scalar_one()


def events(admin_engine, tenant, kind):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text("SELECT count(*) FROM execbound.audit_events WHERE tenant_id = :t AND kind = :k"),
            {"t": tenant, "k": kind},
        ).scalar_one()


@pytest.fixture
def spaces(db, admin_engine, world):
    """Two spaces of one tenant and an administrator seated as `ADMIN` in the first alone.

    The first is the tenant's default space, holding an agent of its own. The world's agent
    is moved to the second, as #662's probe moved it. Each agent also holds one spent key.
    The world's administrator holds no membership: a tenant administrator, workspace-wide.
    """
    tenant = world["identity"].tenant_id
    now = world["clock"].now()
    narrowed = provision_identity(admin_engine, db, tenant, "ADMIN", now)
    # Created while the tenant has one space, which the fixture names by subquery.
    own_agent = provision_identity(admin_engine, db, tenant, "AGENT", now)
    stranger = provision_identity(admin_engine, db, tenant, "HUMAN_APPROVER", now)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        own = default_space(conn, tenant)
        other = make_space(conn, tenant, "Customer B")
        seat(conn, tenant, own, narrowed.principal_id, "ADMIN")
        # A person seated only in the other space: a member, never owned by it.
        conn.execute(
            text("DELETE FROM execbound.space_members WHERE tenant_id = :t AND principal_id = :p"),
            {"t": tenant, "p": stranger.principal_id},
        )
        seat(conn, tenant, other, stranger.principal_id)
        conn.execute(
            text(
                "UPDATE execbound.principals SET space_id = :s "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "s": other, "p": world["identity"].principal_id},
        )
    return {
        "tenant": tenant,
        "own": own,
        "other": other,
        "narrowed": session_for(db, narrowed, world["clock"]),
        "narrowed_identity": narrowed,
        "workspace": session_for(db, world["admin"], world["clock"]),
        "own_agent": own_agent,
        "other_agent": world["identity"],
        "stranger": stranger,
        "own_spent": spent_key(admin_engine, tenant, own_agent.principal_id, now),
        "other_spent": spent_key(admin_engine, tenant, world["identity"].principal_id, now),
    }


def refused(call, code):
    with pytest.raises(AdministrationError) as refusal:
        call()
    assert refusal.value.code == code


def test_sp15_a_space_administrator_is_refused_a_key_for_another_spaces_agent(
    runtime, admin_engine, spaces
):
    """#662's probe: the narrowed administrator asks for a key of the world's agent."""
    tenant, agent = spaces["tenant"], spaces["other_agent"].principal_id
    before = keys_of(admin_engine, tenant, agent), events(admin_engine, tenant, "credential.issued")
    refused(
        lambda: admin_pages.issue(
            runtime, spaces["narrowed"], principal=agent, kind=None, lifetime=HOUR
        ),
        "INVALID_PRINCIPAL",
    )
    # A key that never expires is refused the same way.
    refused(
        lambda: admin_pages.issue(
            runtime, spaces["narrowed"], principal=agent, kind=None, lifetime=None
        ),
        "INVALID_PRINCIPAL",
    )
    assert (
        keys_of(admin_engine, tenant, agent),
        events(admin_engine, tenant, "credential.issued"),
    ) == before
    # The same code as a principal that does not exist, so the refusal discloses nothing.
    refused(
        lambda: admin_pages.issue(
            runtime, spaces["narrowed"], principal=uuid4(), kind=None, lifetime=HOUR
        ),
        "INVALID_PRINCIPAL",
    )


def test_sp15_a_space_administrator_is_refused_revoking_another_spaces_key(
    db, runtime, admin_engine, spaces, seeded
):
    tenant, live = spaces["tenant"], spaces["other_agent"].credential_id
    refused(lambda: admin_pages.revoke(runtime, spaces["narrowed"], live), "INVALID_CREDENTIAL")
    assert key_state(admin_engine, tenant, live)["revoked_at"] is None
    # The same code as a credential that does not exist.
    refused(lambda: admin_pages.revoke(runtime, spaces["narrowed"], uuid4()), "INVALID_CREDENTIAL")
    assert authenticate(db, seeded["tokens"][0]).credential_id == live
    assert events(admin_engine, tenant, "credential.revoked") == 0


def test_sp15_a_space_administrator_is_refused_deleting_another_spaces_key(
    runtime, admin_engine, spaces
):
    tenant, spent = spaces["tenant"], spaces["other_spent"]
    refused(lambda: admin_pages.delete(runtime, spaces["narrowed"], spent), "INVALID_CREDENTIAL")
    assert key_state(admin_engine, tenant, spent)["deleted_at"] is None
    assert events(admin_engine, tenant, "credential.deleted") == 0


def test_sp15_an_approvers_seat_in_another_space_administers_no_key_there(
    db, runtime, admin_engine, spaces
):
    """The space role narrows and only narrows: seated in the other space as
    an approver, the administrator may read it, as the Agents page lets them, and is still
    refused every key of its agents, because their authority there is an approver's."""
    tenant, other = spaces["tenant"], spaces["other_agent"]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        seat(conn, tenant, spaces["other"], spaces["narrowed_identity"].principal_id)
    narrowed = session_for(db, spaces["narrowed_identity"], runtime.clock)
    refused(
        lambda: admin_pages.issue(
            runtime, narrowed, principal=other.principal_id, kind=None, lifetime=HOUR
        ),
        "INVALID_PRINCIPAL",
    )
    refused(
        lambda: admin_pages.revoke(runtime, narrowed, other.credential_id), "INVALID_CREDENTIAL"
    )
    refused(
        lambda: admin_pages.delete(runtime, narrowed, spaces["other_spent"]), "INVALID_CREDENTIAL"
    )
    assert key_state(admin_engine, tenant, other.credential_id)["revoked_at"] is None
    assert key_state(admin_engine, tenant, spaces["other_spent"])["deleted_at"] is None
    # Their own space is untouched by the second seat.
    issued = admin_pages.issue(
        runtime, narrowed, principal=spaces["own_agent"].principal_id, kind=None, lifetime=HOUR
    )
    assert issued.kind == "AGENT"


def test_sp15_a_space_administrator_issues_revokes_and_deletes_their_own_spaces_keys(
    db, runtime, admin_engine, spaces
):
    tenant, agent = spaces["tenant"], spaces["own_agent"]
    issued = admin_pages.issue(
        runtime, spaces["narrowed"], principal=agent.principal_id, kind=None, lifetime=HOUR
    )
    assert issued.kind == "AGENT"
    assert authenticate(db, issued.token).principal_id == agent.principal_id
    admin_pages.revoke(runtime, spaces["narrowed"], issued.credential_id)
    assert key_state(admin_engine, tenant, issued.credential_id)["revoked_at"] is not None
    admin_pages.delete(runtime, spaces["narrowed"], issued.credential_id)
    admin_pages.delete(runtime, spaces["narrowed"], spaces["own_spent"])
    assert key_state(admin_engine, tenant, spaces["own_spent"])["deleted_at"] is not None


def test_sp15_a_workspace_administrator_administers_keys_in_every_space(
    db, runtime, admin_engine, spaces
):
    tenant, workspace = spaces["tenant"], spaces["workspace"]
    for agent, spent in (
        (spaces["own_agent"], spaces["own_spent"]),
        (spaces["other_agent"], spaces["other_spent"]),
    ):
        issued = admin_pages.issue(
            runtime, workspace, principal=agent.principal_id, kind=None, lifetime=HOUR
        )
        assert authenticate(db, issued.token).principal_id == agent.principal_id
        admin_pages.revoke(runtime, workspace, issued.credential_id)
        admin_pages.delete(runtime, workspace, issued.credential_id)
        admin_pages.delete(runtime, workspace, spent)
        assert key_state(admin_engine, tenant, spent)["deleted_at"] is not None
    admin_pages.revoke(runtime, workspace, spaces["other_agent"].credential_id)


def test_sp15_a_persons_credential_is_administered_inside_the_administrators_spaces(
    db, runtime, admin_engine, spaces
):
    """A credential signs in as its person, so it carries their approver authority in every
    space they are seated in. 0071 pinned the opposite here: the space administrator issued
    and revoked a credential of a person seated only in the other space. Since 0072 a person
    is scoped to the administrator's spaces (decided 8 October 2026), so the
    space administrator is refused both, with the codes an unknown person or credential gets,
    and a workspace administrator issues and revokes it as before. A person's credential is
    still never deleted.
    """
    tenant, person = spaces["tenant"], spaces["stranger"]
    before = keys_of(admin_engine, tenant, person.principal_id)
    refused(
        lambda: admin_pages.issue(
            runtime, spaces["narrowed"], principal=person.principal_id, kind=None, lifetime=HOUR
        ),
        "INVALID_PRINCIPAL",
    )
    refused(
        lambda: admin_pages.revoke(runtime, spaces["narrowed"], person.credential_id),
        "INVALID_CREDENTIAL",
    )
    assert keys_of(admin_engine, tenant, person.principal_id) == before
    assert key_state(admin_engine, tenant, person.credential_id)["revoked_at"] is None
    workspace = spaces["workspace"]
    issued = admin_pages.issue(
        runtime, workspace, principal=person.principal_id, kind=None, lifetime=HOUR
    )
    assert issued.kind == "HUMAN_APPROVER" and issued.number is None
    assert authenticate(db, issued.token).principal_id == person.principal_id
    admin_pages.revoke(runtime, workspace, issued.credential_id)
    refused(
        lambda: admin_pages.delete(runtime, workspace, issued.credential_id),
        "INVALID_CREDENTIAL",
    )


def overview_ids(runtime, session):
    page = admin_pages.credentials_overview(runtime, session)
    return (
        {row["principal_id"] for row in page["principals"]},
        {row["credential_id"] for row in page["credentials"]},
        page,
    )


def people(page):
    return (
        sorted(
            (row["principal_id"], row["live"])
            for row in page["principals"]
            if row["kind"] != "AGENT"
        ),
        sorted(row["credential_id"] for row in page["credentials"] if row["kind"] != "AGENT"),
    )


def test_sp15_the_credentials_page_lists_a_space_administrator_their_own_spaces_agents_alone(
    runtime, spaces
):
    principals, credentials, page = overview_ids(runtime, spaces["narrowed"])
    other = spaces["other_agent"]
    assert other.principal_id not in principals
    assert other.credential_id not in credentials and spaces["other_spent"] not in credentials
    assert all(row["principal_id"] != other.principal_id for row in page["credentials"])
    own = spaces["own_agent"]
    assert own.principal_id in principals
    assert {own.credential_id, spaces["own_spent"]} <= credentials
    # Since 0072 a person is listed to them only when every space the person is seated in
    # is one they administer: the person seated only in the other space is not.
    _, _, whole = overview_ids(runtime, spaces["workspace"])
    assert set(people(page)[0]) < set(people(whole)[0])
    assert spaces["stranger"].principal_id not in principals
    assert spaces["stranger"].credential_id not in credentials
    assert page["live"] == sum(1 for row in page["credentials"] if row["state"] == "live")


def test_sp15_the_credentials_page_lists_a_workspace_administrator_every_space(db, runtime, spaces):
    principals, credentials, _ = overview_ids(runtime, spaces["workspace"])
    for agent, spent in (
        (spaces["own_agent"], spaces["own_spent"]),
        (spaces["other_agent"], spaces["other_spent"]),
    ):
        assert agent.principal_id in principals
        assert {agent.credential_id, spent} <= credentials
    # Looking at one space, the list follows it as every other list does, and still names
    # every person.
    with db.transaction(spaces["tenant"]) as conn:
        set_current_space(conn, spaces["workspace"], spaces["other"])
    principals, credentials, page = overview_ids(runtime, spaces["workspace"])
    assert spaces["other_agent"].principal_id in principals
    assert spaces["own_agent"].principal_id not in principals
    assert spaces["own_spent"] not in credentials
    assert spaces["stranger"].principal_id in principals


def test_sp15_the_console_api_refuses_and_hides_another_spaces_agent(
    db, runtime, admin_engine, spaces
):
    tenant, other = spaces["tenant"], spaces["other_agent"]
    with console_client(db, runtime, admin_engine, spaces["narrowed_identity"]) as client:
        listed = client.get(API + "/credentials")
        assert listed.status_code == 200, listed.text
        body = listed.json()
        assert str(other.principal_id) not in {row["principal_id"] for row in body["principals"]}
        assert str(other.principal_id) not in {row["principal_id"] for row in body["credentials"]}
        assert str(spaces["own_agent"].principal_id) in {
            row["principal_id"] for row in body["principals"]
        }
        before = keys_of(admin_engine, tenant, other.principal_id)
        answer = client.post(
            API + "/credentials/issue", {"principal": str(other.principal_id), "lifetime": "1"}
        )
        assert answer.status_code == 400
        assert answer.json()["code"] == "INVALID_PRINCIPAL"
        for path in (
            API + f"/credentials/{other.credential_id}/revoke",
            API + f"/credentials/{spaces['other_spent']}/delete",
        ):
            answer = client.post(path, {})
            assert answer.status_code == 409
        # Under `/agents/{id}`, `require_agent` reads the agent's space since 0072 and answers
        # 404 before the function is reached, as for an agent that does not exist.
        agent = API + f"/agents/{other.principal_id}"
        for path, body in (
            (agent + "/credentials/issue", {"lifetime": "1"}),
            (agent + f"/credentials/{other.credential_id}/revoke", {}),
            (agent + f"/credentials/{spaces['other_spent']}/delete", {}),
        ):
            answer = client.post(path, body)
            assert answer.status_code == 404
        assert keys_of(admin_engine, tenant, other.principal_id) == before
        assert key_state(admin_engine, tenant, other.credential_id)["revoked_at"] is None
        assert key_state(admin_engine, tenant, spaces["other_spent"])["deleted_at"] is None


# Migration 0071: the three functions gain the check in place, and the downgrade takes it away.

BEFORE = "0070_first_password"
TARGET = "0071_space_credential_scope"
_FILE = Path(__file__).resolve().parents[1] / "migrations" / "versions" / f"{TARGET}.py"
FUNCTIONS = ("admin_issue_credential", "admin_revoke_credential", "admin_delete_credential")


def _migration():
    spec = importlib.util.spec_from_file_location("space_credential_scope_migration", _FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def definitions(conn):
    return {
        row.proname: (row.body, row.acl, row.owner, row.prosecdef, row.proconfig)
        for row in conn.execute(
            text(
                "SELECT p.proname, pg_get_functiondef(p.oid) AS body, "
                "CAST(p.proacl AS text) AS acl, CAST(p.proowner AS regrole) AS owner, "
                "p.prosecdef, CAST(p.proconfig AS text) AS proconfig FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(FUNCTIONS)},
        )
    }


def test_sp15_the_upgrade_adds_the_space_check_and_the_downgrade_restores_each_function(
    admin_engine,
):
    migration = _migration()
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            old = definitions(conn)
        assert set(old) == set(FUNCTIONS)
        assert all("space_members" not in body for body, *_ in old.values())
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            new = definitions(conn)
        for name in FUNCTIONS:
            body, *kept = new[name]
            # Owner, grants, SECURITY DEFINER and search_path are exactly as they were.
            assert kept == list(old[name][1:])
            assert "execbound_app=X/execbound_owner" in kept[0]
            expected = old[name][0]
            for before, after in migration.PATCHES[name]:
                expected = expected.replace(before, after)
            assert body == expected and body != old[name][0]
            assert "m.role = 'ADMIN'" in body
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert definitions(conn) == old
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
