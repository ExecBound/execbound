# SPDX-License-Identifier: AGPL-3.0-only
"""SP16 to SP19: an administrator narrowed to spaces administers those spaces' agents and people.

An agent is owned by one space. A person is a member of spaces and owned by none, and a person
with at least one membership has no authority outside their spaces. Migration 0071 gave the
three credential functions the check `admin_create_principal` and `admin_assign_approver`
already made, and left two gaps that its pull request (#675) reported:

1. The other functions that act on an agent by id never asked. An administrator seated as
   `ADMIN` in one space labelled, deactivated, reactivated, bound and unbound an agent of
   another space, and withdrew or took over another space's approver scopes.
2. A person belongs to no space, so 0071 left a person outside the check. A narrowed
   administrator issued a credential for a person seated only in another space, reset their
   password, linked their directory account or ended their sessions, and each of those signs
   in as the person, with the person's approver authority in the other space.

People are scoped to the administrator's spaces (decided 8 October 2026). For an
actor without workspace-wide `access.manage` who holds any membership, a write on a person is
allowed only when the person holds at least one membership and every space they are seated in
is one where the actor's own membership is `ADMIN`: the person's whole reach lies inside the
actor's administration. A person with no membership has workspace-wide reach and is refused.
So is a person whose reach comes from the access model, which only a workspace administrator
changes: a managed person (their roles, not their seats, are their reach) and a member of an
access group (the group's grants reach its members). A workspace administrator is unchanged.

A refusal is the code each function already gives a target that does not exist, so it says
nothing a nonexistent target would not. The pages read the same rule: the People list, the
person detail, the credentials list and the workspace's token list show a narrowed
administrator only the people they may administer, and a change route answers 404 for a
target they may not.
"""

import importlib.util
from datetime import timedelta
from pathlib import Path
from secrets import token_hex
from uuid import UUID, uuid4

import pytest
from alembic import command
from console_api_fixtures import API, console_client
from fastapi import HTTPException
from space_fixtures import default_space, make_space, place, seat, unseat
from sqlalchemy import text
from test_agents_bindings import found as found
from test_dormant_catalog import alembic_config, empty_schema
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_people_pages import call, refused
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.administration import AdministrationError
from execbound.identity import authenticate
from execbound.personal_tokens import list_tokens
from execbound.spaces import set_current_space
from execbound.surfaces import admin_pages, people_pages
from execbound.surfaces.sessions import (
    SessionError,
    issue_session,
    load_session,
    revoke_sessions_of,
)

pytestmark = pytest.mark.integration

HOUR = timedelta(hours=1)
LABEL = "SELECT execbound.admin_label_principal(:a, :p, 'Renamed here')"
DEACTIVATE = "SELECT execbound.admin_deactivate_principal(:a, :p, 'Left the team')"
REACTIVATE = "SELECT execbound.admin_reactivate_principal(:a, :p)"
BIND = "SELECT execbound.admin_bind_agent(:a, :g, :p)"
UNBIND = "SELECT execbound.admin_unbind_agent(:a, :b, 'Withdrawn here')"
ISSUE = "SELECT execbound.admin_issue_credential(:a, :p, :c, :h, now(), now() + interval '1 hour')"
REVOKE = "SELECT execbound.admin_revoke_credential(:a, :c, now())"
EMAIL = "SELECT execbound.admin_set_email(:a, :p, :e)"
RESET = "SELECT execbound.admin_reset_password(:a, :p, :r, :h, now() + interval '1 day')"
INVITE = "SELECT execbound.directory_invite(:a, :p, :v, :i, :h, now() + interval '1 day')"
REVOKE_INVITATION = "SELECT execbound.directory_invitation_revoke(:a, :i, now())"
LINK = "SELECT execbound.directory_link(:a, :p, :v, :s, now())"
UNLINK = "SELECT execbound.directory_unlink(:a, :p, now())"
TOKEN = (
    "SELECT execbound.admin_issue_personal_token("
    ":a, :k, :c, 'Script', :h, :ch, :i, CAST(:i AS timestamptz) + interval '1 day')"
)
REVOKE_TOKEN = "SELECT execbound.admin_revoke_personal_token(:a, :k, now())"
DELETE_TOKEN = "SELECT execbound.admin_delete_personal_token(:a, :k, now())"
ASSIGN = "SELECT execbound.admin_assign_approver(:a, :p, :t, 'endpoint.isolate', :s)"
UNASSIGN = "SELECT execbound.admin_unassign_approver(:a, :p, :t, 'endpoint.isolate')"


def fenced(conn, tenant):
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def session_for(db, identity, clock):
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


def row(admin_engine, tenant, statement, **params):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        found = conn.execute(text(statement), {"t": tenant, **params}).mappings().one_or_none()
        return None if found is None else dict(found)


def principal_row(admin_engine, tenant, principal):
    return row(
        admin_engine,
        tenant,
        "SELECT label, active, email FROM execbound.principals "
        "WHERE tenant_id = :t AND principal_id = :p",
        p=principal,
    )


def count(admin_engine, tenant, statement, **params):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(text(statement), {"t": tenant, **params}).scalar_one()


@pytest.fixture
def scope(db, admin_engine, world):
    """Two spaces, a narrowed administrator of the first, and people seated every way.

    The first is the tenant's default space, A. The world's agent is moved to the second, B.
    The world's administrator holds no membership: a workspace administrator. `narrowed` is
    seated as `ADMIN` in A alone; `peer` is another administrator seated the same way, who
    holds a personal access token, as does the workspace administrator.

    The people, each an approver holding one live credential and an address:
    `in_a` is seated in A alone; `in_b` in B alone; `in_both` in A and B; `unseated` in no
    space; `managed` is seated in A and managed by the access model, with a workspace-wide
    approver role; `grouped` is seated in A and a member of an access group that holds one.
    """
    tenant = world["identity"].tenant_id
    now = world["clock"].now()
    narrowed = provision_identity(admin_engine, db, tenant, "ADMIN", now)
    peer = provision_identity(admin_engine, db, tenant, "ADMIN", now)
    own_agent = provision_identity(admin_engine, db, tenant, "AGENT", now)
    people = {
        name: provision_identity(admin_engine, db, tenant, "HUMAN_APPROVER", now)
        for name in ("in_a", "in_b", "in_both", "unseated", "managed", "grouped")
    }
    group = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        a = default_space(conn, tenant)
        b = make_space(conn, tenant, "Customer B")
        seat(conn, tenant, a, narrowed.principal_id, "ADMIN")
        seat(conn, tenant, a, peer.principal_id, "ADMIN")
        # provision_identity seats every approver in A, as migration 0041 seated them.
        unseat(conn, tenant, a, people["in_b"].principal_id)
        seat(conn, tenant, b, people["in_b"].principal_id)
        seat(conn, tenant, b, people["in_both"].principal_id)
        unseat(conn, tenant, a, people["unseated"].principal_id)
        place(conn, tenant, "principals", "principal_id", world["identity"].principal_id, b)
        conn.execute(
            text("INSERT INTO execbound.access_principals VALUES (:t, :p)"),
            {"t": tenant, "p": people["managed"].principal_id},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.access_groups (tenant_id, group_id, name, created_at) "
                "VALUES (:t, :g, 'Night shift', now())"
            ),
            {"t": tenant, "g": group},
        )
        conn.execute(
            text("INSERT INTO execbound.access_group_members VALUES (:t, :g, :p)"),
            {"t": tenant, "g": group, "p": people["grouped"].principal_id},
        )
        for principal, grantee in ((people["managed"].principal_id, None), (None, group)):
            conn.execute(
                text(
                    "INSERT INTO execbound.access_role_grants "
                    "(tenant_id, grant_id, principal_id, group_id, role, space_id) "
                    "VALUES (:t, :i, :p, :g, 'approver', NULL)"
                ),
                {"t": tenant, "i": uuid4(), "p": principal, "g": grantee},
            )
        for index, person in enumerate(people.values()):
            conn.execute(
                text(
                    "UPDATE execbound.principals SET email = :e "
                    "WHERE tenant_id = :t AND principal_id = :p"
                ),
                {"t": tenant, "p": person.principal_id, "e": f"person{index}.{tenant}@example.com"},
            )
    tokens = {}
    for name, owner in (("peer", peer), ("workspace", world["admin"]), ("narrowed", narrowed)):
        tokens[name] = uuid4()
        call(
            admin_engine,
            tenant,
            TOKEN,
            {
                "a": owner.principal_id,
                "k": tokens[name],
                "c": uuid4(),
                "h": token_hex(32),
                "ch": token_hex(32),
                # The runtime's clock, which every later write on the token reads.
                "i": now,
            },
        )
    return {
        "tenant": tenant,
        "a": a,
        "b": b,
        "narrowed": narrowed,
        "peer": peer,
        "workspace": world["admin"],
        "own_agent": own_agent,
        "other_agent": world["identity"],
        "people": people,
        "tokens": tokens,
    }


REFUSED = ("in_b", "in_both", "unseated", "managed", "grouped")


def actor(scope, name):
    return scope[name].principal_id


# SP16: agents, and the approver scopes of a space.


@pytest.mark.parametrize(
    "statement,before",
    [(LABEL, None), (DEACTIVATE, None), (REACTIVATE, DEACTIVATE)],
    ids=["label", "deactivate", "reactivate"],
)
def test_sp16_a_space_administrator_is_refused_another_spaces_agent(
    admin_engine, scope, statement, before
):
    """#675: label, deactivate and reactivate the world's agent from space A."""
    tenant = scope["tenant"]
    other, own = actor(scope, "other_agent"), actor(scope, "own_agent")
    workspace = actor(scope, "workspace")
    if before is not None:
        for agent in (other, own):
            call(admin_engine, tenant, before, {"a": workspace, "p": agent})
    kept = principal_row(admin_engine, tenant, other)
    assert refused(
        admin_engine, tenant, statement, {"a": actor(scope, "narrowed"), "p": other}
    ) == ("INVALID_PRINCIPAL")
    assert principal_row(admin_engine, tenant, other) == kept
    # The same code as an agent that does not exist.
    assert refused(
        admin_engine, tenant, statement, {"a": actor(scope, "narrowed"), "p": uuid4()}
    ) == ("INVALID_PRINCIPAL")
    # Their own space's agent, and the workspace administrator anywhere.
    call(admin_engine, tenant, statement, {"a": actor(scope, "narrowed"), "p": own})
    call(admin_engine, tenant, statement, {"a": workspace, "p": other})
    assert principal_row(admin_engine, tenant, other) != kept


def test_sp16_an_approvers_seat_in_another_space_administers_none_of_its_agents(
    admin_engine, scope
):
    """Seated in B as an approver, the administrator may read B and still
    administers none of its agents, because their authority there is an approver's."""
    tenant = scope["tenant"]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        seat(conn, tenant, scope["b"], actor(scope, "narrowed"))
    params = {"a": actor(scope, "narrowed"), "p": actor(scope, "other_agent")}
    for statement in (LABEL, DEACTIVATE):
        assert refused(admin_engine, tenant, statement, params) == "INVALID_PRINCIPAL"
    assert principal_row(admin_engine, tenant, actor(scope, "other_agent"))["active"]


def test_sp16_binding_and_unbinding_need_both_sides_in_the_administrators_spaces(
    admin_engine, scope, found
):
    """A binding joins an agent principal to a discovered agent of a connection, and both
    are owned by a space: the principal by its own row, the discovered agent by its
    connection's. A narrowed administrator binds and unbinds only when both are theirs."""
    tenant, narrowed, workspace = (
        scope["tenant"],
        actor(scope, "narrowed"),
        actor(scope, "workspace"),
    )
    first, second, _ = (agent["agent_id"] for agent in found["agents"])
    own, other = actor(scope, "own_agent"), actor(scope, "other_agent")
    # Another space's principal, with a discovered agent of their own space.
    assert refused(admin_engine, tenant, BIND, {"a": narrowed, "g": first, "p": other}) == (
        "INVALID_PRINCIPAL"
    )
    # Their own principal, bound and unbound.
    binding = call(admin_engine, tenant, BIND, {"a": narrowed, "g": first, "p": own})
    call(admin_engine, tenant, UNBIND, {"a": narrowed, "b": binding})
    # The workspace administrator binds another space's principal; the narrowed one may not
    # take that binding back.
    theirs = call(admin_engine, tenant, BIND, {"a": workspace, "g": second, "p": other})
    assert refused(admin_engine, tenant, UNBIND, {"a": narrowed, "b": theirs}) == "INVALID_STATE"
    assert (
        count(
            admin_engine,
            tenant,
            "SELECT count(*) FROM execbound.agent_bindings "
            "WHERE tenant_id = :t AND binding_id = :b AND unbound_at IS NULL",
            b=theirs,
        )
        == 1
    )
    # The same code as a binding that does not exist.
    assert refused(admin_engine, tenant, UNBIND, {"a": narrowed, "b": uuid4()}) == ("INVALID_STATE")
    call(admin_engine, tenant, UNBIND, {"a": workspace, "b": theirs})
    # The discovered agents' connection moves to B: their own principal binds to none of
    # them, and a binding the workspace administrator makes there is not theirs to undo.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        place(conn, tenant, "monitor_connections", "connection_id", found["connection"], scope["b"])
    assert refused(admin_engine, tenant, BIND, {"a": narrowed, "g": first, "p": own}) == (
        "INVALID_AGENT"
    )
    assert refused(admin_engine, tenant, BIND, {"a": narrowed, "g": uuid4(), "p": own}) == (
        "INVALID_AGENT"
    )
    mine = call(admin_engine, tenant, BIND, {"a": workspace, "g": first, "p": own})
    assert refused(admin_engine, tenant, UNBIND, {"a": narrowed, "b": mine}) == "INVALID_STATE"
    call(admin_engine, tenant, UNBIND, {"a": workspace, "b": mine})


def test_sp16_another_spaces_approver_scope_is_neither_withdrawn_nor_taken(
    admin_engine, world, scope
):
    """A scope is one row per approver, target and action, owned by one space. Withdrawing
    one named no space at all, and assigning the same three in A moved B's live row into A."""
    tenant, narrowed, workspace = (
        scope["tenant"],
        actor(scope, "narrowed"),
        actor(scope, "workspace"),
    )
    approver = scope["people"]["in_both"].principal_id
    target = world["canonical"]
    scopes = (
        "SELECT space_id, active FROM execbound.approval_scopes WHERE tenant_id = :t "
        "AND approver_id = :p AND canonical_target_id = :c AND action = 'endpoint.isolate'"
    )
    call(
        admin_engine, tenant, ASSIGN, {"a": workspace, "p": approver, "t": target, "s": scope["b"]}
    )
    held = row(admin_engine, tenant, scopes, p=approver, c=target)
    assert held == {"space_id": scope["b"], "active": True}
    assert refused(admin_engine, tenant, UNASSIGN, {"a": narrowed, "p": approver, "t": target}) == (
        "INVALID_SCOPE"
    )
    assert refused(
        admin_engine, tenant, ASSIGN, {"a": narrowed, "p": approver, "t": target, "s": scope["a"]}
    ) == ("INVALID_SPACE")
    assert row(admin_engine, tenant, scopes, p=approver, c=target) == held
    # Withdrawn by B's administrator, the row may be assigned again in A and withdrawn there.
    call(admin_engine, tenant, UNASSIGN, {"a": workspace, "p": approver, "t": target})
    call(admin_engine, tenant, ASSIGN, {"a": narrowed, "p": approver, "t": target, "s": scope["a"]})
    assert row(admin_engine, tenant, scopes, p=approver, c=target) == {
        "space_id": scope["a"],
        "active": True,
    }
    call(admin_engine, tenant, UNASSIGN, {"a": narrowed, "p": approver, "t": target})


def test_sp16_the_console_api_answers_404_for_another_spaces_agent(
    db, runtime, admin_engine, scope
):
    """`require_agent` checks the agent's space now, so the write never runs; before 0072
    the write landed and the detail read after it answered 404."""
    tenant, other = scope["tenant"], scope["other_agent"]
    kept = principal_row(admin_engine, tenant, other.principal_id)
    agent = f"{API}/agents/{other.principal_id}"
    with console_client(db, runtime, admin_engine, scope["narrowed"]) as client:
        for path, body in (
            (agent + "/label", {"label": "Renamed here"}),
            (agent + "/deactivate", {"reason": "Left the team"}),
            (agent + "/reactivate", {}),
            (agent + "/unbind", {"reason": "Withdrawn here"}),
            (agent + "/credentials/issue", {"lifetime": "1"}),
            (agent + f"/credentials/{other.credential_id}/revoke", {}),
        ):
            answer = client.post(path, body)
            # Before 0072 the label and the deactivation landed and only the read after
            # them answered 404, so the row is checked after every route.
            assert principal_row(admin_engine, tenant, other.principal_id) == kept, path
            assert answer.status_code == 404, (path, answer.text)
        own = f"{API}/agents/{scope['own_agent'].principal_id}"
        answer = client.post(own + "/label", {"label": "Renamed here"})
        assert answer.status_code == 200, answer.text


# SP17: people.


def _directory(admin_engine, tenant, workspace):
    provider = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.identity_providers (tenant_id, provider_id, name, issuer, "
                "client_id, client_auth, secret_ciphertext, secret_key_id, subject_claim, "
                "authorization_endpoint, token_endpoint, jwks_uri, discovery_fetched_at, state, "
                "created_by, created_at, verified_by, verified_at, enabled_at) VALUES "
                "(:t, :v, 'Contoso', 'https://login.example.com/contoso', 'client', "
                "'client_secret_post', :x, 'dir-v1', 'oid', 'https://login.example.com/a', "
                "'https://login.example.com/t', 'https://login.example.com/k', now(), "
                "'enabled', :w, now(), :w, now(), now())"
            ),
            {"t": tenant, "v": provider, "x": "ab" * 40, "w": workspace},
        )
    return provider


class Write:
    """One write on a person: how to make it possible, how to make it, what it changes."""

    def __init__(self, name, statement, code, *, prepare=None, params=None, observe=None):
        self.name, self.statement, self.code = name, statement, code
        self.prepare = prepare or (lambda engine, scope, person: {})
        self.params = params or (lambda scope, person, prepared: {"p": person.principal_id})
        self.observe = observe

    def __repr__(self):
        return self.name


def _credentials(engine, scope, person):
    return count(
        engine,
        scope["tenant"],
        "SELECT count(*) FROM execbound.credentials WHERE tenant_id = :t AND principal_id = :p",
        p=person.principal_id,
    )


def _live(engine, scope, person):
    return count(
        engine,
        scope["tenant"],
        "SELECT count(*) FROM execbound.credentials WHERE tenant_id = :t "
        "AND principal_id = :p AND revoked_at IS NULL",
        p=person.principal_id,
    )


def _person(engine, scope, person):
    return principal_row(engine, scope["tenant"], person.principal_id)


def _resets(engine, scope, person):
    return count(
        engine,
        scope["tenant"],
        "SELECT count(*) FROM execbound.password_resets WHERE tenant_id = :t AND principal_id = :p",
        p=person.principal_id,
    )


def _invitations(engine, scope, person):
    return count(
        engine,
        scope["tenant"],
        "SELECT count(*) FROM execbound.identity_invitations WHERE tenant_id = :t "
        "AND principal_id = :p AND revoked_at IS NULL",
        p=person.principal_id,
    )


def _links(engine, scope, person):
    return count(
        engine,
        scope["tenant"],
        "SELECT count(*) FROM execbound.identity_links WHERE tenant_id = :t "
        "AND principal_id = :p AND revoked_at IS NULL",
        p=person.principal_id,
    )


def _deactivated(engine, scope, person):
    call(
        engine,
        scope["tenant"],
        DEACTIVATE,
        {"a": actor(scope, "workspace"), "p": person.principal_id},
    )
    return {}


def _invited(engine, scope, person):
    invitation = uuid4()
    call(
        engine,
        scope["tenant"],
        INVITE,
        {
            "a": actor(scope, "workspace"),
            "p": person.principal_id,
            "v": scope["provider"],
            "i": invitation,
            "h": token_hex(32),
        },
    )
    return {"invitation": invitation}


def _linked(engine, scope, person):
    call(
        engine,
        scope["tenant"],
        LINK,
        {
            "a": actor(scope, "workspace"),
            "p": person.principal_id,
            "v": scope["provider"],
            "s": f"subject-{person.principal_id}",
        },
    )
    return {}


WRITES = [
    Write(
        "issue",
        ISSUE,
        "INVALID_PRINCIPAL",
        params=lambda scope, person, _: {
            "p": person.principal_id,
            "c": uuid4(),
            "h": token_hex(32),
        },
        observe=_credentials,
    ),
    Write(
        "revoke",
        REVOKE,
        "INVALID_CREDENTIAL",
        params=lambda scope, person, _: {"c": person.credential_id},
        observe=_live,
    ),
    Write("label", LABEL, "INVALID_PRINCIPAL", observe=_person),
    Write("deactivate", DEACTIVATE, "INVALID_PRINCIPAL", observe=_live),
    Write("reactivate", REACTIVATE, "INVALID_PRINCIPAL", prepare=_deactivated, observe=_person),
    Write(
        "email",
        EMAIL,
        "INVALID_PRINCIPAL",
        params=lambda scope, person, _: {
            "p": person.principal_id,
            "e": f"moved.{person.principal_id}@example.net",
        },
        observe=_person,
    ),
    Write(
        "password_code",
        RESET,
        "INVALID_PRINCIPAL",
        params=lambda scope, person, _: {
            "p": person.principal_id,
            "r": uuid4(),
            "h": token_hex(32),
        },
        observe=_resets,
    ),
    Write(
        "directory_invite",
        INVITE,
        "INVALID_PRINCIPAL",
        params=lambda scope, person, _: {
            "p": person.principal_id,
            "v": scope["provider"],
            "i": uuid4(),
            "h": token_hex(32),
        },
        observe=_invitations,
    ),
    Write(
        "directory_invite_revoke",
        REVOKE_INVITATION,
        "INVALID_INVITATION",
        prepare=_invited,
        params=lambda scope, person, prepared: {"i": prepared["invitation"]},
        observe=_invitations,
    ),
    Write(
        "directory_link",
        LINK,
        "INVALID_PRINCIPAL",
        params=lambda scope, person, _: {
            "p": person.principal_id,
            "v": scope["provider"],
            "s": f"subject-{person.principal_id}",
        },
        observe=_links,
    ),
    Write("directory_unlink", UNLINK, "INVALID_PRINCIPAL", prepare=_linked, observe=_links),
]


@pytest.mark.parametrize("write", WRITES, ids=repr)
def test_sp17_a_space_administrator_writes_on_their_spaces_people_alone(admin_engine, scope, write):
    """Each write on a person, on every person outside the administrator's spaces, then on
    the person seated in A alone, then by the workspace administrator on each refused one."""
    tenant, narrowed, workspace = (
        scope["tenant"],
        actor(scope, "narrowed"),
        actor(scope, "workspace"),
    )
    scope["provider"] = _directory(admin_engine, tenant, workspace)
    for name in (*REFUSED, "in_a"):
        person = scope["people"][name]
        prepared = write.prepare(admin_engine, scope, person)
        params = {"a": narrowed, **write.params(scope, person, prepared)}
        before = write.observe(admin_engine, scope, person)
        if name == "in_a":
            call(admin_engine, tenant, write.statement, params)
            assert write.observe(admin_engine, scope, person) != before
            continue
        assert refused(admin_engine, tenant, write.statement, params) == write.code, name
        assert write.observe(admin_engine, scope, person) == before, name
        # The workspace administrator is unchanged.
        call(admin_engine, tenant, write.statement, {**params, "a": workspace})
        assert write.observe(admin_engine, scope, person) != before, name


def test_sp17_every_seat_in_one_of_their_admin_spaces_is_enough(db, admin_engine, scope):
    """Seated as `ADMIN` in both spaces, the administrator administers the person seated in
    both; seated in B as an approver, they administer only those seated in A."""
    tenant, narrowed = scope["tenant"], actor(scope, "narrowed")
    in_both, in_b, in_a = (
        scope["people"][name].principal_id for name in ("in_both", "in_b", "in_a")
    )
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        seat(conn, tenant, scope["b"], narrowed)
    for person in (in_both, in_b):
        assert refused(admin_engine, tenant, LABEL, {"a": narrowed, "p": person}) == (
            "INVALID_PRINCIPAL"
        )
    call(admin_engine, tenant, LABEL, {"a": narrowed, "p": in_a})
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        seat(conn, tenant, scope["b"], narrowed, "ADMIN")
    for person in (in_both, in_b, in_a):
        call(admin_engine, tenant, LABEL, {"a": narrowed, "p": person})


def test_sp17_ending_sessions_reaches_their_spaces_people_alone(db, runtime, admin_engine, scope):
    """`End all sessions` is an update by the runtime role rather than a definer function;
    its statement carries the same rule, so a session outside it survives."""
    clock = runtime.clock
    narrowed = session_for(db, scope["narrowed"], clock)
    for name in REFUSED:
        person = scope["people"][name]
        held = issue_session(db, person, clock=clock)
        assert (
            revoke_sessions_of(db, narrowed, person.principal_id, reason="ADMIN", clock=clock) == 0
        )
        assert (
            load_session(db, held.token, clock=clock).identity.principal_id == person.principal_id
        )
    person = scope["people"]["in_a"]
    held = issue_session(db, person, clock=clock)
    assert revoke_sessions_of(db, narrowed, person.principal_id, reason="ADMIN", clock=clock) == 1
    with pytest.raises(SessionError):
        load_session(db, held.token, clock=clock)
    workspace = session_for(db, scope["workspace"], clock)
    person = scope["people"]["in_b"]
    issue_session(db, person, clock=clock)
    assert revoke_sessions_of(db, workspace, person.principal_id, reason="ADMIN", clock=clock) >= 1


def test_sp17_a_personal_token_is_revoked_by_its_owner_or_their_administrator(
    db, runtime, admin_engine, scope
):
    """A personal access token is a credential of an administrator, so the workspace's token
    routes follow the same rule: another narrowed administrator of A is theirs, a workspace
    administrator is not, and their own token is always theirs."""
    tenant, narrowed, tokens = scope["tenant"], actor(scope, "narrowed"), scope["tokens"]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        # An approver's seat in B narrows them out of administering themselves, and not out
        # of their own token.
        seat(conn, tenant, scope["b"], narrowed)
    state = (
        "SELECT revoked_at IS NOT NULL AS revoked, deleted_at IS NOT NULL AS deleted "
        "FROM execbound.personal_access_tokens WHERE tenant_id = :t AND token_id = :k"
    )
    assert refused(
        admin_engine, tenant, REVOKE_TOKEN, {"a": narrowed, "k": tokens["workspace"]}
    ) == ("INVALID_TOKEN")
    call(
        admin_engine,
        tenant,
        REVOKE_TOKEN,
        {"a": actor(scope, "workspace"), "k": tokens["workspace"]},
    )
    assert refused(
        admin_engine, tenant, DELETE_TOKEN, {"a": narrowed, "k": tokens["workspace"]}
    ) == ("INVALID_TOKEN")
    assert row(admin_engine, tenant, state, k=tokens["workspace"]) == {
        "revoked": True,
        "deleted": False,
    }
    for token in (tokens["narrowed"], tokens["peer"]):
        call(admin_engine, tenant, REVOKE_TOKEN, {"a": narrowed, "k": token})
        call(admin_engine, tenant, DELETE_TOKEN, {"a": narrowed, "k": token})
        assert row(admin_engine, tenant, state, k=token) == {"revoked": True, "deleted": True}


def test_sp17_the_console_answers_404_for_a_person_outside_their_spaces(
    db, runtime, admin_engine, scope
):
    tenant, in_b, in_a = scope["tenant"], scope["people"]["in_b"], scope["people"]["in_a"]
    kept = principal_row(admin_engine, tenant, in_b.principal_id)
    person = f"{API}/people/{in_b.principal_id}"
    with console_client(db, runtime, admin_engine, scope["narrowed"]) as client:
        assert client.get(person).status_code == 404
        for path, body in (
            (person + "/label", {"label": "Renamed here"}),
            (person + "/email", {"email": "moved@example.net"}),
            (person + "/password-link", {"lifetime": "24"}),
            (person + "/credentials/issue", {"lifetime": "8"}),
            (person + f"/credentials/{in_b.credential_id}/revoke", {}),
            (person + "/sessions/end", {}),
            (person + "/deactivate", {"reason": "Left the team"}),
            (person + "/reactivate", {}),
        ):
            answer = client.post(path, body)
            assert answer.status_code == 404, (path, answer.text)
        # The credentials page's own routes reach the function, which refuses.
        answer = client.post(
            API + "/credentials/issue", {"principal": str(in_b.principal_id), "lifetime": "8"}
        )
        assert answer.status_code == 400 and answer.json()["code"] == "INVALID_PRINCIPAL"
        answer = client.post(API + f"/credentials/{in_b.credential_id}/revoke", {})
        assert answer.status_code == 409
        assert principal_row(admin_engine, tenant, in_b.principal_id) == kept
        assert (
            count(
                admin_engine,
                tenant,
                "SELECT count(*) FROM execbound.credentials WHERE tenant_id = :t "
                "AND credential_id = :c AND revoked_at IS NULL",
                c=in_b.credential_id,
            )
            == 1
        )
        answer = client.post(f"{API}/people/{in_a.principal_id}/label", {"label": "Renamed here"})
        assert answer.status_code == 200, answer.text


# SP18: what the pages show a narrowed administrator.


def people_ids(runtime, session):
    page = people_pages.people_overview(runtime, session, state="all", kind=None)
    return {row["principal_id"] for row in page["people"]}


def credential_people(runtime, session):
    page = admin_pages.credentials_overview(runtime, session)
    return (
        {row["principal_id"] for row in page["principals"] if row["kind"] != "AGENT"},
        {row["principal_id"] for row in page["credentials"] if row["kind"] != "AGENT"},
        {row["principal_id"] for row in page["principals"] if row["kind"] == "AGENT"},
    )


def test_sp18_people_and_credentials_list_a_space_administrator_their_people_alone(
    db, runtime, admin_engine, world, scope
):
    clock = runtime.clock
    narrowed = session_for(db, scope["narrowed"], clock)
    workspace = session_for(db, scope["workspace"], clock)
    people = scope["people"]
    outside = {people[name].principal_id for name in REFUSED} | {actor(scope, "workspace")}
    theirs = {
        people["in_a"].principal_id,
        world["human"].principal_id,
        actor(scope, "narrowed"),
        actor(scope, "peer"),
    }
    listed = people_ids(runtime, narrowed)
    assert theirs <= listed and not outside & listed
    principals, credentials, agents = credential_people(runtime, narrowed)
    assert theirs <= principals and not outside & principals
    assert not outside & credentials and people["in_a"].principal_id in credentials
    assert actor(scope, "own_agent") in agents and actor(scope, "other_agent") not in agents
    with pytest.raises(HTTPException) as missing:
        people_pages.person_overview(runtime, narrowed, people["in_b"].principal_id)
    assert missing.value.status_code == 404
    assert people_pages.person_overview(runtime, narrowed, people["in_a"].principal_id)
    # A workspace administrator sees everyone, whichever space they look at.
    everyone = theirs | outside
    assert everyone <= people_ids(runtime, workspace)
    with db.transaction(scope["tenant"]) as conn:
        set_current_space(conn, workspace, scope["a"])
    assert everyone <= people_ids(runtime, workspace)
    assert everyone <= credential_people(runtime, workspace)[0]
    for name in REFUSED:
        assert people_pages.person_overview(runtime, workspace, people[name].principal_id)


def test_sp18_the_workspace_token_list_shows_their_own_and_their_peoples_tokens(
    db, runtime, admin_engine, scope
):
    clock = runtime.clock
    narrowed = session_for(db, scope["narrowed"], clock)
    workspace = session_for(db, scope["workspace"], clock)
    tokens = scope["tokens"]
    listed = {
        UUID(row["token_id"]) for row in list_tokens(db, narrowed, everyone=True, clock=clock)
    }
    assert listed == {tokens["narrowed"], tokens["peer"]}
    listed = {
        UUID(row["token_id"]) for row in list_tokens(db, workspace, everyone=True, clock=clock)
    }
    assert set(tokens.values()) <= listed
    with console_client(db, runtime, admin_engine, scope["narrowed"]) as client:
        answer = client.post(API + f"/tenant/tokens/{tokens['workspace']}/revoke", {})
        assert answer.status_code == 404, answer.text
        answer = client.post(API + f"/tenant/tokens/{tokens['peer']}/revoke", {})
        assert answer.status_code == 200, answer.text


# SP19: the flow a narrowed administrator adds a person through ends in someone they
# administer.


def test_sp19_a_person_a_space_administrator_adds_is_seated_in_their_space_and_theirs(
    db, runtime, admin_engine, scope
):
    """`New approver` and the credentials page's `new:HUMAN_APPROVER` both seat the person in
    the space the administrator writes in (`admin_create_principal`, as 0041 seated every
    approver), so every later write on them is allowed."""
    clock, tenant = runtime.clock, scope["tenant"]
    narrowed = session_for(db, scope["narrowed"], clock)
    made = people_pages.create_approver(runtime, narrowed, "New analyst")
    issued = admin_pages.issue(
        runtime, narrowed, principal=None, kind="HUMAN_APPROVER", lifetime=HOUR
    )
    for person in (made, issued.principal_id):
        seats = count(
            admin_engine,
            tenant,
            "SELECT array_agg(space_id::text || ':' || role) FROM execbound.space_members "
            "WHERE tenant_id = :t AND principal_id = :p",
            p=person,
        )
        assert seats == [f"{scope['a']}:HUMAN_APPROVER"]
        assert person in people_ids(runtime, narrowed)
        people_pages.label_person(runtime, narrowed, person, "Renamed analyst")
        people_pages.set_email(runtime, narrowed, person, f"analyst.{person}@example.com")
        code = people_pages.password_link(runtime, narrowed, person, timedelta(hours=24))
        assert code["principal_id"] == person
        second = admin_pages.issue(runtime, narrowed, principal=person, kind=None, lifetime=HOUR)
        assert authenticate(db, second.token).principal_id == person
        admin_pages.revoke(runtime, narrowed, second.credential_id)
        people_pages.deactivate(runtime, narrowed, person, "Left the team")
        people_pages.reactivate(runtime, narrowed, person)
    # Looking at all of two spaces they administer, the write has no one space to land in
    # and is refused rather than guessed, as before.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        seat(conn, tenant, scope["b"], actor(scope, "narrowed"), "ADMIN")
    narrowed = session_for(db, scope["narrowed"], clock)
    with pytest.raises(AdministrationError) as refusal:
        people_pages.create_approver(runtime, narrowed, "Second analyst")
    assert refusal.value.code == "INVALID_SPACE"


# Migration 0072: every function gains the check in place, and the downgrade takes it away.

BEFORE = "0071_space_credential_scope"
TARGET = "0072_space_principal_scope"
_FILE = Path(__file__).resolve().parents[1] / "migrations" / "versions" / f"{TARGET}.py"


def _migration():
    spec = importlib.util.spec_from_file_location("space_principal_scope_migration", _FILE)
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


def test_sp16_the_upgrade_adds_the_check_and_the_downgrade_restores_each_function(admin_engine):
    migration = _migration()
    names = tuple(migration.PATCHES)
    assert len(names) == 18
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
            assert "(0072)" in body and "role = 'ADMIN'" in body, name
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert definitions(conn, names) == old
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
