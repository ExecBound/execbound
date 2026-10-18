# SPDX-License-Identifier: AGPL-3.0-only
"""The page's administration rule and the definer functions' are one rule, written twice.

Migration `0072_space_principal_scope` gave eighteen definer functions one check, its
`MAY_ADMINISTER`, of whom an administrator narrowed to spaces may change: an agent of a space
where their membership is `ADMIN`, and a person seated in at least one space, every one of
them such a space, whom neither the access model's management nor an access group reaches.
`spaces.administered_clause` states the same rule as one predicate, so a page lists and offers
only the changes the database will make. Nothing compared the two copies until this file
(#241, and the review of #677).

The oracle is `admin_label_principal`, one of the functions that carries the check, called in
a savepoint that is rolled back, so the world is the same for every pair. Every reachable
administrator of the SP16 to SP19 world, with more of them seated every way, is asked about
every principal of the tenant, and the predicate must admit exactly those the function
accepts.

The copies differ in one branch: the functions let an actor who holds no membership at all
administer everyone, where the predicate asks only whether the actor holds `access.manage`
workspace-wide. The branch decides nothing. Every administrator the functions accept who holds
no membership holds `access.manage` workspace-wide, because an unmanaged `ADMIN` without a seat
holds it by kind and the access model's `administrator` role is workspace-wide by constraint,
and every principal that holds neither is refused as an actor before the check is read. The
second test pins that, so a change that let the branch decide something fails here rather than
in a page that offers a change the database refuses. The third holds `spaces.narrowed`, the
question the workspace-wide functions ask, to the predicate's own test of `access.manage`.
"""

from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from space_fixtures import make_space, seat
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import registry as registry
from test_execution import world as world
from test_spaces_principals import LABEL, fenced
from test_spaces_principals import scope as scope

from execbound.access_control import has_permission
from execbound.spaces import administered_clause, narrowed

pytestmark = pytest.mark.integration

# Whom each narrowed administrator administers, by the rule decided on 8 October 2026. The
# world is built so that the rule's every clause decides at least one of these: the `ADMIN`
# role (an approver's seat in B), every seat (A and B, A and C), at least one seat, the
# access model's management and an access group. A workspace administrator administers every
# principal of the tenant.
THEIR_OWN = {
    "narrowed": {"own_agent", "narrowed", "peer", "human", "in_a"},
    "narrowed_ab": {
        "own_agent",
        "other_agent",
        "narrowed",
        "peer",
        "narrowed_ab",
        "approver_in_b",
        "human",
        "in_a",
        "in_b",
        "in_both",
    },
}
THEIR_OWN["peer"] = THEIR_OWN["narrowed"]
# Seated in B as an approver, they read B and administer none of it.
THEIR_OWN["approver_in_b"] = THEIR_OWN["narrowed"]
WORKSPACE = ("workspace", "managed_admin", "group_admin")


def principal(conn, tenant: UUID, kind: str, space: UUID | None = None) -> UUID:
    """A principal written directly, with no credential: neither copy of the rule reads one."""
    principal_id = uuid4()
    conn.execute(
        text(
            "INSERT INTO execbound.principals (tenant_id, principal_id, kind, space_id) "
            "VALUES (:t, :p, :k, :s)"
        ),
        {"t": tenant, "p": principal_id, "k": kind, "s": space},
    )
    return principal_id


def grant(conn, tenant: UUID, role: str, *, principal_id=None, group=None) -> None:
    conn.execute(
        text(
            "INSERT INTO execbound.access_role_grants "
            "(tenant_id, grant_id, principal_id, group_id, role, space_id) "
            "VALUES (:t, :i, :p, :g, :r, NULL)"
        ),
        {"t": tenant, "i": uuid4(), "p": principal_id, "g": group, "r": role},
    )


@pytest.fixture
def rule_world(admin_engine, world, scope):
    """The SP16 to SP19 world, with more administrators and people seated every way.

    From `world` and `scope`: space A, the default, and B; `workspace`, an administrator who
    holds no membership; `narrowed` and `peer`, seated as `ADMIN` in A; `own_agent` in A and
    `other_agent` in B; `human` and `in_a` seated in A, `in_b` in B, `in_both` in A and B,
    `unseated` in no space; `managed`, seated in A and managed by the access model; `grouped`,
    seated in A and a member of an access group.

    Added here: space C and `agent_c` in it; `in_a_and_c`, seated in A and C; `narrowed_ab`,
    seated as `ADMIN` in A and B; `approver_in_b`, seated as `ADMIN` in A and as an approver
    in B; `managed_admin`, seated as `ADMIN` in A and managed with the workspace-wide
    `administrator` role; `group_admin`, an approver seated in A whose group holds that role.
    And the principals who hold no membership and no workspace-wide `access.manage`, whom the
    functions' extra branch would let administer everyone: `unseated`; `demoted`, an `ADMIN` managed
    by the access model with no role; `policy_only`, managed with the `policy_manager` role;
    `deactivated`, an unmanaged `ADMIN` who has been deactivated; and every agent.
    """
    tenant, a, b = scope["tenant"], scope["a"], scope["b"]
    names = {
        name: scope[name].principal_id
        for name in ("workspace", "narrowed", "peer", "own_agent", "other_agent")
    }
    names["human"] = world["human"].principal_id
    names.update({name: person.principal_id for name, person in scope["people"].items()})
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        c = make_space(conn, tenant, "Customer C")
        names["agent_c"] = principal(conn, tenant, "AGENT", c)
        names["in_a_and_c"] = principal(conn, tenant, "HUMAN_APPROVER")
        seat(conn, tenant, a, names["in_a_and_c"])
        seat(conn, tenant, c, names["in_a_and_c"])
        names["narrowed_ab"] = principal(conn, tenant, "ADMIN")
        seat(conn, tenant, a, names["narrowed_ab"], "ADMIN")
        seat(conn, tenant, b, names["narrowed_ab"], "ADMIN")
        names["approver_in_b"] = principal(conn, tenant, "ADMIN")
        seat(conn, tenant, a, names["approver_in_b"], "ADMIN")
        seat(conn, tenant, b, names["approver_in_b"])
        names["managed_admin"] = principal(conn, tenant, "ADMIN")
        seat(conn, tenant, a, names["managed_admin"], "ADMIN")
        names["group_admin"] = principal(conn, tenant, "HUMAN_APPROVER")
        seat(conn, tenant, a, names["group_admin"])
        names["demoted"] = principal(conn, tenant, "ADMIN")
        names["policy_only"] = principal(conn, tenant, "ADMIN")
        for managed in ("managed_admin", "demoted", "policy_only"):
            conn.execute(
                text("INSERT INTO execbound.access_principals VALUES (:t, :p)"),
                {"t": tenant, "p": names[managed]},
            )
        grant(conn, tenant, "administrator", principal_id=names["managed_admin"])
        grant(conn, tenant, "policy_manager", principal_id=names["policy_only"])
        administrators = uuid4()
        conn.execute(
            text(
                "INSERT INTO execbound.access_groups (tenant_id, group_id, name, created_at) "
                "VALUES (:t, :g, 'Administrators', now())"
            ),
            {"t": tenant, "g": administrators},
        )
        conn.execute(
            text("INSERT INTO execbound.access_group_members VALUES (:t, :g, :p)"),
            {"t": tenant, "g": administrators, "p": names["group_admin"]},
        )
        grant(conn, tenant, "administrator", group=administrators)
        names["deactivated"] = principal(conn, tenant, "ADMIN")
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, deactivated_at = now() "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": names["deactivated"]},
        )
        kinds = dict(
            conn.execute(
                text("SELECT principal_id, kind FROM execbound.principals WHERE tenant_id = :t"),
                {"t": tenant},
            ).all()
        )
    # Every principal of the tenant has a name, so a failure names whom it is about.
    assert set(kinds) == set(names.values())
    agents = {name for name, value in names.items() if kinds[value] == "AGENT"}
    assert agents == {"own_agent", "other_agent", "agent_c"}
    return {"tenant": tenant, "names": names, "agents": agents}


def as_session(tenant: UUID, actor: UUID) -> SimpleNamespace:
    """What `administered_clause` reads of a session: its identity, and nothing else."""
    return SimpleNamespace(identity=SimpleNamespace(tenant_id=tenant, principal_id=actor))


def label(conn, actor: UUID, target: UUID) -> str | None:
    """`admin_label_principal`'s answer, in a savepoint rolled back whatever it answers."""
    savepoint = conn.begin_nested()
    try:
        conn.execute(text(LABEL), {"a": actor, "p": target})
    except DBAPIError as refusal:
        return str(refusal.orig.diag.message_primary)
    else:
        return None
    finally:
        savepoint.rollback()


def accepted(conn, actor: UUID, target: UUID) -> bool:
    answer = label(conn, actor, target)
    assert answer in (None, "INVALID_PRINCIPAL"), answer
    return answer is None


def reachable(conn, actor: UUID) -> bool:
    """Whether the functions accept this principal as an administrator at all.

    Asked about a principal that does not exist: an actor they accept is answered
    `INVALID_PRINCIPAL`, and one they do not, `INVALID_ACTOR`, before any target is read.
    """
    answer = label(conn, actor, uuid4())
    assert answer in ("INVALID_PRINCIPAL", "INVALID_ACTOR"), answer
    return answer == "INVALID_PRINCIPAL"


def admitted(conn, tenant: UUID, actor: UUID, *, agents: bool) -> set[UUID]:
    clause = administered_clause(conn, as_session(tenant, actor), "p", agents=agents)
    return set(
        conn.execute(
            text(
                "SELECT p.principal_id FROM execbound.principals p WHERE p.tenant_id = :t"
                + clause.sql  # nosec B608 - the helper's predicate; values are bound
            ),
            {"t": tenant, **clause.params},
        ).scalars()
    )


def member(conn, tenant: UUID, actor: UUID) -> bool:
    return bool(
        conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.space_members "
                "WHERE tenant_id = :t AND principal_id = :p)"
            ),
            {"t": tenant, "p": actor},
        ).scalar_one()
    )


def test_the_page_rule_admits_exactly_whom_the_definer_functions_accept(db, rule_world):
    """For every reachable administrator and every principal of the tenant, the predicate
    admits the principal exactly when `admin_label_principal` accepts them. With
    `agents=False` it narrows only the people, the same ones, and leaves every agent to the
    caller's own `space_clause`."""
    tenant, names, agents = rule_world["tenant"], rule_world["names"], rule_world["agents"]
    name_of = {value: name for name, value in names.items()}
    found = {}
    with db.transaction(tenant) as conn:
        for name, actor in names.items():
            if not reachable(conn, actor):
                continue
            oracle = {name_of[t] for t in names.values() if accepted(conn, actor, t)}
            page = {name_of[p] for p in admitted(conn, tenant, actor, agents=True)}
            assert page == oracle, name
            listed = {name_of[p] for p in admitted(conn, tenant, actor, agents=False)}
            assert listed - agents == oracle - agents, name
            assert agents <= listed, name
            found[name] = oracle
    # The world tells the rule apart, so agreement is not two copies refusing everything.
    for name in WORKSPACE:
        assert found.pop(name) == set(names), name
    assert found == THEIR_OWN


def test_the_branch_only_the_definer_functions_have_decides_nothing(db, rule_world):
    """The functions' extra branch, an actor who holds no membership, decides nothing: every
    administrator they accept holds a membership or `access.manage` workspace-wide, which both
    copies already treat alike, and every principal who holds neither is refused as an actor
    before the check is read."""
    tenant, names = rule_world["tenant"], rule_world["names"]
    branch = set()
    with db.transaction(tenant) as conn:
        for name, actor in names.items():
            workspace_wide = has_permission(conn, tenant, actor, "access.manage")
            seated = member(conn, tenant, actor)
            if reachable(conn, actor):
                assert workspace_wide or seated, name
            elif not (workspace_wide or seated):
                branch.add(name)
    # The world holds a principal of every shape the branch would let administer everyone.
    assert branch == {
        "unseated",
        "demoted",
        "policy_only",
        "deactivated",
        "own_agent",
        "other_agent",
        "agent_c",
    }


def test_narrowed_is_the_absence_of_workspace_access_manage_for_every_reachable_administrator(
    db, rule_world
):
    """`spaces.narrowed`, the question the workspace-wide functions ask, and the predicate's
    own test, workspace-wide `access.manage`, give one answer for every administrator the
    functions accept."""
    tenant, names = rule_world["tenant"], rule_world["names"]
    answers = {}
    with db.transaction(tenant) as conn:
        for name, actor in names.items():
            if reachable(conn, actor):
                answers[name] = narrowed(conn, tenant, actor)
                assert answers[name] == (
                    not has_permission(conn, tenant, actor, "access.manage")
                ), name
    assert {name for name, value in answers.items() if value} == set(THEIR_OWN)
    assert {name for name, value in answers.items() if not value} == set(WORKSPACE)
