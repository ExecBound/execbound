# SPDX-License-Identifier: AGPL-3.0-only
"""People carry counting numbers of their own (0062).

A person reads "User 3" where the console used to print the first characters of a UUID.
Administrators and approvers count upward per workspace in the order they were created, on a
counter separate from agents', so one workspace has a User 1 and an Agent 1. A change between
the two person kinds keeps the number; a change between a person and an agent drops the old
class's number and takes the next of the new one. The numbers are display handles only.
"""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from alembic import command as alembic
from console_api_fixtures import API, console_client
from sqlalchemy import text
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_migration_without_bypass import restricted as restricted
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_teammate_invitations import accept, principal_rows, removed

PERSON_KINDS = ("ADMIN", "HUMAN_APPROVER")


def workspace(engine) -> tuple[UUID, UUID]:
    """A fresh tenant with its one space, and no principal yet."""
    tenant, space = uuid4(), uuid4()
    with engine.begin() as conn:
        fence(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
            {"t": tenant, "n": f"numbers-{tenant.hex[:8]}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Default', now(), :b)"
            ),
            {"t": tenant, "s": space, "b": UUID(int=0)},
        )
    return tenant, space


def fence(conn, tenant) -> None:
    # Limits nothing on an `admin_engine` connection, whose owner bypasses row security
    # (see tenant_fence); on the `restricted` owner's, which has no bypass, it does.
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def insert(conn, tenant, space, kind, *, principal=None, created_at=None) -> UUID:
    principal = principal or uuid4()
    conn.execute(
        text(
            "INSERT INTO execbound.principals(tenant_id, principal_id, kind, space_id, created_at) "
            "VALUES (:t, :p, :k, :s, :c)"
        ),
        {
            "t": tenant,
            "p": principal,
            "k": kind,
            "s": space if kind == "AGENT" else None,
            "c": created_at,
        },
    )
    return principal


def numbered(engine, tenant) -> dict[UUID, tuple[str, int | None]]:
    with engine.begin() as conn:
        fence(conn, tenant)
        rows = conn.execute(
            text(
                "SELECT principal_id, kind, number FROM execbound.principals WHERE tenant_id = :t"
            ),
            {"t": tenant},
        ).all()
    return {principal: (kind, number) for principal, kind, number in rows}


def test_people_count_on_their_own_counter_beside_agents(admin_engine):
    tenant, space = workspace(admin_engine)
    with admin_engine.begin() as conn:
        fence(conn, tenant)
        made = [
            insert(conn, tenant, space, kind)
            for kind in ("ADMIN", "AGENT", "HUMAN_APPROVER", "AGENT", "HUMAN_APPROVER")
        ]
    numbers = numbered(admin_engine, tenant)
    # Each class counts from one in creation order, so the workspace has both a User 1 and
    # an Agent 1, and other workspaces' people (the test database holds many) change nothing.
    assert [numbers[p] for p in made] == [
        ("ADMIN", 1),
        ("AGENT", 1),
        ("HUMAN_APPROVER", 2),
        ("AGENT", 2),
        ("HUMAN_APPROVER", 3),
    ]


def test_a_kind_change_keeps_a_person_number_and_moves_between_classes(admin_engine):
    tenant, space = workspace(admin_engine)
    with admin_engine.begin() as conn:
        fence(conn, tenant)
        owner = insert(conn, tenant, space, "ADMIN")
        approver = insert(conn, tenant, space, "HUMAN_APPROVER")
        agent = insert(conn, tenant, space, "AGENT")
        insert(conn, tenant, space, "AGENT")
    assert numbered(admin_engine, tenant)[approver] == ("HUMAN_APPROVER", 2)

    def change(principal, kind):
        with admin_engine.begin() as conn:
            fence(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.principals SET kind = :k, space_id = :s "
                    "WHERE tenant_id = :t AND principal_id = :p"
                ),
                {"t": tenant, "p": principal, "k": kind, "s": space if kind == "AGENT" else None},
            )

    # Between the two person kinds the number stays: a promotion is the same person.
    change(approver, "ADMIN")
    assert numbered(admin_engine, tenant)[approver] == ("ADMIN", 2)
    change(approver, "HUMAN_APPROVER")
    assert numbered(admin_engine, tenant)[approver] == ("HUMAN_APPROVER", 2)
    # A person who becomes an agent takes the next agent number, and an agent who becomes a
    # person the next person number; neither keeps the other class's count.
    change(approver, "AGENT")
    assert numbered(admin_engine, tenant)[approver] == ("AGENT", 3)
    change(agent, "HUMAN_APPROVER")
    numbers = numbered(admin_engine, tenant)
    assert numbers[agent] == ("HUMAN_APPROVER", 2)
    assert numbers[owner] == ("ADMIN", 1)


def test_concurrent_people_in_one_tenant_get_distinct_numbers(admin_engine):
    """Six writers on six connections insert at once, four people and two agents. The
    per-tenant, per-class advisory lock makes each wait for the one before it to commit, so
    every person reads the last person's number; without it two would read the same maximum
    and the second would stop at the unique index."""
    tenant, space = workspace(admin_engine)
    with admin_engine.begin() as conn:
        fence(conn, tenant)
        first = insert(conn, tenant, space, "ADMIN")
    kinds = ["HUMAN_APPROVER", "ADMIN", "AGENT", "HUMAN_APPROVER", "AGENT", "HUMAN_APPROVER"]
    barrier = Barrier(len(kinds))

    def write(kind):
        with admin_engine.connect() as conn:
            with conn.begin():
                fence(conn, tenant)
                barrier.wait(timeout=10)
                principal = insert(conn, tenant, space, kind)
                # Hold the transaction open a moment, so the others read while it is live.
                time.sleep(0.2)
        return principal

    with ThreadPoolExecutor(max_workers=len(kinds)) as pool:
        made = list(pool.map(write, kinds))
    numbers = numbered(admin_engine, tenant)
    people = sorted(numbers[p][1] for p, k in zip(made, kinds, strict=True) if k != "AGENT")
    agents = sorted(numbers[p][1] for p, k in zip(made, kinds, strict=True) if k == "AGENT")
    assert numbers[first] == ("ADMIN", 1)
    assert people == [2, 3, 4, 5]
    assert agents == [1, 2]


def test_a_replaced_principal_keeps_its_number(db, admin_engine):
    where, account, old, second, second_hash = removed(db, admin_engine)
    tenant = where["tenant_id"]
    before = principal_rows(admin_engine, tenant, old)[old]["number"]
    assert before is not None
    new = uuid4()
    result = accept(db, tenant, second, second_hash, principal=new, signed_in=account)
    assert result["outcome"] == "ACCEPTED"
    rows = principal_rows(admin_engine, tenant, old, new)
    assert rows[old]["replaced_by"] == new
    assert rows[old]["number"] == before
    # The new entry is a new person and takes the next number; the old one keeps its own.
    people = [n for kind, n in numbered(admin_engine, tenant).values() if kind in PERSON_KINDS]
    assert rows[new]["number"] == max(people) > before


def test_people_payloads_carry_their_number(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    human = world["human"].principal_id
    numbers = numbered(admin_engine, tenant)
    with admin_engine.begin() as conn:
        fence(conn, tenant)
        conn.execute(
            text("UPDATE execbound.principals SET email = :e WHERE principal_id = :p"),
            {"e": f"approver-{human.hex[:8]}@example.test", "p": human},
        )
    number = numbers[human][1]
    assert number is not None
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        people = {row["principal_id"]: row for row in client.get(f"{API}/people").json()["people"]}
        assert people[str(human)]["number"] == number
        assert people[str(human)]["email"] == f"approver-{human.hex[:8]}@example.test"
        assert {row["number"] for row in people.values()} == {
            n for p, (kind, n) in numbers.items() if kind in PERSON_KINDS and str(p) in people
        }
        detail = client.get(f"{API}/people/{human}").json()
        assert detail["person"]["number"] == number
        users = {row["principal_id"]: row for row in client.get(f"{API}/access").json()["users"]}
        assert users[str(human)]["number"] == number
        approvers = client.get(f"{API}/approvers").json()
        assignment = next(r for r in approvers["assignments"] if r["approver_id"] == str(human))
        assert (assignment["number"], assignment["email"]) == (
            number,
            f"approver-{human.hex[:8]}@example.test",
        )
        option = next(r for r in approvers["approvers"] if r["principal_id"] == str(human))
        assert option["number"] == number
        spaces = client.get(f"{API}/spaces").json()["items"]
        members = {
            row["principal_id"]: row
            for space in spaces
            for row in client.get(f"{API}/spaces/{space['space_id']}").json()["members"]
        }
        assert members[str(human)]["number"] == number
        credentials = client.get(f"{API}/credentials").json()["credentials"]
        mine = next(
            r for r in credentials if r["credential_id"] == str(world["human"].credential_id)
        )
        assert mine["principal_number"] == number
        assert mine["email"] == f"approver-{human.hex[:8]}@example.test"
    # An agent is not a person, and keeps the agent count it always had.
    agent = provision_identity(admin_engine, db, tenant, "AGENT", datetime.now(UTC))
    after = numbered(admin_engine, tenant)
    assert (
        after[agent.principal_id][1]
        == max(n for kind, n in numbers.values() if kind == "AGENT" and n is not None) + 1
    )


def addressed(engine, tenant) -> dict[UUID, str]:
    """Give every person of the workspace an email, so a member row has one to leak."""
    with engine.begin() as conn:
        fence(conn, tenant)
        rows = conn.execute(
            text(
                "UPDATE execbound.principals "
                "SET email = 'member-' || principal_id::text || '@example.test' "
                "WHERE tenant_id = :t AND kind IN ('ADMIN', 'HUMAN_APPROVER') "
                "RETURNING principal_id, email"
            ),
            {"t": tenant},
        ).all()
    return {principal: email for principal, email in rows}


def teammate(engine, db, tenant, role, now, *, seated):
    """A person who joined through a teammate invitation with one grant of `role` and no Space
    scope, the grant hosted issues today: managed by access control, so the grant and not a
    seat is their authority. `seated` keeps the seat the fixture gives every approver."""
    identity = provision_identity(engine, db, tenant, "HUMAN_APPROVER", now)
    values = {"t": tenant, "p": identity.principal_id, "g": uuid4(), "r": role}
    with engine.begin() as conn:
        fence(conn, tenant)
        if not seated:
            conn.execute(
                text(
                    "DELETE FROM execbound.space_members WHERE tenant_id = :t AND principal_id = :p"
                ),
                values,
            )
        conn.execute(
            text(
                "INSERT INTO execbound.access_principals(tenant_id, principal_id) VALUES (:t, :p)"
            ),
            values,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.access_role_grants(tenant_id, grant_id, principal_id, role) "
                "VALUES (:t, :g, :p, :r)"
            ),
            values,
        )
    return identity


def member_rows(client) -> list[dict]:
    """Every member row of every space the signed-in reader can open."""
    rows = []
    for space in client.get(f"{API}/spaces").json()["items"]:
        read = client.get(f"{API}/spaces/{space['space_id']}")
        assert read.status_code == 200, read.text
        rows.extend(read.json()["members"])
    return rows


def row_of(rows, principal) -> dict:
    found = [row for row in rows if row["principal_id"] == str(principal)]
    assert found, f"{principal} is seated in no space the reader sees"
    return found[0]


def test_a_space_shows_a_members_email_only_to_an_administrator(db, runtime, admin_engine, world):
    """People and Groups already show an administrator every address; a space's member list
    reaches anyone who can read the space, so it names a member by number there instead."""
    tenant = world["identity"].tenant_id
    human = world["human"].principal_id
    emails = addressed(admin_engine, tenant)
    number = numbered(admin_engine, tenant)[human][1]
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        administrator = row_of(member_rows(client), human)
    with console_client(db, runtime, admin_engine, world["human"]) as client:
        approver = row_of(member_rows(client), human)
    assert (administrator["email"], administrator["number"]) == (emails[human], number)
    assert (approver["email"], approver["number"]) == (None, number)


@pytest.mark.parametrize(("role", "seated"), [("viewer", False), ("approver", True)])
def test_a_workspace_role_short_of_administrator_reads_no_members_email(
    db, runtime, admin_engine, world, role, seated
):
    """A teammate invited to the whole workspace as a Viewer or an Approver holds workspace-wide
    `console.read`, so every space opens to them whether or not they are seated in one. That is
    not administration, and People refuses them: the member list names every member, the reader
    included, by number and carries no email."""
    tenant = world["identity"].tenant_id
    reader = teammate(admin_engine, db, tenant, role, world["clock"].now(), seated=seated)
    emails = addressed(admin_engine, tenant)
    numbers = numbered(admin_engine, tenant)
    with console_client(db, runtime, admin_engine, reader) as client:
        assert client.get(f"{API}/people").status_code == 403
        rows = member_rows(client)
    # The reader opens the approver's space, so an absent email is the gate's and not the
    # data's: every person in this workspace has one now.
    row_of(rows, world["human"].principal_id)
    assert {UUID(row["principal_id"]) for row in rows} <= set(emails)
    assert [row["email"] for row in rows] == [None] * len(rows), rows
    assert all(row["number"] == numbers[UUID(row["principal_id"])][1] for row in rows)


def definitions(conn) -> dict[str, object]:
    """The numbering functions, indexes, checks and trigger on `principals`, from the catalog."""
    functions = conn.execute(
        text(
            "SELECT p.proname, pg_get_functiondef(p.oid), p.proacl::text FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'execbound' "
            "AND p.proname LIKE 'number_%' ORDER BY p.proname"
        )
    ).all()
    return {
        "functions": {name: (body, acl) for name, body, acl in functions},
        "indexes": conn.execute(
            text(
                "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'execbound' "
                "AND tablename = 'principals' AND indexdef LIKE '%(tenant_id, number)%' "
                "ORDER BY indexname"
            )
        ).all(),
        "constraints": conn.execute(
            text(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'execbound.principals'::regclass AND conname LIKE '%number%' "
                "ORDER BY conname"
            )
        ).all(),
        "not_null": conn.execute(
            text(
                "SELECT attnotnull FROM pg_attribute WHERE attrelid = "
                "'execbound.principals'::regclass AND attname = 'number'"
            )
        ).scalar_one(),
        "triggers": conn.execute(
            text(
                "SELECT tgname, pg_get_triggerdef(oid) FROM pg_trigger "
                "WHERE tgrelid = 'execbound.principals'::regclass AND NOT tgisinternal "
                "AND tgname = 'principals_number'"
            )
        ).all(),
    }


def test_the_migration_numbers_people_in_order_as_a_hosted_owner(restricted):
    engine, config, _ = restricted
    alembic.upgrade(config, "0061_replaced_principals")
    with engine.connect() as conn:
        at_0058 = definitions(conn)
    start = datetime(2026, 9, 1, tzinfo=UTC)
    first, other = uuid4(), uuid4()
    spaces = {first: uuid4(), other: uuid4()}
    ids = sorted(uuid4() for _ in range(5))
    # In `first`: an administrator from before creation times were kept (numbered first), two
    # approvers created in the reverse of their id order (numbered by time), and two created
    # at the same moment (numbered by id); two agents, already numbered by 0058.
    legacy, late, early, tie_high, tie_low = ids[2], ids[0], ids[1], ids[4], ids[3]
    people = {
        legacy: ("ADMIN", None),
        late: ("HUMAN_APPROVER", start + timedelta(days=3)),
        early: ("HUMAN_APPROVER", start + timedelta(days=1)),
        tie_high: ("HUMAN_APPROVER", start + timedelta(days=2)),
        tie_low: ("HUMAN_APPROVER", start + timedelta(days=2)),
    }
    agents = [uuid4(), uuid4()]
    lone = uuid4()
    with engine.begin() as conn:
        for tenant in (first, other):
            fence(conn, tenant)
            conn.execute(
                text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
                {"t": tenant, "n": f"numbers-{tenant.hex[:8]}"},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.spaces(tenant_id,space_id,name,created_at,created_by) "
                    "VALUES (:t, :s, 'Default', :c, :b)"
                ),
                {"t": tenant, "s": spaces[tenant], "c": start, "b": UUID(int=0)},
            )
        fence(conn, first)
        for agent in agents:
            insert(conn, first, spaces[first], "AGENT", principal=agent, created_at=start)
        for principal, (kind, created_at) in people.items():
            insert(conn, first, spaces[first], kind, principal=principal, created_at=created_at)
        fence(conn, other)
        insert(conn, other, spaces[other], "HUMAN_APPROVER", principal=lone, created_at=start)
    alembic.upgrade(config, "0062_people_numbers")
    with engine.begin() as conn:
        fence(conn, first)
        numbers = dict(
            conn.execute(text("SELECT principal_id, number FROM execbound.principals")).all()
        )
        assert [numbers[p] for p in (legacy, early, tie_low, tie_high, late)] == [1, 2, 3, 4, 5]
        assert [numbers[a] for a in agents] == [1, 2]
        # New rows continue both counts, inside the tenant fence the hosted owner writes under.
        person = insert(conn, first, spaces[first], "HUMAN_APPROVER")
        agent = insert(conn, first, spaces[first], "AGENT")
        after = dict(
            conn.execute(text("SELECT principal_id, number FROM execbound.principals")).all()
        )
        assert (after[person], after[agent]) == (6, 3)
    with engine.begin() as conn:
        fence(conn, other)
        assert (
            conn.execute(
                text("SELECT number FROM execbound.principals WHERE principal_id = :p"), {"p": lone}
            ).scalar_one()
            == 1
        )
    with engine.connect() as conn:
        upgraded = definitions(conn)
    assert sorted(upgraded["functions"]) == ["number_agent_key", "number_principal"]
    assert upgraded["not_null"] is True
    # 0058's rule that only an agent has a number is gone; its positive check stays.
    assert [name for name, _ in upgraded["constraints"]] == ["principals_number_check"]
    alembic.downgrade(config, "0061_replaced_principals")
    with engine.connect() as conn:
        # 0058's function, index, check and trigger come back exactly, and its grants with them.
        assert definitions(conn) == at_0058
    with engine.begin() as conn:
        fence(conn, first)
        numbers = dict(
            conn.execute(
                text("SELECT principal_id, number FROM execbound.principals WHERE kind <> 'AGENT'")
            ).all()
        )
        assert set(numbers.values()) == {None}
        # 0058's own count carries on from the agents' numbers.
        again = insert(conn, first, spaces[first], "AGENT")
        assert (
            conn.execute(
                text("SELECT number FROM execbound.principals WHERE principal_id = :p"),
                {"p": again},
            ).scalar_one()
            == 4
        )
    alembic.upgrade(config, "head")
