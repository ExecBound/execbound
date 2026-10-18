# SPDX-License-Identifier: AGPL-3.0-only
"""Agents and their API keys carry counting numbers, and a spent key can be deleted (0058).

A person reads "Agent 3" and "Key 12" rather than the first characters of a UUID. The numbers
count upward per workspace, one sequence for agents and one for agents' keys; a person's
credential gets none. People have a sequence of their own since 0062 (`test_people_numbers.py`).
A revoked or expired API key can be deleted: it leaves every list, and the audit chain keeps
its issue, revoke and delete events.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command as alembic
from console_api_fixtures import API, console_client
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_console_api_agents import without_token
from test_emergency_stop import audit
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_migration_without_bypass import restricted as restricted
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.replay.verify import _INFORMATIONAL

CREDENTIALS = API + "/credentials"


def numbers(admin_engine, tenant) -> dict[str, dict[str, int | None]]:
    """Every principal's and key's number, and the agents' and people's apart: the two count
    separately since 0062, so an agent's next number is one past the agents' maximum."""
    with admin_engine.begin() as conn:
        principals = conn.execute(
            text(
                "SELECT principal_id, kind, number FROM execbound.principals WHERE tenant_id = :t"
            ),
            {"t": tenant},
        ).all()
        keys = conn.execute(
            text("SELECT credential_id, number FROM execbound.credentials WHERE tenant_id = :t"),
            {"t": tenant},
        ).all()
    return {
        "principals": {str(p): n for p, _, n in principals},
        "agents": {str(p): n for p, kind, n in principals if kind == "AGENT"},
        "people": {str(p): n for p, kind, n in principals if kind != "AGENT"},
        "credentials": {str(c): n for c, n in keys},
    }


def test_agents_and_their_keys_count_upward_and_a_persons_credential_gets_no_number(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    before = numbers(admin_engine, tenant)
    agent_numbers = [n for n in before["agents"].values() if n is not None]
    key_numbers = [n for n in before["credentials"].values() if n is not None]
    # A person is numbered on the people's own count (0062); their credential is not a key.
    human = before["people"][str(world["human"].principal_id)]
    assert human is not None
    assert before["people"][str(world["admin"].principal_id)] is not None
    assert before["credentials"][str(world["human"].credential_id)] is None
    assert before["principals"][str(world["identity"].principal_id)] == max(agent_numbers)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        made = []
        for label in ("Coding agent on my laptop", "Review bot"):
            issued = client.post(
                f"{CREDENTIALS}/issue",
                {"principal": "new:AGENT", "label": label, "lifetime": "8"},
            )
            assert issued.status_code == 200, issued.text
            made.append(without_token(issued))
        assert [m["number"] for m in made] == [max(key_numbers) + 1, max(key_numbers) + 2]
        page = client.get(CREDENTIALS).json()
    after = numbers(admin_engine, tenant)
    assert [after["agents"][m["principal_id"]] for m in made] == [
        max(agent_numbers) + 1,
        max(agent_numbers) + 2,
    ]
    options = {row["principal_id"]: row for row in page["principals"]}
    assert options[made[0]["principal_id"]]["label"] == "Coding agent on my laptop"
    assert options[made[0]["principal_id"]]["number"] == max(agent_numbers) + 1
    assert options[str(world["human"].principal_id)]["number"] == human
    rows = {row["credential_id"]: row for row in page["credentials"]}
    assert rows[made[1]["credential_id"]]["number"] == max(key_numbers) + 2
    assert rows[made[1]["credential_id"]]["principal_number"] == max(agent_numbers) + 2
    assert rows[str(world["human"].credential_id)]["number"] is None


def test_numbers_are_per_workspace(db, admin_engine, world, seeded):
    now = datetime.now(UTC)
    other = seeded["tenants"][1]
    first = numbers(admin_engine, other)
    start = max((n for n in first["agents"].values() if n is not None), default=0)
    for _ in range(2):
        provision_identity(admin_engine, db, world["identity"].tenant_id, "AGENT", now)
    mine = numbers(admin_engine, world["identity"].tenant_id)
    # This workspace now has more agents, so a shared count would give a larger number.
    assert max(n for n in mine["agents"].values() if n is not None) > start
    agent = provision_identity(admin_engine, db, other, "AGENT", now)
    assert numbers(admin_engine, other)["agents"][str(agent.principal_id)] == start + 1


def test_a_principal_whose_kind_changes_takes_the_next_number_of_its_class(db, admin_engine, world):
    tenant = world["identity"].tenant_id
    now = datetime.now(UTC)
    agent = str(provision_identity(admin_engine, db, tenant, "AGENT", now).principal_id)
    person = str(world["human"].principal_id)
    people = max(n for n in numbers(admin_engine, tenant)["people"].values() if n is not None)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.principals SET kind = 'HUMAN_APPROVER', space_id = NULL "
                "WHERE principal_id = :p"
            ),
            {"p": agent},
        )
        top = conn.execute(
            text(
                "SELECT max(number) FROM execbound.principals "
                "WHERE tenant_id = :t AND kind = 'AGENT'"
            ),
            {"t": tenant},
        ).scalar_one()
        conn.execute(
            text(
                "UPDATE execbound.principals SET kind = 'AGENT', space_id = (SELECT space_id "
                "FROM execbound.spaces s WHERE s.tenant_id = principals.tenant_id LIMIT 1) "
                "WHERE principal_id = :p"
            ),
            {"p": person},
        )
    after = numbers(admin_engine, tenant)["principals"]
    # Each drops the number of the class it left and takes the next of the one it joined.
    assert after[agent] == people + 1
    assert after[person] == top + 1


def test_a_label_names_only_a_new_agent(db, runtime, admin_engine, world):
    human = str(world["human"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        for principal in (human, "new:HUMAN_APPROVER"):
            refused = client.post(
                f"{CREDENTIALS}/issue", {"principal": principal, "label": "x", "lifetime": "8"}
            )
            assert refused.status_code == 400 and refused.json()["fields"] == ["label"]
        blank = client.post(
            f"{CREDENTIALS}/issue", {"principal": "new:AGENT", "label": "  ", "lifetime": "8"}
        )
        assert blank.status_code == 400 and blank.json()["fields"] == ["label"]


def test_a_spent_key_is_deleted_from_every_list_and_the_chain_keeps_it(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    agent = str(world["identity"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        issued = without_token(
            client.post(f"{API}/agents/{agent}/credentials/issue", {"lifetime": "1"})
        )
        key = issued["credential_id"]
        live = client.post(f"{CREDENTIALS}/{key}/delete", {})
        assert live.status_code == 409 and live.json()["code"] == "CONFLICT"
        assert client.post(f"{CREDENTIALS}/{key}/revoke", {}).status_code == 200
        deleted = client.post(f"{CREDENTIALS}/{key}/delete", {})
        assert deleted.status_code == 200, deleted.text
        assert key not in {row["credential_id"] for row in deleted.json()["credentials"]}
        detail = client.get(f"{API}/agents/{agent}").json()
        assert key not in {row["credential_id"] for row in detail["credentials"]}
        again = client.post(f"{CREDENTIALS}/{key}/delete", {})
        assert again.status_code == 409
        # A person's spent credential is not an API key and is never deleted here.
        person = str(world["human"].credential_id)
        assert client.post(f"{CREDENTIALS}/{person}/revoke", {}).status_code == 200
        assert client.post(f"{CREDENTIALS}/{person}/delete", {}).status_code == 409
    event = audit(admin_engine, tenant, "credential.deleted")[-1]
    assert event["credential_id"] == key
    assert [e["credential_id"] for e in audit(admin_engine, tenant, "credential.revoked")][
        -2
    ] == key
    assert "credential.deleted" in _INFORMATIONAL


def test_an_expired_key_is_deleted_from_its_agents_page(db, runtime, admin_engine, world):
    agent = str(world["identity"].principal_id)
    expired = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.credentials "
                "(tenant_id,principal_id,credential_id,token_hash,issued_at,expires_at) "
                "VALUES (:t,:p,:c,:h,:i,:e)"
            ),
            {
                "t": world["identity"].tenant_id,
                "p": world["identity"].principal_id,
                "c": expired,
                "h": "0" * 64,
                "i": datetime.now(UTC) - timedelta(days=2),
                "e": datetime.now(UTC) - timedelta(days=1),
            },
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        gone = client.post(f"{API}/agents/{agent}/credentials/{expired}/delete", {})
        assert gone.status_code == 200, gone.text
        assert str(expired) not in {row["credential_id"] for row in gone.json()["credentials"]}


def test_the_migration_numbers_what_exists_in_order_as_a_hosted_owner(restricted):
    engine, config, _ = restricted
    alembic.upgrade(config, "0057_api_key_never")
    tenant, space = uuid4(), uuid4()
    agents = [uuid4(), uuid4()]
    human = uuid4()
    start = datetime(2026, 9, 1, tzinfo=UTC)

    def scoped(conn):
        conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})

    with engine.begin() as conn:
        scoped(conn)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id,name) VALUES(:t,'Numbers')"),
            {"t": tenant},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id,space_id,name,created_at,created_by) "
                "VALUES(:t,:s,'Default',:c,:b)"
            ),
            {"t": tenant, "s": space, "c": start, "b": uuid4()},
        )
        # Created in the reverse of their id order, so the numbers follow time, not ids.
        for offset, principal in enumerate(sorted(agents, reverse=True)):
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id,principal_id,kind,space_id,"
                    "created_at) VALUES (:t,:p,'AGENT',:s,:c)"
                ),
                {"t": tenant, "p": principal, "s": space, "c": start + timedelta(days=offset)},
            )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id,principal_id,kind) "
                "VALUES (:t,:p,'HUMAN_APPROVER')"
            ),
            {"t": tenant, "p": human},
        )
        for offset, principal in enumerate([*sorted(agents, reverse=True), human]):
            conn.execute(
                text(
                    "INSERT INTO execbound.credentials(tenant_id,principal_id,credential_id,"
                    "token_hash,issued_at,expires_at) VALUES (:t,:p,:c,:h,:i,:e)"
                ),
                {
                    "t": tenant,
                    "p": principal,
                    "c": uuid4(),
                    "h": f"{offset:064d}",
                    "i": start + timedelta(hours=offset),
                    "e": start + timedelta(days=30),
                },
            )
    alembic.upgrade(config, "0058_api_key_numbers")
    with engine.begin() as conn:
        scoped(conn)
        principals = dict(
            conn.execute(
                text("SELECT principal_id, number FROM execbound.principals ORDER BY created_at")
            ).all()
        )
        keys = conn.execute(
            text("SELECT number FROM execbound.credentials ORDER BY issued_at")
        ).scalars()
        assert [principals[p] for p in sorted(agents, reverse=True)] == [1, 2]
        assert principals[human] is None
        assert list(keys) == [1, 2, None]
        # New rows continue the count, inside the tenant fence the hosted owner writes under.
        later = uuid4()
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id,principal_id,kind,space_id) "
                "VALUES (:t,:p,'AGENT',:s)"
            ),
            {"t": tenant, "p": later, "s": space},
        )
        assert (
            conn.execute(
                text("SELECT number FROM execbound.principals WHERE principal_id = :p"),
                {"p": later},
            ).scalar_one()
            == 3
        )
    alembic.downgrade(config, "0057_api_key_never")
    with engine.connect() as conn:
        columns = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = "
                "'execbound' AND table_name IN ('principals','credentials') "
                "AND column_name IN ('number','deleted_at')"
            )
        ).scalars()
        assert list(columns) == []
    alembic.upgrade(config, "head")


@pytest.mark.parametrize("state", ["live", "person"])
def test_the_function_deletes_only_a_spent_agent_key(runtime, admin_engine, world, state):
    tenant = world["identity"].tenant_id
    credential = (
        world["identity"].credential_id if state == "live" else world["human"].credential_id
    )
    with pytest.raises(DBAPIError, match="INVALID_CREDENTIAL"):
        with runtime.db.transaction(tenant) as conn:
            conn.execute(
                text("SELECT execbound.admin_delete_credential(:a, :c, :n)"),
                {"a": world["admin"].principal_id, "c": credential, "n": datetime.now(UTC)},
            )
