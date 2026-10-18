# SPDX-License-Identifier: AGPL-3.0-only
"""One name per principal (#678): the rule, the table both sides read, the fenced read.

The rule is written twice, once for the server's few sentences and once for the console's pages,
and both are held to one table of cases in `console/src/test/principal-names.json`. The read
behind every reference runs on a connection fenced to one workspace, as the runtime role, because
the owner the suite migrates with bypasses row-level security and a test on it proves nothing.
"""

import json
from pathlib import Path
from uuid import UUID

from sqlalchemy import text
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world

from execbound.surfaces import names
from execbound.surfaces.console_api.principals import principal_ref
from execbound.surfaces.names import PrincipalFacts, principal_facts, principal_name

TABLE = Path(__file__).resolve().parents[1] / "console" / "src" / "test" / "principal-names.json"


def test_principal_name_follows_the_shared_table():
    cases = json.loads(TABLE.read_text(encoding="utf-8"))
    assert len(cases) >= 9
    for case in cases:
        identifier = UUID(case["principal_id"])
        named = principal_name(case["kind"], case["label"], case["number"], identifier)
        assert named == case["name"], case["case"]


def test_a_reference_holds_only_what_the_facts_hold():
    known = UUID("3f2504e0-4f89-41d3-9a0c-0305e82c3301")
    facts = {known: PrincipalFacts("AGENT", None, 3)}
    ref = principal_ref(known, facts)
    assert ref is not None and (ref.kind, ref.label, ref.number) == ("AGENT", None, 3)
    assert principal_ref(UUID(int=7), facts) is None
    assert principal_ref(None, facts) is None


def numbers(admin_engine, *ids):
    with admin_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT principal_id, kind, number FROM execbound.principals "
                "WHERE principal_id = ANY(CAST(:ids AS uuid[]))"
            ),
            {"ids": [str(identifier) for identifier in ids]},
        )
        return {row.principal_id: (row.kind, row.number) for row in rows}


def test_cf9_principal_facts_reads_only_the_fenced_workspace(db, admin_engine, world, seeded):
    tenant = world["identity"].tenant_id
    other = seeded["tenants"][1]
    assert other != tenant
    agent, person, unasked = (
        world["identity"].principal_id,
        world["admin"].principal_id,
        world["human"].principal_id,
    )
    stranger_agent = seeded["principals"][1]
    stranger = provision_identity(admin_engine, db, other, "HUMAN_APPROVER", world["clock"].now())
    held = numbers(admin_engine, agent, person, stranger_agent, stranger.principal_id)
    # Each workspace has its own Agent 1 and its own first person.
    assert held[agent] == ("AGENT", 1) and held[stranger_agent] == ("AGENT", 1)
    assert held[person][1] == 1 and held[stranger.principal_id] == ("HUMAN_APPROVER", 1)

    with db.transaction(tenant) as conn:
        found = principal_facts(
            conn, tenant, [agent, person, stranger_agent, stranger.principal_id]
        )
    assert set(found) == {agent, person}
    assert found[agent] == PrincipalFacts("AGENT", None, 1)
    assert found[person] == PrincipalFacts("ADMIN", None, 1)
    assert unasked not in found

    # The other workspace's fence finds only its own, even when asked by this one's tenant id.
    with db.transaction(other) as conn:
        assert principal_facts(conn, tenant, [agent, person]) == {}
        mine = principal_facts(conn, other, [agent, stranger_agent])
    assert set(mine) == {stranger_agent}


def test_the_facts_statement_names_its_tenant():
    """Forced row-level security would hide a missing predicate from any behavioural test, so
    the statement's own text holds it in place (the tenant-fence guard's pattern)."""
    assert "tenant_id=:t" in names.FACTS
    assert "principal_id = ANY(" in names.FACTS


def test_principal_facts_with_no_ids_issues_no_query():
    class Refuses:
        def execute(self, *args, **kwargs):
            raise AssertionError("no statement was expected")

    assert principal_facts(Refuses(), UUID(int=1), []) == {}  # type: ignore[arg-type]
