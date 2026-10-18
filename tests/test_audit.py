# SPDX-License-Identifier: AGPL-3.0-only
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from execbound.audit import acted_with, append_event, read_events, verify_chain

pytestmark = pytest.mark.integration


def test_acted_with_names_the_credential_under_the_one_key_or_nothing():
    """Every administration event names the credential that acted under one key, built in
    one place; an owner command that acts with no credential names none."""
    credential = uuid4()
    assert acted_with(credential) == {"actor_credential_id": str(credential)}
    assert acted_with(None) == {}


def test_concurrent_first_appends_form_one_chain(db, seeded):
    tenant, actor = seeded["tenants"][0], seeded["principals"][0]

    def append(index):
        with db.transaction(tenant) as conn:
            return append_event(conn, tenant, actor, "test.recorded", {"index": index})

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(append, range(24)))
    with db.transaction(tenant) as conn:
        events = read_events(conn, tenant)
    head = max(results, key=lambda result: result["sequence"])
    assert [event["sequence"] for event in events] == list(range(1, 25))
    assert verify_chain(events, tenant, 24, head["event_hash"])
    tampered = deepcopy(events)
    tampered[1]["payload"]["index"] = 999
    assert not verify_chain(tampered, tenant, 24, head["event_hash"])
    assert not verify_chain(events[:-1], tenant, 24, head["event_hash"])
    assert not verify_chain(events, seeded["tenants"][1], 24, head["event_hash"])


def test_append_rolls_back_with_parent_transaction(db, seeded):
    tenant, actor = seeded["tenants"][0], seeded["principals"][0]
    with pytest.raises(RuntimeError):
        with db.transaction(tenant) as conn:
            append_event(conn, tenant, actor, "test.recorded", {})
            raise RuntimeError("simulate failed parent write")
    with db.transaction(tenant) as conn:
        assert read_events(conn, tenant) == []
        assert append_event(conn, tenant, actor, "test.recorded", {})["sequence"] == 1


def test_actor_must_belong_to_event_tenant(db, seeded):
    with pytest.raises(DBAPIError), db.transaction(seeded["tenants"][0]) as conn:
        append_event(conn, seeded["tenants"][0], seeded["principals"][1], "test.recorded", {})
    with db.transaction(seeded["tenants"][0]) as conn:
        assert read_events(conn, seeded["tenants"][0]) == []


@pytest.mark.parametrize(
    "payload", [{"value": float("nan")}, {"value": 0.1}, {1: "bad"}, {"value": object()}]
)
def test_payload_rejects_ambiguous_values(db, seeded, payload):
    with pytest.raises(ValueError), db.transaction(seeded["tenants"][0]) as conn:
        append_event(conn, seeded["tenants"][0], seeded["principals"][0], "test.recorded", payload)


def test_event_and_head_are_invisible_to_other_tenant(db, seeded):
    with db.transaction(seeded["tenants"][0]) as conn:
        append_event(conn, seeded["tenants"][0], seeded["principals"][0], "test.recorded", {})
    with db.transaction(seeded["tenants"][1]) as conn:
        assert read_events(conn, seeded["tenants"][0]) == []
        assert conn.execute(text("SELECT count(*) FROM execbound.audit_heads")).scalar_one() == 0
