# SPDX-License-Identifier: AGPL-3.0-only
"""Request handles are durable presentation, never execution authority."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from console_api_fixtures import API, console_client
from space_fixtures import default_space, make_space, place, seat
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import provision_identity, targets
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_requests import wire
from test_resolution import request
from test_runtime import runtime as runtime

from execbound.execution import admit
from execbound.execution.models import wire_hash
from execbound.requests import InvalidRequest, parse_request

CASE = {"source": "tines", "case_id": "INC-4821", "url": "https://lab.tines.com/cases/4821"}


def test_case_is_presentation_and_not_retry_identity():
    plain = parse_request(wire())
    linked = parse_request(wire(external_case=CASE))
    assert wire_hash(plain) == wire_hash(linked)
    assert "external_case" not in plain.model_dump(mode="json")
    assert linked.external_case.case_id == "INC-4821"


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "http://lab.tines.com/cases/1",
        "https://user:pw@lab.tines.com/1",
        "https://127.0.0.1/1",
        "https://0177.0.0.1/1",
        "https://0x7f.0.0.1/1",
        "https://localhost/1",
        "https://lab.tines.com/1?token=secret",
        "https://lab.tines.com/1#secret",
        "https://lab.tines.com/\r\nheader",
    ],
)
def test_case_link_rejects_unsafe_destinations(url):
    with pytest.raises(InvalidRequest):
        parse_request(wire(external_case={**CASE, "url": url}))


def test_retry_preserves_first_case_and_handle(db, world):
    original = request(world, external_case=CASE)
    first = admit(db, world["identity"], original, world["clock"]).view
    retry = admit(
        db,
        world["identity"],
        request(world, external_case={**CASE, "case_id": "CHANGED"}),
        world["clock"],
    ).view
    assert retry.execution_id == first.execution_id
    assert retry.request_ref == first.request_ref == "EB-1"
    with db.transaction(world["identity"].tenant_id) as conn:
        row = conn.execute(text("SELECT frozen FROM execbound.executions")).scalar_one()
        assert row["request"]["external_case"] == CASE
        event = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events "
                "WHERE kind='execution.transition' AND payload->>'to_state'='ATTEMPTED'"
            )
        ).scalar_one()
        assert event["request_ref"] == "EB-1" and event["external_case"] == CASE


def test_concurrent_requests_allocate_unique_handles_in_one_case(db, world, admin_engine):
    requests = targets(admin_engine, world, count=4, production=True)
    requests = [
        parse_request(req.model_dump_json().encode()).model_copy(
            update={"external_case": parse_request(wire(external_case=CASE)).external_case}
        )
        for req in requests
    ]
    barrier = Barrier(len(requests))

    def submit(req):
        barrier.wait(timeout=10)
        return admit(db, world["identity"], req, world["clock"]).view

    with ThreadPoolExecutor(max_workers=4) as pool:
        views = list(pool.map(submit, requests))
    assert {view.request_ref for view in views} == {"EB-1", "EB-2", "EB-3", "EB-4"}
    assert len({view.execution_id for view in views}) == 4


def test_reference_case_and_delivery_search_keep_reviewer_scope(db, runtime, world, admin_engine):
    first = admit(db, world["identity"], request(world, external_case=CASE), world["clock"]).view
    with console_client(db, runtime, admin_engine, world["human"]) as person:
        for term in (
            first.request_ref,
            CASE["case_id"],
            str(first.execution_id),
            str(first.approval_id),
        ):
            results = person.get(API + "/search", params={"q": term}).json()["results"]
            assert any(item["execution_id"] == str(first.execution_id) for item in results)
        detail = person.get(API + "/executions/" + str(first.execution_id)).json()
        assert detail["request_ref"] == first.request_ref
        assert detail["external_case"] == CASE
        with admin_engine.begin() as conn:
            conn.execute(text("UPDATE execbound.approval_scopes SET active=false"))
        for term in (first.request_ref, CASE["case_id"]):
            assert person.get(API + "/search", params={"q": term}).json()["results"] == []


def test_case_groups_and_delivery_lookups_apply_tenant_space_and_action_scope(
    db, runtime, world, admin_engine, seeded
):
    case = parse_request(wire(external_case=CASE)).external_case
    requests = targets(admin_engine, world, count=4, production=True)
    views = [
        admit(
            db, world["identity"], req.model_copy(update={"external_case": case}), world["clock"]
        ).view
        for req in requests
    ]
    parent, allowed, revoked, elsewhere = views
    delivery = uuid4()
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.approval_notifications "
                "(tenant_id,notification_id,approval_id,destination_id,created_at,next_attempt_at) "
                "VALUES (:t,:n,:a,'synthetic',now(),now())"
            ),
            {"t": tenant, "n": delivery, "a": parent.approval_id},
        )
        other_space = make_space(conn, tenant, "Separate customer")
        # Move one execution to a space the reviewer belongs to but whose action scope
        # is still in Default. A scope from another space must not reveal this request.
        seat(conn, tenant, other_space, world["human"].principal_id)
        place(conn, tenant, "executions", "execution_id", elsewhere.execution_id, other_space)
        conn.execute(
            text(
                "UPDATE execbound.approval_scopes SET active=false "
                "WHERE canonical_target_id=(SELECT canonical_target_id FROM execbound.executions "
                "WHERE execution_id=:e)"
            ),
            {"e": revoked.execution_id},
        )
    with console_client(db, runtime, admin_engine, world["human"]) as person:
        detail = person.get(API + "/executions/" + str(parent.execution_id)).json()
        assert [r["request_ref"] for r in detail["related_requests"]] == [allowed.request_ref]
        assert detail["deliveries"][0]["delivery_id"] == str(delivery)
        assert any(e["kind"] == "delivery" for e in detail["timeline"])
        approval = person.get(API + "/approvals/" + str(parent.approval_id)).json()
        assert approval["related_requests"] == detail["related_requests"]
        assert any(e["kind"] == "delivery" for e in approval["timeline"])
        found = person.get(API + "/search", params={"q": str(delivery)}).json()["results"]
        assert [r["execution_id"] for r in found] == [str(parent.execution_id)]
        for view in (revoked, elsewhere):
            assert (
                person.get(API + "/search", params={"q": view.request_ref}).json()["results"] == []
            )
        # Current space membership is checked independently of a valid scope.
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM execbound.space_members WHERE tenant_id=:t "
                    "AND principal_id=:p AND space_id=:s"
                ),
                {"t": tenant, "p": world["human"].principal_id, "s": default_space(conn, tenant)},
            )
        assert person.get(API + "/search", params={"q": str(delivery)}).json()["results"] == []
    other = provision_identity(
        admin_engine, db, seeded["tenants"][1], "ADMIN", world["clock"].now()
    )
    with console_client(db, runtime, admin_engine, other) as outsider:
        for term in (parent.request_ref, CASE["case_id"], str(delivery)):
            assert outsider.get(API + "/search", params={"q": term}).json()["results"] == []


def test_admin_review_case_does_not_inherit_administrative_read_scope(
    db, runtime, world, admin_engine
):
    case = parse_request(wire(external_case=CASE)).external_case
    first, second = [
        admit(
            db, world["identity"], req.model_copy(update={"external_case": case}), world["clock"]
        ).view
        for req in targets(admin_engine, world, count=2, production=True)
    ]
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes "
                "(tenant_id,approver_id,canonical_target_id,action,space_id) "
                "SELECT tenant_id,:p,canonical_target_id,frozen->'intent'->>'action',space_id "
                "FROM execbound.executions WHERE execution_id=:e"
            ),
            {"p": world["admin"].principal_id, "e": first.execution_id},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as person:
        review = person.get(API + "/approvals/" + str(first.approval_id))
        assert review.status_code == 200
        assert review.json()["related_requests"] == []
        # Outside their review scope the administrator reads the record and cannot decide it.
        unassigned = person.get(API + "/approvals/" + str(second.approval_id))
        assert unassigned.status_code == 200
        assert unassigned.json()["reviewing"] is False
        assert unassigned.json()["continuation"] is None
        activity = person.get(API + "/executions/" + str(first.execution_id)).json()
        assert [r["request_ref"] for r in activity["related_requests"]] == [second.request_ref]


def test_reference_is_immutable_for_runtime_and_unique_in_tenant(db, world, admin_engine):
    first = admit(db, world["identity"], request(world), world["clock"]).view
    with pytest.raises(DBAPIError), db.transaction(world["identity"].tenant_id) as conn:
        conn.execute(
            text("UPDATE execbound.executions SET request_number=200 WHERE execution_id=:e"),
            {"e": first.execution_id},
        )
    second = admit(db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"]).view
    with pytest.raises(DBAPIError), admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.executions SET request_number=1 WHERE execution_id=:e"),
            {"e": second.execution_id},
        )


def test_ay19_each_delivery_carries_its_kind(db, runtime, world, admin_engine):
    view = admit(db, world["identity"], request(world), world["clock"]).view
    tenant = world["identity"].tenant_id
    now = world["clock"].now()
    rows = [
        ("approval.pending", "soc", None, None, now + timedelta(seconds=4)),
        ("approval.reminder", "soc", None, None, None),
        ("approval.closed", "soc", "REFUSED", now, now + timedelta(seconds=9)),
    ]
    with admin_engine.begin() as conn:
        for index, (kind, destination, outcome, closed_at, delivered_at) in enumerate(rows):
            conn.execute(
                text(
                    "INSERT INTO execbound.approval_notifications (tenant_id, notification_id, "
                    "approval_id, destination_id, kind, outcome, closed_at, state, created_at, "
                    "next_attempt_at, delivered_at) VALUES (:t, :n, :a, :d, :k, :o, :c, :s, "
                    ":created, :created, :delivered)"
                ),
                {
                    "t": tenant,
                    "n": uuid4(),
                    "a": view.approval_id,
                    "d": destination,
                    "k": kind,
                    "o": outcome,
                    "c": closed_at,
                    "s": "PENDING" if delivered_at is None else "DELIVERED",
                    "created": now + timedelta(seconds=index),
                    "delivered": delivered_at,
                },
            )
    with console_client(db, runtime, admin_engine, world["human"]) as person:
        detail = person.get(API + "/executions/" + str(view.execution_id)).json()
        approval = person.get(API + "/approvals/" + str(view.approval_id)).json()
    for read in (detail, approval):
        assert [d["kind"] for d in read["deliveries"]] == [kind for kind, *_ in rows]
        said = [e["sentence"] for e in read["timeline"] if e["kind"] == "delivery"]
        assert said == [
            "Review notification queued.",
            "Reminder queued.",
            "Outcome message queued.",
            "Review notification delivered.",
            "Outcome message delivered.",
        ]
        assert sum("Review notification" in s for s in said) == 2
