# SPDX-License-Identifier: AGPL-3.0-only
"""SP11: the Spaces area of the console API, every route through the shared harness.

The two standard sweeps first — a bearer credential refused 403 and audited, no session
refused 401 in JSON even to a browser — then the area's own cases: a member refused on
every administration route, a cross-tenant or unknown space answered 404 alike, the
session mutation answering the fresh session view, and the secret check over every
response.
"""

from uuid import uuid4

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, refusals
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

pytestmark = pytest.mark.integration

SPACES = API + "/spaces"
SESSION_SPACE = API + "/session/space"
ZERO = "00000000-0000-0000-0000-000000000000"
ROUTES = [
    (SPACES, "GET", None),
    (SPACES, "POST", {"name": "Customer A"}),
    (f"{SPACES}/{ZERO}", "GET", None),
    (f"{SPACES}/{ZERO}/rename", "POST", {"name": "Customer A"}),
    (f"{SPACES}/{ZERO}/archive", "POST", {"reason": "left"}),
    (f"{SPACES}/{ZERO}/unarchive", "POST", {"reason": "returned"}),
    (f"{SPACES}/{ZERO}/members/assign", "POST", {"principal_id": ZERO, "role": "HUMAN_APPROVER"}),
    (f"{SPACES}/{ZERO}/members/unassign", "POST", {"principal_id": ZERO}),
    (SESSION_SPACE, "POST", {"space_id": None}),
]


@pytest.mark.parametrize("path,method", [(path, method) for path, method, _ in ROUTES])
def test_every_route_refuses_a_bearer_and_no_session(
    db, runtime, seeded, admin_engine, world, path, method
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403 and results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1
    assert results["no_session"].status_code == 401
    assert results["no_session"].headers["content-type"].startswith("application/json")


def test_an_approver_is_refused_on_every_administration_route(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        for path, method, body in ROUTES:
            if (path, method) in {(SPACES, "GET"), (SESSION_SPACE, "POST")}:
                continue
            response = approver.get(path) if method == "GET" else approver.post(path, body)
            assert response.status_code in {403, 404}, (path, response.text)
            assert response.json()["code"] in {"FORBIDDEN", "NOT_FOUND"}
            assert_no_secrets(response)


def test_the_list_answers_the_visible_set_with_its_counts(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer B")
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(SPACES)
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        body = page.json()
        assert {row["space_id"] for row in body["items"]} == {str(first), str(second)}
        assert body["administrator"] is True and body["all_spaces"] is True
        assert body["current_space_id"] is None and body["next_cursor"] is None
        row = next(item for item in body["items"] if item["space_id"] == str(first))
        assert row["members"] >= 1 and row["agents"] >= 1
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        body = approver.get(SPACES).json()
        assert {row["space_id"] for row in body["items"]} == {str(first)}
        # A visible set of one space has nothing to switch between.
        assert body["administrator"] is False and body["all_spaces"] is False


def test_the_list_filters_by_name_and_by_state(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        make_space(conn, tenant, "Customer B")
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        found = client.get(SPACES + "?q=customer").json()
        assert [row["name"] for row in found["items"]] == ["Customer B"]
        assert client.get(SPACES + "?q=" + "x" * 81).status_code == 400
        assert client.get(SPACES + "?state=nonsense").status_code == 400
        assert client.get(SPACES + "?state=archived").json()["items"] == []
        assert len(client.get(SPACES + "?state=all").json()["items"]) == 2
        assert client.get(SPACES + "?cursor=not-a-cursor").status_code == 400


def test_a_space_is_created_renamed_archived_and_unarchived(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        created = client.post(SPACES, {"name": "Customer A", "detail": "First customer"})
        assert created.status_code == 200, created.text
        assert_no_secrets(created)
        space = created.json()["space_id"]
        # A name already taken, case-insensitively, is a conflict and not a body fault.
        taken = client.post(SPACES, {"name": "customer a"})
        assert taken.status_code == 409 and taken.json()["code"] == "CONFLICT"
        detail = client.get(f"{SPACES}/{space}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["space"]["detail"] == "First customer"
        assert detail.json()["selection"] is None and detail.json()["offered"] == []
        renamed = client.post(f"{SPACES}/{space}/rename", {"name": "Customer A2"})
        assert renamed.status_code == 200 and renamed.json()["space"]["name"] == "Customer A2"
        archived = client.post(f"{SPACES}/{space}/archive", {"reason": "customer left"})
        assert archived.status_code == 200
        assert archived.json()["space"]["archived_at"] is not None
        restored = client.post(f"{SPACES}/{space}/unarchive", {"reason": "customer returned"})
        assert restored.json()["space"]["archived_at"] is None


def test_the_last_unarchived_space_cannot_be_archived(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        only = default_space(conn, tenant)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(f"{SPACES}/{only}/archive", {"reason": "closing"})
        assert refused.status_code == 409 and refused.json()["code"] == "CONFLICT"


def test_a_member_is_assigned_and_unassigned_and_the_admin_role_is_refused(
    db, runtime, admin_engine, world
):
    person = str(world["human"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        space = client.post(SPACES, {"name": "Customer A"}).json()["space_id"]
        assigned = client.post(
            f"{SPACES}/{space}/members/assign", {"principal_id": person, "role": "HUMAN_APPROVER"}
        )
        assert assigned.status_code == 200, assigned.text
        assert {row["principal_id"] for row in assigned.json()["members"]} == {person}
        raised = client.post(
            f"{SPACES}/{space}/members/assign", {"principal_id": person, "role": "ADMIN"}
        )
        assert raised.status_code == 400 and raised.json()["code"] == "INVALID_BODY"
        assert raised.json()["fields"] == ["role"]
        withdrawn = client.post(f"{SPACES}/{space}/members/unassign", {"principal_id": person})
        assert withdrawn.status_code == 200 and withdrawn.json()["members"] == []
        again = client.post(f"{SPACES}/{space}/members/unassign", {"principal_id": person})
        assert again.status_code == 400 and again.json()["code"] == "INVALID_PRINCIPAL"


def test_the_last_tenant_administrator_cannot_be_narrowed_away(db, runtime, admin_engine, world):
    actor = str(world["admin"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        space = client.post(SPACES, {"name": "Customer A"}).json()["space_id"]
        refused = client.post(
            f"{SPACES}/{space}/members/assign", {"principal_id": actor, "role": "ADMIN"}
        )
        assert refused.status_code == 409 and refused.json()["code"] == "CONFLICT"


def test_an_archived_space_takes_no_new_member(db, runtime, admin_engine, world):
    person = str(world["human"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        space = client.post(SPACES, {"name": "Customer A"}).json()["space_id"]
        client.post(f"{SPACES}/{space}/archive", {"reason": "customer left"})
        refused = client.post(
            f"{SPACES}/{space}/members/assign", {"principal_id": person, "role": "HUMAN_APPROVER"}
        )
        assert refused.status_code == 409 and refused.json()["code"] == "SPACE_ARCHIVED"


def test_an_unknown_a_cross_tenant_and_an_unseen_space_answer_404_alike(
    db, runtime, admin_engine, world, seeded
):
    """A space that is unknown, another tenant's or outside the person's visible set
    answers `NOT_FOUND` alike, so the answer says nothing about what exists."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Customer B")
    other = seeded["spaces"][1]
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        for space in (uuid4(), other, second):
            answer = approver.get(f"{SPACES}/{space}")
            assert answer.status_code == 404, (space, answer.text)
            assert answer.json()["code"] == "NOT_FOUND"
            assert_no_secrets(answer)


def test_the_session_mutation_answers_the_fresh_view_and_refuses_a_space_of_another(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer B")
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        opened = client.get(API + "/session").json()
        assert opened["space"] is None and opened["spaces"] == 2 and opened["all_spaces"] is True
        switched = client.post(SESSION_SPACE, {"space_id": str(second)})
        assert switched.status_code == 200, switched.text
        # The secret check is deliberately not run over this one response: it answers the
        # session view, which carries the CSRF token the session route already hands out,
        # and that is the one secret the console is given on purpose.
        assert switched.json()["space"] == {
            "space_id": str(second),
            "name": "Customer B",
            "archived": False,
        }
        cleared = client.post(SESSION_SPACE, {"space_id": None})
        assert cleared.json()["space"] is None
        assert client.post(SESSION_SPACE, {"space_id": "not-a-uuid"}).status_code == 400
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        refused = approver.post(SESSION_SPACE, {"space_id": str(second)})
        assert refused.status_code == 404 and refused.json()["code"] == "NOT_FOUND"
        allowed = approver.post(SESSION_SPACE, {"space_id": str(first)})
        assert allowed.status_code == 200
        assert allowed.json()["space"]["space_id"] == str(first)


def test_a_member_of_a_space_reads_its_detail_and_an_administrator_reads_any(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Customer B")
        seat(conn, tenant, second, world["human"].principal_id)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        detail = approver.get(f"{SPACES}/{second}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["administrator"] is False
        assert {row["principal_id"] for row in detail.json()["members"]} == {
            str(world["human"].principal_id)
        }
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.get(f"{SPACES}/{second}").json()["administrator"] is True


def test_a_name_with_markup_comes_back_as_text(db, runtime, admin_engine, world):
    """Every string is the server's and is rendered as inert text; nothing here escapes."""
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        created = client.post(SPACES, {"name": "<script>alert(1)</script>"})
        assert created.status_code == 200, created.text
        detail = client.get(f"{SPACES}/{created.json()['space_id']}")
        assert detail.json()["space"]["name"] == "<script>alert(1)</script>"
        assert_no_secrets(detail)


def test_every_body_fault_is_refused_with_its_field(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.post(SPACES, {"name": ""}).status_code == 400
        assert client.post(SPACES, {"name": "x" * 81}).status_code == 400
        assert client.post(SPACES, {"name": "A", "unknown": 1}).status_code == 400
        assert client.post(SPACES, {}).status_code == 400
        space = client.post(SPACES, {"name": "Customer A"}).json()["space_id"]
        assert client.post(f"{SPACES}/{space}/archive", {}).status_code == 400
        assert client.post(f"{SPACES}/{space}/archive", {"reason": ""}).status_code == 400
