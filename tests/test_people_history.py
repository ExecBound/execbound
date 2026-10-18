# SPDX-License-Identifier: AGPL-3.0-only
"""The People page's history (PH1 to PH4): decisions, sign-ins and administrative events.

The page is the console's and reads `GET /api/console/v1/people/{id}`, whose `history` is the
same three bounded reads the Jinja page made between its two authority checks (#333).
"""

from datetime import timedelta
from uuid import uuid4

from sqlalchemy import text
from test_execution import finish
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import human_config as human_config
from test_people_pages import ORIGIN
from test_people_pages import admin_client as admin_client
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import request
from test_runtime import runtime as runtime

from execbound.execution import admit, decide_approval
from execbound.execution.modes import set_enforcement_mode
from execbound.replay.verify import reject_secrets
from execbound.surfaces import people_pages
from execbound.surfaces.sessions import issue_session


def api(admin_client, path, body):
    """One console API change, as the console makes it: JSON, the token, the exact origin."""
    token = admin_client.get("/api/console/v1/session").json()["csrf_token"]
    answer = admin_client.post(
        "/api/console/v1" + path,
        json=body,
        headers={"X-CSRF-Token": token, **ORIGIN},
    )
    assert answer.status_code == 200, (path, answer.status_code, answer.text[:200])
    return answer


def person(admin_client, principal_id):
    """One person as the console reads them."""
    answer = admin_client.get(f"/api/console/v1/people/{principal_id}")
    assert answer.status_code == 200, answer.text
    return answer


def rows(answer, kind):
    """One of the three history lists, newest first, as the console receives it."""
    return answer.json()["history"][kind]


def test_an_administrator_can_open_their_profile_after_managing_a_space(admin_client, world):
    space = api(admin_client, "/spaces", {"name": "Profile history regression"}).json()["space_id"]
    api(admin_client, f"/spaces/{space}/rename", {"name": "Renamed history space"})
    api(admin_client, f"/spaces/{space}/archive", {"reason": "Finished testing"})
    api(admin_client, f"/spaces/{space}/unarchive", {"reason": "Resume testing"})
    response = person(admin_client, world["admin"].principal_id)
    assert response.json()["is_self"] is True
    events = rows(response, "events")
    for words in ("Created space", "Renamed space", "Archived space", "Unarchived space"):
        assert any(event["words"] == words and event["subject"] == space[:8] for event in events)
    reject_secrets(response.json())


def decide_two(db, world):
    """One approval approved and consumed, then a second denied, both by the world's approver."""
    clock = world["clock"]
    first = admit(db, world["identity"], request(world), clock)
    decide_approval(db, world["human"], first.view.approval_id, "APPROVE", clock)
    finish(db, world, admit(db, world["identity"], request(world), clock))
    # The fixed clock stamps each decision; a second later makes "newest first" observable.
    clock.value += timedelta(seconds=1)
    second = admit(db, world["identity"], request(world, idempotency_key="second"), clock)
    assert second.view.state == "PENDING_APPROVAL"
    decide_approval(db, world["human"], second.view.approval_id, "DENY", clock)
    return first.view.approval_id, second.view.approval_id


def test_ph1_an_approver_page_shows_decisions_and_sign_ins_and_no_administration(
    admin_client, db, world, admin_engine
):
    approved, denied = decide_two(db, world)
    issue_session(db, world["human"], clock=world["clock"], label="Firefox on Linux")
    # History does not change with the scope: the decisions stay after it is unassigned.
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.approval_scopes SET active = false WHERE approver_id = :p"),
            {"p": world["human"].principal_id},
        )
    page = person(admin_client, world["human"].principal_id)
    decisions = rows(page, "decisions")
    assert len(decisions) == 2
    # Newest first: the denial, then the approval, each with its prefix and action.
    assert decisions[0]["approval"] == str(denied)[:8] and decisions[0]["decision"] == "denied"
    assert decisions[1]["approval"] == str(approved)[:8]
    assert decisions[1]["decision"] == "approved"
    assert all(row["action"] == "endpoint.isolate" for row in decisions)
    # The prefix for reading, and the full identifiers beside it for the links the page
    # builds (#678): the approval, and its execution where the reader may open the record.
    assert decisions[0]["approval_id"] == str(denied)
    assert decisions[0]["execution_id"] is not None
    sign_ins = rows(page, "sign_ins")
    assert len(sign_ins) == 1 and sign_ins[0]["device"] == "Firefox on Linux"
    assert sign_ins[0]["state"] == "active"
    # An approver has no administrative events at all.
    assert rows(page, "events") == []
    reject_secrets(page.json())


def test_ph2_an_administrator_page_shows_events_in_words_and_no_decisions(
    admin_client, db, world, admin_engine
):
    approver = world["human"].principal_id
    # The administrator labels the approver, ends their session and changes the mode.
    issue_session(db, world["human"], clock=world["clock"], label="Safari on iPhone")
    assert api(admin_client, f"/people/{approver}/label", {"label": "Night shift approver"})
    assert api(admin_client, f"/people/{approver}/sessions/end", {})
    set_enforcement_mode(db, world["admin"], "OBSERVE", "a quiet week", world["clock"])
    # Signing out one's own other devices is personal and is not administration.
    issue_session(db, world["admin"], clock=world["clock"])
    assert api(admin_client, "/settings/sessions/revoke-others", {})

    page = person(admin_client, world["admin"].principal_id)
    # An administrator's history is events and sign-ins; they decide nothing.
    assert rows(page, "decisions") == []
    events = rows(page, "events")
    joined = "\n".join(f"{row['words']} {row['label'] or ''} {row['subject']}" for row in events)
    assert events[0]["words"] == "Changed the enforcement mode to OBSERVE"
    assert "Ended a session of" in joined and "Night shift approver" in joined
    assert "Labelled" in joined and str(approver)[:8] in joined
    # The world's bundle was created, validated and activated by this administrator.
    assert "Activated policy bundle" in joined
    # A reason is never read into the history.
    assert "a quiet week" not in page.text
    # One session ended for the approver, and none of the administrator's own devices.
    assert sum("Ended a session of" in row["words"] for row in events) == 1
    sign_ins = rows(page, "sign_ins")
    assert sign_ins and any(row["state"] == "signed out" for row in sign_ins)
    reject_secrets(page.json())


def test_ph3_each_table_stops_at_twenty_newest_first_and_says_when_it_is_empty(
    admin_client, db, world, admin_engine
):
    empty = person(admin_client, world["human"].principal_id)
    assert rows(empty, "decisions") == [] and rows(empty, "sign_ins") == []
    assert empty.json()["history_limit"] == people_pages.HISTORY_LIMIT
    grants = []
    for _ in range(people_pages.HISTORY_LIMIT + 5):
        grants.append(issue_session(db, world["human"], clock=world["clock"]))
        # A credential holds only a few live sessions; each one ends before the next.
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.human_sessions SET revoked_at = now() WHERE session_id = :s"
                ),
                {"s": grants[-1].session_id},
            )
    listed = rows(person(admin_client, world["human"].principal_id), "sign_ins")
    assert len(listed) == people_pages.HISTORY_LIMIT
    # Newest first, by the chain's order: the last session issued leads, the first five are
    # past the limit.
    sessions = [row["session"] for row in listed]
    assert sessions[0] == str(grants[-1].session_id)[:8]
    assert sessions[-1] == str(grants[5].session_id)[:8]
    assert not any(str(grant.session_id)[:8] in sessions for grant in grants[:5])


def test_ph4_a_label_with_markup_is_text_and_a_reason_never_appears(
    admin_client, db, world, admin_engine
):
    approver = world["human"].principal_id
    hostile = '<img src=x onerror="alert(1)">'
    assert api(admin_client, f"/people/{approver}/label", {"label": hostile})
    marker = "<b>marker-" + uuid4().hex + "</b>"
    assert api(admin_client, f"/people/{approver}/deactivate", {"reason": marker})
    answer = person(admin_client, world["admin"].principal_id)
    events = answer.json()["history"]["events"]
    assert any(row["words"].startswith("Deactivated") for row in events)
    # The label travels as data, in a JSON string the console renders as text, and the
    # reason is never read into the history at all.
    assert any(row["label"] == hostile for row in events)
    assert answer.headers["content-type"].startswith("application/json")
    page = answer.text
    assert "marker-" not in page
    # The map and the statement agree, and nothing but these kinds is ever read.
    assert set(people_pages.ADMINISTRATIVE) >= {
        "policy.bundle_activated",
        "credential.issued",
        "approval_scope.assigned",
        "principal.deactivated",
        "agent.bound",
        "human_session.revoked",
        "tenant.stop_activated",
    }
    assert "execution.rejected" not in people_pages.ADMINISTRATIVE
    reject_secrets(page)
