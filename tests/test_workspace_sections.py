# SPDX-License-Identifier: AGPL-3.0-only
"""A workspace switch lands on the same section of the other workspace, never a record.

The section is one of a closed set of console page roots, each opening for the sessions its
navigation entry opens for; a section the new session cannot open falls back to where that
session starts, so no answer sends a person to a page they cannot open. Through the second
factor the section rides the signed return cookie. The switch route writes nothing but a section
into it; a section root is also one of the console pages `GET /login?review=` may name (#678).
"""

import re
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from console_api_fixtures import API, ORIGIN, console_config
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import text
from starlette.responses import Response
from test_console_api_step_up import stale
from test_human_sessions import FixedClock
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_workspace_switching import member_pair

from execbound import mfa
from execbound.app import create_app
from execbound.envelope import KeyRing
from execbound.resolution.models import SystemClock
from execbound.surfaces import login_return, sections
from execbound.surfaces.human import landing
from execbound.surfaces.sections import RULES, SECTIONS, Rule, opens, place, start
from execbound.surfaces.sessions import load_session

pytestmark = pytest.mark.integration

NAVIGATION = Path(__file__).resolve().parents[1] / "console/src/shell/navigation.ts"
RING = KeyRing("test", {"test": b"m" * 32})
RECORD = "abcdef01-0000-4000-8000-000000000001"
APPROVAL = "/approvals/" + RECORD
ALL = {
    "approvals.decide",
    "policy.manage",
    "access.manage",
    "console.read",
    "workspace.manage",
}
SESSIONS = [
    ("ADMIN", frozenset(ALL)),
    ("ADMIN", frozenset(ALL - {"access.manage"})),
    ("HUMAN_APPROVER", frozenset({"approvals.decide", "console.read"})),
    ("HUMAN_APPROVER", frozenset({"console.read"})),
    ("HUMAN_APPROVER", frozenset()),
]


@pytest.mark.parametrize(("kind", "permissions"), SESSIONS)
def test_xw6_place_answers_the_section_exactly_when_its_rule_holds(kind, permissions):
    for section in sorted(SECTIONS):
        rule = RULES.get(section, Rule())
        holds = (not rule.admin or kind == "ADMIN") and (
            rule.permission is None or rule.permission in permissions
        )
        assert opens(kind, permissions, section) is holds
        answer = place(kind, permissions, section)
        assert answer == (section if holds else start(kind, permissions))
        assert answer in SECTIONS and opens(kind, permissions, answer)
    assert place(kind, permissions, None) == start(kind, permissions)
    for value in ("/ask", "/policy/" + str(uuid4()), "/activity?open=x", "//x", ""):
        assert not opens(kind, permissions, value)
        assert place(kind, permissions, value) == start(kind, permissions)


def test_xw6_a_viewer_starts_at_home_and_an_approver_on_approvals():
    assert start("HUMAN_APPROVER", {"approvals.decide"}) == "/approvals"
    assert start("HUMAN_APPROVER", set()) == "/"
    assert start("HUMAN_APPROVER", {"console.read"}) == "/"
    assert start("ADMIN", ALL) == "/"
    assert place("HUMAN_APPROVER", set(), "/approvals") == "/"


def test_xw6_place_refuses_to_answer_a_section_it_cannot_open(monkeypatch):
    monkeypatch.setitem(RULES, "/", Rule(permission="nobody.holds.this"))
    with pytest.raises(AssertionError):
        place("ADMIN", ALL, None)


def _entries(source: str, name: str) -> list[str]:
    body = source.split(f"export const {name}", 1)[1]
    body = body.split("= [", 1)[1].split("\n];", 1)[0]
    entries, depth, current = [], 0, ""
    for char in body:
        if char == "{":
            depth += 1
        if depth:
            current += char
        if char == "}":
            depth -= 1
            if depth == 0:
                entries.append(current)
                current = ""
    return entries


def test_xw6_sections_and_rules_mirror_the_console_navigation():
    """Each side changes with the other: a root, a role or a permission changed in one alone
    fails here."""
    source = NAVIGATION.read_text(encoding="utf-8")
    found: dict[str, Rule] = {}
    for entry in _entries(source, "NAVIGATION") + _entries(source, "FOOTER"):
        to = re.search(r'to: "(/[a-z]*)"', entry)
        roles = re.search(r"roles: (ADMIN|EVERYONE)\b", entry)
        permission = re.search(r'permission: "([a-z.]+)"', entry)
        assert to and roles, entry
        found[to.group(1)] = Rule(
            admin=roles.group(1) == "ADMIN",
            permission=permission.group(1) if permission else None,
        )
    found.pop("/ask")
    assert set(found) == SECTIONS
    for root, rule in found.items():
        assert RULES.get(root, Rule()) == rule, root


def _make(admin_engine, tenant, principal, role):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.access_role_grants SET role=:r "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "p": principal, "r": role},
        )
        if role == "administrator":
            conn.execute(
                text(
                    "UPDATE execbound.principals SET kind='ADMIN' "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": tenant, "p": principal},
            )


@contextmanager
def switching(db, runtime, admin_engine, seeded, role="viewer", **config):
    """A browser signed in to the first workspace, whose account is a `role` in the second."""
    grant, _, account, other = member_pair(db, admin_engine, seeded)
    if role != "viewer":
        _make(admin_engine, seeded["tenants"][1], other, role)
    with TestClient(
        create_app(db, runtime=runtime, human=console_config(**config)),
        base_url=ORIGIN,
        follow_redirects=False,
    ) as client:
        client.cookies.set("eb_session", grant.token, domain="127.0.0.1")
        client.cookies.set("eb_csrf", grant.csrf_token, domain="127.0.0.1")
        client.cookies.set("eb_account", grant.account_token, domain="127.0.0.1")
        first = client.get(API + "/session").json()
        headers = {
            "Origin": ORIGIN,
            "X-CSRF-Token": first["csrf_token"],
            "X-ExecBound-Workspace": first["generation"],
        }
        yield client, headers, grant, account


def _switch(client, headers, seeded, **body):
    return client.post(
        API + "/session/workspace",
        json={"tenant_id": str(seeded["tenants"][1]), **body},
        headers=headers,
    )


@pytest.mark.parametrize(
    ("role", "section", "expected"),
    [
        ("administrator", "/agents", "/agents"),
        ("administrator", "/people", "/people"),
        ("administrator", None, "/"),
        ("viewer", "/agents", "/"),
        ("viewer", "/approvals", "/"),
        ("viewer", "/activity", "/activity"),
        ("viewer", None, "/"),
        ("approver", "/agents", "/approvals"),
        ("approver", "/board", "/board"),
        ("approver", None, "/approvals"),
    ],
)
def test_xw6_a_switch_answers_the_section_its_session_may_open(
    db, runtime, admin_engine, seeded, role, section, expected
):
    runtime.clock = SystemClock()
    with switching(db, runtime, admin_engine, seeded, role) as (client, headers, _, _):
        body = {} if section is None else {"section": section}
        response = _switch(client, headers, seeded, **body)
        assert response.status_code == 200, response.text
        assert response.json() == {"location": expected}
        assert client.get(API + "/session").json()["tenant"]["tenant_id"] == str(
            seeded["tenants"][1]
        )


@pytest.mark.parametrize(
    "value",
    ["/ask", "/policy/" + RECORD, "/activity?open=x", "https://example.test/", "//x", ""],
)
def test_xw6_a_malformed_section_is_refused_and_nothing_switches(
    db, runtime, admin_engine, seeded, value
):
    runtime.clock = SystemClock()
    with switching(db, runtime, admin_engine, seeded) as (client, headers, _, _):
        response = _switch(client, headers, seeded, section=value)
        assert response.status_code == 400, response.text
        assert response.json()["code"] == "INVALID_BODY"
        assert response.json()["fields"] == ["section"]
        assert client.get(API + "/session").json()["tenant"]["tenant_id"] == str(
            seeded["tenants"][0]
        )


def test_xw6_an_extra_field_is_refused_and_nothing_switches(db, runtime, admin_engine, seeded):
    runtime.clock = SystemClock()
    with switching(db, runtime, admin_engine, seeded) as (client, headers, _, _):
        response = _switch(client, headers, seeded, section="/activity", next="/agents")
        assert response.status_code == 400, response.text
        assert response.json()["code"] == "INVALID_BODY"
        assert response.json()["fields"] == ["next"]
        assert client.get(API + "/session").json()["tenant"]["tenant_id"] == str(
            seeded["tenants"][0]
        )


def _return_cookies(response) -> list[str]:
    # A Starlette response's headers read with `getlist`, a test client's with `get_list`.
    headers = response.headers
    read = headers.getlist if isinstance(response, Response) else headers.get_list
    return [value for value in read("set-cookie") if value.startswith("eb_review_return=")]


@contextmanager
def through_the_factor(db, runtime, admin_engine, seeded):
    """A switch with `/activity` into a workspace that asks for the account's factor."""
    runtime.clock = SystemClock()
    with switching(db, runtime, admin_engine, seeded, mfa=RING) as (client, headers, grant, _):
        runtime.clock = FixedClock(SystemClock().now())
        session = load_session(db, grant.token, clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
        mfa.confirm_enrollment(
            db,
            session,
            RING,
            mfa.totp(seed, int(runtime.clock.now().timestamp() // 30)),
            clock=runtime.clock,
        )
        # Confirming rotates the session; read the new generation and token.
        current = client.get(API + "/session").json()
        headers = {
            **headers,
            "X-CSRF-Token": current["csrf_token"],
            "X-ExecBound-Workspace": current["generation"],
        }
        runtime.clock.value += timedelta(seconds=30)
        # A code entered within the step-up window is carried through the switch (#678); this
        # one is aged past it, so the destination asks again.
        stale(admin_engine, session.identity.tenant_id, session.session_id)
        response = _switch(client, headers, seeded, section="/activity")
        yield client, response, seed


def _verify(client, runtime, seed):
    from test_sign_in_surface import form_values

    page = client.get("/mfa")
    assert page.status_code == 200, page.text
    fields = form_values(page.text, "/account/security/verify")
    return client.post(
        "/account/security/verify",
        data={**fields, "code": mfa.totp(seed, int(runtime.clock.now().timestamp() // 30))},
        headers={"Origin": ORIGIN},
    )


def test_xw7_the_section_survives_the_second_factor(db, runtime, admin_engine, seeded):
    with through_the_factor(db, runtime, admin_engine, seeded) as (client, response, seed):
        assert response.status_code == 200, response.text
        assert response.json() == {"location": "/mfa"}
        cookies = _return_cookies(response)
        assert len(cookies) == 1
        assert cookies[0].split("=", 1)[1].split(";")[0].split(":")[2] == "/activity"
        completed = _verify(client, runtime, seed)
        assert completed.status_code == 303, completed.text
        assert completed.headers["location"] == "/activity"


@pytest.mark.parametrize("damage", ["tampered", "expired", "duplicated"])
def test_xw7_a_bad_return_cookie_lands_where_the_session_starts(
    db, runtime, admin_engine, seeded, damage
):
    with through_the_factor(db, runtime, admin_engine, seeded) as (client, response, seed):
        assert response.json() == {"location": "/mfa"}
        value = client.cookies.get("eb_review_return")
        assert value is not None
        if damage == "tampered":
            digit = value[-1]
            client.cookies.set(
                "eb_review_return",
                value[:-1] + ("0" if digit != "0" else "1"),
                domain="127.0.0.1",
            )
        elif damage == "expired":
            runtime.clock.value += timedelta(seconds=301)
        else:
            client.cookies.set(
                "eb_review_return", value, domain="127.0.0.1", path="/account/security"
            )
        completed = _verify(client, runtime, seed)
        if damage == "duplicated":
            # The request boundary refuses duplicate cookies before any page reads one.
            assert completed.status_code == 400
            assert "location" not in completed.headers
        else:
            assert completed.status_code == 303, completed.text
            assert completed.headers["location"] == landing("HUMAN_APPROVER")


def test_xw7_a_sign_in_link_may_name_a_section_like_any_console_page(db, runtime):
    """Since the hint's grammar became core's console pages (#678), a section root is one of
    them: `GET /login?review=` keeps it as it keeps an approval."""
    config = console_config()
    with TestClient(
        create_app(db, runtime=runtime, human=config), base_url=ORIGIN, follow_redirects=False
    ) as client:
        section = client.get("/login", params={"review": "/agents"})
        assert section.status_code == 200
        cookies = _return_cookies(section)
        assert len(cookies) == 1
        assert cookies[0].split("=", 1)[1].split(";")[0].split(":")[2] == "/agents"
        kept = client.get("/login", params={"review": APPROVAL})
        assert kept.status_code == 200
        assert len(_return_cookies(kept)) == 1


def test_xw7_only_the_section_writer_is_held_to_sections(runtime):
    config = console_config()
    written = login_return.remember_path(Response(), config, runtime, "/activity")
    assert len(_return_cookies(written)) == 1
    with pytest.raises(HTTPException):
        login_return.remember_path(Response(), config, runtime, "/activity/x")
    for value in ("/activity/x", "/approvals/" + str(uuid4()), "/ask"):
        with pytest.raises(HTTPException):
            login_return.remember_section(Response(), config, runtime, value)
    written = login_return.remember_section(Response(), config, runtime, "/activity")
    assert len(_return_cookies(written)) == 1
    assert login_return.login_location("/activity", runtime.plugins) == "/login?review=%2Factivity"
    assert login_return.login_location(APPROVAL, runtime.plugins) == (
        "/login?review=" + APPROVAL.replace("/", "%2F")
    )
    assert sections.SECTIONS == SECTIONS
