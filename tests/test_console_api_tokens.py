# SPDX-License-Identifier: AGPL-3.0-only
"""A personal access token on the console API (acceptance PT2, PT3, PT7, PT8, PT10, PT13): it
calls an allowed route as its owner, is refused the exceptions `docs/CREDENTIALS.md` names with
a typed and audited code, never replaces a session cookie, has its own rate limit, is refused
where the workspace requires directory sign-in, and is never handed a continuation."""

import json
import re
import secrets
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from console_api_fixtures import API, ORIGIN, console_client, console_config, rejections
from fastapi.testclient import TestClient
from sample_fixtures import empty_workspace, offline_runtime
from sample_fixtures import sample_key as sample_key
from space_fixtures import default_space, make_space
from sqlalchemy import text
from test_agents_bindings import found as found
from test_assistant_loop import answer as scripted_answer
from test_console_api_rules import ALLOW, DENY, ruleset_draft
from test_execution import provision_identity, targets
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential, pending
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_route_authority import served as served_routes
from test_runtime import runtime as runtime

from execbound.app import create_app
from execbound.assistant.client import ScriptedTransport, scripted_message, text_message
from execbound.assistant.config import AssistantConfig
from execbound.execution import admit
from execbound.execution.modes import set_enforcement_mode
from execbound.personal_tokens import issue_token
from execbound.surfaces.console_api.token_rules import TOKEN_ALLOWED, TOKEN_REFUSED
from execbound.surfaces.sessions import issue_session, load_session


def minted(runtime, world) -> str:
    return minted_for(runtime, world["admin"])


def minted_for(runtime, administrator, name: str = "ci") -> str:
    grant = issue_session(runtime.db, administrator, clock=runtime.clock)
    session = load_session(runtime.db, grant.token, clock=runtime.clock)
    token, _ = issue_token(runtime.db, session, name, timedelta(days=1), clock=runtime.clock)
    return token


@contextmanager
def bearer(console, token: str):
    """A client with no cookies, on the same application as the signed-in console.

    Not entered as a context: the console's own client already runs the application's
    lifespan, and the MCP session manager inside it runs once per application."""
    yield TestClient(console.client.app, base_url=ORIGIN, follow_redirects=False)


@contextmanager
def application(db, runtime):
    """The application with nobody signed in, for a test that needs no browser session."""
    app = create_app(db, runtime=runtime, human=console_config())
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        yield client


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def post(client: TestClient, path: str, token: str, body=None):
    return client.post(
        path,
        json=body if body is not None else {},
        headers={**auth(token), "Content-Type": "application/json"},
    )


def refused_as_token(admin_engine, identity) -> int:
    """How many `execution.rejected` events carry the reason `TOKEN_NOT_ALLOWED`."""
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND actor_id=:p AND kind='execution.rejected' "
                    "AND payload->>'reason'='TOKEN_NOT_ALLOWED'"
                ),
                {"t": identity.tenant_id, "p": identity.principal_id},
            ).scalar_one()
        )


def token_failures(admin_engine) -> dict[tuple, int]:
    """Every `token`-surface failure counter, keyed by its reason and attribution."""
    with admin_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT reason, tenant_id, subject_kind, subject_id, sum(count) AS n "
                "FROM execbound.authentication_failures WHERE surface='token' "
                "GROUP BY reason, tenant_id, subject_kind, subject_id"
            )
        ).all()
    return {(row[0], row[1], row[2], row[3]): int(row[4]) for row in rows}


def rejected(admin_engine, identity, reason: str) -> list[dict]:
    """The payloads of one principal's `execution.rejected` events with one reason."""
    with admin_engine.connect() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND actor_id=:p AND kind='execution.rejected' "
                    "AND payload->>'reason'=:r ORDER BY sequence"
                ),
                {"t": identity.tenant_id, "p": identity.principal_id, "r": reason},
            ).scalars()
        )


def human_malformed(admin_engine) -> int:
    """Unattributed malformed credentials counted on the pages' `human` surface."""
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT COALESCE(sum(count), 0) FROM execbound.authentication_failures "
                    "WHERE surface='human' AND reason='MALFORMED' AND tenant_id IS NULL"
                )
            ).scalar_one()
        )


def backing_credential(admin_engine, token: str):
    token_id = token.split(".")[2]
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT credential_id FROM execbound.personal_access_tokens WHERE token_id=:k"),
            {"k": token_id},
        ).scalar_one()


def test_a_token_reads_and_writes_as_its_owner(db, runtime, admin_engine, world):
    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            agents = client.get(API + "/agents", headers=auth(token))
            assert agents.status_code == 200, agents.text
            # No workspace generation for a token: it belongs to one workspace.
            assert "x-execbound-workspace" not in agents.headers
            created = post(client, API + "/agents", token, {"label": "Review bot"})
            assert created.status_code in (200, 201), created.text
    with admin_engine.connect() as conn:
        actor = conn.execute(
            text(
                "SELECT actor_id FROM execbound.audit_events WHERE kind='principal.created' "
                "AND payload->>'principal_id'=:p"
            ),
            {"p": created.json()["principal_id"]},
        ).scalar_one()
    assert actor == world["admin"].principal_id


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (
            "/approvals/00000000-0000-4000-8000-000000000000/decision",
            {"decision": "APPROVE", "continuation": "x"},
        ),
        (
            "/policy/00000000-0000-4000-8000-000000000000/activate",
            {"confirm": True, "reason": "x"},
        ),
        ("/tenant/resume", {"reason": "x"}),
        ("/people", {"label": "Someone"}),
        ("/settings/password", {"current": "c" * 12, "new": "n" * 12}),
    ],
)
def test_the_exceptions_answer_token_not_allowed_and_are_audited(
    db, runtime, admin_engine, world, path, body
):
    token = minted(runtime, world)
    before = rejections(admin_engine, world["admin"])
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            refused = post(client, API + path, token, body)
    assert refused.status_code == 403, refused.text
    assert refused.json()["code"] == "TOKEN_NOT_ALLOWED"
    assert rejections(admin_engine, world["admin"]) == before + 1


def test_every_refused_route_answers_token_not_allowed_through_the_application(
    db, runtime, admin_engine, world
):
    """PT3 over the whole table, and the rule reads the full route template the table uses:
    every served refused route, with its path parameters filled in, is refused and audited.

    Core's own application serves core's routes; the refused routes a plugin adds are walked
    the same way, with that plugin loaded, by that plugin's own console API tests (#496)."""
    token = minted(runtime, world)
    before = refused_as_token(admin_engine, world["admin"])
    with application(db, runtime) as client:
        served = sorted(TOKEN_REFUSED & served_routes(client.app))
        assert served
        for template, method in served:
            path = re.sub(r"\{[^}]+\}", "00000000-0000-4000-8000-000000000000", template)
            answer = (
                client.get(path, headers=auth(token))
                if method == "GET"
                else post(client, path, token, {})
            )
            assert answer.status_code == 403, (template, method, answer.text)
            assert answer.json()["code"] == "TOKEN_NOT_ALLOWED", (template, method)
    assert refused_as_token(admin_engine, world["admin"]) == before + len(served)


def test_an_allowed_route_with_path_parameters_passes_the_rule(db, runtime, admin_engine, world):
    """The template `/api/console/v1/agents/{row_id}` is what the rule looks up, not the path."""
    token = minted(runtime, world)
    agent = world["identity"].principal_id
    before = refused_as_token(admin_engine, world["admin"])
    with application(db, runtime) as client:
        read = client.get(API + f"/agents/{agent}", headers=auth(token))
        reactivate = post(client, API + f"/agents/{agent}/reactivate", token, {"reason": "x"})
    assert read.status_code == 200, read.text
    assert reactivate.status_code == 403 and reactivate.json()["code"] == "TOKEN_NOT_ALLOWED"
    assert refused_as_token(admin_engine, world["admin"]) == before + 1


def test_a_token_may_switch_to_enforcing_and_not_to_observe_only(db, runtime, admin_engine, world):
    token = minted(runtime, world)
    before = refused_as_token(admin_engine, world["admin"])
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            observe = post(client, API + "/tenant/mode", token, {"mode": "OBSERVE", "reason": "x"})
            still = client.get(API + "/tenant", headers=auth(token))
            set_enforcement_mode(runtime.db, world["admin"], "OBSERVE", "setup", runtime.clock)
            enforce = post(client, API + "/tenant/mode", token, {"mode": "ENFORCE", "reason": "x"})
    assert observe.status_code == 403 and observe.json()["code"] == "TOKEN_NOT_ALLOWED"
    assert still.json()["mode"]["value"] == "ENFORCE"
    assert enforce.status_code == 200, enforce.text
    assert enforce.json()["mode"]["value"] == "ENFORCE"
    assert refused_as_token(admin_engine, world["admin"]) == before + 1


def test_a_token_issues_a_key_only_for_an_agent(db, runtime, admin_engine, world):
    token = minted(runtime, world)
    before = refused_as_token(admin_engine, world["admin"])
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            person = post(
                client,
                API + "/credentials/issue",
                token,
                {"principal": "new:HUMAN_APPROVER", "lifetime": "8"},
            )
            approver = post(
                client,
                API + "/credentials/issue",
                token,
                {"principal": str(world["human"].principal_id), "lifetime": "8"},
            )
            agent = post(
                client,
                API + "/credentials/issue",
                token,
                {"principal": "new:AGENT", "label": "Coding agent", "lifetime": "8"},
            )
            existing = post(
                client,
                API + "/credentials/issue",
                token,
                {"principal": str(world["identity"].principal_id), "lifetime": "8"},
            )
    assert person.status_code == 403 and person.json()["code"] == "TOKEN_NOT_ALLOWED"
    assert approver.status_code == 403 and approver.json()["code"] == "TOKEN_NOT_ALLOWED"
    assert agent.status_code == 200, agent.text
    assert existing.status_code == 200, existing.text
    assert refused_as_token(admin_engine, world["admin"]) == before + 2


def test_an_eb1_credential_is_still_refused_as_a_bearer(db, runtime, admin_engine, world, seeded):
    """PT7: an agent key and an administrator's own `eb1` credential, both refused and audited
    exactly as before tokens existed."""
    agent_before = rejections(admin_engine, world["identity"])
    admin_before = rejections(admin_engine, world["admin"])
    administrator = credential(admin_engine, world["admin"])
    with application(db, runtime) as client:
        agent = client.get(API + "/agents", headers=auth(seeded["tokens"][0]))
        admin = client.get(API + "/agents", headers=auth(administrator))
    assert agent.status_code == 403 and admin.status_code == 403
    assert rejections(admin_engine, world["identity"]) == agent_before + 1
    assert rejections(admin_engine, world["admin"]) == admin_before + 1


def test_a_token_refusal_names_the_backing_credential_and_no_other_refusal_does(
    db, runtime, admin_engine, world, seeded
):
    """Every event a token causes is attributed through its backing credential, which is the
    token one to one; the refusals of the route rule and both body rules carry it."""
    token = minted(runtime, world)
    backing = str(backing_credential(admin_engine, token))
    with application(db, runtime) as client:
        post(client, API + "/tenant/resume", token, {"reason": "x"})
        post(client, API + "/tenant/mode", token, {"mode": "OBSERVE", "reason": "x"})
        post(client, API + "/credentials/issue", token, {"principal": "new:HUMAN_APPROVER"})
        post(
            client,
            API + "/credentials/issue",
            token,
            {"principal": "new:HUMAN_APPROVER", "lifetime": "8"},
        )
        client.get(API + "/agents", headers=auth(seeded["tokens"][0]))
    refusals = rejected(admin_engine, world["admin"], "TOKEN_NOT_ALLOWED")
    # The resume route, observe-only and the approver's key; the body without a lifetime is
    # refused by the model first, as any caller's is. Each names the route template and the
    # method it refused, so a review of the chain can say what the token was denied.
    refused = {
        "operation": "surface",
        "reason": "TOKEN_NOT_ALLOWED",
        "actor_credential_id": backing,
    }
    assert refusals == [
        {**refused, "route": API + "/tenant/resume", "method": "POST"},
        {**refused, "route": API + "/tenant/mode", "method": "POST"},
        {**refused, "route": API + "/credentials/issue", "method": "POST"},
    ]
    # An agent key's refusal is unchanged.
    assert rejected(admin_engine, world["identity"], "INVALID_IDENTITY")[-1] == {
        "operation": "surface",
        "reason": "INVALID_IDENTITY",
    }


def test_an_event_a_token_caused_maps_to_its_name_through_the_list_and_after_deletion(
    db, runtime, admin_engine, world
):
    """The event names the backing credential, and the token list maps it to the token's name.
    Once the token is revoked and deleted it leaves every list, and its `personal_token.issued`
    event, which names both, still maps it."""
    tenant = world["admin"].tenant_id
    token = minted_for(runtime, world["admin"], "deploy bot")
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            created = post(client, API + "/spaces", token, {"name": "Customer B"})
            assert created.status_code == 200, created.text
        with admin_engine.connect() as conn:
            acted = conn.execute(
                text(
                    "SELECT payload->>'actor_credential_id' FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND kind='space.created' "
                    "AND payload->>'space_id'=:s"
                ),
                {"t": tenant, "s": created.json()["space_id"]},
            ).scalar_one()
        for path in ("/settings/tokens", "/tenant/tokens"):
            rows = console.get(API + path).json()["tokens"]
            assert [row["name"] for row in rows if row["credential_id"] == acted] == [
                "deploy bot"
            ], path
        [row] = console.get(API + "/settings/tokens").json()["tokens"]
        token_id = row["token_id"]
        assert console.post(API + f"/settings/tokens/{token_id}/revoke", {}).status_code == 200
        assert console.post(API + f"/settings/tokens/{token_id}/delete", {}).status_code == 200
        for path in ("/settings/tokens", "/tenant/tokens"):
            assert console.get(API + path).json()["tokens"] == [], path
    with admin_engine.connect() as conn:
        names = conn.execute(
            text(
                "SELECT payload->>'name' FROM execbound.audit_events "
                "WHERE tenant_id=:t AND kind='personal_token.issued' "
                "AND payload->>'credential_id'=:c"
            ),
            {"t": tenant, "c": acted},
        ).scalars()
        assert list(names) == ["deploy bot"]


def test_a_database_failure_checking_a_named_space_answers_a_typed_unavailable(
    db, runtime, admin_engine, world, monkeypatch
):
    """The guard's own space check reads the database; a failure there answers the console
    API's typed 503, as every other dependency failure a route meets does."""
    from sqlalchemy.exc import OperationalError

    from execbound.surfaces.console_api import guards

    def down(conn, session):
        raise OperationalError("SELECT 1", {}, Exception("connection lost"))

    token = minted(runtime, world)
    with admin_engine.connect() as conn:
        space = default_space(conn, world["admin"].tenant_id)
    monkeypatch.setattr(guards, "visible_spaces", down)
    with application(db, runtime) as client:
        answer = client.get(
            API + "/agents", headers={**auth(token), "X-ExecBound-Space": str(space)}
        )
    assert answer.status_code == 503, answer.text
    assert answer.json()["code"] == "UNAVAILABLE"


def test_a_token_names_its_space_in_a_workspace_with_two(db, runtime, admin_engine, world, seeded):
    tenant = world["admin"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Customer B")
    with admin_engine.begin() as conn:
        foreign = default_space(conn, seeded["tenants"][1])
    token = minted(runtime, world)

    def in_space(space) -> dict[str, str]:
        return {**auth(token), "Content-Type": "application/json", "X-ExecBound-Space": space}

    with application(db, runtime) as client:
        unnamed = post(client, API + "/agents", token, {"label": "Nowhere"})
        named = client.post(API + "/agents", json={"label": "In B"}, headers=in_space(str(second)))
        listed = client.get(API + "/agents", headers=in_space(str(second)))
        everywhere = client.get(API + "/agents", headers=auth(token))
        refused = {
            "another tenant's": client.post(
                API + "/agents", json={"label": "x"}, headers=in_space(str(foreign))
            ),
            "random": client.post(
                API + "/agents", json={"label": "x"}, headers=in_space(str(uuid4()))
            ),
            "another tenant's, read": client.get(API + "/agents", headers=in_space(str(foreign))),
        }
        malformed = {
            "not a uuid": client.get(API + "/agents", headers=in_space("not-a-uuid")),
            "upper case": client.get(API + "/agents", headers=in_space(str(second).upper())),
            "twice": client.get(
                API + "/agents",
                headers=[
                    ("Authorization", f"Bearer {token}"),
                    ("X-ExecBound-Space", str(second)),
                    ("X-ExecBound-Space", str(second)),
                ],
            ),
        }
    assert unnamed.status_code == 422 and unnamed.json()["code"] == "SPACE_REQUIRED"
    assert named.status_code == 200, named.text
    agent = named.json()["principal_id"]
    with admin_engine.connect() as conn:
        owner = conn.execute(
            text("SELECT space_id FROM execbound.principals WHERE principal_id=:p"), {"p": agent}
        ).scalar_one()
    assert owner == second
    assert listed.status_code == 200, listed.text
    assert [row["principal_id"] for row in listed.json()["agents"] if row["principal_id"]] == [
        agent
    ]
    governed = {row["principal_id"] for row in everywhere.json()["agents"]}
    assert {agent, str(world["identity"].principal_id)} <= governed
    for name, answer in refused.items():
        assert answer.status_code == 422, (name, answer.text)
        assert answer.json()["code"] == "SPACE_REQUIRED", name
    for name, answer in malformed.items():
        assert answer.status_code == 400, (name, answer.text)
    with admin_engine.connect() as conn:
        agents = conn.execute(
            text("SELECT count(*) FROM execbound.principals WHERE tenant_id=:t AND label='x'"),
            {"t": tenant},
        ).scalar_one()
    assert agents == 0


def test_a_cookie_request_ignores_the_space_header(db, runtime, admin_engine, world):
    tenant = world["admin"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Customer B")
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        plain = console.get(API + "/agents")
        named = console.get(API + "/agents", headers={"X-ExecBound-Space": str(second)})
        garbled = console.get(API + "/agents", headers={"X-ExecBound-Space": "not-a-uuid"})
    assert plain.status_code == named.status_code == garbled.status_code == 200
    assert plain.json() == named.json() == garbled.json()


def test_the_bearer_scheme_edge_cases_land_where_intended(db, runtime, admin_engine, world):
    """The scheme is case-insensitive (RFC 9110, section 11.1), so `bearer` takes the token
    path. Two Authorization headers never reach a route: the application refuses them as an
    ambiguous identity. A double space or a tab is not the token path, and meets the pages'
    refusal of a bearer credential instead, which never looks a token up."""
    token = minted(runtime, world)
    before_token = token_failures(admin_engine)
    before_human = human_malformed(admin_engine)
    with application(db, runtime) as client:
        lower = client.get(API + "/agents", headers={"Authorization": f"bearer {token}"})
        twice = client.get(
            API + "/agents",
            headers=[("Authorization", f"Bearer {token}"), ("Authorization", f"Bearer {token}")],
        )
        spaced = client.get(API + "/agents", headers={"Authorization": f"Bearer  {token}"})
        tabbed = client.get(API + "/agents", headers={"Authorization": f"Bearer\t{token}"})
    assert lower.status_code == 200, lower.text
    assert twice.status_code == 400
    assert twice.json() == {"detail": "Unsupported or ambiguous identity fields"}
    for answer in (spaced, tabbed):
        assert answer.status_code == 401, answer.text
        assert answer.json()["code"] == "SESSION_REQUIRED"
        assert answer.headers["www-authenticate"] == "Bearer"
    assert token_failures(admin_engine) == before_token
    # The double space and the tab are malformed credentials on the pages' surface.
    assert human_malformed(admin_engine) == before_human + 2


def test_a_cookie_and_a_token_together_are_refused(db, runtime, admin_engine, world):
    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        both = console.client.get(API + "/agents", headers=auth(token))
    assert both.status_code == 400


def test_a_token_still_meets_the_boundary_and_body_rules(db, runtime, admin_engine, world):
    """Only CSRF, Origin, the workspace generation and the step-up are left out for a token."""
    token = minted(runtime, world)
    with application(db, runtime) as client:
        query = client.get(API + "/agents?unexpected=1", headers=auth(token))
        host = client.get(API + "/agents", headers={**auth(token), "Host": "evil.example"})
        media = client.post(
            API + "/agents",
            content=b'{"label": "x"}',
            headers={**auth(token), "Content-Type": "text/plain"},
        )
        unknown = post(client, API + "/agents", token, {"label": "x", "space_id": None})
        large = post(client, API + "/agents", token, {"label": "x" * 70000})
    assert query.status_code == 400
    assert host.status_code == 400
    assert media.status_code == 415 and media.json()["code"] == "UNSUPPORTED_MEDIA_TYPE"
    assert unknown.status_code == 400 and unknown.json()["code"] == "INVALID_BODY"
    assert large.status_code == 413 and large.json()["code"] == "TOO_LARGE"


def test_a_token_has_its_own_rate_limit(db, runtime, admin_engine, world, monkeypatch):
    from execbound.surfaces.limits import RequestLimiter, RequestLimits

    token = minted(runtime, world)
    monkeypatch.setattr(
        runtime, "limiter", RequestLimiter(RequestLimits(token_requests=2), runtime.clock)
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            answers = [client.get(API + "/agents", headers=auth(token)) for _ in range(3)]
    assert [a.status_code for a in answers[:2]] == [200, 200]
    assert answers[2].status_code == 429 and "retry-after" in answers[2].headers


def test_a_wrong_secret_is_refused_and_counted_on_the_token_surface(
    db, runtime, admin_engine, world
):
    token = minted(runtime, world)
    wrong = token.rsplit(".", 1)[0] + "." + secrets.token_urlsafe(32)
    tenant = world["admin"].tenant_id
    key = ("MISMATCH", tenant, "credential", backing_credential(admin_engine, token))
    before = token_failures(admin_engine)
    with application(db, runtime) as client:
        refused = client.get(API + "/agents", headers=auth(wrong))
    assert refused.status_code == 401 and refused.json()["code"] == "SESSION_REQUIRED"
    # As the agent API answers a refused key.
    assert refused.headers["www-authenticate"] == "Bearer"
    after = token_failures(admin_engine)
    assert after.get(key, 0) == before.get(key, 0) + 1
    assert sum(after.values()) == sum(before.values()) + 1


def test_an_unknown_or_malformed_token_is_counted_without_attribution(
    db, runtime, admin_engine, world
):
    """As for an `eb1` credential: a token nobody holds names no tenant or subject, so a guessed
    id cannot add a row per guess to a workspace's counters."""
    tenant = world["admin"].tenant_id
    unknown = f"ebp1.{tenant}.{uuid4()}.{secrets.token_urlsafe(32)}"
    token = minted(runtime, world)
    wrong = token.rsplit(".", 1)[0] + "." + secrets.token_urlsafe(32)
    before = token_failures(admin_engine)
    with application(db, runtime) as client:
        guessed = client.get(API + "/agents", headers=auth(unknown))
        garbled = client.get(API + "/agents", headers=auth("ebp1.not-a-token"))
        mismatched = client.get(API + "/agents", headers=auth(wrong))
    # One answer whatever the class, so a refusal says nothing about whether a token exists.
    for answer in (guessed, garbled):
        assert answer.status_code == mismatched.status_code == 401
        assert answer.json() == mismatched.json()
        assert answer.headers["www-authenticate"] == mismatched.headers["www-authenticate"]
    after = token_failures(admin_engine)
    for reason in ("UNKNOWN", "MALFORMED"):
        key = (reason, None, None, None)
        assert after.get(key, 0) == before.get(key, 0) + 1
    assert sum(after.values()) == sum(before.values()) + 3


def test_directory_sign_in_refuses_a_token_as_it_refuses_a_session(
    db, runtime, admin_engine, world
):
    """PT13: a workspace that requires directory sign-in answers a token exactly as it answers
    a browser session signed in with a credential, and counts neither as a failed sign-in."""
    from test_directory_store import RING, FixedClock, registered

    from execbound.directory import DirectoryConfig

    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        provider = registered(
            runtime.db,
            DirectoryConfig(RING, "https://app.example"),
            {"tenant": world["admin"].tenant_id, "admin": world["admin"].principal_id},
            FixedClock(),
        )
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.identity_providers SET require_sign_in=true "
                    "WHERE tenant_id=:t AND provider_id=:p"
                ),
                {"t": world["admin"].tenant_id, "p": provider},
            )
        before = token_failures(admin_engine)
        session = console.get(API + "/agents")
        with bearer(console, token) as client:
            refused = client.get(API + "/agents", headers=auth(token))
    assert session.status_code == 403 and session.json()["code"] == "DIRECTORY_REQUIRED"
    assert refused.status_code == session.status_code
    assert refused.json() == session.json()
    assert token_failures(admin_engine) == before


def test_a_token_is_never_offered_an_approval_continuation(db, runtime, admin_engine, world):
    """The second barrier behind the route rule: a continuation is bound to the session's id
    and CSRF token, which for a token are its own id and nothing, so none is ever minted. The
    continuation is also what says the viewer may decide: the console offers the decision only
    for a pending approval whose continuation is not null (`DetailView.tsx`, `canDecide`)."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes "
                "(tenant_id,approver_id,canonical_target_id,action,space_id) "
                "VALUES (:t,:p,:c,'endpoint.isolate', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id=:t))"
            ),
            {
                "t": world["admin"].tenant_id,
                "p": world["admin"].principal_id,
                "c": world["canonical"],
            },
        )
    view = pending(runtime, world)
    token = minted(runtime, world)
    path = API + f"/approvals/{view.approval_id}"
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        browser = console.get(path)
        with bearer(console, token) as client:
            read = client.get(path, headers=auth(token))
    assert browser.status_code == 200, browser.text
    assert browser.json()["status"] == "pending" and browser.json()["continuation"]
    assert read.status_code == 200, read.text
    assert read.json()["status"] == "pending"
    assert read.json()["continuation"] is None


def test_a_token_is_never_offered_a_reconcile(
    db, runtime, admin_engine, world, live_provider, connector
):
    """Neither the settlement nor its continuation: a token is refused reconcile by route, so
    neither the detail nor the list offers it one."""
    [development] = targets(admin_engine, world, count=1)
    admission = admit(db, world["identity"], development, world["clock"])
    assert admission.view.state == "DISPATCH_COMMITTED"
    token = minted(runtime, world)
    path = API + f"/executions/{admission.view.execution_id}"
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        browser = console.get(path)
        with bearer(console, token) as client:
            read = client.get(path, headers=auth(token))
            listed = client.get(API + "/executions", headers=auth(token))
    assert browser.status_code == 200, browser.text
    assert browser.json()["reconcile"]["available"] is True
    assert browser.json()["reconcile"]["continuation"]
    assert read.status_code == 200, read.text
    assert read.json()["reconcile"] == {"available": False, "kind": None, "continuation": None}
    [item] = [
        row
        for row in listed.json()["items"]
        if row["execution_id"] == str(admission.view.execution_id)
    ]
    assert item["reconcile"] == {"available": False, "kind": None, "continuation": None}


# --- The token routes, the owner lifecycle and the credential lists -------------------------


def test_an_administrator_creates_lists_revokes_and_deletes_own_tokens(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        issued = console.post(API + "/settings/tokens/issue", {"name": "ci", "lifetime": "720"})
        assert issued.status_code == 200, issued.text
        assert issued.headers["cache-control"] == "no-store"
        body = issued.json()
        assert body["token"].startswith("ebp1.")
        token_id = body["row"]["token_id"]
        # The row is built from the store's own view plus the session, not a re-read of the
        # list after commit, so the owner is right even before the read below runs.
        assert body["row"]["owner_id"] == str(world["admin"].principal_id)
        assert body["row"]["state"] == "live" and body["row"]["last_used_at"] is None
        listed = console.get(API + "/settings/tokens").json()["tokens"]
        assert [row["token_id"] for row in listed] == [token_id]
        assert "token" not in listed[0]
        assert console.post(API + f"/settings/tokens/{token_id}/revoke", {}).status_code == 200
        assert console.post(API + f"/settings/tokens/{token_id}/delete", {}).status_code == 200
        assert console.get(API + "/settings/tokens").json()["tokens"] == []


def test_a_person_who_is_not_an_administrator_cannot_create_a_token(
    db, runtime, admin_engine, world
):
    tenant = world["human"].tenant_id
    with admin_engine.connect() as conn:
        credentials_before = conn.execute(
            text("SELECT count(*) FROM execbound.credentials WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    with console_client(db, runtime, admin_engine, world["human"]) as console:
        refused = console.post(API + "/settings/tokens/issue", {"name": "ci", "lifetime": "8"})
    assert refused.status_code == 403 and refused.json()["code"] == "FORBIDDEN"
    with admin_engine.connect() as conn:
        tokens = conn.execute(
            text("SELECT count(*) FROM execbound.personal_access_tokens WHERE tenant_id=:t"),
            {"t": tenant},
        ).scalar_one()
        credentials_after = conn.execute(
            text("SELECT count(*) FROM execbound.credentials WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    assert tokens == 0
    assert credentials_after == credentials_before


def test_another_administrator_revokes_any_token_in_the_workspace(db, runtime, admin_engine, world):
    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        workspace = console.get(API + "/tenant/tokens").json()["tokens"]
        token_id = workspace[0]["token_id"]
        assert console.post(API + f"/tenant/tokens/{token_id}/revoke", {}).status_code == 200
        with bearer(console, token) as client:
            assert client.get(API + "/agents", headers=auth(token)).status_code == 401


def test_the_backing_credential_stays_out_of_the_credential_lists(db, runtime, admin_engine, world):
    minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        page = console.get(API + "/credentials").json()
    with admin_engine.connect() as conn:
        backing = {
            str(c)
            for c in conn.execute(
                text("SELECT credential_id FROM execbound.personal_access_tokens")
            ).scalars()
        }
    assert not backing & {row["credential_id"] for row in page["credentials"]}


def test_an_action_by_token_is_audited_as_the_owner_with_its_credential(
    db, runtime, admin_engine, world
):
    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            post(
                client,
                API + "/credentials/issue",
                token,
                {"principal": "new:AGENT", "label": "Coding agent", "lifetime": "8"},
            )
    with admin_engine.connect() as conn:
        backing = conn.execute(
            text("SELECT credential_id FROM execbound.personal_access_tokens")
        ).scalar_one()
        event = (
            conn.execute(
                text(
                    "SELECT actor_id, payload FROM execbound.audit_events "
                    "WHERE kind='credential.issued' ORDER BY sequence DESC LIMIT 1"
                )
            )
            .mappings()
            .one()
        )
    assert event["actor_id"] == world["admin"].principal_id
    assert event["payload"]["actor_credential_id"] == str(backing)


def issued_rows(admin_engine, tenant) -> tuple[int, int, int]:
    """What issuing a token writes, counted: token rows, credential rows and issue events."""
    with admin_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT (SELECT count(*) FROM execbound.personal_access_tokens "
                "WHERE tenant_id=:t), "
                "(SELECT count(*) FROM execbound.credentials WHERE tenant_id=:t), "
                "(SELECT count(*) FROM execbound.audit_events "
                "WHERE tenant_id=:t AND kind='personal_token.issued')"
            ),
            {"t": tenant},
        ).one()
    return int(row[0]), int(row[1]), int(row[2])


def test_creating_a_token_needs_a_recently_verified_factor_only_when_one_is_enrolled(
    db, runtime, admin_engine, world
):
    """`require_recent_factor` (mfa.py) is conditional: it steps up only an administrator who
    has an enrolled, enabled factor, and is a no-op otherwise. The unconditional half is
    already proven every time a token is issued in this file's other tests, since `world`'s
    fixture administrator enrolls no factor at all and still succeeds unstepped; this test is
    the enrolled half, modelled on `test_teammate_invitations.py::test_ti25...`: enrol a
    factor, age the session's assurance row past thirty minutes, the issue route refuses, and a
    fresh factor (the same step-up `/mfa` itself performs, `mfa.verify_factor`) lets it
    succeed again."""
    from execbound import mfa
    from execbound.envelope import KeyRing

    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        session = load_session(db, console.client.cookies.get("eb_session"), clock=runtime.clock)
        ring = KeyRing("test", {"test": b"m" * 32})
        seed = mfa.begin_enrollment(db, session, ring, clock=runtime.clock)
        recovery_codes = mfa.confirm_enrollment(
            db,
            session,
            ring,
            mfa.totp(seed, int(runtime.clock.now().timestamp() // 30)),
            clock=runtime.clock,
        )
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.session_assurance SET verified_at = :v "
                    "WHERE tenant_id = :t AND session_id = :s"
                ),
                {
                    "v": datetime.now(UTC) - timedelta(minutes=31),
                    "t": world["admin"].tenant_id,
                    "s": session.session_id,
                },
            )
        before = issued_rows(admin_engine, world["admin"].tenant_id)
        refused = console.post(API + "/settings/tokens/issue", {"name": "ci", "lifetime": "8"})
        assert refused.status_code == 401 and refused.json()["code"] == "MFA_REQUIRED"
        # The refusal creates nothing: no token, no backing credential, no issue event.
        assert issued_rows(admin_engine, world["admin"].tenant_id) == before
        # A recovery code, not another TOTP code, so this does not depend on real time having
        # moved into a new thirty-second step since `confirm_enrollment` minted its own.
        assert mfa.verify_factor(db, session, ring, recovery_codes[0], clock=runtime.clock)
        issued = console.post(API + "/settings/tokens/issue", {"name": "ci-2", "lifetime": "8"})
    assert issued.status_code == 200, issued.text


def test_a_policy_change_by_token_records_the_token_credential(db, runtime, admin_engine, world):
    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            drafted = post(
                client, API + "/policy", token, {"source": "template", "template": "review-all"}
            )
    assert drafted.status_code in (200, 201), drafted.text
    with admin_engine.connect() as conn:
        backing = conn.execute(
            text("SELECT credential_id FROM execbound.personal_access_tokens")
        ).scalar_one()
        payload = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events WHERE kind LIKE 'policy.%' "
                "ORDER BY sequence DESC LIMIT 1"
            )
        ).scalar_one()
    assert payload["actor_credential_id"] == str(backing)


def test_issuing_a_token_is_refused_where_directory_sign_in_is_required(
    db, runtime, admin_engine, world
):
    """A workspace whose only identity provider requires sign-in refuses issuing a new token
    with `DIRECTORY_REQUIRED`, the typed code the console already uses for a workspace that
    needs directory sign-in."""
    from test_directory_store import RING, FixedClock, registered

    from execbound.directory import DirectoryConfig

    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        provider = registered(
            runtime.db,
            DirectoryConfig(RING, "https://app.example"),
            {"tenant": world["admin"].tenant_id, "admin": world["admin"].principal_id},
            FixedClock(),
        )
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.identity_providers SET require_sign_in=true "
                    "WHERE tenant_id=:t AND provider_id=:p"
                ),
                {"t": world["admin"].tenant_id, "p": provider},
            )
        refused = console.post(API + "/settings/tokens/issue", {"name": "ci", "lifetime": "8"})
    assert refused.status_code == 403 and refused.json()["code"] == "DIRECTORY_REQUIRED"


def test_a_different_administrator_cannot_revoke_through_settings_but_can_through_tenant(
    db, runtime, admin_engine, world
):
    """`/settings/tokens/{token_id}/revoke` acts only on the caller's own tokens, even though
    the store's `admin_revoke_personal_token` accepts any token in the workspace; a second
    administrator reaches the same token only through `/tenant/tokens/{token_id}/revoke`."""
    other_admin = provision_identity(
        admin_engine, runtime.db, world["admin"].tenant_id, "ADMIN", runtime.clock.now()
    )
    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        token_id = console.get(API + "/settings/tokens").json()["tokens"][0]["token_id"]
    with console_client(db, runtime, admin_engine, other_admin) as console:
        refused = console.post(API + f"/settings/tokens/{token_id}/revoke", {})
        assert refused.status_code == 404, refused.text
        allowed = console.post(API + f"/tenant/tokens/{token_id}/revoke", {})
        assert allowed.status_code == 200, allowed.text
        with bearer(console, token) as client:
            assert client.get(API + "/agents", headers=auth(token)).status_code == 401


def test_issuing_a_one_hour_token_succeeds_even_as_the_clock_advances_between_reads(
    db, runtime, admin_engine, world, monkeypatch
):
    """`issue_token` must derive `expires_at` from its own `issued_at`, read once, not from a
    route's separate and earlier clock read. The definer refuses a lifetime under an hour; two
    reads a few milliseconds apart used to leave a `lifetime: "1"` request a hair short of a
    whole hour and always refused with a real (advancing) clock."""

    class AdvancingClock:
        def __init__(self, start):
            self._value = start

        def now(self):
            self._value = self._value + timedelta(milliseconds=5)
            return self._value

    monkeypatch.setattr(runtime, "clock", AdvancingClock(datetime.now(UTC)))
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        issued = console.post(API + "/settings/tokens/issue", {"name": "ci", "lifetime": "1"})
    assert issued.status_code == 200, issued.text


def test_the_three_change_routes_declare_a_body_so_the_generated_client_sends_one():
    """Without a declared requestBody, `openapi-ts` generates a client call with no body and no
    `Content-Type`, and the guard's media-type check answers 415 — exactly what a real console
    client sent before these three routes carried `body_of(Empty)`."""
    from execbound.surfaces.console_api import console_api_document

    document = console_api_document()
    operations = {
        operation.get("operationId"): operation
        for path in document["paths"].values()
        for operation in path.values()
    }
    for operation_id in ("revokeOwnToken", "deleteOwnToken", "revokeWorkspaceToken"):
        assert "requestBody" in operations[operation_id], operation_id


def test_issuing_an_eleventh_token_answers_its_own_code_not_conflict(
    db, runtime, admin_engine, world
):
    """`TOO_MANY_TOKENS` is its own console code, not the generic
    `CONFLICT` every other named refusal above avoids."""
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        for _ in range(10):
            made = console.post(API + "/settings/tokens/issue", {"name": "ci", "lifetime": "8"})
            assert made.status_code == 200, made.text
        refused = console.post(API + "/settings/tokens/issue", {"name": "ci", "lifetime": "8"})
    assert refused.status_code == 409 and refused.json()["code"] == "TOO_MANY_TOKENS"


def test_an_unknown_token_id_is_not_found_and_a_live_one_cannot_be_deleted(
    db, runtime, admin_engine, world
):
    """An id that does not exist at all is `NOT_FOUND` on both the own-token and the workspace
    revoke route; a token that exists but is in the wrong state for the action (a live one, for
    delete) is `CONFLICT`, never `NOT_FOUND`."""
    minted(runtime, world)
    unknown = uuid4()
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        token_id = console.get(API + "/settings/tokens").json()["tokens"][0]["token_id"]
        unknown_own = console.post(API + f"/settings/tokens/{unknown}/revoke", {})
        unknown_workspace = console.post(API + f"/tenant/tokens/{unknown}/revoke", {})
        live_delete = console.post(API + f"/settings/tokens/{token_id}/delete", {})
    assert unknown_own.status_code == 404, unknown_own.text
    assert unknown_workspace.status_code == 404, unknown_workspace.text
    assert live_delete.status_code == 409 and live_delete.json()["code"] == "CONFLICT"


def test_an_approver_is_refused_the_list_and_workspace_revoke_routes(
    db, runtime, admin_engine, world
):
    """A non-administrator is refused the two list routes and the workspace revoke route, as
    they already are refused issuing a token."""
    token_id = uuid4()
    with console_client(db, runtime, admin_engine, world["human"]) as console:
        own_list = console.get(API + "/settings/tokens")
        workspace_list = console.get(API + "/tenant/tokens")
        revoke = console.post(API + f"/tenant/tokens/{token_id}/revoke", {})
    assert own_list.status_code == 403, own_list.text
    assert workspace_list.status_code == 403, workspace_list.text
    assert revoke.status_code == 403, revoke.text


def test_the_backing_credential_stays_out_of_a_persons_own_credential_history(
    db, runtime, admin_engine, world
):
    """`people_pages.py`'s per-person credential history (`GET /people/{principal_id}`) excludes
    a token-backing credential the same way the cross-cutting `/credentials` list does."""
    minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        page = console.get(API + f"/people/{world['admin'].principal_id}").json()
    with admin_engine.connect() as conn:
        backing = str(
            conn.execute(
                text("SELECT credential_id FROM execbound.personal_access_tokens")
            ).scalar_one()
        )
    assert backing not in {row["credential_id"] for row in page["credentials"]}


def test_the_issued_audit_event_never_carries_the_token_string(db, runtime, admin_engine, world):
    """`personal_token.issued`'s payload names the token and its backing credential by id only;
    the bearer string itself is never written to the audit chain."""
    token = minted(runtime, world)
    with admin_engine.connect() as conn:
        payload = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events "
                "WHERE kind='personal_token.issued' ORDER BY sequence DESC LIMIT 1"
            )
        ).scalar_one()
    assert "token" not in payload
    assert token not in str(payload)


# --- Attribution: every write a token may make names its backing credential ------------------
#
# Every event a token causes records the owner as `actor_id` and the token's backing credential
# as `actor_credential_id`. Each case below is one allowed write that audits (`TOKEN_ALLOWED`'s
# POST routes and the allowed bodies of `/tenant/mode` and `/credentials/issue`); the writes
# that audit nothing (`/client-errors`, `/welcome/example`, `/policy/{bundle_id}/preview` and
# `/monitor/setup/verify`) have no event to carry it. The assistant and removing the samples
# need a configured deployment of their own and are the two tests after this one.


def last_sequence(admin_engine, tenant) -> int:
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT COALESCE(max(sequence), 0) FROM execbound.audit_events "
                    "WHERE tenant_id=:t"
                ),
                {"t": tenant},
            ).scalar_one()
        )


def appended_since(admin_engine, tenant, sequence: int) -> list[dict[str, Any]]:
    with admin_engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT kind, actor_id, payload FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND sequence > :s ORDER BY sequence"
                ),
                {"t": tenant, "s": sequence},
            ).mappings()
        ]


def unattributed(events, owner, backing) -> list[tuple[str, Any]]:
    """Every event not recorded as the owner through the token's backing credential."""
    return [
        (event["kind"], event["payload"].get("actor_credential_id"))
        for event in events
        if event["actor_id"] != owner or event["payload"].get("actor_credential_id") != backing
    ]


def _agent(ctx) -> dict[str, str]:
    return {"agent": str(ctx.world["identity"].principal_id)}


def _agent_key(ctx) -> dict[str, str]:
    return {**_agent(ctx), "key": str(ctx.world["identity"].credential_id)}


def _revoked_agent_key(ctx) -> dict[str, str]:
    values = _agent_key(ctx)
    path = "/agents/{agent}/credentials/{key}/revoke".format(**values)
    assert ctx.post(path, {}).status_code == 200
    return values


def _discovered(ctx) -> dict[str, str]:
    agents = ctx.request.getfixturevalue("found")["agents"]
    return {**_agent(ctx), "discovered": str(agents[0]["agent_id"])}


def _bound(ctx) -> dict[str, str]:
    values = _discovered(ctx)
    bound = ctx.post("/agents/{agent}/bind".format(**values), {"target": values["discovered"]})
    assert bound.status_code == 200, bound.text
    return values


def _finding(ctx) -> dict[str, str]:
    # Imported here: that module imports this one's token helpers for its own MQ2 case.
    from test_console_api_monitoring import seed_tines

    seed_tines(ctx.runtime.db, ctx.world)
    with ctx.runtime.db.transaction(ctx.world["admin"].tenant_id) as conn:
        finding = conn.execute(
            text(
                "SELECT finding_id FROM execbound.monitor_findings "
                "WHERE acknowledged_at IS NULL ORDER BY created_at, finding_id LIMIT 1"
            )
        ).scalar_one()
    return {"finding": str(finding)}


def _draft(ctx) -> dict[str, str]:
    drafted = ctx.post("/policy", {"source": "template", "template": "review-all"})
    assert drafted.status_code == 200, drafted.text
    return {"bundle": drafted.json()["bundle_id"]}


def _ruleset_draft(ctx) -> dict[str, str]:
    return {"bundle": str(ruleset_draft(ctx.runtime.db, ctx.world))}


def _space(ctx) -> dict[str, str]:
    created = ctx.post("/spaces", {"name": "Customer B"})
    assert created.status_code == 200, created.text
    return {"space": created.json()["space_id"]}


def _observing(ctx) -> dict[str, str]:
    admin = ctx.world["admin"]
    set_enforcement_mode(ctx.runtime.db, admin, "OBSERVE", "setup", ctx.runtime.clock)
    return {}


def _stopped(ctx) -> dict[str, str]:
    assert ctx.post("/tenant/stop", {"reason": "first"}).status_code == 200
    return {}


def _connection(ctx) -> dict[str, str]:
    """An operator's Tines connection, with no collection waiting."""
    from execbound.monitoring import collection
    from execbound.monitoring import store as monitor_store
    from execbound_harness.fake_tines import BASE_URL

    connection = monitor_store.create_connection(
        ctx.runtime.db,
        ctx.world["admin"],
        label="Operator's Tines",
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint("token-test-key"),
        clock=ctx.runtime.clock,
    )
    return {"connection": str(connection)}


@dataclass(frozen=True)
class Write:
    """One token write: what it needs first, the call, and the event kinds it must append."""

    path: str
    body: dict[str, Any]
    kinds: frozenset[str]
    prepare: Callable[[Any], dict[str, str]] = field(default=lambda ctx: {})
    status: int = 200


WRITES = {
    "create an agent": Write(
        "/agents", {"label": "Review bot"}, frozenset({"principal.created", "principal.labelled"})
    ),
    "label an agent": Write(
        "/agents/{agent}/label", {"label": "Renamed"}, frozenset({"principal.labelled"}), _agent
    ),
    "issue an agent's key": Write(
        "/agents/{agent}/credentials/issue",
        {"lifetime": "8"},
        frozenset({"credential.issued"}),
        _agent,
    ),
    "revoke an agent's key": Write(
        "/agents/{agent}/credentials/{key}/revoke",
        {},
        frozenset({"credential.revoked"}),
        _agent_key,
    ),
    "delete an agent's key": Write(
        "/agents/{agent}/credentials/{key}/delete",
        {},
        frozenset({"credential.deleted"}),
        _revoked_agent_key,
    ),
    "deactivate an agent": Write(
        "/agents/{agent}/deactivate",
        {"reason": "retired"},
        frozenset({"credential.revoked", "principal.deactivated"}),
        _agent,
    ),
    "bind an agent": Write(
        "/agents/{agent}/bind", {"target": "{discovered}"}, frozenset({"agent.bound"}), _discovered
    ),
    "unbind an agent": Write(
        "/agents/{agent}/unbind", {"reason": "wrong agent"}, frozenset({"agent.unbound"}), _bound
    ),
    "govern a discovered agent": Write(
        "/agents/{discovered}/govern",
        {"lifetime": "8"},
        frozenset({"principal.created", "principal.labelled", "agent.bound", "credential.issued"}),
        _discovered,
    ),
    "issue a key for a new agent": Write(
        "/credentials/issue",
        {"principal": "new:AGENT", "label": "Coding agent", "lifetime": "8"},
        frozenset({"principal.created", "principal.labelled", "credential.issued"}),
    ),
    "issue a key for an existing agent": Write(
        "/credentials/issue",
        {"principal": "{agent}", "lifetime": "8"},
        frozenset({"credential.issued"}),
        _agent,
    ),
    "delete a key": Write(
        "/credentials/{key}/delete", {}, frozenset({"credential.deleted"}), _revoked_agent_key
    ),
    "draft a policy": Write(
        "/policy",
        {"source": "template", "template": "review-all"},
        frozenset({"policy.bundle_created", "policy.ruleset_compiled"}),
    ),
    "validate a draft": Write(
        "/policy/{bundle}/validate",
        {"confirm": True},
        frozenset({"policy.bundle_validated"}),
        _draft,
    ),
    "retire a draft": Write(
        "/policy/{bundle}/retire", {"confirm": True}, frozenset({"policy.bundle_retired"}), _draft
    ),
    "change a draft's rules": Write(
        "/policy/{bundle}/rules",
        {"rules": [ALLOW, DENY], "budgets": []},
        frozenset({"policy.rules_changed"}),
        _ruleset_draft,
    ),
    "acknowledge a monitoring finding": Write(
        "/monitor/findings/{finding}/acknowledge",
        {},
        frozenset({"monitor.finding_acknowledged"}),
        _finding,
    ),
    "ask for a monitoring collection": Write(
        "/monitor/connections/{connection}/collect",
        {},
        frozenset({"monitor.collection_requested"}),
        _connection,
    ),
    "change a monitoring connection's schedule": Write(
        "/monitor/connections/{connection}/schedule",
        {"activity_interval_seconds": 1800},
        frozenset({"monitor.schedule_changed"}),
        _connection,
    ),
    "create a space": Write("/spaces", {"name": "Customer B"}, frozenset({"space.created"})),
    "rename a space": Write(
        "/spaces/{space}/rename", {"name": "Customer B2"}, frozenset({"space.renamed"}), _space
    ),
    "archive a space": Write(
        "/spaces/{space}/archive",
        {"reason": "customer left"},
        frozenset({"space.archived"}),
        _space,
    ),
    "switch to enforcing": Write(
        "/tenant/mode",
        {"mode": "ENFORCE", "reason": "go live"},
        frozenset({"tenant.mode_changed"}),
        _observing,
    ),
    "change the approval deadline": Write(
        "/tenant/deadline",
        {"deadline": "600", "reason": "ten minutes"},
        frozenset({"tenant.approval_deadline_changed"}),
    ),
    "start an emergency stop": Write(
        "/tenant/stop", {"reason": "incident"}, frozenset({"tenant.stop_activated"})
    ),
    # The kernel's own refusals of a token's allowed write, audited as `execution.rejected`.
    "switch to enforcing while enforcing": Write(
        "/tenant/mode",
        {"mode": "ENFORCE", "reason": "again"},
        frozenset({"execution.rejected"}),
        status=409,
    ),
    "change the approval deadline to what it is": Write(
        "/tenant/deadline",
        {"deadline": "120", "reason": "same"},
        frozenset({"execution.rejected"}),
        status=409,
    ),
    "start an emergency stop while stopped": Write(
        "/tenant/stop",
        {"reason": "again"},
        frozenset({"execution.rejected"}),
        _stopped,
        status=409,
    ),
}


def _formatted(value: Any, values: dict[str, str]) -> Any:
    return value.format(**values) if isinstance(value, str) else value


@pytest.mark.parametrize("case", list(WRITES))
def test_every_write_a_token_makes_names_its_backing_credential(
    db, runtime, admin_engine, world, request, case
):
    """Each allowed write, called with a token, appends events that name the owner as the
    actor and the token's backing credential as `actor_credential_id`, whatever else the
    payload holds (the tenant events keep their own `credential_id` too)."""
    write = WRITES[case]
    tenant = world["admin"].tenant_id
    token = minted(runtime, world)
    backing = str(backing_credential(admin_engine, token))
    with application(db, runtime) as client:

        def call(path: str, body: dict[str, Any]):
            return post(client, API + path, token, body)

        ctx = SimpleNamespace(runtime=runtime, world=world, request=request, post=call)
        values = write.prepare(ctx)
        before = last_sequence(admin_engine, tenant)
        body = {key: _formatted(value, values) for key, value in write.body.items()}
        response = call(write.path.format(**values), body)
    assert response.status_code == write.status, response.text
    events = appended_since(admin_engine, tenant, before)
    assert write.kinds <= {event["kind"] for event in events}, [e["kind"] for e in events]
    assert unattributed(events, world["admin"].principal_id, backing) == []


# Every POST route a token may call is covered above by `WRITES`, or named here as one that
# appends no audit event (checked directly against each route's own store function), or as
# proven by a separate test needing its own configured deployment: the assistant
# (`test_the_assistant_by_token_names_its_backing_credential`) and removing the samples
# (`test_removing_the_samples_by_token_names_its_backing_credential`), both below. A route a
# future change makes callable by a token, and every route already here, is checked by the guard
# test that follows, so coverage cannot go stale silently.
NO_AUDIT_EVENT = frozenset(
    {
        "/client-errors",  # writes one log line only (`console.client_error`).
        "/welcome/example",  # a synthetic computation with no database write.
        "/policy/{bundle_id}/preview",  # a read against history/replay, not a mutation.
        "/monitor/setup/verify",  # a read of retained collection evidence.
    }
)
COVERED_BY_ANOTHER_TEST = frozenset(
    {
        "/assistant/rules",
        "/assistant/settings",
        "/assistant/turns",
        "/assistant/turns/{turn_id}/opened",
        "/samples/remove",
    }
)


def _normalized(path: str) -> str:
    """A path template with every `{parameter}` reduced to one spelling, so `WRITES`' own
    parameter names (`{agent}`, `{key}`, `{bundle}`, `{space}`, `{discovered}`) compare equal to
    `token_rules`' (`{principal_id}`, `{credential_id}`, `{bundle_id}`, `{space_id}`,
    `{row_id}`)."""
    return re.sub(r"\{[^}]+\}", "{}", path)


def test_every_token_allowed_post_route_has_attribution_evidence():
    """A token-callable route this file does not know about is worse than one whose own test
    fails: it would silently ship with nobody checking its attribution. Deleting a `WRITES`
    case, or an entry from either excused set, must fail this test rather than passing vacuously
    (checked by hand, not asserted here, since a passing suite cannot prove what a deliberately
    broken one would have caught)."""
    covered = {_normalized(write.path) for write in WRITES.values()}
    excused = {_normalized(path) for path in NO_AUDIT_EVENT | COVERED_BY_ANOTHER_TEST}
    routes = {
        _normalized(path[len("/api/console/v1") :])
        for path, method in TOKEN_ALLOWED
        if method == "POST"
    }
    missing = routes - covered - excused
    assert not missing, missing
    # An exemption for a route tokens can no longer call is stale, and a route both covered
    # and excused hides which of the two is the evidence.
    assert excused <= routes, excused - routes
    assert not covered & excused, covered & excused


BLOCK = AssistantConfig(api_key="token-test-key", person_hourly_turns=50)
PROPOSED_RULE = {
    "id": "review-production-isolation",
    "action": "endpoint.isolate",
    "effect": "REVIEW",
    "quorum": 2,
    "when": [{"kind": "fact", "name": "is_production", "operator": "is", "values": [True]}],
}


def test_the_assistant_by_token_names_its_backing_credential(db, runtime, admin_engine, world):
    """The switch, a question answered and one that fails, opening the explanation and a
    drafted rule: every event the assistant appends for a token names its credential."""
    runtime.assistant = BLOCK
    runtime.assistant_transport = ScriptedTransport(
        [scripted_answer(("Nothing to report.", []), cannot_answer=True)]
    )
    tenant = world["admin"].tenant_id
    token = minted(runtime, world)
    backing = str(backing_credential(admin_engine, token))
    bundle = ruleset_draft(runtime.db, world)
    before = last_sequence(admin_engine, tenant)
    config = console_config(assistant_enabled=True)
    app = create_app(db, runtime=runtime, human=config)
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        switched = post(
            client, API + "/assistant/settings", token, {"enabled": True, "reason": "x"}
        )
        assert switched.status_code == 200, switched.text
        asked = post(client, API + "/assistant/turns", token, {"question": "What changed?"})
        assert asked.status_code == 200, asked.text
        turn = asked.json()["turn_id"]
        opened = post(client, API + f"/assistant/turns/{turn}/opened", token)
        assert opened.status_code == 200, opened.text
        # The script is spent, so this turn fails and is audited as refused.
        failed = post(client, API + "/assistant/turns", token, {"question": "And now?"})
        assert failed.status_code == 200, failed.text
        runtime.assistant_transport = ScriptedTransport(
            [scripted_message(text_message(json.dumps(PROPOSED_RULE)))]
        )
        drafted = post(
            client,
            API + "/assistant/rules",
            token,
            {"bundle_id": str(bundle), "words": "review production isolation"},
        )
        assert drafted.status_code == 200, drafted.text
    events = appended_since(admin_engine, tenant, before)
    kinds = [event["kind"] for event in events]
    assert {
        "tenant.assistant_changed",
        "assistant.asked",
        "assistant.explained",
        "assistant.refused",
    } <= set(kinds), kinds
    assert kinds.count("assistant.asked") == 2, kinds
    # One of the two is the answered question; the other is `/assistant/rules`' own record of
    # the rule it drafted, named by the rule's id.
    proposed = [
        event
        for event in events
        if event["kind"] == "assistant.asked"
        and event["payload"].get("proposed") == PROPOSED_RULE["id"]
    ]
    assert len(proposed) == 1, events
    assert unattributed(events, world["admin"].principal_id, backing) == []


def test_removing_the_samples_by_token_names_its_backing_credential(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    token = minted_for(runtime, workspace.admin)
    backing = str(backing_credential(admin_engine, token))
    with console_client(db, runtime, admin_engine, workspace.admin) as console:
        added = console.post(API + "/samples", {})
        assert added.status_code == 200, added.text
        before = last_sequence(admin_engine, workspace.tenant_id)
        with bearer(console, token) as client:
            removed = post(client, API + "/samples/remove", token)
    assert removed.status_code == 200, removed.text
    events = appended_since(admin_engine, workspace.tenant_id, before)
    kinds = {event["kind"] for event in events}
    assert {"samples.removed", "policy.bundle_retired"} <= kinds, kinds
    assert unattributed(events, workspace.admin.principal_id, backing) == []


def test_a_token_reads_the_samples_status_its_owner_reads(db, admin_engine, seeded, sample_key):
    """Reading the samples' status is allowed to a token, as `/connection` is; adding them is
    not, since that activates a policy (`token_rules.TOKEN_REFUSED`)."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    token = minted_for(runtime, workspace.admin)
    with console_client(db, runtime, admin_engine, workspace.admin) as console:
        added = console.post(API + "/samples", {})
        assert added.status_code == 200, added.text
        with bearer(console, token) as client:
            read = client.get(API + "/samples", headers=auth(token))
    assert read.status_code == 200, read.text
    assert read.json() == added.json()


def test_a_token_downloads_the_samples_demo_configuration_its_owner_downloads(
    db, admin_engine, seeded, sample_key
):
    """The demo configuration is the samples' status in the shape `execbound-demo` reads, so a
    token may download it as it may read the status (#247); it carries no generation, being
    bound to one workspace."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    token = minted_for(runtime, workspace.admin)
    with console_client(db, runtime, admin_engine, workspace.admin) as console:
        assert console.post(API + "/samples", {}).status_code == 200
        own = console.get(API + "/samples/demo-configuration")
        with bearer(console, token) as client:
            read = client.get(API + "/samples/demo-configuration", headers=auth(token))
    assert read.status_code == 200, read.text
    assert read.json() == own.json()
    assert read.headers["cache-control"] == "no-store"


def test_a_browser_session_names_its_own_credential_on_the_same_events(
    db, runtime, admin_engine, world
):
    """The event's shape does not depend on the caller: a browser session's writes name the
    credential its session was issued for, under the same key a token's do. This covers the
    space changes a token may make and the three only a browser may (unarchive, seating and
    unseating a member), and a person's deactivation, which ends their open session."""
    tenant = world["admin"].tenant_id
    approver = str(world["human"].principal_id)
    # An open session for the approver, so deactivating them revokes it.
    issue_session(runtime.db, world["human"], clock=runtime.clock)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        # After signing in, so the chain from here on is only what the writes append.
        before = last_sequence(admin_engine, tenant)
        created = console.post(API + "/spaces", {"name": "Customer B"})
        assert created.status_code == 200, created.text
        space = created.json()["space_id"]
        changes = [
            (f"/spaces/{space}/rename", {"name": "B2"}),
            (f"/spaces/{space}/archive", {"reason": "left"}),
            (f"/spaces/{space}/unarchive", {"reason": "back"}),
            (
                f"/spaces/{space}/members/assign",
                {"principal_id": approver, "role": "HUMAN_APPROVER"},
            ),
            (f"/spaces/{space}/members/unassign", {"principal_id": approver}),
            ("/tenant/stop", {"reason": "incident"}),
            (f"/people/{approver}/deactivate", {"reason": "left the team"}),
        ]
        for path, body in changes:
            answer = console.post(API + path, body)
            assert answer.status_code == 200, (path, answer.text)
    # `console_client` signs in with the administrator's own credential.
    session_credential = world["admin"].credential_id
    events = appended_since(admin_engine, tenant, before)
    kinds = [event["kind"] for event in events]
    assert [kind for kind in kinds if kind.startswith(("space.", "tenant."))] == [
        "space.created",
        "space.renamed",
        "space.archived",
        "space.unarchived",
        "space.member_assigned",
        "space.member_unassigned",
        "tenant.stop_activated",
    ]
    assert {"credential.revoked", "human_session.revoked", "principal.deactivated"} <= set(kinds)
    assert unattributed(events, world["admin"].principal_id, str(session_credential)) == []
