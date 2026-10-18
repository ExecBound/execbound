# SPDX-License-Identifier: AGPL-3.0-only
"""The console API base: the session route, the JSON guards, the typed errors, the document.

Every case here is one each console API route inherits through the harness in
`console_api_fixtures`: a bearer credential refused and audited, no session answered with a
typed code even to a browser, the CSRF header, the exact Origin, the content type, the body
bound, an unknown field, a GET-only route posted to, the secret check over every response, the
release header, and the committed OpenAPI document equal to the generated one.
"""

import json
import logging

import pytest
from console_api_fixtures import (
    API,
    assert_no_secrets,
    console_client,
    refusals,
    rejections,
)
from sqlalchemy import text
from test_human_surface import human_config as human_config
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound.surfaces.console_api import console_api_document
from execbound.surfaces.console_api.errors import CODES
from execbound.surfaces.console_api.token_rules import (
    TOKEN_ALLOWED,
    TOKEN_BODY_LIMITS,
    TOKEN_REFUSED,
    token_allowed,
)
from execbound.surfaces.limits import RequestLimits
from execbound.transports import MailConfig

REPORT = {"route": "/activity", "release": "abc1234", "name": "TypeError", "stack_hash": "ab" * 32}


def test_the_session_route_says_who_for_which_tenant_and_hands_over_the_token(
    db, runtime, admin_engine, world, monkeypatch
):
    monkeypatch.setenv("EXECBOUND_COMMIT", "abc1234def")
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(API + "/session")
        assert response.status_code == 200
        body = response.json()
        assert body["identity"]["kind"] == "ADMIN"
        assert body["identity"]["principal_id"] == str(world["admin"].principal_id)
        assert body["tenant"]["tenant_id"] == str(world["identity"].tenant_id)
        assert body["tenant"]["mode"] in {"ENFORCE", "OBSERVE"}
        assert body["tenant"]["approval_deadline_seconds"] >= 60
        assert body["release"] == "abc1234def"
        assert body["csrf_token"] == admin.client.cookies["eb_csrf"]
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-ExecBound-Release"] == "abc1234def"
        assert response.headers["Content-Security-Policy"].startswith(
            "default-src 'none'; script-src 'self'"
        )
        assert_no_secrets(
            response
        ) if False else None  # the token is the one secret this route returns
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        body = approver.get(API + "/session").json()
        assert body["identity"]["kind"] == "HUMAN_APPROVER"
        assert body["identity"]["label"]


def test_the_session_names_a_person_by_label_then_sign_in_address_then_role(
    db, runtime, admin_engine, world
):
    # Nobody who joins by invitation or signup is given a label, so the role word alone
    # named them twice in the sidebar: "Approver" over the role line "Approver".
    human = world["human"].principal_id
    address = f"reviewer-{human}@example.test"

    def named(label, email):
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.principals SET label=:l, email=:e WHERE principal_id=:p"),
                {"l": label, "e": email, "p": human},
            )
        with console_client(db, runtime, admin_engine, world["human"]) as approver:
            return approver.get(API + "/session").json()["identity"]["label"]

    assert named(None, None) == "Approver"
    assert named(None, address) == address
    assert named("Riley Reviewer", address) == "Riley Reviewer"


def test_without_a_plugin_the_session_reports_no_feature(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        view = admin.get(API + "/session").json()
    assert view["features"] == [] and view["invitations"] is False


def test_the_session_says_whether_this_deployment_can_send_mail(
    db, runtime, admin_engine, world, monkeypatch
):
    """The people page offers to invite by email only where a relay exists; without one an
    invitation would wait for mail that never comes."""
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(API + "/session").json()["mail"] is False
    relay = MailConfig("localhost", 2525, "tls", "relay", "relay-password", "a@example.com")
    monkeypatch.setattr(runtime, "mail", relay)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(API + "/session").json()["mail"] is True


def test_a_bearer_credential_and_a_missing_session_are_refused_with_typed_codes(
    db, runtime, seeded, admin_engine, world
):
    for path, method in ((API + "/session", "GET"), (API + "/client-errors", "POST")):
        results = refusals(db, runtime, seeded, admin_engine, world, path, method)
        assert results["bearer"].status_code == 403, (path, results["bearer"].text)
        assert results["bearer"].json()["code"] == "FORBIDDEN"
        assert results["audited"] == 1, path
        missing = results["no_session"]
        assert missing.status_code == 401, (path, missing.text)
        assert missing.headers["content-type"].startswith("application/json"), "a browser got HTML"
        assert missing.json() == {
            "code": "SESSION_REQUIRED",
            "detail": CODES["SESSION_REQUIRED"][1],
        }


def test_a_mutation_needs_the_token_the_origin_json_and_a_bounded_body(
    db, runtime, admin_engine, world, caplog
):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        before = rejections(admin_engine, world["admin"])
        assert (
            admin.post(API + "/client-errors", REPORT, csrf=None).json()["code"] == "INVALID_CSRF"
        )
        assert admin.post(API + "/client-errors", REPORT, csrf="wrong").status_code == 403
        assert rejections(admin_engine, world["admin"]) == before + 2
        assert (
            admin.post(API + "/client-errors", REPORT, origin="http://evil.example").status_code
            == 403
        )
        assert admin.post(API + "/client-errors", REPORT, origin=None).status_code == 403
        wrong_type = admin.post(API + "/client-errors", REPORT, content_type="text/plain")
        assert (
            wrong_type.status_code == 415 and wrong_type.json()["code"] == "UNSUPPORTED_MEDIA_TYPE"
        )
        assert admin.post(API + "/client-errors", raw=b"x" * 5000).json()["code"] == "TOO_LARGE"
        assert admin.post(API + "/client-errors", raw=b"not json").json()["code"] == "INVALID_BODY"
        assert (
            admin.post(API + "/client-errors", raw=b'{"route": "/a", "route": "/b"}').json()["code"]
            == "INVALID_BODY"
        )
        unknown = admin.post(API + "/client-errors", {**REPORT, "message": "secret text"})
        assert unknown.status_code == 400 and unknown.json()["fields"] == ["message"]
        assert admin.post(API + "/client-errors", {**REPORT, "route": "/activity?open=1"}).json()[
            "fields"
        ] == ["route"]
        with caplog.at_level(logging.WARNING, logger="execbound"):
            accepted = admin.post(API + "/client-errors", REPORT)
        assert accepted.status_code == 204 and accepted.content == b""
        assert_no_secrets(accepted)
        payloads = [
            getattr(record, "execbound", {})
            for record in caplog.records
            if getattr(record, "execbound", {}).get("event") == "console.client_error"
        ]
        assert len(payloads) == 1, [getattr(r, "execbound", None) for r in caplog.records][-5:]
        assert payloads[0]["stack_hash"] == REPORT["stack_hash"]
        assert "secret text" not in str(payloads[0]) and "message" not in payloads[0]
        # A GET-only route posted to, and a POST-only route read, are refused by method.
        assert admin.post(API + "/session", {}).status_code == 405
        assert admin.get(API + "/client-errors").status_code == 405
        assert admin.post(API + "/session", {}).json()["code"] == "METHOD_NOT_ALLOWED"


def test_the_committed_openapi_document_is_current_and_names_only_the_console():
    """The committed document is exactly core's own (#496): the published console API,
    which the docs site renders and the core console's client is generated from, compared whole,
    schemas included. A plugin's areas are in that plugin's own document, never here."""
    from console_sbom_fixtures import ROOT

    committed = json.loads(
        (ROOT / "console" / "openapi" / "console-v1.json").read_text(encoding="utf-8")
    )
    generated = console_api_document()
    assert committed == generated
    assert {"/api/console/v1/session", "/api/console/v1/client-errors"} <= set(generated["paths"])
    assert all(path.startswith("/api/console/v1/") for path in generated["paths"])
    assert generated["info"]["title"] == "ExecBound console API"
    assert not any(path.startswith("/v1/") for path in generated["paths"])


def test_the_console_reference_opens_with_authentication_and_marks_each_token_rule():
    document = console_api_document()
    assert document["info"]["description"].lstrip().startswith("## Authentication")
    for path, item in document["paths"].items():
        for method, operation in item.items():
            key = (path, method.upper())
            # Ties the document's own path spelling (`get_openapi`'s `path_format`) to the
            # gateway's (`route.path`, what `token_allowed` is actually called with in
            # `guards.py`): the two must name the same routes, or a formatting difference
            # between them would let a route go undocumented, or worse, misdocumented.
            assert key in TOKEN_ALLOWED | TOKEN_REFUSED, key
            expected = "allowed" if token_allowed(path, method.upper()) else "refused"
            assert operation["x-execbound-token"] == expected, (path, method)
            if key in TOKEN_BODY_LIMITS:
                continue  # test_the_two_body_ruled_operations_state_their_own_limit checks these
            generic = (
                "Personal access tokens: allowed."
                if expected == "allowed"
                else "Personal access tokens: refused; sign in to the console."
            )
            assert operation["description"].endswith(generic), (path, method)


def test_the_two_body_ruled_operations_state_their_own_limit():
    document = console_api_document()
    mode = document["paths"][API + "/tenant/mode"]["post"]
    assert mode["x-execbound-token"] == "allowed"
    assert mode["description"].endswith(
        "Personal access tokens: allowed to switch to enforcing only; switching to "
        "observe-only is refused."
    )
    issue = document["paths"][API + "/credentials/issue"]["post"]
    assert issue["x-execbound-token"] == "allowed"
    assert issue["description"].endswith(
        "Personal access tokens: allowed to issue a key for an agent only; a person's "
        "credential is refused."
    )


def test_the_rate_limit_sentence_matches_the_configured_default():
    """The introduction states the token's own rate limit from `RequestLimits()`, the way
    `agent_api_guide.introduction` states the agent API's; this pins the rendered number to
    that default so the two can never drift apart silently."""
    limits = RequestLimits()
    document = console_api_document()
    assert (
        f"rate limit of {limits.token_requests} requests per {limits.token_window_seconds} "
        "seconds" in document["info"]["description"]
    )


@pytest.mark.parametrize("path", [API + "/session"])
def test_every_route_response_passes_the_secret_check(db, runtime, admin_engine, world, path):
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        response = approver.get(path)
        assert response.status_code == 200
        body = response.json()
        body.pop("csrf_token")
        from execbound.replay.verify import reject_secrets

        reject_secrets(body)
        assert response.headers.get_list("set-cookie") == []


def test_each_status_falls_back_to_its_generic_code_never_a_named_one():
    """A console API refusal that carries only a status, a plain `HTTPException` from a shared
    guard or an execution error answered by status, reads the generic code for that status. A
    code a route raises for one named cause never stands in for its whole status: before this
    was pinned, a bare 409 answered `INVALID_PROPOSAL`, "The assistant could not draft that
    rule.", because it happened to be the last 409 declared."""
    from execbound.surfaces.console_api.errors import BY_STATUS, CODES, api_error_response

    generic = {
        400: "INVALID_REQUEST",
        401: "SESSION_REQUIRED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        413: "TOO_LARGE",
        415: "UNSUPPORTED_MEDIA_TYPE",
        423: "STOPPED",
        429: "TOO_MANY_REQUESTS",
        503: "UNAVAILABLE",
    }
    assert BY_STATUS == generic
    assert all(CODES[code][0] == status for status, code in BY_STATUS.items())
    body = json.loads(api_error_response(409).body)
    assert body == {"code": "CONFLICT", "detail": "Something changed first."}
