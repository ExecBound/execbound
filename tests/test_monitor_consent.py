# SPDX-License-Identifier: AGPL-3.0-only
"""MC8 to MC11: connecting Microsoft Entra by verified admin consent (#228, #678).

An administrator starts an attempt from the console, which answers Microsoft's sign-in address
and sets a binding cookie in that browser. Microsoft posts the administrator's id_token to
`/connect/entra/signed-in`, which verifies it, checks the attempt, the browser and the directory,
and only then sends the browser on to the admin consent page for that directory. Microsoft
sends the browser back to `/connect/entra/consented`, which creates one `platform_app`
connection, or records a new consent on the connection an update names. Every refusal ends the
attempt as refused with its code and the step that refused it, creates nothing, logs the code
alone and lands on the Connections view; the page then reads what happened from the server.

Real PostgreSQL. Microsoft's sign-in and consent pages are `execbound_harness.fake_entra_login`,
reached through an injected transport; nothing here contacts Microsoft.
"""

import base64
import json
import logging
import re
import secrets
import time
from contextlib import contextmanager
from datetime import timedelta
from html import unescape
from urllib.parse import urlencode
from uuid import UUID, uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential, form_values
from test_monitor_connect_store import every_text
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.app import create_app
from execbound.directory import DirectoryKeys
from execbound.logging_schema import install as install_logging
from execbound.monitoring import consent, sealing
from execbound.monitoring.consent import GLOBAL_ADMINISTRATOR, PRIVILEGED_ROLE_ADMINISTRATOR
from execbound.surfaces.human import HumanConfig, ScoutConfig, ScoutEntra
from execbound.surfaces.tokens import TokenKeys
from execbound_harness.fake_entra_login import CLIENT, DIRECTORY, FakeEntraLogin, parts

pytestmark = pytest.mark.integration

ORIGIN = "https://execbound.test"
API = "/api/console/v1"
START = API + "/monitor/connections/entra/start"
SIGNED_IN = "/connect/entra/signed-in"
CONSENTED = "/connect/entra/consented"
LOGIN = "https://login.microsoftonline.com"
# The name a directory administrator sees for the app: it may appear in the console's copy and
# nowhere else, not in a row, an event or a log line.
DISPLAY = "Synthetic Scout Display-9c1e"
OTHER_DIRECTORY = "deadbeef-0000-4000-8000-00000000beef"
DONE = "/monitor?view=connections&connect=done"
REFUSED = "/monitor?view=connections&connect=refused"


@pytest.fixture(autouse=True)
def structured_logging():
    """The application's logger, installed before each test's call begins. pytest attaches its
    capture to a logger that does not propagate only if it already does not when a phase
    starts, and installing the logger is what stops it propagating; without this the first test
    in a process to build an application would capture nothing it logs."""
    install_logging()


@pytest.fixture
def collector(tmp_path):
    return sealing.generate(tmp_path / "collector")


@pytest.fixture
def login():
    return FakeEntraLogin()


def entra_config(collector, login, *, authority="organizations", entra=True, **changes):
    return HumanConfig(
        ORIGIN,
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        scout=ScoutConfig(
            collector=collector,
            entra=ScoutEntra(CLIENT, authority, DISPLAY, http=login.client()) if entra else None,
        ),
        **changes,
    )


class Browser:
    """One administrator's browser, signed in to the console at `ORIGIN`."""

    def __init__(self, client: TestClient, csrf: str) -> None:
        self.client = client
        self.csrf = csrf

    def start(self, body=None):
        return self.client.post(
            START,
            content=json.dumps(body if body is not None else {"label": "Directory"}).encode(),
            headers={
                "Origin": ORIGIN,
                "X-CSRF-Token": self.csrf,
                "Content-Type": "application/json",
            },
        )

    def signed_in(self, fields, *, origin=LOGIN):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if origin is not None:
            headers["Origin"] = origin
        return self.client.post(SIGNED_IN, content=urlencode(fields).encode(), headers=headers)

    def consented(self, pairs):
        return self.client.get(CONSENTED + "?" + urlencode(pairs))

    def binding(self):
        return self.client.cookies.get("__Host-eb_connect")

    def forget_binding(self):
        self.client.cookies.delete("__Host-eb_connect")


@contextmanager
def browser(db, runtime, admin_engine, identity, config):
    app = create_app(db, runtime=runtime, human=config)
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, identity)
        signed = client.post("/session", data=values, headers={"Origin": ORIGIN})
        assert signed.status_code == 303, signed.text
        opened = client.get(API + "/session")
        assert opened.status_code == 200, opened.text
        yield Browser(client, opened.json()["csrf_token"])


def landed(response) -> str:
    """Where an onward page moves the browser."""
    assert response.status_code == 200, response.text
    found = re.search(r'http-equiv="refresh" content="0; url=([^"]+)"', response.text)
    assert found is not None, response.text
    return unescape(found.group(1))


def cleared(response) -> bool:
    """Whether the response ends the binding cookie."""
    return any(
        header.startswith("__Host-eb_connect=") and "max-age=0" in header.lower()
        for header in response.headers.get_list("set-cookie")
    )


def attempts(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_connect_attempts WHERE tenant_id = :t "
                    "ORDER BY created_at"
                ),
                {"t": tenant},
            ).mappings()
        ]


def connections(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text("SELECT * FROM execbound.monitor_connections WHERE tenant_id = :t"),
                {"t": tenant},
            ).mappings()
        ]


def events(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT kind, payload, actor_id, space_id FROM execbound.audit_events "
                    "WHERE tenant_id = :t AND kind LIKE 'monitor.%' ORDER BY sequence"
                ),
                {"t": tenant},
            ).mappings()
        ]


def refusals(caplog):
    """The codes `monitor.connect_refused` logged, in order, each line checked to carry the
    code and nothing else."""
    found = []
    for record in caplog.records:
        payload = getattr(record, "execbound", {})
        if payload.get("event") == "monitor.connect_refused":
            assert set(payload) - {"request_id"} == {"event", "code"}, payload
            found.append(payload["code"])
    return found


def logged(caplog) -> str:
    """Everything logged, the structured payloads included."""
    return caplog.text + json.dumps(
        [getattr(record, "execbound", {}) for record in caplog.records], default=str
    )


def started(b):
    """Start an attempt: the authorize URL and its query."""
    answer = b.start()
    assert answer.status_code == 200, answer.text
    url = answer.json()["authorize_url"]
    return url, parts(url)[1]


def signed(b, login):
    """Start and sign in: the consent URL Microsoft is sent to, and the start's query."""
    url, query = started(b)
    _, fields = login.authorize(url)
    answer = b.signed_in(fields)
    assert answer.status_code == 303, answer.text
    return answer.headers["location"], query


def secrets_of(query, b, fields=None):
    """Every secret one attempt carried: the state, the nonce, the binding and the id_token."""
    values = [query["state"], query["nonce"], b.binding() or "never-set"]
    if fields:
        values.append(fields["id_token"])
    return values


def test_mc10_a_consent_creates_one_connection_from_a_verified_administrator(
    db, runtime, admin_engine, world, collector, login, caplog
):
    caplog.set_level(logging.DEBUG, logger="execbound")
    admin = world["admin"]
    tenant = admin.tenant_id
    with browser(db, runtime, admin_engine, admin, entra_config(collector, login)) as b:
        answer = b.start({"label": "Directory"})
        assert answer.status_code == 200, answer.text
        assert answer.headers["cache-control"] == "no-store"
        url = answer.json()["authorize_url"]
        address, query = parts(url)
        assert address == f"{LOGIN}/organizations/oauth2/v2.0/authorize"
        assert set(query) == {
            "client_id",
            "response_type",
            "response_mode",
            "scope",
            "redirect_uri",
            "state",
            "nonce",
            "prompt",
        }
        assert {key: query[key] for key in query if key not in {"state", "nonce"}} == {
            "client_id": CLIENT,
            "response_type": "id_token",
            "response_mode": "form_post",
            "scope": "openid",
            "redirect_uri": ORIGIN + SIGNED_IN,
            "prompt": "select_account",
        }
        assert re.fullmatch(rf"mc1\.{tenant}\.[0-9a-f-]{{36}}\.[A-Za-z0-9_-]{{43}}", query["state"])
        [cookie] = [
            header
            for header in answer.headers.get_list("set-cookie")
            if header.startswith("__Host-eb_connect=")
        ]
        attributes = {part.strip().lower() for part in cookie.split(";")[1:]}
        assert attributes == {"httponly", "secure", "samesite=none", "path=/", "max-age=600"}
        redirect, fields = login.authorize(url)
        assert redirect == ORIGIN + SIGNED_IN
        moved = b.signed_in(fields)
        assert moved.status_code == 303, moved.text
        consent, consent_query = parts(moved.headers["location"])
        assert consent == f"{LOGIN}/{DIRECTORY}/v2.0/adminconsent"
        assert consent_query == {
            "client_id": CLIENT,
            "scope": "https://graph.microsoft.com/.default",
            "redirect_uri": ORIGIN + CONSENTED,
            "state": query["state"],
        }
        spent = secrets_of(query, b, fields)
        back, pairs = login.consent(moved.headers["location"])
        assert back == ORIGIN + CONSENTED
        done = b.consented(pairs)
        assert landed(done) == DONE
        assert cleared(done)
    [connection] = connections(admin_engine, tenant)
    [attempt] = attempts(admin_engine, tenant)
    assert {
        key: connection[key]
        for key in (
            "kind",
            "credential_mode",
            "directory_ref",
            "client_ref",
            "key_fingerprint",
            "label",
            "space_id",
            "created_by",
            "consented_by",
            "collect_requested_by",
            "active",
        )
    } == {
        "kind": "entra_agent_id",
        "credential_mode": "platform_app",
        "directory_ref": DIRECTORY,
        "client_ref": CLIENT,
        "key_fingerprint": None,
        "label": "Directory",
        "space_id": attempt["space_id"],
        "created_by": admin.principal_id,
        "consented_by": admin.principal_id,
        "collect_requested_by": admin.principal_id,
        "active": True,
    }
    assert connection["consented_at"] is not None
    assert (attempt["state"], attempt["connection_id"]) == (
        "consented",
        connection["connection_id"],
    )
    recorded = events(admin_engine, tenant)
    assert [event["kind"] for event in recorded] == [
        "monitor.connection_created",
        "monitor.consent_recorded",
    ]
    assert recorded[0]["payload"] == {
        "connection_id": str(connection["connection_id"]),
        "space_id": str(attempt["space_id"]),
        "kind": "entra_agent_id",
        "credential_mode": "platform_app",
        "label": "Directory",
        "attempt_id": str(attempt["attempt_id"]),
    }
    assert recorded[1]["payload"] == {
        "connection_id": str(connection["connection_id"]),
        "directory_ref": DIRECTORY,
        "attempt_id": str(attempt["attempt_id"]),
    }
    assert {event["actor_id"] for event in recorded} == {admin.principal_id}
    # No state, nonce, binding, id_token or display name in a table, an event or a log line.
    stored = every_text(admin_engine)
    for value in [*spent, DISPLAY]:
        assert [(table, column) for table, column, found in stored if value in found] == []
        assert value not in logged(caplog)
    assert refusals(caplog) == []


def test_mc10_microsofts_success_with_a_parameter_it_adds_later_still_completes(
    db, runtime, admin_engine, world, collector, login, caplog
):
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        location, _ = signed(b, login)
        _, pairs = login.consent(location, future_parameter="UNKNOWN-VALUE-4f1a")
        assert landed(b.consented(pairs)) == DONE
    assert len(connections(admin_engine, tenant)) == 1
    assert [
        (table, column)
        for table, column, found in every_text(admin_engine)
        if "UNKNOWN-VALUE-4f1a" in found or "future_parameter" in found
    ] == []
    assert "UNKNOWN-VALUE-4f1a" not in logged(caplog)
    assert "future_parameter" not in logged(caplog)


@pytest.mark.parametrize(
    "change,code",
    [
        ("long scope", "INVALID_SCOPE"),
        ("no scope", "INVALID_SCOPE"),
        ("repeated state", "REPEATED_PARAMETER"),
        ("repeated tenant", "REPEATED_PARAMETER"),
        ("tenant differs", "DIRECTORY_MISMATCH"),
        ("not granted", "CONSENT_NOT_GRANTED"),
        ("microsoft error", "PROVIDER_ERROR"),
        ("no cookie", "BINDING_MISSING"),
        ("expired", "ATTEMPT_EXPIRED"),
    ],
)
def test_mc8_each_refusal_at_the_consent_callback_creates_nothing(
    db, runtime, admin_engine, world, collector, login, caplog, change, code
):
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        location, query = signed(b, login)
        if change == "microsoft error":
            _, pairs = login.consent(
                location,
                error="access_denied",
                error_uri="https://login.microsoftonline.com/error?code=65004",
                error_subcode="cancel",
            )
        else:
            _, pairs = login.consent(location)
        values = dict(pairs)
        if change == "long scope":
            pairs = [(k, "x" * 2049 if k == "scope" else v) for k, v in pairs]
        elif change == "no scope":
            pairs = [(k, v) for k, v in pairs if k != "scope"]
        elif change == "repeated state":
            pairs = [*pairs, ("state", values["state"])]
        elif change == "repeated tenant":
            pairs = [*pairs, ("tenant", values["tenant"])]
        elif change == "tenant differs":
            pairs = [(k, OTHER_DIRECTORY if k == "tenant" else v) for k, v in pairs]
        elif change == "not granted":
            pairs = [(k, "False" if k == "admin_consent" else v) for k, v in pairs]
        elif change == "no cookie":
            b.forget_binding()
        elif change == "expired":
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE execbound.monitor_connect_attempts SET "
                        "created_at = created_at - interval '11 minutes', "
                        "expires_at = expires_at - interval '11 minutes' WHERE tenant_id = :t"
                    ),
                    {"t": tenant},
                )
        spent = secrets_of(query, b)
        answer = b.consented(pairs)
        assert landed(answer) == REFUSED
        assert cleared(answer)
    [attempt] = attempts(admin_engine, tenant)
    assert (attempt["state"], attempt["refusal_code"], attempt["refused_step"]) == (
        "refused",
        code,
        "consented",
    )
    assert connections(admin_engine, tenant) == []
    assert events(admin_engine, tenant) == []
    assert refusals(caplog) == [code]
    for value in [*spent, DISPLAY, "65004", "cancel", "denied the request"]:
        assert value not in logged(caplog)


def id_token(login, query, **changes):
    """An id_token for the attempt `query` started, wrong in the way `changes` says."""
    return login.id_token(nonce=query["nonce"], **changes)


@pytest.mark.parametrize(
    "change,code",
    [
        ("issuer of another directory", "INVALID_ISSUER"),
        ("an issuer that is not Microsoft's", "INVALID_ISSUER"),
        ("no administrator role", "NO_ADMIN_ROLE"),
        ("a reader's role only", "NO_ADMIN_ROLE"),
        ("no roles claim", "NO_ADMIN_ROLE"),
        ("another key", "INVALID_SIGNATURE"),
        ("alg none", "INVALID_ALGORITHM"),
        ("HS256", "INVALID_ALGORITHM"),
        ("another audience", "INVALID_AUDIENCE"),
        ("another nonce", "NONCE_MISMATCH"),
        ("expired", "INVALID_TIME"),
        ("not yet valid", "INVALID_TIME"),
        ("issued in the future", "INVALID_TIME"),
        ("no cookie", "BINDING_MISSING"),
        ("another attempt's cookie", "BINDING_MISMATCH"),
        ("microsoft error", "PROVIDER_ERROR"),
        ("another origin", "INVALID_ORIGIN"),
        ("no origin", "INVALID_ORIGIN"),
        ("expired attempt", "ATTEMPT_EXPIRED"),
        ("repeated state", "REPEATED_PARAMETER"),
    ],
)
def test_mc8_each_refusal_at_the_sign_in_callback_asks_microsoft_for_nothing(
    db, runtime, admin_engine, world, collector, login, caplog, change, code
):
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    now = runtime.clock.now().timestamp()
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        url, query = started(b)
        _, fields = login.authorize(url)
        origin = LOGIN
        tokens = {
            "issuer of another directory": {"claims": {"iss": f"{LOGIN}/{OTHER_DIRECTORY}/v2.0"}},
            "an issuer that is not Microsoft's": {
                "claims": {"iss": f"https://sts.windows.net/{DIRECTORY}/"}
            },
            "no administrator role": {"roles": ()},
            # Global Reader reads the directory and cannot consent for it.
            "a reader's role only": {"roles": ("f2ef992c-3afb-46b9-b7cf-a126ee74c451",)},
            "no roles claim": {"drop": ("wids",)},
            "another key": {"key": rsa.generate_private_key(public_exponent=65537, key_size=2048)},
            "alg none": {"header": {"alg": "none"}},
            "HS256": {"header": {"alg": "HS256"}},
            "another audience": {"audience": OTHER_DIRECTORY},
            "expired": {"now": now - 7200},
            "not yet valid": {"claims": {"nbf": int(now) + 3600}},
            "issued in the future": {"claims": {"iat": int(now) + 3600}},
        }
        if change in tokens:
            fields = {**fields, "id_token": id_token(login, query, **tokens[change])}
        elif change == "another nonce":
            fields = {**fields, "id_token": login.id_token(nonce="another-nonce")}
        elif change == "no cookie":
            b.forget_binding()
        elif change == "another attempt's cookie":
            started(b)
        elif change == "microsoft error":
            fields = {
                "error": "access_denied",
                "error_description": "AADSTS50105: denied the request",
                "state": query["state"],
            }
        elif change == "another origin":
            origin = "https://elsewhere.example"
        elif change == "no origin":
            origin = None
        elif change == "expired attempt":
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE execbound.monitor_connect_attempts SET "
                        "created_at = created_at - interval '11 minutes', "
                        "expires_at = expires_at - interval '11 minutes' WHERE tenant_id = :t"
                    ),
                    {"t": tenant},
                )
        spent = secrets_of(query, b, fields if "id_token" in fields else None)
        if change == "repeated state":
            answer = b.client.post(
                SIGNED_IN,
                content=(urlencode(fields) + "&state=" + query["state"]).encode(),
                headers={
                    "Origin": LOGIN,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
        else:
            answer = b.signed_in(fields, origin=origin)
        # No admin consent address was issued: the browser lands back on Connections.
        assert landed(answer) == REFUSED
        assert cleared(answer)
    rows = attempts(admin_engine, tenant)
    # The attempt the callback named; a second, started for another cookie, is still live.
    refused = rows[0]
    assert (refused["state"], refused["refusal_code"], refused["refused_step"]) == (
        "refused",
        code,
        "signed_in",
    )
    assert refused["directory_ref"] is None
    assert connections(admin_engine, tenant) == []
    assert events(admin_engine, tenant) == []
    assert refusals(caplog) == [code]
    for value in [*spent, DISPLAY, "denied the request"]:
        assert value not in logged(caplog)
    assert [path for path in login.requests if path.endswith("/adminconsent")] == []


def test_mc8_a_state_naming_no_attempt_is_refused_before_microsofts_keys_are_fetched(
    db, runtime, admin_engine, world, collector, login, caplog
):
    """Anyone can post a well-shaped state with a token naming a key Microsoft never published.
    The attempt is looked up first, so such a post costs one read and never a fetch of
    Microsoft's keys."""
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        started(b)
        forged = f"mc1.{tenant}.{uuid4()}.{secrets.token_urlsafe(32)}"
        token = login.id_token(nonce="any", header={"kid": "never-published"})
        answer = b.signed_in({"id_token": token, "state": forged})
        assert landed(answer) == REFUSED
    assert refusals(caplog) == ["INVALID_STATE"]
    assert login.requests == [
        path for path in login.requests if path.endswith("/oauth2/v2.0/authorize")
    ]
    [live] = attempts(admin_engine, tenant)
    assert live["state"] == "started"


@pytest.mark.parametrize("beside_rsa", [False, True], ids=["ec-alone", "ec-beside-rsa"])
def test_an_ec_key_under_the_kid_never_verifies_microsofts_rs256_token(login, beside_rsa):
    """The directory key cache also serves ES256 keys to a customer's own identity provider.
    The consent step reads Microsoft's set for RS256 alone, so a P-256 key published under the
    token's `kid` is never found for it: alone, the `kid` is unknown and refused, never an
    exception; beside the RSA key, the RSA key still verifies the token."""
    p256 = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    entry = {
        "kty": "EC",
        "use": "sig",
        "crv": "P-256",
        "kid": login.kid,
        "x": base64.urlsafe_b64encode(p256.x.to_bytes(32, "big")).decode().rstrip("="),
        "y": base64.urlsafe_b64encode(p256.y.to_bytes(32, "big")).decode().rstrip("="),
    }
    published = {"keys": [entry, *(login.jwks()["keys"] if beside_rsa else [])]}
    fetched: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        fetched.append(str(request.url))
        return httpx.Response(200, json=published)

    keys = DirectoryKeys(consent.KEYS_URI, httpx.Client(transport=httpx.MockTransport(answer)))
    token = login.id_token(nonce="a-nonce")
    if beside_rsa:
        assert consent._claims(token, keys, CLIENT, time.time())["tid"] == DIRECTORY
    else:
        with pytest.raises(consent.ConnectRefused) as refused:
            consent._claims(token, keys, CLIENT, time.time())
        assert refused.value.code == "UNKNOWN_KEY"
    assert fetched == [consent.KEYS_URI]


@pytest.mark.parametrize(
    "origin,name",
    [(ORIGIN, "__Host-eb_connect"), ("http://127.0.0.1:8000", "eb_connect")],
)
def test_mc8_the_binding_cookie_ends_with_the_attributes_it_was_set_with(
    db, runtime, collector, login, origin, name
):
    """SameSite=None with Secure on every origin, a loopback one included, since a browser
    refuses SameSite=None without Secure and would keep the cookie it was asked to end."""
    config = HumanConfig(
        origin,
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        scout=ScoutConfig(
            collector=collector, entra=ScoutEntra(CLIENT, "organizations", DISPLAY, http=None)
        ),
    )
    with TestClient(
        create_app(db, runtime=runtime, human=config), base_url=origin, follow_redirects=False
    ) as client:
        answer = client.get(CONSENTED + "?state=x")
    assert landed(answer) == REFUSED
    [cookie] = [
        header for header in answer.headers.get_list("set-cookie") if header.startswith(name + "=")
    ]
    attributes = {part.strip().lower() for part in cookie.split(";")[1:]}
    assert {"httponly", "secure", "samesite=none", "path=/", "max-age=0"} <= attributes


def test_mc8_a_single_tenant_registration_accepts_its_own_directory_only(
    db, runtime, admin_engine, world, collector, login, caplog
):
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    config = entra_config(collector, login, authority=OTHER_DIRECTORY)
    with browser(db, runtime, admin_engine, world["admin"], config) as b:
        url, _ = started(b)
        assert parts(url)[0] == f"{LOGIN}/{OTHER_DIRECTORY}/oauth2/v2.0/authorize"
        _, fields = login.authorize(url)
        assert landed(b.signed_in(fields)) == REFUSED
    assert attempts(admin_engine, tenant)[0]["refusal_code"] == "INVALID_DIRECTORY"
    assert refusals(caplog) == ["INVALID_DIRECTORY"]


def test_mc8_names_and_addresses_in_the_token_change_nothing(
    db, runtime, admin_engine, world, collector, login
):
    """Only `tid` and `wids` are read: an `email`, `preferred_username`, `upn` or `oid` naming
    someone else, or another directory, neither changes who connected nor looks anyone up."""
    login.extra = {
        "email": "someone@another-directory.example",
        "preferred_username": "admin@another-directory.example",
        "upn": "admin@another-directory.example",
        "name": "Someone Else",
    }
    tenant = world["admin"].tenant_id
    with admin_engine.connect() as conn:
        before = conn.execute(text("SELECT count(*) FROM execbound.principals")).scalar_one()
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        location, _ = signed(b, login)
        _, pairs = login.consent(location)
        assert landed(b.consented(pairs)) == DONE
    [connection] = connections(admin_engine, tenant)
    assert connection["created_by"] == connection["consented_by"] == world["admin"].principal_id
    with admin_engine.connect() as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.principals")).scalar_one() == before
        )
    assert [
        (table, column)
        for table, column, found in every_text(admin_engine)
        if "another-directory.example" in found or "Someone Else" in found
    ] == []


def test_mc8_a_used_state_completes_nothing_and_keeps_how_the_attempt_ended(
    db, runtime, admin_engine, world, collector, login, caplog
):
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        location, query = signed(b, login)
        _, pairs = login.consent(location)
        assert landed(b.consented(pairs)) == DONE
        b.client.cookies.set("__Host-eb_connect", "replayed-binding", domain="execbound.test")
        again = b.consented(pairs)
        assert landed(again) == REFUSED
        # The sign-in step too, with the same state.
        assert landed(b.signed_in({"id_token": "x.y.z", "state": query["state"]})) == REFUSED
    [attempt] = attempts(admin_engine, tenant)
    assert attempt["state"] == "consented" and attempt["refusal_code"] is None
    assert len(connections(admin_engine, tenant)) == 1
    assert [event["kind"] for event in events(admin_engine, tenant)] == [
        "monitor.connection_created",
        "monitor.consent_recorded",
    ]
    assert refusals(caplog)[0] == "ATTEMPT_USED"


def test_mc8_a_consent_for_an_attempt_that_never_signed_in_is_out_of_order(
    db, runtime, admin_engine, world, collector, login, caplog
):
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        _, query = started(b)
        answer = b.consented(
            [
                ("admin_consent", "True"),
                ("tenant", DIRECTORY),
                ("scope", "https://graph.microsoft.com/Directory.Read.All"),
                ("state", query["state"]),
            ]
        )
        assert landed(answer) == REFUSED
    [attempt] = attempts(admin_engine, tenant)
    assert (attempt["state"], attempt["refusal_code"], attempt["refused_step"]) == (
        "refused",
        "OUT_OF_ORDER",
        "consented",
    )
    assert connections(admin_engine, tenant) == []


def test_mc8_a_state_naming_another_workspace_finds_no_attempt(
    db, runtime, admin_engine, world, seeded, collector, login, caplog
):
    """The state's tenant segment sets the fence; an attempt is found only under its own, so a
    state rewritten to name another workspace finds nothing, and the attempt is left as it was."""
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        url, query = started(b)
        _, fields = login.authorize(url)
        moved = query["state"].replace(str(tenant), str(seeded["tenants"][1]))
        assert landed(b.signed_in({**fields, "state": moved})) == REFUSED
    [attempt] = attempts(admin_engine, tenant)
    assert attempt["state"] == "started"
    assert refusals(caplog) == ["INVALID_STATE"]


def test_mc8_a_full_workspace_and_an_occupied_space_are_refused_before_microsoft(
    db, runtime, admin_engine, world, collector, login
):
    admin = world["admin"]
    tenant = admin.tenant_id
    with browser(db, runtime, admin_engine, admin, entra_config(collector, login)) as b:
        with admin_engine.begin() as conn:
            space = conn.execute(
                text("SELECT space_id FROM execbound.spaces WHERE tenant_id = :t"), {"t": tenant}
            ).scalar_one()
            entra = insert_entra(conn, tenant, admin.principal_id, space, OTHER_DIRECTORY)
        occupied = b.start()
        assert (occupied.status_code, occupied.json()["code"]) == (409, "CONNECTION_EXISTS")
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET active = false, revoked_at = now() "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": tenant, "c": entra},
            )
            for _ in range(19):
                insert_entra(conn, tenant, admin.principal_id, space, str(uuid4()), active=False)
        full = b.start()
        assert (full.status_code, full.json()["code"]) == (409, "CONNECTION_CAPACITY")
    assert attempts(admin_engine, tenant) == []
    assert login.requests == []


def test_mc8_a_workspace_starts_five_attempts_at_once_and_twenty_a_day(
    db, runtime, admin_engine, world, collector, login
):
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        for _ in range(5):
            assert b.start().status_code == 200
        sixth = b.start()
        assert (sixth.status_code, sixth.json()["code"]) == (429, "ATTEMPT_CAPACITY")
        for _ in range(15):
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE execbound.monitor_connect_attempts SET "
                        "created_at = created_at - interval '11 minutes', "
                        "expires_at = expires_at - interval '11 minutes' WHERE tenant_id = :t"
                    ),
                    {"t": tenant},
                )
            assert b.start().status_code == 200
        twenty_first = b.start()
        assert (twenty_first.status_code, twenty_first.json()["code"]) == (
            429,
            "ATTEMPT_CAPACITY",
        )
    assert len(attempts(admin_engine, tenant)) == 20


def insert_entra(conn, tenant, principal, space, directory, *, active=True):
    """An operator's Entra connection, written by the owner."""
    connection = uuid4()
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, label, "
            "base_url, key_fingerprint, created_at, created_by, kind, directory_ref, client_ref, "
            "space_id, active, revoked_at) VALUES (:t, :c, 'Operator directory', "
            "'https://graph.microsoft.com', :k, now(), :p, 'entra_agent_id', :d, :client, :s, "
            ":active, CASE WHEN :active THEN NULL ELSE now() END)"
        ),
        {
            "t": tenant,
            "c": connection,
            "k": "ab" * 32,
            "p": principal,
            "d": directory,
            "client": CLIENT,
            "s": space,
            "active": active,
        },
    )
    return connection


def other_workspace(admin_engine, seeded):
    """Workspace B: its tenant, principal and space."""
    return seeded["tenants"][1], seeded["principals"][1], seeded["spaces"][1]


def test_mc9_a_directory_connected_in_another_workspace_is_refused_before_consent(
    db, runtime, admin_engine, world, seeded, collector, login, caplog
):
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    other, principal, space = other_workspace(admin_engine, seeded)
    with admin_engine.begin() as conn:
        held = insert_entra(conn, other, principal, space, DIRECTORY.upper())
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        url, _ = started(b)
        _, fields = login.authorize(url)
        answer = b.signed_in(fields)
        assert landed(answer) == REFUSED
    [attempt] = attempts(admin_engine, tenant)
    assert (attempt["refusal_code"], attempt["refused_step"]) == (
        "DIRECTORY_UNAVAILABLE",
        "signed_in",
    )
    assert [path for path in login.requests if path.endswith("/adminconsent")] == []
    for value in (str(other), str(held)):
        assert value not in answer.text and value not in logged(caplog)
        assert value not in json.dumps(attempt, default=str)


def test_mc9_a_directory_connected_elsewhere_after_the_sign_in_is_refused_at_consent(
    db, runtime, admin_engine, world, seeded, collector, login, caplog
):
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    other, principal, space = other_workspace(admin_engine, seeded)
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        location, _ = signed(b, login)
        with admin_engine.begin() as conn:
            held = insert_entra(conn, other, principal, space, DIRECTORY)
        _, pairs = login.consent(location)
        answer = b.consented(pairs)
        assert landed(answer) == REFUSED
    [attempt] = attempts(admin_engine, tenant)
    assert (attempt["refusal_code"], attempt["refused_step"]) == (
        "DIRECTORY_UNAVAILABLE",
        "consented",
    )
    assert connections(admin_engine, tenant) == []
    for value in (str(other), str(held)):
        assert value not in answer.text and value not in logged(caplog)
        assert value not in json.dumps(attempt, default=str)


@pytest.mark.parametrize("step", ["signed_in", "consented"])
def test_mc8_a_database_failure_at_a_callback_ends_the_attempt_as_unavailable(
    db, runtime, admin_engine, world, collector, login, caplog, step
):
    """A failure the database words for people, not a code, still ends the attempt, and only
    `UNAVAILABLE` reaches its record and the log. Here the workspace's connection registry is
    held past the callback's five-second lock wait, and PostgreSQL cancels the call."""
    caplog.set_level(logging.DEBUG, logger="execbound")
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        if step == "signed_in":
            url, _ = started(b)
            _, fields = login.authorize(url)

            def callback():
                return b.signed_in(fields)
        else:
            location, _ = signed(b, login)
            _, pairs = login.consent(location)

            def callback():
                return b.consented(pairs)

        with admin_engine.begin() as held:
            held.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"monitor-connections:{tenant}"},
            )
            answer = callback()
        assert landed(answer) == REFUSED
    [attempt] = attempts(admin_engine, tenant)
    assert (attempt["state"], attempt["refusal_code"], attempt["refused_step"]) == (
        "refused",
        "UNAVAILABLE",
        step,
    )
    assert connections(admin_engine, tenant) == []
    assert refusals(caplog) == ["UNAVAILABLE"]
    assert "lock timeout" not in logged(caplog)


def deactivate(admin_engine, identity):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": identity.tenant_id, "p": identity.principal_id},
        )


def test_mc10_an_administrator_deactivated_after_signing_in_creates_nothing(
    db, runtime, admin_engine, world, collector, login
):
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        location, _ = signed(b, login)
        deactivate(admin_engine, world["admin"])
        _, pairs = login.consent(location)
        assert landed(b.consented(pairs)) == REFUSED
    [attempt] = attempts(admin_engine, tenant)
    assert (attempt["refusal_code"], attempt["refused_step"]) == ("INVALID_ACTOR", "consented")
    assert connections(admin_engine, tenant) == []
    assert events(admin_engine, tenant) == []


def test_mc10_an_administrator_deactivated_before_signing_in_is_refused_there(
    db, runtime, admin_engine, world, collector, login
):
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        url, _ = started(b)
        deactivate(admin_engine, world["admin"])
        _, fields = login.authorize(url)
        assert landed(b.signed_in(fields)) == REFUSED
    [attempt] = attempts(admin_engine, tenant)
    assert (attempt["refusal_code"], attempt["refused_step"]) == ("INVALID_ACTOR", "signed_in")


def test_mc11_updating_consent_records_it_on_the_same_connection(
    db, runtime, admin_engine, world, collector, login
):
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        location, _ = signed(b, login)
        _, pairs = login.consent(location)
        assert landed(b.consented(pairs)) == DONE
        [connection] = connections(admin_engine, tenant)
        first = connection["consented_at"]
        runtime.clock.value += timedelta(minutes=1)
        answer = b.start({"connection_id": str(connection["connection_id"])})
        assert answer.status_code == 200, answer.text
        url = answer.json()["authorize_url"]
        _, fields = login.authorize(url)
        moved = b.signed_in(fields)
        assert moved.status_code == 303
        _, pairs = login.consent(moved.headers["location"])
        assert landed(b.consented(pairs)) == DONE
    [updated] = connections(admin_engine, tenant)
    assert updated["connection_id"] == connection["connection_id"]
    assert updated["consented_at"] >= first
    update = attempts(admin_engine, tenant)[-1]
    assert (update["state"], update["connection_id"], update["label"]) == (
        "consented",
        connection["connection_id"],
        None,
    )
    assert [event["kind"] for event in events(admin_engine, tenant)] == [
        "monitor.connection_created",
        "monitor.consent_recorded",
        "monitor.consent_recorded",
    ]


def test_mc11_an_update_from_another_directory_is_refused_at_the_sign_in(
    db, runtime, admin_engine, world, collector, login
):
    tenant = world["admin"].tenant_id
    with browser(db, runtime, admin_engine, world["admin"], entra_config(collector, login)) as b:
        location, _ = signed(b, login)
        _, pairs = login.consent(location)
        assert landed(b.consented(pairs)) == DONE
        [connection] = connections(admin_engine, tenant)
        url = b.start({"connection_id": str(connection["connection_id"])}).json()["authorize_url"]
        login.directory = OTHER_DIRECTORY
        _, fields = login.authorize(url)
        assert landed(b.signed_in(fields)) == REFUSED
    update = attempts(admin_engine, tenant)[-1]
    assert (update["refusal_code"], update["refused_step"]) == ("DIRECTORY_MISMATCH", "signed_in")
    assert connections(admin_engine, tenant)[0]["directory_ref"] == DIRECTORY


@pytest.mark.parametrize("entra", [False, True])
def test_mc13_the_browser_routes_exist_only_where_entra_is_configured(
    db, runtime, admin_engine, world, collector, login, entra
):
    config = entra_config(collector, login, entra=entra)
    with TestClient(
        create_app(db, runtime=runtime, human=config), base_url=ORIGIN, follow_redirects=False
    ) as client:
        posted = client.post(
            SIGNED_IN,
            content=b"state=x",
            headers={"Origin": LOGIN, "Content-Type": "application/x-www-form-urlencoded"},
        )
        got = client.get(CONSENTED + "?state=x")
    if entra:
        assert landed(posted) == REFUSED and landed(got) == REFUSED
    else:
        assert (posted.status_code, got.status_code) == (404, 404)


def test_mc8_the_two_consent_roles_are_microsofts_template_ids():
    """From Microsoft's built-in roles reference; the module records where and when."""
    assert GLOBAL_ADMINISTRATOR == "62e90394-69f5-4237-9190-012177145e10"
    assert PRIVILEGED_ROLE_ADMINISTRATOR == "e8611ab8-c189-46e8-94e1-60213ab1f814"
    assert UUID(GLOBAL_ADMINISTRATOR) and UUID(PRIVILEGED_ROLE_ADMINISTRATOR)
