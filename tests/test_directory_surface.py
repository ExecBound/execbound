# SPDX-License-Identifier: AGPL-3.0-only
"""The directory routes as a browser reaches them: the flow, the self-link, `/invite`.

The directory is `tests/directory_fixtures.StandIn` behind an injected transport, so what these
tests are about is the route: the transient cookie, the `state` comparison, the refusals that
all look alike, the hint cookie, and the session that comes out being the same session a
credential produces. What the relying party verifies is `tests/test_directory.py`.
"""

import logging
import re
import secrets
from html import unescape
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from conftest import assert_secret_free
from fastapi.testclient import TestClient
from idp_fixtures import (
    CLIENT_ID,
    CLIENT_SECRET,
    ISSUER,
    NAME,
    SUBJECT,
    TENANT_ID,
    USERNAME,
    StandIn,
    directory_ec_key,
    directory_key,
    discovery_document,
)
from sqlalchemy import text
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_sign_in_surface import landed_at

from execbound import directory_store as store
from execbound.app import create_app
from execbound.directory import (
    DirectoryAccount,
    DirectoryConfig,
    DirectoryRefused,
    Discovery,
    new_flow,
)
from execbound.envelope import KEY_BYTES, KeyRing
from execbound.surfaces.directory_pages import MAX_CODE_BYTES
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

ORIGIN = "http://127.0.0.1"
RING = KeyRing("dir-v1", {"dir-v1": b"\x22" * KEY_BYTES})
APPROVER_SUBJECT = "77777777-0000-4000-8000-0000000000cc"
REFUSED = "That account cannot sign in here."
INVALID_CODE = "This invitation is not valid."


def form_values(html, action):
    for found, body in re.findall(r'<form[^>]*action="([^"]+)"[^>]*>(.*?)</form>', html, re.S):
        if found == action:
            return {
                name: unescape(value)
                for name, value in re.findall(
                    r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', body
                )
            }
    raise AssertionError(f"No form posting to {action}")


@pytest.fixture(scope="module")
def key():
    return directory_key()


@pytest.fixture
def stand_in(key):
    return StandIn(key)


@pytest.fixture
def settings(stand_in):
    return DirectoryConfig(RING, ORIGIN, stand_in.client())


@pytest.fixture
def config(settings):
    return HumanConfig(
        ORIGIN,
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        directory=settings,
    )


@pytest.fixture
def bare_config():
    """A deployment given no key ring: every route here answers 404."""
    return HumanConfig(ORIGIN, TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}))


def build(db, runtime, human):
    made = TestClient(create_app(db, runtime=runtime, human=human), base_url=ORIGIN)
    made.follow_redirects = False
    return made


@pytest.fixture
def client(db, runtime, config):
    with build(db, runtime, config) as made:
        yield made


def person(engine, tenant, kind, *, active=True):
    principal = uuid4()
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, active, space_id)"
                " VALUES (:t, :p, :k, :a, NULL)"
            ),
            {"t": tenant, "p": principal, "k": kind, "a": active},
        )
    return principal


@pytest.fixture
def tenant(db, runtime, world, admin_engine, settings):
    """A tenant whose administrator registered, verified and enabled a directory."""
    identity = world["admin"]
    document = discovery_document()
    discovery = Discovery(
        ISSUER,
        document["authorization_endpoint"],
        document["token_endpoint"],
        document["jwks_uri"],
        TENANT_ID,
    )
    provider = store.register(
        db,
        settings,
        identity.tenant_id,
        identity.principal_id,
        name="Contoso",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        subject_claim="oid",
        discovery=discovery,
        clock=runtime.clock,
    )
    store.link_self(
        db,
        identity.tenant_id,
        identity.principal_id,
        provider,
        DirectoryAccount(SUBJECT, NAME, USERNAME, "refresh"),
        clock=runtime.clock,
    )
    store.set_state(
        db, identity.tenant_id, identity.principal_id, provider, "enabled", clock=runtime.clock
    )
    return {
        "tenant_id": identity.tenant_id,
        "admin": identity.principal_id,
        "approver": world["human"].principal_id,
        "provider": provider,
    }


# ---- the route the whole thing hangs on -------------------------------------------------


def test_the_callback_is_the_directorys_and_not_a_configured_providers(client):
    """`/login/{provider}/callback` would match this path with `provider = "directory"`.

    It is declared first for exactly that reason. A 404 here would mean a customer's browser
    came back from their directory to a page that told them nothing.
    """
    answer = client.get("/login/directory/callback")
    assert answer.status_code == 403
    assert REFUSED in answer.text


def test_every_directory_route_is_absent_without_a_key_ring(db, runtime, bare_config):
    with build(db, runtime, bare_config) as made:
        assert made.get("/invite").status_code == 404
        assert made.get("/login/directory/callback").status_code == 404
        assert (
            made.post(
                f"/login/directory/{uuid4()}",
                data={"csrf": "x"},
                headers={"Origin": ORIGIN},
            ).status_code
            == 404
        )


def test_a_provider_id_nothing_registered_answers_404(client):
    opened = client.get("/login")
    values = {"csrf": opened.cookies.get("eb_login")}
    answer = client.post(f"/login/directory/{uuid4()}", data=values, headers={"Origin": ORIGIN})
    assert answer.status_code == 404


# ---- the flow ----------------------------------------------------------------------------


def start(client, provider):
    opened = client.get("/login")
    values = {"csrf": opened.cookies.get("eb_login")}
    return client.post(f"/login/directory/{provider}", data=values, headers={"Origin": ORIGIN})


def test_a_start_redirects_to_the_directory_and_sets_one_lax_cookie(client, tenant, stand_in):
    answer = start(client, tenant["provider"])
    assert answer.status_code == 303
    location = answer.headers["location"]
    assert location.startswith(discovery_document()["authorization_endpoint"])
    query = parse_qs(urlsplit(location).query)
    cookie = answer.headers["set-cookie"]
    assert "samesite=lax" in cookie.lower()
    assert "httponly" in cookie.lower()
    assert query["state"][0] in cookie
    # The verifier is in the cookie and never in the address bar.
    assert "code_verifier" not in query


def test_a_start_without_the_csrf_field_is_refused(client, tenant):
    client.get("/login")
    answer = client.post(
        f"/login/directory/{tenant['provider']}", data={"csrf": "wrong"}, headers={"Origin": ORIGIN}
    )
    assert answer.status_code == 403


def test_a_start_from_another_origin_is_refused(client, tenant):
    opened = client.get("/login")
    answer = client.post(
        f"/login/directory/{tenant['provider']}",
        data={"csrf": opened.cookies.get("eb_login")},
        headers={"Origin": "https://elsewhere.example"},
    )
    assert answer.status_code == 403


def test_a_draft_provider_starts_no_public_flow(db, runtime, client, settings, world):
    identity = world["admin"]
    document = discovery_document()
    provider = store.register(
        db,
        settings,
        identity.tenant_id,
        identity.principal_id,
        name="Contoso",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        subject_claim="oid",
        discovery=Discovery(
            ISSUER,
            document["authorization_endpoint"],
            document["token_endpoint"],
            document["jwks_uri"],
            TENANT_ID,
        ),
        clock=runtime.clock,
    )
    assert start(client, provider).status_code == 404


def linked_approver(db, runtime, tenant):
    store.link_person(
        db,
        tenant["tenant_id"],
        tenant["admin"],
        tenant["approver"],
        tenant["provider"],
        APPROVER_SUBJECT,
        clock=runtime.clock,
    )


def complete(client, started, stand_in, *, code="the-code", state=None, extra=None):
    location = started.headers["location"]
    query = parse_qs(urlsplit(location).query)
    stand_in.nonce = query["nonce"][0]
    parameters = {"code": code, "state": state or query["state"][0], **(extra or {})}
    return client.get("/login/directory/callback", params=parameters)


def test_a_linked_person_signs_in_and_the_browser_remembers_the_provider(
    db, runtime, client, tenant, stand_in
):
    linked_approver(db, runtime, tenant)
    stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
    answer = complete(client, start(client, tenant["provider"]), stand_in)
    assert landed_at(answer) == "/approvals"
    cookies = answer.headers.get_list("set-cookie")
    assert any(name.startswith("eb_session=") for name in cookies)
    assert any(str(tenant["provider"]) in name for name in cookies)
    # The transient cookie is deleted on first use, so a replay has nothing to match.
    assert any(name.startswith("eb_dirflow=;") or 'eb_dirflow=""' in name for name in cookies)
    assert_secret_free(answer.text)


def test_a_directory_signing_with_es256_signs_a_linked_person_in(
    db, runtime, client, tenant, stand_in
):
    """A directory whose ID tokens are ES256, under a P-256 key in its key set, reaches the
    same session an RS256 directory does."""
    linked_approver(db, runtime, tenant)
    stand_in.key, stand_in.alg = directory_ec_key(), "ES256"
    stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
    answer = complete(client, start(client, tenant["provider"]), stand_in)
    assert landed_at(answer) == "/approvals"
    assert any(name.startswith("eb_session=") for name in answer.headers.get_list("set-cookie"))
    assert len(stand_in.fetches) == 1
    assert_secret_free(answer.text)


def test_the_remembered_provider_puts_one_button_on_the_sign_in_page(
    db, runtime, client, tenant, stand_in
):
    linked_approver(db, runtime, tenant)
    stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
    complete(client, start(client, tenant["provider"]), stand_in)
    client.cookies.delete("eb_session")
    page = client.get("/login")
    assert "Continue with Contoso" in page.text
    assert form_values(page.text, f"/login/directory/{tenant['provider']}")
    # And that page's policy names the host its own button redirects a browser to.
    assert "login.microsoftonline.com" in page.headers["content-security-policy"]


def test_a_browser_that_has_never_been_through_a_directory_is_told_nothing(client, tenant):
    page = client.get("/login")
    assert "Continue with Contoso" not in page.text
    assert "login.microsoftonline.com" not in page.headers["content-security-policy"]


def test_a_replayed_callback_has_nothing_to_match(db, runtime, client, tenant, stand_in):
    linked_approver(db, runtime, tenant)
    stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
    started = start(client, tenant["provider"])
    first = complete(client, started, stand_in)
    assert landed_at(first) == "/approvals"
    client.cookies.delete("eb_dirflow")
    again = complete(client, started, stand_in)
    assert again.status_code == 403
    assert REFUSED in again.text


def test_a_state_that_does_not_match_the_cookie_is_refused(db, runtime, client, tenant, stand_in):
    linked_approver(db, runtime, tenant)
    started = start(client, tenant["provider"])
    answer = complete(client, started, stand_in, state="not-the-state")
    assert answer.status_code == 403
    assert REFUSED in answer.text


def test_a_state_outside_ascii_is_refused_as_a_state_and_not_answered_503(
    db, runtime, client, tenant, stand_in
):
    """Compared as `str`, a state holding a character outside ASCII made
    `hmac.compare_digest` raise, and the callback answered 503 instead of refusing it."""
    linked_approver(db, runtime, tenant)
    started = start(client, tenant["provider"])
    answer = complete(client, started, stand_in, state="Zustand-ü")
    assert answer.status_code == 403
    assert REFUSED in answer.text


def test_a_code_as_long_as_entra_issues_signs_in(db, runtime, client, tenant, stand_in):
    """Entra ID's authorization code for the lab tenant on 21 September 2026 was 2,208
    characters, and the callback refused any code over 2,048, logged as `INVALID_STATE`, so
    the first Test sign-in against a real directory came back "That account cannot sign in
    here." RFC 6749 leaves a code's size to the issuer, and Microsoft's have run past 4,000.
    """
    linked_approver(db, runtime, tenant)
    stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
    for length in (2208, 4096):
        answer = complete(client, start(client, tenant["provider"]), stand_in, code="c" * length)
        assert landed_at(answer) == "/approvals", length


def test_a_code_past_the_bound_is_refused_under_its_own_name(
    db, runtime, client, tenant, stand_in, caplog
):
    """Still bounded, because this server sends the code on to the token endpoint; and a code
    that is missing or too long is named as that rather than as a state that did not match."""
    linked_approver(db, runtime, tenant)
    for code in ("", "c" * (MAX_CODE_BYTES + 1)):
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="execbound"):
            answer = complete(client, start(client, tenant["provider"]), stand_in, code=code)
        assert answer.status_code == 403 and REFUSED in answer.text
        written = [
            getattr(record, "execbound", {}).get("code")
            for record in caplog.records
            if getattr(record, "execbound", {}).get("event") == "directory.refused"
        ]
        assert written == ["INVALID_CODE"], (len(code), written)


def test_a_callback_the_directory_refused_says_what_every_refusal_says(client, tenant):
    start(client, tenant["provider"])
    answer = client.get("/login/directory/callback", params={"error": "access_denied"})
    assert answer.status_code == 403
    assert REFUSED in answer.text


def test_a_subject_nobody_linked_is_refused_and_creates_nothing(
    db, runtime, client, tenant, stand_in
):
    stand_in.claim_changes = {"oid": "99999999-0000-4000-8000-0000000000ee"}
    answer = complete(client, start(client, tenant["provider"]), stand_in)
    assert answer.status_code == 403
    assert REFUSED in answer.text
    assert store.locate_link(db, tenant["provider"], "99999999-0000-4000-8000-0000000000ee") is None


def test_an_issuer_the_directory_names_must_be_the_one_the_flow_began_at(
    db, runtime, client, tenant, stand_in
):
    """RFC 9207, and the one parameter a mix-up attack would have to get right."""
    linked_approver(db, runtime, tenant)
    stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
    answer = complete(
        client,
        start(client, tenant["provider"]),
        stand_in,
        extra={"iss": "https://elsewhere.example"},
    )
    assert answer.status_code == 403


# ---- the invitation ------------------------------------------------------------------------


def test_the_invite_page_names_nothing_before_the_code_is_right(client, tenant):
    page = client.get("/invite")
    assert page.status_code == 200
    assert "Contoso" not in page.text
    assert str(tenant["tenant_id"]) not in page.text
    assert form_values(page.text, "/invite")


def test_a_code_is_redeemed_and_the_next_step_names_the_directory(db, runtime, client, tenant):
    minted = store.invite(
        db, tenant["tenant_id"], tenant["admin"], tenant["approver"], tenant["provider"]
    )
    page = client.get("/invite")
    values = form_values(page.text, "/invite")
    answer = client.post(
        "/invite", data={**values, "code": minted.code}, headers={"Origin": ORIGIN}
    )
    assert answer.status_code == 200
    assert "Contoso" in answer.text
    assert discovery_document()["authorization_endpoint"] in answer.text
    # The code is never echoed back to the page, and never in an address.
    assert minted.code not in answer.text
    assert_secret_free(answer.text)


def test_the_invited_person_is_bound_by_the_sign_in_that_follows(
    db, runtime, client, tenant, stand_in
):
    minted = store.invite(
        db, tenant["tenant_id"], tenant["admin"], tenant["approver"], tenant["provider"]
    )
    page = client.get("/invite")
    values = form_values(page.text, "/invite")
    answer = client.post(
        "/invite", data={**values, "code": minted.code}, headers={"Origin": ORIGIN}
    )
    location = re.search(r'href="([^"]+authorize[^"]*)"', answer.text).group(1)
    query = parse_qs(urlsplit(unescape(location)).query)
    stand_in.nonce = query["nonce"][0]
    stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
    signed = client.get(
        "/login/directory/callback",
        params={"code": "the-code", "state": query["state"][0]},
    )
    assert landed_at(signed) == "/approvals"
    assert store.locate_link(db, tenant["provider"], APPROVER_SUBJECT) == (
        tenant["tenant_id"],
        tenant["approver"],
    )


@pytest.mark.parametrize("code", ["nonsense", "ebv1.not.a.code", ""])
def test_a_code_that_is_not_one_gets_the_one_sentence(client, tenant, code):
    page = client.get("/invite")
    values = form_values(page.text, "/invite")
    answer = client.post("/invite", data={**values, "code": code}, headers={"Origin": ORIGIN})
    assert answer.status_code == 403
    assert INVALID_CODE in answer.text


def test_the_invite_form_needs_the_exact_origin_and_the_cookie(client, tenant):
    page = client.get("/invite")
    values = form_values(page.text, "/invite")
    elsewhere = client.post(
        "/invite",
        data={**values, "code": "x"},
        headers={"Origin": "https://elsewhere.example"},
    )
    assert elsewhere.status_code == 403
    forged = client.post("/invite", data={"csrf": "wrong", "code": "x"}, headers={"Origin": ORIGIN})
    assert forged.status_code == 403


# ---- the self-link -------------------------------------------------------------------------


def test_the_self_link_route_needs_a_session(client, tenant):
    answer = client.get(f"/login/directory/{tenant['provider']}/link")
    assert answer.status_code == 401


# ---- the flow cookie is authenticated, because the callback cannot read the session --------


def test_the_flow_cookie_carries_a_mac_and_a_forged_one_is_refused(client, tenant, settings):
    """The callback is the directory's cross-site redirect back, so the SameSite=Strict session
    cookie is not sent with it. Which invitation is being redeemed and who is linking their own
    account therefore come from this cookie, and a cookie a caller could write would be an
    account takeover: they would name somebody else's principal and bind their own directory
    account to it."""
    started = start(client, tenant["provider"])
    sealed = started.headers["set-cookie"].split("=", 1)[1].split(";")[0]
    assert settings.open_flow(sealed).provider_id == str(tenant["provider"])
    payload, _, _ = sealed.rpartition(".")
    for forged in (payload, sealed[:-1] + ("0" if sealed[-1] != "0" else "1"), "x.y.z"):
        with pytest.raises(DirectoryRefused):
            settings.open_flow(forged)


def test_a_forged_flow_cookie_binds_nobody(db, runtime, client, tenant, stand_in):
    """A cookie naming another person's principal, with a state the caller also chose."""
    flow = new_flow(str(tenant["provider"]), link_principal=str(tenant["approver"]))
    client.cookies.set("eb_dirflow", flow.encode())
    stand_in.nonce = flow.nonce
    stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
    answer = client.get(
        "/login/directory/callback", params={"code": "the-code", "state": flow.state}
    )
    assert answer.status_code == 403
    assert REFUSED in answer.text
    assert store.locate_link(db, tenant["provider"], APPROVER_SUBJECT) is None


def test_a_person_links_their_own_account_without_the_session_cookie_coming_back(
    db, runtime, client, tenant, stand_in, settings
):
    """The whole point of the MAC: this round trip is what a real browser does."""
    flow = new_flow(str(tenant["provider"]), link_principal=str(tenant["approver"]))
    client.cookies.set("eb_dirflow", settings.seal_flow(flow))
    stand_in.nonce = flow.nonce
    stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
    answer = client.get(
        "/login/directory/callback", params={"code": "the-code", "state": flow.state}
    )
    # An approver lands on their own settings; an administrator lands on tenant settings.
    assert landed_at(answer, session=False) == "/settings"
    assert store.locate_link(db, tenant["provider"], APPROVER_SUBJECT) == (
        tenant["tenant_id"],
        tenant["approver"],
    )
    # No session was issued: the person already had one, and this bound an account.
    assert not any(name.startswith("eb_session=") for name in answer.headers.get_list("set-cookie"))


def test_a_self_link_for_a_principal_who_may_not_act_is_refused(
    db, runtime, client, tenant, stand_in, settings, admin_engine
):
    """The database is what checks the cookie's principal, not the route."""
    stranger = person(admin_engine, tenant["tenant_id"], "HUMAN_APPROVER", active=False)
    flow = new_flow(str(tenant["provider"]), link_principal=str(stranger))
    client.cookies.set("eb_dirflow", settings.seal_flow(flow))
    stand_in.nonce = flow.nonce
    stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
    answer = client.get(
        "/login/directory/callback", params={"code": "the-code", "state": flow.state}
    )
    assert answer.status_code == 403
    assert store.locate_link(db, tenant["provider"], APPROVER_SUBJECT) is None
