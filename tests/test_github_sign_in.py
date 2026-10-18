# SPDX-License-Identifier: AGPL-3.0-only
"""The GitHub relying party, against an in-process API: what it accepts and what it will not.

GitHub hands back no signed assertion, so what stands in for verification is the pair of
authenticated calls below and the rule about which address may find a person. Each test
states one thing GitHub answered and asserts the refusal it earns.
"""

import httpx
import pytest

from execbound.github import (
    AUTHORIZATION_ENDPOINT,
    EMAILS_ENDPOINT,
    SCOPE,
    TOKEN_ENDPOINT,
    USER_ENDPOINT,
    GitHubProvider,
)
from execbound.signin import CALLBACK, ProviderConfig, SignInRefused, new_flow

CLIENT = "Iv1.0123456789abcdef"
ORIGIN = "https://app.example.com"
CONFIG = ProviderConfig(CLIENT, "a-client-secret", ORIGIN + CALLBACK.format("github"))
TOKEN = "gho_thisisnotarealtoken"  # nosec B105 - a fixture value, not a credential
USER = {"id": 4242, "login": "dana", "name": "Dana Reyes"}
PRIMARY = {"email": "dana@example.com", "primary": True, "verified": True}
OTHER = {"email": "old@example.com", "primary": False, "verified": True}
UNVERIFIED = {"email": "dana@example.com", "primary": True, "verified": False}


def provider(
    *,
    token: dict | None = None,
    token_status: int = 200,
    user: object = USER,
    emails: object = (PRIMARY, OTHER),
    seen: list | None = None,
) -> GitHubProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append((str(request.url), dict(request.headers)))
        if str(request.url) == TOKEN_ENDPOINT:
            body = token if token is not None else {"access_token": TOKEN, "scope": SCOPE}
            return httpx.Response(token_status, json=body)
        if str(request.url) == USER_ENDPOINT:
            return httpx.Response(200, json=user)
        if str(request.url) == EMAILS_ENDPOINT:
            return httpx.Response(200, json=list(emails) if type(emails) is tuple else emails)
        return httpx.Response(404, json={})

    return GitHubProvider(CONFIG, httpx.Client(transport=httpx.MockTransport(handler)))


def test_the_endpoints_are_pinned_and_the_scope_is_one_thing():
    assert AUTHORIZATION_ENDPOINT.startswith("https://github.com/")
    assert TOKEN_ENDPOINT.startswith("https://github.com/")
    assert USER_ENDPOINT == "https://api.github.com/user"
    assert EMAILS_ENDPOINT == "https://api.github.com/user/emails"
    assert SCOPE == "user:email"


def test_the_authorization_request_carries_pkce_and_a_state():
    flow = new_flow()
    url = provider().begin(flow)
    assert url.startswith(AUTHORIZATION_ENDPOINT + "?")
    query = dict(part.split("=", 1) for part in url.split("?", 1)[1].split("&"))
    assert query["state"] == flow.state
    assert query["code_challenge_method"] == "S256"
    assert query["scope"] == "user%3Aemail"
    assert query["allow_signup"] == "false"
    # The challenge travels; the verifier never does.
    assert flow.verifier not in url


def test_a_complete_flow_names_the_account_by_its_numeric_id():
    account = provider().complete("the-code", new_flow(), now=0.0)
    assert account.provider == "github"
    # The id, never the login: a username can be released and claimed by somebody else.
    assert account.subject == "4242"
    assert account.email == "dana@example.com"
    assert account.display_name == "Dana Reyes"


def test_the_access_token_authenticates_the_two_calls_and_is_kept_nowhere():
    seen: list = []
    account = provider(seen=seen).complete("the-code", new_flow(), now=0.0)
    called = [url for url, _ in seen]
    assert called == [TOKEN_ENDPOINT, USER_ENDPOINT, EMAILS_ENDPOINT]
    for _url, headers in seen[1:]:
        assert headers["authorization"] == f"Bearer {TOKEN}"
        assert headers["x-github-api-version"]
    assert TOKEN not in repr(account)
    assert all(TOKEN != value for value in vars(account).values())


def test_the_verifier_and_the_redirect_uri_are_sent_to_the_token_endpoint():
    sent: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == TOKEN_ENDPOINT:
            sent.update(dict(part.split("=", 1) for part in request.content.decode().split("&")))
            return httpx.Response(200, json={"access_token": TOKEN, "scope": SCOPE})
        if str(request.url) == USER_ENDPOINT:
            return httpx.Response(200, json=USER)
        return httpx.Response(200, json=[PRIMARY])

    flow = new_flow()
    GitHubProvider(CONFIG, httpx.Client(transport=httpx.MockTransport(handler))).complete(
        "the-code", flow, now=0.0
    )
    assert sent["code_verifier"] == flow.verifier
    assert sent["code"] == "the-code"
    assert sent["redirect_uri"] == CONFIG.redirect_uri.replace(":", "%3A").replace("/", "%2F")


@pytest.mark.parametrize(
    ("token", "status", "code"),
    [
        ({"error": "bad_verification_code"}, 200, "EXCHANGE_REFUSED"),
        ({"access_token": TOKEN, "scope": "repo"}, 200, "SCOPE_REFUSED"),
        ({"access_token": TOKEN}, 200, "SCOPE_REFUSED"),
        ({"access_token": "", "scope": SCOPE}, 200, "EXCHANGE_REFUSED"),
        ({"scope": SCOPE}, 200, "EXCHANGE_REFUSED"),
        ({"access_token": TOKEN, "scope": SCOPE}, 401, "EXCHANGE_REFUSED"),
    ],
)
def test_an_exchange_that_answers_anything_else_is_refused(token, status, code):
    with pytest.raises(SignInRefused) as refused:
        provider(token=token, token_status=status).complete("the-code", new_flow(), now=0.0)
    assert refused.value.code == code


@pytest.mark.parametrize(
    ("emails", "code"),
    [
        # Nothing primary and verified: no address is evidence of anything.
        ([UNVERIFIED], "EMAIL_UNVERIFIED"),
        ([OTHER], "EMAIL_UNVERIFIED"),
        ([], "EMAIL_UNVERIFIED"),
        ([{"email": "dana@example.com", "primary": True}], "EMAIL_UNVERIFIED"),
        ([{"email": "dana@example.com", "verified": True}], "EMAIL_UNVERIFIED"),
        # Two primaries is an answer this server does not understand, and guessing which to
        # trust is exactly the wrong move.
        ([PRIMARY, dict(PRIMARY, email="other@example.com")], "PROVIDER_REFUSED"),
        ({"email": "dana@example.com"}, "PROVIDER_REFUSED"),
    ],
)
def test_only_a_primary_and_verified_address_may_find_a_person(emails, code):
    with pytest.raises(SignInRefused) as refused:
        provider(emails=emails).complete("the-code", new_flow(), now=0.0)
    assert refused.value.code == code


def test_an_unverified_address_is_refused_even_when_it_matches_a_person():
    """The whole attack this stops: adding somebody else's address to a GitHub account and
    signing in as them. GitHub will hold an unverified address; it is never evidence."""
    with pytest.raises(SignInRefused) as refused:
        provider(emails=[UNVERIFIED]).complete("the-code", new_flow(), now=0.0)
    assert refused.value.code == "EMAIL_UNVERIFIED"


@pytest.mark.parametrize(
    "user",
    [
        {"login": "dana"},
        {"id": "4242", "login": "dana"},
        {"id": 0, "login": "dana"},
        {"id": -1, "login": "dana"},
        {"id": True, "login": "dana"},
    ],
)
def test_an_account_with_no_usable_identifier_is_refused(user):
    with pytest.raises(SignInRefused) as refused:
        provider(user=user).complete("the-code", new_flow(), now=0.0)
    assert refused.value.code in {"NO_SUBJECT", "PROVIDER_REFUSED"}


def test_the_login_stands_in_for_a_missing_name_and_is_only_ever_a_hint():
    account = provider(user={"id": 4242, "login": "dana", "name": None}).complete(
        "the-code", new_flow(), now=0.0
    )
    assert account.display_name == "dana"
    assert account.subject == "4242"


def test_a_provider_that_cannot_be_reached_is_its_own_refusal():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope", request=request)

    failing = GitHubProvider(CONFIG, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(SignInRefused) as refused:
        failing.complete("the-code", new_flow(), now=0.0)
    assert refused.value.code == "PROVIDER_UNAVAILABLE"


def test_an_api_that_refuses_the_token_is_refused_rather_than_guessed():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == TOKEN_ENDPOINT:
            return httpx.Response(200, json={"access_token": TOKEN, "scope": SCOPE})
        return httpx.Response(403, json={"message": "Forbidden"})

    with pytest.raises(SignInRefused) as refused:
        GitHubProvider(CONFIG, httpx.Client(transport=httpx.MockTransport(handler))).complete(
            "the-code", new_flow(), now=0.0
        )
    assert refused.value.code == "PROVIDER_REFUSED"
