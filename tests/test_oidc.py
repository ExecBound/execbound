# SPDX-License-Identifier: AGPL-3.0-only
"""The Google relying party, against an in-process signer: every check has its own refusal.

No network. The ID tokens are signed here with a generated RSA key and the JWKS is served by
an `httpx.MockTransport`, so each test states exactly one thing that is wrong with an
assertion and asserts the code it is refused with.
"""

import base64
import json
import time
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from execbound.oidc import (
    AUTHORIZATION_ENDPOINT,
    JWKS_ENDPOINT,
    TOKEN_ENDPOINT,
    GoogleProvider,
    JwksCache,
    exchange,
    verify_id_token,
)
from execbound.signin import (
    CALLBACK,
    FlowState,
    ProviderConfig,
    SignInRefused,
    new_flow,
    read_flow,
)

CLIENT = "1234.apps.googleusercontent.com"
ORIGIN = "https://app.example.com"
CALLBACK_PATH = CALLBACK.format("google")
CONFIG = ProviderConfig(CLIENT, "a-client-secret", ORIGIN + CALLBACK_PATH)
KID = "signing-key-1"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def integer(value: int) -> str:
    return b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def jwks_document(key, *, kid: str = KID) -> dict:
    numbers = key.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": integer(numbers.n),
                "e": integer(numbers.e),
            }
        ]
    }


def sign(key, claims: dict, *, alg: str = "RS256", kid: str = KID, signature=None) -> str:
    header = b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    payload = b64(json.dumps(claims).encode())
    signed = f"{header}.{payload}".encode("ascii")
    raw = signature or key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{b64(raw)}"


def claims(now: float, **overrides) -> dict:
    base = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT,
        "azp": CLIENT,
        "sub": "109876543210987654321",
        "exp": int(now) + 600,
        "iat": int(now),
        "nonce": "the-nonce",
        "email": "dana@example.com",
        "email_verified": True,
        "name": "Dana Reyes",
    }
    base.update(overrides)
    return base


def cache(key, *, kid: str = KID, counter: list | None = None) -> JwksCache:
    def handler(request: httpx.Request) -> httpx.Response:
        if counter is not None:
            counter.append(str(request.url))
        return httpx.Response(200, json=jwks_document(key, kid=kid))

    return JwksCache(httpx.Client(transport=httpx.MockTransport(handler)))


def test_the_endpoints_are_pinned_and_not_configurable():
    """An operator supplies three values; everything that chooses a host is in the source."""
    assert AUTHORIZATION_ENDPOINT.startswith("https://accounts.google.com/")
    assert TOKEN_ENDPOINT.startswith("https://oauth2.googleapis.com/")
    assert JWKS_ENDPOINT.startswith("https://www.googleapis.com/")
    assert set(vars(CONFIG)) == {"client_id", "client_secret", "redirect_uri"}


def test_a_redirect_uri_belongs_to_this_deployment_and_nowhere_else():
    assert CONFIG.belongs_to(ORIGIN, "google")
    assert not CONFIG.belongs_to("https://evil.example.net", "google")
    # The provider's own callback path, so a Google block cannot claim GitHub's address.
    assert not CONFIG.belongs_to(ORIGIN, "github")
    for wrong in ("https://app.example.com/elsewhere", "ftp://app.example.com" + CALLBACK_PATH):
        with pytest.raises(ValueError):
            ProviderConfig(CLIENT, "secret", wrong).check("google")


def test_the_authorization_request_carries_pkce_a_state_and_a_nonce(key):
    flow = new_flow()
    url = GoogleProvider(CONFIG, cache(key)).begin(flow)
    assert url.startswith(AUTHORIZATION_ENDPOINT + "?")
    query = dict(part.split("=", 1) for part in url.split("?", 1)[1].split("&"))
    assert query["response_type"] == "code"
    assert query["code_challenge_method"] == "S256"
    assert query["state"] == flow.state and query["nonce"] == flow.nonce
    # The challenge travels; the verifier never does.
    assert flow.verifier not in url
    assert query["scope"] == "openid+email"


def test_the_transient_cookie_round_trips_and_refuses_anything_else():
    flow = new_flow()
    assert read_flow(flow.encode()) == flow
    for wrong in ("", "a.b", "a.b.c.d", "a.b.c!", "x" * 600, None, 7):
        with pytest.raises(SignInRefused) as refused:
            read_flow(wrong)
        assert refused.value.code == "INVALID_STATE"


def test_a_well_formed_assertion_names_the_account(key):
    now = time.time()
    account = verify_id_token(sign(key, claims(now)), CONFIG, "the-nonce", cache(key), now=now)
    assert account.subject == "109876543210987654321"
    assert account.email == "dana@example.com"
    assert account.display_name == "Dana Reyes"


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"iss": "https://accounts.evil.example"}, "INVALID_ISSUER"),
        ({"iss": "https://login.microsoftonline.com/x/v2.0"}, "INVALID_ISSUER"),
        ({"aud": "another-client.apps.googleusercontent.com"}, "INVALID_AUDIENCE"),
        ({"azp": "another-client.apps.googleusercontent.com"}, "INVALID_AUDIENCE"),
        ({"exp": 1}, "INVALID_TIME"),
        ({"iat": 1}, "INVALID_TIME"),
        ({"exp": "soon"}, "INVALID_TIME"),
        ({"nonce": "a-different-nonce"}, "INVALID_NONCE"),
        ({"nonce": None}, "INVALID_NONCE"),
        # Outside ASCII, which `secrets.compare_digest` refuses to compare as text.
        ({"nonce": "the-nonce-ü"}, "INVALID_NONCE"),
        # A lone surrogate, which JSON can carry and UTF-8 cannot encode.
        ({"nonce": "\ud800"}, "INVALID_NONCE"),
        ({"email_verified": False}, "EMAIL_UNVERIFIED"),
        ({"email_verified": "true"}, "EMAIL_UNVERIFIED"),
        ({"email": None}, "NO_EMAIL"),
        ({"sub": ""}, "NO_SUBJECT"),
    ],
)
def test_one_wrong_claim_is_one_refusal(key, overrides, code):
    now = time.time()
    token = sign(key, claims(now, **overrides))
    with pytest.raises(SignInRefused) as refused:
        verify_id_token(token, CONFIG, "the-nonce", cache(key), now=now)
    assert refused.value.code == code


def test_a_bare_accounts_google_com_issuer_is_accepted(key):
    """Google emits the issuer both ways and its own documentation says so."""
    now = time.time()
    token = sign(key, claims(now, iss="accounts.google.com"))
    assert verify_id_token(token, CONFIG, "the-nonce", cache(key), now=now).subject


@pytest.mark.parametrize("alg", ["none", "HS256", "RS512", "ES256"])
def test_an_assertion_naming_another_algorithm_is_refused_before_any_key_is_fetched(key, alg):
    now = time.time()
    fetches: list[str] = []
    token = sign(key, claims(now), alg=alg)
    with pytest.raises(SignInRefused) as refused:
        verify_id_token(token, CONFIG, "the-nonce", cache(key, counter=fetches), now=now)
    assert refused.value.code == "INVALID_ALGORITHM"
    assert fetches == []


def test_a_forged_signature_is_refused(key):
    now = time.time()
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = sign(
        key, claims(now), signature=other.sign(b"anything", padding.PKCS1v15(), hashes.SHA256())
    )
    with pytest.raises(SignInRefused) as refused:
        verify_id_token(token, CONFIG, "the-nonce", cache(key), now=now)
    assert refused.value.code == "INVALID_SIGNATURE"


def test_an_assertion_signed_by_another_key_is_refused(key):
    now = time.time()
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = sign(other, claims(now))
    with pytest.raises(SignInRefused) as refused:
        verify_id_token(token, CONFIG, "the-nonce", cache(key), now=now)
    assert refused.value.code == "INVALID_SIGNATURE"


def test_an_unknown_key_id_refetches_once_and_then_refuses(key):
    now = time.time()
    fetches: list[str] = []
    keys = cache(key, kid="a-different-key", counter=fetches)
    token = sign(key, claims(now))
    with pytest.raises(SignInRefused) as refused:
        verify_id_token(token, CONFIG, "the-nonce", keys, now=now)
    assert refused.value.code == "UNKNOWN_KEY"
    assert len(fetches) == 1
    # A second assertion naming the same unknown key fetches once more and no more, so a
    # stream of them cannot make this server call Google in a loop.
    with pytest.raises(SignInRefused):
        verify_id_token(token, CONFIG, "the-nonce", keys, now=now)
    assert len(fetches) == 2


def test_a_cached_key_is_not_refetched(key):
    now = time.time()
    fetches: list[str] = []
    keys = cache(key, counter=fetches)
    for _ in range(3):
        verify_id_token(sign(key, claims(now)), CONFIG, "the-nonce", keys, now=now)
    assert len(fetches) == 1
    assert fetches[0] == JWKS_ENDPOINT


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", "!!!.###.$$$", "x" * 9000, None, 7])
def test_a_token_that_is_not_one_is_refused(key, token):
    with pytest.raises(SignInRefused) as refused:
        verify_id_token(token, CONFIG, "the-nonce", cache(key), now=time.time())
    assert refused.value.code in {"INVALID_TOKEN", "INVALID_ALGORITHM"}


def test_the_exchange_sends_the_verifier_and_keeps_only_the_id_token():
    sent: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent.update(dict(part.split("=", 1) for part in request.content.decode().split("&")))
        return httpx.Response(
            200, json={"id_token": "header.payload.signature", "access_token": "not-kept"}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    flow = FlowState("state", "nonce", "verifier")
    assert exchange(CONFIG, "the-code", flow.verifier, http=client) == "header.payload.signature"
    assert sent["grant_type"] == "authorization_code"
    assert sent["code_verifier"] == "verifier"
    assert sent["code"] == "the-code"


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (400, {"error": "invalid_grant"}),
        (200, {"access_token": "only-this"}),
        (200, {"id_token": 7}),
        (200, {"id_token": ""}),
        (500, {}),
    ],
)
def test_an_exchange_that_answers_anything_else_is_refused(status, body):
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json=body))
    )
    with pytest.raises(SignInRefused) as refused:
        exchange(CONFIG, "the-code", "verifier", http=client)
    assert refused.value.code == "EXCHANGE_REFUSED"


def test_a_provider_that_cannot_be_reached_is_its_own_refusal():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(SignInRefused) as refused:
        exchange(CONFIG, "the-code", "verifier", http=client)
    assert refused.value.code == "PROVIDER_UNAVAILABLE"
    with pytest.raises(SignInRefused) as missing:
        JwksCache(client).key(str(uuid4()))
    assert missing.value.code == "PROVIDER_UNAVAILABLE"
