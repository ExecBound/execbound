# SPDX-License-Identifier: AGPL-3.0-only
"""The Microsoft relying party, against an in-process signer: every check has its own refusal.

No network. ID tokens are signed here with a generated RSA key and the key set and token
endpoint are served by an `httpx.MockTransport`, so each case states exactly one thing wrong
with an assertion and the code it is refused with. The provider is multi-tenant through the
`organizations` authority, so what stands in for a single pinned tenant is checked here: the
issuer must be the token's own tenant's, the personal-account tenant is refused, the subject is
the tenant and object identifiers together, and the address is believed only when Microsoft
says the tenant verified its domain (`xms_edov`).
"""

import base64
import json
import re
import secrets
import time
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_emergency_stop import audit
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound.account_links import begin_link, finish_link
from execbound.app import create_app
from execbound.microsoft import (
    AUTHORIZATION_ENDPOINT,
    AUTHORIZATION_ORIGIN,
    JWKS_ENDPOINT,
    PERSONAL_TENANT,
    TOKEN_ENDPOINT,
    MicrosoftProvider,
    keys,
    verify_id_token,
)
from execbound.oidc import JwksCache
from execbound.passwords import issue_reset, redeem_reset, sign_in_with_password
from execbound.replay.export import export_history
from execbound.replay.verify import _INFORMATIONAL, verify_export
from execbound.signin import (
    CALLBACK,
    ExternalAccount,
    FlowState,
    ProviderConfig,
    SignInRefused,
    challenge,
    new_flow,
)
from execbound.surfaces.configuration import read_configuration, sign_in_providers
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import issue_session, load_session
from execbound.surfaces.tokens import TokenKeys
from execbound.user_accounts import provider_sign_in

CLIENT = "6f0b7c1e-2a3d-4e5f-8a9b-0c1d2e3f4a5b"
ORIGIN = "https://app.example.com"
CONFIG = ProviderConfig(CLIENT, "a-client-secret", ORIGIN + CALLBACK.format("microsoft"))
KID = "microsoft-signing-key"
TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
OTHER_TENANT = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
OBJECT = "00000000-0000-0000-66f3-3332eca7ea81"
NONCE = "the-nonce"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def integer(value: int) -> str:
    return b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def key_set(key, *, kid: str = KID) -> dict:
    numbers = key.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
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
    """A v2.0 ID token as Microsoft issues one with the `email` and `xms_edov` optional claims."""
    base = {
        "ver": "2.0",
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "aud": CLIENT,
        "exp": int(now) + 3600,
        "iat": int(now),
        "nbf": int(now),
        "nonce": NONCE,
        "tid": TENANT,
        "oid": OBJECT,
        "sub": "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ",
        "email": "dana@contoso.example",
        "xms_edov": True,
        "preferred_username": "someone-else@contoso.example",
        "name": "Dana Reyes",
    }
    base.update(overrides)
    return {name: value for name, value in base.items() if value is not ...}


def cache(key, *, kid: str = KID, counter: list | None = None) -> JwksCache:
    def handler(request: httpx.Request) -> httpx.Response:
        if counter is not None:
            counter.append(str(request.url))
        return httpx.Response(200, json=key_set(key, kid=kid))

    return JwksCache(httpx.Client(transport=httpx.MockTransport(handler)), endpoint=JWKS_ENDPOINT)


def refused(token, keys, *, now) -> str:
    with pytest.raises(SignInRefused) as raised:
        verify_id_token(token, CONFIG, NONCE, keys, now=now)
    return raised.value.code


DEFECTS = [
    ({"ver": "1.0"}, "INVALID_TOKEN"),
    ({"ver": ...}, "INVALID_TOKEN"),
    ({"tid": ...}, "INVALID_TENANT"),
    ({"tid": TENANT.upper()}, "INVALID_TENANT"),
    ({"tid": "contoso.example"}, "INVALID_TENANT"),
    (
        {
            "tid": PERSONAL_TENANT,
            "iss": f"https://login.microsoftonline.com/{PERSONAL_TENANT}/v2.0",
        },
        "INVALID_TENANT",
    ),
    ({"iss": f"https://login.microsoftonline.com/{OTHER_TENANT}/v2.0"}, "INVALID_ISSUER"),
    ({"iss": "https://login.microsoftonline.com/{tenantid}/v2.0"}, "INVALID_ISSUER"),
    ({"iss": f"https://sts.windows.net/{TENANT}/"}, "INVALID_ISSUER"),
    ({"aud": "another-client"}, "INVALID_AUDIENCE"),
    ({"aud": [CLIENT]}, "INVALID_AUDIENCE"),
    ({"azp": "another-client"}, "INVALID_AUDIENCE"),
    ({"exp": 1}, "INVALID_TIME"),
    ({"exp": "soon"}, "INVALID_TIME"),
    ({"iat": 1}, "INVALID_TIME"),
    ({"nbf": int(time.time()) + 3600}, "INVALID_TIME"),
    ({"nbf": "now"}, "INVALID_TIME"),
    ({"nonce": "a-different-nonce"}, "INVALID_NONCE"),
    ({"nonce": ...}, "INVALID_NONCE"),
    ({"nonce": "\ud800"}, "INVALID_NONCE"),
    ({"oid": ...}, "NO_SUBJECT"),
    ({"oid": OBJECT.upper()}, "NO_SUBJECT"),
    ({"oid": "not-an-object-id"}, "NO_SUBJECT"),
    ({"xms_edov": ...}, "EMAIL_UNVERIFIED"),
    ({"xms_edov": False}, "EMAIL_UNVERIFIED"),
    ({"xms_edov": "true"}, "EMAIL_UNVERIFIED"),
    ({"xms_edov": 1}, "EMAIL_UNVERIFIED"),
    ({"email": ...}, "NO_EMAIL"),
    ({"email": ""}, "NO_EMAIL"),
    ({"email": "a" * 243 + "@example.com"}, "NO_EMAIL"),
    ({"email": ["dana@contoso.example"]}, "NO_EMAIL"),
]


def test_mi1_the_token_is_verified_claim_by_claim(key):
    now = time.time()
    fetches: list[str] = []
    keys = cache(key, counter=fetches)
    account = verify_id_token(sign(key, claims(now)), CONFIG, NONCE, keys, now=now)
    # The subject is the tenant and object identifiers together; `sub` is pairwise per
    # application and `preferred_username` is never read.
    assert account == ExternalAccount(
        "microsoft", f"{TENANT}:{OBJECT}", "dana@contoso.example", None
    )
    assert fetches == [JWKS_ENDPOINT]


@pytest.mark.parametrize(("overrides", "code"), DEFECTS)
def test_mi1_each_wrong_claim_is_its_own_refusal(key, overrides, code):
    now = time.time()
    assert refused(sign(key, claims(now, **overrides)), cache(key), now=now) == code


def test_mi1_an_address_of_the_maximum_length_is_read(key):
    now = time.time()
    address = "a" * 242 + "@example.com"
    assert len(address) == 254
    token = sign(key, claims(now, email=address))
    assert verify_id_token(token, CONFIG, NONCE, cache(key), now=now).email == address


def test_mi1_a_not_before_within_the_skew_is_accepted(key):
    now = time.time()
    token = sign(key, claims(now, nbf=int(now) + 120))
    assert verify_id_token(token, CONFIG, NONCE, cache(key), now=now).subject


@pytest.mark.parametrize("alg", ["none", "HS256", "RS512", "ES256"])
def test_mi1_another_algorithm_is_refused_before_any_key_is_fetched(key, alg):
    now = time.time()
    fetches: list[str] = []
    token = sign(key, claims(now), alg=alg)
    assert refused(token, cache(key, counter=fetches), now=now) == "INVALID_ALGORITHM"
    assert fetches == []


def test_mi1_a_bad_signature_is_refused_before_any_claim_is_read(key):
    now = time.time()
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Every claim wrong, so a refusal naming a claim would mean a claim was read first.
    wrong = claims(now, ver="1.0", tid=PERSONAL_TENANT, xms_edov=False)
    assert refused(sign(other, wrong), cache(key), now=now) == "INVALID_SIGNATURE"
    forged = sign(key, claims(now), signature=other.sign(b"x", padding.PKCS1v15(), hashes.SHA256()))
    assert refused(forged, cache(key), now=now) == "INVALID_SIGNATURE"


def test_mi1_an_unknown_key_refetches_once_and_then_refuses(key):
    now = time.time()
    fetches: list[str] = []
    keys = cache(key, kid="a-rotated-key", counter=fetches)
    token = sign(key, claims(now))
    assert refused(token, keys, now=now) == "UNKNOWN_KEY"
    assert fetches == [JWKS_ENDPOINT]
    # One fetch per assertion naming a key the set does not hold, never a loop.
    assert refused(token, keys, now=now) == "UNKNOWN_KEY"
    assert len(fetches) == 2


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", "!!!.###.$$$", "x" * 9000, None, 7])
def test_mi1_a_token_that_is_not_one_is_refused(key, token):
    assert refused(token, cache(key), now=time.time()) in {"INVALID_TOKEN", "INVALID_ALGORITHM"}


def test_mi2_the_provider_is_pinned_and_present_only_when_configured(key):
    """Everything that chooses a host is in the source; the flow is authorization code with
    PKCE, a state and a nonce, and the exchange keeps the ID token and nothing else."""
    assert AUTHORIZATION_ENDPOINT == (
        "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
    )
    assert TOKEN_ENDPOINT == "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
    assert JWKS_ENDPOINT == "https://login.microsoftonline.com/organizations/discovery/v2.0/keys"
    assert AUTHORIZATION_ORIGIN == "https://login.microsoftonline.com"
    assert PERSONAL_TENANT == "9188040d-6c67-4c5b-b112-36a304b66dad"
    sent: list[httpx.Request] = []
    now = time.time()
    flow = FlowState("the-state", NONCE, "the-verifier-" + "v" * 40)

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(
            200,
            json={
                "id_token": sign(key, claims(now)),
                "access_token": "never-kept",
                "refresh_token": "never-kept",
            },
        )

    provider = MicrosoftProvider(
        CONFIG, cache(key), http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    assert (provider.name, provider.label) == ("microsoft", "Microsoft")
    assert provider.authorization_origin == AUTHORIZATION_ORIGIN
    address = urlsplit(provider.begin(flow))
    assert f"{address.scheme}://{address.netloc}{address.path}" == AUTHORIZATION_ENDPOINT
    query = parse_qsl(address.query, strict_parsing=True)
    assert dict(query) == {
        "response_type": "code",
        "client_id": CLIENT,
        "redirect_uri": CONFIG.redirect_uri,
        "scope": "openid email",
        "state": "the-state",
        "nonce": NONCE,
        "code_challenge": challenge(flow.verifier),
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    assert len(query) == 9
    assert flow.verifier not in address.query
    account = provider.complete("the-code", flow, now=now)
    assert account.subject == f"{TENANT}:{OBJECT}"
    (exchange,) = sent
    assert str(exchange.url) == TOKEN_ENDPOINT
    assert dict(parse_qsl(exchange.content.decode())) == {
        "grant_type": "authorization_code",
        "code": "the-code",
        "redirect_uri": CONFIG.redirect_uri,
        "client_id": CLIENT,
        "client_secret": "a-client-secret",
        "code_verifier": flow.verifier,
        "scope": "openid email",
    }
    assert "never-kept" not in repr(account)


def test_mi2_a_token_from_the_exchange_is_held_to_the_flows_nonce(key):
    now = time.time()
    flow = FlowState("the-state", "a-different-nonce", "verifier")
    token = sign(key, claims(now))
    provider = MicrosoftProvider(
        CONFIG,
        cache(key),
        http=httpx.Client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"id_token": token}))
        ),
    )
    with pytest.raises(SignInRefused) as raised:
        provider.complete("the-code", flow, now=now)
    assert raised.value.code == "INVALID_NONCE"


def test_mi2_an_exchange_that_answers_anything_else_is_refused():
    for status, body in ((400, {"error": "invalid_grant"}), (200, {"access_token": "only"})):
        provider = MicrosoftProvider(
            CONFIG,
            JwksCache(endpoint=JWKS_ENDPOINT),
            http=httpx.Client(
                transport=httpx.MockTransport(lambda _, s=status, b=body: httpx.Response(s, json=b))
            ),
        )
        with pytest.raises(SignInRefused) as raised:
            provider.complete("the-code", FlowState("s", NONCE, "v"), now=time.time())
        assert raised.value.code == "EXCHANGE_REFUSED"


def test_mi2_each_provider_fetches_only_its_own_key_set(key):
    fetched: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetched.append(str(request.url))
        return httpx.Response(200, json=key_set(key))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    JwksCache(client, endpoint=JWKS_ENDPOINT).key(KID)
    JwksCache(client).key(KID)
    assert fetched == [JWKS_ENDPOINT, "https://www.googleapis.com/oauth2/v3/certs"]


# The configuration block, the routes and the page policy.

SURFACE = {
    "origin": ORIGIN,
    "active_key_id": "state-v1",
    "continuation_keys": {"state-v1": "21" * 32},
    "connectors": [
        {
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "account_id": "00000000-0000-0000-0000-000000000002",
            "origin": "http://127.0.0.1:8001",
            "dispatch_token": "dispatch-test" * 3,
            "control_token": "control-test" * 3,
            "evidence_keys": {"proof": "31" * 32},
        }
    ],
}


def block(provider: str, *, redirect: str | None = None) -> dict:
    return {
        "client_id": f"{provider}-client",
        "client_secret": f"{provider}-secret",
        "redirect_uri": redirect or ORIGIN + CALLBACK.format(provider),
    }


def configured(tmp_path, sign_in: dict):
    path = tmp_path / "private.json"
    path.write_text(json.dumps(SURFACE | {"sign_in": sign_in}), encoding="utf-8")
    return read_configuration(path)


def test_mi2_the_block_builds_the_provider_after_google_and_github(tmp_path):
    every = configured(tmp_path, {name: block(name) for name in ("microsoft", "github", "google")})
    built = sign_in_providers(every.sign_in)
    assert [provider.name for provider in built] == ["google", "github", "microsoft"]
    assert isinstance(built[-1], MicrosoftProvider)
    assert built[-1].begin(FlowState("s", "n", "v")).startswith(AUTHORIZATION_ENDPOINT + "?")
    alone = sign_in_providers(configured(tmp_path, {"microsoft": block("microsoft")}).sign_in)
    assert [provider.name for provider in alone] == ["microsoft"]
    assert sign_in_providers(configured(tmp_path, {"google": block("google")}).sign_in)[0].name == (
        "google"
    )
    assert all(
        provider.name != "microsoft"
        for provider in sign_in_providers(configured(tmp_path, {}).sign_in)
    )


@pytest.mark.parametrize(
    "redirect",
    [
        ORIGIN + CALLBACK.format("google"),
        "https://elsewhere.example" + CALLBACK.format("microsoft"),
        ORIGIN + "/login/microsoft",
    ],
)
def test_mi2_a_redirect_uri_that_is_not_this_deployments_callback_refuses_start(tmp_path, redirect):
    with pytest.raises(ValueError):
        configured(tmp_path, {"microsoft": block("microsoft", redirect=redirect)})


@pytest.mark.integration
def test_mi2_the_route_and_the_form_action_exist_only_with_the_block(db, runtime):
    def surface(*providers):
        human = HumanConfig(
            "http://127.0.0.1",
            TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
            providers=providers,
        )
        return TestClient(create_app(db, runtime=runtime, human=human), base_url="http://127.0.0.1")

    with surface() as bare:
        bare.follow_redirects = False
        page = bare.get("/login")
        assert "login.microsoftonline.com" not in page.headers["Content-Security-Policy"]
        assert "Continue with Microsoft" not in page.text
        token = re.search(r'name="csrf" value="([^"]+)"', page.text)
        assert token is not None
        # A request the page itself would make: its own CSRF token, its own origin.
        answer = bare.post(
            "/login/microsoft",
            data={"csrf": token.group(1)},
            headers={"Origin": "http://127.0.0.1"},
        )
        assert answer.status_code == 404
        assert bare.get("/login/microsoft/callback?code=c&state=s").status_code == 404
    local = ProviderConfig(
        "microsoft-client", "microsoft-secret", "http://127.0.0.1" + CALLBACK.format("microsoft")
    )
    with surface(MicrosoftProvider(local, keys())) as offered:
        offered.follow_redirects = False
        page = offered.get("/login")
        policy = page.headers["Content-Security-Policy"]
        assert "form-action 'self' https://login.microsoftonline.com;" in policy
        assert "Continue with Microsoft" in page.text
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)
        assert csrf is not None
        begun = offered.post(
            "/login/microsoft", data={"csrf": csrf.group(1)}, headers={"Origin": "http://127.0.0.1"}
        )
        assert begun.status_code == 303
        assert begun.headers["location"].startswith(AUTHORIZATION_ENDPOINT + "?")


# Through the store, as the routes call it: an owner links Microsoft, then signs in with it.

ADDRESS = "dana@contoso.example"
PASSWORD = "a decent passphrase"


def linked(db, runtime, world, admin_engine, subject: str = f"{TENANT}:{OBJECT}"):
    """The tenant's approver, with a password and a verified address, links a Microsoft
    subject from a fresh session of their own, as Account security does."""
    tenant, principal = world["human"].tenant_id, world["human"].principal_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text("UPDATE execbound.principals SET email = :e WHERE principal_id = :p"),
            {"e": ADDRESS, "p": principal},
        )
    reset = issue_reset(db, tenant, world["admin"].principal_id, principal, clock=runtime.clock)
    redeem_reset(db, reset.code, PASSWORD, clock=runtime.clock)
    granted = issue_session(
        db, sign_in_with_password(db, ADDRESS, PASSWORD, clock=runtime.clock), clock=runtime.clock
    )
    session = load_session(db, granted.token, clock=runtime.clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.user_accounts SET email_verified_at=now() WHERE account_id=:a"),
            {"a": session.account_id},
        )
    flow = new_flow()
    token = begin_link(db, session, "microsoft", flow, clock=runtime.clock)
    finish_link(
        db,
        token,
        flow,
        ExternalAccount("microsoft", subject, ADDRESS, None),
        clock=runtime.clock,
    )
    return session.account_id


@pytest.mark.integration
def test_mi5_a_microsoft_sign_in_replays(db, runtime, world, admin_engine):
    account = linked(db, runtime, world, admin_engine)
    identity = provider_sign_in(
        db, ExternalAccount("microsoft", f"{TENANT}:{OBJECT}", ADDRESS, None), clock=runtime.clock
    )
    assert identity.tenant_id == world["human"].tenant_id
    granted = issue_session(db, identity, clock=runtime.clock)
    assert load_session(db, granted.token, clock=runtime.clock).account_id == account
    [payload] = audit(admin_engine, identity.tenant_id, "human_sign_in.microsoft")
    # The subject is the provider's own claim, recorded as every provider's is.
    assert set(payload) >= {"credential_id", "kind", "expires_at"}
    history = export_history(db, world["admin"])
    verified = verify_export(history, history.head)
    assert "UNKNOWN_EVENT_SEMANTICS" not in verified.issues
    assert "human_sign_in.microsoft" in _INFORMATIONAL
