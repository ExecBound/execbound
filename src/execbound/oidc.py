# SPDX-License-Identifier: AGPL-3.0-only
"""Google as a sign-in provider: OpenID Connect, with the ID token verified here.

Google is deployment configuration rather than a tenant row, so everything about it except
the client id, the client secret and the redirect URI is **pinned in this file**. No
discovery document is fetched: an operator cannot move the flow to a host they control, and
a document that is wrong or unavailable cannot stop somebody signing in. A tenant's own
identity provider is #177's, whose
issuer is not knowable in advance and which therefore does fetch discovery.

This module decides nothing about authority. It answers "which Google account is this, and
did Google really say so"; which person that is, and whether they may act, is decided by
rows in `execbound.passwords` and the tables behind it.

No new dependency: `cryptography` is already the project's, and the JWKS is turned into an
RSA public key with it.
"""

import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from execbound.signin import (
    MAX_BODY,
    ExternalAccount,
    FlowState,
    ProviderConfig,
    SignInRefused,
    body_of,
    challenge,
    client,
    segment,
)

# Pinned: the issuer Google states, the two forms it states it in, and the three endpoints.
ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})
AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"  # nosec B105 - a pinned endpoint address, not a secret
JWKS_ENDPOINT = "https://www.googleapis.com/oauth2/v3/certs"
AUTHORIZATION_ORIGIN = "https://accounts.google.com"
PROVIDER = "google"
LABEL = "Google"
# `openid email` and nothing else. ExecBound asks for no scope it could use against the
# account, so the access token the exchange returns is read and discarded.
SCOPE = "openid email"
# Google signs ID tokens with RS256. An assertion naming any other algorithm, `none`
# included, is refused before a key is looked up, so no confusion between a signature and a
# MAC is reachable from a token's own header.
ALGORITHM = "RS256"
MAX_SKEW = 300
MAX_TOKEN_BYTES = 8192
_JWKS_TTL = 3600.0


class JwksCache:
    """A provider's signing keys, cached by key id, refetched once when one is missing.

    The endpoint is Google's unless a provider pins its own (`execbound.microsoft` does); it is
    a constant of the provider's module either way, never configuration.

    A `kid` that is still missing after one refetch is a refusal rather than a second fetch,
    so an assertion naming an unknown key cannot make this server call out repeatedly.
    """

    def __init__(self, http: httpx.Client | None = None, endpoint: str = JWKS_ENDPOINT) -> None:
        self._client = http
        self._endpoint = endpoint
        self._keys: dict[str, rsa.RSAPublicKey] = {}
        self._fetched_at = 0.0

    def _fetch(self) -> None:
        owned = self._client is None
        http = client(self._client)
        try:
            response = http.get(self._endpoint, headers={"Accept": "application/json"})
        except httpx.HTTPError:
            raise SignInRefused("PROVIDER_UNAVAILABLE") from None
        finally:
            if owned:
                http.close()
        document = body_of(response, "PROVIDER_UNAVAILABLE")
        entries = document.get("keys") if type(document) is dict else None
        keys: dict[str, rsa.RSAPublicKey] = {}
        for entry in entries if type(entries) is list else []:
            if type(entry) is not dict or entry.get("kty") != "RSA":
                continue
            if entry.get("alg") not in (None, ALGORITHM):
                continue
            kid, modulus, exponent = entry.get("kid"), entry.get("n"), entry.get("e")
            if not all(type(value) is str for value in (kid, modulus, exponent)):
                continue
            try:
                numbers = rsa.RSAPublicNumbers(_integer(str(exponent)), _integer(str(modulus)))
                keys[str(kid)] = numbers.public_key()
            except ValueError:
                continue
        if not keys:
            raise SignInRefused("PROVIDER_UNAVAILABLE")
        self._keys = keys
        self._fetched_at = time.monotonic()

    def key(self, kid: str) -> rsa.RSAPublicKey:
        if kid not in self._keys or time.monotonic() - self._fetched_at > _JWKS_TTL:
            self._fetch()
        if kid not in self._keys:
            raise SignInRefused("UNKNOWN_KEY")
        return self._keys[kid]


def _integer(value: str) -> int:
    return int.from_bytes(segment(value), "big")


@dataclass(frozen=True)
class GoogleProvider:
    """The relying party. `config` is the only thing an operator supplies."""

    config: ProviderConfig
    keys: JwksCache
    http: httpx.Client | None = None
    name: str = PROVIDER
    label: str = LABEL
    authorization_origin: str = AUTHORIZATION_ORIGIN

    def begin(self, flow: FlowState) -> str:
        """Where the browser is sent. Every value is this server's own; nothing is a request's."""
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.config.client_id,
                "redirect_uri": self.config.redirect_uri,
                "scope": SCOPE,
                "state": flow.state,
                "nonce": flow.nonce,
                "code_challenge": challenge(flow.verifier),
                "code_challenge_method": "S256",
                "prompt": "select_account",
            }
        )
        return f"{AUTHORIZATION_ENDPOINT}?{query}"

    def complete(self, code: str, flow: FlowState, *, now: float) -> ExternalAccount:
        token = exchange(self.config, code, flow.verifier, http=self.http)
        return verify_id_token(token, self.config, flow.nonce, self.keys, now=now)


def exchange(
    config: ProviderConfig,
    code: str,
    verifier: str,
    *,
    http: httpx.Client | None = None,
    endpoint: str = TOKEN_ENDPOINT,
    scope: str | None = None,
) -> str:
    """The server-side half of the flow: the code for an ID token, and nothing else kept.

    `endpoint` and `scope` are a provider module's own constants: Google's endpoint takes no
    scope, and Microsoft's is given the one its authorization request asked for.
    """
    owned = http is None
    session = client(http)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.redirect_uri,
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "code_verifier": verifier,
    }
    if scope is not None:
        form["scope"] = scope
    try:
        response = session.post(endpoint, data=form, headers={"Accept": "application/json"})
    except httpx.HTTPError:
        raise SignInRefused("PROVIDER_UNAVAILABLE") from None
    finally:
        if owned:
            session.close()
    body = body_of(response, "EXCHANGE_REFUSED")
    token = body.get("id_token") if type(body) is dict else None
    if type(token) is not str or not 0 < len(token) <= MAX_TOKEN_BYTES:
        raise SignInRefused("EXCHANGE_REFUSED")
    return token


def verify_id_token(
    token: object, config: ProviderConfig, nonce: str, keys: JwksCache, *, now: float
) -> ExternalAccount:
    """Every check Google's own documentation names, each its own refusal.

    The order matters: the algorithm is settled from the header before any key is fetched,
    the signature is checked before any claim is believed, and the claims are checked before
    an address is read out of them.
    """
    payload = signed_payload(token, keys)
    _claims(payload, config, nonce, now)
    email = payload.get("email")
    name = payload.get("name")
    subject = payload.get("sub")
    if payload.get("email_verified") is not True:
        raise SignInRefused("EMAIL_UNVERIFIED")
    if type(email) is not str or not email or len(email) > 254:
        raise SignInRefused("NO_EMAIL")
    if type(subject) is not str or not 0 < len(subject) <= 255:
        raise SignInRefused("NO_SUBJECT")
    return ExternalAccount(PROVIDER, subject, email, name if type(name) is str and name else None)


def signed_payload(token: object, keys: JwksCache) -> dict[str, Any]:
    """The claims of an RS256 JWT whose signature verifies against `keys`, believed in nothing.

    The size and shape come first, then the algorithm from the header before any key is
    fetched, then the key id, then the signature. Every provider that verifies an ID token
    here calls this, and then checks the claims its own documentation names, one by one.
    """
    if type(token) is not str or not 0 < len(token) <= MAX_TOKEN_BYTES:
        raise SignInRefused("INVALID_TOKEN")
    parts = token.split(".")
    if len(parts) != 3:
        raise SignInRefused("INVALID_TOKEN")
    try:
        header = json.loads(segment(parts[0]).decode("utf-8"))
        payload = json.loads(segment(parts[1]).decode("utf-8"))
        signature = segment(parts[2])
    except (ValueError, UnicodeDecodeError):
        raise SignInRefused("INVALID_TOKEN") from None
    if type(header) is not dict or type(payload) is not dict:
        raise SignInRefused("INVALID_TOKEN")
    if header.get("alg") != ALGORITHM:
        raise SignInRefused("INVALID_ALGORITHM")
    kid = header.get("kid")
    if type(kid) is not str or not kid:
        raise SignInRefused("INVALID_TOKEN")
    signed = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        keys.key(kid).verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise SignInRefused("INVALID_SIGNATURE") from None
    return payload


def same_nonce(supplied: object, nonce: str) -> bool:
    """The flow's nonce, compared in constant time.

    As bytes, because `secrets.compare_digest` refuses a `str` outside ASCII, and with
    `surrogatepass`, because a JSON claim can carry a lone surrogate UTF-8 cannot encode.
    """
    return type(supplied) is str and secrets.compare_digest(
        supplied.encode("utf-8", "surrogatepass"), nonce.encode()
    )


def _claims(payload: dict[str, Any], config: ProviderConfig, nonce: str, now: float) -> None:
    if payload.get("iss") not in ISSUERS:
        raise SignInRefused("INVALID_ISSUER")
    if payload.get("aud") != config.client_id:
        raise SignInRefused("INVALID_AUDIENCE")
    authorized = payload.get("azp")
    if authorized is not None and authorized != config.client_id:
        raise SignInRefused("INVALID_AUDIENCE")
    expiry, issued = payload.get("exp"), payload.get("iat")
    if type(expiry) is not int or type(issued) is not int:
        raise SignInRefused("INVALID_TIME")
    if now >= expiry or abs(now - issued) > MAX_SKEW:
        raise SignInRefused("INVALID_TIME")
    if not same_nonce(payload.get("nonce"), nonce):
        raise SignInRefused("INVALID_NONCE")


# Kept for readers who reach for it: the maximum size of a body this module will parse.
__all__ = [
    "ALGORITHM",
    "AUTHORIZATION_ENDPOINT",
    "ISSUERS",
    "JWKS_ENDPOINT",
    "LABEL",
    "MAX_BODY",
    "MAX_SKEW",
    "PROVIDER",
    "SCOPE",
    "TOKEN_ENDPOINT",
    "GoogleProvider",
    "JwksCache",
    "exchange",
    "same_nonce",
    "signed_payload",
    "verify_id_token",
]
