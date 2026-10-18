# SPDX-License-Identifier: AGPL-3.0-only
"""A customer's directory, scripted in process, so no test in this suite makes a network call.

One `httpx.MockTransport` answers the four addresses a real directory serves: the discovery
document, the JWKS, the token endpoint for an authorization code, and the token endpoint again
for a refresh. Everything a test wants to make go wrong is a keyword here rather than a mutated
module, so a refusal test says what it changed in its own first line.
"""

import base64
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ISSUER = "https://login.microsoftonline.com/9f11b4a0-0000-4000-8000-00000000abcd/v2.0"
HOST = "login.microsoftonline.com"
TENANT_ID = "9f11b4a0-0000-4000-8000-00000000abcd"
CLIENT_ID = "8a0d1f5c-1111-4000-8000-0000000000aa"
CLIENT_SECRET = "a-client-secret-value"  # nosec B105 - a synthetic value for the tests
SUBJECT = "0c1d2e3f-2222-4000-8000-0000000000bb"
KID = "directory-key-1"
NAME = "Dana Reyes"
USERNAME = "dana@contoso.example"
REFRESH = "refresh-token-one"  # nosec B105 - a synthetic value for the tests
ROTATED = "refresh-token-two"  # nosec B105 - a synthetic value for the tests


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def integer(value: int) -> str:
    return b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def rsa_jwk(key: Any, *, kid: str = KID, **changes: Any) -> dict[str, Any]:
    """An RSA key's public JWK, with `changes` on top and any member set to None removed."""
    numbers = key.public_key().public_numbers()
    entry = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": integer(numbers.n),
        "e": integer(numbers.e),
    }
    entry.update(changes)
    return {name: value for name, value in entry.items() if value is not None}


def ec_jwk(key: Any, *, kid: str = KID, **changes: Any) -> dict[str, Any]:
    """An EC key's public JWK, coordinates at the curve's full width as RFC 7518 6.2.1 has them."""
    numbers = key.public_key().public_numbers()
    width = (key.curve.key_size + 7) // 8
    entry = {
        "kty": "EC",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "crv": {256: "P-256", 384: "P-384"}.get(key.curve.key_size, key.curve.name),
        "x": b64(numbers.x.to_bytes(width, "big")),
        "y": b64(numbers.y.to_bytes(width, "big")),
    }
    entry.update(changes)
    return {name: value for name, value in entry.items() if value is not None}


def jwks_document(key: Any, *, kid: str = KID) -> dict[str, Any]:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {"keys": [ec_jwk(key, kid=kid)]}
    return {"keys": [rsa_jwk(key, kid=kid)]}


def discovery_document(**changes: Any) -> dict[str, Any]:
    document = {
        "issuer": ISSUER,
        "authorization_endpoint": f"https://{HOST}/{TENANT_ID}/oauth2/v2.0/authorize",
        "token_endpoint": f"https://{HOST}/{TENANT_ID}/oauth2/v2.0/token",
        "jwks_uri": f"https://{HOST}/{TENANT_ID}/discovery/v2.0/keys",
        "response_types_supported": ["code", "id_token", "code id_token"],
        "code_challenge_methods_supported": ["plain", "S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "subject_types_supported": ["pairwise"],
    }
    document.update(changes)
    return {name: value for name, value in document.items() if value is not None}


def claims(now: float, nonce: str | None = "the-nonce", **changes: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "tid": TENANT_ID,
        "oid": SUBJECT,
        "sub": "pairwise-" + SUBJECT,
        "exp": int(now) + 600,
        "iat": int(now),
        "name": NAME,
        "preferred_username": USERNAME,
    }
    if nonce is not None:
        payload["nonce"] = nonce
    payload.update(changes)
    return {name: value for name, value in payload.items() if value is not None}


def sign(key: Any, payload: dict[str, Any], *, alg: str = "RS256", kid: str = KID) -> str:
    header = b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    body = b64(json.dumps(payload).encode())
    signed = f"{header}.{body}".encode("ascii")
    if alg == "PS256":
        raw = key.sign(
            signed,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    elif alg in {"none", "HS256"}:
        raw = b"not-a-signature"
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        # The JWS form (RFC 7518 3.4): R and S at the curve's full width, never DER.
        width = (key.curve.key_size + 7) // 8
        r, s = decode_dss_signature(key.sign(signed, ec.ECDSA(hashes.SHA256())))
        raw = r.to_bytes(width, "big") + s.to_bytes(width, "big")
    else:
        raw = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{body}.{b64(raw)}"


@dataclass
class StandIn:
    """One directory, answering its four addresses and recording what it was asked.

    Every failure a test wants is a field: a discovery document that disagrees with itself, an
    unreachable host, a token response that refuses, a refresh that answers `invalid_grant`.
    """

    key: Any
    nonce: str | None = "the-nonce"
    # What the directory thinks the time is. A test driving a fixed clock points this at that
    # clock, so an assertion minted here is inside the skew this server allows rather than five
    # minutes behind whatever the test advanced to.
    now: Callable[[], float] = time.time
    discovery: dict[str, Any] | None = None
    unreachable: bool = False
    jwks_kid: str = KID
    # A whole key set to publish instead of `key`'s own, for a set holding two families or an
    # entry this server must skip.
    jwks: dict[str, Any] | None = None
    alg: str = "RS256"
    claim_changes: dict[str, Any] = field(default_factory=dict)
    token_status: int = 200
    token_body: dict[str, Any] | None = None
    refresh_status: int = 200
    refresh_body: dict[str, Any] | None = None
    refresh_claims: dict[str, Any] = field(default_factory=dict)
    seen: list[httpx.Request] = field(default_factory=list)
    fetches: list[str] = field(default_factory=list)

    def document(self) -> dict[str, Any]:
        return self.discovery if self.discovery is not None else discovery_document()

    def id_token(self, *, nonce: str | None, extra: dict[str, Any]) -> str:
        payload = claims(self.now(), nonce, **{**self.claim_changes, **extra})
        return sign(self.key, payload, alg=self.alg, kid=KID)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        path = str(request.url)
        if self.unreachable:
            raise httpx.ConnectError("unreachable", request=request)
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.document())
        if "/discovery/v2.0/keys" in path:
            self.fetches.append(path)
            published = self.jwks
            if published is None:
                published = jwks_document(self.key, kid=self.jwks_kid)
            return httpx.Response(200, json=published)
        form = dict(
            part.split("=", 1) for part in request.content.decode().split("&") if "=" in part
        )
        if form.get("grant_type") == "refresh_token":
            if self.refresh_body is not None or self.refresh_status != 200:
                return httpx.Response(
                    self.refresh_status, json=self.refresh_body or {"error": "invalid_grant"}
                )
            return httpx.Response(
                200,
                json={
                    "id_token": self.id_token(nonce=None, extra=self.refresh_claims),
                    "refresh_token": ROTATED,
                },
            )
        if self.token_body is not None or self.token_status != 200:
            return httpx.Response(
                self.token_status, json=self.token_body or {"error": "invalid_grant"}
            )
        return httpx.Response(
            200,
            json={
                "id_token": self.id_token(nonce=self.nonce, extra={}),
                "access_token": "not-kept",
                "refresh_token": REFRESH,
            },
        )

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handle))


def directory_key() -> Any:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def directory_ec_key(curve: ec.EllipticCurve | None = None) -> Any:
    """A directory's ES256 signing key, or one on `curve` for a key this server must skip."""
    return ec.generate_private_key(curve or ec.SECP256R1())
