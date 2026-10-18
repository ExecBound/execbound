# SPDX-License-Identifier: AGPL-3.0-only
"""A fake of Microsoft's sign-in and admin consent endpoints, for the Entra connect tests.

It answers through an injected `httpx` transport only, never a socket, and holds a synthetic
signing key. Each endpoint answers as data what Microsoft would send the browser:

- the JWKS at the pinned keys address;
- `/{authority}/oauth2/v2.0/authorize`: the fields Microsoft's `form_post` page would post to
  the redirect URI (`id_token` and `state`), the id_token signed for the request's `nonce` and
  `client_id` with the directory, roles and extra claims the test chose;
- `/{tenant}/v2.0/adminconsent`: the redirect URI and the query Microsoft's admin consent
  reference documents for it, on success `admin_consent=True`, `tenant`, `scope` (the granted
  permission URIs, space separated) and `state`, and on an error `admin_consent`, `error`,
  `error_description` and `state`, with any other parameter a test adds.

`id_token` also builds a token directly, so a test can sign one that is wrong in exactly one way.
Nothing here contacts Microsoft.
"""

import base64
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

LOGIN_ORIGIN = "https://login.microsoftonline.com"
KEYS_PATH = "/common/discovery/v2.0/keys"
DIRECTORY = "c0ffee00-1111-4222-8333-444455556666"
CLIENT = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
GLOBAL_ADMINISTRATOR = "62e90394-69f5-4237-9190-012177145e10"
# The permissions a consent to the deployment's app grants, as the redirect's `scope` names them.
GRANTED = (
    "https://graph.microsoft.com/AgentIdentity.Read.All "
    "https://graph.microsoft.com/Application.Read.All "
    "https://graph.microsoft.com/AuditLog.Read.All "
    "https://graph.microsoft.com/Directory.Read.All"
)


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _integer(value: int) -> str:
    return _base64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


@dataclass
class FakeEntraLogin(httpx.BaseTransport):
    """One synthetic Microsoft sign-in: a directory, its administrator's roles and a key."""

    directory: str = DIRECTORY
    roles: tuple[str, ...] = (GLOBAL_ADMINISTRATOR,)
    # Claims added to every id_token the authorize endpoint signs, `email` and the like.
    extra: dict[str, Any] = field(default_factory=dict)
    kid: str = "fake-entra-key-1"
    key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        repr=False,
    )
    requests: list[str] = field(default_factory=list)

    def jwks(self) -> dict[str, Any]:
        numbers = self.key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": self.kid,
                    "alg": "RS256",
                    "n": _integer(numbers.n),
                    "e": _integer(numbers.e),
                }
            ]
        }

    def id_token(
        self,
        *,
        nonce: str,
        audience: str = CLIENT,
        directory: str | None = None,
        roles: tuple[str, ...] | None = None,
        claims: Mapping[str, Any] | None = None,
        header: Mapping[str, Any] | None = None,
        key: rsa.RSAPrivateKey | None = None,
        now: float | None = None,
        drop: tuple[str, ...] = (),
    ) -> str:
        """An id_token as Microsoft signs one, with `claims` on top and `drop` removed."""
        moment = int(time.time() if now is None else now)
        tenant = self.directory if directory is None else directory
        payload: dict[str, Any] = {
            "ver": "2.0",
            "iss": f"{LOGIN_ORIGIN}/{tenant}/v2.0",
            "aud": audience,
            "tid": tenant,
            "oid": str(uuid4()),
            "sub": _base64url(uuid4().bytes),
            "nonce": nonce,
            "iat": moment,
            "nbf": moment,
            "exp": moment + 3600,
            "wids": list(self.roles if roles is None else roles),
            **self.extra,
            **(claims or {}),
        }
        for name in drop:
            payload.pop(name, None)
        head = {"alg": "RS256", "typ": "JWT", "kid": self.kid, **(header or {})}
        signing = ".".join(
            _base64url(json.dumps(part, separators=(",", ":")).encode()) for part in (head, payload)
        )
        if head.get("alg") == "none":
            return signing + "."
        signature = (key or self.key).sign(
            signing.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{signing}.{_base64url(signature)}"

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host != "login.microsoftonline.com" or request.url.scheme != "https":
            raise httpx.ConnectError("Unpinned origin")
        path = request.url.path
        self.requests.append(path)
        query = dict(parse_qsl(request.url.query.decode("ascii"), keep_blank_values=True))
        if path == KEYS_PATH and request.method == "GET":
            return httpx.Response(200, json=self.jwks())
        if path.endswith("/oauth2/v2.0/authorize") and request.method == "GET":
            # What Microsoft's form_post page would post to the redirect URI.
            return httpx.Response(
                200,
                json={
                    "redirect_uri": query.get("redirect_uri"),
                    "fields": {
                        "id_token": self.id_token(
                            nonce=query.get("nonce", ""), audience=query.get("client_id", "")
                        ),
                        "state": query.get("state", ""),
                    },
                },
            )
        if path.endswith("/v2.0/adminconsent") and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "redirect_uri": query.get("redirect_uri"),
                    "query": {
                        "admin_consent": "True",
                        "tenant": path.split("/")[1],
                        "scope": GRANTED,
                        "state": query.get("state", ""),
                    },
                },
            )
        return httpx.Response(404, json={"error": "not_found"})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=self, trust_env=False, follow_redirects=False)

    def authorize(self, url: str) -> tuple[str, dict[str, str]]:
        """Microsoft's sign-in for an authorize URL: the redirect URI and the posted fields."""
        with self.client() as http:
            answer = http.get(url).json()
        return answer["redirect_uri"], answer["fields"]

    def consent(
        self, url: str, *, error: str | None = None, **extra: str
    ) -> tuple[str, list[tuple[str, str]]]:
        """Microsoft's admin consent for a consent URL: the redirect URI and its query, as
        pairs, a success unless `error` names one, with `extra` parameters added."""
        with self.client() as http:
            answer = http.get(url).json()
        query = dict(answer["query"])
        if error is not None:
            query = {
                "admin_consent": "True",
                "error": error,
                "error_description": "AADSTS65004: The resource owner denied the request.",
                "state": query["state"],
            }
        return answer["redirect_uri"], [*query.items(), *extra.items()]


def parts(url: str) -> tuple[str, dict[str, str]]:
    """An address's origin and path, and its query as a mapping."""
    parsed = urlsplit(url)
    return (
        f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
        dict(parse_qsl(parsed.query, keep_blank_values=True)),
    )
