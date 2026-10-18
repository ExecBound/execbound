# SPDX-License-Identifier: AGPL-3.0-only
"""The shape every sign-in provider has, and the pieces all of them share.

A provider answers one question: **which account at that provider is this browser, and did
the provider really say so.** It decides nothing else. Which person that account is, what
role they have and whether they may act are decided by rows an administrator or the operator
provisioned, which is why nothing in this module or its implementations reads a principal.
A verified address proves only that one browser; it can start a **new** account through a
plugin's own signup point (`Registry.provider_signup`, #504), but it never attaches to an
existing one, so the provider's say-so is never, by itself, a reason to extend an account's
own authority.

Two shapes live under it today and they are not the same protocol. Google is OpenID Connect
and hands back a signed ID token this server verifies itself. GitHub is OAuth 2.0 with no
ID token at all, so the account is read from two authenticated calls to GitHub's own API.
The contract below is deliberately the smaller of the two — begin, complete, an account —
so a customer's own identity provider (#177)
joins as a third implementation rather than as a second flow.

Each provider is configured by a block in the private configuration and serves no route at
all when its block is absent, so a deployment offers exactly the buttons it was given.
"""

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

import httpx

TIMEOUT = httpx.Timeout(5.0)
MAX_BODY = 64 * 1024
CALLBACK = "/login/{}/callback"
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")


class SignInRefused(Exception):
    """A refusal with a private code; the browser is shown one sentence for all of them."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Sign-in refused")


@dataclass(frozen=True)
class ProviderConfig:
    """The three values a deployment supplies for any provider.

    Everything that chooses a host is pinned in the provider's own module, so nothing an
    operator writes can move a flow, and the redirect URI is checked against this
    deployment's own origin and this provider's own callback path before the server starts.
    """

    client_id: str
    client_secret: str
    redirect_uri: str

    def check(self, provider: str) -> None:
        if not self.client_id or len(self.client_id) > 256:
            raise ValueError("Invalid client id")
        if not self.client_secret or len(self.client_secret) > 256:
            raise ValueError("Invalid client secret")
        parsed = urlsplit(self.redirect_uri)
        if parsed.scheme not in {"http", "https"} or parsed.path != CALLBACK.format(provider):
            raise ValueError("Invalid redirect URI")

    def belongs_to(self, origin: str, provider: str) -> bool:
        return self.redirect_uri == origin.rstrip("/") + CALLBACK.format(provider)


@dataclass(frozen=True)
class FlowState:
    """What the transient cookie carries between the two halves of a flow.

    The nonce is minted for every provider and checked by the ones whose protocol has one;
    a provider with no assertion to bind it to simply does not read it, and the cookie's
    shape stays the same either way.
    """

    state: str
    nonce: str
    verifier: str

    def encode(self) -> str:
        return f"{self.state}.{self.nonce}.{self.verifier}"


@dataclass(frozen=True)
class ExternalAccount:
    """A verified account at a provider.

    `subject` is the provider's own stable identifier and is what identifies the account
    after explicit linking. `email` is verified at the provider but never authorizes
    anonymous attachment to an existing account. Existing subjects are resolved by their
    retained binding; an address is only a display hint during ordinary sign-in. A plugin's
    own signup point (#504) may use that verified address to start a **new** account instead,
    which is a different authority than attachment and never available at `/login`.
    """

    provider: str
    subject: str
    email: str
    display_name: str | None


class SignInProvider(Protocol):
    """What the routes need from a provider, and nothing more.

    Both names are read-only, so an implementation is free to be a frozen dataclass and
    nothing at runtime can rename a provider out from under a route.
    """

    @property
    def name(self) -> str:
        """The provider's own name: the path segment and the stored discriminator."""
        ...

    @property
    def label(self) -> str:
        """What the button says. Inert text, rendered through the autoescaping template."""
        ...

    @property
    def authorization_origin(self) -> str:
        """The host a form submission may redirect to, for the pages' `form-action`.

        Pinned in the provider's own module beside its endpoints, never configured, so a
        deployment's policy names exactly the hosts its own buttons send a browser to.
        """
        ...

    def begin(self, flow: FlowState) -> str:
        """Where to send the browser, built entirely from this server's own values."""
        ...

    def complete(self, code: str, flow: FlowState, *, now: float) -> ExternalAccount:
        """The account behind an authorization code, or `SignInRefused` with a reason."""
        ...


def new_flow() -> FlowState:
    return FlowState(
        secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    )


def read_flow(value: object) -> FlowState:
    """The cookie's three values, or a refusal; nothing here trusts a length alone."""
    if type(value) is not str or len(value) > 512:
        raise SignInRefused("INVALID_STATE")
    parts = value.split(".")
    if len(parts) != 3 or not all(_SEGMENT.fullmatch(part) for part in parts):
        raise SignInRefused("INVALID_STATE")
    return FlowState(parts[0], parts[1], parts[2])


def challenge(verifier: str) -> str:
    """The PKCE S256 challenge. Both providers support PKCE and both are given one."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def segment(value: str) -> bytes:
    if _SEGMENT.fullmatch(value) is None:
        raise ValueError("Invalid base64url segment")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def client(supplied: httpx.Client | None) -> httpx.Client:
    """One transport rule for every provider: https, no redirects, no retry, five seconds."""
    return supplied or httpx.Client(
        transport=httpx.HTTPTransport(retries=0, trust_env=False),
        trust_env=False,
        follow_redirects=False,
        timeout=TIMEOUT,
    )


def body_of(response: httpx.Response, code: str) -> object:
    """A bounded JSON body, or the caller's refusal; a provider's bytes are never quoted."""
    import json

    if response.status_code != 200 or len(response.content) > MAX_BODY:
        raise SignInRefused(code)
    try:
        return json.loads(response.content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SignInRefused(code) from None
