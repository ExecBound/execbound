# SPDX-License-Identifier: AGPL-3.0-only
"""Microsoft as a sign-in provider: OpenID Connect, with the ID token verified here (#678).

Like Google (`execbound.oidc`), Microsoft is deployment configuration rather than a tenant row,
so everything about it except the client id, the client secret and the redirect URI is
**pinned in this file**, and no discovery document is fetched.

**The `organizations` authority, and what replaces a pinned tenant.** A workspace's own
directory (#177) pins one Entra tenant and refuses `common`, `organizations` and `consumers`,
because that pin is what stops an account in another Microsoft tenant holding the same address
(#241). That rule stands for directories. This button is a different thing: a personal sign-in
method like Google, whose job is to prove one browser's account, not to admit anybody to a
workspace. Security teams hold Entra work accounts, so the button is multi-tenant through the
`organizations` authority, a recorded deviation from #241's single-tenant rule. Four checks
stand in for the pin:

- the issuer must be the issuer of the token's own `tid`, so a token is believed only about the
  tenant that signed it;
- the subject is `tid:oid`, so no account in one tenant can be taken for an account in another;
- the address is believed only when `xms_edov` is the JSON value `true`, Microsoft's statement
  that the tenant holding the account verified the address's domain, and then only where any
  provider's address is: to start a new account through a plugin's signup, or to link a
  provider from a signed-in account whose own verified address equals it. Sign-in itself is by
  subject alone;
- personal Microsoft accounts are refused twice: by the `organizations` authority at Microsoft,
  and by refusing the personal-account tenant here.

The provider is core, beside Google and GitHub, so the deviation also reaches a self-hosted
deployment whose operator configures `sign_in.microsoft`. That is the operator's own choice,
made by adding the block; nothing turns it on by default.

`sub` is not used: Microsoft makes it pairwise per application, so a replaced app registration
would orphan every binding. `preferred_username` is never read, because it is not verified.
"""

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from execbound.oidc import MAX_SKEW, JwksCache, exchange, same_nonce, signed_payload
from execbound.signin import (
    ExternalAccount,
    FlowState,
    ProviderConfig,
    SignInRefused,
    challenge,
)

PROVIDER = "microsoft"
LABEL = "Microsoft"
# Pinned: the multi-tenant work-account authority's three endpoints and the host a form may
# send a browser to.
AUTHORIZATION_ENDPOINT = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
TOKEN_ENDPOINT = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"  # nosec B105 - a pinned endpoint address, not a secret
JWKS_ENDPOINT = "https://login.microsoftonline.com/organizations/discovery/v2.0/keys"
AUTHORIZATION_ORIGIN = "https://login.microsoftonline.com"
# The issuer of a v2.0 ID token names the tenant that signed it.
ISSUER = "https://login.microsoftonline.com/{}/v2.0"
# The tenant every personal Microsoft account belongs to. The `organizations` authority does
# not sign anybody in to it; a token naming it is refused here as well.
PERSONAL_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"
# `openid email` and nothing else, as Google's: no scope the server could use against the
# account, so the access token the exchange returns is never read.
SCOPE = "openid email"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@dataclass(frozen=True)
class MicrosoftProvider:
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
        token = exchange(
            self.config, code, flow.verifier, http=self.http, endpoint=TOKEN_ENDPOINT, scope=SCOPE
        )
        return verify_id_token(token, self.config, flow.nonce, self.keys, now=now)


def keys() -> JwksCache:
    """Microsoft's signing keys, from its own pinned key set."""
    return JwksCache(endpoint=JWKS_ENDPOINT)


def verify_id_token(
    token: object, config: ProviderConfig, nonce: str, keys: JwksCache, *, now: float
) -> ExternalAccount:
    """Every check, each its own refusal, in an order that believes nothing early.

    The algorithm is settled from the header before any key is fetched and the signature is
    checked before any claim is read (`signed_payload`). Then the token's version, its tenant,
    the issuer for that tenant, the audience, the times and the nonce; only then the subject,
    and the address last, once Microsoft has said the tenant verified it.
    """
    payload = signed_payload(token, keys)
    if payload.get("ver") != "2.0":
        raise SignInRefused("INVALID_TOKEN")
    tenant = payload.get("tid")
    if type(tenant) is not str or _UUID.fullmatch(tenant) is None or tenant == PERSONAL_TENANT:
        raise SignInRefused("INVALID_TENANT")
    if payload.get("iss") != ISSUER.format(tenant):
        raise SignInRefused("INVALID_ISSUER")
    _audience_and_time(payload, config, now)
    if not same_nonce(payload.get("nonce"), nonce):
        raise SignInRefused("INVALID_NONCE")
    subject = payload.get("oid")
    if type(subject) is not str or _UUID.fullmatch(subject) is None:
        raise SignInRefused("NO_SUBJECT")
    # Exactly the JSON value `true`: not the string, not 1. Microsoft emits the optional claim
    # as a boolean, and anything else is a token this code does not understand.
    if payload.get("xms_edov") is not True:
        raise SignInRefused("EMAIL_UNVERIFIED")
    email = payload.get("email")
    if type(email) is not str or not 0 < len(email) <= 254:
        raise SignInRefused("NO_EMAIL")
    return ExternalAccount(PROVIDER, f"{tenant}:{subject}", email, None)


def _audience_and_time(payload: dict[str, Any], config: ProviderConfig, now: float) -> None:
    if payload.get("aud") != config.client_id:
        raise SignInRefused("INVALID_AUDIENCE")
    authorized = payload.get("azp")
    if authorized is not None and authorized != config.client_id:
        raise SignInRefused("INVALID_AUDIENCE")
    expiry, issued, before = payload.get("exp"), payload.get("iat"), payload.get("nbf")
    if type(expiry) is not int or type(issued) is not int:
        raise SignInRefused("INVALID_TIME")
    if now >= expiry or abs(now - issued) > MAX_SKEW:
        raise SignInRefused("INVALID_TIME")
    if before is not None and (type(before) is not int or before > now + MAX_SKEW):
        raise SignInRefused("INVALID_TIME")


__all__ = [
    "AUTHORIZATION_ENDPOINT",
    "AUTHORIZATION_ORIGIN",
    "ISSUER",
    "JWKS_ENDPOINT",
    "LABEL",
    "PERSONAL_TENANT",
    "PROVIDER",
    "SCOPE",
    "TOKEN_ENDPOINT",
    "MicrosoftProvider",
    "keys",
    "verify_id_token",
]
