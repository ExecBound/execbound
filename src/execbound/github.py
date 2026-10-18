# SPDX-License-Identifier: AGPL-3.0-only
"""GitHub as a sign-in provider: OAuth 2.0, with the account read from GitHub's own API.

GitHub is **not** OpenID Connect for this flow. There is no ID token and therefore nothing
signed for this server to verify: what the authorization code buys is an access token, and
the account behind it is whatever two authenticated calls to GitHub's API say it is. That
difference is the reason this is its own module rather than a parameter of the Google one,
and it is worth naming plainly: a Google sign-in is checked against Google's published keys
here, and a GitHub sign-in is GitHub's word over an authenticated channel.

What that word has to say before a person is found:

- `GET /user` gives the stable numeric `id`, which is the subject and the only identifier
  used after the first sign-in. The `login` is a display hint and is never a lookup key;
  GitHub usernames are reassignable, and matching on one would hand an account to whoever
  claimed a freed name.
- `GET /user/emails` gives the addresses. The one address that may find a person is the one
  GitHub marks **both `primary` and `verified`**. An unverified address is not evidence of
  anything, and a non-primary one is an address the person may not control any more.

The access token is used for those two calls and discarded. It is never stored, never
logged, never returned and never written to any row; `user:email` is the only scope asked
for, so it could read nothing else even if it were kept.

Everything that chooses a host is pinned below. The client id, the client secret and the
redirect URI are the whole of what an operator supplies.
"""

from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from execbound.signin import (
    ExternalAccount,
    FlowState,
    ProviderConfig,
    SignInRefused,
    body_of,
    challenge,
    client,
)

AUTHORIZATION_ENDPOINT = "https://github.com/login/oauth/authorize"
TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"  # nosec B105 - a pinned endpoint address, not a secret
USER_ENDPOINT = "https://api.github.com/user"
EMAILS_ENDPOINT = "https://api.github.com/user/emails"
AUTHORIZATION_ORIGIN = "https://github.com"
PROVIDER = "github"
LABEL = "GitHub"
# The one scope. It reads the person's addresses and nothing else: no repository, no
# organisation, no write anywhere.
SCOPE = "user:email"
API_VERSION = "2022-11-28"
ACCEPT = "application/vnd.github+json"
MAX_EMAILS = 100


@dataclass(frozen=True)
class GitHubProvider:
    config: ProviderConfig
    http: httpx.Client | None = None
    name: str = PROVIDER
    label: str = LABEL
    authorization_origin: str = AUTHORIZATION_ORIGIN

    def begin(self, flow: FlowState) -> str:
        """Where the browser is sent. PKCE is included because GitHub supports it, and the
        `state` is what the callback compares with the transient cookie."""
        query = urlencode(
            {
                "client_id": self.config.client_id,
                "redirect_uri": self.config.redirect_uri,
                "scope": SCOPE,
                "state": flow.state,
                "code_challenge": challenge(flow.verifier),
                "code_challenge_method": "S256",
                # A flow started at `/login` still needs an existing person, so offering to
                # create a GitHub account on the way would be offering a dead end there. A
                # flow started at `/signup` (#504) may now create a new ExecBound account
                # from this provider, but never from an account GitHub minted mid-flow: a
                # GitHub account made here has no verified primary address yet, so the
                # provider signup point would refuse it regardless of this setting.
                "allow_signup": "false",
            }
        )
        return f"{AUTHORIZATION_ENDPOINT}?{query}"

    def complete(self, code: str, flow: FlowState, *, now: float) -> ExternalAccount:
        owned = self.http is None
        session = client(self.http)
        try:
            token = _token(self.config, code, flow.verifier, session)
            return _account(token, session)
        finally:
            if owned:
                session.close()


def _token(config: ProviderConfig, code: str, verifier: str, session: httpx.Client) -> str:
    """The code for an access token. GitHub answers 200 with an `error` for a bad code, so
    the body is read for one rather than the status alone."""
    try:
        response = session.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "authorization_code",
                "client_id": config.client_id,
                "client_secret": config.client_secret,
                "code": code,
                "redirect_uri": config.redirect_uri,
                "code_verifier": verifier,
            },
            headers={"Accept": "application/json"},
        )
    except httpx.HTTPError:
        raise SignInRefused("PROVIDER_UNAVAILABLE") from None
    body = body_of(response, "EXCHANGE_REFUSED")
    if type(body) is not dict or body.get("error") is not None:
        raise SignInRefused("EXCHANGE_REFUSED")
    token = body.get("access_token")
    if type(token) is not str or not 0 < len(token) <= 512:
        raise SignInRefused("EXCHANGE_REFUSED")
    granted = body.get("scope")
    # A token that did not come back with the one scope asked for cannot answer the two
    # calls below, and getting a different scope than the one requested is worth refusing
    # rather than discovering halfway through.
    if type(granted) is not str or SCOPE not in granted.split(","):
        raise SignInRefused("SCOPE_REFUSED")
    return token


def _get(url: str, token: str, session: httpx.Client) -> object:
    try:
        response = session.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": ACCEPT,
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
    except httpx.HTTPError:
        raise SignInRefused("PROVIDER_UNAVAILABLE") from None
    return body_of(response, "PROVIDER_REFUSED")


def _account(token: str, session: httpx.Client) -> ExternalAccount:
    user = _get(USER_ENDPOINT, token, session)
    if type(user) is not dict:
        raise SignInRefused("PROVIDER_REFUSED")
    identifier = user.get("id")
    # The numeric id, never the login: a GitHub username can be released and claimed by
    # somebody else, and the id cannot.
    if type(identifier) is not int or isinstance(identifier, bool) or identifier <= 0:
        raise SignInRefused("NO_SUBJECT")
    name = user.get("name") or user.get("login")
    addresses = _get(EMAILS_ENDPOINT, token, session)
    if type(addresses) is not list or len(addresses) > MAX_EMAILS:
        raise SignInRefused("PROVIDER_REFUSED")
    verified = [
        entry["email"]
        for entry in addresses
        if type(entry) is dict
        and entry.get("primary") is True
        and entry.get("verified") is True
        and type(entry.get("email")) is str
        and 0 < len(entry["email"]) <= 254
    ]
    if len(verified) != 1:
        # None means no address is both primary and verified, which is not evidence of
        # anything; more than one means GitHub answered something this server does not
        # understand, and guessing which to trust is exactly the wrong move.
        raise SignInRefused("EMAIL_UNVERIFIED" if not verified else "PROVIDER_REFUSED")
    return ExternalAccount(
        PROVIDER,
        str(identifier),
        verified[0],
        name if type(name) is str and name else None,
    )
