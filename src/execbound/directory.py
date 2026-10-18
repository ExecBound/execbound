# SPDX-License-Identifier: AGPL-3.0-only
"""A customer's own identity provider as an OpenID Connect relying party.

`oidc.py` verifies Google, and everything about Google except three configured values is pinned
in that file on purpose: an operator must not be able to move that flow, and a discovery
document that is wrong or unreachable must not be able to stop anybody signing in. A customer's
directory is the opposite case. Its issuer is not knowable in advance, nobody here can pin its
endpoints, and the only party who knows them is the customer. So this module fetches discovery
**once, at registration**, validates it hard, and stores the three endpoints on the provider's
row. The flow afterwards reads the row, never the network, so a document that changes or
disappears cannot move a live sign-in or stop one.

What this module decides is one question: which account at that directory is this browser, and
did the directory really say so. Which person that account is, what role they hold and whether
they may act are decided by rows an administrator provisioned, which is why nothing here reads
a principal.

Deprovisioning is the other half. There is no claim in an already-minted token that says an
account was disabled ten minutes ago, and Entra ID transmits no Shared Signals event to an
outside relying party at all. The one mechanism both Entra ID and Okta honour is refusing to
redeem a refresh token once the account is disabled or its sessions are revoked, so that is
what `recheck` does, and it answers with exactly three outcomes because the caller must treat
"the directory says no" and "the directory did not answer" differently.

Every outbound call goes through an injected `httpx.Client`, the same seam #429 uses, so the
tests script a directory in process and CI makes no network call.
"""

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlencode, urlsplit
from uuid import UUID

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from execbound.envelope import KeyRing, unseal
from execbound.signin import (
    MAX_BODY,
    SignInRefused,
    body_of,
    challenge,
    client,
    segment,
)

CALLBACK = "/login/directory/callback"
# `openid profile email` names the person for the display hints, and `offline_access` is what
# the recheck redeems. Nothing here asks for a scope against the directory's own data: the
# refresh token can mint an ID token for this client and nothing else.
SCOPE = "openid profile email offline_access"
# The signature algorithms an ID token may carry, the three this server supports, each tied to
# the one family of key it verifies with: RS256 and PS256 an RSA key, ES256 a P-256 key. A
# directory's keys are filed under their family, so a header can only ever find a key of the
# family its algorithm names and never chooses how a key of another kind is used. Anything
# else, `none` and `HS256` among them, is refused before any key is fetched: an algorithm this
# server cannot check is a refusal and not a fallback.
ALGORITHMS: dict[str, Literal["RSA", "EC"]] = {"RS256": "RSA", "PS256": "RSA", "ES256": "EC"}
_RSA_PADDING: dict[str, padding.AsymmetricPadding] = {
    "RS256": padding.PKCS1v15(),
    "PS256": padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
}
# A P-256 coordinate, and one half of an ES256 signature, is exactly this many bytes (RFC 7518
# 3.4 and 6.2.1.2).
P256_BYTES = 32
PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey
MAX_SKEW = 300
MAX_TOKEN_BYTES = 16384
MAX_REFRESH_BYTES = 4096
MAX_ISSUER = 512
JWKS_TTL = 3600.0
SUBJECT_CLAIMS = ("sub", "oid")
# Entra ID's multi-tenant endpoints. An issuer naming one of them authenticates an account in
# any Microsoft directory in the world, which is the nOAuth class of confusion: a person whose
# address matches signs in from a tenant nobody vetted. A registered issuer names one directory.
ENTRA_HOST = "login.microsoftonline.com"
ENTRA_SHARED = frozenset({"common", "organizations", "consumers"})
_ENTRA = re.compile(r"https://login\.microsoftonline\.com/([^/]+)/v2\.0/?")
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
_UUID = re.compile(r"[0-9a-fA-F-]{36}")
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")


class DirectoryRefused(SignInRefused):
    """A refusal with a private code; the browser is shown one sentence for all of them."""


@dataclass(frozen=True)
class Discovery:
    """The three addresses a flow needs, read once and then stored on the provider's row."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    issuer_tenant: str | None


@dataclass(frozen=True)
class DirectoryAccount:
    """A verified account at a customer's directory.

    `subject` is the value of the claim the provider row names, and is the only thing that
    identifies the account. The two display values are hints: bounded, inert, shown as text and
    never read for a lookup, because an address and a username at a directory are mutable and
    Microsoft's own guidance is to stop identifying people by them.
    """

    subject: str
    display_name: str | None
    display_username: str | None
    refresh_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Recheck:
    """What the directory said about an account this server still has a session for."""

    state: Literal["VERIFIED", "REFUSED", "UNAVAILABLE"]
    code: str
    refresh_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class DirectoryFlow:
    """What the transient cookie carries between the two halves of a directory flow.

    Beyond #429's three values it names the provider, because one redirect URI serves every
    tenant, and either an invitation being redeemed or a signed-in person linking their own
    account. Exactly one of those two is ever set, and a cookie naming both is refused.
    """

    state: str
    nonce: str
    verifier: str
    provider_id: str
    invitation_id: str | None = None
    link_principal: str | None = None

    def encode(self) -> str:
        return ".".join(
            (
                self.state,
                self.nonce,
                self.verifier,
                self.provider_id,
                self.invitation_id or "-",
                self.link_principal or "-",
            )
        )


def new_flow(
    provider_id: str, *, invitation_id: str | None = None, link_principal: str | None = None
) -> DirectoryFlow:
    return DirectoryFlow(
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(48),
        provider_id,
        invitation_id,
        link_principal,
    )


def read_flow(value: object) -> DirectoryFlow:
    """The six values a flow carries, or a refusal; nothing here trusts a length alone.

    This reads the payload. What proves this server wrote it is the MAC `DirectoryConfig`
    puts around it, and every caller goes through `open_flow` rather than here.
    """
    if type(value) is not str or len(value) > 768:
        raise DirectoryRefused("INVALID_STATE")
    parts = value.split(".")
    if len(parts) != 6 or not all(_SEGMENT.fullmatch(part) for part in parts):
        raise DirectoryRefused("INVALID_STATE")
    provider, invitation, principal = parts[3], parts[4], parts[5]
    if _UUID.fullmatch(provider) is None:
        raise DirectoryRefused("INVALID_STATE")
    if invitation != "-" and _UUID.fullmatch(invitation) is None:
        raise DirectoryRefused("INVALID_STATE")
    if principal != "-" and _UUID.fullmatch(principal) is None:
        raise DirectoryRefused("INVALID_STATE")
    if invitation != "-" and principal != "-":
        # An invitation binds a subject to the person the code named; a self-link binds it to
        # the person already signed in. A cookie claiming both is a cookie this server did not
        # write.
        raise DirectoryRefused("INVALID_STATE")
    return DirectoryFlow(
        parts[0],
        parts[1],
        parts[2],
        provider,
        None if invitation == "-" else invitation,
        None if principal == "-" else principal,
    )


def normalize_issuer(value: object) -> str:
    """An issuer this server will register, or a refusal naming what is wrong with it.

    https, a host, no credentials, no query and no fragment, no trailing slash, and short
    enough to store. A cleartext issuer is refused outright: an ID token fetched over http is
    an ID token anybody on the path may have written.
    """
    if type(value) is not str or not 0 < len(value.strip()) <= MAX_ISSUER:
        raise DirectoryRefused("INVALID_ISSUER")
    issuer = value.strip().rstrip("/")
    parsed = urlsplit(issuer)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise DirectoryRefused("INVALID_ISSUER")
    if parsed.hostname == ENTRA_HOST:
        found = _ENTRA.fullmatch(issuer + "/")
        if found is None or found.group(1).lower() in ENTRA_SHARED:
            raise DirectoryRefused("SHARED_ENTRA_ISSUER")
    return issuer


def entra_tenant(issuer: str) -> str | None:
    """The one Microsoft directory an Entra issuer names, derived rather than typed.

    An assertion whose `tid` is anything else is refused, so an account in another Microsoft
    tenant holding the same address cannot sign in here.
    """
    found = _ENTRA.fullmatch(issuer.rstrip("/") + "/")
    return found.group(1) if found is not None else None


def _document(issuer: str, http: httpx.Client | None) -> Any:
    owned = http is None
    session = client(http)
    try:
        response = session.get(
            issuer + "/.well-known/openid-configuration", headers={"Accept": "application/json"}
        )
    except httpx.HTTPError:
        raise DirectoryRefused("DISCOVERY_UNAVAILABLE") from None
    finally:
        if owned:
            session.close()
    return body_of(response, "DISCOVERY_UNAVAILABLE")


def _endpoint(document: dict[str, Any], name: str, host: str) -> str:
    value = document.get(name)
    if type(value) is not str or not 0 < len(value) <= MAX_ISSUER:
        raise DirectoryRefused("DISCOVERY_INCOMPLETE")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise DirectoryRefused("DISCOVERY_INSECURE")
    if parsed.hostname != host:
        # A document that sends the token exchange or the key fetch to a host the issuer does
        # not own is a document that redirects this server's client secret somewhere else.
        raise DirectoryRefused("DISCOVERY_FOREIGN_HOST")
    return value


def _offers(document: dict[str, Any], name: str, value: str, *, required: bool) -> None:
    listed = document.get(name)
    if listed is None and not required:
        return
    if type(listed) is not list or value not in listed:
        raise DirectoryRefused("DISCOVERY_UNSUPPORTED")


def discover(issuer: str, *, http: httpx.Client | None = None) -> Discovery:
    """Fetch and validate a directory's discovery document. Every refusal has its own code."""
    document = _document(issuer, http)
    if type(document) is not dict:
        raise DirectoryRefused("DISCOVERY_INCOMPLETE")
    if document.get("issuer") != issuer:
        # The document must agree with the address it was fetched from, or the issuer claim
        # this server checks on every assertion means nothing.
        raise DirectoryRefused("DISCOVERY_ISSUER_MISMATCH")
    host = urlsplit(issuer).hostname or ""
    _offers(document, "response_types_supported", "code", required=True)
    _offers(document, "code_challenge_methods_supported", "S256", required=False)
    algorithms = document.get("id_token_signing_alg_values_supported")
    if type(algorithms) is not list or not any(
        type(algorithm) is str and algorithm in ALGORITHMS for algorithm in algorithms
    ):
        raise DirectoryRefused("DISCOVERY_UNSUPPORTED")
    return Discovery(
        issuer,
        _endpoint(document, "authorization_endpoint", host),
        _endpoint(document, "token_endpoint", host),
        _endpoint(document, "jwks_uri", host),
        entra_tenant(issuer),
    )


class DirectoryKeys:
    """One directory's signing keys, cached by key id and family, refetched once when missing.

    A key is filed under its `kid` and its family, RSA or EC, so an assertion finds a key only
    of the family its algorithm names: RFC 7517 lets two keys of different types share a `kid`,
    and neither displaces the other here. A key still missing after one refetch is a refusal
    rather than a second fetch, so an assertion naming an unknown key cannot make this server
    call a customer's directory repeatedly.
    """

    def __init__(self, jwks_uri: str, http: httpx.Client | None = None) -> None:
        self._uri = jwks_uri
        self._client = http
        self._keys: dict[tuple[str, str], PublicKey] = {}
        self._fetched_at = 0.0

    def _fetch(self) -> None:
        owned = self._client is None
        session = client(self._client)
        try:
            response = session.get(self._uri, headers={"Accept": "application/json"})
        except httpx.HTTPError:
            raise DirectoryRefused("PROVIDER_UNAVAILABLE") from None
        finally:
            if owned:
                session.close()
        document = body_of(response, "PROVIDER_UNAVAILABLE")
        entries = document.get("keys") if type(document) is dict else None
        keys: dict[tuple[str, str], PublicKey] = {}
        for entry in entries if type(entries) is list else []:
            found = _public_key(entry)
            if found is not None:
                kid, family, public = found
                keys[(kid, family)] = public
        if not keys:
            raise DirectoryRefused("PROVIDER_UNAVAILABLE")
        self._keys = keys
        self._fetched_at = time.monotonic()

    def key(self, kid: str, algorithm: str) -> PublicKey:
        """The key `kid` names in the family `algorithm` needs, or a refusal."""
        family = ALGORITHMS.get(algorithm)
        if family is None:
            raise DirectoryRefused("INVALID_ALGORITHM")
        wanted = (kid, family)
        if wanted not in self._keys or time.monotonic() - self._fetched_at > JWKS_TTL:
            self._fetch()
        if wanted not in self._keys:
            raise DirectoryRefused("UNKNOWN_KEY")
        return self._keys[wanted]


def _public_key(entry: object) -> tuple[str, str, PublicKey] | None:
    """One JWKS entry as its key id, family and public key, or None for one never to use.

    An entry is skipped, never refused, so one key this server cannot use does not stop a
    directory whose other keys it can. Skipped: a type other than RSA or EC; a declared `alg`
    that is not a string naming an algorithm this server verifies with a key of that type
    (`RS256` or `PS256` for RSA, `ES256` for EC), so `RS512` on an RSA key and `ES384` on a
    P-256 key are skipped as well, since this server would never verify under the algorithm
    the key is declared for; a private key, which RFC 7518 marks by its `d` member, since a
    private key a directory published is one anybody may sign with; and, for EC, any curve but
    P-256 and any coordinate that is not exactly 32 bytes or not a point on that curve.

    A declared `alg` admits the key to its family and binds it no tighter: the key is filed by
    `kid` and family, so an RSA key declaring `RS256` also verifies a `PS256` header, and one
    declaring `PS256` an `RS256` header. Either padding still needs the directory's private
    key, and `ES256` is the only EC algorithm, so the family is the binding this server keeps.
    """
    if type(entry) is not dict or "d" in entry:
        return None
    kid, kty, declared = entry.get("kid"), entry.get("kty"), entry.get("alg")
    if type(kid) is not str or kty not in ("RSA", "EC"):
        return None
    if declared is not None and (type(declared) is not str or ALGORITHMS.get(declared) != kty):
        return None
    try:
        if kty == "RSA":
            modulus, exponent = entry.get("n"), entry.get("e")
            if type(modulus) is not str or type(exponent) is not str:
                return None
            numbers = rsa.RSAPublicNumbers(_integer(exponent), _integer(modulus))
            return kid, "RSA", numbers.public_key()
        x, y = entry.get("x"), entry.get("y")
        if entry.get("crv") != "P-256" or type(x) is not str or type(y) is not str:
            return None
        x_bytes, y_bytes = segment(x), segment(y)
        if len(x_bytes) != P256_BYTES or len(y_bytes) != P256_BYTES:
            return None
        # The uncompressed SEC1 point; the library refuses one that is not on the curve.
        point = b"\x04" + x_bytes + y_bytes
        return kid, "EC", ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except ValueError:
        return None


def verify_signature(key: PublicKey, algorithm: str, signed: bytes, signature: bytes) -> None:
    """Check one JWS signature under `algorithm` with `key`, or refuse `INVALID_SIGNATURE`.

    The key must be of the family the algorithm names, checked here as well as by the cache
    that found it, so no path can verify an algorithm with a key of another kind. An ES256
    signature is R and S as exactly 32 bytes each (RFC 7518 3.4); the DER form a signing library
    returns before a JWS library converts it is refused, as is any other length.
    """
    try:
        if algorithm == "ES256":
            if (
                isinstance(key, ec.EllipticCurvePublicKey)
                and isinstance(key.curve, ec.SECP256R1)
                and len(signature) == 2 * P256_BYTES
            ):
                r = int.from_bytes(signature[:P256_BYTES], "big")
                s = int.from_bytes(signature[P256_BYTES:], "big")
                key.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA256()))
                return
        elif algorithm in _RSA_PADDING and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, _RSA_PADDING[algorithm], hashes.SHA256())
            return
    except (InvalidSignature, ValueError):
        pass
    raise DirectoryRefused("INVALID_SIGNATURE")


def _integer(value: str) -> int:
    return int.from_bytes(segment(value), "big")


@dataclass(frozen=True)
class DirectoryProvider:
    """One tenant's registered provider, as the flow uses it.

    Every value here came from the provider's row, which an administrator of that tenant wrote
    and a discovery fetch validated. The client secret is opened from its envelope by the
    caller and held only for the life of this object.
    """

    provider_id: str
    name: str
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    subject_claim: str
    issuer_tenant: str | None
    authorization_endpoint: str
    token_endpoint: str
    redirect_uri: str
    keys: DirectoryKeys
    http: httpx.Client | None = None

    @property
    def authorization_origin(self) -> str:
        """The host a form submission may redirect to, for the pages' `form-action`."""
        parsed = urlsplit(self.authorization_endpoint)
        return f"{parsed.scheme}://{parsed.netloc}"

    def begin(self, flow: DirectoryFlow) -> str:
        """Where the browser is sent. Every value is this server's own; nothing is a request's."""
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": SCOPE,
                "state": flow.state,
                "nonce": flow.nonce,
                "code_challenge": challenge(flow.verifier),
                "code_challenge_method": "S256",
            }
        )
        separator = "&" if urlsplit(self.authorization_endpoint).query else "?"
        return f"{self.authorization_endpoint}{separator}{query}"

    def complete(self, code: str, flow: DirectoryFlow, *, now: float) -> DirectoryAccount:
        body = self._post(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code_verifier": flow.verifier,
            },
            "EXCHANGE_REFUSED",
        )
        if type(body) is not dict:
            raise DirectoryRefused("EXCHANGE_REFUSED")
        claims = self.verify(body.get("id_token"), flow.nonce, now=now)
        return DirectoryAccount(
            self.subject_of(claims),
            _hint(claims.get("name"), 80),
            _hint(claims.get("preferred_username") or claims.get("email"), 120),
            _refresh(body.get("refresh_token")),
        )

    def recheck(self, refresh_token: str, subject: str, *, now: float) -> Recheck:
        """Ask the directory whether this account may still mint a token, and say which answer.

        `invalid_grant` is the one error word that ends a session: it is what both Entra ID and
        Okta answer for an account that was disabled, deleted or had its sessions revoked. Every
        other error word, `invalid_client` included, is unavailability, because a client secret
        rotated at the customer's end is a misconfiguration and ending every session in the
        tenant over one is worse than waiting for somebody to notice.
        """
        try:
            body = self._post(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": SCOPE,
                },
                "RECHECK_UNAVAILABLE",
                refusals={"invalid_grant"},
            )
        except DirectoryRefused as refused:
            if refused.code == "PROVIDER_REFUSED":
                return Recheck("REFUSED", "invalid_grant")
            return Recheck("UNAVAILABLE", refused.code)
        if type(body) is not dict:
            return Recheck("UNAVAILABLE", "RECHECK_UNAVAILABLE")
        try:
            claims = self.verify(body.get("id_token"), None, now=now)
            current = self.subject_of(claims)
        except DirectoryRefused as refused:
            return Recheck("UNAVAILABLE", refused.code)
        if current != subject:
            # The refresh token now names somebody else, which is not a thing a directory does
            # by accident. It is a definitive refusal, not an outage.
            return Recheck("REFUSED", "SUBJECT_CHANGED")
        return Recheck("VERIFIED", "OK", _refresh(body.get("refresh_token")))

    def _post(
        self, form: dict[str, str], code: str, *, refusals: frozenset[str] | set[str] = frozenset()
    ) -> Any:
        owned = self.http is None
        session = client(self.http)
        try:
            response = session.post(
                self.token_endpoint, data=form, headers={"Accept": "application/json"}
            )
        except httpx.HTTPError:
            raise DirectoryRefused(code) from None
        finally:
            if owned:
                session.close()
        if response.status_code != 200:
            word = _error_word(response)
            if word in refusals:
                raise DirectoryRefused("PROVIDER_REFUSED")
            raise DirectoryRefused(code)
        return body_of(response, code)

    def subject_of(self, claims: dict[str, Any]) -> str:
        value = claims.get(self.subject_claim)
        if type(value) is not str or not 0 < len(value) <= 255:
            raise DirectoryRefused("NO_SUBJECT")
        return value

    def verify(self, token: object, nonce: str | None, *, now: float) -> dict[str, Any]:
        """Every check the specification names, each its own refusal.

        The order matters: the algorithm is settled from the header before any key is fetched,
        the signature is checked before any claim is believed, and the claims are checked before
        a subject is read out of them.
        """
        if type(token) is not str or not 0 < len(token) <= MAX_TOKEN_BYTES:
            raise DirectoryRefused("INVALID_TOKEN")
        parts = token.split(".")
        if len(parts) != 3:
            raise DirectoryRefused("INVALID_TOKEN")
        try:
            header = json.loads(segment(parts[0]).decode("utf-8"))
            payload = json.loads(segment(parts[1]).decode("utf-8"))
            signature = segment(parts[2])
        except (ValueError, UnicodeDecodeError):
            raise DirectoryRefused("INVALID_TOKEN") from None
        if type(header) is not dict or type(payload) is not dict:
            raise DirectoryRefused("INVALID_TOKEN")
        algorithm = header.get("alg")
        if type(algorithm) is not str or algorithm not in ALGORITHMS:
            raise DirectoryRefused("INVALID_ALGORITHM")
        kid = header.get("kid")
        if type(kid) is not str or not kid:
            raise DirectoryRefused("INVALID_TOKEN")
        signed = f"{parts[0]}.{parts[1]}".encode("ascii")
        verify_signature(self.keys.key(kid, algorithm), algorithm, signed, signature)
        self._claims(payload, nonce, now)
        return payload

    def _claims(self, payload: dict[str, Any], nonce: str | None, now: float) -> None:
        if payload.get("iss") != self.issuer:
            raise DirectoryRefused("INVALID_ISSUER")
        audience = payload.get("aud")
        if audience != self.client_id and not (
            type(audience) is list and audience == [self.client_id]
        ):
            raise DirectoryRefused("INVALID_AUDIENCE")
        authorized = payload.get("azp")
        if authorized is not None and authorized != self.client_id:
            raise DirectoryRefused("INVALID_AUDIENCE")
        expiry, issued = payload.get("exp"), payload.get("iat")
        if type(expiry) is not int or type(issued) is not int:
            raise DirectoryRefused("INVALID_TIME")
        # `exp` is what bounds a token's age; `iat` is held only to not being in the future.
        # Entra ID backdates `iat` by five minutes by design and describes it as when the
        # authentication occurred, so a token straight from its token endpoint arrived with an
        # `iat` more than MAX_SKEW old and the first real Test sign-in, on 21 September 2026,
        # was refused for it. This token is the one the back channel returned for this flow's
        # code, bound by its nonce and PKCE, so an old `iat` replays nothing (OpenID Connect
        # Core 3.1.3.7 leaves the acceptable range to the client).
        if now >= expiry or issued > now + MAX_SKEW or issued > expiry:
            raise DirectoryRefused("INVALID_TIME")
        if self.issuer_tenant is not None and payload.get("tid") != self.issuer_tenant:
            # The registered issuer names one Microsoft directory; an assertion from any other
            # is refused however well its address matches somebody here.
            raise DirectoryRefused("INVALID_DIRECTORY")
        if nonce is not None:
            supplied = payload.get("nonce")
            # As bytes, as `oidc._claims` compares it: a claim outside ASCII, or a lone
            # surrogate JSON can carry, is a refusal and never an exception.
            if type(supplied) is not str or not secrets.compare_digest(
                supplied.encode("utf-8", "surrogatepass"), nonce.encode()
            ):
                raise DirectoryRefused("INVALID_NONCE")


def _error_word(response: httpx.Response) -> str:
    """The directory's own refusal word, or the empty string. Never quoted anywhere else."""
    if len(response.content) > MAX_BODY:
        return ""
    try:
        body = json.loads(response.content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return ""
    word = body.get("error") if type(body) is dict else None
    return word if type(word) is str and len(word) <= 64 else ""


def _hint(value: object, limit: int) -> str | None:
    """A display value: bounded, stripped, inert, and never a lookup key."""
    if type(value) is not str:
        return None
    trimmed = value.strip()[:limit]
    return trimmed or None


def _refresh(value: object) -> str | None:
    if type(value) is not str or not 0 < len(value) <= MAX_REFRESH_BYTES:
        return None
    return value


@dataclass(frozen=True)
class ProviderRow:
    """One registered provider, exactly as the row holds it.

    The client secret is here as its ciphertext and its key id, never as itself: opening it is
    a deliberate call in `DirectoryConfig.provider`, so a row read for a page or an audit event
    carries nothing that could be used against the customer's directory.
    """

    tenant_id: UUID
    provider_id: UUID
    name: str
    issuer: str
    client_id: str
    secret_ciphertext: str = field(repr=False)
    secret_key_id: str
    subject_claim: str
    issuer_tenant: str | None
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    state: str
    created_at: datetime
    verified_at: datetime | None = None
    enabled_at: datetime | None = None
    disabled_at: datetime | None = None


@dataclass(frozen=True)
class DirectoryConfig:
    """What a deployment needs before any tenant can register a directory at all.

    The ring is the whole of it: without one there is nowhere to keep a customer's client
    secret, so the console offers no registration form and this object does not exist. The
    redirect URI is derived from the deployment's own origin and is the same string for every
    tenant, which is what makes it a value a runbook can print.

    `caches` holds one JWKS cache per provider so a directory's keys are fetched once rather
    than once per sign-in. It is bounded and simply emptied when it fills: a cache is an
    optimisation, and the cost of losing it is one more fetch.
    """

    ring: KeyRing
    origin: str
    http: httpx.Client | None = None
    caches: dict[str, DirectoryKeys] = field(default_factory=dict, repr=False)
    limit: int = 64

    @property
    def redirect_uri(self) -> str:
        return self.origin.rstrip("/") + CALLBACK

    def seal_flow(self, flow: DirectoryFlow) -> str:
        """The flow cookie with a MAC around it, under the ring's active key.

        The cookie has to be authenticated rather than merely opaque, because the callback
        cannot read the session: the directory's redirect back is a cross-site top-level
        navigation and the SameSite=Strict session cookie is not sent with it. So the two
        things the callback trusts the cookie for — which invitation is being redeemed, and
        which person is linking their own account — would otherwise be a caller's to write.
        Both were written on a request this server had already checked; the MAC is what makes
        that still true on the way back.
        """
        encoded = flow.encode()
        digest = hmac.new(
            self.ring.key(self.ring.active_key_id), encoded.encode("ascii"), hashlib.sha256
        )
        return f"{encoded}.{digest.hexdigest()}"

    def open_flow(self, value: object) -> DirectoryFlow:
        """The flow this server wrote, or a refusal.

        Every key in the ring is tried rather than one the cookie names, so a rotation does
        not strand a flow already in the air and the cookie carries no key id to parse: the
        digest is hex, so one `rsplit` on the last dot separates it from a payload that has
        dots of its own.
        """
        if type(value) is not str or len(value) > 1024:
            raise DirectoryRefused("INVALID_STATE")
        encoded, separator, supplied = value.rpartition(".")
        if not separator or _HEX_DIGEST.fullmatch(supplied) is None:
            raise DirectoryRefused("INVALID_STATE")
        raw = encoded.encode("ascii", "ignore")
        if any(
            hmac.compare_digest(hmac.new(key, raw, hashlib.sha256).hexdigest(), supplied)
            for key in self.ring.keys.values()
        ):
            return read_flow(encoded)
        raise DirectoryRefused("INVALID_STATE")

    def keys(self, row: ProviderRow) -> DirectoryKeys:
        found = self.caches.get(str(row.provider_id))
        if found is None:
            if len(self.caches) >= self.limit:
                self.caches.clear()
            found = DirectoryKeys(row.jwks_uri, self.http)
            self.caches[str(row.provider_id)] = found
        return found

    def provider(self, row: ProviderRow) -> DirectoryProvider:
        """The row as a relying party, with its client secret opened for this call's lifetime."""
        return DirectoryProvider(
            str(row.provider_id),
            row.name,
            row.issuer,
            row.client_id,
            unseal(
                self.ring,
                row.secret_ciphertext,
                row.secret_key_id,
                row.tenant_id,
                row.provider_id,
                "client_secret",
            ),
            row.subject_claim,
            row.issuer_tenant,
            row.authorization_endpoint,
            row.token_endpoint,
            self.redirect_uri,
            self.keys(row),
            self.http,
        )
