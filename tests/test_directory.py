# SPDX-License-Identifier: AGPL-3.0-only
"""The relying party for a customer's own identity provider: discovery, the token, the recheck.

No database and no network. The directory is `tests/directory_fixtures.StandIn`, behind an
`httpx.MockTransport` passed in at the seam #429 established, so every refusal below is the
code this server produced and not a timeout somebody's CI produced.
"""

import hashlib
import time
from uuid import UUID, uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from idp_fixtures import (
    CLIENT_ID,
    CLIENT_SECRET,
    HOST,
    ISSUER,
    KID,
    REFRESH,
    ROTATED,
    SUBJECT,
    TENANT_ID,
    StandIn,
    b64,
    claims,
    directory_ec_key,
    directory_key,
    discovery_document,
    ec_jwk,
    jwks_document,
    rsa_jwk,
    sign,
)

from execbound.directory import (
    DirectoryConfig,
    DirectoryKeys,
    DirectoryProvider,
    DirectoryRefused,
    ProviderRow,
    discover,
    entra_tenant,
    new_flow,
    normalize_issuer,
    read_flow,
    verify_signature,
)
from execbound.envelope import KeyRing, seal
from execbound.signin import segment

REDIRECT = "https://app.example/login/directory/callback"


@pytest.fixture(scope="module")
def key():
    return directory_key()


@pytest.fixture(scope="module")
def ec_key():
    return directory_ec_key()


def provider(stand_in: StandIn, *, subject_claim: str = "oid", issuer_tenant=TENANT_ID):
    document = discovery_document()
    return DirectoryProvider(
        str(uuid4()),
        "Contoso",
        ISSUER,
        CLIENT_ID,
        CLIENT_SECRET,
        subject_claim,
        issuer_tenant,
        document["authorization_endpoint"],
        document["token_endpoint"],
        REDIRECT,
        DirectoryKeys(document["jwks_uri"], stand_in.client()),
        stand_in.client(),
    )


# ---- the issuer an administrator may register ------------------------------------------


def test_a_tenant_specific_entra_issuer_is_accepted_and_names_its_directory():
    assert normalize_issuer(ISSUER) == ISSUER
    assert entra_tenant(ISSUER) == TENANT_ID


@pytest.mark.parametrize("shared", ["common", "organizations", "consumers"])
def test_a_shared_entra_issuer_is_refused_because_it_authenticates_any_directory(shared):
    """The nOAuth class: `common` would admit an account in a Microsoft tenant nobody vetted."""
    with pytest.raises(DirectoryRefused) as refused:
        normalize_issuer(f"https://{HOST}/{shared}/v2.0")
    assert refused.value.code == "SHARED_ENTRA_ISSUER"


@pytest.mark.parametrize(
    "value",
    [
        "http://login.example/realm",
        "https://user:pass@login.example/realm",
        "https://login.example/realm?x=1",
        "https://login.example/realm#f",
        "not-a-url",
        "",
        None,
        b"https://login.example",
        "https://" + "a" * 600,
    ],
)
def test_an_issuer_that_is_not_one_is_refused(value):
    with pytest.raises(DirectoryRefused):
        normalize_issuer(value)


def test_an_okta_issuer_carries_no_directory_pin():
    issuer = normalize_issuer("https://dev-1234.okta.com/oauth2/default/")
    assert issuer == "https://dev-1234.okta.com/oauth2/default"
    assert entra_tenant(issuer) is None


# ---- discovery, validated once and then stored -----------------------------------------


def test_discovery_answers_the_three_endpoints_and_the_directory(key):
    found = discover(ISSUER, http=StandIn(key).client())
    document = discovery_document()
    assert found.authorization_endpoint == document["authorization_endpoint"]
    assert found.token_endpoint == document["token_endpoint"]
    assert found.jwks_uri == document["jwks_uri"]
    assert found.issuer_tenant == TENANT_ID


def test_a_document_that_names_another_issuer_is_refused(key):
    stand_in = StandIn(key, discovery=discovery_document(issuer="https://elsewhere.example"))
    with pytest.raises(DirectoryRefused) as refused:
        discover(ISSUER, http=stand_in.client())
    assert refused.value.code == "DISCOVERY_ISSUER_MISMATCH"


def test_a_token_endpoint_on_another_host_is_refused(key):
    """A document that moves the exchange moves this server's client secret with it."""
    stand_in = StandIn(
        key, discovery=discovery_document(token_endpoint="https://collector.example/token")
    )
    with pytest.raises(DirectoryRefused) as refused:
        discover(ISSUER, http=stand_in.client())
    assert refused.value.code == "DISCOVERY_FOREIGN_HOST"


def test_a_cleartext_endpoint_is_refused(key):
    stand_in = StandIn(
        key, discovery=discovery_document(jwks_uri=f"http://{HOST}/{TENANT_ID}/keys")
    )
    with pytest.raises(DirectoryRefused) as refused:
        discover(ISSUER, http=stand_in.client())
    assert refused.value.code == "DISCOVERY_INSECURE"


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"response_types_supported": ["id_token"]}, "DISCOVERY_UNSUPPORTED"),
        ({"code_challenge_methods_supported": ["plain"]}, "DISCOVERY_UNSUPPORTED"),
        ({"id_token_signing_alg_values_supported": ["HS256"]}, "DISCOVERY_UNSUPPORTED"),
        ({"id_token_signing_alg_values_supported": ["ES384", "RS512"]}, "DISCOVERY_UNSUPPORTED"),
        # A list where an algorithm's name belongs is a document this server cannot read, and
        # a refusal rather than an exception.
        ({"id_token_signing_alg_values_supported": [["RS256"]]}, "DISCOVERY_UNSUPPORTED"),
        ({"id_token_signing_alg_values_supported": "RS256"}, "DISCOVERY_UNSUPPORTED"),
        ({"token_endpoint": None}, "DISCOVERY_INCOMPLETE"),
    ],
)
def test_a_directory_this_server_cannot_speak_to_is_refused(key, changes, code):
    stand_in = StandIn(key, discovery=discovery_document(**changes))
    with pytest.raises(DirectoryRefused) as refused:
        discover(ISSUER, http=stand_in.client())
    assert refused.value.code == code


@pytest.mark.parametrize(
    "offered", [["ES256"], ["PS256"], ["RS256", "ES256"], [["ES256"], "RS256"]]
)
def test_a_directory_signing_with_any_algorithm_this_server_verifies_registers(key, offered):
    """RS256, PS256 and ES256, the three this server verifies. A list where a name belongs is
    passed over, so the name beside it still registers the directory."""
    stand_in = StandIn(
        key, discovery=discovery_document(id_token_signing_alg_values_supported=offered)
    )
    assert discover(ISSUER, http=stand_in.client()).issuer == ISSUER


def test_an_unreachable_directory_is_refused_and_nothing_is_saved(key):
    with pytest.raises(DirectoryRefused) as refused:
        discover(ISSUER, http=StandIn(key, unreachable=True).client())
    assert refused.value.code == "DISCOVERY_UNAVAILABLE"


# ---- the authorization request ---------------------------------------------------------


def test_the_authorization_request_carries_only_this_servers_own_values(key):
    stand_in = StandIn(key)
    flow = new_flow(str(uuid4()))
    location = provider(stand_in).begin(flow)
    assert location.startswith(discovery_document()["authorization_endpoint"] + "?")
    assert f"state={flow.state}" in location
    assert f"nonce={flow.nonce}" in location
    assert "code_challenge_method=S256" in location
    assert "offline_access" in location
    assert flow.verifier not in location


def test_the_flow_cookie_round_trips_and_refuses_what_this_server_did_not_write():
    flow = new_flow(str(uuid4()), invitation_id=str(uuid4()))
    assert read_flow(flow.encode()) == flow
    both = new_flow(str(uuid4()), invitation_id=str(uuid4()))
    forged = f"{both.state}.{both.nonce}.{both.verifier}.{both.provider_id}.{uuid4()}.{uuid4()}"
    for value in ("", "a.b", forged, "x" * 800, None, f"{both.state}.{both.nonce}.v.nope.-.-"):
        with pytest.raises(DirectoryRefused):
            read_flow(value)


# ---- the assertion ---------------------------------------------------------------------


def test_a_good_assertion_answers_the_subject_and_the_display_hints(key):
    stand_in = StandIn(key)
    flow = new_flow(str(uuid4()))
    account = provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert account.subject == SUBJECT
    assert account.display_name == "Dana Reyes"
    assert account.display_username == "dana@contoso.example"
    assert account.refresh_token == REFRESH


def test_the_subject_claim_the_row_names_is_the_one_read(key):
    stand_in = StandIn(key)
    flow = new_flow(str(uuid4()))
    account = provider(stand_in, subject_claim="sub").complete(
        "the-code", _with_nonce(stand_in, flow), now=time.time()
    )
    assert account.subject == "pairwise-" + SUBJECT


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"iss": "https://elsewhere.example"}, "INVALID_ISSUER"),
        ({"aud": "another-client"}, "INVALID_AUDIENCE"),
        ({"azp": "another-client"}, "INVALID_AUDIENCE"),
        ({"exp": 1}, "INVALID_TIME"),
        # A day ahead: an `iat` in the future beyond the skew. An old one is Entra's normal.
        ({"iat": int(time.time()) + 86400}, "INVALID_TIME"),
        (
            {"iat": int(time.time()) + 3 * 86400, "exp": int(time.time()) + 2 * 86400},
            "INVALID_TIME",
        ),
        ({"tid": "11111111-0000-4000-8000-000000000000"}, "INVALID_DIRECTORY"),
        ({"oid": None}, "NO_SUBJECT"),
    ],
)
def test_every_claim_this_server_checks_has_its_own_refusal(key, changes, code):
    stand_in = StandIn(key, claim_changes=changes)
    flow = new_flow(str(uuid4()))
    with pytest.raises(DirectoryRefused) as refused:
        provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert refused.value.code == code


@pytest.mark.parametrize("age", [305, 3600, 2 * 86400])
def test_an_issued_at_in_the_past_is_accepted_as_entra_sends_it(key, age):
    """Entra ID backdates `iat` by five minutes by design and describes it as when the
    authentication occurred, so a token straight from its token endpoint arrives with an `iat`
    past any five-minute window. On 21 September 2026 the first real Test sign-in was refused
    `INVALID_TIME` for exactly that. What bounds a token's age is `exp`; the token is this
    flow's, from the back channel, under its nonce and PKCE, so an old `iat` replays nothing."""
    stand_in = StandIn(key, claim_changes={"iat": int(time.time()) - age})
    flow = new_flow(str(uuid4()))
    account = provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert account.subject == SUBJECT


@pytest.mark.parametrize("nonce", ["a-different-nonce", "a-nonce-outside-ascii-ü", "\ud800"])
def test_a_replayed_nonce_is_refused(key, nonce):
    stand_in = StandIn(key, nonce=nonce)
    with pytest.raises(DirectoryRefused) as refused:
        provider(stand_in).complete("the-code", new_flow(str(uuid4())), now=time.time())
    assert refused.value.code == "INVALID_NONCE"


@pytest.mark.parametrize("alg", ["none", "HS256", "ES384", "ES512", "RS512", "EdDSA"])
def test_an_algorithm_this_server_cannot_verify_is_refused_before_any_key_is_fetched(key, alg):
    stand_in = StandIn(key, alg=alg)
    flow = new_flow(str(uuid4()))
    with pytest.raises(DirectoryRefused) as refused:
        provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert refused.value.code == "INVALID_ALGORITHM"
    assert stand_in.fetches == []


def test_a_ps256_assertion_verifies(key):
    stand_in = StandIn(key, alg="PS256")
    flow = new_flow(str(uuid4()))
    account = provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert account.subject == SUBJECT


@pytest.mark.parametrize(
    "declared,alg",
    [
        pytest.param("RS256", "PS256", id="declares-rs256-signs-ps256"),
        pytest.param("PS256", "RS256", id="declares-ps256-signs-rs256"),
    ],
)
def test_a_declared_rsa_alg_admits_the_key_to_its_family_and_binds_it_no_tighter(
    key, declared, alg
):
    """A key is filed by `kid` and family, so an RSA key declaring one of the two RSA
    algorithms this server verifies also verifies the other: both paddings need the
    directory's private key, and this is the binding `_public_key` describes."""
    stand_in = StandIn(key, jwks={"keys": [rsa_jwk(key, alg=declared)]}, alg=alg)
    flow = new_flow(str(uuid4()))
    account = provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert account.subject == SUBJECT


# ---- ES256, and keeping each algorithm to its own family of key ---------------------------


def test_an_es256_assertion_verifies(ec_key):
    stand_in = StandIn(ec_key, alg="ES256")
    flow = new_flow(str(uuid4()))
    account = provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert account.subject == SUBJECT
    assert account.refresh_token == REFRESH
    assert len(stand_in.fetches) == 1


def test_an_es256_refresh_verifies_and_rotates(ec_key):
    answer = provider(StandIn(ec_key, alg="ES256")).recheck(REFRESH, SUBJECT, now=time.time())
    assert answer.state == "VERIFIED"
    assert answer.refresh_token == ROTATED


def test_a_key_set_holding_both_families_serves_each_its_own_algorithm(key, ec_key):
    """RFC 7517 4.5 lets two keys of different types share a `kid`; each is filed under its own
    family, so neither displaces the other and each verifies only its own algorithm."""
    both = {"keys": [rsa_jwk(key), ec_jwk(ec_key)]}
    for signer, alg in ((key, "RS256"), (key, "PS256"), (ec_key, "ES256")):
        stand_in = StandIn(signer, alg=alg, jwks=both)
        flow = new_flow(str(uuid4()))
        account = provider(stand_in).complete(
            "the-code", _with_nonce(stand_in, flow), now=time.time()
        )
        assert account.subject == SUBJECT


@pytest.mark.parametrize(
    "header_alg,published",
    [
        # An ES256 header whose `kid` names only an RSA key, and an RS256 or PS256 header whose
        # `kid` names only a P-256 key: no key of the algorithm's own family exists.
        ("ES256", "rsa"),
        ("RS256", "ec"),
        ("PS256", "ec"),
    ],
)
def test_an_algorithm_finds_no_key_of_another_family_under_its_kid(
    key, ec_key, header_alg, published
):
    """The algorithm confusion class: a header must never choose how a key it did not pick is
    used. The cache is cold here, so its first read is its only one and finds no key of the
    algorithm's family; the warm-cache tests below show the one further read."""
    signer = ec_key if header_alg == "ES256" else key
    jwks = {"keys": [rsa_jwk(key) if published == "rsa" else ec_jwk(ec_key)]}
    stand_in = StandIn(signer, alg=header_alg, jwks=jwks)
    flow = new_flow(str(uuid4()))
    with pytest.raises(DirectoryRefused) as refused:
        provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert refused.value.code == "UNKNOWN_KEY"
    assert len(stand_in.fetches) == 1


def _reshaped(token: str, change) -> str:
    header, body, signature = token.split(".")
    return f"{header}.{body}.{b64(change(segment(signature)))}"


def _der(raw: bytes) -> bytes:
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


@pytest.mark.parametrize(
    "change",
    [
        # The same signature in ASN.1 DER, which is what a library hands back before a JWS
        # library converts it; RFC 7518 3.4 has R and S as exactly 32 bytes each, nothing else.
        pytest.param(_der, id="der"),
        pytest.param(lambda raw: raw[:63], id="63-bytes"),
        pytest.param(lambda raw: raw + b"\x00", id="65-bytes"),
        # S with a leading zero byte names the same integer, so only the length refuses it.
        pytest.param(lambda raw: raw[:32] + b"\x00" + raw[32:], id="s-zero-padded"),
        pytest.param(lambda raw: b"\x00" + raw[:31] + raw[32:], id="shifted"),
        pytest.param(lambda raw: bytes(64), id="zero"),
        pytest.param(lambda raw: raw[:32] + bytes(32), id="zero-s"),
        pytest.param(lambda raw: raw[32:] + raw[:32], id="swapped"),
    ],
)
def test_an_es256_signature_in_any_other_form_is_refused(ec_key, change):
    stand_in = StandIn(ec_key, alg="ES256")
    issued = stand_in.id_token
    stand_in.id_token = lambda **named: _reshaped(issued(**named), change)
    flow = new_flow(str(uuid4()))
    with pytest.raises(DirectoryRefused) as refused:
        provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert refused.value.code == "INVALID_SIGNATURE"


def test_an_es256_signature_by_another_p256_key_is_refused(ec_key):
    stand_in = StandIn(directory_ec_key(), alg="ES256", jwks=jwks_document(ec_key))
    flow = new_flow(str(uuid4()))
    with pytest.raises(DirectoryRefused) as refused:
        provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert refused.value.code == "INVALID_SIGNATURE"


def _off_curve(ec_key) -> dict:
    numbers = ec_key.public_key().public_numbers()
    return ec_jwk(ec_key, y=b64(((numbers.y + 1) % 2**256).to_bytes(32, "big")))


def _short_x(ec_key) -> dict:
    entry = ec_jwk(ec_key)
    return {**entry, "x": b64(segment(entry["x"])[1:])}


def _long_y(ec_key) -> dict:
    entry = ec_jwk(ec_key)
    return {**entry, "y": b64(b"\x00" + segment(entry["y"]))}


def _resplit(at: int):
    """The key's own 64 bytes of point, cut at `at` instead of 32. Joined again they are the
    same SEC1 point, which the library accepts as this very key, so the coordinate-length rule
    is the only thing that refuses it. A 31- or 33-byte coordinate alone makes a point of the
    wrong total length, which the library refuses whether or not the rule is there."""

    def entry(ec_key) -> dict:
        published = ec_jwk(ec_key)
        point = segment(published["x"]) + segment(published["y"])
        return {**published, "x": b64(point[:at]), "y": b64(point[at:])}

    return entry


def _private(ec_key) -> dict:
    scalar = ec_key.private_numbers().private_value
    return ec_jwk(ec_key, d=b64(scalar.to_bytes(32, "big")))


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param(lambda k: ec_jwk(k, crv="P-384"), id="named-p384"),
        pytest.param(lambda k: ec_jwk(k, crv=None), id="no-curve"),
        pytest.param(lambda k: ec_jwk(k, alg="ES384"), id="declares-es384"),
        pytest.param(lambda k: ec_jwk(k, alg="RS256"), id="declares-rs256"),
        pytest.param(lambda k: ec_jwk(k, alg=["ES256"]), id="declares-a-list"),
        pytest.param(lambda k: ec_jwk(k, x=None), id="no-x"),
        pytest.param(lambda k: ec_jwk(k, y=12), id="y-not-text"),
        pytest.param(lambda k: ec_jwk(k, x="not base64url!"), id="x-not-base64url"),
        pytest.param(_off_curve, id="off-curve"),
        pytest.param(_short_x, id="x-31-bytes"),
        pytest.param(_long_y, id="y-33-bytes"),
        pytest.param(_resplit(31), id="same-point-x-31-y-33"),
        pytest.param(_resplit(33), id="same-point-x-33-y-31"),
        # A published private key is a compromised one: anybody may sign with it.
        pytest.param(_private, id="private"),
    ],
)
def test_an_ec_entry_this_server_must_not_use_is_skipped(ec_key, entry):
    stand_in = StandIn(ec_key, alg="ES256", jwks={"keys": [entry(ec_key)]})
    flow = new_flow(str(uuid4()))
    with pytest.raises(DirectoryRefused) as refused:
        provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    # A set holding nothing this server can use is the directory's failure, not the token's.
    assert refused.value.code == "PROVIDER_UNAVAILABLE"
    assert len(stand_in.fetches) == 1


def test_a_skipped_ec_entry_leaves_the_kid_unknown_beside_a_usable_key(key, ec_key):
    """Beside a usable RSA key the set is read, the P-384 key under the `kid` is skipped, and
    the ES256 assertion naming it is refused with the set read once."""
    p384 = directory_ec_key(ec.SECP384R1())
    jwks = {"keys": [rsa_jwk(key, kid="rsa-key"), ec_jwk(p384, crv="P-256")]}
    stand_in = StandIn(ec_key, alg="ES256", jwks=jwks)
    flow = new_flow(str(uuid4()))
    with pytest.raises(DirectoryRefused) as refused:
        provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert refused.value.code == "UNKNOWN_KEY"
    assert len(stand_in.fetches) == 1


def test_an_entry_declaring_a_list_beside_a_usable_key_leaves_sign_in_working(key):
    """The entry is skipped, not the set: the usable RSA key beside it still signs in."""
    jwks = {"keys": [rsa_jwk(key, kid="listed", alg=["RS256"]), rsa_jwk(key)]}
    stand_in = StandIn(key, jwks=jwks)
    flow = new_flow(str(uuid4()))
    account = provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert account.subject == SUBJECT


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"alg": "ES256"}, id="declares-es256"),
        # RSA algorithms this server does not verify: a key declared for one is never used.
        pytest.param({"alg": "RS512"}, id="declares-rs512"),
        pytest.param({"alg": "PS384"}, id="declares-ps384"),
        pytest.param({"alg": ["RS256"]}, id="declares-a-list"),
        pytest.param({"d": "AQAB"}, id="private"),
    ],
)
def test_an_rsa_entry_this_server_must_not_use_is_skipped(key, changes):
    stand_in = StandIn(key, jwks={"keys": [rsa_jwk(key, **changes)]})
    flow = new_flow(str(uuid4()))
    with pytest.raises(DirectoryRefused) as refused:
        provider(stand_in).complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert refused.value.code == "PROVIDER_UNAVAILABLE"


@pytest.mark.parametrize(
    "public,algorithm",
    [
        pytest.param("rsa", "ES256", id="rsa-key-es256"),
        pytest.param("p256", "RS256", id="p256-key-rs256"),
        pytest.param("p256", "PS256", id="p256-key-ps256"),
        pytest.param("p256", "HS256", id="p256-key-hs256"),
        pytest.param("rsa", "none", id="rsa-key-none"),
    ],
)
def test_the_signature_check_refuses_a_key_the_algorithm_does_not_name(
    key, ec_key, public, algorithm
):
    """The key cache already files keys by family; this is the check under it, so a caller
    that ever hands it a key of the wrong type gets a refusal and never an exception. A key of
    one type cannot verify the other's signature at all, so the test after this one shows the
    refusal holding where a verification is possible."""
    chosen = {"rsa": key.public_key(), "p256": ec_key.public_key()}[public]
    with pytest.raises(DirectoryRefused) as refused:
        verify_signature(chosen, algorithm, b"signed", bytes(64))
    assert refused.value.code == "INVALID_SIGNATURE"


# P-384's field prime and group order (SEC 2, section 2.5.1).
P384_PRIME = 2**384 - 2**128 - 2**96 + 2**32 - 1
P384_ORDER = int(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    16,
)


def _p384_key_verifying(message: bytes) -> tuple[ec.EllipticCurvePublicKey, bytes]:
    """A P-384 public key, and a 64-byte R and S it verifies over `message` with SHA-256.

    ECDSA lets anybody choose the signature first and solve for a key. With S equal to R,
    verification computes (e/R)G + Q and compares its x with R, so Q = P - (e/R)G verifies for
    any point P whose x is R. An x below 2**256 makes R and S fit the 32 bytes each that an
    ES256 signature has, so the length check cannot refuse it and only the curve check can.
    """
    curve = ec.SECP384R1()
    generator = ec.derive_private_key(1, curve).public_key().public_numbers()
    b = (generator.y**2 - generator.x**3 + 3 * generator.x) % P384_PRIME
    r = int.from_bytes(hashlib.sha256(b"an x below 2**256").digest(), "big")
    while True:
        # P-384's prime is 3 mod 4, so a square root, where one exists, is a single power.
        square = (r**3 - 3 * r + b) % P384_PRIME
        y = pow(square, (P384_PRIME + 1) // 4, P384_PRIME)
        if y * y % P384_PRIME == square:
            break
        r += 1
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    shift = ec.derive_private_key(e * pow(r, -1, P384_ORDER) % P384_ORDER, curve)
    kx, ky = shift.public_key().public_numbers().x, shift.public_key().public_numbers().y
    # Q = P + (-kG), one affine addition of two points with different x.
    slope = ((-ky) - y) * pow(kx - r, -1, P384_PRIME) % P384_PRIME
    qx = (slope * slope - r - kx) % P384_PRIME
    qy = (slope * (r - qx) - y) % P384_PRIME
    public = ec.EllipticCurvePublicNumbers(qx, qy, curve).public_key()
    return public, r.to_bytes(32, "big") * 2


def test_the_signature_check_never_verifies_es256_with_a_p384_key():
    """ES256 names P-256. A P-384 key that really does verify this 64-byte signature with
    SHA-256 is still refused, so the curve is checked and not left to the signature's length."""
    public, signature = _p384_key_verifying(b"signed")
    # The key accepts the signature: this raises nothing.
    public.verify(_der(signature), b"signed", ec.ECDSA(hashes.SHA256()))
    with pytest.raises(DirectoryRefused) as refused:
        verify_signature(public, "ES256", b"signed", signature)
    assert refused.value.code == "INVALID_SIGNATURE"


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_an_unknown_key_is_refetched_once_and_then_refused(key, ec_key, alg):
    """The cache is warmed by an earlier sign-in's key, so the assertion's unknown `kid` is a
    miss: the set is read exactly once more and the assertion refused."""
    stand_in = StandIn(ec_key if alg == "ES256" else key, alg=alg, jwks_kid="some-other-key")
    signing_in = provider(stand_in)
    signing_in.keys.key("some-other-key", alg)
    assert len(stand_in.fetches) == 1
    flow = new_flow(str(uuid4()))
    with pytest.raises(DirectoryRefused) as refused:
        signing_in.complete("the-code", _with_nonce(stand_in, flow), now=time.time())
    assert refused.value.code == "UNKNOWN_KEY"
    assert len(stand_in.fetches) == 2


# ---- the key cache: a hit reads nothing, a miss reads the set exactly once more --------


def _cache(stand_in: StandIn) -> DirectoryKeys:
    return DirectoryKeys(discovery_document()["jwks_uri"], stand_in.client())


def test_a_warm_cache_answers_a_key_it_holds_without_reading_the_set(key):
    stand_in = StandIn(key)
    keys = _cache(stand_in)
    first = keys.key(KID, "RS256")
    assert len(stand_in.fetches) == 1
    # PS256 needs the same family under the same `kid`, so it is the same cached key.
    assert keys.key(KID, "RS256") is first
    assert keys.key(KID, "PS256") is first
    assert len(stand_in.fetches) == 1


def test_a_family_a_warm_cache_lacks_reads_the_set_once_more_and_is_refused(key):
    """An RSA key is cached under the `kid` and an ES256 assertion names it. The set is read
    exactly once more, in case the directory has since published a P-256 key there, and the
    assertion is then refused; the RSA key is answered from that read with no other."""
    stand_in = StandIn(key)
    keys = _cache(stand_in)
    keys.key(KID, "RS256")
    with pytest.raises(DirectoryRefused) as refused:
        keys.key(KID, "ES256")
    assert refused.value.code == "UNKNOWN_KEY"
    assert len(stand_in.fetches) == 2
    keys.key(KID, "RS256")
    assert len(stand_in.fetches) == 2


@pytest.mark.parametrize("change", ["rotated-kid", "p256-under-the-rsa-kid"])
def test_a_key_published_after_the_cache_was_warmed_is_found_by_one_more_read(key, ec_key, change):
    """A directory that rotates to a new `kid`, or publishes a P-256 key under a `kid` it
    already uses for RSA, is answered at the next assertion naming it, not after the cache's
    time to live."""
    stand_in = StandIn(key)
    keys = _cache(stand_in)
    keys.key(KID, "RS256")
    if change == "rotated-kid":
        rotated = directory_key()
        stand_in.jwks = {"keys": [rsa_jwk(key), rsa_jwk(rotated, kid="rotated-key")]}
        found, expected = keys.key("rotated-key", "RS256"), rotated
    else:
        stand_in.jwks = {"keys": [rsa_jwk(key), ec_jwk(ec_key)]}
        found, expected = keys.key(KID, "ES256"), ec_key
    assert found.public_numbers() == expected.public_key().public_numbers()
    assert len(stand_in.fetches) == 2


def test_a_forged_signature_is_refused(key):
    other = directory_key()
    document = discovery_document()

    def handler(request: httpx.Request) -> httpx.Response:
        if "/keys" in str(request.url):
            return httpx.Response(200, json=jwks_document(key))
        return httpx.Response(
            200, json={"id_token": sign(other, claims(time.time(), "n")), "refresh_token": REFRESH}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    built = DirectoryProvider(
        str(uuid4()),
        "Contoso",
        ISSUER,
        CLIENT_ID,
        CLIENT_SECRET,
        "oid",
        TENANT_ID,
        document["authorization_endpoint"],
        document["token_endpoint"],
        REDIRECT,
        DirectoryKeys(document["jwks_uri"], client),
        client,
    )
    flow = new_flow(str(uuid4()))
    with pytest.raises(DirectoryRefused) as refused:
        built.complete(
            "the-code",
            flow.__class__(flow.state, "n", flow.verifier, flow.provider_id),
            now=time.time(),
        )
    assert refused.value.code == "INVALID_SIGNATURE"


def test_a_refused_exchange_never_reaches_the_verification(key):
    stand_in = StandIn(key, token_status=400, token_body={"error": "invalid_grant"})
    with pytest.raises(DirectoryRefused) as refused:
        provider(stand_in).complete("the-code", new_flow(str(uuid4())), now=time.time())
    assert refused.value.code == "EXCHANGE_REFUSED"


# ---- the recheck, and its three answers ------------------------------------------------


def test_a_redeemed_refresh_token_verifies_and_rotates(key):
    stand_in = StandIn(key)
    answer = provider(stand_in).recheck(REFRESH, SUBJECT, now=time.time())
    assert answer.state == "VERIFIED"
    assert answer.refresh_token == ROTATED


def test_invalid_grant_ends_the_session(key):
    """What Entra ID and Okta both answer for an account that was disabled or deleted."""
    stand_in = StandIn(key, refresh_status=400, refresh_body={"error": "invalid_grant"})
    answer = provider(stand_in).recheck(REFRESH, SUBJECT, now=time.time())
    assert answer.state == "REFUSED"
    assert answer.code == "invalid_grant"


def test_a_subject_that_changed_ends_the_session(key):
    stand_in = StandIn(key, refresh_claims={"oid": "11111111-0000-4000-8000-0000000000ff"})
    answer = provider(stand_in).recheck(REFRESH, SUBJECT, now=time.time())
    assert answer.state == "REFUSED"
    assert answer.code == "SUBJECT_CHANGED"


@pytest.mark.parametrize(
    "changes",
    [
        {"refresh_status": 400, "refresh_body": {"error": "invalid_client"}},
        {"refresh_status": 500, "refresh_body": {"error": "server_error"}},
        {"unreachable": True},
    ],
)
def test_anything_but_a_definitive_refusal_is_unavailability(key, changes):
    """A client secret rotated at the customer's end must not end every session in the tenant."""
    answer = provider(StandIn(key, **changes)).recheck(REFRESH, SUBJECT, now=time.time())
    assert answer.state == "UNAVAILABLE"


def test_an_unverifiable_answer_is_unavailability_rather_than_a_refusal(key):
    stand_in = StandIn(key, refresh_body={"id_token": "not-a-token"}, refresh_status=200)
    answer = provider(stand_in).recheck(REFRESH, SUBJECT, now=time.time())
    assert answer.state == "UNAVAILABLE"


def test_neither_the_client_secret_nor_a_refresh_token_is_in_a_repr(key):
    built = provider(StandIn(key))
    assert CLIENT_SECRET not in repr(built)
    answer = provider(StandIn(key)).recheck(REFRESH, SUBJECT, now=time.time())
    assert ROTATED not in repr(answer)


# ---- the deployment's settings ----------------------------------------------------------


def test_the_redirect_uri_is_one_string_for_every_tenant():
    ring = KeyRing("k1", {"k1": bytes(32)})
    settings = DirectoryConfig(ring, "https://gateway.example")
    assert settings.redirect_uri == "https://gateway.example/login/directory/callback"


def test_a_provider_row_becomes_a_relying_party_with_its_secret_opened(key):
    ring = KeyRing("k1", {"k1": bytes(range(32))})
    tenant, identifier = uuid4(), uuid4()
    ciphertext, key_id = seal(ring, CLIENT_SECRET, tenant, identifier, "client_secret")
    document = discovery_document()
    row = ProviderRow(
        tenant_id=tenant,
        provider_id=identifier,
        name="Contoso",
        issuer=ISSUER,
        client_id=CLIENT_ID,
        secret_ciphertext=ciphertext,
        secret_key_id=key_id,
        subject_claim="oid",
        issuer_tenant=TENANT_ID,
        authorization_endpoint=document["authorization_endpoint"],
        token_endpoint=document["token_endpoint"],
        jwks_uri=document["jwks_uri"],
        state="enabled",
        created_at=None,
    )
    settings = DirectoryConfig(ring, "https://app.example", StandIn(key).client())
    built = settings.provider(row)
    assert built.client_secret == CLIENT_SECRET
    assert built.authorization_origin == f"https://{HOST}"
    # One cache per provider, so a second sign-in through the same directory fetches no keys.
    assert settings.keys(row) is built.keys


def _with_nonce(stand_in: StandIn, flow):
    stand_in.nonce = flow.nonce
    return flow


def test_a_provider_id_is_a_uuid_string_everywhere_it_travels():
    flow = new_flow(str(uuid4()))
    assert UUID(read_flow(flow.encode()).provider_id)
    assert KID  # the fixture's key id is used by every assertion above
