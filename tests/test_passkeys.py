# SPDX-License-Identifier: AGPL-3.0-only
"""Cryptographically valid WebAuthn ceremonies, including origin and replay refusal."""

import base64
import hashlib
import json
import secrets

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from sqlalchemy import text
from test_human_sessions import humans as humans
from test_mfa_sessions import enrolled

from execbound import passkeys
from execbound.mfa import saved_passkeys
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration
ORIGIN = "http://127.0.0.1"


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def registration(options, origin=ORIGIN):
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32), -3: numbers.y.to_bytes(32)})
    credential = secrets.token_bytes(32)
    auth = (
        hashlib.sha256(b"127.0.0.1").digest()
        + b"\x45"
        + bytes(4)
        + bytes(16)
        + len(credential).to_bytes(2)
        + credential
        + key
    )
    client = json.dumps(
        {"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}
    ).encode()
    response = {
        "id": b64(credential),
        "rawId": b64(credential),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(client),
            "attestationObject": b64(cbor2.dumps({"fmt": "none", "authData": auth, "attStmt": {}})),
        },
    }
    return private, credential, response


def assertion(options, private, credential, *, uv=True, origin=ORIGIN, count=1):
    """`count` is the authenticator's signature counter, which must rise from one use to the
    next of the same passkey."""
    auth = hashlib.sha256(b"127.0.0.1").digest() + (b"\x05" if uv else b"\x01") + count.to_bytes(4)
    client = json.dumps(
        {"type": "webauthn.get", "challenge": options["challenge"], "origin": origin}
    ).encode()
    signature = private.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "id": b64(credential),
        "rawId": b64(credential),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(client),
            "authenticatorData": b64(auth),
            "signature": b64(signature),
        },
    }


def test_passkey_registration_authentication_and_single_use_challenge(db, humans):
    clock, grant, _ = enrolled(db, humans)
    session = load_session(db, grant.token, clock=clock)
    options = passkeys.begin(db, session, ORIGIN, "register", clock=clock)
    private, credential, response = registration(options)
    assert passkeys.complete(db, session, ORIGIN, "register", response, clock=clock)
    assert not passkeys.complete(db, session, ORIGIN, "register", response, clock=clock)
    pending_grant = issue_session(db, humans[0], clock=clock)
    pending = load_session(db, pending_grant.token, clock=clock, allow_pending_mfa=True)
    options = passkeys.begin(db, pending, ORIGIN, "authenticate", clock=clock)
    assert passkeys.complete(
        db, pending, ORIGIN, "authenticate", assertion(options, private, credential), clock=clock
    )
    assert not load_session(db, pending_grant.token, clock=clock).mfa_required


@pytest.mark.parametrize("fault", ["origin", "verification", "signature"])
def test_authentication_rejects_wrong_origin_missing_user_verification_and_forgery(
    db, humans, fault
):
    clock, grant, _ = enrolled(db, humans)
    session = load_session(db, grant.token, clock=clock)
    options = passkeys.begin(db, session, ORIGIN, "register", clock=clock)
    private, credential, response = registration(options)
    assert passkeys.complete(db, session, ORIGIN, "register", response, clock=clock)
    pending_grant = issue_session(db, humans[0], clock=clock)
    pending = load_session(db, pending_grant.token, clock=clock, allow_pending_mfa=True)
    options = passkeys.begin(db, pending, ORIGIN, "authenticate", clock=clock)
    response = assertion(
        options,
        private,
        credential,
        uv=fault != "verification",
        origin="https://evil.example" if fault == "origin" else ORIGIN,
    )
    if fault == "signature":
        response["response"]["signature"] = b64(bytes(64))
    assert not passkeys.complete(db, pending, ORIGIN, "authenticate", response, clock=clock)
    assert load_session(db, pending_grant.token, clock=clock, allow_pending_mfa=True).mfa_required


# The algorithms a registration offers and accepts, in order: py_webauthn 2.7.0's default list.
# 3.0 narrowed its default to EdDSA, ES256 and RS256 and put EdDSA first; ExecBound passes this
# list itself so the upgrade changed neither what a browser is asked for nor what a passkey
# may use. Narrowing it is a separate decision, and this pin makes that a reviewed diff.
OFFERED = [-7, -8, -36, -37, -38, -39, -257, -258, -259]


def authenticator_data(credential, public_key):
    """Registration authenticator data: user present and verified, attested credential data."""
    return (
        hashlib.sha256(b"127.0.0.1").digest()
        + b"\x45"
        + bytes(4)
        + bytes(16)
        + len(credential).to_bytes(2)
        + credential
        + public_key
    )


def registration_with(options, public_key, *, attestation=None):
    """A `none` registration of an arbitrary COSE key, or of the attestation object given."""
    credential = secrets.token_bytes(32)
    auth = authenticator_data(credential, cbor2.dumps(public_key))
    if attestation is None:
        attestation = cbor2.dumps({"fmt": "none", "authData": auth, "attStmt": {}})
    elif callable(attestation):
        attestation = attestation(auth)
    client = json.dumps(
        {"type": "webauthn.create", "challenge": options["challenge"], "origin": ORIGIN}
    ).encode()
    return credential, {
        "id": b64(credential),
        "rawId": b64(credential),
        "type": "public-key",
        "response": {"clientDataJSON": b64(client), "attestationObject": b64(attestation)},
    }


def signed_assertion(options, credential, sign):
    auth = hashlib.sha256(b"127.0.0.1").digest() + b"\x05" + (1).to_bytes(4)
    client = json.dumps(
        {"type": "webauthn.get", "challenge": options["challenge"], "origin": ORIGIN}
    ).encode()
    return {
        "id": b64(credential),
        "rawId": b64(credential),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(client),
            "authenticatorData": b64(auth),
            "signature": b64(sign(auth + hashlib.sha256(client).digest())),
        },
    }


def ed25519_key():
    private = ed25519.Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, {1: 1, 3: -8, -1: 6, -2: raw}


def p521_key():
    private = ec.generate_private_key(ec.SECP521R1())
    numbers = private.public_key().public_numbers()
    return private, {
        1: 2,
        3: -36,
        -1: 3,
        -2: numbers.x.to_bytes(66),
        -3: numbers.y.to_bytes(66),
    }


def failures(admin_engine, session):
    with admin_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t "
                "AND kind='account_security.verification_failed' "
                "AND payload->>'method'='passkey'"
            ),
            {"t": session.identity.tenant_id},
        ).scalar_one()


def saved(db, session):
    with db.transaction(session.identity.tenant_id) as conn:
        return len(saved_passkeys(conn, session))


def test_registration_offers_the_same_algorithms_in_the_same_order(db, humans):
    clock, grant, _ = enrolled(db, humans)
    session = load_session(db, grant.token, clock=clock)
    options = passkeys.begin(db, session, ORIGIN, "register", clock=clock)
    assert options["pubKeyCredParams"] == [{"type": "public-key", "alg": alg} for alg in OFFERED]


@pytest.mark.parametrize("key", [ed25519_key, p521_key], ids=["Ed25519", "ES512"])
def test_a_passkey_on_an_offered_algorithm_registers_and_authenticates(db, humans, key):
    """Ed25519 is what an authenticator is now most often asked for first; ES512 is one of
    the algorithms the narrower 3.0 default would have refused at registration."""
    clock, grant, _ = enrolled(db, humans)
    session = load_session(db, grant.token, clock=clock)
    options = passkeys.begin(db, session, ORIGIN, "register", clock=clock)
    private, public_key = key()
    credential, response = registration_with(options, public_key)
    assert passkeys.complete(db, session, ORIGIN, "register", response, clock=clock)

    def sign(data):
        if isinstance(private, ed25519.Ed25519PrivateKey):
            return private.sign(data)
        return private.sign(data, ec.ECDSA(hashes.SHA512()))

    pending_grant = issue_session(db, humans[0], clock=clock)
    pending = load_session(db, pending_grant.token, clock=clock, allow_pending_mfa=True)
    options = passkeys.begin(db, pending, ORIGIN, "authenticate", clock=clock)
    assert passkeys.complete(
        db,
        pending,
        ORIGIN,
        "authenticate",
        signed_assertion(options, credential, sign),
        clock=clock,
    )
    assert not load_session(db, pending_grant.token, clock=clock).mfa_required


def duplicate_keys(auth):
    """An attestation object whose map names `authData` twice: a parser that keeps the last
    value and one that keeps the first would read different credentials from the same bytes."""
    _, other = ed25519_key()
    decoy = authenticator_data(secrets.token_bytes(32), cbor2.dumps(other))
    entries = [("fmt", "none"), ("authData", decoy), ("attStmt", {}), ("authData", auth)]
    return bytes([0xA0 + len(entries)]) + b"".join(
        cbor2.dumps(key) + cbor2.dumps(value) for key, value in entries
    )


def rs1_key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    return {1: 3, 3: -65535, -1: numbers.n.to_bytes(256), -2: numbers.e.to_bytes(3)}


@pytest.mark.parametrize(
    "fault",
    ["duplicate-keys", "numeric-format", "unoffered-algorithm"],
)
def test_a_malformed_or_unoffered_registration_is_refused_and_recorded(
    db, humans, admin_engine, fault
):
    """Refused the way every other bad proof is: `complete` answers False, records
    `verification_failed` and saves nothing, rather than raising past its handler."""
    clock, grant, _ = enrolled(db, humans)
    session = load_session(db, grant.token, clock=clock)
    options = passkeys.begin(db, session, ORIGIN, "register", clock=clock)
    if fault == "unoffered-algorithm":
        _, response = registration_with(options, rs1_key())
    else:
        _, public_key = ed25519_key()
        attestation = (
            duplicate_keys
            if fault == "duplicate-keys"
            else lambda auth: cbor2.dumps({"fmt": 1, "authData": auth, "attStmt": {}})
        )
        _, response = registration_with(options, public_key, attestation=attestation)
    before = failures(admin_engine, session)
    assert passkeys.complete(db, session, ORIGIN, "register", response, clock=clock) is False
    assert failures(admin_engine, session) == before + 1
    assert saved(db, session) == 0
