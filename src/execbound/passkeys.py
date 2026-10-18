# SPDX-License-Identifier: AGPL-3.0-only
"""WebAuthn proofs pinned to this deployment, user, session and single-use challenge."""

import json
import secrets
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import text
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from execbound.db import Database
from execbound.mfa import MfaError, _change, _event, _factor, _recent, _transaction, saved_passkeys
from execbound.resolution.models import Clock, SystemClock
from execbound.surfaces.sessions import Session

# The algorithms a passkey may use, in the order a browser is asked for them: exactly
# py_webauthn 2.7.0's default. 3.0 narrowed its own default to EdDSA, ES256 and RS256 and put
# EdDSA first; passing this list to both registration calls kept that upgrade from changing
# what is offered or what is accepted. Narrowing it is a decision of its own, and
# tests/test_passkeys.py pins the list so that one is a reviewed change.
ALGORITHMS = (
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.EDDSA,
    COSEAlgorithmIdentifier.ECDSA_SHA_512,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_384,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_512,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_384,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_512,
)


def begin(
    db: Database, session: Session, origin: str, kind: str, *, clock: Clock | None = None
) -> dict[str, Any]:
    if kind not in {"register", "authenticate"}:
        raise MfaError("INVALID_OPERATION")
    clock = clock or SystemClock()
    challenge = secrets.token_bytes(32)
    rp = urlsplit(origin).hostname
    assert rp is not None
    with _transaction(db, session, clock) as conn:
        factor = _factor(conn, session)
        if factor is None or factor["enabled_at"] is None:
            raise MfaError("NOT_ENROLLED")
        if kind == "register":
            _recent(conn, session, clock.now())
        credentials = [
            PublicKeyCredentialDescriptor(id=bytes.fromhex(row["credential_id"]))
            for row in saved_passkeys(conn, session)
        ]
        if (kind == "register" and len(credentials) >= 5) or (
            kind == "authenticate" and not credentials
        ):
            raise MfaError("FACTOR_LIMIT")
        _change(
            conn,
            session,
            clock.now(),
            "passkey_begin",
            {"kind": kind, "challenge": challenge.hex()},
        )
    if kind == "register":
        options = generate_registration_options(
            rp_id=rp,
            rp_name="ExecBound",
            user_id=(session.account_id or session.identity.principal_id).bytes,
            user_name=f"ExecBound {str(session.account_id or session.identity.principal_id)[:8]}",
            challenge=challenge,
            exclude_credentials=credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            timeout=120000,
            supported_pub_key_algs=list(ALGORITHMS),
        )
    else:
        authentication = generate_authentication_options(
            rp_id=rp,
            challenge=challenge,
            allow_credentials=credentials,
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=120000,
        )
        return dict(json.loads(options_to_json(authentication)))
    result: dict[str, Any] = json.loads(options_to_json(options))
    return result


def complete(
    db: Database,
    session: Session,
    origin: str,
    kind: str,
    credential: dict[str, Any],
    *,
    clock: Clock | None = None,
) -> bool:
    clock = clock or SystemClock()
    rp = urlsplit(origin).hostname
    assert rp is not None
    with _transaction(db, session, clock) as conn:
        row = (
            conn.execute(
                text(
                    "SELECT * FROM execbound.passkey_challenges WHERE tenant_id=:t AND "
                    "session_id=:s"
                ),
                {"t": session.identity.tenant_id, "s": session.session_id},
            )
            .mappings()
            .one_or_none()
        )
        if (
            row is None
            or row["kind"] != kind
            or row["used_at"] is not None
            or row["expires_at"] <= clock.now()
        ):
            return False
        _change(conn, session, clock.now(), "passkey_consume", {"kind": kind})
        factor = _factor(conn, session)
        if (
            factor is None
            or factor["enabled_at"] is None
            or (factor["locked_until"] is not None and factor["locked_until"] > clock.now())
        ):
            return False
        try:
            if kind == "register":
                _recent(conn, session, clock.now())
                registration = verify_registration_response(
                    credential=credential,
                    expected_challenge=bytes.fromhex(row["challenge"]),
                    expected_rp_id=rp,
                    expected_origin=origin,
                    require_user_verification=True,
                    supported_pub_key_algs=list(ALGORITHMS),
                )
                _change(
                    conn,
                    session,
                    clock.now(),
                    "passkey_register",
                    {
                        "credential_id": registration.credential_id.hex(),
                        "public_key": registration.credential_public_key.hex(),
                        "sign_count": registration.sign_count,
                    },
                )
                _event(conn, session, "passkey_added")
            elif kind == "authenticate":
                identifier = base64url_to_bytes(credential["id"]).hex()
                saved = next(
                    (
                        item
                        for item in saved_passkeys(conn, session)
                        if item["credential_id"] == identifier
                    ),
                    None,
                )
                if saved is None:
                    raise ValueError
                handle = credential.get("response", {}).get("userHandle")
                if handle is not None and base64url_to_bytes(handle) != saved["principal_id"].bytes:
                    raise ValueError
                verified = verify_authentication_response(
                    credential=credential,
                    expected_challenge=bytes.fromhex(row["challenge"]),
                    expected_rp_id=rp,
                    expected_origin=origin,
                    credential_public_key=bytes.fromhex(saved["public_key"]),
                    credential_current_sign_count=saved["sign_count"],
                    require_user_verification=True,
                )
                _change(
                    conn,
                    session,
                    clock.now(),
                    "passkey_verify",
                    {
                        "credential_id": identifier,
                        "sign_count": verified.new_sign_count,
                        "method": "passkey",
                    },
                )
                _event(conn, session, "verified", {"method": "passkey"})
            else:
                return False
        except (WebAuthnException, ValueError, KeyError, TypeError):
            _change(conn, session, clock.now(), "fail", {})
            _event(conn, session, "verification_failed", {"method": "passkey"})
            return False
    return True


def remove(db: Database, session: Session, identifier: str, *, clock: Clock | None = None) -> None:
    clock = clock or SystemClock()
    with _transaction(db, session, clock) as conn:
        _recent(conn, session, clock.now())
        _change(conn, session, clock.now(), "passkey_remove", {"credential_id": identifier})
        _event(conn, session, "passkey_removed")
