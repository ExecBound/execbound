# SPDX-License-Identifier: AGPL-3.0-only
"""Known-answer and input-boundary tests for authenticator codes."""

import base64

import pytest

from execbound.mfa import recovery_digest, totp, verify_totp


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ],
)
def test_rfc_6238_sha1_vectors_with_six_digits(timestamp, expected):
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp(secret, timestamp // 30) == expected
    assert verify_totp(secret, expected, timestamp, -1) == timestamp // 30


def test_only_one_adjacent_step_is_accepted_and_used_steps_are_refused():
    secret = base64.b32encode(b"12345678901234567890").decode()
    code = totp(secret, 100)
    assert verify_totp(secret, code, 101 * 30, 99) == 100
    assert verify_totp(secret, code, 102 * 30, 99) is None
    assert verify_totp(secret, code, 100 * 30, 100) is None


@pytest.mark.parametrize("value", ["", "12345", "1234567", "１２３４５６", " 123456", None])
def test_code_is_exactly_six_ascii_digits(value):
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert verify_totp(secret, value, 3000, -1) is None


def test_recovery_digest_is_domain_separated_and_does_not_accept_arbitrary_input():
    from uuid import UUID

    principal = UUID(int=1)
    assert recovery_digest(principal, "abcd-1234-abcd-1234-abcd-1234") != recovery_digest(
        UUID(int=2), "abcd-1234-abcd-1234-abcd-1234"
    )
    assert recovery_digest(principal, "not a recovery code") is None


def test_match_factor_answers_without_touching_a_database():
    """`match_factor` reads only the row it is given: a current code, a held recovery code, a
    code for a step already used, and anything else, with no connection anywhere in reach."""
    from datetime import UTC, datetime
    from uuid import UUID

    from execbound.envelope import KeyRing, seal
    from execbound.mfa import FactorCheck, match_factor, new_recovery_codes

    ring = KeyRing("test", {"test": b"m" * 32})
    account = UUID(int=7)
    secret = base64.b32encode(b"12345678901234567890").decode()
    sealed, key_id = seal(ring, secret, account, account, "authenticator_seed")
    shown, retained = new_recovery_codes(account)
    now = datetime.fromtimestamp(1000 * 30 + 5, UTC)
    row = {
        "tenant_id": account,
        "principal_id": account,
        "sealed": sealed,
        "key_id": key_id,
        "last_step": 999,
        "recovery_hashes": retained,
    }

    current = match_factor(row, ring, totp(secret, 1000), now)
    assert (current.result, current.method, current.step, current.digest) == (
        FactorCheck.VERIFIED,
        "totp",
        1000,
        None,
    )
    held = match_factor(row, ring, shown[0], now)
    assert (held.result, held.method, held.step) == (FactorCheck.VERIFIED, "recovery", None)
    assert held.digest == recovery_digest(account, shown[0])
    assert held.digest not in repr(held)
    # The step just used is still on the person's screen: reused, never a failure.
    assert match_factor(row, ring, totp(secret, 999), now).result is FactorCheck.REUSED
    wrong = next(
        f"{n:06d}"
        for n in range(1_000_000)
        if f"{n:06d}" not in {totp(secret, s) for s in range(997, 1002)}
    )
    assert match_factor(row, ring, wrong, now).result is FactorCheck.REFUSED
    assert match_factor(row, ring, "abcd-abcd-abcd-abcd-abcd-abcd", now).result is (
        FactorCheck.REFUSED
    )
    assert match_factor(row, ring, None, now).result is FactorCheck.REFUSED
    assert match_factor(row, ring, totp(secret, 1003), now).result is FactorCheck.REFUSED
