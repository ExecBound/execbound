# SPDX-License-Identifier: AGPL-3.0-only
"""The password primitives, with no database: the hash, the decoy and the code's shape.

What matters here is that a record verifies under its own parameters rather than the
module's, that an unknown address costs what a known one costs, and that a malformed code is
refused before anything is looked up.
"""

import time
from uuid import uuid4

import pytest

from execbound.passwords import (
    ALGORITHM,
    DECOY,
    DKLEN,
    MAX_PASSWORD,
    MIN_PASSWORD,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    PasswordError,
    PasswordRecord,
    check_password,
    code_digest,
    derive,
    hash_password,
    normalize_email,
    reset_code,
    reset_selectors,
    verify_password,
)

PASSWORD = "correct horse battery staple"


def test_a_hash_verifies_its_own_password_and_refuses_every_other():
    record = hash_password(PASSWORD)
    assert record.algorithm == ALGORITHM
    assert (record.n, record.r, record.p, record.dklen) == (SCRYPT_N, SCRYPT_R, SCRYPT_P, DKLEN)
    assert verify_password(record, PASSWORD)
    for wrong in (PASSWORD + " ", PASSWORD.upper(), "", None, 7, PASSWORD[:-1]):
        assert not verify_password(record, wrong)


def test_the_password_itself_is_nowhere_in_the_record():
    record = hash_password(PASSWORD)
    stored = " ".join(str(value) for value in vars(record).values())
    assert PASSWORD not in stored
    assert "horse" not in stored


def test_two_hashes_of_one_password_differ_because_the_salt_does():
    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    assert first.salt != second.salt
    assert first.hash != second.hash
    assert verify_password(first, PASSWORD) and verify_password(second, PASSWORD)


def test_a_record_verifies_under_its_own_parameters_not_the_modules():
    """A row written before the parameters rose must keep working, which is the whole
    reason they are columns instead of constants."""
    salt = "ab" * 16
    weaker = PasswordRecord(ALGORITHM, 2**14, 8, 1, 32, salt, "0" * 64)
    record = PasswordRecord(ALGORITHM, 2**14, 8, 1, 32, salt, derive(PASSWORD, weaker))
    assert record.n != SCRYPT_N
    assert verify_password(record, PASSWORD)
    assert not verify_password(record, "something else entirely")


def test_an_unknown_algorithm_is_refused_rather_than_guessed():
    record = PasswordRecord("argon2id", SCRYPT_N, 8, 1, 32, "ab" * 16, "0" * 64)
    with pytest.raises(PasswordError):
        derive(PASSWORD, record)
    assert not verify_password(record, PASSWORD)


def test_the_decoy_costs_what_a_real_record_costs():
    """An unknown address is verified against this, so the two must not be told apart by a
    stopwatch. The bound is deliberately loose: this asserts the same order of work, which
    is what the decoy is for, and not a timing guarantee the language cannot give."""
    record = hash_password(PASSWORD)
    real = _elapsed(lambda: verify_password(record, "a wrong password entirely"))
    decoy = _elapsed(lambda: verify_password(DECOY, "a wrong password entirely"))
    assert not verify_password(DECOY, PASSWORD)
    assert 0.4 < decoy / real < 2.5, (decoy, real)


def _elapsed(call):
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        call()
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [
        ("Dana@Example.COM", "dana@example.com"),
        ("  dana@example.com  ", "dana@example.com"),
        ("ﬁrst@example.com", "first@example.com"),
    ],
)
def test_an_address_has_one_spelling(supplied, expected):
    assert normalize_email(supplied) == expected


@pytest.mark.parametrize(
    "supplied",
    [
        "",
        "dana",
        "dana@example",
        "dana@@example.com",
        "dana example@com",
        "dana@exam ple.com",
        "a" * 250 + "@example.com",
        None,
        7,
    ],
)
def test_anything_that_is_not_an_address_is_not_one(supplied):
    assert normalize_email(supplied) is None


def test_a_password_is_bounded_and_may_not_be_the_address():
    assert check_password("a" * MIN_PASSWORD) == "a" * MIN_PASSWORD
    for wrong in ("a" * (MIN_PASSWORD - 1), "a" * (MAX_PASSWORD + 1), None, 7):
        with pytest.raises(PasswordError) as refused:
            check_password(wrong)
        assert refused.value.code == "INVALID_PASSWORD"
    with pytest.raises(PasswordError):
        check_password("dana@example.com", "dana@example.com")


def test_a_code_names_its_tenant_and_its_row_and_nothing_else():
    tenant, reset = uuid4(), uuid4()
    code, digest = reset_code(tenant, reset)
    assert code.startswith(f"ebp1.{tenant}.{reset}.")
    assert digest == code_digest(code)
    assert reset_selectors(code) == (tenant, reset)


@pytest.mark.parametrize(
    "supplied",
    [
        "",
        "ebp1.not-a-uuid.also-not.AAAA",
        "ebi1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.3f2504e0-4f89-11d3-9a0c-0305e82c3301."
        + "A" * 43,
        "ebp1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.3f2504e0-4f89-11d3-9a0c-0305e82c3301."
        + "A" * 42,
        "ebp1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        "x" * 200,
        None,
    ],
)
def test_a_malformed_code_is_refused_before_anything_is_looked_up(supplied):
    with pytest.raises(PasswordError) as refused:
        reset_selectors(supplied)
    assert refused.value.code == "INVALID_RESET"
