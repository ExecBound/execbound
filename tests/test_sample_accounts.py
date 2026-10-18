# SPDX-License-Identifier: AGPL-3.0-only
"""Sample account derivation (#420, SM3): known answers, binding and format.

The known answers were computed once from the definition in `provider/sample_accounts.py`
(HMAC-SHA256 of the key over `execbound/sample-account/v1`, a NUL, the label, a NUL, then the
tenant's and the account's sixteen raw bytes) with the key `00 01 02 ... 1f`. They pin the
encoding: changing any part of it cuts every sample connection that exists, so it has to fail
here first.
"""

import hashlib
import re
from uuid import UUID

import pytest

from execbound.provider.connector import ConnectionConfig
from execbound.provider.sample_accounts import (
    SAMPLE_KEY_ID,
    SampleProvider,
    derive,
    parse_sample_key,
    sample_account,
    sample_connection,
    sample_material,
)

KEY = bytes(range(32))
TENANT = UUID("11111111-1111-4111-8111-111111111111")
ACCOUNT = UUID("22222222-2222-4222-8222-222222222222")
OTHER = UUID("33333333-3333-4333-8333-333333333333")
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


def test_sm3_the_derivation_has_fixed_known_answers():
    material = sample_material(KEY, TENANT, ACCOUNT)
    assert material.dispatch_token == "SYTX8bPtfhr1jMfpdW3ZTJkGsNDq23kZXMH9T23vDAE"
    assert material.control_token == "CX_ZN_bKg_1qzOGx7KMHI14610DJAGs52QdAu-Dar0M"
    assert material.journal_key.hex() == (
        "63517c4f5928c191c83fdf791846321fda6d3e53c6a09a06cff29ffa897e37c2"
    )
    assert derive(KEY, "dispatch", TENANT, ACCOUNT).hex() == (
        "4984d7f1b3ed7e1af58cc7e9756dd94c9906b0d0eadb79195cc1fd4f6def0c01"
    )
    assert derive(KEY, "control", TENANT, ACCOUNT).hex() == (
        "097fd937f6ca83fd6acce1b1eca307235e3ad740c9006b39d90740bbe0daaf43"
    )


def test_sm3_a_token_for_one_tenant_or_account_fails_for_another():
    mine = sample_material(KEY, TENANT, ACCOUNT)
    assert sample_material(KEY, TENANT, OTHER).dispatch_token == (
        "rbRuQ8XQwJeGJadzEPLjcopMdouRoGF6oigN78WfDSQ"
    )
    # The same two ids the other way round name a different account of a different tenant.
    assert sample_material(KEY, ACCOUNT, TENANT).dispatch_token == (
        "reIhN9TsTSF4ImBixJsVbAlLvXVsbRdx3hvCw74bJ9E"
    )
    for other in (
        sample_material(KEY, TENANT, OTHER),
        sample_material(KEY, OTHER, ACCOUNT),
        sample_material(KEY, ACCOUNT, TENANT),
        sample_material(bytes(range(1, 33)), TENANT, ACCOUNT),
    ):
        assert other.dispatch_token != mine.dispatch_token
        assert other.control_token != mine.control_token
        assert other.journal_key != mine.journal_key


def test_sm3_the_three_labels_never_produce_the_same_value():
    values = [derive(KEY, label, TENANT, ACCOUNT) for label in ("dispatch", "control", "journal")]
    assert len(set(values)) == 3
    with pytest.raises(ValueError):
        derive(KEY, "cancel", TENANT, ACCOUNT)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        derive(KEY[:31], "dispatch", TENANT, ACCOUNT)


def test_sm3_the_values_take_the_forms_a_generated_account_has():
    material = sample_material(KEY, TENANT, ACCOUNT)
    assert TOKEN.fullmatch(material.dispatch_token)
    assert TOKEN.fullmatch(material.control_token)
    assert len(material.journal_key) == 32
    assert material.dispatch_token not in repr(material)
    account = sample_account(KEY, TENANT, ACCOUNT)
    assert account.key_id == SAMPLE_KEY_ID == "sample-v1"
    assert account.provider == "mock_crowdstrike"
    assert account.dispatch_token_hash == (
        hashlib.sha256(material.dispatch_token.encode()).hexdigest()
    )
    assert account.control_token_hash == (
        hashlib.sha256(material.control_token.encode()).hexdigest()
    )
    assert account.signing_key == material.journal_key
    provider = SampleProvider("mock_crowdstrike", "http://127.0.0.1:8001", KEY)
    assert KEY.hex() not in repr(provider)
    connection = sample_connection(provider, TENANT, ACCOUNT)
    assert isinstance(connection, ConnectionConfig)
    assert (connection.dispatch_token, connection.control_token) == (
        material.dispatch_token,
        material.control_token,
    )
    assert dict(connection.evidence_keys) == {SAMPLE_KEY_ID: material.journal_key}
    assert connection.origin == "http://127.0.0.1:8001"


@pytest.mark.parametrize("value", [KEY.hex(), bytes(range(128)).hex()])
def test_sm3_a_sample_key_is_32_to_128_bytes_of_lower_case_hex(value):
    assert parse_sample_key(value) == bytes.fromhex(value)


@pytest.mark.parametrize(
    "value",
    ["", "00" * 31, "00" * 129, KEY.hex().upper(), "zz" * 32, "0" * 65, None, 42, KEY],
)
def test_sm3_anything_else_is_refused_as_a_sample_key(value):
    with pytest.raises(ValueError):
        parse_sample_key(value)


@pytest.mark.parametrize(
    ("provider", "origin", "key"),
    [
        ("mock_entra", "http://127.0.0.1:8001", KEY),
        ("mock_crowdstrike", "http://10.0.0.5:8001", KEY),
        ("mock_crowdstrike", "https://mock.example.net/v1", KEY),
        ("mock_crowdstrike", "http://127.0.0.1:8001", KEY[:31]),
    ],
)
def test_sm3_a_sample_provider_is_refused_wherever_a_connector_would_be(provider, origin, key):
    with pytest.raises(ValueError):
        SampleProvider(provider, origin, key)
    assert SampleProvider("mock_crowdstrike", "https://mock.example.net", KEY).origin == (
        "https://mock.example.net"
    )
