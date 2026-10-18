# SPDX-License-Identifier: AGPL-3.0-only
"""Factor encryption keys enter only the private runtime file and are scrubbed at boot."""

import json

import pytest

from execbound.boot import CONSUMED, BootError, _runtime_config


def test_separate_mfa_keyring_is_merged_without_logging_or_overwriting():
    ring = {"active_key_id": "factor-v1", "keys": {"factor-v1": "a1" * 32}}
    environment = {
        "EXECBOUND_RUNTIME_CONFIG_JSON": "{}",
        "EXECBOUND_MFA_KEYS_JSON": json.dumps(ring),
    }
    assert json.loads(_runtime_config(environment))["mfa"] == ring
    assert "EXECBOUND_MFA_KEYS_JSON" in CONSUMED
    environment["EXECBOUND_RUNTIME_CONFIG_JSON"] = json.dumps({"mfa": ring})
    with pytest.raises(BootError) as error:
        _runtime_config(environment)
    assert ring["keys"]["factor-v1"] not in str(error.value)


@pytest.mark.parametrize(
    "value", ['{"keys":false}', '{"active_key_id":"x","keys":{"x":"secret"}}', "[]"]
)
def test_invalid_mfa_keyring_is_refused_without_echo(value):
    with pytest.raises(BootError) as error:
        _runtime_config({"EXECBOUND_RUNTIME_CONFIG_JSON": "{}", "EXECBOUND_MFA_KEYS_JSON": value})
    assert value not in str(error.value)
