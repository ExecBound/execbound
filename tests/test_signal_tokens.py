# SPDX-License-Identifier: AGPL-3.0-only
"""The producer credential: `sg1.`, held as a digest, scrubbed."""

from uuid import UUID

import pytest

from execbound.secrets import find_secrets
from execbound.signals.tokens import SignalTokenError, digest, new_token, selectors

TENANT, SOURCE = UUID(int=1), UUID(int=2)
# A tenant id with a hex letter in it, so upper-casing it changes the text.
LETTERED = UUID(int=0xA)


def test_a_token_names_its_tenant_and_source_and_is_stored_as_a_digest():
    token, stored = new_token(TENANT, SOURCE)
    assert token.startswith(f"sg1.{TENANT}.{SOURCE}.")
    # sg1 (3) + 3 dots + two 36-character UUIDs + 43 characters of secret.
    assert len(token) == 121
    assert stored == digest(token) and len(stored) == 64
    assert selectors(token) == (TENANT, SOURCE)


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "mo1." + f"{TENANT}.{SOURCE}." + "A" * 43,
        "eb1." + f"{TENANT}.{SOURCE}." + "A" * 43,
        f"sg1.{TENANT}.{SOURCE}." + "A" * 42,
        f"sg1.{TENANT}.{SOURCE}." + "A" * 43 + ".extra",
        f"sg1.{str(LETTERED).upper()}.{SOURCE}." + "A" * 43,
        f"sg1.{TENANT}.{str(LETTERED).upper()}." + "A" * 43,
        # Decodes to the same 32 bytes as "A" * 43, but is not their canonical encoding.
        f"sg1.{TENANT}.{SOURCE}." + "A" * 42 + "B",
        f"sg1.{TENANT}.{SOURCE}." + "+" * 43,
        "sg1." + "x" * 200,
    ],
)
def test_anything_else_is_refused_without_quoting_it(token):
    with pytest.raises(SignalTokenError) as caught:
        selectors(token)
    assert str(caught.value) == "Invalid producer token"


def test_the_scrubber_recognises_a_producer_token():
    token, _ = new_token(TENANT, SOURCE)
    assert find_secrets({"note": f"sent {token} to the gateway"})
