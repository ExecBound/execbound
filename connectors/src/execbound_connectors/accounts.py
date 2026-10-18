# SPDX-License-Identifier: Apache-2.0
"""A mock provider's accounts: the tokens it accepts and the key it signs journals with.

Trusted mock configuration, never the server's: the server holds the matching tokens and
verification ring in its own connection configuration (#496).
"""

from dataclasses import dataclass, field
from uuid import UUID

from execbound_protocol.catalog import ProviderName
from execbound_protocol.provider import (
    JournalRecord,
    ProviderError,
    SignedJournal,
    parse_provider,
    signature,
)


@dataclass(frozen=True)
class ProviderAccount:
    """Trusted mock configuration; hashes for requests, separate key for journal proof."""

    tenant_id: UUID
    account_id: UUID
    dispatch_token_hash: str = field(repr=False)
    control_token_hash: str = field(repr=False)
    signing_key: bytes = field(repr=False)
    key_id: str = "journal-v1"
    provider: ProviderName = "mock_crowdstrike"

    def __post_init__(self) -> None:
        import re

        if (
            self.provider not in {"mock_crowdstrike", "mock_entra"}
            or not re.fullmatch(r"[0-9a-f]{64}", self.dispatch_token_hash)
            or not re.fullmatch(r"[0-9a-f]{64}", self.control_token_hash)
            or self.dispatch_token_hash == self.control_token_hash
            or len(self.signing_key) < 32
            or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", self.key_id)
        ):
            raise ValueError("Invalid provider account")


def sign_record(record: JournalRecord, account: ProviderAccount) -> SignedJournal:
    record = parse_provider(record.model_dump_json().encode(), JournalRecord)
    account.__post_init__()
    if (
        record.command.account_id != account.account_id
        or record.command.tenant_id != account.tenant_id
        or record.command.provider != account.provider
    ):
        raise ProviderError("INVALID_SCOPE")
    return SignedJournal(
        key_id=account.key_id,
        record=record,
        signature=signature(record, account.key_id, account.signing_key),
    )
