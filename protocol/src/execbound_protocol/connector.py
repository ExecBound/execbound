# SPDX-License-Identifier: Apache-2.0
"""The connector interface, and the checks a connector runs on its own evidence.

A connector is the one piece of code that talks to a vendor. The server hands it a frozen
`ProviderCommand`, never its own dispatch record, and settles on the bytes it returns only
after verifying them itself, with keys from the connection the operator configured. So the
interface here carries no verifier: a connector cannot vouch for its own evidence. What it
can do, and should, is check the evidence before returning it, so a binding mistake is caught
where it was made; `check_journal` and `check_connector_record` are those checks, and the
server's verifiers run the same ones (#496).
"""

import hmac
from collections.abc import Mapping
from typing import Protocol
from uuid import UUID

from execbound_protocol.catalog import ProviderName
from execbound_protocol.connector_record import (
    CONNECTOR_RECORD_V1,
    ConnectorRecord,
    record_signature,
)
from execbound_protocol.provider import (
    MAX_PROVIDER_BYTES,
    ProviderCommand,
    ProviderError,
    SignedJournal,
    parse_provider,
    signature,
)


class ConnectorConfig(Protocol):
    """What the runtime reads off a connection, whatever shape the vendor's credential has.

    A mock is reached at a configured origin with two bearer tokens; Graph is reached at an
    origin pinned in source with a client credential. Neither set of fields belongs in the
    other's dataclass, so what is stated here is only the part the runtime itself needs:
    who the connection is for, which provider family it belongs to, the ring its evidence
    verifies against, and the secrets that authenticate it.
    """

    # Read-only members throughout. Both implementations are frozen dataclasses, whose
    # attributes mypy treats as unsettable, so a Protocol declaring mutable ones would
    # match neither of them.
    @property
    def tenant_id(self) -> UUID: ...

    @property
    def account_id(self) -> UUID: ...

    @property
    def provider(self) -> ProviderName: ...

    @property
    def evidence_keys(self) -> Mapping[str, bytes]: ...

    @property
    def secrets(self) -> frozenset[str]:
        """Every value that authenticates this connection to its vendor.

        ``runtime._independent`` holds connectors of different provider families apart on
        this, so a deployment cannot configure one family's credential as another's. Asking
        each config to name its own secrets is what lets that rule cover a credential
        shaped nothing like a pair of bearer tokens.
        """

    def with_keys(self, evidence_keys: Mapping[str, bytes]) -> "ConnectorConfig":
        """This connection with a different evidence ring, for validating a rotation.

        ``Runtime.rotate`` builds every candidate config and checks them together before
        anything is applied, so a rotation that would leave two families sharing a key
        fails as a whole. Each config makes its own copy because only it knows its shape.
        """


class Connector(Protocol):
    """The gateway's whole view of a provider connection.

    Stated as a Protocol rather than a base class because the two implementations share no
    behaviour at all: one posts to a configured origin and checks a signature the provider
    co-signed, the other performs a vendor exchange and signs its own account of it. A
    shared superclass would exist only to satisfy a type. There is no verifier here: the
    server builds the one it settles with from `config`, so the evidence a connector returns
    is never checked by code the connector chose.
    """

    # Read-only: a Protocol's mutable attribute is invariant, which would refuse every
    # implementation that holds its own config type.
    @property
    def config(self) -> ConnectorConfig: ...

    def dispatch(self, command: ProviderCommand) -> bytes: ...

    def lookup(self, command: ProviderCommand) -> bytes | None: ...

    def cancel(self, command: ProviderCommand) -> bytes: ...

    def rotate_keys(self, evidence_keys: Mapping[str, bytes]) -> None: ...

    def close(self) -> None: ...


def check_journal(
    command: ProviderCommand,
    evidence: bytes,
    keys: Mapping[str, bytes],
    *,
    tenant_id: UUID,
    account_id: UUID,
    provider: ProviderName,
) -> SignedJournal:
    """A provider's signed journal for exactly this command, under one of these keys.

    Refuses with `INVALID_EVIDENCE` a journal for another command, another tenant, account
    or provider, under a key outside the ring, or whose signature does not hold.
    """
    command = parse_provider(command.model_dump_json().encode(), ProviderCommand)
    signed = parse_provider(evidence, SignedJournal)
    key = keys.get(signed.key_id)
    if (
        key is None
        or command.tenant_id != tenant_id
        or command.account_id != account_id
        or command.provider != provider
        or signed.record.command != command
        or not hmac.compare_digest(signed.signature, signature(signed.record, signed.key_id, key))
    ):
        raise ProviderError("INVALID_EVIDENCE")
    return signed


def check_connector_record(
    command: ProviderCommand,
    evidence: bytes,
    keys: Mapping[str, bytes],
    *,
    account_id: UUID,
    provider: str,
) -> ConnectorRecord:
    """A connector's own signed record of one exchange for exactly this command.

    Refuses with `INVALID_EVIDENCE` an oversized record, one under another scheme, another
    account or provider, a key outside the ring, a signature that does not hold, or one
    bound to anything but this command's operation, account, hashes, operation and frozen
    version. A record from another execution verifies as a signature and is still refused
    here, which is the whole point of checking the binding.
    """
    if len(evidence) > MAX_PROVIDER_BYTES:
        raise ProviderError("INVALID_EVIDENCE")
    signed = parse_provider(evidence, ConnectorRecord)
    key = keys.get(signed.key_id)
    exchange = signed.record
    if (
        key is None
        or exchange.scheme != CONNECTOR_RECORD_V1
        or exchange.account_id != account_id
        or exchange.provider != provider
        or exchange.operation_id != command.operation_id
        or exchange.account_id != command.account_id
        or exchange.intent_hash != command.intent_hash
        or exchange.plan_hash != command.plan_hash
        or exchange.provider_operation != command.provider_operation
        or exchange.frozen != command.expected_version
        or not hmac.compare_digest(signed.signature, record_signature(exchange, signed.key_id, key))
    ):
        raise ProviderError("INVALID_EVIDENCE")
    return signed
