# SPDX-License-Identifier: Apache-2.0
"""The connection to Microsoft Graph: one exchange, and ExecBound's signed account of it.

A mock connector posts to an origin an operator configured and verifies a signature the
provider co-signed. Nothing here resembles that. Graph shares no secret with ExecBound and
signs no receipt, so this performs the read, the comparison and the single write itself,
then signs what it saw with a key ExecBound holds. The resulting record is authenticated as
ExecBound's own and is never evidence that Microsoft acted; see "A vendor that co-signs
nothing" in ``docs/PROVIDER.md``.

This module decides nothing about authority. It is reached only after policy admitted the
request and the kernel committed the one send attempt, and it returns evidence the kernel
settles on.
"""

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from uuid import UUID

from execbound_protocol.catalog import ProviderName
from execbound_protocol.connector import check_connector_record
from execbound_protocol.connector_record import (
    ConnectorExchange,
    sign_exchange,
)
from execbound_protocol.provider import (
    GRAPH_PROVIDER as _GRAPH_PROVIDER,
)
from execbound_protocol.provider import (
    ProviderCommand,
    ProviderError,
)

from execbound_connectors.graph import GraphCredential, GraphDispatchError, GraphUserWriter

GRAPH_PROVIDER: ProviderName = _GRAPH_PROVIDER
# The one operation this connector performs. The catalog binds `identity.disable` to it;
# a command naming anything else is refused rather than quietly disabled, because the
# writer below can do exactly one thing and a connector must not decide it meant that.
DISABLE = "disable"

# The two refusals whose exchange the record vocabulary can state. Every other reason the
# writer raises — AUTH_LOST, FORBIDDEN, REFUSED, SCHEMA_DRIFT, MALFORMED, UNAVAILABLE,
# INDETERMINATE — has no verified terminal reason to settle under, so it raises and the
# kernel retains the execution as uncertain. That is the safe direction and it is also a
# known limitation: a 403 on the write means no mutation happened, and Graph publishes no
# journal to resolve it with, so such an execution stays uncertain. "A vendor that
# co-signs nothing" in ``docs/PROVIDER.md`` records it.
_RECORDED = MappingProxyType(
    {"VERSION_MISMATCH": "VERSION_MISMATCH", "TARGET_ABSENT": "TARGET_NOT_FOUND"}
)


@dataclass(frozen=True)
class GraphConnectionConfig:
    """One tenant's Graph connection, shaped for the credential Graph actually takes.

    Deliberately not a `ConnectionConfig`. That dataclass describes an HTTP endpoint an
    operator supplied, with an origin it validates and two bearer tokens; this one has a
    directory, a client id and a client secret, and its origin is pinned in source so no
    operator can move it. Admitting both shapes to one dataclass would make four fields
    conditional and invite a client id to be configured where a bearer token belongs.
    """

    tenant_id: UUID
    account_id: UUID
    credential: GraphCredential
    evidence_keys: Mapping[str, bytes] = field(repr=False)
    signing_key_id: str
    provider: ProviderName = GRAPH_PROVIDER

    def __post_init__(self) -> None:
        if (
            self.provider != GRAPH_PROVIDER
            or not self.evidence_keys
            or any(len(key) < 32 for key in self.evidence_keys.values())
            # The ring verifies; one member of it signs. A signing id outside the ring
            # would produce records the ring cannot verify, by this connector's own check
            # or the server's, so it is refused here rather than on the first dispatch.
            or self.signing_key_id not in self.evidence_keys
        ):
            raise ValueError("Invalid Graph connection")
        self.credential.__post_init__()
        object.__setattr__(self, "evidence_keys", MappingProxyType(dict(self.evidence_keys)))

    @property
    def secrets(self) -> frozenset[str]:
        return frozenset({self.credential.secret})

    def with_keys(self, evidence_keys: Mapping[str, bytes]) -> "GraphConnectionConfig":
        return dataclasses.replace(self, evidence_keys=evidence_keys)


class GraphConnector:
    """Performs one Graph exchange for a committed dispatch and signs what it saw."""

    def __init__(
        self, config: GraphConnectionConfig, writer: GraphUserWriter | None = None
    ) -> None:
        config.__post_init__()
        self.config = config
        self._writer = writer or GraphUserWriter(config.credential)

    def rotate_keys(self, evidence_keys: Mapping[str, bytes]) -> None:
        """Replace the ring. The signing member must survive the rotation.

        A ring that drops the key this connector signs with would leave it signing records
        nothing can verify, so `__post_init__` refuses the replacement and the rotation
        fails as a whole rather than half-applying.
        """
        self.config = dataclasses.replace(self.config, evidence_keys=evidence_keys)

    def close(self) -> None:
        self._writer.close()

    def _scoped(self, provider: ProviderCommand) -> ProviderCommand:
        if (
            provider.tenant_id != self.config.tenant_id
            or provider.account_id != self.config.account_id
            or provider.provider != self.config.provider
            or provider.provider_operation != DISABLE
        ):
            raise ProviderError("INVALID_SCOPE")
        return provider

    def _exchange(
        self,
        provider: ProviderCommand,
        outcome: str,
        *,
        observed: str | None,
        window_ms: int,
        status: int,
    ) -> ConnectorExchange:
        return ConnectorExchange(
            operation_id=provider.operation_id,
            account_id=provider.account_id,
            intent_hash=provider.intent_hash,
            plan_hash=provider.plan_hash,
            provider=provider.provider,
            provider_operation=provider.provider_operation,
            frozen=provider.expected_version,
            observed=observed,
            window_ms=window_ms,
            status=status,
            outcome=outcome,  # type: ignore[arg-type]
        )

    def dispatch(self, command: ProviderCommand) -> bytes:
        provider = self._scoped(command)
        try:
            seen = self._writer.disable(provider.resource_provider_id, provider.expected_version)
        except GraphDispatchError as error:
            recorded = _RECORDED.get(error.reason)
            if recorded is None or error.status is None:
                # Nothing the verified vocabulary can state. The kernel reads this as a
                # lost dispatch and retains the execution as uncertain.
                raise ProviderError() from None
            exchange = self._exchange(
                provider,
                recorded,
                observed=error.observed,
                # A read that never reached a comparison measured no gap; zero is the
                # honest span between a read and a write that was never due.
                window_ms=error.window_ms or 0,
                status=error.status,
            )
        else:
            exchange = self._exchange(
                provider,
                "EXECUTED",
                observed=seen.observed,
                window_ms=seen.window_ms,
                status=seen.status,
            )
        try:
            evidence = sign_exchange(
                exchange,
                self.config.signing_key_id,
                self.config.evidence_keys[self.config.signing_key_id],
            )
        except (ProviderError, ValueError):
            raise ProviderError() from None
        # The record this connector just made must verify under the ring it just signed
        # with, for the same reason the mock verifies before returning: a binding mistake
        # is caught where it was made, not after it has settled an execution.
        check_connector_record(
            provider,
            evidence,
            self.config.evidence_keys,
            account_id=self.config.account_id,
            provider=self.config.provider,
        )
        return evidence

    def lookup(self, command: ProviderCommand) -> bytes | None:
        """Graph publishes nothing to look up, and a re-read would not be a lookup.

        Reading the user again cannot distinguish this connector's own write from someone
        else disabling the account, which is exactly why `GraphUserWriter` refuses to
        retry. Returning that reading as a journal would let an uncertain operation settle
        on a guess, so an uncertain Graph operation stays uncertain.
        """
        self._scoped(command)
        return None

    def cancel(self, command: ProviderCommand) -> bytes:
        """Graph offers no cancellation, and a record may not claim one.

        `ConnectorExchange.consistent` refuses a CANCELLED_NOT_EXECUTED record outright, so
        there is nothing this could return that would settle anything.
        """
        raise ProviderError("CANCEL_UNSUPPORTED")
