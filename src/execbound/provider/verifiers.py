# SPDX-License-Identifier: AGPL-3.0-only
"""The verifier the server settles a connector's evidence with, built from its connection.

A connector returns evidence; whether that evidence settles an execution is decided here,
with keys from the connection the operator configured, and never by code the connector
carries (#496). The match is on the exact configuration type, so a connection of
a kind the server does not know has no verifier at all, and nothing it returns can settle.
"""

from execbound.execution.models import EvidenceVerifier
from execbound.provider.connector import ConnectionConfig, ConnectorConfig, JournalVerifier
from execbound.provider.connector_record import ConnectorRecordVerifier
from execbound.provider.graph_connector import GraphConnectionConfig


def verifier_for(config: ConnectorConfig) -> EvidenceVerifier:
    """The verifier for this connection's evidence; ValueError for a connection unknown here."""
    if type(config) is ConnectionConfig:
        return JournalVerifier(
            config.tenant_id, config.account_id, config.evidence_keys, provider=config.provider
        )
    if type(config) is GraphConnectionConfig:
        return ConnectorRecordVerifier(config.account_id, config.provider, config.evidence_keys)
    raise ValueError("No verifier for this connection")
