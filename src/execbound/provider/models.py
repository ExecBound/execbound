# SPDX-License-Identifier: AGPL-3.0-only
"""Narrow authenticated provider protocol, independent of caller request fields.

The protocol itself, the provider command, its journal and their parsing and signing, is
`execbound_protocol.provider` (#496), named here where it always was. What stays
is the server's: freezing a `ProviderCommand` from its own dispatch command, and the mock
providers' accounts.
"""

from execbound_connectors.accounts import ProviderAccount as ProviderAccount
from execbound_connectors.accounts import sign_record as sign_record
from execbound_protocol.provider import GRAPH_PROVIDER as GRAPH_PROVIDER
from execbound_protocol.provider import MAX_PROVIDER_BYTES as MAX_PROVIDER_BYTES
from execbound_protocol.provider import CredentialState as CredentialState
from execbound_protocol.provider import CredentialTransition as CredentialTransition
from execbound_protocol.provider import EndpointState as EndpointState
from execbound_protocol.provider import EndpointTransition as EndpointTransition
from execbound_protocol.provider import IdentityState as IdentityState
from execbound_protocol.provider import IdentityTransition as IdentityTransition
from execbound_protocol.provider import JournalRecord as JournalRecord
from execbound_protocol.provider import KeyId as KeyId
from execbound_protocol.provider import ProtocolModel as ProtocolModel
from execbound_protocol.provider import ProviderCommand as ProviderCommand
from execbound_protocol.provider import ProviderError as ProviderError
from execbound_protocol.provider import SignedJournal as SignedJournal
from execbound_protocol.provider import parse_provider as parse_provider
from execbound_protocol.provider import sign_journal as sign_journal
from execbound_protocol.provider import signature as signature

from execbound.execution.models import DispatchCommand


def provider_command(command: DispatchCommand) -> ProviderCommand:
    command = parse_provider(command.model_dump_json().encode(), DispatchCommand)
    frozen = command.frozen
    return ProviderCommand(
        tenant_id=frozen.intent.tenant_id,
        account_id=frozen.intent.account_id,
        canonical_target_id=command.canonical_target_id,
        provider=frozen.intent.provider,
        action=frozen.intent.action,
        provider_operation=frozen.intent.provider_operation,
        arguments=frozen.intent.arguments,
        resource_provider_id=frozen.resource_provider_id,
        expected_version=frozen.resource_version,
        operation_id=command.operation_id,
        execution_id=command.execution_id,
        intent_hash=command.intent_hash,
        plan_hash=command.plan_hash,
    )
