# SPDX-License-Identifier: Apache-2.0
"""The provider protocol: the command a connector receives, the journal a provider signs
for it, and the strict parsing every provider message goes through.

The server freezes a `ProviderCommand` from its own dispatch command and hands it to a
connector; a provider answers with a `SignedJournal` over a `JournalRecord` binding that
exact command. Nothing here reads the server, so a provider or connector can be built
against it alone (#496).
"""

import hashlib
import hmac
import json
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator

from execbound_protocol.arguments import Arguments
from execbound_protocol.canonical import canonical_json
from execbound_protocol.catalog import (
    PRODUCTION_ACTIONS,
    ActionName,
    CatalogError,
    ProviderName,
    ProviderOperation,
)
from execbound_protocol.strict import Digest, StrictModel, Version, _reject_number, _unique_object

MAX_PROVIDER_BYTES = 32768
KeyId = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_.-]{1,64}$")]


# The one real provider bound so far. Named here rather than in the connector module so
# the offline replay can read it without importing an HTTP client it must never use.
GRAPH_PROVIDER = "graph"


class ProviderError(ValueError):
    def __init__(self, code: str = "PROVIDER_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Provider unavailable")


class ProtocolModel(StrictModel):
    model_config = ConfigDict(revalidate_instances="always")
    version: Literal[1] = 1

    @field_validator("version", mode="before")
    @classmethod
    def integer_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Invalid protocol version")
        return value


class ProviderCommand(ProtocolModel):
    tenant_id: UUID
    account_id: UUID
    canonical_target_id: UUID
    provider: ProviderName = "mock_crowdstrike"
    action: ActionName = "endpoint.isolate"
    provider_operation: ProviderOperation = "contain"
    arguments: Arguments = Field(default_factory=Arguments)
    resource_provider_id: str = Field(min_length=1, max_length=128)
    expected_version: Version
    operation_id: UUID
    execution_id: UUID
    intent_hash: Digest
    plan_hash: Digest

    @model_validator(mode="after")
    def exact_operation(self) -> Self:
        try:
            binding = PRODUCTION_ACTIONS.binding(self.provider, self.action)
            if self.provider_operation != binding.provider_operation:
                raise CatalogError("Invalid provider operation")
            PRODUCTION_ACTIONS.normalize_arguments(self.action, self.arguments.root)
        except CatalogError:
            raise ValueError("Invalid provider operation") from None
        return self

    @property
    def command_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.model_dump(mode="json")).encode()).hexdigest()


class IdentityState(StrictModel):
    model_config = ConfigDict(revalidate_instances="always")
    account_enabled: bool
    session_generation: int = Field(ge=0, le=2**63 - 1)


class IdentityTransition(StrictModel):
    model_config = ConfigDict(revalidate_instances="always")
    before: IdentityState
    after: IdentityState


class EndpointState(StrictModel):
    model_config = ConfigDict(revalidate_instances="always")
    contained: bool


class EndpointTransition(StrictModel):
    model_config = ConfigDict(revalidate_instances="always")
    before: EndpointState
    after: EndpointState


class CredentialState(StrictModel):
    model_config = ConfigDict(revalidate_instances="always")
    password_generation: int = Field(ge=0, le=2**63 - 1)
    must_change_password: bool


class CredentialTransition(StrictModel):
    model_config = ConfigDict(revalidate_instances="always")
    before: CredentialState
    after: CredentialState


class JournalRecord(ProtocolModel):
    command: ProviderCommand
    command_hash: Digest
    outcome: Literal["EXECUTED", "VERSION_MISMATCH", "CANCELLED_NOT_EXECUTED", "TARGET_NOT_FOUND"]
    occurred_at: AwareDatetime
    resulting_version: Version | None
    mutation_count: int = Field(ge=0, le=1)
    # Omission is part of the original endpoint wire contract and signing envelope.
    identity_transition: IdentityTransition | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    endpoint_transition: EndpointTransition | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    credential_transition: CredentialTransition | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.command_hash != self.command.command_hash:
            raise ValueError("Invalid command binding")
        executed = self.outcome == "EXECUTED"
        if executed:
            if (
                self.mutation_count != 1
                or self.resulting_version is None
                or self.resulting_version == self.command.expected_version
            ):
                raise ValueError("Invalid executed evidence")
        elif self.mutation_count != 0:
            raise ValueError("Invalid nonexecution evidence")
        elif self.outcome == "VERSION_MISMATCH":
            if (
                self.resulting_version is None
                or self.resulting_version == self.command.expected_version
            ):
                raise ValueError("Invalid version mismatch evidence")
        elif self.resulting_version is not None:
            raise ValueError("Unexpected nonexecution version")
        action = self.command.action
        expected = {
            "identity": executed and self.command.provider == "mock_entra",
            "credential": executed and action == "identity.reset_password",
            "endpoint": executed and action == "endpoint.lift_isolation",
        }
        present = {
            "identity": self.identity_transition is not None,
            "credential": self.credential_transition is not None,
            "endpoint": self.endpoint_transition is not None,
        }
        if present != expected:
            raise ValueError("Unexpected transition evidence")
        if self.identity_transition is not None:
            before, after = self.identity_transition.before, self.identity_transition.after
            if action == "identity.revoke_sessions":
                valid = (
                    after.account_enabled == before.account_enabled
                    and after.session_generation == before.session_generation + 1
                )
            elif action == "identity.reset_password":
                valid = (
                    after.account_enabled == before.account_enabled
                    and after.session_generation == before.session_generation
                )
            else:
                valid = (
                    after.account_enabled == (action == "identity.enable")
                    and after.session_generation == before.session_generation
                )
            if not valid:
                raise ValueError("Invalid identity transition")
        if self.credential_transition is not None:
            earlier = self.credential_transition.before
            later = self.credential_transition.after
            if later.password_generation != earlier.password_generation + 1 or (
                later.must_change_password
                != self.command.arguments.root["require_change_at_next_sign_in"]
            ):
                raise ValueError("Invalid credential transition")
        if self.endpoint_transition is not None and self.endpoint_transition.after.contained:
            raise ValueError("Invalid endpoint transition")
        return self


class SignedJournal(ProtocolModel):
    key_id: KeyId
    record: JournalRecord
    signature: Digest


def parse_provider[T: StrictModel](raw: bytes, model: type[T]) -> T:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_PROVIDER_BYTES:
            raise ValueError()
        json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
        return model.model_validate_json(raw)
    except (ValueError, RecursionError):
        raise ProviderError("INVALID_MESSAGE") from None


def signature(record: JournalRecord, key_id: str, key: bytes) -> str:
    message = canonical_json(
        {"version": 1, "key_id": key_id, "record": record.model_dump(mode="json")}
    )
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def sign_journal(record: JournalRecord, key_id: str, key: bytes) -> SignedJournal:
    """A journal record signed under one key. Which key, and whether the record lies in
    that key's scope, are the caller's to decide: a provider signs only for its own account.
    """
    record = parse_provider(record.model_dump_json().encode(), JournalRecord)
    return SignedJournal(key_id=key_id, record=record, signature=signature(record, key_id, key))
