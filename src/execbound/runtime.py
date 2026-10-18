# SPDX-License-Identifier: AGPL-3.0-only
"""One private composition boundary for every external execution adapter."""

import secrets
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import timedelta
from threading import BoundedSemaphore, Lock
from types import MappingProxyType
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.assistant.config import AssistantConfig
from execbound.contracts import PRODUCTION_CATALOG, Catalog
from execbound.db import Database, UnsafeDatabaseRole
from execbound.execution import _rejection, admit, get_execution, report_outcome, store
from execbound.execution.models import (
    NO_PRECONDITIONS,
    CheckpointGrant,
    DenialCategory,
    DispatchCommand,
    EvidenceVerifier,
    ExecutionError,
    ExecutionView,
    PreconditionConfig,
    TerminalEvidence,
    VerifiedTier,
    VerifierFactory,
)
from execbound.execution.offered import ActionListing, listing
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.notifications import Destination
from execbound.plugins import NO_PLUGINS, LoadedPlugins
from execbound.provider.checkpoint_evidence import CheckpointProvider, CheckpointVerifier
from execbound.provider.connector import Connector, ConnectorConfig, MockConnector
from execbound.provider.executor import ExecutorKey, verifier_for_grant
from execbound.provider.gateway import dispatch_owned
from execbound.provider.models import provider_command
from execbound.provider.published_keys import (
    hmac_key,
    published_executor_key,
    published_journal_key,
)
from execbound.provider.sample_accounts import SAMPLE_PROVIDER, SampleProvider, sample_connection
from execbound.provider.verifiers import verifier_for
from execbound.requests import InvalidRequest, parse_request
from execbound.resolution.models import Clock, SystemClock
from execbound.surfaces.limits import RequestLimiter, RequestLimits
from execbound.surfaces.tokens import Continuation, InvalidContinuation, TokenKeys, sign, verify
from execbound.transports import MailConfig


def _hmac_forms(keys: Iterable[bytes]) -> set[bytes]:
    """Keys as HMAC-SHA256 uses them (`published_keys.hmac_key`).

    Every ring compared below is an HMAC-SHA256 key ring: a connector's evidence keys, a Gate
    account's journal keys, the continuation keys and a sample key, which derives by HMAC. Two
    keys whose forms are equal verify the same signatures however they are written, a key and
    the same key with a zero byte appended among them, so independence is asked of the forms.
    """
    return {hmac_key(key) for key in keys}


def _independent(configs: Sequence[ConnectorConfig], keys: TokenKeys | None) -> None:
    """Different provider families may share no vendor credential and no evidence key.

    Each config names its own `secrets`, because the rule has to cover a family whose
    credential is not a pair of bearer tokens at all: the Graph connection authenticates
    with a client secret. Asking the config rather than reading two named fields is what
    keeps this from silently skipping the family it was extended to protect. Keys are
    compared in the form HMAC uses them (`_hmac_forms`).
    """
    for index, config in enumerate(configs):
        authentication = config.secrets
        for other in configs[:index]:
            if config.provider != other.provider and (
                authentication & other.secrets
                or _hmac_forms(config.evidence_keys.values())
                & _hmac_forms(other.evidence_keys.values())
            ):
                raise ValueError("Provider families require independent credentials and keys")
    if keys is not None and _hmac_forms(keys.keys.values()) & _hmac_forms(
        key for config in configs for key in config.evidence_keys.values()
    ):
        raise ValueError("Continuation keys must be independent from provider keys")


def _journal_independent(
    providers: Iterable[CheckpointProvider],
    configs: Sequence[ConnectorConfig],
    keys: TokenKeys | None,
) -> None:
    """A checkpoint journal key is held by no connector ring and no continuation ring.

    Asked at construction and again by `Runtime.rotate`, since a reload replaces both of
    those rings and the journal keys stay as the file declared them at start. Keys are
    compared in the form HMAC uses them (`_hmac_forms`).
    """
    journal_keys = _hmac_forms(key for p in providers for key in p.evidence_keys.values())
    shared = _hmac_forms(key for c in configs for key in c.evidence_keys.values())
    if keys is not None:
        shared |= _hmac_forms(keys.keys.values())
    if journal_keys & shared:
        raise ValueError("Checkpoint journal keys must be independent")


def _unpublished(
    configs: Iterable[ConnectorConfig],
    providers: Iterable[CheckpointProvider],
    samples: Iterable[SampleProvider],
) -> None:
    """No connector ring, Gate account's journal key or sample key is a published test key.

    The executor protocol publishes the journal keys its vectors are signed under, and replay
    the one its fixtures are re-signed under (`provider.published_keys`), and a journal anyone
    can sign settles nothing it claims to.
    Asked of what a runtime holds rather than of the file it was read from, so a deployment
    built any other way is held to it too, at construction and again by `Runtime.rotate`. A
    Graph connection's ring is asked too: it signs ExecBound's own record of the exchange,
    which a published key would let anyone write. So is a sample key, from which anyone
    holding it derives every sample account's tokens and journal key. Each is compared in
    the form HMAC uses it, so a published key with zero bytes appended is refused as well.
    """
    held = [key for config in configs for key in config.evidence_keys.values()]
    held += [key for provider in providers for key in provider.evidence_keys.values()]
    held += [sample.key for sample in samples]
    if any(published_journal_key(key) for key in held):
        raise ValueError("Published test keys authenticate nothing")


def _samples_independent(
    samples: Iterable[SampleProvider],
    configs: Sequence[ConnectorConfig],
    keys: TokenKeys | None,
    providers: Iterable[CheckpointProvider],
) -> None:
    """A sample key is no connector's evidence key, no continuation key and no journal key.

    It derives every workspace's sample credentials and journal key (#420), so sharing it with
    any other ring would let whoever holds that ring act on every sample connection too. Asked
    at construction and again by `Runtime.rotate`, since a reload replaces the other rings.
    Keys are compared in the form HMAC uses them (`_hmac_forms`), as the sample key derives
    by HMAC-SHA256.
    """
    used = _hmac_forms(key for config in configs for key in config.evidence_keys.values())
    used |= _hmac_forms(key for provider in providers for key in provider.evidence_keys.values())
    if keys is not None:
        used |= _hmac_forms(keys.keys.values())
    if _hmac_forms(sample.key for sample in samples) & used:
        raise ValueError("Sample keys must be independent")


def _ring(conn: Connection, tenant: UUID) -> list[ExecutorKey]:
    """The tenant's registered keys as the two questions below both weigh them.

    One loader, because admission asks whether a grant it is about to issue could be
    attested and settlement asks whether this record attests one, and those have to be the
    same question about the same rows. A row the model refuses fails the whole ring rather
    than being dropped from it: a key nothing could have signed with is not evidence that
    the rest of the ring is what an administrator registered, and answering the permissive
    way would settle grants against a ring this process could not read.
    """
    return [ExecutorKey(**key) for key in store.executor_keys(conn, tenant)]


def checkpoint_verifier_for(
    providers: Mapping[tuple[UUID, UUID], CheckpointProvider],
) -> VerifierFactory:
    """The verifier factory for a deployment's checkpoints, over its journal keys.

    Each verifier it builds checks the executor's record against the tenant's key ring
    and a provider journal against the journal key configured for the grant's own tenant
    and Gate account, both taken from the execution row. A grant whose account has no
    journal key configured settles from its executor's record alone.
    """
    held = MappingProxyType(dict(providers))

    def factory(conn: Connection, row: dict[str, Any]) -> EvidenceVerifier:
        executor = verifier_for_grant(row, _ring(conn, row["tenant_id"]))
        entry = held.get((row["tenant_id"], executor.account_id))
        return CheckpointVerifier(executor, None if entry is None else entry.verifier())

    return factory


def executor_verifier(conn: Connection, row: dict[str, Any]) -> EvidenceVerifier:
    """The verifier for one granted checkpoint, built at this composition boundary.

    The kernel names no concrete verifier, exactly as reconciliation takes one rather than
    building it, and it supplies the connection and the execution row, so the tenant's key
    ring is read on the connection that read the row it is weighed against and the grant
    instant comes from that row rather than from anything the executor sent.

    The outcome route calls this in both of its transactions and settles on what the
    fenced one answers, because the ring is not immutable the way the grant instant is. A
    retirement or a registration landing between the two reads cannot change which keys
    speak for this grant — `dispatch_attempted_at` is stamped once and both of a key's own
    instants are weighed against it — but a compromise is retroactive by construction, and
    a settlement resting on a ring read before the fence was taken would not see one
    committing in that window.

    This is the factory of a deployment that configured no journal key: it settles from
    executor records only, and a journal presented to it is refused. A deployment that
    configured some settles through `Runtime.verifier_for`, which is the same factory over
    its `checkpoint_providers`.
    """
    return checkpoint_verifier_for({})(conn, row)


def attestable_ring(conn: Connection, tenant: UUID) -> bool:
    """Whether a grant issued on this connection now could be attested afterwards.

    What admission asks before it reserves anything, over the same rows and the same
    loader `executor_verifier` weighs a report against, so the two cannot come to disagree
    about what a usable ring is. A ring that will not load answers no, because no record
    could be attested against one; a key with no revocation of any kind stamped answers
    yes, because that is the key the verifier will weigh against the grant about to be
    issued. The one thing the verifier asks that this does not is whether the key predates
    the grant, which for a grant issued now is a key stamped with a registration time in
    the future — an instant the administration commands take from the clock.

    Asked of this boundary rather than answered in SQL because the rule a row must satisfy
    is not one the column can express: a small-order public key is thirty-two bytes of
    lowercase hex like any other and is a key nobody holds the private half of.

    A published test key loads, and attests nothing (`ExecutorVerifier._current`), so it is
    not the key this asks for either: a ring whose only live keys are published answers no,
    as one that will not load does, rather than issuing grants only the executor's bare word
    could settle.
    """
    try:
        ring = _ring(conn, tenant)
    except ValueError:
        return False
    return any(
        key.revoked_at is None and not published_executor_key(key.public_key) for key in ring
    )


def denial_notice(request_ref: str | None, denial: DenialCategory = "withheld") -> str:
    """The one sentence a `DENIED` answer carries: its category and the request's reference.

    Built from the reference and the category alone, so it names nothing finer: never the
    recorded reason, the rule that matched, the fact that put the target out of bounds, the
    limit, its window or counts, the other execution holding the target, or a reviewer's
    words. The protected agent may be mistaken, prompt-injected or compromised, and its
    denials must not hand it a map of the policy; the reason is kept for a person, who finds
    the record by searching the console for the same reference (`docs/THREAT_MODEL.md`
    T1.16). Every view the store answers with carries its reference; one built without it
    still gets a sentence with nothing of the cause in it.

    `busy` and `limit` tell an honest agent when waiting is worth a new request: another
    request holds the target, or a shared limit covering this request is spent
    (`store.denial_category`). A limit can be recorded beside a rule that denies the request
    too, so its sentence promises only that a new request after the limit resets is decided
    afresh, never that it will be decided differently. Every other denial is `withheld`, and
    its sentence promises only what holds for every cause: re-sending this request returns
    this same answer. None of the three calls a refusal permanent, and whether to make a new
    request is the person's call.
    """
    where = f"by searching the console for {request_ref}" if request_ref else "in the console"
    if denial == "busy":
        return (
            "Denied because another request holds this target. Re-sending this request "
            "returns this same answer; a new request after that one settles may be decided "
            f"differently. A person can find it {where}."
        )
    if denial == "limit":
        return (
            "Denied because a shared limit is spent. Re-sending this request returns this same "
            "answer; a new request after the limit resets is decided afresh. A person can find "
            f"it {where}."
        )
    return (
        f"Denied. The reason is recorded for a person, who can find it {where}. "
        "Re-sending this request returns this same answer."
    )


class _HeldVerifier:
    """A configured account's verifier, as the runtime holds it at the moment it is used."""

    def __init__(self, runtime: "Runtime", account: tuple[UUID, UUID]) -> None:
        self._runtime, self._account = runtime, account
        # Fixed for the account: a rotation changes a connection's ring, never its kind.
        self.attests_external_execution = self._current().attests_external_execution

    def _current(self) -> EvidenceVerifier:
        return self._runtime._verifiers[self._account]

    def verify(self, command: DispatchCommand, evidence: bytes) -> TerminalEvidence | None:
        return self._current().verify(command, evidence)

    def verified_tier(self, proof: TerminalEvidence) -> VerifiedTier:
        return self._current().verified_tier(proof)


class Runtime:
    def __init__(
        self,
        db: Database,
        connectors: Sequence[Connector],
        *,
        clock: Clock | None = None,
        concurrency: int | None = None,
        keys: TokenKeys | None = None,
        approval_url: str | None = None,
        catalog: Catalog | None = None,
        limits: RequestLimits | None = None,
        notifications: Sequence[Destination] = (),
        preconditions: PreconditionConfig | None = None,
        mail: MailConfig | None = None,
        assistant: AssistantConfig | None = None,
        checkpoint_providers: Sequence[CheckpointProvider] = (),
        plugins: LoadedPlugins = NO_PLUGINS,
        sample_providers: Sequence[SampleProvider] = (),
    ) -> None:
        if concurrency is None:
            concurrency = min(16, db.capacity)
        if type(concurrency) is not int or not 1 <= concurrency <= 64:
            raise ValueError("Invalid runtime concurrency")
        if concurrency > db.capacity:
            # A cap above the pool turns load into five-second pool timeouts and 503s.
            raise ValueError("Runtime concurrency exceeds the database pool capacity")
        self.concurrency = concurrency
        # Each connector's configuration is read once and held here. The runtime validates
        # this copy, rotates this copy and builds the verifiers it settles with from it, so
        # nothing a connector reports about itself afterwards decides what its evidence
        # proves (#496).
        held = [(connector, connector.config) for connector in connectors]
        configured = {(config.tenant_id, config.account_id): c for c, config in held}
        if len(configured) != len(connectors):
            raise ValueError("Duplicate connector account")
        configs = [config for _, config in held]
        _independent(configs, keys)
        self._configs: dict[tuple[UUID, UUID], ConnectorConfig] = {
            (config.tenant_id, config.account_id): config for config in configs
        }
        self._verifiers = {
            account: verifier_for(config) for account, config in self._configs.items()
        }
        self.db, self.clock = db, clock or SystemClock()
        self.keys, self.approval_url = keys, approval_url
        self._rotation = Lock()
        self.catalog = catalog or PRODUCTION_CATALOG
        # Deployment configuration, held here beside the connectors and the catalog and
        # threaded to admission, never read from a request. Every declaration must name a
        # provider binding this deployment's catalog actually binds: a class for a binding
        # nothing can resolve describes an operation no grant will ever name, so it is a
        # configuration mistake rather than a harmless extra.
        if preconditions is not None and type(preconditions) is not PreconditionConfig:
            raise ValueError("Invalid precondition configuration")
        self.preconditions = preconditions or NO_PRECONDITIONS
        bound = self.catalog.actions.provider_operations
        if any(binding not in bound for binding in self.preconditions.classes):
            raise ValueError("Precondition classes must name a bound provider operation")
        self.limiter = RequestLimiter(limits, self.clock)
        if any(type(d) is not Destination for d in notifications):
            raise ValueError("Invalid notification destination")
        # The relay email destinations send through; a destination with none is refused
        # here rather than failed row by row at the first drain.
        if mail is not None and type(mail) is not MailConfig:
            raise ValueError("Invalid mail configuration")
        if mail is None and any(d.kind == "email" for d in notifications):
            raise ValueError("Invalid mail configuration")
        self.notifications = tuple(notifications)
        self.mail = mail
        # The assistant's operator configuration, or None: absent means the feature does
        # not exist, and nothing below this line reads it (#330).
        self.assistant = assistant
        # The provider transport the assistant's turns use. None in every process: the
        # console builds an `HttpTransport` from the configuration above. A test sets a
        # scripted one here, which is the only way a turn runs without calling a model.
        self.assistant_transport: Any | None = None
        self.connectors = MappingProxyType(configured)
        # The tenants a configured connector belongs to. The endpoint mock refuses a sample
        # token for any tenant it holds a configured account for, so no sample connection is
        # derived, and no samples are offered, in one of these (#420).
        self._configured_tenants = frozenset(tenant for tenant, _ in configured)
        # The journal keys a Gate account's provider signs with: verification only, never a
        # destination. The type is checked before any field is read, so a stray value is
        # refused as a configuration mistake rather than failing on an attribute.
        if any(type(p) is not CheckpointProvider for p in checkpoint_providers):
            raise ValueError("Invalid checkpoint provider")
        providers = {(p.tenant_id, p.account_id): p for p in checkpoint_providers}
        if len(providers) != len(checkpoint_providers) or set(providers) & set(configured):
            # A journal key names a Gate account, and a Gate account has no connector.
            raise ValueError("Invalid checkpoint provider")
        _journal_independent(providers.values(), configs, keys)
        self.checkpoint_providers = MappingProxyType(providers)
        # Sample targets (#420): the mocks that accept derived sample accounts, keyed by
        # provider. Each entry's origin is the only place a sample connection may reach.
        if any(type(p) is not SampleProvider for p in sample_providers):
            raise ValueError("Invalid sample provider")
        samples: dict[str, SampleProvider] = {p.provider: p for p in sample_providers}
        if len(samples) != len(sample_providers):
            raise ValueError("Invalid sample provider")
        _samples_independent(samples.values(), configs, keys, providers.values())
        _unpublished(configs, providers.values(), samples.values())
        self.sample_providers: Mapping[str, SampleProvider] = MappingProxyType(samples)
        self.verifier_for = checkpoint_verifier_for(providers)
        self._capacity = BoundedSemaphore(concurrency)
        # First-party plugins the private configuration named (#238). Their pages, console
        # areas and console pages mount after core's; nothing on the execution path reads this.
        if type(plugins) is not LoadedPlugins:
            raise ValueError("Invalid plugins")
        self.plugins = plugins

    def rotate(
        self, keys: TokenKeys, evidence: Mapping[tuple[UUID, UUID], Mapping[str, bytes]]
    ) -> None:
        """Swap the continuation ring and every connector's evidence ring together.

        Validation repeats the construction rules; nothing changes unless all of it passes,
        and keys that remain in a ring keep verifying what they signed. The checkpoint
        journal keys do not rotate here, since a reload that changes them is refused as a
        configuration change, but neither rotated ring may take one of them up.
        """
        if type(keys) is not TokenKeys or set(evidence) != set(self.connectors):
            raise ValueError("Rotation must cover every configured account")
        rotated = {
            account: config.with_keys(evidence[account])
            for account, config in self._configs.items()
        }
        _independent(list(rotated.values()), keys)
        _unpublished(rotated.values(), (), ())
        _journal_independent(self.checkpoint_providers.values(), list(rotated.values()), keys)
        _samples_independent(
            self.sample_providers.values(),
            list(rotated.values()),
            keys,
            self.checkpoint_providers.values(),
        )
        verifiers = {account: verifier_for(config) for account, config in rotated.items()}
        with self._rotation:
            for account, connector in self.connectors.items():
                connector.rotate_keys(rotated[account].evidence_keys)
            self._configs, self._verifiers = rotated, verifiers
            self.keys = keys

    def evidence_verifier(self, tenant_id: UUID, account_id: UUID) -> EvidenceVerifier | None:
        """The verifier this runtime settles a configured account's evidence with, or None.

        Built from the configuration the runtime validated and rotates, never from what the
        connector reports. The verifier returned reads the account's current ring each time
        it is used, so a rotation that lands while a dispatch is in flight applies to that
        dispatch's evidence too. None for an account with no configured connector: a sample
        account's connection is derived by this runtime itself and carries its own copy.
        """
        account = (tenant_id, account_id)
        if account not in self._verifiers:
            return None
        return _HeldVerifier(self, account)

    def samples_available(self, tenant_id: UUID) -> bool:
        """Whether this deployment can serve sample targets for one tenant.

        It needs a sample key for the endpoint mock, and a tenant this deployment holds no
        configured connector for: the mock refuses a sample token for any tenant it holds a
        configured account for, so a sample connection there could never be served (#420).
        What the console offers and what install accepts both ask this.
        """
        return (
            SAMPLE_PROVIDER in self.sample_providers and tenant_id not in self._configured_tenants
        )

    def available_accounts(self, tenant_id: UUID) -> frozenset[tuple[UUID, str]]:
        """The accounts this deployment can dispatch to for one tenant.

        Every configured connector's, and, for a provider this deployment holds a sample key
        for, every active account the install function marked `sample`. That second half is
        the one kernel change sample targets make (#420): such an account counts as connected,
        except in a tenant this deployment holds a configured connector for. The mock refuses a
        sample token in a tenant it holds a configured account for, so a request dispatched
        there would be answered 401 and left INDETERMINATE; admission refuses it instead,
        before anything is sent.
        """
        configured = {
            (account, connector.config.provider)
            for (tenant, account), connector in self.connectors.items()
            if tenant == tenant_id
        }
        if not self.sample_providers or tenant_id in self._configured_tenants:
            return frozenset(configured)
        try:
            with self.db.transaction(tenant_id) as conn:
                rows = conn.execute(
                    text(
                        "SELECT account_id, provider FROM execbound.connector_accounts "
                        "WHERE tenant_id = :t AND active AND sample"
                    ),
                    {"t": tenant_id},
                ).all()
        except (SQLAlchemyError, UnsafeDatabaseRole):
            raise ExecutionError() from None
        return frozenset(
            configured
            | {
                (row.account_id, str(row.provider))
                for row in rows
                if row.provider in self.sample_providers
            }
        )

    @contextmanager
    def connection(self, tenant_id: UUID, account_id: UUID) -> Iterator[Connector | None]:
        """The connection that serves one account: configured, derived, or none at all.

        A configured connector is the deployment's and outlives this call. A sample account's
        is built here from the provider's sample key and its configured origin, only for an
        account whose row is active and marked `sample` in a tenant holding no configured
        connector, and closed when the call ends. An account not marked `sample` never gets a
        derived connection, whatever it is asked as.
        """
        configured = self.connectors.get((tenant_id, account_id))
        if configured is not None:
            yield configured
            return
        derived = self._sample_connector(tenant_id, account_id)
        try:
            yield derived
        finally:
            if derived is not None:
                derived.close()

    def _sample_connector(self, tenant_id: UUID, account_id: UUID) -> MockConnector | None:
        if not self.sample_providers or tenant_id in self._configured_tenants:
            return None
        try:
            with self.db.transaction(tenant_id) as conn:
                provider = conn.execute(
                    text(
                        "SELECT provider FROM execbound.connector_accounts "
                        "WHERE tenant_id = :t AND account_id = :a AND active AND sample"
                    ),
                    {"t": tenant_id, "a": account_id},
                ).scalar_one_or_none()
        except (SQLAlchemyError, UnsafeDatabaseRole):
            raise ExecutionError() from None
        entry = None if provider is None else self.sample_providers.get(str(provider))
        if entry is None:
            return None
        return MockConnector(sample_connection(entry, tenant_id, account_id))

    def reject(
        self,
        identity: Identity,
        code: str = "INVALID_REQUEST",
        *,
        actor_credential: bool = False,
        route: str | None = None,
        method: str | None = None,
    ) -> None:
        """Audit one surface refusal; `route` and `method`, when given, name what was refused
        (a personal access token's `TOKEN_NOT_ALLOWED` names the route template it asked for)."""
        try:
            _rejection(
                self.db,
                identity,
                "surface",
                code,
                self.clock,
                actor_credential=actor_credential,
                route=route,
                method=method,
            )
        except Exception:
            # Rejection audit is best effort when its own dependency is unsafe.
            # It must never release raw diagnostics through a protocol adapter.
            return

    def execute(self, identity: Identity, raw: bytes) -> ExecutionView:
        if not self._capacity.acquire(blocking=False):
            raise ExecutionError("BUSY")
        try:
            view = self._execute(identity, raw)
        except ExecutionError as exc:
            log_event(
                "execute.completed",
                level="WARNING",
                tenant_id=identity.tenant_id,
                principal_id=identity.principal_id,
                code=exc.code,
            )
            raise
        finally:
            self._capacity.release()
        log_event(
            "execute.completed",
            tenant_id=identity.tenant_id,
            principal_id=identity.principal_id,
            execution_id=view.execution_id,
            state=view.state,
        )
        return view

    def _execute(self, identity: Identity, raw: bytes) -> ExecutionView:
        try:
            try:
                request = parse_request(raw)
            except InvalidRequest:
                self.reject(identity, "INVALID_REQUEST")
                raise ExecutionError("INVALID_REQUEST") from None
            admission = admit(
                self.db,
                identity,
                request,
                self.clock,
                available_accounts=self.available_accounts(identity.tenant_id),
                catalog=self.catalog,
                notifications=[d for d in self.notifications if d.tenant_id == identity.tenant_id],
                preconditions=self.preconditions,
                attestable=attestable_ring,
            )
            if admission.view.checkpoint is not None:
                # An externally executed operation: the grant is the whole answer and
                # ExecBound sends nothing, so this branch never indexes the connector
                # table, which by construction holds no entry for a checkpoint account.
                # A ticket beside a grant would dispatch an operation the caller has just
                # been told to perform itself, charging the target twice, so it is refused.
                # The refusal is audited because the caller is told nothing, but
                # execution.rejected names no execution and is written best effort. What an
                # administrator finds the charged row by is execution.checkpoint_granted,
                # which admission committed with the execution, the operation, the plan hash
                # and both deadlines before this contradiction was visible here.
                if admission.ticket is not None:
                    self.reject(identity, "EXECUTION_UNAVAILABLE")
                    raise ExecutionError("EXECUTION_UNAVAILABLE")
                return admission.view
            if admission.ticket is None:
                return admission.view
            # Ticket stays in this trusted process. Select from the committed
            # frozen account, never from a caller field or a fresh mapping read.
            with self.db.transaction(identity.tenant_id) as conn:
                row = store.read(conn, identity.tenant_id, admission.view.execution_id)
                account = store.frozen(row).intent.account_id
            # A configured connector, or the sample connection derived for an active account
            # marked `sample`; admission has already refused an account that has neither.
            with self.connection(identity.tenant_id, account) as connector:
                if connector is None:
                    raise ExecutionError("CONNECTOR_UNAVAILABLE")
                return dispatch_owned(
                    self.db,
                    admission.ticket,
                    connector,
                    self.clock,
                    self.preconditions,
                    verifier=self.evidence_verifier(identity.tenant_id, account),
                )
        finally:
            pass

    def report(self, identity: Identity, execution_id: UUID, raw: bytes) -> ExecutionView:
        """An external executor's report of what it did with the grant it was issued.

        It shares the capacity bound admission takes, so reports and admissions together
        occupy no more of the deployment's writers than that one bound allows: an executor
        cannot take more of a deployment by reporting than by asking.
        """
        if not self._capacity.acquire(blocking=False):
            raise ExecutionError("BUSY")
        try:
            view = report_outcome(
                self.db,
                identity,
                execution_id,
                raw,
                verifier_for=self.verifier_for,
                clock=self.clock,
            )
        except ExecutionError as exc:
            log_event(
                "outcome.recorded",
                level="WARNING",
                tenant_id=identity.tenant_id,
                principal_id=identity.principal_id,
                execution_id=execution_id,
                code=exc.code,
            )
            raise
        finally:
            self._capacity.release()
        log_event(
            "outcome.recorded",
            tenant_id=identity.tenant_id,
            principal_id=identity.principal_id,
            execution_id=view.execution_id,
            state=view.state,
        )
        return view

    def status(
        self, identity: Identity, execution_id: UUID, continuation: str | None = None
    ) -> ExecutionView:
        try:
            claim = None
            if continuation is not None:
                if self.keys is None:
                    raise InvalidContinuation
                claim = verify(
                    continuation,
                    self.keys,
                    tenant_id=identity.tenant_id,
                    principal_id=identity.principal_id,
                    credential_id=identity.credential_id,
                    audience="execution.status",
                    now=self.clock.now(),
                )
                if claim.execution_id != execution_id:
                    raise InvalidContinuation
            view = get_execution(self.db, identity, execution_id, self.clock)
            if claim and (
                claim.plan_hash != view.plan_hash or claim.approval_id != view.approval_id
            ):
                raise InvalidContinuation
            log_event(
                "status.completed",
                tenant_id=identity.tenant_id,
                principal_id=identity.principal_id,
                execution_id=view.execution_id,
                state=view.state,
            )
            return view
        except InvalidContinuation:
            self.reject(identity, "INVALID_CONTINUATION")
            raise ExecutionError("INVALID_CONTINUATION") from None
        except ExecutionError as exc:
            self.reject(identity, exc.code)
            raise

    def list_actions(self, identity: Identity) -> ActionListing:
        """The operations the agent's own space offers it (#545); never a target or a rule.

        A refusal is audited as the surface's, as a status read's is.
        """
        try:
            listed = listing(self.db, identity, self.clock, catalog=self.catalog)
        except ExecutionError as exc:
            self.reject(identity, exc.code)
            raise
        log_event(
            "actions.listed",
            tenant_id=identity.tenant_id,
            principal_id=identity.principal_id,
            count=len(listed.actions),
        )
        return listed

    def _described(
        self, identity: Identity, view: ExecutionView, grant: CheckpointGrant
    ) -> dict[str, object]:
        """The grant as its caller receives it, with the act window's signed token.

        ``grant`` is what admission committed and retained, in its own namespace so no
        presenter-chosen key enters the model's; ``act`` is minted here for this one answer,
        at an audience every existing verifier refuses. It is null rather than absent when
        the deployment holds no keys or the window has closed, because the reservation and
        the claim are committed either way and the caller must be told what it is holding.
        """
        act = None
        if self.keys is not None and self.clock.now() < grant.act_expires_at:
            act = sign(
                Continuation(
                    tenant_id=identity.tenant_id,
                    principal_id=identity.principal_id,
                    credential_id=identity.credential_id,
                    audience="execution.checkpoint_outcome",
                    execution_id=view.execution_id,
                    operation_id=grant.operation_id,
                    plan_hash=view.plan_hash,
                    expires_at=grant.act_expires_at,
                    nonce=secrets.token_urlsafe(24),
                ),
                self.keys,
            )
        described = grant.model_dump(mode="json")
        if grant.expected_version is not None and grant.command is not None:
            # The command ExecBound would have sent had it dispatched: what a vendor that
            # speaks the provider protocol accepts verbatim, and what an executor for any
            # other vendor reads the target, action, arguments and version out of. Under
            # UNAVAILABLE there is no version, so there is no command either.
            described["provider_command"] = provider_command(grant.command).model_dump(mode="json")
        return {"grant": described, "act": act}

    def present(self, identity: Identity, view: ExecutionView) -> dict[str, object]:
        payload: dict[str, object] = view.model_dump(mode="json")
        if view.tenant_stopped:
            payload["tenant_stopped"] = True
        if view.observed is not None:
            # Recorded decision only: no continuation, no approval page, nothing to retry into.
            payload["observed"] = view.observed.model_dump(mode="json")
        if view.checkpoint is not None:
            # Set by the admission this request performed and by nothing else: a status
            # read never carries one, so the grant described here is always the one this
            # identity was just answered with.
            payload["checkpoint"] = self._described(identity, view, view.checkpoint)
        if view.state == "DENIED":
            # The state, the category the record gives and the reference, never the cause;
            # added for this state alone, so every other answer keeps its bytes. A view with
            # no recorded category, which only a test double builds, is told nothing more
            # than withheld.
            denial: DenialCategory = view.denial or "withheld"
            payload["denial"] = denial
            payload["notice"] = denial_notice(view.request_ref, denial)
        if view.state != "PENDING_APPROVAL" or self.keys is None:
            return payload
        with self.db.transaction(identity.tenant_id) as conn:
            store.identity_check(conn, identity, self.clock, "AGENT")
            row = store.read(conn, identity.tenant_id, view.execution_id)
            if row["principal_id"] != identity.principal_id:
                raise ExecutionError("NOT_FOUND")
            approval = store.approval_row(conn, row)
            if approval is None:
                raise ExecutionError("INVALID_STATE")
            expiry = min(
                approval["expires_at"], identity.expires_at, self.clock.now() + timedelta(minutes=2)
            )
            store.identity_check(conn, identity, self.clock, "AGENT")
        if self.clock.now() < expiry:
            payload["continuation"] = sign(
                Continuation(
                    tenant_id=identity.tenant_id,
                    principal_id=identity.principal_id,
                    credential_id=identity.credential_id,
                    audience="execution.status",
                    execution_id=view.execution_id,
                    approval_id=view.approval_id,
                    plan_hash=view.plan_hash,
                    expires_at=expiry,
                    nonce=secrets.token_urlsafe(24),
                ),
                self.keys,
            )
        if self.approval_url:
            payload["approval_url"] = self.approval_url
        return payload
