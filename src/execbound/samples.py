# SPDX-License-Identifier: AGPL-3.0-only
"""Sample targets (#420): a new workspace's first governed action, added by one click.

`install` gives an empty workspace one sample connector account for the endpoint mock, its two
context sources, the `endpoint.isolate` mapping, three sample targets with their trusted facts,
aliases and open critical incidents, the installing administrator's review scope on each, and
the product's own starter ruleset compiled for that mapping and activated. The registry rows are
written by migration 0060's `samples_install`, because the runtime holds no write on any of
those tables; the bundle is created, validated and activated by the policy store in the same
fenced transaction, so what goes live is checked exactly as a bundle a person activates is.
`remove` takes them back out without deleting anything, and refuses while a sample request is
unresolved. `refresh` does both in one transaction, so the facts are recorded afresh (#545).
`status` is what Home's guided setup reads.

The target set and its facts live here and nowhere else. The endpoint mock creates a target the
first time a sample command names it, at `SAMPLE_RESOURCE_VERSION`, the version these facts
record, so the first allowed request really executes.
"""

import ipaddress
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from execbound.access_control import has_permission
from execbound.audit import acted_with, append_event
from execbound.db import Database, UnsafeDatabaseRole
from execbound.execution import store
from execbound.execution.models import UNRESOLVED, AuthorityCheck, ExecutionError
from execbound.getting_started import host_facts
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.operations import PRODUCTION_ACTIONS
from execbound.policy.models import BundleContent, MappingRef, Ruleset
from execbound.policy.rulesets import project, ruleset_bundle
from execbound.policy.store import PolicyStoreError, activate_new_bundle
from execbound.provider.sample_accounts import SAMPLE_PROVIDER, SAMPLE_RESOURCE_VERSION
from execbound.quickstart import starter_rules
from execbound.resolution.models import Clock, SystemClock
from execbound.spaces import SpaceError, default_space

SAMPLE_ACTION = "endpoint.isolate"
SAMPLE_MAPPING_VERSION = "sample-v1"
SampleState = Literal["absent", "present", "removable"]
# The refusals the two definer functions raise by name; any other database fault is UNAVAILABLE.
_CODES = frozenset(
    {
        "INVALID_ACTOR",
        "INVALID_CLOCK",
        "POLICY_PRESENT",
        "ACCOUNT_PRESENT",
        "MAPPING_PRESENT",
        "INVALID_SPACE",
        "INVALID_TARGETS",
        "SAMPLES_BUSY",
    }
)
# The errors whose `code` is a fixed vocabulary, and the shape such a code has, so a fault's
# log line can name one without ever carrying free text.
_CODED = (ExecutionError, PolicyStoreError)
_FIXED_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_ACTIVE_SAMPLE = (
    "SELECT account_id FROM execbound.connector_accounts "
    "WHERE tenant_id = :t AND sample AND active ORDER BY account_id LIMIT 1"
)
# The three conditions `samples_install` refuses on, read so Home offers exactly what the
# function would accept: no policy selected anywhere, no active connection, and the mapping's
# reference free or held by a previous install's inactive mapping.
_OFFERED = """
SELECT NOT EXISTS (SELECT 1 FROM execbound.space_policy_selection WHERE tenant_id = :t)
   AND NOT EXISTS (SELECT 1 FROM execbound.connector_accounts WHERE tenant_id = :t AND active)
   AND NOT EXISTS (
       SELECT 1 FROM execbound.operation_mappings m
        WHERE m.tenant_id = :t AND m.operation_ref = 'endpoint.isolate'
          AND (m.active OR NOT EXISTS (
              SELECT 1 FROM execbound.connector_accounts a
               WHERE a.tenant_id = m.tenant_id AND a.account_id = m.account_id AND a.sample)))
"""
_HOSTS = """
SELECT r.provider_id, r.role, r.environment, r.criticality, r.observed_at,
       i.canonical_target_id,
       (SELECT a.normalized_value FROM execbound.resource_aliases a
         WHERE a.tenant_id = r.tenant_id AND a.account_id = r.account_id
           AND a.provider = r.provider AND a.resource_type = r.resource_type
           AND a.resource_id = r.resource_id AND a.kind = 'hostname'
         ORDER BY a.alias_id LIMIT 1) AS hostname,
       n.incident_id, n.severity AS incident_severity, n.observed_at AS incident_observed_at
  FROM execbound.resources r
  JOIN execbound.resource_identities i
    ON i.tenant_id = r.tenant_id AND i.account_id = r.account_id AND i.provider = r.provider
   AND i.resource_type = r.resource_type AND i.resource_id = r.resource_id
  LEFT JOIN execbound.incidents n
    ON n.tenant_id = r.tenant_id AND n.account_id = r.account_id AND n.provider = r.provider
   AND n.resource_type = r.resource_type AND n.resource_id = r.resource_id
   AND n.status = 'OPEN'
 WHERE r.tenant_id = :t AND r.account_id = :a AND r.active
 ORDER BY r.provider_id
"""
_BUSY = """
SELECT EXISTS (
    SELECT 1 FROM execbound.executions e
     WHERE e.tenant_id = :t AND e.state = ANY(CAST(:states AS text[]))
       AND e.frozen #>> '{intent,account_id}' = :a)
"""
_FIRST = """
SELECT e.execution_id, e.state, e.created_at,
       e.frozen ->> 'resource_provider_id' AS provider_id
  FROM execbound.executions e
 WHERE e.tenant_id = :t AND e.frozen #>> '{intent,account_id}' = :a
 ORDER BY e.created_at, e.execution_id LIMIT 1
"""
# The sample targets on which a request since their facts were recorded reached the provider
# in a way that changed the target there, or may have: executed, or dispatched and not yet
# settled, or settled on somebody's word alone. An executed isolation moves the mock's target
# past `SAMPLE_RESOURCE_VERSION`, the version the facts record, so a later request on it ends
# `STALE_AUTHORIZATION`; a refresh records the targets afresh, on a new account, so the account
# bounds this to the facts in force. A denial, a lapsed approval, a refused precondition and a
# verified non-execution change nothing at the provider.
_CHANGED = """
SELECT DISTINCT e.frozen ->> 'resource_provider_id'
  FROM execbound.executions e
 WHERE e.tenant_id = :t AND e.frozen #>> '{intent,account_id}' = :a
   AND e.state = ANY(CAST(:states AS text[]))
"""
_CHANGING = ("EXECUTED", "DISPATCH_COMMITTED", "INDETERMINATE", "FAILED_EFFECT_UNKNOWN")
# A policy a person made over the samples, which a refresh would break, so a refresh is refused
# while either exists (#545). A read, under the fence the refresh already holds.
# - A bundle other than the current starter, not retired, whose mappings name the sample
#   account. A refresh switches that account off, which would leave such a bundle unable to
#   validate or authorize anything (a copy of the starter is then refused `INVALID_COMPONENT`).
# - The starter selected in a space other than the default one. The removal drops the unchanged
#   starter from every space that selects it and the install makes the new one live in the
#   default space alone, so that space would be left with no policy (`NO_ACTIVE_BUNDLE`).
_PERSONS_POLICY = """
SELECT EXISTS (
    SELECT 1 FROM execbound.policy_bundle_contents c
      JOIN execbound.policy_bundle_lifecycle l
        ON l.tenant_id = c.tenant_id AND l.bundle_id = c.bundle_id
     WHERE c.tenant_id = :t AND c.bundle_id <> :starter AND l.state <> 'RETIRED'
       AND jsonb_typeof(c.content -> 'mappings') = 'array'
       AND EXISTS (
           SELECT 1 FROM jsonb_array_elements(c.content -> 'mappings') m
            WHERE m ->> 'account_id' = :a))
    OR EXISTS (
        SELECT 1 FROM execbound.space_policy_selection s
         WHERE s.tenant_id = :t AND s.bundle_id = :starter AND s.space_id <> :space)
"""
# The `operation_ref` an agent sends to isolate a sample target: the one the samples' starter
# bundle names, while the tenant's mapping of it is active, on the sample account and for the
# isolation action. Read rather than assumed, since a tenant's operation_ref is its own key and
# not the catalog action. Never another mapping of the account: an owner may map the isolation
# action to it again under another reference (`administration.create_mapping`), which the
# starter does not name, so the offered check refuses it while the starter is the space's
# policy. None where the starter names no such mapping, and the console then words the request
# without an operation; at most one row, whatever else is mapped.
_OPERATION = """
SELECT om.operation_ref
  FROM execbound.policy_bundle_contents c
 CROSS JOIN LATERAL jsonb_array_elements(c.content -> 'mappings') m
  JOIN execbound.operation_mappings om
    ON om.tenant_id = c.tenant_id AND om.operation_ref = m ->> 'operation_ref'
 WHERE c.tenant_id = :t AND c.bundle_id = :starter
   AND om.account_id = :a AND om.active AND om.action = :action
 ORDER BY om.operation_ref LIMIT 1
"""

# Whether the starter decides the samples' requests as its rules read: it is the active bundle
# the default space selects, the one an agent of that space is decided under
# (`store.active_bundle`), and the workspace enforces it rather than observing
# (`store.enforcement_mode`, ENFORCE where no row says otherwise). A policy a person activated
# in its place, even an unchanged copy, decides them as that person wrote it.
_IN_FORCE = """
SELECT EXISTS (
    SELECT 1 FROM execbound.space_policy_selection s
      JOIN execbound.policy_bundle_lifecycle l
        ON l.tenant_id = s.tenant_id AND l.bundle_id = s.bundle_id
     WHERE s.tenant_id = :t AND s.bundle_id = :starter AND l.state = 'ACTIVE'
       AND s.space_id = (
           SELECT p.space_id FROM execbound.spaces p WHERE p.tenant_id = :t
            ORDER BY p.created_at, p.space_id LIMIT 1))
   AND COALESCE(
       (SELECT c.enforcement_mode FROM execbound.tenant_policy_control c WHERE c.tenant_id = :t),
       'ENFORCE') = 'ENFORCE'
"""


class SampleError(ValueError):
    """A refusal with its code; the message never carries a database diagnostic."""

    def __init__(self, code: str = "UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Sample targets unavailable")


@dataclass(frozen=True)
class SampleTarget:
    """One sample target and the trusted facts ExecBound records for it."""

    provider_id: str
    hostname: str
    role: Literal["workstation", "domain_controller"]
    environment: Literal["development", "production"]
    criticality: int
    # What the starter rules do to `endpoint.isolate` on it, and the rule that decides it.
    expected: Literal["allow", "require approval", "deny"]
    rule_id: str


SAMPLE_TARGETS: tuple[SampleTarget, ...] = (
    SampleTarget(
        "sample-ws-dev-01",
        "ws-dev-01.sample.invalid",
        "workstation",
        "development",
        1,
        "allow",
        "isolate-workstation-open-critical",
    ),
    SampleTarget(
        "sample-ws-prod-01",
        "ws-prod-01.sample.invalid",
        "workstation",
        "production",
        2,
        "require approval",
        "isolate-production-needs-review",
    ),
    SampleTarget(
        "sample-dc-01",
        "dc-01.sample.invalid",
        "domain_controller",
        "production",
        3,
        "deny",
        "isolate-never-domain-controller",
    ),
)


@dataclass(frozen=True)
class SampleHost:
    """One installed sample target, with what the starter rules read on it."""

    provider_id: str
    hostname: str
    role: str
    environment: str
    criticality: int
    canonical_target_id: UUID
    incident_id: UUID | None
    effect: str
    rules: tuple[str, ...]


@dataclass(frozen=True)
class SampleRequest:
    """The first request an agent made on a sample target."""

    execution_id: UUID
    state: str
    provider_id: str
    created_at: datetime


@dataclass(frozen=True)
class SampleStatus:
    """Whether a workspace has samples, whether it may add them, and what they are."""

    state: SampleState
    offered: bool
    available: bool
    account_id: UUID | None = None
    bundle_id: UUID | None = None
    hosts: tuple[SampleHost, ...] = ()
    observed_at: datetime | None = None
    stale_at: datetime | None = None
    first_request: SampleRequest | None = None
    # The operation_ref the starter bundle names for the samples' active mapping of the
    # isolation action, which the example request names (#545); None while no samples are
    # installed, or where the starter names no such mapping (`_OPERATION`).
    operation_ref: str | None = None
    # Whether the starter is the policy deciding the samples' requests (`_IN_FORCE`): false
    # while none are installed, while a policy a person activated selects in its place, and
    # while the workspace observes rather than enforces.
    in_force: bool = False
    # The provider ids of the sample targets a request since their facts were recorded changed
    # at the provider, or may have (`_CHANGED`); empty while none are installed.
    changed: frozenset[str] = frozenset()
    # Whether the workspace's emergency stop is active (`store.stop`), under which admission
    # refuses every new request with `TENANT_STOPPED` before it reads a fact; false while no
    # samples are installed.
    stopped: bool = False


def starter_bundle_id(tenant_id: UUID, account_id: UUID) -> UUID:
    """The starter bundle an install makes for one sample account, derived rather than stored.

    Bundle content is immutable per id and any edit makes a successor with a new one, so "a
    space still selects this id" is exactly "the starter bundle is still active and unchanged".
    """
    return uuid5(
        NAMESPACE_URL,
        f"https://execbound.invalid/samples/v1/{tenant_id}/{account_id}/starter-bundle",
    )


def starter_ruleset() -> Ruleset:
    return Ruleset.model_validate_json(starter_rules())


def starter_bundle(tenant_id: UUID, account_id: UUID) -> BundleContent:
    """The product's starter ruleset, compiled for the one sample mapping."""
    spec = PRODUCTION_ACTIONS.bound(SAMPLE_PROVIDER, SAMPLE_ACTION)
    ruleset = starter_ruleset()
    mapping = MappingRef(
        operation_ref=SAMPLE_ACTION,
        account_id=account_id,
        mapping_version=SAMPLE_MAPPING_VERSION,
        schema_version="action.v1",
        context_contract_version=spec.context_contract_version,
    )
    return ruleset_bundle(
        ruleset,
        tenant_id=tenant_id,
        bundle_id=starter_bundle_id(tenant_id, account_id),
        mappings=(mapping,),
        context_settings=ruleset.context,
    )


def _targets_document() -> list[dict[str, Any]]:
    return [
        {
            "provider_id": target.provider_id,
            "hostname": target.hostname,
            "role": target.role,
            "environment": target.environment,
            "criticality": target.criticality,
            "version": SAMPLE_RESOURCE_VERSION,
            "canonical_target_id": str(uuid4()),
            "resource_id": str(uuid4()),
            "incident_id": str(uuid4()),
        }
        for target in SAMPLE_TARGETS
    ]


def _call(conn: Connection, statement: str, params: dict[str, Any]) -> dict[str, Any]:
    """Run one samples function; a refusal it raises by name surfaces as that code alone.

    Any other database fault propagates unchanged, so `_administration` reports it as
    `UNAVAILABLE` under its own class name.
    """
    try:
        result = conn.execute(text(statement), params).scalar_one()
    except DBAPIError as exc:
        diagnostic = getattr(exc.orig, "diag", None)
        message = getattr(diagnostic, "message_primary", None)
        if message in _CODES:
            raise SampleError(message) from None
        raise
    return dict(result)


def _reason(cause: Exception) -> str:
    """A fault's class name, and for the stores' own errors the fixed code they carry too.

    `PolicyStoreError` and `ExecutionError` carry a code from a closed vocabulary, which is
    what tells a ruleset mismatch from a database outage. Nothing else about the exception is
    read, and never its message, which can carry a database diagnostic or a value.
    """
    name = type(cause).__name__
    code = getattr(cause, "code", None) if isinstance(cause, _CODED) else None
    if isinstance(code, str) and _FIXED_CODE.fullmatch(code):
        return f"{name}:{code}"
    return name


def _refusal(identity: Identity, code: str, cause: Exception | None = None) -> SampleError:
    """Log one refusal and return it to be raised.

    A fault is logged with `_reason` as the reason and never with its message; a refusal by
    name needs no reason beyond its code.
    """
    code = "FORBIDDEN" if code == "INVALID_ACTOR" else code
    fields: dict[str, Any] = {
        "tenant_id": identity.tenant_id,
        "principal_id": identity.principal_id,
        "code": code,
    }
    if cause is not None:
        fields["reason"] = _reason(cause)
    log_event("samples.refused", level="WARNING", **fields)
    return SampleError(code)


@contextmanager
def _administration(
    db: Database, identity: Identity, clock: Clock, authority_check: AuthorityCheck | None
) -> Iterator[tuple[Connection, datetime]]:
    """One fenced transaction for a live tenant administrator, with every failure a refusal.

    What `install`, `remove` and `refresh` share: the kind checked before anything is read,
    then the tenant fence, the administrator rechecked under it, the caller's authority check
    and the clock read once, and the administrator rechecked again before the commit. A
    refusal leaves as a `SampleError` with its code, logged as `samples.refused`. A
    space-scoped ADMIN passes the kernel's check, which accepts the permission in any scope,
    and is refused by the definer function, or by `refresh` with the definer's own test before
    its first read of policy, as `INVALID_ACTOR`, which is `FORBIDDEN` here as for anyone else.
    """
    if identity.kind != "ADMIN":
        raise _refusal(identity, "FORBIDDEN")
    try:
        with db.transaction(identity.tenant_id) as conn:
            store.fence(conn, identity.tenant_id, clock)
            store.identity_check(conn, identity, clock, "ADMIN")
            if authority_check is not None:
                authority_check(conn)
            yield conn, store.now(clock)
            store.identity_check(conn, identity, clock, "ADMIN")
    except SampleError as exc:
        raise _refusal(identity, exc.code) from None
    except (ExecutionError, PolicyStoreError) as exc:
        if exc.code == "INVALID_IDENTITY":
            raise _refusal(identity, "FORBIDDEN") from None
        raise _refusal(identity, "UNAVAILABLE", exc) from None
    except (SpaceError, SQLAlchemyError, UnsafeDatabaseRole, ValueError) as exc:
        raise _refusal(identity, "UNAVAILABLE", exc) from None


def install(
    db: Database,
    identity: Identity,
    *,
    available: bool,
    clock: Clock | None = None,
    authority_check: AuthorityCheck | None = None,
) -> SampleStatus:
    """Add the sample targets to an empty workspace, or report the ones already there.

    One transaction under the tenant fence: the definer function writes the registry rows, the
    policy store creates, validates and activates the starter bundle over them, and the audit
    chain records both, naming the administrator. `available` says whether this deployment holds
    a sample key for the endpoint mock; without one nothing could reach the samples, so nothing
    is added. A second install finds the samples present and answers their status, writing
    nothing and logging nothing.
    """
    clock = clock or SystemClock()
    if not available:
        raise _refusal(identity, "SAMPLES_UNAVAILABLE")
    with _administration(db, identity, clock, authority_check) as (conn, now):
        installed = _install_rows(conn, identity, clock, now)
        found = status(conn, identity.tenant_id, available=available)
    if installed:
        log_event(
            "samples.installed",
            tenant_id=identity.tenant_id,
            principal_id=identity.principal_id,
            state=found.state,
        )
    return found


def remove(
    db: Database,
    identity: Identity,
    *,
    available: bool,
    clock: Clock | None = None,
    authority_check: AuthorityCheck | None = None,
) -> SampleStatus:
    """Take the samples back out: every sample row switched off, nothing deleted.

    The starter bundle is retired only while a space still selects it unchanged. A removal is
    refused while any request on the sample account is unresolved, so nothing pending approval
    or unsettled is stranded, and a workspace with no samples is answered with its status,
    nothing written and nothing logged.
    """
    clock = clock or SystemClock()
    removed = False
    with _administration(db, identity, clock, authority_check) as (conn, now):
        account = conn.execute(text(_ACTIVE_SAMPLE), {"t": identity.tenant_id}).scalar_one_or_none()
        if account is not None:
            removed = _remove_rows(conn, identity, account, now)
        found = status(conn, identity.tenant_id, available=available)
    if removed:
        log_event(
            "samples.removed",
            tenant_id=identity.tenant_id,
            principal_id=identity.principal_id,
            state=found.state,
        )
    return found


def refresh(
    db: Database,
    identity: Identity,
    *,
    available: bool,
    clock: Clock | None = None,
    authority_check: AuthorityCheck | None = None,
) -> SampleStatus:
    """Re-create the sample targets with fresh facts (#545): remove, then install.

    One fenced transaction, the one `install` and `remove` each take: the definer functions
    switch the current sample rows off and write a new set, the starter bundle is retired and a
    new one activated over the new mapping, and the audit chain records the removal and the
    install exactly as the two separate actions record them, each naming the administrator.
    It is refused `POLICY_PRESENT` before anything is removed while a policy a person made
    depends on the samples (`_PERSONS_POLICY`): a bundle other than the starter that names the
    sample account, which switching the account off would break, or the starter selected in a
    space other than the default one, which would be left with no policy. The actor is checked
    first, as the definer functions check it, so an administrator seated in a space is refused
    `FORBIDDEN` and never learns from the answer whether such a policy exists.
    A refusal from either step refuses the whole, and the removal is rolled back with it:
    `SAMPLES_BUSY` while a request on the samples is unresolved, which includes a held request
    whose approval lapsed until the recovery run ends it, and `POLICY_PRESENT` or
    `ACCOUNT_PRESENT` once a person has activated a policy or added a connection of their own.
    A workspace with no samples is answered with its status, nothing written and nothing
    logged, as `remove` answers it.

    Each target comes back with a new canonical id, resource and incident, so a request naming
    an old incident is refused; review of the targets returns to the refreshing administrator
    alone, as an install gives it to the installing one; and the first request is counted
    afresh. Requests already made keep their rows.
    """
    clock = clock or SystemClock()
    if not available:
        raise _refusal(identity, "SAMPLES_UNAVAILABLE")
    refreshed = False
    with _administration(db, identity, clock, authority_check) as (conn, now):
        account = conn.execute(text(_ACTIVE_SAMPLE), {"t": identity.tenant_id}).scalar_one_or_none()
        if account is not None:
            # The definer functions' own test of the actor, a tenant administrator seated in no
            # space, made before the read below rather than after it inside `samples_remove`.
            if not has_permission(
                conn, identity.tenant_id, identity.principal_id, "workspace.manage"
            ):
                raise SampleError("INVALID_ACTOR")
            starter = starter_bundle_id(identity.tenant_id, account)
            persons = conn.execute(
                text(_PERSONS_POLICY),
                {
                    "t": identity.tenant_id,
                    "a": str(account),
                    "starter": starter,
                    "space": default_space(conn, identity.tenant_id),
                },
            ).scalar_one()
            if persons:
                raise SampleError("POLICY_PRESENT")
            if not _remove_rows(conn, identity, account, now):
                # Unreachable: the read above found the account an active sample one under the
                # fence this transaction holds, so the removal cannot find it gone. Were it
                # gone, the install would follow a removal this refresh never made or recorded.
                raise SampleError()
            if not _install_rows(conn, identity, clock, now):
                # Unreachable: the removal just switched the only active sample account off
                # under the fence this transaction holds, so the install cannot find it present.
                raise SampleError()
            refreshed = True
        found = status(conn, identity.tenant_id, available=available)
    if refreshed:
        log_event(
            "samples.refreshed",
            tenant_id=identity.tenant_id,
            principal_id=identity.principal_id,
            state=found.state,
        )
    return found


def _install_rows(conn: Connection, identity: Identity, clock: Clock, now: datetime) -> bool:
    """Write a new set of sample rows and make the starter bundle over them live.

    Inside the caller's fenced transaction: the definer function writes the registry rows for a
    new account and grants the acting administrator a review scope on each new target, the
    policy store creates, validates and activates the starter bundle over them, and the audit
    chain records both, naming the administrator. False, with nothing written, when samples are
    already present (the function's `PRESENT`). A refusal the function raises by name leaves as
    a `SampleError` with that code.
    """
    account = uuid4()
    space = default_space(conn, identity.tenant_id)
    result = _call(
        conn,
        "SELECT execbound.samples_install(:actor, :account, :space, CAST(:targets AS jsonb), :now)",
        {
            "actor": identity.principal_id,
            "account": account,
            "space": space,
            "targets": json.dumps(_targets_document()),
            "now": now,
        },
    )
    if result["outcome"] != "INSTALLED":
        return False
    record = activate_new_bundle(
        conn, identity, starter_bundle(identity.tenant_id, account), clock, space=space
    )
    append_event(
        conn,
        identity.tenant_id,
        identity.principal_id,
        "samples.installed",
        {
            "account_id": str(account),
            "provider": SAMPLE_PROVIDER,
            "bundle_id": str(record.content.bundle_id),
            "content_hash": record.content.content_hash,
            "targets": [target.provider_id for target in SAMPLE_TARGETS],
            **acted_with(identity.credential_id),
        },
        space=space,
    )
    return True


def _remove_rows(conn: Connection, identity: Identity, account: UUID, now: datetime) -> bool:
    """Switch one sample account's rows off, every reviewer's scope on its targets among them,
    and record it, inside the caller's fenced transaction. The definer function refuses with
    `SAMPLES_BUSY` while a request on the account is unresolved, and retires the starter bundle
    only while a space still selects it unchanged. False, with nothing written, when the
    account is no longer an active sample one (the function's `ABSENT`)."""
    bundle = starter_bundle_id(identity.tenant_id, account)
    result = _call(
        conn,
        "SELECT execbound.samples_remove(:actor, :account, :bundle, :now)",
        {"actor": identity.principal_id, "account": account, "bundle": bundle, "now": now},
    )
    if result["outcome"] != "REMOVED":
        return False
    _record_removal(conn, identity, account, bundle, result)
    return True


def _record_removal(
    conn: Connection, identity: Identity, account: UUID, bundle: UUID, result: dict[str, Any]
) -> None:
    """The removal and, when it retired the starter bundle, that bundle's own lifecycle
    events, in the words `activate_bundle` and `retire_bundle` use for the same transitions."""
    retired = result.get("retired") is True
    append_event(
        conn,
        identity.tenant_id,
        identity.principal_id,
        "samples.removed",
        {
            "account_id": str(account),
            "bundle_id": str(bundle),
            "retired": retired,
            **acted_with(identity.credential_id),
        },
    )
    if not retired:
        return
    content_hash = str(
        conn.execute(
            text(
                "SELECT content_hash FROM execbound.policy_bundle_contents "
                "WHERE tenant_id = :t AND bundle_id = :b"
            ),
            {"t": identity.tenant_id, "b": bundle},
        ).scalar_one()
    )
    for value in result.get("spaces", []):
        space = UUID(str(value))
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "policy.bundle_deselected",
            {
                "bundle_id": str(bundle),
                "content_hash": content_hash,
                "space_id": str(space),
                **acted_with(identity.credential_id),
            },
            space=space,
        )
    append_event(
        conn,
        identity.tenant_id,
        identity.principal_id,
        "policy.bundle_retired",
        {
            "bundle_id": str(bundle),
            "content_hash": content_hash,
            **acted_with(identity.credential_id),
        },
    )


def status(conn: Connection, tenant: UUID, *, available: bool) -> SampleStatus:
    """The samples' state for Home, read on the caller's connection.

    `absent` with `offered` when this deployment holds a sample key and the workspace has no
    policy and no connection; `present` while a request on a sample is unresolved, so removal
    would be refused; `removable` otherwise. Each host carries what the starter rules read on
    its facts, as the rules read and never as the kernel's decision.
    """
    account = conn.execute(text(_ACTIVE_SAMPLE), {"t": tenant}).scalar_one_or_none()
    if account is None:
        offered = available and bool(conn.execute(text(_OFFERED), {"t": tenant}).scalar_one())
        return SampleStatus("absent", offered, available)
    ruleset = starter_ruleset()
    hosts: list[SampleHost] = []
    observed: list[datetime] = []
    for row in conn.execute(text(_HOSTS), {"t": tenant, "a": account}).mappings():
        facts = host_facts(
            {
                "resource_type": "endpoint",
                "role": row["role"],
                "environment": row["environment"],
                "criticality": row["criticality"],
                "incident_id": row["incident_id"],
                "incident_severity": row["incident_severity"],
            }
        )
        reading = project(ruleset, SAMPLE_ACTION, facts)
        hosts.append(
            SampleHost(
                provider_id=str(row["provider_id"]),
                hostname=str(row["hostname"]),
                role=str(row["role"]),
                environment=str(row["environment"]),
                criticality=int(row["criticality"]),
                canonical_target_id=row["canonical_target_id"],
                incident_id=row["incident_id"],
                effect=reading.effect,
                rules=reading.rules,
            )
        )
        observed.append(row["observed_at"])
        if row["incident_observed_at"] is not None:
            observed.append(row["incident_observed_at"])
    busy = bool(
        conn.execute(
            text(_BUSY), {"t": tenant, "a": str(account), "states": list(UNRESOLVED)}
        ).scalar_one()
    )
    first = conn.execute(text(_FIRST), {"t": tenant, "a": str(account)}).mappings().one_or_none()
    starter = starter_bundle_id(tenant, account)
    operation = conn.execute(
        text(_OPERATION), {"t": tenant, "starter": starter, "a": account, "action": SAMPLE_ACTION}
    ).scalar_one_or_none()
    in_force = bool(conn.execute(text(_IN_FORCE), {"t": tenant, "starter": starter}).scalar_one())
    changed = frozenset(
        str(provider_id)
        for provider_id in conn.execute(
            text(_CHANGED), {"t": tenant, "a": str(account), "states": list(_CHANGING)}
        ).scalars()
        if provider_id is not None
    )
    oldest = min(observed) if observed else None
    ages = [setting.max_age_seconds for setting in ruleset.context or ()]
    return SampleStatus(
        state="present" if busy else "removable",
        offered=False,
        available=available,
        account_id=account,
        bundle_id=starter,
        hosts=tuple(hosts),
        observed_at=oldest,
        stale_at=None if oldest is None or not ages else oldest + timedelta(seconds=min(ages)),
        first_request=None
        if first is None
        else SampleRequest(
            first["execution_id"],
            str(first["state"]),
            str(first["provider_id"]),
            first["created_at"],
        ),
        operation_ref=None if operation is None else str(operation),
        in_force=in_force,
        changed=changed,
        stopped=store.stop(conn, tenant) is not None,
    )


def sample_workstation(status: SampleStatus) -> SampleHost | None:
    """The installed sample development workstation, once it carries an open incident; None
    while it is missing or its incident is closed. Home's Getting started page and the console's
    "Connect this agent" card both name the same example request from this one selection, so
    neither picks the target out of `status.hosts` its own way."""
    host = next(
        (host for host in status.hosts if host.provider_id == SAMPLE_TARGETS[0].provider_id),
        None,
    )
    return host if host is not None and host.incident_id is not None else None


# Which sample target carries each of the demo's named targets, by what the starter rules read
# on it: the decide beat's allowed workstation, its denied domain controller and its production
# workstation that waits for a person.
_DEMO_TARGETS = (
    ("workstation", "allow"),
    ("domain_controller", "deny"),
    ("production", "require approval"),
)


def _decided_as_expected(status: SampleStatus) -> dict[str, SampleHost] | None:
    """The installed sample carrying each of the demo's named targets, or None while a request
    the decide beat sends could not be served, or would not be decided as the beat expects:
    the samples are `available` (this deployment holds the sample key and no configured
    connector for the tenant, without which no sample connection is derived and admission
    refuses every request), the starter is the policy in force (`in_force`: the default space
    selects it and the workspace enforces it, so the targets' effects are the starter's, which
    are what `effect` reads), the operation the starter names for them is the isolation action
    the demo sends (`status.operation_ref`), and each named target carries an open incident,
    without which admission finds no context. And no emergency stop is active (`stopped`):
    under one, admission refuses every new request with `TENANT_STOPPED` before it reads a
    fact, and only an administrator's release ends it."""
    if (
        not status.available
        or not status.in_force
        or status.stopped
        or status.operation_ref != SAMPLE_ACTION
    ):
        return None
    by_effect = {host.effect: host for host in status.hosts if host.incident_id is not None}
    if any(effect not in by_effect for _, effect in _DEMO_TARGETS):
        return None
    return {name: by_effect[effect] for name, effect in _DEMO_TARGETS}


def _current(status: SampleStatus, now: datetime) -> bool:
    """Whether the samples' facts are still current at `now`: stale from the instant `now`
    reaches `stale_at`, as admission judges a fact against its `valid_until` and as the Sample
    targets card judges the same `stale_at` (`held.useStaleSince`)."""
    return status.stale_at is None or now < status.stale_at


def demo_targets(status: SampleStatus, *, now: datetime) -> dict[str, SampleHost] | None:
    """The installed sample carrying each of the demo's named targets, or None while
    `execbound-demo` could not run on the samples at `now` (#247).

    Every request its decide beat sends has to be one this deployment can decide and serve,
    and decides as the beat expects (`_decided_as_expected`), on facts still current: the
    starter keeps each for an hour (`stale_at`), nothing records them again but a refresh, and
    from then every request on the samples is refused before any decision with
    `EXECUTION_UNAVAILABLE`. The two it expects to execute, the workstation's and, once
    approved, production's, have to find their targets at the provider as the facts record
    them. So no request on the samples is unresolved (the status is not `present`), since one
    waiting for approval or provider evidence may yet change a target, and none since the
    facts were recorded has changed a named target at the provider (`status.changed`; the
    domain controller too, so the samples are as their facts record them), as guided setup's
    own requests do when the person's agent isolates the sample workstation and the approved
    production one: the demo's isolation of either would then end `STALE_AUTHORIZATION`.
    Home's Sample targets card offers the download, and the route hands it out, only while
    this answers targets, so a person is never given a file whose first request is refused, or
    decided otherwise; where only a refresh stands in the way, the card says so instead
    (`demo_needs_refresh`). Facts that go stale after the download refuse the run's requests
    before any decision, and the demo then says to refresh, as the card does.
    """
    hosts = _decided_as_expected(status)
    if hosts is None or status.state == "present" or not _current(status, now):
        return None
    if any(host.provider_id in status.changed for host in hosts.values()):
        return None
    return hosts


def demo_needs_refresh(status: SampleStatus, *, now: datetime) -> bool:
    """Whether a refresh of the sample facts is what stands between the samples and the demo
    at `now`: everything else `demo_targets` asks holds, no request on them is unresolved, and
    either the facts have gone stale or a request since they were recorded changed a named
    target at the provider. A refresh records the targets afresh, at the version the mock
    creates them at, with facts current for another hour, and activates the starter again.
    Never while anything `_decided_as_expected` asks fails, none of which a refresh changes:
    it leaves the workspace's mode, its emergency stop and a policy a person activated in the
    starter's place as they are, and cannot serve samples this deployment does not; nor while a
    request is unresolved, which refuses a refresh. A refresh may still be refused while a
    policy a person drafted names the samples, and the card then says why and what to
    retire."""
    hosts = _decided_as_expected(status)
    return (
        hosts is not None
        and status.state != "present"
        and (
            not _current(status, now)
            or any(host.provider_id in status.changed for host in hosts.values())
        )
    )


def _loopback(origin: str) -> bool:
    """Whether an origin names the machine it is read on: a loopback IP address, or `localhost`
    and its subdomains."""
    host = (urlsplit(origin).hostname or "").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def demo_configuration(
    status: SampleStatus, *, now: datetime, origin: str, tenant_id: UUID, provider_origin: str
) -> dict[str, Any] | None:
    """`execbound-demo`'s configuration for a workspace's samples (#247); None while the demo
    could not run on them at `now` (`demo_targets`).

    The shape the demo reads as `sandbox.json` with no `credentials` object, which the person
    adds for the agent API key they issue, and `"workspace": "samples"`, which tells the demo
    to send its requests unmarked and to run only the beats three sample targets can carry.
    Each named target is the installed sample whose facts the starter rules read as that
    target's effect, by hostname with its open incident, and the pool is empty. `providers`
    names the endpoint mock that serves the samples, so the boundary beat can show it refusing
    the agent's key, only where the mock's address is not a loopback one. A loopback address
    is the gateway's own view of the mock, and nothing the gateway holds says whether the
    person's machine reaches the mock there: the Community bundle publishes the gateway's port
    alone, on the host's loopback, and keeps the mock on a loopback address inside its own
    network namespace, so even a gateway on loopback is no sign. On the person's machine such
    an address names whatever listens on that port, which the beat would hand agent A's key,
    so the file then names no mock (the field is optional) and the beat checks the gateway
    alone; a person whose machine does reach the mock there may name it themselves.
    """
    hosts = demo_targets(status, now=now)
    if hosts is None:
        return None
    targets: dict[str, Any] = {
        name: {"kind": "hostname", "value": host.hostname, "incident_id": str(host.incident_id)}
        for name, host in hosts.items()
    }
    targets["pool"] = []
    return {
        "workspace": "samples",
        "origin": origin,
        "tenant_id": str(tenant_id),
        **({} if _loopback(provider_origin) else {"providers": {"endpoint": provider_origin}}),
        "targets": targets,
    }


def sample_accounts(conn: Connection, tenant: UUID) -> frozenset[UUID]:
    """Every account the install function ever marked sample in this tenant, active or not."""
    return frozenset(
        conn.execute(
            text(
                "SELECT account_id FROM execbound.connector_accounts "
                "WHERE tenant_id = :t AND sample"
            ),
            {"t": tenant},
        ).scalars()
    )


def sample_bundles(conn: Connection, tenant: UUID) -> frozenset[UUID]:
    """The starter bundle id of every sample account, for the Sample badge on the policy."""
    return frozenset(
        starter_bundle_id(tenant, account) for account in sample_accounts(conn, tenant)
    )
