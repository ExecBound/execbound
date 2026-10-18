# SPDX-License-Identifier: AGPL-3.0-only
"""Owner-connection provisioning of trusted context: sources, inventory facts and incidents.

Adapters produce a context manifest; this module validates it against the contract catalog
and the tenant's registry, then writes rows with the owner role inside one audited tenant
transaction. Nothing here sits behind an HTTP route or runs with the runtime role. A refused
manifest writes nothing and audits nothing, and no value from a manifest reaches an error.
"""

import hashlib
import json
import os
import re
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import Field, ValidationError, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError

from execbound.administration import AdministrationError
from execbound.audit import append_event
from execbound.contracts import (
    PRODUCTION_CATALOG,
    Catalog,
    Column,
    FactRow,
    FactSpec,
    Signal,
    SourceKind,
    value_matches,
)
from execbound.requests import StrictModel
from execbound.secrets import find_secrets, secret_shaped
from execbound.signals.capabilities import CAPABILITIES
from execbound.signals.capabilities import capability as signal_capability
from execbound.signals.tokens import new_token as new_signal_token

MANIFEST_FORMAT = "execbound.context-manifest.v1"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_FACTS = 64
MAX_RETRACTIONS = 32
MAX_WRITERS = 16
FUTURE_SKEW = timedelta(seconds=60)
STATEMENT_TIMEOUT_MS = 60_000
LOCK_TIMEOUT_MS = 5_000
SOURCE_KINDS: frozenset[str] = frozenset({"inventory", "incident"})
COUNT_KEYS = (
    "entries",
    "applied",
    "unchanged",
    "unknown_resources",
    "facts_written",
    "facts_retracted",
    "resources_deactivated",
    "incidents_created",
    "incidents_updated",
)
_WRITER = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_RESOURCE_COLUMNS = ("role", "privilege_class", "environment", "criticality")
_INCIDENT_COLUMNS = ("status", "severity")

FactName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")]
FactValue = str | int | bool
Version = Annotated[str, Field(min_length=1, max_length=80)]
Provider = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")]
ProviderId = Annotated[str, Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")]
Writer = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
ResourceType = Literal["endpoint", "identity"]


class ProvisioningError(AdministrationError):
    """A safe code and, for entry-level refusals, the entry index; never a manifest value."""

    def __init__(self, code: str, entry: int | None = None) -> None:
        super().__init__(code)
        self.entry = entry


class Entry(StrictModel):
    """One observed resource (inventory) or incident; incidents carry `incident_id`."""

    provider: Provider
    resource_type: ResourceType
    provider_id: ProviderId
    version: Version
    observed_at: datetime
    facts: dict[FactName, FactValue] = Field(max_length=MAX_FACTS)
    retract: tuple[FactName, ...] = Field(default=(), max_length=MAX_RETRACTIONS)
    active: bool | None = None
    provider_version: Version | None = None
    incident_id: UUID | None = None

    @field_validator("observed_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Observation time needs a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def shape(self) -> "Entry":
        if len(set(self.retract)) != len(self.retract) or set(self.retract) & set(self.facts):
            raise ValueError("Retractions must be unique and outside the facts")
        if self.incident_id is None:
            if (
                not self.facts
                and not self.retract
                and self.active is None
                and self.provider_version is None
            ):
                raise ValueError("Entry states nothing")
        elif (
            self.retract
            or self.active is not None
            or self.provider_version is not None
            or not self.facts
        ):
            raise ValueError("Incident entries carry facts only")
        return self


class Manifest(StrictModel):
    manifest: Literal["execbound.context-manifest.v1"]
    tenant_id: UUID
    account_id: UUID
    source_id: UUID
    kind: Literal["inventory", "incident"]
    writer: Writer
    entries: tuple[Entry, ...] = Field(max_length=MAX_ENTRIES)

    @model_validator(mode="after")
    def consistent(self) -> "Manifest":
        keys: set[object] = set()
        for item in self.entries:
            if (item.incident_id is None) != (self.kind == "inventory"):
                raise ValueError("Entry shape differs from the manifest kind")
            key: object = (
                (item.provider, item.resource_type, item.provider_id)
                if self.kind == "inventory"
                else item.incident_id
            )
            if key in keys:
                raise ValueError("Duplicate entry")
            keys.add(key)
        return self


@dataclass(frozen=True)
class ParsedManifest:
    manifest: Manifest
    digest: str
    size: int


@dataclass(frozen=True)
class ImportResult:
    manifest_digest: str
    counts: dict[str, int]
    outcomes: tuple[str, ...]

    def summary(self) -> dict[str, Any]:
        """What `context-import` prints: the manifest digest and the counts, no outcome."""
        return {"manifest_digest": self.manifest_digest, **self.counts}


def _entry_index(error: ValidationError) -> int | None:
    for problem in error.errors():
        location = problem.get("loc", ())
        if len(location) >= 2 and location[0] == "entries" and type(location[1]) is int:
            return location[1]
    return None


def read_manifest(path: Path) -> bytes:
    """Read at most one byte past the size bound so an oversized file is refused, not loaded."""
    with path.open("rb") as handle:
        return handle.read(MAX_MANIFEST_BYTES + 1)


def parse_manifest(data: bytes) -> ParsedManifest:
    if type(data) is not bytes:
        raise ProvisioningError("INVALID_MANIFEST")
    if len(data) > MAX_MANIFEST_BYTES:
        raise ProvisioningError("MANIFEST_TOO_LARGE")
    try:
        manifest = Manifest.model_validate_json(data)
    except ValidationError as error:
        raise ProvisioningError("INVALID_MANIFEST", _entry_index(error)) from None
    # `context.imported` carries the manifest's ids, its kind and its writer (which
    # `_source` holds to the source's own writer labels, screened at `create_context_source`),
    # a digest and counts, never an entry's value. An entry's own version, provider_version
    # and facts are instead stored on `resources`, `resource_facts` and `incidents`, and from
    # there copied into the frozen plan of every request that resolves them, which the
    # transition event does carry. A shaped value buried in an entry's own fields must never
    # parse successfully in the first place.
    for index, entry in enumerate(manifest.entries):
        if find_secrets(entry.model_dump(mode="json"), limit=1):
            raise ProvisioningError("INVALID_MANIFEST", index)
    return ParsedManifest(manifest, hashlib.sha256(data).hexdigest(), len(data))


class ReportNotWritten(ProvisioningError):
    """`context-import`'s report failed after its import had committed.

    No refusal, because the import stands: it carries the import's result, so the command can
    still print what it did beside the code.
    """

    def __init__(self, code: str, result: ImportResult) -> None:
        super().__init__(code)
        self.result = result


class ReportFile:
    """Per-entry outcomes for the operator, in a new private file; never manifest values.

    The file is created when this is, before the import, so a path that exists or cannot be
    created is refused `REPORT_UNAVAILABLE` with nothing imported, as every other refusal of
    `context-import` is. Held as a context manager around the import, it removes the file
    again when the block ends in an exception, so a refused import leaves no report behind.
    `write` runs after the import has committed, so a write that fails is no refusal: it raises
    `ReportNotWritten`, and the block it ends removes the partial file.
    """

    def __init__(self, path: Path) -> None:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError:
            raise ProvisioningError("REPORT_UNAVAILABLE") from None
        self.path = path
        self._handle = os.fdopen(descriptor, "w", encoding="utf-8")

    def __enter__(self) -> "ReportFile":
        return self

    def __exit__(self, kind: type[BaseException] | None, *_: object) -> None:
        if kind is not None:
            self.discard()

    def write(self, result: ImportResult) -> None:
        document = {**result.summary(), "outcomes": list(result.outcomes)}
        try:
            with self._handle as handle:
                json.dump(document, handle, indent=2, sort_keys=True)
                handle.write("\n")
        except (OSError, ValueError):
            raise ReportNotWritten("REPORT_UNAVAILABLE", result) from None

    def discard(self) -> None:
        """Close and remove the file, as far as the file system allows; never raises, so the
        error that ended the import is the one reported."""
        with suppress(OSError):
            self._handle.close()
        with suppress(OSError):
            self.path.unlink(missing_ok=True)


# Fact routing through the catalog


@dataclass(frozen=True)
class _Route:
    storage: Column | FactRow
    specs: tuple[FactSpec, ...]


@dataclass(frozen=True)
class _Routes:
    stored: dict[str, _Route]
    derived: frozenset[str]
    ambiguous: frozenset[str]


def _routes(catalog: Catalog, resource_type: str, kind: SourceKind) -> _Routes:
    stored: dict[str, _Route] = {}
    derived: set[str] = set()
    ambiguous: set[str] = set()
    for version in sorted(catalog.versions):
        contract = catalog.contract(version)
        if contract.resource_type != resource_type:
            continue
        for spec in contract.facts:
            if spec.source_kind != kind:
                continue
            if spec.derivation is not None or spec.storage is None:
                derived.add(spec.name)
                continue
            if isinstance(spec.storage, Signal):
                # Doubly unreachable: `Manifest.kind` excludes "signal", so `kind` is never
                # "signal" here, and the contract's own validation requires Signal storage
                # to pair with `source_kind == "signal"` (contracts.py's
                # `_validate_contract`), so such a spec never matches the loop's `kind`
                # filter above either. This skip only proves to the type checker that a
                # signal fact can never be routed as a manifest destination.
                continue
            known = stored.get(spec.name)
            if known is None:
                stored[spec.name] = _Route(spec.storage, (spec,))
            elif known.storage != spec.storage:
                ambiguous.add(spec.name)
            else:
                stored[spec.name] = _Route(known.storage, (*known.specs, spec))
    ambiguous |= derived & set(stored)
    return _Routes(stored, frozenset(derived), frozenset(ambiguous))


@dataclass(frozen=True)
class _Plan:
    """What one entry asks for, routed to storage and checked against every domain."""

    columns: dict[str, FactValue | None]
    rows: dict[str, FactValue]
    row_retractions: tuple[str, ...]


def _route(routes: _Routes, name: str, index: int) -> _Route:
    if name in routes.ambiguous:
        raise ProvisioningError("AMBIGUOUS_FACT", index)
    if name in routes.derived:
        raise ProvisioningError("DERIVED_FACT", index)
    route = routes.stored.get(name)
    if route is None:
        raise ProvisioningError("UNKNOWN_FACT", index)
    return route


def _plan(manifest: Manifest, catalog: Catalog, now: datetime) -> tuple[_Plan, ...]:
    tables: dict[str, _Routes] = {}
    plans: list[_Plan] = []
    for index, item in enumerate(manifest.entries):
        if item.observed_at > now + FUTURE_SKEW:
            raise ProvisioningError("FUTURE_OBSERVATION", index)
        routes = tables.get(item.resource_type)
        if routes is None:
            routes = tables[item.resource_type] = _routes(
                catalog, item.resource_type, manifest.kind
            )
        columns: dict[str, FactValue | None] = {}
        rows: dict[str, FactValue] = {}
        retractions: list[str] = []
        for name, value in item.facts.items():
            route = _route(routes, name, index)
            if not all(value_matches(spec, value) for spec in route.specs):
                raise ProvisioningError("INVALID_VALUE", index)
            if isinstance(route.storage, Column):
                columns[route.storage.column] = value
            else:
                rows[name] = value
        for name in item.retract:
            route = _route(routes, name, index)
            if isinstance(route.storage, Column):
                columns[route.storage.column] = None
            else:
                retractions.append(name)
        plans.append(_Plan(columns, rows, tuple(retractions)))
    return tuple(plans)


# Retained rows


@dataclass(frozen=True)
class _Resource:
    resource_id: UUID
    provider: str
    resource_type: str
    version: str
    source_id: UUID
    columns: dict[str, object]
    observed_at: datetime
    active: bool


@dataclass(frozen=True)
class _Fact:
    value: object
    version: str
    source_id: UUID
    observed_at: datetime


@dataclass(frozen=True)
class _Incident:
    resource_id: UUID
    provider: str
    resource_type: str
    version: str
    source_id: UUID
    columns: dict[str, object]
    observed_at: datetime


def _instant(value: datetime | None) -> datetime:
    now = value or datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ProvisioningError("INVALID_CLOCK")
    return now.astimezone(UTC)


@contextmanager
def _transaction(engine: Engine, tenant: UUID) -> Iterator[Connection]:
    try:
        with engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('statement_timeout', :ms, true)"),
                {"ms": str(STATEMENT_TIMEOUT_MS)},
            )
            conn.execute(
                text("SELECT set_config('lock_timeout', :ms, true)"), {"ms": str(LOCK_TIMEOUT_MS)}
            )
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :tenant, true)"),
                {"tenant": str(tenant)},
            )
            owner = conn.execute(
                text(
                    "SELECT current_user = (SELECT tableowner FROM pg_tables "
                    "WHERE schemaname = 'execbound' AND tablename = 'tenants')"
                )
            ).scalar_one()
            if owner is not True:
                raise ProvisioningError("INVALID_CONNECTION")
            yield conn
    except ProvisioningError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ProvisioningError("PROVISIONING_UNAVAILABLE") from None


def _tenant(conn: Connection, tenant: UUID) -> None:
    # Owner writers use the same control -> audit -> row order as execution/refresh.
    # Taking the tenant row first deadlocks against refresh holding the audit head.
    exists = conn.execute(
        text("SELECT active FROM execbound.tenants WHERE tenant_id=:t"), {"t": tenant}
    ).scalar_one_or_none()
    if exists is not True:
        raise ProvisioningError("INVALID_TENANT")
    conn.execute(
        text(
            "INSERT INTO execbound.tenant_policy_control(tenant_id,changed_at) "
            "VALUES (:t,now()) ON CONFLICT(tenant_id) DO NOTHING"
        ),
        {"t": tenant},
    )
    conn.execute(
        text("SELECT 1 FROM execbound.tenant_policy_control WHERE tenant_id=:t FOR UPDATE"),
        {"t": tenant},
    ).one()
    conn.execute(
        text(
            "INSERT INTO execbound.audit_heads(tenant_id) VALUES (:t) "
            "ON CONFLICT(tenant_id) DO NOTHING"
        ),
        {"t": tenant},
    )
    conn.execute(
        text("SELECT 1 FROM execbound.audit_heads WHERE tenant_id=:t FOR UPDATE"), {"t": tenant}
    ).one()
    active = conn.execute(
        text("SELECT active FROM execbound.tenants WHERE tenant_id = :tenant FOR UPDATE"),
        {"tenant": tenant},
    ).scalar_one_or_none()
    if active is not True:
        raise ProvisioningError("INVALID_TENANT")


def _actor(conn: Connection, tenant: UUID, actor: UUID) -> None:
    kind = conn.execute(
        text(
            "SELECT kind FROM execbound.principals "
            "WHERE tenant_id = :tenant AND principal_id = :principal AND active"
        ),
        {"tenant": tenant, "principal": actor},
    ).scalar_one_or_none()
    if kind != "ADMIN":
        raise ProvisioningError("INVALID_ACTOR")


def _account(conn: Connection, tenant: UUID, account: UUID) -> None:
    active = conn.execute(
        text(
            "SELECT active FROM execbound.connector_accounts "
            "WHERE tenant_id = :tenant AND account_id = :account"
        ),
        {"tenant": tenant, "account": account},
    ).scalar_one_or_none()
    if active is not True:
        raise ProvisioningError("INVALID_ACCOUNT")


def _source(conn: Connection, manifest: Manifest) -> None:
    row = (
        conn.execute(
            text(
                "SELECT kind, allowed_writers, active FROM execbound.context_sources "
                "WHERE tenant_id = :tenant AND account_id = :account AND source_id = :source"
            ),
            {
                "tenant": manifest.tenant_id,
                "account": manifest.account_id,
                "source": manifest.source_id,
            },
        )
        .mappings()
        .one_or_none()
    )
    if row is None or row["active"] is not True or row["kind"] != manifest.kind:
        raise ProvisioningError("INVALID_SOURCE")
    if manifest.writer not in tuple(row["allowed_writers"]):
        raise ProvisioningError("INVALID_WRITER")


def _resources(conn: Connection, manifest: Manifest) -> dict[tuple[str, str, str], _Resource]:
    if not manifest.entries:
        return {}
    rows = (
        conn.execute(
            text("""
        SELECT r.provider, r.resource_type, r.provider_id, r.resource_id, r.version,
               r.source_id, r.role, r.privilege_class, r.environment, r.criticality,
               r.observed_at, r.active
        FROM execbound.resources r
        JOIN unnest(CAST(:providers AS text[]), CAST(:types AS text[]), CAST(:ids AS text[]))
          AS k(provider, resource_type, provider_id)
          ON k.provider = r.provider AND k.resource_type = r.resource_type
         AND k.provider_id = r.provider_id
        WHERE r.tenant_id = :tenant AND r.account_id = :account
    """),
            {
                "tenant": manifest.tenant_id,
                "account": manifest.account_id,
                "providers": [item.provider for item in manifest.entries],
                "types": [item.resource_type for item in manifest.entries],
                "ids": [item.provider_id for item in manifest.entries],
            },
        )
        .mappings()
        .all()
    )
    return {
        (row["provider"], row["resource_type"], row["provider_id"]): _Resource(
            row["resource_id"],
            row["provider"],
            row["resource_type"],
            row["version"],
            row["source_id"],
            {name: row[name] for name in _RESOURCE_COLUMNS},
            row["observed_at"],
            row["active"],
        )
        for row in rows
    }


def _facts(
    conn: Connection, manifest: Manifest, ids: Sequence[UUID]
) -> dict[tuple[UUID, str], _Fact]:
    if not ids:
        return {}
    rows = (
        conn.execute(
            text(
                "SELECT resource_id, fact_name, value, version, source_id, observed_at "
                "FROM execbound.resource_facts WHERE tenant_id = :tenant AND account_id = :account "
                "AND resource_id = ANY(CAST(:ids AS uuid[]))"
            ),
            {"tenant": manifest.tenant_id, "account": manifest.account_id, "ids": list(ids)},
        )
        .mappings()
        .all()
    )
    return {
        (row["resource_id"], row["fact_name"]): _Fact(
            row["value"], row["version"], row["source_id"], row["observed_at"]
        )
        for row in rows
    }


def _incidents(conn: Connection, manifest: Manifest) -> dict[UUID, _Incident]:
    ids = [item.incident_id for item in manifest.entries if item.incident_id is not None]
    if not ids:
        return {}
    rows = (
        conn.execute(
            text(
                "SELECT incident_id, resource_id, provider, resource_type, version, source_id, "
                "status, severity, observed_at FROM execbound.incidents "
                "WHERE tenant_id = :tenant AND account_id = :account "
                "AND incident_id = ANY(CAST(:ids AS uuid[]))"
            ),
            {"tenant": manifest.tenant_id, "account": manifest.account_id, "ids": ids},
        )
        .mappings()
        .all()
    )
    return {
        row["incident_id"]: _Incident(
            row["resource_id"],
            row["provider"],
            row["resource_type"],
            row["version"],
            row["source_id"],
            {name: row[name] for name in _INCIDENT_COLUMNS},
            row["observed_at"],
        )
        for row in rows
    }


# Planning writes


def _same(retained: object, value: object) -> bool:
    return type(retained) is type(value) and retained == value


@dataclass
class _Writes:
    resources: list[dict[str, Any]] = field(default_factory=list)
    fact_upserts: list[dict[str, Any]] = field(default_factory=list)
    fact_deletes: list[dict[str, Any]] = field(default_factory=list)
    incident_inserts: list[dict[str, Any]] = field(default_factory=list)
    incident_updates: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(COUNT_KEYS, 0))
    outcomes: list[str] = field(default_factory=list)


def _order(retained_at: datetime, item: Entry, index: int) -> None:
    if item.observed_at < retained_at:
        raise ProvisioningError("OBSERVATION_REGRESSION", index)


def _plan_inventory(
    manifest: Manifest,
    index: int,
    item: Entry,
    plan: _Plan,
    resource: _Resource,
    facts: dict[tuple[UUID, str], _Fact],
    writes: _Writes,
) -> bool:
    key = {
        "tenant": manifest.tenant_id,
        "account": manifest.account_id,
        "provider": resource.provider,
        "resource_type": resource.resource_type,
        "resource_id": resource.resource_id,
    }
    applied = False
    if plan.columns or item.active is not None or item.provider_version is not None:
        # The resources row's version is the provider's expected version, checked atomically
        # at dispatch; a manifest changes it only by stating provider_version. Values, the
        # source and the active flag are the row's content.
        _order(resource.observed_at, item, index)
        columns = {**resource.columns, **plan.columns}
        active = resource.active if item.active is None else item.active
        version = resource.version if item.provider_version is None else item.provider_version
        changed = (
            any(not _same(resource.columns[name], value) for name, value in plan.columns.items())
            or active != resource.active
            or version != resource.version
            or resource.source_id != manifest.source_id
        )
        if changed or item.observed_at > resource.observed_at:
            writes.resources.append(
                {
                    **key,
                    **columns,
                    "version": version,
                    "source": manifest.source_id if changed else resource.source_id,
                    "observed": item.observed_at,
                    "active": active,
                }
            )
            applied = True
        if changed:
            for name, value in plan.columns.items():
                if _same(resource.columns[name], value):
                    continue
                writes.counts["facts_retracted" if value is None else "facts_written"] += 1
            if active != resource.active and not active:
                writes.counts["resources_deactivated"] += 1
    for name, value in plan.rows.items():
        retained = facts.get((resource.resource_id, name))
        if retained is None:
            changed = True
        else:
            _order(retained.observed_at, item, index)
            changed = not _same(retained.value, value) or retained.source_id != manifest.source_id
            if changed and retained.version == item.version:
                raise ProvisioningError("VERSION_REUSED", index)
        if retained is not None and not changed and item.observed_at <= retained.observed_at:
            continue
        writes.fact_upserts.append(
            {
                **key,
                "name": name,
                "value": json.dumps(value),
                "version": item.version if changed or retained is None else retained.version,
                "source": manifest.source_id if changed or retained is None else retained.source_id,
                "observed": item.observed_at,
            }
        )
        applied = True
        if changed:
            writes.counts["facts_written"] += 1
    for name in plan.row_retractions:
        retained = facts.get((resource.resource_id, name))
        if retained is None:
            continue
        _order(retained.observed_at, item, index)
        writes.fact_deletes.append({**key, "name": name})
        writes.counts["facts_retracted"] += 1
        applied = True
    return applied


def _plan_incident(
    manifest: Manifest,
    index: int,
    item: Entry,
    plan: _Plan,
    resource: _Resource,
    incidents: dict[UUID, _Incident],
    writes: _Writes,
) -> bool:
    assert item.incident_id is not None  # nosec B101 - the manifest validator guarantees it
    key = {
        "tenant": manifest.tenant_id,
        "account": manifest.account_id,
        "incident": item.incident_id,
    }
    retained = incidents.get(item.incident_id)
    if retained is None:
        writes.incident_inserts.append(
            {
                **key,
                "provider": resource.provider,
                "resource_type": resource.resource_type,
                "resource_id": resource.resource_id,
                "source": manifest.source_id,
                "version": item.version,
                "status": plan.columns.get("status"),
                "severity": plan.columns.get("severity"),
                "observed": item.observed_at,
            }
        )
        writes.counts["incidents_created"] += 1
        writes.counts["facts_written"] += len(plan.columns)
        return True
    if (retained.resource_id, retained.provider, retained.resource_type) != (
        resource.resource_id,
        resource.provider,
        resource.resource_type,
    ):
        raise ProvisioningError("INCIDENT_RELINKED", index)
    _order(retained.observed_at, item, index)
    columns = {**retained.columns, **plan.columns}
    changed = (
        any(not _same(retained.columns[name], value) for name, value in plan.columns.items())
        or retained.source_id != manifest.source_id
    )
    if changed and retained.version == item.version:
        raise ProvisioningError("VERSION_REUSED", index)
    if not changed and item.observed_at <= retained.observed_at:
        return False
    writes.incident_updates.append(
        {
            **key,
            **columns,
            "source": manifest.source_id if changed else retained.source_id,
            "version": item.version if changed else retained.version,
            "observed": item.observed_at,
        }
    )
    writes.counts["incidents_updated"] += 1
    if changed:
        writes.counts["facts_written"] += sum(
            1 for name, value in plan.columns.items() if not _same(retained.columns[name], value)
        )
    return True


def _plan_writes(
    conn: Connection, manifest: Manifest, plans: Sequence[_Plan], *, strict: bool
) -> _Writes:
    resources = _resources(conn, manifest)
    known = sorted({resource.resource_id for resource in resources.values()})
    facts = _facts(conn, manifest, known) if manifest.kind == "inventory" else {}
    incidents = _incidents(conn, manifest) if manifest.kind == "incident" else {}
    writes = _Writes()
    writes.counts["entries"] = len(manifest.entries)
    for index, (item, plan) in enumerate(zip(manifest.entries, plans, strict=True)):
        resource = resources.get((item.provider, item.resource_type, item.provider_id))
        if resource is None:
            if strict:
                raise ProvisioningError("UNKNOWN_RESOURCE", index)
            writes.counts["unknown_resources"] += 1
            writes.outcomes.append("unknown_resource")
            continue
        if manifest.kind == "inventory":
            applied = _plan_inventory(manifest, index, item, plan, resource, facts, writes)
        else:
            applied = _plan_incident(manifest, index, item, plan, resource, incidents, writes)
        writes.counts["applied" if applied else "unchanged"] += 1
        writes.outcomes.append("applied" if applied else "unchanged")
    return writes


_RESOURCE_UPDATE = text(
    "UPDATE execbound.resources SET version = :version, source_id = :source, role = :role, "
    "privilege_class = :privilege_class, environment = :environment, "
    "criticality = :criticality, observed_at = :observed, active = :active, demo_fixture = false "
    "WHERE tenant_id = :tenant AND account_id = :account AND provider = :provider "
    "AND resource_type = :resource_type AND resource_id = :resource_id"
)
_FACT_UPSERT = text(
    "INSERT INTO execbound.resource_facts (tenant_id, account_id, provider, resource_type, "
    "resource_id, fact_name, value, source_id, version, observed_at) "
    "VALUES (:tenant, :account, :provider, :resource_type, :resource_id, :name, "
    "CAST(:value AS jsonb), :source, :version, :observed) "
    "ON CONFLICT (tenant_id, account_id, provider, resource_type, resource_id, fact_name) "
    "DO UPDATE SET value = EXCLUDED.value, source_id = EXCLUDED.source_id, "
    "version = EXCLUDED.version, observed_at = EXCLUDED.observed_at, demo_fixture = false"
)
_FACT_DELETE = text(
    "DELETE FROM execbound.resource_facts WHERE tenant_id = :tenant AND account_id = :account "
    "AND provider = :provider AND resource_type = :resource_type "
    "AND resource_id = :resource_id AND fact_name = :name"
)
_INCIDENT_INSERT = text(
    "INSERT INTO execbound.incidents (tenant_id, account_id, provider, resource_type, "
    "incident_id, resource_id, source_id, version, status, severity, observed_at) "
    "VALUES (:tenant, :account, :provider, :resource_type, :incident, :resource_id, :source, "
    ":version, :status, :severity, :observed)"
)
_INCIDENT_UPDATE = text(
    "UPDATE execbound.incidents SET source_id = :source, version = :version, status = :status, "
    "severity = :severity, observed_at = :observed, demo_fixture = false "
    "WHERE tenant_id = :tenant AND account_id = :account AND incident_id = :incident"
)


def _apply(conn: Connection, writes: _Writes) -> None:
    for statement, rows in (
        (_RESOURCE_UPDATE, writes.resources),
        (_FACT_UPSERT, writes.fact_upserts),
        (_FACT_DELETE, writes.fact_deletes),
        (_INCIDENT_INSERT, writes.incident_inserts),
        (_INCIDENT_UPDATE, writes.incident_updates),
    ):
        if rows:
            conn.execute(statement, rows)


def _retire_fixture_provenance(conn: Connection, manifest: Manifest) -> None:
    """A successful ordinary import owns its observations, even when their values repeat.

    The tenant lock shared with refresh prevents a refresh reading the old marker while
    an import commits new facts. For inventory, retiring the parent also excludes all its
    children from refresh. No caller-supplied field can grant synthetic provenance.
    """
    if manifest.kind == "inventory":
        conn.execute(
            text("""UPDATE execbound.resources r SET demo_fixture=false
            FROM unnest(CAST(:providers AS text[]), CAST(:types AS text[]), CAST(:ids AS text[]))
              AS k(provider, resource_type, provider_id)
            WHERE r.tenant_id=:t AND r.account_id=:a AND r.demo_fixture
              AND r.provider=k.provider AND r.resource_type=k.resource_type
              AND r.provider_id=k.provider_id"""),
            {
                "t": manifest.tenant_id,
                "a": manifest.account_id,
                "providers": [item.provider for item in manifest.entries],
                "types": [item.resource_type for item in manifest.entries],
                "ids": [item.provider_id for item in manifest.entries],
            },
        )
    else:
        conn.execute(
            text("""UPDATE execbound.incidents SET demo_fixture=false
            WHERE tenant_id=:t AND account_id=:a AND demo_fixture
              AND incident_id=ANY(CAST(:ids AS uuid[]))"""),
            {
                "t": manifest.tenant_id,
                "a": manifest.account_id,
                "ids": [item.incident_id for item in manifest.entries],
            },
        )


def import_manifest(
    engine: Engine,
    tenant: UUID,
    parsed: ParsedManifest,
    actor: UUID,
    *,
    strict: bool = False,
    now: datetime | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> ImportResult:
    """Apply one manifest atomically under an ADMIN actor; refusal writes and audits nothing."""
    manifest = parsed.manifest
    if manifest.tenant_id != tenant:
        raise ProvisioningError("TENANT_MISMATCH")
    plans = _plan(manifest, catalog, _instant(now))
    with _transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        _account(conn, tenant, manifest.account_id)
        _source(conn, manifest)
        writes = _plan_writes(conn, manifest, plans, strict=strict)
        _retire_fixture_provenance(conn, manifest)
        _apply(conn, writes)
        append_event(
            conn,
            tenant,
            actor,
            "context.imported",
            {
                "source_id": str(manifest.source_id),
                "account_id": str(manifest.account_id),
                "kind": manifest.kind,
                "writer": manifest.writer,
                "manifest_digest": parsed.digest,
                "manifest_bytes": parsed.size,
                **writes.counts,
            },
        )
    return ImportResult(parsed.digest, dict(writes.counts), tuple(writes.outcomes))


# Context sources


def create_context_source(
    engine: Engine,
    tenant: UUID,
    account: UUID,
    kind: str,
    writers: Sequence[str],
    actor: UUID,
) -> UUID:
    """Create an active source whose writer labels are fixed for its life; audited."""
    if kind not in SOURCE_KINDS:
        raise ProvisioningError("INVALID_KIND")
    labels = tuple(writers)
    if (
        not 1 <= len(labels) <= MAX_WRITERS
        or any(type(label) is not str or not _WRITER.fullmatch(label) for label in labels)
        or len(set(labels)) != len(labels)
    ):
        raise ProvisioningError("INVALID_WRITER")
    if secret_shaped(*labels):
        raise ProvisioningError("INVALID_WRITER")
    source = uuid4()
    with _transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        _account(conn, tenant, account)
        conn.execute(
            text(
                "INSERT INTO execbound.context_sources "
                "(tenant_id, account_id, source_id, kind, allowed_writers) "
                "VALUES (:tenant, :account, :source, :kind, CAST(:writers AS text[]))"
            ),
            {
                "tenant": tenant,
                "account": account,
                "source": source,
                "kind": kind,
                "writers": sorted(labels),
            },
        )
        append_event(
            conn,
            tenant,
            actor,
            "context_source.created",
            {
                "source_id": str(source),
                "account_id": str(account),
                "kind": kind,
                "allowed_writers": sorted(labels),
            },
        )
    return source


def deactivate_context_source(engine: Engine, tenant: UUID, source: UUID, actor: UUID) -> None:
    """Deactivate a source; every fact it attests then fails resolution. Audited."""
    with _transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        updated = conn.execute(
            text(
                "UPDATE execbound.context_sources SET active = false "
                "WHERE tenant_id = :tenant AND source_id = :source AND active"
            ),
            {"tenant": tenant, "source": source},
        ).rowcount
        if updated != 1:
            raise ProvisioningError("INVALID_SOURCE")
        append_event(conn, tenant, actor, "context_source.deactivated", {"source_id": str(source)})


# Security signal sources (#478)

# The capability vocabulary is kept in one place, `signals.capabilities`.
SIGNAL_CAPABILITIES = frozenset(CAPABILITIES)
SIGNAL_INPUT_PATHS = frozenset({"independent", "agent_forwarded"})
_SIGNAL_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:-]{0,95}")
_PRODUCER = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_PRODUCER_VERSION = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")
MIN_SIGNAL_LIFETIME = timedelta(hours=1)
MAX_SIGNAL_LIFETIME = timedelta(hours=720)
MAX_SIGNAL_GRACE_SECONDS = 3600
MAX_SIGNAL_PRINCIPALS = 64


@dataclass(frozen=True)
class SignalSourceGrant:
    source_id: UUID
    expires_at: datetime
    output: Path


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _reserve_output(output: Path) -> int:
    try:
        return os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        raise ProvisioningError("OUTPUT_UNAVAILABLE") from None


def _write_once(descriptor: int, token: str) -> None:
    pending = (token + "\n").encode("ascii")
    while pending:
        pending = pending[os.write(descriptor, pending) :]
    os.fsync(descriptor)


def _signal_space(conn: Connection, tenant: UUID, space: UUID | None) -> UUID:
    """The named space of this tenant, or its only one when none was named."""
    rows = (
        conn.execute(
            text(
                "SELECT space_id FROM execbound.spaces WHERE tenant_id = :t "
                "AND (CAST(:s AS uuid) IS NULL OR space_id = :s) ORDER BY created_at, space_id"
            ),
            {"t": tenant, "s": space},
        )
        .scalars()
        .all()
    )
    if len(rows) != 1:
        raise ProvisioningError("INVALID_SPACE")
    return UUID(str(rows[0]))


def _signal_principals(
    conn: Connection, tenant: UUID, principals: tuple[UUID, ...], group: UUID | None
) -> tuple[list[str] | None, UUID | None]:
    if group is not None:
        known = conn.execute(
            text("SELECT 1 FROM execbound.principal_groups WHERE tenant_id = :t AND group_id = :g"),
            {"t": tenant, "g": group},
        ).scalar_one_or_none()
        if known is None:
            raise ProvisioningError("INVALID_GROUP")
        return None, group
    agents = conn.execute(
        text(
            "SELECT count(*) FROM execbound.principals WHERE tenant_id = :t "
            "AND principal_id = ANY(CAST(:p AS uuid[])) AND kind = 'AGENT' AND active"
        ),
        {"t": tenant, "p": [str(item) for item in principals]},
    ).scalar_one()
    if agents != len(principals):
        raise ProvisioningError("INVALID_PRINCIPAL")
    return sorted(str(item) for item in principals), None


def create_signal_source(
    engine: Engine,
    tenant: UUID,
    actor: UUID,
    *,
    label: str,
    producer: str,
    version_min: str,
    version_max: str,
    capabilities: Sequence[str],
    principals: Sequence[UUID] = (),
    group: UUID | None = None,
    space: UUID | None = None,
    offered: bool = False,
    input_path: str = "independent",
    attests_liveness: bool = False,
    lifetime: timedelta,
    output: Path,
    now: datetime | None = None,
) -> SignalSourceGrant:
    """Register a producer and write its token once to a new private file.

    Authority data, so an owner command audited under `actor`, as `create_context_source` is.
    The output file is created exclusively with owner-only permissions before the row
    commits and removed on any failure, as `administration.issue_credential` does, so a token
    never outlives a source that was not created. The audit event names the scope and never
    the token or its digest.
    """
    if type(tenant) is not UUID:
        raise ProvisioningError("INVALID_INPUT")
    wanted = tuple(capabilities)
    scope = tuple(principals)
    if type(label) is not str or not _SIGNAL_LABEL.fullmatch(label):
        raise ProvisioningError("INVALID_LABEL")
    if type(producer) is not str or not _PRODUCER.fullmatch(producer):
        raise ProvisioningError("INVALID_PRODUCER")
    if secret_shaped(label):
        raise ProvisioningError("INVALID_LABEL")
    if secret_shaped(producer):
        raise ProvisioningError("INVALID_PRODUCER")
    if any(
        type(value) is not str or not _PRODUCER_VERSION.fullmatch(value)
        for value in (version_min, version_max)
    ) or _version_key(version_min) > _version_key(version_max):
        raise ProvisioningError("INVALID_VERSION")
    if not wanted or len(set(wanted)) != len(wanted) or not set(wanted) <= SIGNAL_CAPABILITIES:
        raise ProvisioningError("INVALID_CAPABILITY")
    if input_path not in SIGNAL_INPUT_PATHS:
        raise ProvisioningError("INVALID_INPUT_PATH")
    if type(offered) is not bool or type(attests_liveness) is not bool:
        raise ProvisioningError("INVALID_INPUT")
    if (
        (not scope) == (group is None)
        or len(set(scope)) != len(scope)
        or len(scope) > MAX_SIGNAL_PRINCIPALS
    ):
        raise ProvisioningError("INVALID_SCOPE")
    if not MIN_SIGNAL_LIFETIME <= lifetime <= MAX_SIGNAL_LIFETIME:
        raise ProvisioningError("INVALID_LIFETIME")
    created_at = _instant(now)
    expires_at = created_at + lifetime
    source = uuid4()
    token, token_digest = new_signal_token(tenant, source)
    subjects = sorted({signal_capability(name).subject for name in wanted})
    descriptor = _reserve_output(output)
    closed = False
    try:
        with _transaction(engine, tenant) as conn:
            _tenant(conn, tenant)
            _actor(conn, tenant, actor)
            placed = _signal_space(conn, tenant, space)
            principal_ids, group_id = _signal_principals(conn, tenant, scope, group)
            conn.execute(
                text(
                    "INSERT INTO execbound.signal_sources (tenant_id, source_id, space_id, "
                    "offered_tenant_wide, label, producer_name, producer_version_min, "
                    "producer_version_max, capabilities, subject_kinds, principal_ids, "
                    "principal_group_id, placement, input_path, attests_liveness, token_hash, "
                    "created_at, created_by, expires_at, rate_window_at) VALUES (:t, :s, :space, "
                    ":offered, :label, :producer, :vmin, :vmax, CAST(:caps AS text[]), "
                    "CAST(:subjects AS text[]), CAST(:principals AS uuid[]), :group, "
                    "'out_of_process', :path, :liveness, :digest, :now, :actor, :expires, :now)"
                ),
                {
                    "t": tenant,
                    "s": source,
                    "space": placed,
                    "offered": offered,
                    "label": label,
                    "producer": producer,
                    "vmin": version_min,
                    "vmax": version_max,
                    "caps": sorted(wanted),
                    "subjects": subjects,
                    "principals": principal_ids,
                    "group": group_id,
                    "path": input_path,
                    "liveness": attests_liveness,
                    "digest": token_digest,
                    "now": created_at,
                    "actor": actor,
                    "expires": expires_at,
                },
            )
            append_event(
                conn,
                tenant,
                actor,
                "signal_source.created",
                {
                    "source_id": str(source),
                    "space_id": str(placed),
                    "offered_tenant_wide": offered,
                    "label": label,
                    "producer_name": producer,
                    "producer_version_min": version_min,
                    "producer_version_max": version_max,
                    "capabilities": sorted(wanted),
                    "subject_kinds": subjects,
                    "principal_ids": principal_ids,
                    "principal_group_id": str(group_id) if group_id is not None else None,
                    "placement": "out_of_process",
                    "input_path": input_path,
                    "attests_liveness": attests_liveness,
                    "expires_at": expires_at.isoformat(),
                },
                space=placed,
            )
            _write_once(descriptor, token)
            os.close(descriptor)
            closed = True
    except BaseException:
        if not closed:
            os.close(descriptor)
        output.unlink(missing_ok=True)
        raise
    return SignalSourceGrant(source, expires_at, output)


def rotate_signal_source(
    engine: Engine,
    tenant: UUID,
    source: UUID,
    actor: UUID,
    *,
    lifetime: timedelta,
    grace_seconds: int = 600,
    output: Path,
    now: datetime | None = None,
) -> SignalSourceGrant:
    """Replace the token; the previous one keeps working for the grace window.

    The source row is locked before it is read, as `signal_admit` locks it before it admits,
    so a rotation and an admission serialize: an admission either finishes under the old
    token or starts after the new one is committed.
    """
    # The token spells out both ids, so only a UUID object's canonical text will do: a string
    # the database would still match, in capitals say, would mint a token no parser accepts.
    if type(tenant) is not UUID or type(source) is not UUID:
        raise ProvisioningError("INVALID_INPUT")
    if type(grace_seconds) is not int or not 0 <= grace_seconds <= MAX_SIGNAL_GRACE_SECONDS:
        raise ProvisioningError("INVALID_GRACE")
    if not MIN_SIGNAL_LIFETIME <= lifetime <= MAX_SIGNAL_LIFETIME:
        raise ProvisioningError("INVALID_LIFETIME")
    at = _instant(now)
    expires_at = at + lifetime
    token, token_digest = new_signal_token(tenant, source)
    descriptor = _reserve_output(output)
    closed = False
    try:
        with _transaction(engine, tenant) as conn:
            _tenant(conn, tenant)
            _actor(conn, tenant, actor)
            row = (
                conn.execute(
                    text(
                        "SELECT space_id, token_hash, expires_at, active, revoked_at "
                        "FROM execbound.signal_sources "
                        "WHERE tenant_id = :t AND source_id = :s FOR UPDATE"
                    ),
                    {"t": tenant, "s": source},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise ProvisioningError("INVALID_SOURCE")
            if not row["active"] or row["revoked_at"] is not None:
                raise ProvisioningError("INVALID_STATE")
            previous, until = None, None
            if grace_seconds > 0 and at < row["expires_at"]:
                previous = row["token_hash"]
                until = min(at + timedelta(seconds=grace_seconds), row["expires_at"])
            conn.execute(
                text(
                    "UPDATE execbound.signal_sources SET token_hash = :h, "
                    "previous_token_hash = :p, previous_valid_until = :u, expires_at = :e, "
                    "rotated_at = :n, rotated_by = :a WHERE tenant_id = :t AND source_id = :s"
                ),
                {
                    "h": token_digest,
                    "p": previous,
                    "u": until,
                    "e": expires_at,
                    "n": at,
                    "a": actor,
                    "t": tenant,
                    "s": source,
                },
            )
            append_event(
                conn,
                tenant,
                actor,
                "signal_source.rotated",
                {
                    "source_id": str(source),
                    "expires_at": expires_at.isoformat(),
                    "grace_seconds": grace_seconds,
                },
                space=row["space_id"],
            )
            _write_once(descriptor, token)
            os.close(descriptor)
            closed = True
    except BaseException:
        if not closed:
            os.close(descriptor)
        output.unlink(missing_ok=True)
        raise
    return SignalSourceGrant(source, expires_at, output)


def revoke_signal_source(
    engine: Engine, tenant: UUID, source: UUID, actor: UUID, now: datetime | None = None
) -> None:
    """Immediate and final: every token stops, and every fact it attested fails.

    Locked before it is read, as rotation is, so a revocation waits for an admission in
    flight, and every admission after it is refused.
    """
    if type(tenant) is not UUID or type(source) is not UUID:
        raise ProvisioningError("INVALID_INPUT")
    at = _instant(now)
    with _transaction(engine, tenant) as conn:
        _tenant(conn, tenant)
        _actor(conn, tenant, actor)
        row = (
            conn.execute(
                text(
                    "SELECT space_id, revoked_at FROM execbound.signal_sources "
                    "WHERE tenant_id = :t AND source_id = :s FOR UPDATE"
                ),
                {"t": tenant, "s": source},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise ProvisioningError("INVALID_SOURCE")
        if row["revoked_at"] is not None:
            raise ProvisioningError("INVALID_STATE")
        conn.execute(
            text(
                "UPDATE execbound.signal_sources SET active = false, revoked_at = :n, "
                "revoked_by = :a, previous_token_hash = NULL, previous_valid_until = NULL "
                "WHERE tenant_id = :t AND source_id = :s"
            ),
            {"n": at, "a": actor, "t": tenant, "s": source},
        )
        append_event(
            conn,
            tenant,
            actor,
            "signal_source.revoked",
            {"source_id": str(source)},
            space=row["space_id"],
        )


def list_signal_sources(engine: Engine, tenant: UUID) -> list[dict[str, Any]]:
    """Registration and health, never a digest; health is shown, never an input to a decision."""
    with _transaction(engine, tenant) as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT source_id, space_id, offered_tenant_wide, label, producer_name, "
                    "producer_version_min, producer_version_max, capabilities, subject_kinds, "
                    "principal_ids, principal_group_id, placement, input_path, "
                    "attests_liveness, registration_version, created_at, expires_at, "
                    "rotated_at, previous_valid_until, active, revoked_at, record_count, "
                    "last_accepted_at, last_refused_at, last_refusal_code, conflict_count, "
                    "rate_refusal_count "
                    "FROM execbound.signal_sources WHERE tenant_id = :t "
                    "ORDER BY created_at, source_id"
                ),
                {"t": tenant},
            )
            .mappings()
            .all()
        )
    return [json.loads(json.dumps(dict(row), default=str)) for row in rows]
