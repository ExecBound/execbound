# SPDX-License-Identifier: AGPL-3.0-only
"""Build trusted facts under one context contract; this module never authorizes."""

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from execbound.contracts import (
    Column,
    ContextContract,
    ContractError,
    SourceSetting,
    effective_source,
    value_matches,
)
from execbound.resolution.models import TrustedFact
from execbound.resolution.registry import ResolutionError

if TYPE_CHECKING:
    # Types only; `resolve_facts` imports what it runs from signals.resolve itself (see there).
    from execbound.signals.resolve import SignalScope


def resolve_facts(
    contract: ContextContract,
    settings: Sequence[SourceSetting] | None,
    *,
    resource: Mapping[str, Any],
    fact_rows: Sequence[Mapping[str, Any]],
    incident: Mapping[str, Any] | None,
    now: datetime,
    signal_rows: Sequence[Mapping[str, Any]] = (),
    signal_scope: "SignalScope | None" = None,
) -> tuple[TrustedFact, ...]:
    """Rows carry their source's kind, allowed_writers and source_active columns.

    A signal fact is built from `signal_rows` under `signal_scope`'s mapping; a caller that
    passes neither, such as `resolution.resolve_request`, resolves it to `INVALID_CONTEXT`.
    """
    rows: dict[str, Mapping[str, Any]] = {}
    for row in fact_rows:
        if row["fact_name"] in rows:
            raise ResolutionError()
        rows[row["fact_name"]] = row
    if (incident is None) != (contract.incident == "none"):
        raise ResolutionError()
    resolved: dict[str, TrustedFact] = {}
    try:
        for spec in contract.facts:
            if spec.derivation is not None:
                dependency = resolved[spec.derivation.dependency]
                resolved[spec.name] = TrustedFact(
                    name=spec.name,
                    value=dependency.value == spec.derivation.value,
                    origin="DERIVED",
                    source_id=dependency.source_id,
                    source_kind=dependency.source_kind,
                    source_object_id=dependency.source_object_id,
                    source_version=dependency.source_version,
                    permitted_writers=dependency.permitted_writers,
                    observed_at=dependency.observed_at,
                    valid_until=dependency.valid_until,
                    dependencies=(spec.derivation.dependency,),
                )
                continue
            if spec.source_kind == "signal":
                # Imported here, not at module level: the signals modules import
                # execbound.resolution.models, which runs this package's __init__, which
                # imports this module. A module-level import back into signals.resolve would
                # then find signals.models, signals.mapping or signals.resolve half-initialized
                # whenever one of them is the first execbound module imported.
                from execbound.signals.resolve import signal_fact

                resolved[spec.name] = signal_fact(
                    spec,
                    contract,
                    settings,
                    signal_scope,
                    signal_rows,
                    provider_id=resource["provider_id"],
                    now=now,
                )
                continue
            if spec.source_kind == "incident":
                if incident is None or not isinstance(spec.storage, Column):
                    raise ResolutionError()
                source, value = incident, incident[spec.storage.column]
                object_id, version = str(incident["incident_id"]), incident["version"]
            elif isinstance(spec.storage, Column):
                source, value = resource, resource[spec.storage.column]
                object_id, version = resource["provider_id"], resource["version"]
            else:
                source = rows[spec.name]
                value, object_id, version = (
                    source["value"],
                    resource["provider_id"],
                    source["version"],
                )
            defaults = effective_source(contract, settings, spec.source_kind)
            writers = source["allowed_writers"]
            observed = source["observed_at"].astimezone(UTC)
            valid_until = observed + timedelta(seconds=defaults.max_age_seconds)
            if (
                not source["source_active"]
                or source["source_kind"] != spec.source_kind
                or not writers
                or not set(writers) <= set(defaults.permitted_writers)
                or observed > now
                or valid_until <= now
                or value is None
                or not value_matches(spec, value)
            ):
                raise ResolutionError()
            resolved[spec.name] = TrustedFact(
                name=spec.name,
                value=value,
                origin="RESOLVED",
                source_id=source["source_id"],
                source_kind=spec.source_kind,
                source_object_id=object_id,
                source_version=version,
                permitted_writers=tuple(sorted(set(writers))),
                observed_at=observed,
                valid_until=valid_until,
            )
    except (KeyError, ContractError):
        raise ResolutionError() from None
    return tuple(resolved.values())
