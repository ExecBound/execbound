# SPDX-License-Identifier: AGPL-3.0-only
"""One non-locking statement supplies coherent evidence after coordinator lock waits."""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import Connection, RowMapping

from execbound.contracts import PRODUCTION_CATALOG, Catalog, SourceSetting
from execbound.identity import Identity
from execbound.requests import ActionRequest
from execbound.resolution import _now, registry
from execbound.resolution.facts import resolve_facts
from execbound.resolution.models import CanonicalIntent, Clock, ResolvedRequest, binding_hash
from execbound.resolution.registry import ResolutionError, mapping_context
from execbound.signals.resolve import SignalScope, reader_arguments
from execbound.spaces import SpaceFilter, Visibility, space_clause

# The coherent statement `resolve_snapshot` runs; `_statement` puts the signal reader below
# in place of its `/*signals*/` marker.
_COHERENT = """
        WITH named AS (
          SELECT m.tenant_id, m.account_id, m.provider, m.resource_type
          FROM execbound.operation_mappings m
          JOIN execbound.connector_accounts ca USING (tenant_id, account_id, provider)
          WHERE m.tenant_id=:tenant AND m.operation_ref=:operation AND m.active AND ca.active
        ), probe AS (
          SELECT
            CASE WHEN :kind='canonical' THEN EXISTS (
              SELECT 1 FROM named n JOIN execbound.resources pr
                ON pr.tenant_id=n.tenant_id AND pr.account_id=n.account_id
                AND pr.provider=n.provider AND pr.resource_type=n.resource_type
              WHERE pr.resource_id=CAST(:target AS uuid) AND pr.active
            ) ELSE (
              SELECT count(*)=1 AND COALESCE(bool_and(pr.active), false)
              FROM named n JOIN execbound.resource_aliases pa
                ON pa.tenant_id=n.tenant_id AND pa.account_id=n.account_id
                AND pa.provider=n.provider AND pa.resource_type=n.resource_type
                AND pa.kind=:kind AND pa.normalized_value=:value
                AND pa.valid_from<=:now AND pa.expires_at>:now
              LEFT JOIN execbound.resources pr
                ON pr.tenant_id=pa.tenant_id AND pr.account_id=pa.account_id
                AND pr.provider=pa.provider AND pr.resource_type=pa.resource_type
                AND pr.resource_id=pa.resource_id
            ) END AS target_resolves,
            (CAST(:run AS uuid) IS NULL OR EXISTS (
              SELECT 1 FROM execbound.agent_runs pg
              WHERE pg.tenant_id=:tenant AND pg.principal_id=:principal AND pg.run_id=:run
                AND pg.issued_at<=:now AND pg.expires_at>:now
            )) AS run_live
        )
        SELECT probe.target_resolves, probe.run_live, coherent.*
        FROM probe LEFT JOIN (
        SELECT to_jsonb(m) AS mapping, to_jsonb(r) AS resource,
               to_jsonb(i) AS incident, to_jsonb(s) AS inventory_source,
               to_jsonb(z) AS incident_source, a.alias_id, a.expires_at AS alias_expiry,
               g.expires_at AS run_expiry, b.canonical_target_id,
               COALESCE((
                 SELECT jsonb_agg(jsonb_build_object('fact', to_jsonb(f), 'source', to_jsonb(fs))
                                  ORDER BY f.fact_name)
                 FROM execbound.resource_facts f
                 JOIN execbound.context_sources fs
                   ON fs.tenant_id=f.tenant_id AND fs.account_id=f.account_id
                   AND fs.source_id=f.source_id
                 WHERE f.tenant_id=r.tenant_id AND f.account_id=r.account_id
                   AND f.provider=r.provider AND f.resource_type=r.resource_type
                   AND f.resource_id=r.resource_id
               ), '[]'::jsonb) AS facts,
               /*signals*/ AS signals
        FROM execbound.operation_mappings m
        JOIN execbound.connector_accounts ca USING (tenant_id, account_id, provider)
        LEFT JOIN LATERAL (
          SELECT aliases.*, count(*) OVER () AS candidate_count
          FROM execbound.resource_aliases aliases
          WHERE aliases.tenant_id=m.tenant_id AND aliases.account_id=m.account_id
            AND aliases.provider=m.provider AND aliases.resource_type=m.resource_type
            AND aliases.kind=:kind AND aliases.normalized_value=:value
            AND aliases.valid_from<=:now AND aliases.expires_at>:now
        ) a ON :kind<>'canonical'
        JOIN execbound.resources r
          ON r.tenant_id=m.tenant_id AND r.account_id=m.account_id AND r.provider=m.provider
          AND r.resource_type=m.resource_type
          AND r.resource_id=CASE WHEN :kind='canonical' THEN CAST(:target AS uuid)
                                 ELSE a.resource_id END
        JOIN execbound.resource_identities b
          ON b.tenant_id=r.tenant_id AND b.account_id=r.account_id AND b.provider=r.provider
          AND b.resource_type=r.resource_type AND b.resource_id=r.resource_id
        JOIN execbound.context_sources s
          ON s.tenant_id=r.tenant_id AND s.account_id=r.account_id AND s.source_id=r.source_id
        LEFT JOIN execbound.incidents i
          ON i.tenant_id=r.tenant_id AND i.account_id=r.account_id AND i.provider=r.provider
          AND i.resource_type=r.resource_type AND i.resource_id=r.resource_id
          AND i.incident_id=:incident
        LEFT JOIN execbound.context_sources z
          ON z.tenant_id=i.tenant_id AND z.account_id=i.account_id AND z.source_id=i.source_id
        LEFT JOIN execbound.agent_runs g
          ON g.tenant_id=m.tenant_id AND g.principal_id=:principal AND g.run_id=:run
          AND g.issued_at<=:now AND g.expires_at>:now
        WHERE m.tenant_id=:tenant AND m.operation_ref=:operation AND m.active AND ca.active
          AND r.active AND (CAST(:run AS uuid) IS NULL OR g.run_id IS NOT NULL)
          AND (:kind='canonical' OR a.candidate_count=1)
        LIMIT 2
        ) coherent ON true
    """

# The newest record per admitted source for this resource, read in the same statement as the
# resource it is about. Applicability is in the WHERE clause: the source is the agent's space's
# or offered (`/*space*/`, the predicate `space_clause` builds), the agent is in its principal
# scope, and the bundle admits it (`:signal_sources`). A foreign row is never read.
# Nor is a request-scoped one: a request's `reference` is the agent's own string, so matching
# on it would let any agent in the source's scope choose the record meant for another request.
# The intake refuses one; a request-scoped capability must bind it to something the agent does
# not choose. The principal scope is also returned as `in_scope`, one predicate in both places,
# so `signal_fact` re-checks it on the row as it re-checks the space and the host.
# The read goes back no further than the contract's signal ceiling (`:signal_ceiling`), beyond
# which no setting lets a record apply. Nothing bounds the newest from above: a record observed
# after the decision is still the source's newest word, and `signal_fact` refuses it rather than
# fall back to the one it replaced.
_IN_SCOPE = """(:principal = ANY(ss.principal_ids) OR EXISTS (
                       SELECT 1 FROM execbound.principal_group_members gm
                       WHERE gm.tenant_id = ss.tenant_id AND gm.group_id = ss.principal_group_id
                         AND gm.principal_id = :principal))"""
_SIGNALS = """
               COALESCE((
                 SELECT jsonb_agg(to_jsonb(latest) - 'recency' ORDER BY latest.source_id)
                 FROM (
                   SELECT g.source_id, g.source_event_id, g.record_digest,
                          g.registration_version, g.producer_name, g.producer_version,
                          g.capability, g.verdict, g.confidence, g.observed_at,
                          g.received_at, g.expires_at,
                          ss.active AS source_active, ss.revoked_at AS source_revoked_at,
                          ss.input_path, ss.attests_liveness, ss.space_id,
                          ss.offered_tenant_wide, g.subject_provider_id,
                          /*in_scope*/ AS in_scope,
                          row_number() OVER (
                            PARTITION BY g.source_id, g.capability
                            ORDER BY g.observed_at DESC, g.received_at DESC,
                                     g.source_event_id COLLATE "C" DESC
                          ) AS recency
                   FROM execbound.security_signals g
                   JOIN execbound.signal_sources ss
                     ON ss.tenant_id = g.tenant_id AND ss.source_id = g.source_id
                   WHERE g.tenant_id = r.tenant_id AND g.subject_kind = 'resource'
                     AND g.subject_account_id = r.account_id
                     AND g.subject_provider = r.provider
                     AND g.subject_resource_type = r.resource_type
                     AND g.subject_provider_id = r.provider_id
                     AND g.capability = ANY(CAST(:signal_capabilities AS text[]))
                     AND g.source_id = ANY(CAST(:signal_sources AS uuid[]))
                     AND (g.action IS NULL OR g.action = m.action)
                     AND g.request_reference IS NULL
                     AND g.observed_at > :now - CAST(:signal_ceiling AS integer)
                                                  * interval '1 second'
                     AND /*in_scope*/
                     /*space*/
                 ) latest
                 WHERE latest.recency = 1
               ), '[]'::jsonb)"""


def _space(scope: SignalScope | None) -> SpaceFilter:
    """The agent's one space as a filter; the nil UUID matches no space when none applies."""
    space = scope.space if scope is not None else UUID(int=0)
    return space_clause(
        Visibility(everything=False, spaces=(space,), current=space, roles={}), "ss", offered=True
    )


def _statement(space: SpaceFilter) -> str:
    # Every substitution is fixed text: `_SIGNALS` and `_IN_SCOPE` are literals and `space.sql`
    # is the predicate `space_clause` builds; every value is a bound parameter.
    signals = _SIGNALS.replace("/*in_scope*/", _IN_SCOPE).replace("/*space*/", space.sql)
    return _COHERENT.replace("/*signals*/", signals)


def _fact_row(raw: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    row = {
        **raw,
        "source_kind": source["kind"],
        "source_active": source["active"],
        "allowed_writers": source["allowed_writers"],
    }
    row["source_id"] = UUID(row["source_id"])
    row["observed_at"] = datetime.fromisoformat(row["observed_at"])
    return row


def _unresolved(probe: RowMapping, request: ActionRequest, mapping: dict[str, Any]) -> str:
    """Why the coherent statement found no single row: the target, the run, or the rest.

    Only so the audit can record the cause (#545): the caller is answered the same 503
    whatever this returns, and nothing here decides anything. It reads two columns the
    coherent statement computed in the same round trip, so every refusal costs the same
    statements whatever its cause and adds no timing signal. The target is resolved the way
    `registry.resource` resolves it, with the same alias window, the same single-candidate
    rule and the same active resource, so an unknown or ambiguous target, or a hostname for
    an identity action, is `INVALID_TARGET`; a run that is not live is `INVALID_RUN`; and
    anything else, such as a missing source or identity row, stays `INVALID_CONTEXT`.
    """
    if not probe["target_resolves"]:
        return "INVALID_TARGET"
    if mapping["resource_type"] == "identity" and request.target.kind == "hostname":
        return "INVALID_TARGET"
    if not probe["run_live"]:
        return "INVALID_RUN"
    return "INVALID_CONTEXT"


def resolve_snapshot(
    conn: Connection,
    identity: Identity,
    request: ActionRequest,
    clock: Clock,
    *,
    settings: Sequence[SourceSetting] | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
    # Required, so a caller that forgets the bundle's mappings and the agent's space is a type
    # error; `None` is for a caller that has neither, and resolves no signal fact.
    signals: SignalScope | None,
) -> tuple[ResolvedRequest, UUID]:
    now = _now(clock)
    # Read the mapping on its own first. An unknown operation or an argument outside the
    # action spec must fail before the coherent statement below reads any resource, alias,
    # incident or fact row, so an invalid argument is rejected identically whatever the
    # caller named as its target.
    named = registry.mapping(conn, identity.tenant_id, request.operation_ref, catalog=catalog)
    _, named_contract = mapping_context(named, catalog=catalog, arguments=request.arguments)
    capabilities, sources, ceiling = reader_arguments(named_contract, signals)
    space = _space(signals)
    # The coherent statement, joined onto one row that says whether the target resolves and
    # whether the run is live. The probe is always there, so the answer is at least one row
    # and a refusal's cause is read from it rather than from a second statement: every
    # refusal from here costs the same round trips, whatever the cause (#545). The evidence
    # columns are the statement's own, unchanged, and the probe decides nothing.
    found = (
        conn.execute(
            text(_statement(space)),
            {
                "tenant": identity.tenant_id,
                "principal": identity.principal_id,
                "operation": request.operation_ref,
                "kind": request.target.kind,
                "value": request.target.value,
                "target": request.target.value if request.target.kind == "canonical" else None,
                "incident": request.claimed_context.incident_id,
                "run": request.run_id,
                "now": now,
                "signal_capabilities": capabilities,
                "signal_sources": sources,
                "signal_ceiling": ceiling,
                **space.params,
            },
        )
        .mappings()
        .all()
    )
    rows = [row for row in found if row["mapping"] is not None]
    if len(rows) != 1:
        raise ResolutionError(_unresolved(found[0], request, named))
    row = rows[0]
    mapping, resource = row["mapping"], row["resource"]
    # The frozen plan takes its mapping fields from the coherent statement's own row.
    spec, contract = mapping_context(mapping, catalog=catalog, arguments=request.arguments)
    if spec.resource_type == "identity" and request.target.kind == "hostname":
        raise ResolutionError("INVALID_TARGET")
    incident = None
    if contract.incident == "required":
        if row["incident"] is None or row["incident_source"] is None:
            raise ResolutionError("INVALID_CONTEXT")
        incident = _fact_row(row["incident"], row["incident_source"])
    facts = resolve_facts(
        contract,
        settings,
        resource=_fact_row(resource, row["inventory_source"]),
        fact_rows=[_fact_row(item["fact"], item["source"]) for item in row["facts"]],
        incident=incident,
        now=now,
        signal_rows=row["signals"],
        signal_scope=signals,
    )
    expiry = min(identity.expires_at.astimezone(UTC), *(f.valid_until for f in facts))
    for key in ("alias_expiry", "run_expiry"):
        if row[key] is not None:
            expiry = min(expiry, row[key])
    if _now(clock) >= expiry:
        raise ResolutionError()
    return ResolvedRequest(
        request=request,
        intent=CanonicalIntent(
            tenant_id=identity.tenant_id,
            principal_id=identity.principal_id,
            account_id=UUID(mapping["account_id"]),
            provider=spec.provider,
            provider_operation=spec.provider_operation,
            action=spec.action,
            resource_type=spec.resource_type,
            target_id=UUID(resource["resource_id"]),
            arguments=request.arguments,
        ),
        resource_provider_id=resource["provider_id"],
        resource_version=resource["version"],
        mapping_version=mapping["mapping_version"],
        schema_version=spec.schema_version,
        context_contract_version=contract.version,
        facts=facts,
        resolved_at=now,
        valid_until=expiry,
        alias_id=row["alias_id"],
    ), row["canonical_target_id"]


def attest_snapshot(
    conn: Connection,
    identity: Identity,
    frozen: ResolvedRequest,
    canonical: UUID,
    clock: Clock,
    *,
    settings: Sequence[SourceSetting] | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
    signals: SignalScope | None,
) -> None:
    try:
        ResolvedRequest.model_validate(frozen)
    except ValidationError:
        raise ResolutionError("STALE_AUTHORIZATION") from None
    current, target = resolve_snapshot(
        conn, identity, frozen.request, clock, settings=settings, catalog=catalog, signals=signals
    )
    if (
        target != canonical
        or _now(clock) >= frozen.valid_until
        or current.valid_until < frozen.valid_until
        or binding_hash(current) != binding_hash(frozen)
        or any(current.fact(f.name).observed_at < f.observed_at for f in frozen.facts)
    ):
        raise ResolutionError("STALE_AUTHORIZATION")
