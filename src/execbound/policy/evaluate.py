# SPDX-License-Identifier: AGPL-3.0-only
"""Compose internal policy and limit results; this module never dispatches."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from execbound.contracts import (
    PRODUCTION_CATALOG,
    SIGNAL_WRITER,
    Catalog,
    Column,
    ContextContract,
    ContractError,
    FactSpec,
    Signal,
    effective_source,
    value_matches,
)
from execbound.identity import Identity
from execbound.operations import CatalogError
from execbound.policy.approval import VerifiedApproval
from execbound.policy.cedar import evaluate_policy_sets
from execbound.policy.models import BundleContent, LimitRule, PolicyEvaluation, UsageSnapshot
from execbound.resolution.models import (
    Clock,
    ResolvedRequest,
    SystemClock,
    TrustedFact,
    plan_hash,
    scalar_facts,
)
from execbound.signals.capabilities import CapabilityError
from execbound.signals.mapping import UnmappedSignal, combine, fact_window

__all__ = ["PRODUCTION_CATALOG", "evaluate"]


def _now(clock: Clock) -> datetime:
    now = clock.now()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Invalid clock")
    return now.astimezone(UTC)


def _source(fact: TrustedFact) -> tuple[Any, ...]:
    return (
        fact.source_id,
        fact.source_object_id,
        fact.source_version,
        fact.permitted_writers,
        fact.observed_at,
        fact.valid_until,
    )


def _root(contract: ContextContract, spec: FactSpec) -> FactSpec:
    return contract.fact(spec.derivation.dependency) if spec.derivation is not None else spec


def _signal_evidence(
    spec: FactSpec,
    fact: TrustedFact,
    resolved: ResolvedRequest,
    bundle: BundleContent,
    max_age_seconds: int,
) -> None:
    """Recompute a signal fact from its frozen records under the evaluated bundle's mapping.

    Resolution's mapping is never trusted by itself. A plan is refused unless the bundle's
    own entry, applied to exactly the records it froze, reproduces the value, the source and
    its registration version, and the observation, and unless its validity is no longer than
    those records support. The records name neither their capability nor their subject, so
    the evidence must name the capability the contract stores this fact under, and no record
    may be observed or received after the decision it rests on.
    """
    if not isinstance(spec.storage, Signal):
        raise ValueError("Invalid signal evidence")
    entry = bundle.signal_mapping(resolved.context_contract_version, spec.storage.capability)
    evidence = fact.signal
    if (
        entry is None
        or evidence is None
        or evidence.capability != spec.storage.capability
        or fact.source_object_id != resolved.resource_provider_id
        or fact.permitted_writers != (SIGNAL_WRITER,)
    ):
        raise ValueError("Invalid signal evidence")
    # Compared as instants: two aware times sharing one zone compare by wall clock.
    decided = resolved.resolved_at.astimezone(UTC)
    if any(
        item.observed_at.astimezone(UTC) > decided or item.received_at.astimezone(UTC) > decided
        for item in evidence.records
    ):
        raise ValueError("Invalid signal evidence")
    try:
        combined = combine(entry, evidence.records)
    except (UnmappedSignal, CapabilityError):
        raise ValueError("Invalid signal evidence") from None
    determining = next(item for item in evidence.records if item.source_id == combined.source_id)
    observed, supported_until = fact_window(evidence.records, max_age_seconds=max_age_seconds)
    if (
        combined.value != fact.value
        or combined.source_id != fact.source_id
        or fact.source_version != str(determining.registration_version)
        or fact.observed_at != observed
        or fact.valid_until > supported_until
    ):
        raise ValueError("Invalid signal evidence")


class InvalidArguments(ValueError):
    """Frozen arguments no longer match the action's catalog spec."""


def _trusted_entities(
    resolved: ResolvedRequest,
    identity: Identity,
    now: datetime,
    bundle: BundleContent,
    catalog: Catalog,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    # model_copy deliberately skips validation; an internal object is not an
    # authorization proof until this complete operation tuple is rechecked.
    ResolvedRequest.model_validate(resolved)
    intent = resolved.intent
    try:
        # The frozen model is structural, so evaluation is where the operation tuple
        # is rechecked against the catalog between resolution and provider dispatch.
        # Named for the operation, not shadowing the per-fact spec used below.
        operation = catalog.actions.validate_operation(
            provider=intent.provider,
            resource_type=intent.resource_type,
            action=intent.action,
            provider_operation=intent.provider_operation,
            schema_version=resolved.schema_version,
        )
        contract = catalog.for_operation(
            resolved.context_contract_version, intent.action, intent.resource_type
        )
    except (CatalogError, ContractError):
        raise ValueError("Unknown contract") from None
    try:
        # Resolution normalized these arguments; the frozen copy is rechecked here so
        # policy reads only values the catalog still accepts for this action.
        arguments = catalog.actions.normalize_arguments(intent.action, intent.arguments.root)
    except CatalogError:
        raise InvalidArguments("Invalid arguments") from None
    facts = {fact.name: fact for fact in resolved.facts}
    if (
        len(facts) != len(resolved.facts)
        or set(facts) != contract.fact_names
        or not resolved.resolved_at <= now < resolved.valid_until <= identity.expires_at
    ):
        raise ValueError("Invalid evidence")
    column_inventory = [
        facts[spec.name]
        for spec in contract.facts
        if spec.source_kind == "inventory" and isinstance(_root(contract, spec).storage, Column)
    ]
    incidents = [facts[spec.name] for spec in contract.facts if spec.source_kind == "incident"]
    for spec in contract.facts:
        fact = facts[spec.name]
        source = effective_source(contract, bundle.context_settings, spec.source_kind)
        dependencies = (spec.derivation.dependency,) if spec.derivation is not None else ()
        if (
            not value_matches(spec, fact.value)
            or fact.origin != ("DERIVED" if spec.derivation is not None else "RESOLVED")
            or fact.source_kind != spec.source_kind
            or fact.dependencies != dependencies
            or not fact.permitted_writers
            or fact.permitted_writers != tuple(sorted(set(fact.permitted_writers)))
            or not set(fact.permitted_writers) <= set(source.permitted_writers)
            or not fact.observed_at <= resolved.resolved_at <= now < fact.valid_until
            or fact.valid_until > fact.observed_at + timedelta(seconds=source.max_age_seconds)
            or resolved.valid_until > fact.valid_until
            or (fact.signal is not None) != (spec.source_kind == "signal")
        ):
            raise ValueError("Invalid evidence")
        if spec.source_kind == "incident":
            if (
                _source(fact) != _source(incidents[0])
                or str(UUID(fact.source_object_id)) != fact.source_object_id
            ):
                raise ValueError("Inconsistent incident evidence")
            if contract.bind_incident_claim and fact.source_object_id != str(
                resolved.request.claimed_context.incident_id
            ):
                raise ValueError("Unlinked incident evidence")
        elif isinstance(_root(contract, spec).storage, Column):
            if (
                _source(fact) != _source(column_inventory[0])
                or fact.source_object_id != resolved.resource_provider_id
                or fact.source_version != resolved.resource_version
            ):
                raise ValueError("Inconsistent inventory evidence")
        elif spec.source_kind == "signal":
            _signal_evidence(spec, fact, resolved, bundle, source.max_age_seconds)
        elif fact.source_object_id != resolved.resource_provider_id:
            raise ValueError("Inconsistent inventory evidence")
        if spec.derivation is not None:
            dependency = facts[spec.derivation.dependency]
            if fact.value != (dependency.value == spec.derivation.value) or _source(
                fact
            ) != _source(dependency):
                raise ValueError("Invalid derivation")
    principal = {"type": "ExecBound::Agent", "id": f"{identity.tenant_id}/{identity.principal_id}"}
    resource = {
        "type": f"ExecBound::{contract.cedar_entity_type}",
        "id": (
            f"{intent.tenant_id}/{intent.account_id}/{intent.provider}/"
            f"{intent.resource_type}/{intent.target_id}"
        ),
    }
    request = {
        "principal": principal,
        "action": {"type": "ExecBound::Action", "id": intent.action},
        "resource": resource,
        "context": {"arguments": arguments} if operation.arguments else {},
    }
    resource_attrs: dict[str, Any] = {
        "tenant": str(intent.tenant_id),
        "account": str(intent.account_id),
        **{name: fact.value for name, fact in facts.items()},
    }
    entities = [
        {"uid": principal, "attrs": {"tenant": str(identity.tenant_id)}, "parents": []},
        {"uid": resource, "attrs": resource_attrs, "parents": []},
    ]
    return request, entities


def evaluate(
    *,
    bundle: BundleContent,
    identity: Identity,
    resolved: ResolvedRequest,
    usage: UsageSnapshot,
    clock: Clock | None = None,
    approval: VerifiedApproval | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> PolicyEvaluation:
    """Evaluate an active, verified store snapshot and trusted preapproval counts.

    This pure component does not load active state or refresh credentials. The
    coordinator must authenticate/resolve/load before calling it, then recheck
    bundle, identity, evidence, approvals and usage in the atomic dispatch unit.
    No caller-supplied approval flag can satisfy an obligation here.
    """
    clock = clock or SystemClock()
    binding: str | None = None

    def denied(*reasons: str) -> PolicyEvaluation:
        return PolicyEvaluation(
            effect="DENY",
            reasons=tuple(sorted(set(reasons))),
            bundle_id=bundle.bundle_id,
            content_hash=bundle.content_hash,
            plan_hash=binding,
        )

    try:
        now = _now(clock)
        if (
            identity.kind != "AGENT"
            or identity.expires_at <= now
            or identity.tenant_id != resolved.intent.tenant_id
            or identity.principal_id != resolved.intent.principal_id
        ):
            return denied("INVALID_IDENTITY")
        if bundle.tenant_id != identity.tenant_id:
            return denied("INVALID_BUNDLE")
        mappings = [m for m in bundle.mappings if m.operation_ref == resolved.request.operation_ref]
        if (
            len(mappings) != 1
            # A mapping that names its action must name the plan's, which is its row's.
            or mappings[0].action not in (None, resolved.intent.action)
            or any(
                getattr(mappings[0], name) != value
                for name, value in (
                    ("account_id", resolved.intent.account_id),
                    ("mapping_version", resolved.mapping_version),
                    ("schema_version", resolved.schema_version),
                    ("context_contract_version", resolved.context_contract_version),
                )
            )
        ):
            return denied("INVALID_BUNDLE")
        try:
            request, entities = _trusted_entities(resolved, identity, now, bundle, catalog)
        except InvalidArguments:
            return denied("INVALID_ARGUMENTS")
        except (ValueError, TypeError, OverflowError):
            return denied("INVALID_CONTEXT")
        binding = plan_hash(resolved, bundle.security_versions)
        try:
            for rule in bundle.limits:
                LimitRule.model_validate(rule.model_dump())
                # Action names are patterns, so the catalog is what decides whether a
                # rule names real actions, in its list as much as its own. CatalogError
                # is listed explicitly: a bundle defect must deny as INVALID_USAGE,
                # never as DEPENDENCY_UNAVAILABLE.
                for name in rule.action_names:
                    catalog.actions.action(name)
        except (CatalogError, ValidationError, TypeError, ValueError):
            return denied("INVALID_USAGE")
        counts = {count.rule_id: count for count in usage.counts}
        rules = {rule.rule_id: rule for rule in bundle.limits}
        if (
            usage.tenant_id != identity.tenant_id
            or usage.principal_id != identity.principal_id
            or usage.bundle_id != bundle.bundle_id
            or usage.account_id != resolved.intent.account_id
            or len(counts) != len(usage.counts)
            or len(rules) != len(bundle.limits)
            or set(counts) != set(rules)
            or any(type(group) is not UUID for group in usage.groups)
            or any(
                type(value) is not int or not 0 <= value <= 2**63 - 1
                for count in counts.values()
                for value in (count.confirmed_targets, count.unresolved_targets)
            )
        ):
            return denied("INVALID_USAGE")
        result = evaluate_policy_sets(
            schema=bundle.cedar_schema,
            authorization=bundle.authorization_policies,
            approval=bundle.approval_policies,
            request=request,
            entities=entities,
        )
        reasons = []
        obligations = {f"policy:{policy_id}" for policy_id in result.approval_ids}
        if result.error:
            reasons.append("POLICY_ERROR")
        if not result.authorized:
            reasons.append("NOT_AUTHORIZED")
        facts = scalar_facts(resolved)
        for rule_id, rule in rules.items():
            # The store supplies the complete bundle snapshot. A rule that does not apply
            # to this candidate's action, account, memberships or frozen facts neither
            # charges nor waives anything, exactly like a rule for another action.
            if not rule.applies_to(
                action=resolved.intent.action,
                account_id=resolved.intent.account_id,
                groups=usage.groups,
                facts=facts,
                space_id=usage.space_id,
            ):
                continue
            count = counts[rule_id]
            if any(
                type(value) is not int or not 0 <= value <= 2**63 - 1
                for value in (count.confirmed_targets, count.unresolved_targets)
            ):
                reasons.append("INVALID_USAGE")
            else:
                # Discover escalation obligations before satisfying them. Hard
                # limits use the candidate's actual approved/autonomous impact.
                projected = count.projected_targets
                if approval is not None and rule.budget == "autonomous":
                    projected -= 1
                if rule.on_exceed == "DENY" and projected > rule.max_targets:
                    reasons.append(f"HARD_LIMIT:{rule_id}")
                elif (
                    rule.on_exceed == "REQUIRE_APPROVAL"
                    and count.projected_targets > rule.max_targets
                ):
                    obligations.add(f"limit:{rule_id}")
        finished = _now(clock)
        if finished < now or finished >= resolved.valid_until:
            reasons.append("INVALID_CONTEXT")
        if reasons:
            return denied(*reasons)
        satisfied = False
        if approval is not None:
            if (
                type(approval) is not VerifiedApproval
                or approval.tenant_id != identity.tenant_id
                or approval.principal_id != identity.principal_id
                or approval.bundle_id != bundle.bundle_id
                or approval.plan_hash != binding
                or approval.obligation_ids != tuple(sorted(obligations))
                or approval.expires_at.tzinfo is None
                or not finished < approval.expires_at <= resolved.valid_until
            ):
                return denied("INVALID_APPROVAL")
            satisfied = True
        return PolicyEvaluation(
            effect="REQUIRE_APPROVAL" if obligations and not satisfied else "ELIGIBLE",
            reasons=("APPROVAL_REQUIRED",) if obligations and not satisfied else (),
            obligation_ids=tuple(sorted(obligations)),
            bundle_id=bundle.bundle_id,
            content_hash=bundle.content_hash,
            plan_hash=binding,
        )
    except Exception:
        # Inputs and dependencies may include sensitive context or policy text.
        return denied("DEPENDENCY_UNAVAILABLE")
