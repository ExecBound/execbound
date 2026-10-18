# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable policy content and explicit, scoped input to limit evaluation."""

import hashlib
from collections.abc import Iterable, Mapping
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from execbound.audit import canonical_json
from execbound.domains import LONG_MAX, LONG_MIN, ScalarValue
from execbound.operations import ActionName
from execbound.requests import StrictModel
from execbound.resolution.models import ContractVersion, FactName, SecurityVersions, Version
from execbound.signals.models import SignalMapping, mapping_for

RuleId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,79}$")]
PositiveCount = Annotated[int, Field(ge=1, le=2**63 - 1)]
Count = Annotated[int, Field(ge=0, le=2**63 - 1)]
WriterName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
MaxAgeSeconds = Annotated[int, Field(ge=1, le=86400)]
MAX_RULE_ACTIONS = 8
MAX_GROUPS = 64
LimitScope = Literal["principal", "tenant", "group", "account", "selector", "space"]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ContextSetting(StrictModel):
    """Tenant tuning for one contract source; contracts still bound it by a ceiling."""

    context_contract_version: ContractVersion
    source_kind: Literal["inventory", "incident", "signal"]
    max_age_seconds: MaxAgeSeconds
    permitted_writers: tuple[WriterName, ...] = Field(min_length=1, max_length=16)

    @field_validator("permitted_writers")
    @classmethod
    def canonical_writers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("Duplicate permitted writer")
        return tuple(sorted(value))


class LimitSelector(StrictModel):
    """One scalar trusted fact of the frozen plan with exactly one selected value."""

    fact: FactName
    equals: ScalarValue

    @field_validator("equals")
    @classmethod
    def bounded_scalar(cls, value: ScalarValue) -> ScalarValue:
        if type(value) is str and not 1 <= len(value) <= 254:
            raise ValueError("Invalid selector value")
        if type(value) is int and not LONG_MIN <= value <= LONG_MAX:
            raise ValueError("Invalid selector value")
        return value

    def matches(self, facts: Mapping[str, ScalarValue]) -> bool:
        """Exact type and value equality; a plan without the fact never matches."""
        value = facts.get(self.fact)
        return value is not None and type(value) is type(self.equals) and value == self.equals


class LimitRule(StrictModel):
    rule_id: RuleId
    action: ActionName
    scope: LimitScope
    window_seconds: PositiveCount
    max_targets: PositiveCount
    budget: Literal["autonomous", "total"]
    on_exceed: Literal["DENY", "REQUIRE_APPROVAL"]
    # Serialized only when set, so existing bundle content hashes and plan hashes are
    # unchanged; a rule without qualifiers is exactly the rule it was before qualifiers existed.
    actions: tuple[ActionName, ...] | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_RULE_ACTIONS,
        exclude_if=lambda value: value is None,
    )
    group_id: UUID | None = Field(default=None, exclude_if=lambda value: value is None)
    account_id: UUID | None = Field(default=None, exclude_if=lambda value: value is None)
    selector: LimitSelector | None = Field(default=None, exclude_if=lambda value: value is None)
    # A per-customer ceiling inside one tenant. Serialized only when set, like every other
    # qualifier, so existing bundle content hashes and plan hashes are unchanged.
    space_id: UUID | None = Field(default=None, exclude_if=lambda value: value is None)

    @field_validator("actions")
    @classmethod
    def canonical_actions(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if value is None:
            return None
        if len(set(value)) != len(value):
            raise ValueError("Duplicate action")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def qualified_scope(self) -> Self:
        # A qualifier without its scope, or a scope without its qualifier, is refused so a
        # rule can never silently widen to the tenant.
        for scope, qualifier in (
            ("group", self.group_id),
            ("account", self.account_id),
            ("selector", self.selector),
            ("space", self.space_id),
        ):
            if (qualifier is not None) != (self.scope == scope):
                raise ValueError("Scope qualifier mismatch")
        if self.actions is not None and self.action not in self.actions:
            raise ValueError("Action list omits the rule action")
        return self

    @property
    def action_names(self) -> tuple[str, ...]:
        return self.actions if self.actions is not None else (self.action,)

    def applies_to(
        self,
        *,
        action: str,
        account_id: UUID,
        groups: Iterable[UUID],
        facts: Mapping[str, ScalarValue],
        space_id: UUID | None = None,
    ) -> bool:
        """Whether a candidate with these frozen attributes is charged and capped by this rule."""
        if action not in self.action_names:
            return False
        if self.scope == "group":
            return self.group_id in set(groups)
        if self.scope == "account":
            return self.account_id == account_id
        if self.scope == "space":
            # No assert: a candidate with no recorded space fails closed out of the scope,
            # exactly as an unvalidated copy without its selector does.
            return space_id is not None and self.space_id == space_id
        if self.scope == "selector":
            # No assert: an unvalidated copy without its selector fails closed.
            return self.selector is not None and self.selector.matches(facts)
        return True


class QuorumRule(StrictModel):
    """How many distinct human approvers an obligation needs; absent means one."""

    rule_id: RuleId
    obligation: Annotated[
        str, Field(min_length=8, max_length=160, pattern=r"^(policy|limit):[A-Za-z0-9._:-]{1,150}$")
    ]
    required: int = Field(ge=2, le=5)


class MappingRef(StrictModel):
    operation_ref: RuleId
    account_id: UUID
    mapping_version: Version
    schema_version: Literal["action.v1"]
    context_contract_version: ContractVersion
    # Serialized only when set, so existing bundle content hashes are unchanged.
    observe_only: bool = Field(default=False, exclude_if=lambda value: value is False)
    external_executor: bool = Field(default=False, exclude_if=lambda value: value is False)
    # The catalog action this ref serves, when the ref is another name for it
    # (`mapping-create --ref`). Serialized only when set, like the two flags above, so every
    # existing bundle keeps its content hash; absent, the ref is the action's own name. The
    # store refuses one that is not the action the tenant's mapping row serves.
    action: ActionName | None = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def single_placement(self) -> Self:
        # Observing reserves nothing, claims nothing and grants nothing; a checkpoint
        # reserves impact, takes the claim and grants one act to an external executor.
        # An operation declaring both has no defined placement, so bundle content
        # carrying the pair is refused before it can ever be activated.
        if self.observe_only and self.external_executor:
            raise ValueError("Conflicting mapping placement")
        return self

    @model_validator(mode="after")
    def one_spelling(self) -> Self:
        # A ref that is its action's own name says so by leaving `action` out, so one bundle
        # never has two serializations, and two content hashes, for one meaning.
        if self.action is not None and self.action == self.operation_ref:
            raise ValueError("Redundant mapping action")
        return self

    @property
    def action_name(self) -> str:
        """The catalog action this mapping serves: what rules, schemas and limits speak of."""
        return self.action if self.action is not None else self.operation_ref


MAX_RULES = 64
MAX_CONDITIONS = 8
MAX_VALUES = 16
MAX_NOTE = 200

RuleEffect = Literal["ALLOW", "DENY", "REVIEW"]
ConditionOperator = Literal["is", "is_not", "in", "at_least", "at_most"]
FieldName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")]


class Condition(StrictModel):
    """One comparison against a declared fact of the action's contract, or its argument.

    A condition never carries free text. It names something the catalog declares, with one
    operator and values the declared domain admits, which is why a rule cannot widen what the
    bundle could already say.
    """

    kind: Literal["fact", "argument"]
    name: FieldName
    operator: ConditionOperator
    values: tuple[ScalarValue, ...] = Field(min_length=1, max_length=MAX_VALUES)

    @model_validator(mode="after")
    def arity(self) -> Self:
        # Only `in` takes several values; every other operator is a single comparison, and
        # accepting a list for them would leave the combining rule unstated.
        if self.operator != "in" and len(self.values) != 1:
            raise ValueError("Only `in` takes several values")
        if len(set(self.values)) != len(self.values):
            raise ValueError("Duplicate condition value")
        return self


class Rule(StrictModel):
    id: RuleId
    action: ActionName
    effect: RuleEffect
    when: tuple[Condition, ...] = Field(default=(), max_length=MAX_CONDITIONS)
    quorum: int | None = Field(default=None, ge=2, le=5)
    # Shown on pages and never compiled. It exists so a rule can say why it is there; it
    # reaches no policy component, no obligation and no error message.
    note: str | None = Field(default=None, max_length=MAX_NOTE)

    @model_validator(mode="after")
    def quorum_is_a_review_property(self) -> Self:
        if self.quorum is not None and self.effect != "REVIEW":
            raise ValueError("Only a REVIEW rule carries a quorum")
        if len({(condition.kind, condition.name) for condition in self.when}) != len(self.when):
            raise ValueError("Duplicate condition subject")
        return self


class Ruleset(StrictModel):
    version: Literal[1] = 1
    rules: tuple[Rule, ...] = Field(min_length=1, max_length=MAX_RULES)
    budgets: tuple[LimitRule, ...] = Field(default=(), max_length=64)
    context: tuple[ContextSetting, ...] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @field_validator("budgets")
    @classmethod
    def canonical_budgets(cls, value: tuple[LimitRule, ...]) -> tuple[LimitRule, ...]:
        # The same rule `BundleContent.limits` applies, so what the compiler emits is already
        # the stored form. Validation recompiles and compares the two tuples directly; a
        # ruleset whose budgets were written in another order would otherwise be refused as
        # a mismatch by a bundle it produced itself. One budget cannot show this, which is
        # why the first mismatch test, with one, did not.
        if len({rule.rule_id for rule in value}) != len(value):
            raise ValueError("Duplicate budget identity")
        return tuple(sorted(value, key=lambda rule: rule.rule_id))

    @model_validator(mode="after")
    def distinct_rule_ids(self) -> Self:
        ids = [rule.id for rule in self.rules]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate rule id")
        return self


class BundleContent(StrictModel):
    tenant_id: UUID
    bundle_id: UUID
    cedar_schema: str = Field(min_length=1, max_length=65536)
    authorization_policies: str = Field(min_length=1, max_length=131072)
    approval_policies: str = Field(max_length=131072)
    mappings: tuple[MappingRef, ...] = Field(min_length=1, max_length=64)
    limits: tuple[LimitRule, ...] = Field(max_length=64)
    context_settings: tuple[ContextSetting, ...] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    quorum: tuple[QuorumRule, ...] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    # The bundle's source, when it has one. Serialized only when set, exactly as the three
    # fields above, so every bundle written before rulesets existed hashes to the same bytes
    # it always did. A bundle created from a pasted document carries none and behaves as it
    # always has; for a bundle that carries one, the compiled components above are the
    # compiler's output and validation refuses a mismatch.
    ruleset: Ruleset | None = Field(default=None, exclude_if=lambda value: value is None)
    # How signal facts are read. Serialized only when set, exactly as the fields above, so
    # every bundle written before signals existed hashes to the bytes it always did.
    signal_mappings: tuple[SignalMapping, ...] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @field_validator("quorum")
    @classmethod
    def distinct_quorum(cls, value: tuple[QuorumRule, ...] | None) -> tuple[QuorumRule, ...] | None:
        if value is None:
            return None
        rule_ids = [rule.rule_id for rule in value]
        obligations = [rule.obligation for rule in value]
        if (
            not 1 <= len(value) <= 64
            or len(set(rule_ids)) != len(rule_ids)
            or len(set(obligations)) != len(obligations)
        ):
            raise ValueError("Invalid quorum rules")
        return tuple(sorted(value, key=lambda rule: rule.obligation))

    def required_approvers(self, obligation_ids: tuple[str, ...]) -> int:
        """The largest requirement over the decision's obligations, or one."""
        needed = [rule.required for rule in self.quorum or () if rule.obligation in obligation_ids]
        return max(needed, default=1)

    @field_validator("context_settings")
    @classmethod
    def canonical_settings(
        cls, value: tuple[ContextSetting, ...] | None
    ) -> tuple[ContextSetting, ...] | None:
        if value is None:
            return None
        keys = [(item.context_contract_version, item.source_kind) for item in value]
        if not 1 <= len(value) <= 32 or len(set(keys)) != len(keys):
            raise ValueError("Invalid context settings")
        return tuple(
            sorted(value, key=lambda item: (item.context_contract_version, item.source_kind))
        )

    @field_validator("signal_mappings")
    @classmethod
    def canonical_signal_mappings(
        cls, value: tuple[SignalMapping, ...] | None
    ) -> tuple[SignalMapping, ...] | None:
        if value is None:
            return None
        keys = [(item.context_contract_version, item.capability) for item in value]
        if not 1 <= len(value) <= 32 or len(set(keys)) != len(keys):
            raise ValueError("Invalid signal mappings")
        return tuple(
            sorted(value, key=lambda item: (item.context_contract_version, item.capability))
        )

    def signal_mapping(self, version: str, capability: str) -> SignalMapping | None:
        """The one entry for this contract version and capability, if the bundle has it."""
        return mapping_for(self.signal_mappings, version, capability)

    @field_validator("cedar_schema", "authorization_policies", "approval_policies")
    @classmethod
    def bounded_text(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 131072:
            raise ValueError("Policy component too large")
        return value

    @field_validator("cedar_schema")
    @classmethod
    def bounded_schema(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 65536:
            raise ValueError("Schema too large")
        return value

    @field_validator("limits")
    @classmethod
    def unique_limits(cls, value: tuple[LimitRule, ...]) -> tuple[LimitRule, ...]:
        if len({rule.rule_id for rule in value}) != len(value):
            raise ValueError("Duplicate rule identity")
        return tuple(sorted(value, key=lambda rule: rule.rule_id))

    @field_validator("mappings")
    @classmethod
    def unique_mappings(cls, value: tuple[MappingRef, ...]) -> tuple[MappingRef, ...]:
        if len({item.operation_ref for item in value}) != len(value):
            raise ValueError("Duplicate operation mapping")
        return tuple(sorted(value, key=lambda item: item.operation_ref))

    @property
    def content_hash(self) -> str:
        return _digest(canonical_json(self.model_dump(mode="json")))

    @property
    def security_versions(self) -> SecurityVersions:
        return SecurityVersions(
            bundle=self.content_hash,
            authorization=_digest(self.authorization_policies),
            approval=_digest(self.approval_policies),
            limits=_digest(canonical_json([rule.model_dump(mode="json") for rule in self.limits])),
        )


class ProjectedUsage(StrictModel):
    rule_id: RuleId
    confirmed_targets: Count
    unresolved_targets: Count

    @property
    def projected_targets(self) -> int:
        # Every new single-target action proposes one unit. Approval settlement
        # and the autonomous exemption belong to the later execution transaction.
        return self.confirmed_targets + self.unresolved_targets + 1


class UsageSnapshot(StrictModel):
    """Internal preapproval counts; later dispatch must recompute under locks."""

    tenant_id: UUID
    principal_id: UUID
    bundle_id: UUID
    # The frozen intent's account and the memberships read inside the fence for this
    # decision; evaluate applies account and group scopes only through these.
    account_id: UUID
    groups: tuple[UUID, ...] = Field(default=(), max_length=MAX_GROUPS)
    # The space the agent's own principal row named for this decision, read inside the
    # fence. Serialized only when set, so every capture written before spaces existed is
    # byte-identical.
    space_id: UUID | None = Field(default=None, exclude_if=lambda value: value is None)
    counts: tuple[ProjectedUsage, ...] = Field(max_length=64)

    @field_validator("groups")
    @classmethod
    def canonical_groups(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(set(value)) != len(value):
            raise ValueError("Duplicate group")
        return tuple(sorted(value, key=str))

    @model_validator(mode="after")
    def unique_counts(self) -> Self:
        if len({count.rule_id for count in self.counts}) != len(self.counts):
            raise ValueError("Duplicate usage rule")
        return self


class PolicyEvaluation(StrictModel):
    effect: Literal["DENY", "REQUIRE_APPROVAL", "ELIGIBLE"]
    reasons: tuple[str, ...] = ()
    obligation_ids: tuple[str, ...] = ()
    bundle_id: UUID
    content_hash: str
    plan_hash: str | None = None
