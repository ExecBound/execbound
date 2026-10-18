# SPDX-License-Identifier: AGPL-3.0-only
"""Isolated impact facts; no stored counters, database or provider capabilities."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from execbound.domains import ScalarValue
from execbound.identity import Identity
from execbound.operations import ActionName, operation
from execbound.policy.models import BundleContent, ProjectedUsage, UsageSnapshot
from execbound.resolution.models import ResolvedRequest, scalar_facts


@dataclass(frozen=True)
class Impact:
    execution_id: UUID
    principal_id: UUID
    action: ActionName
    target_id: UUID
    approved: bool | None
    created_at: datetime
    state: Literal["UNRESOLVED", "CONFIRMED", "NONEXECUTION", "HYPOTHETICAL", "OBSERVED"]
    # The scope attributes of the decision that produced this unit, from its frozen plan
    # and captured identity only, so a later provisioning change never rewrites history.
    account_id: UUID
    facts: Mapping[str, ScalarValue]
    # None when the capture predates recorded membership; such rows never count toward
    # a group scope and make a candidate group rule's count a lower bound.
    groups: tuple[UUID, ...] | None
    # None when the capture predates recorded spaces; such rows never count toward a
    # space scope and make a candidate space rule's count a lower bound.
    space_id: UUID | None = None
    confirmed_at: datetime | None = None
    # Facts whose value this ledger cannot know: a candidate's reading of the unit's signal
    # facts when the plan did not freeze what that reading needs. Such a unit never counts
    # toward a selector over one of them and makes the rule's count a lower bound, as
    # unrecorded membership does for a group.
    unknown_facts: frozenset[str] = frozenset()


def utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Replay requires aware semantic time")
    return value.astimezone(UTC)


class Ledger:
    def __init__(self, tenant_id: UUID) -> None:
        self.tenant_id = tenant_id
        self.impacts: dict[UUID, Impact] = {}

    def reserve(
        self,
        execution_id: UUID,
        principal_id: UUID,
        action: ActionName,
        target_id: UUID,
        approved: bool,
        at: datetime,
        *,
        account_id: UUID,
        facts: Mapping[str, ScalarValue],
        groups: tuple[UUID, ...] | None,
        space_id: UUID | None = None,
        unknown_facts: frozenset[str] = frozenset(),
    ) -> None:
        operation(action)
        if type(approved) is not bool:
            raise ValueError("Missing approval classification")
        value = Impact(
            execution_id,
            principal_id,
            action,
            target_id,
            approved,
            utc(at),
            "UNRESOLVED",
            account_id,
            facts,
            groups,
            space_id,
            unknown_facts=unknown_facts,
        )
        previous = self.impacts.get(execution_id)
        if previous is not None and previous != value:
            raise ValueError("Conflicting replay reservation")
        self.impacts[execution_id] = value

    def observe(
        self,
        execution_id: UUID,
        principal_id: UUID,
        action: ActionName,
        target_id: UUID,
        approved: bool,
        at: datetime,
        *,
        account_id: UUID,
        facts: Mapping[str, ScalarValue],
        groups: tuple[UUID, ...] | None,
        space_id: UUID | None = None,
        unknown_facts: frozenset[str] = frozenset(),
    ) -> None:
        """An observed decision that would have executed; counted only by observe-mode usage."""
        operation(action)
        if type(approved) is not bool:
            raise ValueError("Missing approval classification")
        value = Impact(
            execution_id,
            principal_id,
            action,
            target_id,
            approved,
            utc(at),
            "OBSERVED",
            account_id,
            facts,
            groups,
            space_id,
            unknown_facts=unknown_facts,
        )
        previous = self.impacts.get(execution_id)
        if previous is not None and previous != value:
            raise ValueError("Conflicting replay observation")
        self.impacts[execution_id] = value

    def uncertain(
        self,
        execution_id: UUID,
        principal_id: UUID,
        action: ActionName,
        target_id: UUID,
        at: datetime,
        *,
        account_id: UUID,
        facts: Mapping[str, ScalarValue],
        groups: tuple[UUID, ...] | None,
        space_id: UUID | None = None,
        unknown_facts: frozenset[str] = frozenset(),
    ) -> None:
        operation(action)
        previous = self.impacts.get(execution_id)
        if previous is not None:
            if (previous.principal_id, previous.action, previous.target_id) != (
                principal_id,
                action,
                target_id,
            ):
                raise ValueError("Conflicting hypothetical execution")
            return
        self.impacts[execution_id] = Impact(
            execution_id,
            principal_id,
            action,
            target_id,
            None,
            utc(at),
            "HYPOTHETICAL",
            account_id,
            facts,
            groups,
            space_id,
            unknown_facts=unknown_facts,
        )

    def settle(self, execution_id: UUID, executed: bool, at: datetime) -> None:
        current = self.impacts.get(execution_id)
        if current is None or type(executed) is not bool or utc(at) < current.created_at:
            raise ValueError("Invalid replay settlement")
        if current.state == "HYPOTHETICAL":
            raise ValueError("Historical proof cannot settle a hypothetical action")
        terminal: Literal["CONFIRMED", "NONEXECUTION"] = "CONFIRMED" if executed else "NONEXECUTION"
        time = utc(at) if executed else None
        if current.state not in {"UNRESOLVED", terminal}:
            raise ValueError("Conflicting replay settlement")
        if current.state == terminal and current.confirmed_at != time:
            raise ValueError("Changed replay settlement time")
        self.impacts[execution_id] = replace(current, state=terminal, confirmed_at=time)

    def correct(self, execution_id: UUID, at: datetime) -> None:
        """The one second settlement: a verified non-execution over a stated failure.

        `settle` is left exactly as narrow as it is, because a widened one would let any
        history claim CONFIRMED to NONEXECUTION, which is the refund an export must not be
        able to invent. This admits CONFIRMED only, writes NONEXECUTION with a null
        confirmation time, and refuses everything else including a second call.
        """
        current = self.impacts.get(execution_id)
        if current is None or utc(at) < current.created_at or current.state != "CONFIRMED":
            raise ValueError("Invalid replay correction")
        self.impacts[execution_id] = replace(current, state="NONEXECUTION", confirmed_at=None)

    def guards(self, target_id: UUID, *, excluding: UUID | None = None) -> tuple[UUID, ...]:
        return tuple(
            sorted(
                (
                    item.execution_id
                    for item in self.impacts.values()
                    if item.target_id == target_id
                    and item.execution_id != excluding
                    and item.state in {"UNRESOLVED", "HYPOTHETICAL"}
                ),
                key=str,
            )
        )

    def usage(
        self,
        bundle: BundleContent,
        identity: Identity,
        at: datetime,
        *,
        frozen: ResolvedRequest,
        groups: tuple[UUID, ...] | None,
        space_id: UUID | None = None,
        action: ActionName | None = None,
        observed: bool = False,
    ) -> tuple[UsageSnapshot, UsageSnapshot, tuple[UUID, ...], tuple[str, ...]]:
        """Lower and upper projections, their hypothetical dependencies and the unknown rules.

        Each rule counts retained units in its own scope exactly as the store does: any
        action in the rule's list, the asking principal, the rule's account, a selector
        over the unit's retained facts, or membership of the rule's group as recorded on
        the unit. ``groups`` is the candidate's recorded membership; ``None`` means the
        capture predates recorded membership, so the candidate is evaluated as a member
        of nothing and every group rule for its action is reported unknown. A unit with
        unknown membership never counts toward a group scope; when that rule applies to
        the candidate and the unit would otherwise have counted (by state and window),
        the count is only a lower bound, so the rule is reported unknown too. A unit whose
        selected fact is unknown (a candidate's signal reading the plan cannot supply) is
        treated the same way for a selector scope. A unit that would not have counted
        anyway leaves the rule known. The unknown rules matter to a candidate bundle only:
        the baseline reproduces what the kernel did with what it had.
        """
        if bundle.tenant_id != self.tenant_id or identity.tenant_id != self.tenant_id:
            raise ValueError("Foreign replay ledger")
        now = utc(at)
        facts = scalar_facts(frozen)
        known = groups or ()
        candidate_action = action or frozen.intent.action
        lower, upper, dependencies = [], [], set()
        unknown: set[str] = set()
        for rule in bundle.limits:
            try:
                start = now - timedelta(seconds=rule.window_seconds)
            except OverflowError:
                start = datetime.min.replace(tzinfo=UTC)
            applicable = rule.applies_to(
                action=candidate_action,
                account_id=frozen.intent.account_id,
                groups=known,
                facts=facts,
                space_id=space_id,
            )
            if rule.scope == "group" and groups is None and candidate_action in rule.action_names:
                unknown.add(rule.rule_id)
            if rule.scope == "space" and space_id is None and candidate_action in rule.action_names:
                unknown.add(rule.rule_id)
            confirmed = unresolved = hypothetical = 0
            for item in self.impacts.values():
                if item.action not in rule.action_names or (
                    rule.budget == "autonomous" and item.approved is True
                ):
                    continue
                if rule.scope == "principal" and item.principal_id != identity.principal_id:
                    continue
                if rule.scope == "account" and item.account_id != rule.account_id:
                    continue
                if rule.scope == "selector" and (
                    # No assert: an unvalidated copy without its selector counts nothing.
                    rule.selector is None
                    or (
                        rule.selector.fact not in item.unknown_facts
                        and not rule.selector.matches(item.facts)
                    )
                ):
                    continue
                # Classify by state and window before membership, as the store's filters
                # are conjunctive: a unit that would not have counted anyway (a
                # non-execution, a confirmation before the window, an observed decision
                # under an enforced evaluation) is skipped before its membership can
                # make a rule unknown.
                if item.state == "CONFIRMED":
                    if item.confirmed_at is None or item.confirmed_at <= start:
                        continue
                    bucket = "confirmed"
                elif item.state == "UNRESOLVED":
                    bucket = "unresolved"
                elif item.state == "OBSERVED":
                    # The assumed-executed projection: only an observe-mode evaluation
                    # counts an observed decision, as if it ran when it was recorded.
                    if not observed or not start < item.created_at <= now:
                        continue
                    bucket = "confirmed"
                elif item.state == "HYPOTHETICAL":
                    bucket = "hypothetical"
                else:
                    continue
                if rule.scope == "space":
                    if item.space_id is None:
                        # The kernel never counted this unit toward a space, so for a
                        # candidate the rule applies to the count is only a lower bound.
                        if applicable:
                            unknown.add(rule.rule_id)
                        continue
                    if rule.space_id != item.space_id:
                        continue
                if rule.scope == "group":
                    if item.groups is None:
                        # The kernel never counted this unit toward a group, so for a
                        # candidate the rule applies to the count is only a lower bound.
                        if applicable:
                            unknown.add(rule.rule_id)
                        continue
                    if rule.group_id not in item.groups:
                        continue
                if (
                    rule.scope == "selector"
                    and rule.selector is not None
                    and rule.selector.fact in item.unknown_facts
                ):
                    # Nobody can say whether this unit matches the selector, so for a
                    # candidate the rule applies to the count is only a lower bound.
                    if applicable:
                        unknown.add(rule.rule_id)
                    continue
                if bucket == "confirmed":
                    if item.confirmed_at and item.confirmed_at > now:
                        raise ValueError("Backward replay semantic clock")
                    confirmed += 1
                elif bucket == "unresolved":
                    unresolved += 1
                else:
                    hypothetical += 1
                    # A dependency only of a decision the rule can affect: the evaluator
                    # applies the same test with the snapshot's membership.
                    if applicable:
                        dependencies.add(item.execution_id)
            lower.append(
                ProjectedUsage(
                    rule_id=rule.rule_id, confirmed_targets=confirmed, unresolved_targets=unresolved
                )
            )
            upper.append(
                ProjectedUsage(
                    rule_id=rule.rule_id,
                    confirmed_targets=confirmed,
                    unresolved_targets=unresolved + hypothetical,
                )
            )

        def snapshot(counts: list[ProjectedUsage]) -> UsageSnapshot:
            return UsageSnapshot(
                tenant_id=self.tenant_id,
                principal_id=identity.principal_id,
                bundle_id=bundle.bundle_id,
                account_id=frozen.intent.account_id,
                groups=known,
                space_id=space_id,
                counts=tuple(counts),
            )

        return (
            snapshot(lower),
            snapshot(upper),
            tuple(sorted(dependencies, key=str)),
            tuple(sorted(unknown)),
        )
