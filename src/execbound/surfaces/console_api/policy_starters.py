# SPDX-License-Identifier: AGPL-3.0-only
"""Conservative, lossless entry points into the existing rule compiler.

Legacy conversion recognises reviewed bytes, not arbitrary Cedar. Unknown policies and
custom quorum bindings remain documents. A copy never drops mapping placement, trusted
context, or a budget that the form does not support.
"""

import hashlib
import json
from importlib import resources
from uuid import UUID, uuid4

from execbound.contracts import Catalog
from execbound.policy.models import BundleContent, LimitRule, MappingRef, Rule, Ruleset
from execbound.policy.rulesets import compile_ruleset, ruleset_bundle

# The reviewed starter packs: Apache-2.0 data beside their own `LICENSE`, since whoever starts
# from one copies it into their own policy (#496). Exact legacy fingerprints prevent
# speculative conversion. Tests bind the packs to the independent harness packs, so the
# application wheel needs no harness.
_STARTERS = resources.files("execbound").joinpath("data", "starters")
RULES = json.loads(_STARTERS.joinpath("rules.json").read_text(encoding="utf-8"))
PACKS = json.loads(_STARTERS.joinpath("packs.json").read_text(encoding="utf-8"))


def first_policy(tenant: UUID, mappings: tuple[MappingRef, ...], catalog: Catalog) -> BundleContent:
    """The reviewed response baseline, narrowed to configured actions of a new workspace."""
    actions = {mapping.action_name for mapping in mappings}
    if not actions or not actions <= set(PACKS["soc"]["actions"]):
        raise ValueError("No supported operation mappings")
    rules = tuple(
        Rule.model_validate_json(json.dumps(RULES[rule_id]))
        for rule_id in PACKS["soc"]["rules"]
        if RULES[rule_id]["action"] in actions
    )
    limits = tuple(
        limit
        for action in sorted(actions)
        for limit in (
            LimitRule(
                rule_id=f"principal-autonomous-{action.replace('.', '-')}",
                action=action,
                scope="principal",
                window_seconds=3600,
                max_targets=10,
                budget="autonomous",
                on_exceed="REQUIRE_APPROVAL",
            ),
            LimitRule(
                rule_id=f"tenant-total-{action.replace('.', '-')}",
                action=action,
                scope="tenant",
                window_seconds=900,
                max_targets=20,
                budget="total",
                on_exceed="DENY",
            ),
        )
    )
    return ruleset_bundle(
        Ruleset(rules=rules, budgets=limits),
        tenant_id=tenant,
        bundle_id=uuid4(),
        mappings=mappings,
        catalog=catalog,
    )


def source_rules(content: BundleContent, catalog: Catalog) -> Ruleset | None:
    if content.ruleset is not None:
        compiled = compile_ruleset(content.ruleset, content.mappings, catalog=catalog)
        if all(
            getattr(content, field) == getattr(compiled, field)
            for field in (
                "cedar_schema",
                "authorization_policies",
                "approval_policies",
                "limits",
                "quorum",
            )
        ):
            return content.ruleset
        return None
    # Approval policy identifiers change when compilation reorders/splits policies. A
    # custom quorum cannot be carried across that boundary without an explicit mapping.
    if content.quorum:
        return None
    fingerprint = hashlib.sha256(
        json.dumps(
            [content.cedar_schema, content.authorization_policies, content.approval_policies],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    for pack in PACKS.values():
        if (
            fingerprint == pack["fingerprint"]
            and sorted(mapping.action_name for mapping in content.mappings) == pack["actions"]
        ):
            return Ruleset.model_validate_json(
                json.dumps(
                    {
                        "rules": [RULES[rule_id] for rule_id in pack["rules"]],
                        "budgets": [limit.model_dump(mode="json") for limit in content.limits],
                    }
                )
            )
    return None


def editable_copy(
    content: BundleContent, catalog: Catalog, *, review_all: bool = False
) -> BundleContent | None:
    ruleset = source_rules(content, catalog)
    if ruleset is None:
        return None
    if review_all:
        # Existing denials, conditions, quorum and limits remain. This adds review to
        # every mapped action that the existing authorization would otherwise allow, once
        # per action however many refs serve it.
        ids = {rule.id for rule in ruleset.rules}
        additions = []
        served = dict.fromkeys(mapping.action_name for mapping in content.mappings)
        for index, action in enumerate(served):
            rule_id = f"review-every-action-{index}"
            while rule_id in ids:
                rule_id += "x"
            additions.append(Rule(id=rule_id, action=action, effect="REVIEW"))
        ruleset = Ruleset.model_validate_json(
            json.dumps(
                {
                    **ruleset.model_dump(mode="json"),
                    "rules": [
                        rule.model_dump(mode="json") for rule in (*ruleset.rules, *additions)
                    ],
                }
            )
        )
    return ruleset_bundle(
        ruleset,
        tenant_id=content.tenant_id,
        bundle_id=uuid4(),
        mappings=content.mappings,
        context_settings=content.context_settings,
        signal_mappings=content.signal_mappings,
        catalog=catalog,
    )
