# SPDX-License-Identifier: AGPL-3.0-only
"""Shared policy setup: a tenant whose active bundle was written as rules.

The Policy pages moved into the console when it replaced the old Jinja pages (#333); this
describes a bundle rather than a page, so the assistant's tests and the console API's read
it here.
"""

from uuid import uuid4

from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound_harness.demo import ENDPOINT_RULESET


def activated_ruleset_bundle(db, world):
    """The endpoint pack as rules, active in the world's tenant: budgets of ten autonomous
    targets per principal and twenty in total, the pair the sandbox's candidate caps."""
    content = ruleset_bundle(
        ENDPOINT_RULESET,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    return content
