# SPDX-License-Identifier: AGPL-3.0-only
"""The getting-started helpers (#496): a workspace's progress, read from its own audit chain.
`host_facts` is held against the rules in `tests/test_rulesets.py`."""

import pytest

from execbound.audit import append_event
from execbound.getting_started import PROGRESS_STEPS, progress

pytestmark = pytest.mark.integration


def test_progress_is_the_earliest_audit_record_of_each_step(db, seeded):
    tenant, actor = seeded["tenants"][0], seeded["principals"][0]
    with db.transaction(tenant) as conn:
        assert progress(conn, tenant) == dict.fromkeys(PROGRESS_STEPS)
        append_event(conn, tenant, actor, "credential.issued", {"kind": "AGENT"})
        append_event(
            conn,
            tenant,
            actor,
            "execution.evaluated",
            {"decision": {"effect": "DENY", "reasons": ["HARD_LIMIT:tenant_total"]}},
        )
        found = progress(conn, tenant)
    assert found["agent_credential"] is not None
    assert found["limit_refused"] is not None
    # A refusal by a hard limit is a denial too, and the earlier of the two is the one shown.
    assert found["denied"] == found["limit_refused"]
    # No request was ever made, so the executions table has nothing to report.
    assert found["first_request"] is None
    assert {step for step, at in found.items() if at is None} == {
        "claimed",
        "approver_credential",
        "first_request",
        "claim_refused",
        "decided",
    }
