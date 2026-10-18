# SPDX-License-Identifier: AGPL-3.0-only
"""GC18's kernel half: the synthetic workflow contract a calling story must handle.

The contract covers both calls and every branch a story must handle: denial, approval
wait, expiry, report failure and retry. It is driven over the same HTTP surface a real
story would call, with the protected mocks acting as the external executor: the story holds
its own vendor credential, ExecBound dispatches nothing, and the only thing the grant
buys is the right to settle the one execution it names.

Every answer the story receives is recorded on the story as its shape — the status, the
body's key set, the state and the refusal code — and the walk below asserts the whole of
it at the end. That dictionary is the contract the checkpoint guide documents, so a change
to any shape a story branches on fails here rather than in a customer's story.

The page half of GC18 is `tests/test_browser_surfaces.py::test_gc18_the_pages_label_an_\
externally_executed_operation_as_inert_text`, which drives the record and approval pages
with real Chromium. Neither half is the other's: this one never renders a page and that
one never reports an outcome.
"""

import json
import secrets
from datetime import timedelta

import pytest
from checkpoint_fixtures import (
    gate_bundle,
    grant_row,
    report_body,
    signed_record,
)
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from fastapi.testclient import TestClient
from scope_fixtures import rule, scoped_bundle
from sqlalchemy import text
from test_execution import provision_credential, targets
from test_execution import registry as registry
from test_execution import world as world

from execbound.app import create_app
from execbound.execution import decide_approval
from execbound.runtime import Runtime
from execbound.surfaces.tokens import TokenKeys
from execbound_harness.demo import APPROVAL

VIEW_KEYS = ("approval_id", "approval_state", "execution_id", "plan_hash", "request_ref", "state")
# What a granted answer and a pending one add to that view, and what a refusal carries
# instead of any of it. Sorted, because a story reads a body and not an ordering.
GRANT_KEYS = tuple(sorted((*VIEW_KEYS, "checkpoint")))
PENDING_KEYS = tuple(sorted((*VIEW_KEYS, "approval_url", "continuation")))
# A denial adds its category and the one sentence that names its reference and nothing of
# its reason.
DENIED_KEYS = tuple(sorted((*VIEW_KEYS, "denial", "notice")))
REFUSAL_KEYS = ("code", "detail")


def shape(response):
    """One answer as a story sees it: what it branches on and nothing it cannot read."""
    body = response.json()
    checkpoint = body.get("checkpoint")
    return {
        "status": response.status_code,
        "keys": tuple(sorted(body)),
        "state": body.get("state"),
        "code": body.get("code"),
        "checkpoint": None if checkpoint is None else tuple(sorted(checkpoint)),
    }


class Vendor:
    """The protected mock standing in for the platform the story actually calls.

    It records what the story asked it to do, so a branch that must not act can be shown
    not to have acted, and it signs the executor's record with the key half ExecBound
    never holds.
    """

    def __init__(self, db, world):
        self.db, self.world, self.performed = db, world, []

    def act(self, execution_id, grant, **changes):
        self.performed.append((execution_id, grant["expected_version"]))
        return signed_record(self.db, self.world, execution_id, **changes)


class Story:
    """A scripted caller: one request, one act at its own vendor, one report.

    It holds an agent credential and its vendor's, and nothing else. There is no second
    grant and no pull interface: every answer below is the whole of what ExecBound tells
    it, and each branch is what a story has to do with one.
    """

    def __init__(self, client, vendor):
        # Every branch this story takes, in the order it takes them, with the shape
        # ExecBound answered each call with. Held on the story rather than in a module
        # global so one walk's contract is never another's.
        self.client, self.vendor, self.contract = client, vendor, {}

    def ask(self, action, branch):
        answered = self.client.post("/v1/execute", json=json.loads(action.model_dump_json()))
        self.contract[branch] = shape(answered)
        return answered.json()

    def report(self, execution_id, body, branch):
        answered = self.client.post(f"/v1/executions/{execution_id}/outcome", json=body)
        self.contract[branch] = shape(answered)
        return answered.json()


@pytest.fixture
def story(db, gate_world, admin_engine):
    """The story, its client and its vendor, against a deployment serving Gate alone.

    The credential outlives a grant's report window on purpose: that window is the shorter
    of a day and the requesting credential's own expiry, so a story on a shorter one would
    be answered about its identity where the expiry branch below expects to be answered
    about the deadline.
    """
    world = gate_world
    scoped_bundle(
        db,
        world,
        # Two autonomous isolations before a human is asked, and three in all before the
        # tenant's ceiling refuses one outright: the two answers a story must tell apart.
        rule(rule_id="autonomous", budget="autonomous", max_targets=2),
        rule(rule_id="ceiling", scope="tenant", budget="total", max_targets=3, on_exceed="DENY"),
    )
    gate_bundle(db, world, approval_policies=APPROVAL, limits=world["bundle"].limits)
    identity = world["identity"]
    with admin_engine.begin() as conn:
        token = provision_credential(
            conn,
            identity.tenant_id,
            identity.principal_id,
            world["clock"].now(),
            timedelta(days=2),
        )
    # A deployment that signs its act grants and knows where its approvals are decided:
    # both are what a story reads, and a runtime holding neither would answer with a null
    # act and no approval page and quietly change two of the shapes below.
    runtime = Runtime(
        db,
        [],
        clock=world["clock"],
        keys=TokenKeys("story-v1", {"story-v1": secrets.token_bytes(32)}),
        approval_url="http://127.0.0.1:8000/approvals",
    )
    app = create_app(db, runtime=runtime)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + token
        yield Story(client, Vendor(db, world))


def held(admin_engine, world, execution_id):
    return grant_row(admin_engine, world["identity"].tenant_id, execution_id)


def test_gc18_a_story_handles_a_grant_a_denial_an_approval_wait_an_expiry_and_a_failure(
    db, gate_world, admin_engine, story
):
    """The whole exchange, every branch, in the order a story meets them."""
    world = gate_world
    first, stranded, approved, denied = targets(admin_engine, world, count=4)

    # 1. The grant. The story is told what it may do, once, and what will settle it.
    answer = story.ask(first, "grant")
    grant = answer["checkpoint"]["grant"]
    assert answer["state"] == "DISPATCH_COMMITTED"
    assert answer["checkpoint"]["act"] is not None
    assert grant["regranted"] is False and grant["report_secret"]
    assert grant["precondition_class"] == "UNAVAILABLE" and grant["expected_version"] is None
    record = story.vendor.act(answer["execution_id"], grant)
    settled = story.report(
        answer["execution_id"],
        report_body(world, grant["report_secret"], record=record),
        "report",
    )
    assert settled["state"] == "EXECUTED"

    # 2. The grant this story will never report, taken now because the tenant's ceiling
    # below refuses everything after the denial and the expiry is answered last.
    lost = story.ask(stranded, "expiry-grant")
    lost_grant = lost["checkpoint"]["grant"]

    # 3. The approval wait. No grant until a human decides, and the story is told where the
    # decision is made rather than left to poll blindly.
    waiting = story.ask(approved, "approval-wait")
    assert waiting["state"] == "PENDING_APPROVAL" and "checkpoint" not in waiting
    decide_approval(db, world["human"], waiting["approval_id"], "APPROVE", world["clock"])
    retried = story.ask(approved, "approved-retry")
    assert retried["execution_id"] == waiting["execution_id"]
    approved_grant = retried["checkpoint"]["grant"]

    # 4. The report failure, and the retry that is the story's remedy. A forged secret does
    # not authenticate; a record the tenant's keys do not attest does not verify; neither
    # settles anything, and the correct report still does.
    story.report(
        retried["execution_id"],
        report_body(world, "not-the-secret-this-grant-was-given"),
        "report-unauthenticated",
    )
    tampered = dict(story.vendor.act(retried["execution_id"], approved_grant))
    tampered["signature"] = "0" * 128
    story.report(
        retried["execution_id"],
        report_body(world, approved_grant["report_secret"], record=tampered),
        "report-unverifiable",
    )
    assert held(admin_engine, world, retried["execution_id"])["settlement_tier"] is None
    recovered = story.report(
        retried["execution_id"],
        report_body(
            world,
            approved_grant["report_secret"],
            record=story.vendor.act(retried["execution_id"], approved_grant),
        ),
        "report-retried",
    )
    assert recovered["state"] == "EXECUTED"

    # 5. The denial. Nothing was granted, so there is nothing to act on and nothing to
    # report: the story stops here, and its vendor is never called.
    performed = len(story.vendor.performed)
    refused = story.ask(denied, "denial")
    assert refused["state"] == "DENIED" and "checkpoint" not in refused
    assert len(story.vendor.performed) == performed

    # 6. The expiry. A grant nobody reported inside its report window is no longer the
    # story's to settle; an administrator's is the only exit left, which is what the
    # refusal tells it rather than inviting a retry that can never succeed.
    world["clock"].value = held(admin_engine, world, lost["execution_id"])["report_expires_at"]
    story.report(
        lost["execution_id"],
        report_body(world, lost_grant["report_secret"], outcome="UNKNOWN", reason=None),
        "expiry-report",
    )
    assert held(admin_engine, world, lost["execution_id"])["state"] == "DISPATCH_COMMITTED"

    # The contract as a whole: the shapes of every answer a story branches on.
    assert story.contract == {
        "grant": {
            "status": 202,
            "keys": GRANT_KEYS,
            "state": "DISPATCH_COMMITTED",
            "code": None,
            "checkpoint": ("act", "grant"),
        },
        "report": {
            "status": 200,
            "keys": VIEW_KEYS,
            "state": "EXECUTED",
            "code": None,
            "checkpoint": None,
        },
        "approval-wait": {
            "status": 202,
            "keys": PENDING_KEYS,
            "state": "PENDING_APPROVAL",
            "code": None,
            "checkpoint": None,
        },
        "approved-retry": {
            "status": 202,
            "keys": GRANT_KEYS,
            "state": "DISPATCH_COMMITTED",
            "code": None,
            "checkpoint": ("act", "grant"),
        },
        "report-unauthenticated": {
            "status": 403,
            "keys": REFUSAL_KEYS,
            "state": None,
            "code": "INVALID_REPORT",
            "checkpoint": None,
        },
        "report-unverifiable": {
            "status": 400,
            "keys": REFUSAL_KEYS,
            "state": None,
            "code": "INVALID_RECORD",
            "checkpoint": None,
        },
        "report-retried": {
            "status": 200,
            "keys": VIEW_KEYS,
            "state": "EXECUTED",
            "code": None,
            "checkpoint": None,
        },
        "denial": {
            "status": 200,
            "keys": DENIED_KEYS,
            "state": "DENIED",
            "code": None,
            "checkpoint": None,
        },
        "expiry-grant": {
            "status": 202,
            "keys": GRANT_KEYS,
            "state": "DISPATCH_COMMITTED",
            "code": None,
            "checkpoint": ("act", "grant"),
        },
        "expiry-report": {
            "status": 409,
            "keys": REFUSAL_KEYS,
            "state": None,
            "code": "REPORT_WINDOW_CLOSED",
            "checkpoint": None,
        },
    }


def test_gc18_the_story_is_told_a_grant_is_neither_an_execution_nor_an_approval(
    db, gate_world, admin_engine, story
):
    """What a story must not read into the two answers that carry a checkpoint object.

    A grant is not a dispatch: ExecBound performed nothing, and the state it answers with
    is the state of a committed reservation. It is not an approval either: the approval
    branch answers with no checkpoint at all, and the grant that follows a decision carries
    the same act the first one would have.
    """
    world = gate_world
    (target,) = targets(admin_engine, world, count=1)
    answer = story.ask(target, "grant")
    execution_id = answer["execution_id"]
    row = held(admin_engine, world, execution_id)
    # Reserved and committed, with no provider ever asked and no evidence of anything.
    assert (row["state"], row["settlement_tier"], row["result"]) == (
        "DISPATCH_COMMITTED",
        None,
        None,
    )
    assert row["report_expires_at"] is not None
    with admin_engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(world["identity"].tenant_id)},
        )
        kinds = [
            row.kind
            for row in conn.execute(
                text(
                    "SELECT kind FROM execbound.audit_events WHERE tenant_id=:t ORDER BY sequence"
                ),
                {"t": world["identity"].tenant_id},
            )
        ]
    assert "execution.checkpoint_granted" in kinds
    assert "execution.dispatch_attempt" not in kinds
    # The status read answers the same body it always has: the act and the secret are
    # served by the admission that issued them and by no later request.
    status = story.client.get(f"/v1/executions/{execution_id}")
    assert status.status_code == 202 and "checkpoint" not in status.json()
    # And the grant is not an approval: nothing about this execution was approved.
    assert answer["approval_id"] is None and answer["approval_state"] is None
