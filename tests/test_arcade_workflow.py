# SPDX-License-Identifier: AGPL-3.0-only
"""AL27: the fixture Arcade caller, and the wire contract it holds this deployment to.

Limitation 2 in `docs/ARCADE.md` rests on a question the vendor's documentation does not answer:
whether a real Arcade deployment sends `success` on every post hook. If it does not, every
governed call it carries strands in retained uncertainty and this integration is not fit.
The place to find that out is a fixture rather than a tenant, so the caller here drives the
surface a hook process actually serves — `create_arcade` over real HTTP — with the bodies
of the published contract, and everything it records is asserted against
`execbound_harness.fake_arcade.HOOK_CONTRACT` rather than against what `parse_pre_hook` and
`parse_post_hook` happen to admit.

That direction is the whole point of the file. A walk asserting what the parser accepts
would pass however narrow the deployment became, because the parser is what it would be
measuring itself against. A walk asserting what the contract requires fails when the
deployment stops fitting the platform, which is the failure worth having early. Three of
the contract's requirements are narrower than the published schema: the second node drives
two of them, and the third — that an ExecBound settlement rests on a field the schema marks
optional — is the settlement table the first node asserts in full.

`docs/ACCEPTANCE_TESTS.md` places AL27 here and the other carrier rows in `tests/test_arcade.py`.
Those rows assert what one branch does and what it left behind; this file asserts that
every branch answers something a platform can read, against one object a guide can render.
"""

import re
from uuid import UUID

import httpx
import pytest
from arcade_fixtures import (
    APPROVALS_PAGE,
    APPROVE_RISKY,
    GOVERNED_TOOL,
    WORLD_DEVICE,
    approving_runtime,
    arcade_boundary,
    audit_head,
    correlation_rows,
    governed_bundle,
    governed_target,
    hook_block,
    transitions,
)
from arcade_fixtures import arcade_world as arcade_world
from checkpoint_fixtures import (
    execution_states,
    grant_row,
    long_lived_admin,
    retained,
    scoped,
)
from checkpoint_fixtures import owner as owner
from context_fixtures import CATALOG, SYNTHETIC_FACTS
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world

from execbound.execution import decide_approval
from execbound.recovery_run import recover
from execbound_harness.fake_arcade import (
    CONTENT_TYPES,
    EXECUTION_ID_PATTERN,
    HOOK_CONTRACT,
    UNCHANGED,
    ContractError,
    FakeArcade,
    answer_unfit,
    post_body,
    pre_body,
    tool_context,
    tool_info,
)

# Every branch the walk drives, in the order it drives them. A settlement branch needs a
# grant of its own before it has anything to report, so each of those is two: the pre hook
# that took the grant, and the arrival that settled it or did not.
BRANCHES = (
    "governed-permit",
    "duplicate-pre",
    "denial",
    "approval-wait",
    "approved-retry",
    "ungoverned-pass",
    "success-grant",
    "reported-success",
    "duplicate-post",
    "failure-grant",
    "reported-failure",
    "silence-grant",
    "absent-success",
    "oversized-grant",
    "oversized-body",
)

# The endpoints the walk names, one per branch that takes a grant, because the canonical
# claim of an unsettled grant is what refuses a second grant on the same target. The risk
# each carries is what decides it: the synthetic pack permits an isolation from 50, and
# `APPROVE_RISKY` sends one from 60 to a human, so 55 is decided without an approval and 10
# is denied outright. `WORLD_DEVICE` carries 70 and is what the approval branch names.
PERMITTED = "55"
DENIED = "10"
TARGETS = {
    "governed-permit": "device-31",
    "denial": "device-32",
    "success-grant": "device-33",
    "failure-grant": "device-34",
    "silence-grant": "device-35",
    "oversized-grant": "device-36",
}

# What a platform reports about the tool it ran. It agrees with the declaration's `expect`,
# because a contradiction is the map's denial and this walk is not about that branch.
TOOL_METADATA = {
    "behavior": {"destructive": True, "read_only": False, "idempotent": False},
    "classification": {"service_domains": ["endpoint"]},
}
# The whole of `ToolContext`, sent by the branches that send a maximal message: a platform
# may send all four fields and a deployment that refused any of them would not fit it.
FULL_CONTEXT = {
    "user_id": "analyst@example.test",
    "secrets": ["CROWDSTRIKE_TOKEN"],
    "metadata": {"project": "fixture-project"},
    "authorization": [{"provider_id": "crowdstrike", "oauth2": {"at": "header.payload.signature"}}],
}
# An `execution_id` the published schema permits and this deployment cannot key on, and one
# it can. Both are asserted against `EXECUTION_ID_PATTERN` before they are sent, so what
# drives the two probes is the contract rather than a guess about the deployment.
UNKEYABLE_ID = "arcade/execution 9"
KEYABLE_ID = "arcade-execution-1"
# A framing outside the two spellings the hook surface admits. It is a content type a
# platform may legitimately send, which is what makes its refusal a fact about fit.
UNFRAMED = "application/json;charset=utf-8"


def governed(**changes):
    """The tool identity every governed branch names, with whatever it says about itself."""
    return tool_info(**GOVERNED_TOOL, **changes)


def endpoint(admin_engine, world, provider_id, risk):
    """One endpoint at a named risk, which is what decides the branch that names it."""
    return governed_target(
        admin_engine, world, provider_id, facts={**SYNTHETIC_FACTS, "risk_score": risk}
    )


def correlated(admin_engine, tenant, arcade_id):
    """The ExecBound execution this Arcade execution's own correlation row names."""
    execution_id = correlation_rows(admin_engine, tenant)[arcade_id]["execution_id"]
    assert isinstance(execution_id, UUID)
    return execution_id


def pending(admin_engine, tenant):
    """The one approval this tenant holds, which is the row a human decides."""
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        return (
            conn.execute(
                text("SELECT approval_id FROM execbound.approvals WHERE tenant_id=:t"),
                {"t": tenant},
            )
            .scalars()
            .one()
        )


def settlement(admin_engine, tenant, execution_id, *, success, before=None):
    """What one arrival left an execution as, in the shape the post hook table states it.

    ``before`` is the state the row held when the arrival reached it, and it is what turns
    a row that did not move into the table's own word for it rather than into a state
    literal that would read as a settlement.
    """
    row = retained(admin_engine, tenant, execution_id)
    return {
        "success": success,
        "state": UNCHANGED if row.state == before else row.state,
        "tier": row.tier,
        "impact": row.impact,
        "claim_released": row.released_at is not None,
    }


def test_al27_the_fixture_caller_walks_every_branch_the_contract_describes(
    db, arcade_world, seeded, admin_engine
):
    """The whole exchange, every branch, against the contract the harness holds.

    The order is one an agent meets: a governed tool call that passes, the same call
    redelivered, a call that is denied, a call that waits for a human and the retry that
    follows the decision, a call of a toolkit nobody governs, and then the four arrivals the
    post hook table in `docs/ARCADE.md` distinguishes — a stated success, a stated failure, a
    body that states no result and a body too large to read — with the grant nobody reported
    on left to the sweep at the end.

    Two things are asserted about every one of them. The recorded answer fits
    `HOOK_CONTRACT["answer"]`: a 200, a code from the three the platform acts on, and no key
    beyond the two the contract describes. And the messages that produced it are the
    published shapes, because `FakeArcade` builds nothing else — the permit branch sends a
    pre hook carrying the fewest fields the contract allows, an empty context and a tool
    that describes itself not at all, and the redelivery sends every optional field at once.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    governed_bundle(db, world, approval_policies=APPROVE_RISKY)
    for branch, device in TARGETS.items():
        endpoint(admin_engine, world, device, DENIED if branch == "denial" else PERMITTED)
    admin = long_lived_admin(admin_engine, db, world)
    settled = {}
    with arcade_boundary(
        db,
        world,
        seeded,
        block=hook_block(post_bytes=2048),
        runtime=approving_runtime(db, world),
    ) as driver:
        caller = FakeArcade(driver.client, driver.token)

        # 1. The governed permit, on the smallest message the published contract allows: a
        # tool that reports nothing about itself and an empty context. Nothing about this
        # walk reports on it afterwards, which is what makes it the table's last row.
        permit = caller.pre(
            "governed-permit",
            execution_id="arcade-execution-1",
            tool=governed(),
            inputs={"device_id": TARGETS["governed-permit"]},
        )
        assert (permit.code, permit.error_message) == ("OK", None)
        unreported = correlated(admin_engine, tenant, "arcade-execution-1")
        assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]

        # 2. The same Arcade execution id again, this time carrying every optional field a
        # platform may send. It is answered from its own row and opens nothing new.
        repeat = caller.pre(
            "duplicate-pre",
            execution_id="arcade-execution-1",
            tool=governed(metadata=TOOL_METADATA),
            inputs={"device_id": TARGETS["governed-permit"]},
            context=tool_context(**FULL_CONTEXT),
        )
        assert (repeat.code, repeat.error_message) == ("OK", None)
        assert list(correlation_rows(admin_engine, tenant)) == ["arcade-execution-1"]
        assert correlated(admin_engine, tenant, "arcade-execution-1") == unreported
        assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]

        # 3. The denial. The agent is told the state and the execution the tenant now holds,
        # and nothing about which rule stopped it.
        denied = caller.pre(
            "denial",
            execution_id="arcade-execution-2",
            tool=governed(metadata=TOOL_METADATA),
            inputs={"device_id": TARGETS["denial"]},
        )
        assert denied.code == "CHECK_FAILED"
        assert denied.error_message is not None
        assert denied.error_message.startswith("DENIED execution=")

        # 4. The approval wait: a refusal that blocks the tool call, naming the page a human
        # decides on rather than leaving the agent to poll.
        waiting = caller.pre(
            "approval-wait",
            execution_id="arcade-execution-3",
            tool=governed(),
            inputs={"device_id": WORLD_DEVICE},
        )
        assert waiting.code == "CHECK_FAILED"
        assert waiting.error_message is not None
        assert waiting.error_message.startswith("PENDING_APPROVAL execution=")
        assert waiting.error_message.endswith(f"approvals={APPROVALS_PAGE}")
        approval = pending(admin_engine, tenant)
        decide_approval(db, world["human"], approval, "APPROVE", world["clock"], catalog=CATALOG)

        # 5. The retry, under the new Arcade execution id the platform mints per tool call.
        retried = caller.pre(
            "approved-retry",
            execution_id="arcade-execution-4",
            tool=governed(),
            inputs={"device_id": WORLD_DEVICE},
        )
        assert (retried.code, retried.error_message) == ("OK", None)
        assert correlated(admin_engine, tenant, "arcade-execution-4") == correlated(
            admin_engine, tenant, "arcade-execution-3"
        )

        # 6. The ungoverned toolkit: the operator's standing decision, taken with no kernel
        # call, so the tenant's chain does not move and no correlation row is opened.
        head = audit_head(admin_engine, tenant)
        passed = caller.pre(
            "ungoverned-pass",
            execution_id="arcade-execution-5",
            tool=tool_info(toolkit="gmail", name="SendEmail", version="1.0"),
            inputs={"recipient": "analyst@example.test"},
        )
        assert (passed.code, passed.error_message) == ("OK", None)
        assert audit_head(admin_engine, tenant) == head
        assert "arcade-execution-5" not in correlation_rows(admin_engine, tenant)

        # 7. A stated success, reported in the largest post hook the contract describes:
        # every optional field at once, which changes what settles not at all.
        granted = caller.pre(
            "success-grant",
            execution_id="arcade-execution-6",
            tool=governed(metadata=TOOL_METADATA),
            inputs={"device_id": TARGETS["success-grant"]},
        )
        assert granted.code == "OK"
        executed = correlated(admin_engine, tenant, "arcade-execution-6")
        stated = caller.post(
            "reported-success",
            execution_id="arcade-execution-6",
            tool=governed(metadata=TOOL_METADATA),
            context=tool_context(**FULL_CONTEXT),
            inputs={"device_id": TARGETS["success-grant"]},
            success=True,
            output={"value": {"status": "contained"}},
            execution_code="TOOL_OK",
            execution_error="",
        )
        assert (stated.code, stated.error_message) == ("OK", None)
        settled["reported_success"] = settlement(admin_engine, tenant, executed, success=True)
        row = correlation_rows(admin_engine, tenant)["arcade-execution-6"]
        # The reported inputs derive the request the decision froze, so the arrival that
        # carried them is recorded as agreeing with it rather than contradicting it.
        assert (row["denial_contradiction_at"], row["inputs_contradiction_at"]) == (None, None)

        # 8. The same statement delivered twice, which nothing documents as impossible. It
        # is answered, it moves the row once, and it reaches no kernel call at all: the
        # settled row holds no secret to present, so the tenant's chain does not move for
        # it — not even the audited rejection a report the kernel refuses would leave.
        chain = audit_head(admin_engine, tenant)
        again = caller.post(
            "duplicate-post",
            execution_id="arcade-execution-6",
            tool=governed(),
            success=True,
        )
        assert (again.code, again.error_message) == ("OK", None)
        assert audit_head(admin_engine, tenant) == chain
        assert (
            settlement(admin_engine, tenant, executed, success=True) == settled["reported_success"]
        )
        assert [
            step for step in transitions(admin_engine, tenant, executed) if step[1] == "EXECUTED"
        ] == [("DISPATCH_COMMITTED", "EXECUTED", "ASSERTED")]

        # 9. A stated failure, in the smallest post hook that states anything: the three
        # required fields and `success`. It costs the caller exactly what the success cost.
        failing = caller.pre(
            "failure-grant",
            execution_id="arcade-execution-7",
            tool=governed(),
            inputs={"device_id": TARGETS["failure-grant"]},
        )
        assert failing.code == "OK"
        failed = correlated(admin_engine, tenant, "arcade-execution-7")
        failure_answer = caller.post(
            "reported-failure",
            execution_id="arcade-execution-7",
            tool=governed(),
            success=False,
        )
        assert (failure_answer.code, failure_answer.error_message) == ("OK", None)
        settled["reported_failure"] = settlement(admin_engine, tenant, failed, success=False)

        # 10. An absent `success` beside a platform code and a platform message: the schema
        # makes the field optional, so this states no result at all, and neither of the two
        # strings beside it states one either.
        quiet = caller.pre(
            "silence-grant",
            execution_id="arcade-execution-8",
            tool=governed(),
            inputs={"device_id": TARGETS["silence-grant"]},
        )
        assert quiet.code == "OK"
        uncertain = correlated(admin_engine, tenant, "arcade-execution-8")
        silent = caller.post(
            "absent-success",
            execution_id="arcade-execution-8",
            tool=governed(),
            execution_code="VENDOR_TIMEOUT",
            execution_error="the vendor answered 500",
        )
        assert (silent.code, silent.error_message) == ("OK", None)
        settled["absent_success"] = settlement(admin_engine, tenant, uncertain, success=None)

        # 11. A body past this deployment's `post_bytes`, made large by the one optional
        # field that carries whatever the tool returned. Nothing is read, so nothing moves.
        large = caller.pre(
            "oversized-grant",
            execution_id="arcade-execution-9",
            tool=governed(),
            inputs={"device_id": TARGETS["oversized-grant"]},
        )
        assert large.code == "OK"
        unread = correlated(admin_engine, tenant, "arcade-execution-9")
        oversized = caller.post(
            "oversized-body",
            execution_id="arcade-execution-9",
            tool=governed(),
            success=True,
            output={"value": "vendor-output-marker" * 200},
        )
        assert (oversized.code, oversized.error_message) == ("OK", None)
        settled["unreadable_body"] = settlement(
            admin_engine, tenant, unread, success=None, before="DISPATCH_COMMITTED"
        )
        assert correlation_rows(admin_engine, tenant)["arcade-execution-9"]["settled_at"] is None

    # 12. No post hook at all, which is the grant of branch 1. It stands where admission
    # committed it until its report window closes, and the scheduled run then moves it into
    # the retained uncertainty an unread body leaves it in anyway.
    settled["no_post_hook"] = settlement(
        admin_engine, tenant, unreported, success=None, before="DISPATCH_COMMITTED"
    )
    world["clock"].value = grant_row(admin_engine, tenant, unreported)["report_expires_at"]
    swept = recover(db, admin, {}, clock=world["clock"])
    settled["no_post_hook"]["swept_to"] = retained(admin_engine, tenant, unreported).state

    # The contract as a whole. Every answer fits the shape a platform branches on, every
    # branch was walked, and what each arrival settled is the post hook table in `docs/ARCADE.md`.
    assert caller.unfit() == {}
    assert sorted(caller.shapes) == sorted(BRANCHES)
    assert {shape["code"] for shape in caller.shapes.values()} == {"OK", "CHECK_FAILED"}
    assert settled == HOOK_CONTRACT["settlement"]
    # The three grants this walk left open, asserted after the table rather than before it
    # so that a settlement moving is reported as the settlement it is: branch 1, the
    # approved retry, and the one whose report was too large to read.
    assert swept.swept == 3


def test_al27_the_id_class_and_the_framing_are_requirements_the_schema_does_not_carry(
    db, arcade_world, seeded, admin_engine
):
    """Two shapes `HOOK_CONTRACT` requires that Arcade's published schema leaves open.

    Both are questions about a platform nobody here has run, both are cheap to answer
    against a fixture and expensive to answer in a tenant, and both are written in the
    contract so that an integration guide can tell an operator what to check. An
    `execution_id` outside the kernel's key class blocks the tool call it was sent for,
    because it is refused rather than mangled into one. A post hook framed with a content
    type this surface does not admit is a 400, which is not a hook answer at all and which
    the published contract does not retry, so the settlement it carried is lost and the
    grant waits for the sweep.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    with arcade_boundary(db, world, seeded) as driver:
        caller = FakeArcade(driver.client, driver.token)
        assert re.fullmatch(EXECUTION_ID_PATTERN, UNKEYABLE_ID) is None
        refused = caller.pre(
            "unkeyable-id",
            execution_id=UNKEYABLE_ID,
            tool=governed(),
            inputs={"device_id": WORLD_DEVICE},
        )
        assert (refused.code, refused.error_message) == ("CHECK_FAILED", "UNSUPPORTED_EXECUTION_ID")
        # Refused ahead of the correlation row and ahead of the kernel: nothing was opened,
        # decided or reserved for a hook this deployment could not key on.
        assert execution_states(admin_engine, tenant) == []
        assert correlation_rows(admin_engine, tenant) == {}

        assert re.fullmatch(EXECUTION_ID_PATTERN, KEYABLE_ID) is not None
        granted = caller.pre(
            "keyable-id",
            execution_id=KEYABLE_ID,
            tool=governed(),
            inputs={"device_id": WORLD_DEVICE},
        )
        assert granted.code == "OK"
        execution_id = correlated(admin_engine, tenant, KEYABLE_ID)

        assert UNFRAMED.lower() not in {spelling.lower() for spelling in CONTENT_TYPES}
        lost = caller.post(
            "unframed-report",
            execution_id=KEYABLE_ID,
            tool=governed(),
            success=True,
            content_type=UNFRAMED,
        )
        assert lost.status == 400
        assert answer_unfit(caller.shapes["unframed-report"]) == (
            "status 400",
            "missing ['code']",
            "undocumented ['detail']",
            "code None",
        )
        assert retained(admin_engine, tenant, execution_id).state == "DISPATCH_COMMITTED"

        settling = caller.post(
            "framed-report",
            execution_id=KEYABLE_ID,
            tool=governed(),
            success=True,
            content_type=CONTENT_TYPES[1],
        )
        assert settling.code == "OK"
        assert answer_unfit(caller.shapes["framed-report"]) == ()
        assert retained(admin_engine, tenant, execution_id).state == "EXECUTED"


def test_al27_the_fixture_caller_builds_the_published_shapes_and_reaches_loopback_only():
    """What the caller refuses to do, which is what makes the walk above worth anything.

    A body carrying a field the published contract does not describe would drive a branch no
    platform can reach, and a message missing a required one would be a hook nobody has to
    answer. Neither is a thing this caller can build. It is also a protected mock: the client
    it is handed must address one of the loopback names, and an origin outside them is
    refused before anything is sent.
    """
    with pytest.raises(ContractError):
        post_body(execution_id="a", tool=tool_info(**GOVERNED_TOOL), status="done")
    with pytest.raises(ContractError):
        pre_body(execution_id="a", tool={"toolkit": "endpoint_mock", "name": "x"}, inputs={})
    with pytest.raises(ContractError):
        tool_context(api_key="a field the published context does not carry")
    with httpx.Client(base_url="https://arcade.invalid") as remote:
        with pytest.raises(ContractError):
            FakeArcade(remote, "synthetic-token")
    # One branch records one answer, so a walk cannot quietly overwrite what it already
    # asked. Driven against a transport that answers rather than a deployment, because what
    # is asserted is the caller's own bookkeeping.
    answered = httpx.MockTransport(lambda request: httpx.Response(200, json={"code": "OK"}))
    with httpx.Client(base_url="http://testserver", transport=answered) as client:
        caller = FakeArcade(client, "synthetic-token")
        sent = caller.pre(
            "once", execution_id="arcade-execution-1", tool=tool_info(**GOVERNED_TOOL), inputs={}
        )
        assert caller.shapes == {"once": sent.shape()}
        assert answer_unfit(sent.shape()) == ()
        with pytest.raises(ContractError):
            caller.pre(
                "once",
                execution_id="arcade-execution-1",
                tool=tool_info(**GOVERNED_TOOL),
                inputs={},
            )
