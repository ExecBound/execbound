# SPDX-License-Identifier: AGPL-3.0-only
"""The console API's decision coverage and unrouted reads, and the hold record on approvals
(AR15, AR18).

Real PostgreSQL. Both reads answer a workspace administrator only: an administrator seated in
one Space is refused, an approver is refused, and a personal access token of an administrator
may read them as it may read the approvers matrix. An approval item carries how many people
could decide it when it was held only for a reader with workspace-wide `access.manage`.
"""

from datetime import timedelta
from uuid import uuid4

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_approval_routing import AR15, assign, canonical_target, no_individual_scope
from test_console_api_tokens import application, auth, minted_for
from test_execution import provision_identity, request
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import approval_routing
from execbound.execution import admit
from execbound.notifications import matching_destinations

pytestmark = pytest.mark.integration

NUMBER = iter(range(2_000_000, 3_000_000))


def copy(admin_engine, world, source, target, space, *, created, held):
    """A copy of the held request `source` on `target` in `space`, with its approval as `held`
    gives it: (approval state, execution state, expires_at, required, reviewers_at_hold)."""
    tenant, execution = world["identity"].tenant_id, uuid4()
    state, execution_state, expires, required, recorded = held
    now = world["clock"].now()
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO execbound.executions
              (tenant_id,execution_id,principal_id,credential_id,intent_hash,wire_hash,plan_hash,
               canonical_target_id,bundle_id,frozen,state,created_at,changed_at,operation_id,
               owner_hash,settlement_tier,space_id,request_number)
            SELECT tenant_id,:e,principal_id,credential_id,
                   encode(sha256(convert_to(CAST(:e AS text),'UTF8')),'hex'),wire_hash,plan_hash,
                   :c,bundle_id,frozen,:state,:at,:at,:e,owner_hash,settlement_tier,:s,:n
              FROM execbound.executions WHERE tenant_id=:t AND execution_id=:source
            """),
            {
                "t": tenant,
                "e": execution,
                "c": target,
                "state": execution_state,
                "at": now - created,
                "s": space,
                "n": next(NUMBER),
                "source": source,
            },
        )
        conn.execute(
            text("""
            INSERT INTO execbound.approvals
              (tenant_id,approval_id,execution_id,principal_id,plan_hash,bundle_id,
               obligation_ids,expires_at,created_at,state,required_approvers,space_id,
               reviewers_at_hold)
            SELECT tenant_id,:a,:e,principal_id,plan_hash,bundle_id,obligation_ids,
                   :x,:at,:state,:required,:s,:recorded
              FROM execbound.approvals WHERE tenant_id=:t AND execution_id=:source
            """),
            {
                "t": tenant,
                "a": uuid4(),
                "e": execution,
                "x": now + expires,
                "at": now - created,
                "state": state,
                "required": required,
                "s": space,
                "recorded": recorded,
                "source": source,
            },
        )
        number = conn.execute(
            text(
                "SELECT request_number FROM execbound.executions "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution},
        ).scalar_one()
    return execution, f"EB-{number}"


OPEN = timedelta(minutes=10)
GONE = -timedelta(minutes=1)


@pytest.fixture
def unrouted(db, admin_engine, world):
    """Two Spaces with one pending approval nobody can decide (A), one quorum-2 approval one
    person can decide (B), one lapsed unrouted approval, one routed and one pre-record row."""
    tenant = world["identity"].tenant_id
    template = admit(db, world["identity"], request(world), world["clock"])
    assert template.view.state == "PENDING_APPROVAL"
    with admin_engine.begin() as conn:
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Bravo")
        seat(conn, tenant, second, world["human"].principal_id)
    source = template.view.execution_id
    nobody = canonical_target(admin_engine, world)
    _, nobody_ref = copy(
        admin_engine,
        world,
        source,
        nobody,
        first,
        created=timedelta(minutes=2),
        held=("PENDING", "PENDING_APPROVAL", OPEN, 1, 0),
    )
    short = canonical_target(admin_engine, world)
    short_execution, short_ref = copy(
        admin_engine,
        world,
        source,
        short,
        second,
        created=timedelta(minutes=1),
        held=("PENDING", "PENDING_APPROVAL", OPEN, 2, 1),
    )
    assign(admin_engine, world, [world["human"].principal_id], short, second)
    copy(
        admin_engine,
        world,
        source,
        canonical_target(admin_engine, world),
        first,
        created=timedelta(days=1),
        held=("EXPIRED", "STALE_AUTHORIZATION", GONE, 1, 0),
    )
    copy(
        admin_engine,
        world,
        source,
        canonical_target(admin_engine, world),
        first,
        created=timedelta(hours=1),
        held=("EXPIRED", "STALE_AUTHORIZATION", GONE, 1, None),
    )
    # Older than the window: not recent.
    copy(
        admin_engine,
        world,
        source,
        canonical_target(admin_engine, world),
        first,
        created=timedelta(days=8),
        held=("EXPIRED", "STALE_AUTHORIZATION", GONE, 1, 0),
    )
    return {
        "template": template.view,
        "short": (short_execution, short_ref),
        "nobody_ref": nobody_ref,
        "spaces": (first, second),
    }


def test_ar18_unrouted_counts_now_and_the_last_seven_days(
    db, runtime, admin_engine, world, unrouted
):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        response = client.get(API + "/approval-coverage/unrouted")
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
    body = response.json()
    assert (body["pending"], body["pending_nobody"], body["pending_truncated"]) == (2, 1, False)
    execution, ref = unrouted["short"]
    latest = body["pending_latest"]
    assert (latest["execution_id"], latest["request_ref"]) == (str(execution), ref)
    assert latest["space_id"] == str(unrouted["spaces"][1])
    assert latest["state"] == "PENDING"
    # The two open ones and the lapsed one; not the routed template, the row with no record or
    # the one past the window.
    assert body["recent"] == 3
    assert body["recent_latest"]["request_ref"] == ref


def test_ar18_a_seated_administrator_is_refused_both_reads(
    db, runtime, admin_engine, world, unrouted
):
    tenant = world["identity"].tenant_id
    seated = provision_identity(admin_engine, db, tenant, "ADMIN", world["clock"].now())
    with admin_engine.begin() as conn:
        seat(conn, tenant, default_space(conn, tenant), seated.principal_id, "ADMIN")
    with console_client(db, runtime, admin_engine, seated) as client:
        for path in ("/approval-coverage", "/approval-coverage/unrouted"):
            refused = client.get(API + path)
            assert refused.status_code == 403, refused.text
            assert refused.json()["code"] == "FORBIDDEN"


def test_ar18_an_approver_is_refused_both_reads(db, runtime, admin_engine, world, unrouted):
    with console_client(db, runtime, admin_engine, world["human"]) as client:
        for path in ("/approval-coverage", "/approval-coverage/unrouted"):
            refused = client.get(API + path)
            assert refused.status_code == 403, refused.text


def test_ar18_a_token_may_read_coverage_and_unrouted(db, runtime, admin_engine, world, unrouted):
    token = minted_for(runtime, world["admin"])
    with application(db, runtime) as client:
        for path in ("/approval-coverage", "/approval-coverage/unrouted"):
            answer = client.get(API + path, headers=auth(token))
            assert answer.status_code == 200, answer.text
    assert answer.json()["pending"] == 2


def test_ar18_only_a_workspace_administrator_sees_the_hold_record(
    db, runtime, admin_engine, world, unrouted
):
    approval = unrouted["template"].approval_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        others = client.get(API + "/approvals", params={"view": "others"}).json()["items"]
        mine = {item["approval_id"]: item for item in others}
        assert mine[str(approval)]["reviewers_at_hold"] == 1
        detail = client.get(API + f"/approvals/{approval}").json()
        assert detail["item"]["reviewers_at_hold"] == 1
    with console_client(db, runtime, admin_engine, world["human"]) as client:
        pending = client.get(API + "/approvals", params={"view": "pending"}).json()["items"]
        assert pending and all(item["reviewers_at_hold"] is None for item in pending)
        detail = client.get(API + f"/approvals/{approval}").json()
        assert detail["item"]["reviewers_at_hold"] is None


@pytest.mark.parametrize("case", list(AR15))
def test_ar15_the_three_counts_agree(db, runtime, admin_engine, world, case):
    setup, count, _ = AR15[case]
    setup(admin_engine, db, world)
    pending = admit(db, world["identity"], request(world), world["clock"])
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        others = client.get(API + "/approvals", params={"view": "others"}).json()["items"]
    [row] = [item for item in others if item["approval_id"] == str(pending.view.approval_id)]
    with db.transaction(tenant) as conn:
        space = conn.execute(
            text("SELECT space_id FROM execbound.approvals WHERE tenant_id=:t AND approval_id=:a"),
            {"t": tenant, "a": pending.view.approval_id},
        ).scalar_one()
        eligible = approval_routing.eligible_reviewers(
            conn, tenant, space, world["canonical"], "endpoint.isolate"
        )
        _, assigned = matching_destinations(conn, tenant, pending.view.approval_id, [])
    assert row["reviewers"] == eligible == assigned == count
    assert row["reviewers_at_hold"] == count


def test_the_unrouted_read_needs_no_individual_scope_to_answer(db, runtime, admin_engine, world):
    """With nothing held, both reads answer empty rather than refusing."""
    no_individual_scope(admin_engine, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        unrouted = client.get(API + "/approval-coverage/unrouted").json()
        coverage = client.get(API + "/approval-coverage").json()
    assert (unrouted["pending"], unrouted["recent"], unrouted["pending_latest"]) == (0, 0, None)
    assert [space["name"] for space in coverage["spaces"]] == ["Default"]
