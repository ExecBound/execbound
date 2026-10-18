# SPDX-License-Identifier: AGPL-3.0-only
"""The console API's approval routes (#333): the queue, the detail, the decision.

Every route is an approver's, as the pages are, and each is held to the harness's refusals:
a bearer credential refused and audited, no session answered with a typed code, and the
secret check over every response. On top of that: the queue scoped to the approver, the
detail in words with its continuation, a decision through `decide_approval` with its comment
in the audit event, a quorum of two needing two people, a decision during a stop answered
423, an expired approval refused with its code and audited as the form's expired token is,
an approval past its deadline out of the pending queue and into the lapsed one
(#426), and every refusal the form
makes, each with its typed code.
"""

import secrets
from datetime import timedelta
from uuid import uuid4

import pytest
from console_api_fixtures import (
    API,
    assert_no_secrets,
    console_client,
    refusals,
    rejections,
)
from space_fixtures import default_space, make_space, place, seat, unseat
from sqlalchemy import text
from test_approval_notifications import destination as webhook
from test_approval_quorum import activate, quorum_bundle, second_approver
from test_emergency_stop import audit
from test_execution import provision_identity, request, targets
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import pending
from test_monitoring_worker import receiver as receiver
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution import activate_stop, decide_approval, release_stop
from execbound.execution.models import ExecutionError
from execbound.notifications import deliver_pending
from execbound.operations import PRODUCTION_ACTIONS
from execbound.recovery_run import recover
from execbound.runtime import Runtime
from execbound.surfaces.console_api.errors import CODES
from execbound.surfaces.console_api.executions import STATE_WORDS
from execbound.surfaces.human import records as read_records
from execbound.surfaces.tokens import TokenKeys
from execbound_harness.demo import endpoint_bundle

ROUTES = (
    (API + "/approvals", "GET"),
    (API + "/approvals/{approval_id}", "GET"),
    (API + "/approvals/{approval_id}/decision", "POST"),
)


def detail(client, approval_id):
    return client.get(f"{API}/approvals/{approval_id}")


def decide(client, approval_id, continuation, decision="APPROVE", comment="", **extra):
    body = {"decision": decision, "comment": comment, "continuation": continuation, **extra}
    return client.post(f"{API}/approvals/{approval_id}/decision", body)


def test_the_queue_requires_assignments_even_for_an_administrator(db, runtime, admin_engine, world):
    view = pending(runtime, world)
    # A production target this approver is not assigned; it is pending for somebody else.
    [other] = targets(admin_engine, world, count=1, production=True)
    runtime.execute(world["identity"], other.model_dump_json().encode())
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "DELETE FROM execbound.approval_scopes WHERE approver_id=:p "
                "AND canonical_target_id<>:c"
            ),
            {"p": world["human"].principal_id, "c": world["canonical"]},
        )
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        response = approver.get(API + "/approvals")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["view"] == "pending" and body["next_cursor"] is None
        assert [item["approval_id"] for item in body["items"]] == [str(view.approval_id)]
        [item] = body["items"]
        assert item["action"] == "endpoint.isolate" and item["action_label"] == "Isolate endpoint"
        assert item["target"] == "device-01" and item["environment"] == "production"
        assert item["resource_class"] == "workstation"
        assert item["agent"]["principal_id"] == str(world["identity"].principal_id)
        assert item["approval_state"] == "PENDING" and item["execution_state"] == "PENDING_APPROVAL"
        assert item["required"] == 1 and item["recorded"] == 0 and item["mine"] is None
        assert item["total_seconds"] > 0 and item["deadline_clock"] == "approval deadline"
        assert body["server_time"]
        assert response.headers["Cache-Control"] == "no-store"
        assert_no_secrets(response)
        assert approver.get(API + "/approvals?view=decided").json()["items"] == []
        assert approver.get(API + "/approvals?view=later").json()["code"] == "INVALID_REQUEST"
        assert approver.get(API + "/approvals?cursor=!!").json()["code"] == "INVALID_REQUEST"
        assert approver.get(API + "/approvals?state=PENDING").status_code == 400
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(API + "/approvals").json()["items"] == []
        # The administrator reads it, as a record waiting on someone else, and cannot decide
        # it: no continuation is minted outside the reader's own review scope (#678).
        read = detail(admin, view.approval_id)
        assert read.status_code == 200, read.text
        assert read.json()["reviewing"] is False and read.json()["continuation"] is None
        assert decide(admin, view.approval_id, "x").status_code == 400  # Invalid continuation.


def test_the_detail_says_the_plan_in_words_with_its_facts_rules_quorum_and_deadline(
    db, runtime, admin_engine, world
):
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label='triage-agent-a' WHERE principal_id=:p"),
            {"p": world["identity"].principal_id},
        )
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        response = detail(approver, view.approval_id)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "pending" and body["continuation"]
        assert body["item"]["agent"]["label"] == "triage-agent-a"
        assert body["sentence"].startswith(
            "Isolate endpoint on device-01, a production workstation, requested by triage-agent-a"
        )
        names = {fact["name"]: fact for fact in body["facts"]}
        assert names["environment"]["value"] == "production"
        assert names["environment"]["source_kind"] == "inventory"
        assert names["environment"]["origin"] == "RESOLVED"
        assert names["environment"]["age_seconds"] >= 0 and names["environment"]["observed_at"]
        assert names["environment"]["permitted_writers"]
        [obligation] = body["obligations"]
        assert obligation["kind"] == "policy" and obligation["id"].startswith("policy:")
        assert obligation["sentence"].endswith("requires a person.")
        assert body["quorum"] == {"required": 1, "recorded": 0, "decisions": [], "mine": None}
        assert body["deadline"]["clock"] == "approval deadline"
        assert body["deadline"]["total_seconds"] == body["item"]["total_seconds"]
        assert body["effect"]["reversible"] is True
        assert body["effect"]["reversed_by"] == "Lift endpoint isolation"
        assert body["effect"]["provider"] == "mock_crowdstrike"
        assert body["effect"]["provider_operation"] == "contain"
        assert "Reversible by Lift endpoint isolation." in body["effect"]["sentence"]
        assert body["limits"] and body["limits"][0]["max_targets"] >= 1
        assert body["mode"] == "ENFORCE" and body["stop"] is None and body["notices"] == []
        assert body["plan_hash"] == view.plan_hash
        assert_no_secrets_but_the_continuation(response)
        assert detail(approver, uuid4()).json()["code"] == "NOT_FOUND"
        assert detail(approver, "not-a-uuid").json()["code"] == "NOT_FOUND"
        assert detail(approver, str(view.approval_id).upper()).json()["code"] == "NOT_FOUND"
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.approval_scopes SET active=false WHERE approver_id=:p"),
                {"p": world["human"].principal_id},
            )
        assert detail(approver, view.approval_id).status_code == 404


def assert_no_secrets_but_the_continuation(response) -> None:
    body = response.json()
    body.pop("continuation", None)
    from execbound.replay.verify import reject_secrets

    reject_secrets(body)
    assert response.headers.get_list("set-cookie") == []


def test_a_decision_goes_through_the_kernel_with_its_comment_and_lands_in_decided_today(
    db, runtime, admin_engine, world, live_provider
):
    tenant = world["identity"].tenant_id
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        continuation = detail(approver, view.approval_id).json()["continuation"]
        decided = decide(
            approver, view.approval_id, continuation, comment="  Confirmed with on-call <b>7</b>  "
        )
        assert decided.status_code == 200, decided.text
        assert decided.json() == {
            "approval_id": str(view.approval_id),
            "decision": "APPROVE",
            "approval_state": "APPROVED",
            "execution_state": "PENDING_APPROVAL",
            "required": 1,
            "recorded": 1,
        }
        assert_no_secrets(decided)
        [approved] = [
            t
            for t in audit(admin_engine, tenant, "approval.transition")
            if t["to_state"] == "APPROVED"
        ]
        assert approved["comment"] == "Confirmed with on-call <b>7</b>"
        after = detail(approver, view.approval_id).json()
        assert after["status"] == "settled" and after["continuation"] is None
        assert after["quorum"]["mine"] == "APPROVE" and after["item"]["decided_at"]
        assert pending(runtime, world).state == "EXECUTED"
        assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 1
        assert approver.get(API + "/approvals").json()["items"] == []
        today = approver.get(API + "/approvals?view=decided").json()
        assert [item["approval_id"] for item in today["items"]] == [str(view.approval_id)]
        assert today["items"][0]["approval_state"] == "CONSUMED"
        # The same person again: the kernel refuses, and the code says the decision stands.
        again = decide(approver, view.approval_id, continuation)
        assert again.status_code == 409 and again.json()["code"] == "ALREADY_DECIDED"


def test_another_tenants_approver_can_neither_see_nor_decide_an_approval(
    db, runtime, admin_engine, world, seeded, live_provider
):
    """An approval in one tenant does not exist for an approver of another (CR3), even
    one holding the real continuation, which is bound to its own tenant and approver."""
    tenant = world["identity"].tenant_id
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        continuation = detail(approver, view.approval_id).json()["continuation"]
    other_tenant = seeded["tenants"][1]
    assert other_tenant != tenant
    stranger = provision_identity(
        admin_engine, db, other_tenant, "HUMAN_APPROVER", world["clock"].now()
    )
    with console_client(db, runtime, admin_engine, stranger) as foreign:
        assert foreign.get(API + "/approvals").json()["items"] == []
        assert foreign.get(API + "/approvals?view=decided").json()["items"] == []
        hidden = detail(foreign, view.approval_id)
        assert hidden.status_code == 404 and hidden.json()["code"] == "NOT_FOUND"
        refused = decide(foreign, view.approval_id, continuation)
        # The continuation is bound to its own tenant and approver, so it does not verify here:
        # the answer any stale continuation gets, which says nothing about whether it exists.
        assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_CONTINUATION")
    # Nothing moved: the approval still waits for its own approver, and nothing ran.
    assert pending(runtime, world).state == "PENDING_APPROVAL"
    assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 0


def test_a_denial_without_a_comment_leaves_the_payload_unchanged(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        continuation = detail(approver, view.approval_id).json()["continuation"]
        denied = decide(approver, view.approval_id, continuation, decision="DENY")
        assert denied.status_code == 200 and denied.json()["approval_state"] == "DENIED"
        assert denied.json()["execution_state"] == "DENIED"
    [event] = [
        t for t in audit(admin_engine, tenant, "approval.transition") if t["to_state"] == "DENIED"
    ]
    assert "comment" not in event


def test_a_quorum_of_two_needs_two_different_people(db, runtime, admin_engine, world):
    activate(db, world, quorum_bundle(world))
    other = second_approver(admin_engine, db, world)
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as first:
        body = detail(first, view.approval_id).json()
        assert body["quorum"]["required"] == 2 and body["item"]["required"] == 2
        [obligation] = body["obligations"]
        assert obligation["kind"] == "policy"
        recorded = decide(first, view.approval_id, body["continuation"], comment="First of two")
        assert recorded.status_code == 200, recorded.text
        assert recorded.json()["approval_state"] == "PENDING"
        assert recorded.json()["recorded"] == 1 and recorded.json()["required"] == 2
        waiting = detail(first, view.approval_id).json()
        assert waiting["status"] == "decided" and waiting["continuation"] is None
        assert waiting["quorum"]["recorded"] == 1 and waiting["quorum"]["mine"] == "APPROVE"
        [decision] = waiting["quorum"]["decisions"]
        assert decision["principal_id"] == str(world["human"].principal_id)
        # Still pending, so still in the queue, and marked as mine.
        [item] = first.get(API + "/approvals").json()["items"]
        assert item["mine"] == "APPROVE" and item["recorded"] == 1
        # The same person, a second time, is refused whatever token they hold.
        repeated = decide(first, view.approval_id, body["continuation"])
        assert repeated.status_code == 409 and repeated.json()["code"] == "ALREADY_DECIDED"
    with console_client(db, runtime, admin_engine, other) as second:
        page = detail(second, view.approval_id).json()
        assert page["status"] == "pending" and page["quorum"]["recorded"] == 1
        done = decide(second, view.approval_id, page["continuation"])
        assert done.status_code == 200 and done.json()["approval_state"] == "APPROVED"
        assert done.json()["recorded"] == 2
    [recorded_event] = audit(
        admin_engine, world["identity"].tenant_id, "approval.decision_recorded"
    )
    assert recorded_event["comment"] == "First of two"


def test_a_decision_during_a_stop_is_refused_423_and_the_detail_says_why(
    db, runtime, admin_engine, world
):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        continuation = detail(approver, view.approval_id).json()["continuation"]
        activate_stop(db, world["admin"], "Contain agent 7", world["clock"])
        paused = detail(approver, view.approval_id).json()
        assert paused["status"] == "paused" and paused["continuation"] is None
        assert paused["stop"]["reason"] == "Contain agent 7" and paused["stop"]["stopped_at"]
        refused = decide(approver, view.approval_id, continuation)
        assert refused.status_code == 423, refused.text
        assert refused.json() == {"code": "STOPPED", "detail": CODES["STOPPED"][1]}
        release_stop(db, world["admin"], "Reviewed", world["clock"])
        resumed = detail(approver, view.approval_id).json()
        assert resumed["status"] == "pending" and resumed["continuation"]
        assert decide(approver, view.approval_id, continuation).status_code == 200


def test_an_expired_approval_is_refused_with_its_code_and_audited_as_the_form_is(
    db, runtime, admin_engine, world
):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        continuation = detail(approver, view.approval_id).json()["continuation"]
        before = rejections(admin_engine, world["human"])
        world["clock"].value += timedelta(seconds=121)
        expired = detail(approver, view.approval_id).json()
        assert expired["status"] == "expired" and expired["continuation"] is None
        refused = decide(approver, view.approval_id, continuation)
        assert refused.status_code == 409, refused.text
        assert refused.json()["code"] == "APPROVAL_EXPIRED"
        assert rejections(admin_engine, world["human"]) == before + 1
        with admin_engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"),
                {"t": str(world["identity"].tenant_id)},
            )
            reasons = (
                conn.execute(
                    text(
                        "SELECT payload->>'reason' FROM execbound.audit_events "
                        "WHERE tenant_id=:t AND actor_id=:p AND kind='execution.rejected' "
                        "ORDER BY sequence DESC LIMIT 1"
                    ),
                    {"t": world["identity"].tenant_id, "p": world["human"].principal_id},
                )
                .scalars()
                .all()
            )
        assert reasons == ["INVALID_CONTINUATION"]


def test_a_lapsed_approval_leaves_pending_and_is_read_as_lapsed(db, runtime, admin_engine, world):
    """#426: `view=pending` is what an approver can still decide, so an approval past its
    deadline is not in it, and the Home page's `awaiting` list, which is the same read, is
    not either. The approval itself does not disappear: `view=lapsed` holds it, with the
    moment it lapsed on the row, because an approval that expired unanswered is a fact."""
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        queue = approver.get(API + "/approvals")
        assert [item["approval_id"] for item in queue.json()["items"]] == [str(view.approval_id)]
        assert approver.get(API + "/approvals?view=lapsed").json()["items"] == []
        before = approver.get(API + "/overview").json()
        assert [row["approval_id"] for row in before["awaiting"]] == [str(view.approval_id)]

        world["clock"].value += timedelta(seconds=121)

        still = approver.get(API + "/approvals")
        assert still.status_code == 200, still.text
        assert still.json()["view"] == "pending" and still.json()["items"] == []
        # Nothing invites a decision that cannot be made: the Home card reads the same list.
        assert approver.get(API + "/overview").json()["awaiting"] == []
        # Nobody decided it, so it is not in today's decisions either.
        assert approver.get(API + "/approvals?view=decided").json()["items"] == []

        lapsed = approver.get(API + "/approvals?view=lapsed")
        assert lapsed.status_code == 200, lapsed.text
        body = lapsed.json()
        assert body["view"] == "lapsed"
        [item] = body["items"]
        assert item["approval_id"] == str(view.approval_id)
        assert item["approval_state"] == "PENDING" and item["execution_state"] == "PENDING_APPROVAL"
        # The moment it lapsed travels with the row; the page prints it instead of 0:00.
        assert item["expires_at"] < body["server_time"]
        assert_no_secrets(lapsed)
        # The detail still reads, and says why nothing can be decided.
        assert detail(approver, view.approval_id).json()["status"] == "expired"
        assert approver.get(API + "/approvals?view=nonsense").status_code == 400

        # And once the recovery run has ended it, it is still a fact somebody can read:
        # the row stays in `view=lapsed`, now `EXPIRED` with its execution stale, and the
        # detail reads the same. Ending an approval never removes it from the one view
        # that says it ran out of time (#426's kernel half).
        world["clock"].value += timedelta(seconds=301)
        assert recover(db, world["admin"], {}, clock=world["clock"]).expired == 1
        ended = approver.get(API + "/approvals?view=lapsed")
        assert ended.status_code == 200, ended.text
        [after] = ended.json()["items"]
        assert after["approval_id"] == str(view.approval_id)
        assert after["approval_state"] == "EXPIRED"
        assert after["execution_state"] == "STALE_AUTHORIZATION"
        assert approver.get(API + "/approvals").json()["items"] == []
        assert approver.get(API + "/overview").json()["awaiting"] == []
        assert detail(approver, view.approval_id).json()["status"] == "expired"


def test_every_form_refusal_has_a_typed_code(db, runtime, admin_engine, world):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        continuation = detail(approver, view.approval_id).json()["continuation"]
        before = rejections(admin_engine, world["human"])
        # The body: an unknown decision, a comment over the bound, a secret in the comment,
        # an unknown field, a missing continuation.
        wrong = decide(approver, view.approval_id, continuation, decision="MAYBE")
        assert wrong.status_code == 400 and wrong.json()["fields"] == ["decision"]
        assert decide(approver, view.approval_id, continuation, comment="x" * 501).json()[
            "fields"
        ] == ["comment"]
        secret = decide(
            approver, view.approval_id, continuation, comment="Bearer eb1.aaaa.bbbb.cccc"
        )
        assert secret.status_code == 400 and secret.json()["fields"] == ["comment"]
        # The kernel refused that one itself and audited it, as it does for the form.
        assert rejections(admin_engine, world["human"]) == before + 1
        assert decide(approver, view.approval_id, continuation, note="x").json()["fields"] == [
            "note"
        ]
        missing = approver.post(
            f"{API}/approvals/{view.approval_id}/decision", {"decision": "DENY"}
        )
        assert missing.status_code == 400 and missing.json()["fields"] == ["continuation"]
        assert rejections(admin_engine, world["human"]) == before + 1
        # The continuation: forged, or for another approval, is audited as the form's is.
        forged = decide(approver, view.approval_id, continuation[:-4] + "0000")
        assert forged.status_code == 400 and forged.json()["code"] == "INVALID_CONTINUATION"
        other = decide(approver, uuid4(), continuation)
        assert other.status_code == 400 and other.json()["code"] == "INVALID_CONTINUATION"
        assert rejections(admin_engine, world["human"]) == before + 3
        # The mutation guard: no token, wrong Origin, the wrong content type.
        body = {"decision": "APPROVE", "comment": "", "continuation": continuation}
        path = f"{API}/approvals/{view.approval_id}/decision"
        assert approver.post(path, body, csrf=None).json()["code"] == "INVALID_CSRF"
        assert approver.post(path, body, origin="http://evil.example").status_code == 403
        assert approver.post(path, body, content_type="text/plain").status_code == 415
        # Out of scope now: the record the continuation names is nothing to this approver.
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.approval_scopes SET active=false WHERE approver_id=:p"),
                {"p": world["human"].principal_id},
            )
        gone = decide(approver, view.approval_id, continuation)
        assert gone.status_code == 404 and gone.json()["code"] == "NOT_FOUND"
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.approval_scopes SET active=true WHERE approver_id=:p"),
                {"p": world["human"].principal_id},
            )
        # Nothing above decided anything.
        assert detail(approver, view.approval_id).json()["status"] == "pending"


def test_a_bearer_credential_and_a_missing_session_are_refused_on_every_route(
    db, runtime, seeded, admin_engine, world
):
    for path, method in ROUTES:
        concrete = path.format(approval_id=uuid4())
        results = refusals(db, runtime, seeded, admin_engine, world, concrete, method)
        assert results["bearer"].status_code == 403, (concrete, results["bearer"].text)
        assert results["bearer"].json()["code"] == "FORBIDDEN"
        assert results["audited"] == 1, concrete
        assert results["no_session"].status_code == 401, concrete
        assert results["no_session"].json()["code"] == "SESSION_REQUIRED"


def test_provider_markup_travels_as_data(db, runtime, admin_engine, world):
    markup = "<b>device</b><script>alert(1)</script>"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET provider_id=:m "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"m": markup, "t": world["identity"].tenant_id, "r": world["target"]},
        )
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        response = detail(approver, view.approval_id)
        assert response.headers["content-type"].startswith("application/json")
        body = response.json()
        assert body["item"]["target"] == markup and markup in body["sentence"]
        [item] = approver.get(API + "/approvals").json()["items"]
        assert item["target"] == markup


def test_the_catalog_names_what_reverses_each_action():
    reversed_by = {spec.action: spec.reversed_by for spec in PRODUCTION_ACTIONS.specs}
    assert reversed_by == {
        "endpoint.isolate": "endpoint.lift_isolation",
        "endpoint.lift_isolation": "endpoint.isolate",
        "identity.disable": "identity.enable",
        "identity.enable": "identity.disable",
        "identity.revoke_sessions": None,
        "identity.reset_password": None,
    }


def test_a_kernel_conflict_the_route_does_not_name_answers_conflict_not_the_assistants_copy(
    db, runtime, admin_engine, world, monkeypatch
):
    """An execution error the decision route does not translate reaches the app's handler and
    is answered by its status alone. `INVALID_BUNDLE` is a 409, and a 409 with no code of its
    own must read as the generic conflict, not as "The assistant could not draft that rule."
    """
    from execbound.execution.models import ExecutionError
    from execbound.surfaces.console_api import approvals

    def conflicting(*args, **kwargs):
        raise ExecutionError("INVALID_BUNDLE")

    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        continuation = detail(approver, view.approval_id).json()["continuation"]
        monkeypatch.setattr(approvals, "decide_approval", conflicting)
        refused = decide(approver, view.approval_id, continuation)
        assert refused.status_code == 409, refused.text
        assert refused.json() == {"code": "CONFLICT", "detail": CODES["CONFLICT"][1]}
        assert_no_secrets(refused)


def _number(admin_engine, principal_id) -> int:
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT number FROM execbound.principals WHERE principal_id=:p"),
            {"p": principal_id},
        ).scalar_one()


def test_queue_and_detail_carry_the_agents_number(db, runtime, admin_engine, world):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        [queued] = approver.get(API + "/approvals").json()["items"]
        item = detail(approver, view.approval_id).json()["item"]
    agent = {"principal_id": str(world["identity"].principal_id), "label": None, "number": 1}
    assert queued["agent"] == agent and item["agent"] == agent


def test_decisions_carry_kind_and_number(db, runtime, admin_engine, world):
    """A quorum of two, so the first decision is on the detail while the approval still waits."""
    activate(db, world, quorum_bundle(world, required=2))
    second = second_approver(admin_engine, db, world)
    view = pending(runtime, world)
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    with console_client(db, runtime, admin_engine, second) as approver:
        [decided] = detail(approver, view.approval_id).json()["quorum"]["decisions"]
    assert decided["principal_id"] == str(world["human"].principal_id)
    assert (decided["kind"], decided["label"]) == ("HUMAN_APPROVER", None)
    assert decided["number"] == _number(admin_engine, world["human"].principal_id)


def test_the_item_words_its_execution_state(db, runtime, admin_engine, world, live_provider):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        held = detail(approver, view.approval_id).json()["item"]
        assert held["execution_state"] == "PENDING_APPROVAL"
        assert held["execution_state_label"] == STATE_WORDS["PENDING_APPROVAL"]
        decide(
            approver, view.approval_id, detail(approver, view.approval_id).json()["continuation"]
        )
        pending(runtime, world)
        settled = detail(approver, view.approval_id).json()["item"]
    assert settled["execution_state"] == "EXECUTED"
    assert settled["execution_state_label"] == STATE_WORDS["EXECUTED"]


def test_the_detail_sentence_names_an_unlabelled_agent_by_number(db, runtime, admin_engine, world):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        sentence = detail(approver, view.approval_id).json()["sentence"]
    assert "requested by Agent 1 at " in sentence and sentence.endswith(" UTC.")
    assert str(world["identity"].principal_id)[:8] not in sentence


# Waiting on others (#678): an administrator reads the approvals they are not assigned to
# decide, with how many people can decide each, and can never decide one from that read.

ISOLATE = "endpoint.isolate"


def _tenant(conn, tenant) -> None:
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def _canonical(admin_engine, execution_id):
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT canonical_target_id FROM execbound.executions WHERE execution_id=:e"),
            {"e": execution_id},
        ).scalar_one()


def _assign(admin_engine, tenant, principal, canonical, space=None, action=ISOLATE) -> None:
    """One review assignment, upserted as `admin_assign_approver` upserts it."""
    with admin_engine.begin() as conn:
        _tenant(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes "
                "(tenant_id, approver_id, canonical_target_id, action, space_id) "
                "VALUES (:t, :p, :c, :a, :s) "
                "ON CONFLICT (tenant_id, approver_id, canonical_target_id, action) "
                "DO UPDATE SET active = true, space_id = excluded.space_id"
            ),
            {
                "t": tenant,
                "p": principal,
                "c": canonical,
                "a": action,
                "s": space or default_space(conn, tenant),
            },
        )


def _held(runtime, admin_engine, world):
    """A pending approval on a fresh production target, which `targets` assigns to the world's
    approver alone."""
    [wire] = targets(admin_engine, world, count=1, production=True)
    return runtime.execute(world["identity"], wire.model_dump_json().encode())


def _session(db, world, who):
    from execbound.surfaces.sessions import issue_session, load_session

    return load_session(
        db, issue_session(db, world[who], clock=world["clock"]).token, clock=world["clock"]
    )


def _ids(rows):
    return [row["execution_id"] for row in rows]


def _approval(admin_engine, approval_id):
    with admin_engine.connect() as conn:
        state = conn.execute(
            text("SELECT state FROM execbound.approvals WHERE approval_id=:a"),
            {"a": approval_id},
        ).scalar_one()
        decided = conn.execute(
            text("SELECT count(*) FROM execbound.approval_decisions WHERE approval_id=:a"),
            {"a": approval_id},
        ).scalar_one()
    return state, decided


def test_records_refuses_others_to_anyone_but_an_administrator_reading_outside_review(
    db, runtime, admin_engine, world
):
    pending(runtime, world)
    approver = _session(db, world, "human")
    admin = _session(db, world, "admin")
    for session, reviewing in ((approver, False), (approver, True), (admin, True)):
        with pytest.raises(ExecutionError) as refused:
            read_records(runtime, session, pending=True, others=True, reviewing=reviewing)
        assert refused.value.code == "INVALID_IDENTITY"
    assert len(read_records(runtime, admin, pending=True, others=True)) == 1


def test_others_is_the_complement_of_the_administrators_own_scope(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    theirs = pending(runtime, world)
    ours = _held(runtime, admin_engine, world)
    _assign(
        admin_engine,
        tenant,
        world["admin"].principal_id,
        _canonical(admin_engine, ours.execution_id),
    )
    admin = _session(db, world, "admin")
    assert _ids(read_records(runtime, admin, pending=True, others=True)) == [theirs.execution_id]
    assert _ids(read_records(runtime, admin, pending=True, reviewing=True)) == [ours.execution_id]


def test_an_administrator_sees_approvals_waiting_on_others_and_cannot_decide_them(
    db, runtime, admin_engine, world
):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        own = detail(approver, view.approval_id).json()
        borrowed = own["continuation"]
        assert borrowed and own["reviewing"] is True
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        listed = admin.get(API + "/approvals?view=others")
        assert listed.status_code == 200, listed.text
        assert_no_secrets(listed)
        body = listed.json()
        assert body["view"] == "others"
        [item] = body["items"]
        assert item["approval_id"] == str(view.approval_id)
        assert (item["reviewers"], item["reviewers_left"], item["assigned_to_you"]) == (1, 1, False)
        assert item["expires_at"] > body["server_time"]
        assert admin.get(API + "/approvals").json()["items"] == []
        read = detail(admin, view.approval_id)
        assert read.status_code == 200, read.text
        assert_no_secrets(read)
        page = read.json()
        assert page["reviewing"] is False and page["continuation"] is None
        assert page["status"] == "pending" and page["your_review_elsewhere"] is None
        assert (page["item"]["reviewers"], page["item"]["reviewers_left"]) == (1, 1)
        assert page["item"]["assigned_to_you"] is False
        before = rejections(admin_engine, world["admin"])
        refused = decide(admin, view.approval_id, borrowed)
        assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_CONTINUATION")
        assert rejections(admin_engine, world["admin"]) == before + 1
    assert _approval(admin_engine, view.approval_id) == ("PENDING", 0)


def test_waiting_on_others_is_an_administrators_view(db, runtime, admin_engine, world):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        refused = approver.get(API + "/approvals?view=others")
        assert (refused.status_code, refused.json()["code"]) == (403, "FORBIDDEN")
        [item] = approver.get(API + "/approvals").json()["items"]
        page = detail(approver, view.approval_id).json()
        for row in (item, page["item"]):
            assert row["reviewers"] is None and row["reviewers_left"] is None
            assert row["assigned_to_you"] is None
        assert page["your_review_elsewhere"] is None and page["reviewing"] is True


def test_an_approval_the_administrator_reviews_is_not_waiting_on_others(
    db, runtime, admin_engine, world
):
    view = pending(runtime, world)
    _assign(
        admin_engine, world["identity"].tenant_id, world["admin"].principal_id, world["canonical"]
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        [item] = admin.get(API + "/approvals").json()["items"]
        assert item["approval_id"] == str(view.approval_id)
        assert (item["reviewers"], item["reviewers_left"], item["assigned_to_you"]) == (2, 2, True)
        assert admin.get(API + "/approvals?view=others").json()["items"] == []
        page = detail(admin, view.approval_id).json()
        assert page["reviewing"] is True and page["continuation"]


def test_waiting_on_others_stays_inside_the_administrators_spaces(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    inside = pending(runtime, world)
    outside = _held(runtime, admin_engine, world)
    with admin_engine.begin() as conn:
        _tenant(conn, tenant)
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer B")
        for table in ("executions", "approvals"):
            place(conn, tenant, table, "execution_id", outside.execution_id, second)
        seat(conn, tenant, second, world["human"].principal_id)
        seat(conn, tenant, first, world["admin"].principal_id, "ADMIN")
    _assign(
        admin_engine,
        tenant,
        world["human"].principal_id,
        _canonical(admin_engine, outside.execution_id),
        second,
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        listed = admin.get(API + "/approvals?view=others").json()["items"]
        assert [item["approval_id"] for item in listed] == [str(inside.approval_id)]
        hidden = detail(admin, outside.approval_id)
        assert (hidden.status_code, hidden.json()["code"]) == (404, "NOT_FOUND")


def test_the_reviewer_count_is_people_who_can_open_the_record(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    activate(db, world, quorum_bundle(world, required=2))
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        [item] = admin.get(API + "/approvals?view=others").json()["items"]
        # Two approvals needed, one person who can give one: the quorum cannot be reached.
        assert (item["required"], item["recorded"]) == (2, 0)
        assert (item["reviewers"], item["reviewers_left"]) == (1, 1)
        with admin_engine.begin() as conn:
            _tenant(conn, tenant)
            unseat(conn, tenant, default_space(conn, tenant), world["human"].principal_id)
        [item] = admin.get(API + "/approvals?view=others").json()["items"]
        assert item["approval_id"] == str(view.approval_id)
        assert (item["reviewers"], item["reviewers_left"]) == (0, 0)
        assert detail(admin, view.approval_id).json()["item"]["reviewers"] == 0


def test_an_administrators_lapsed_view_covers_every_reviewer(db, runtime, admin_engine, world):
    view = pending(runtime, world)
    other = second_approver(admin_engine, db, world)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.approval_scopes SET active=false WHERE approver_id=:p"),
            {"p": other.principal_id},
        )
    world["clock"].value += timedelta(seconds=121)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        lapsed = admin.get(API + "/approvals?view=lapsed").json()["items"]
        assert [item["approval_id"] for item in lapsed] == [str(view.approval_id)]
        assert lapsed[0]["assigned_to_you"] is False
    with console_client(db, runtime, admin_engine, other) as stranger:
        assert stranger.get(API + "/approvals?view=lapsed").json()["items"] == []
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        lapsed = approver.get(API + "/approvals?view=lapsed").json()["items"]
        assert [item["approval_id"] for item in lapsed] == [str(view.approval_id)]


def test_assigning_yourself_moves_a_review_from_another_space(db, runtime, admin_engine, world):
    """The upsert keyed without the space (0045) moves an existing review; this pins it."""
    tenant = world["identity"].tenant_id
    admin_id = world["admin"].principal_id
    here = pending(runtime, world)
    # The same agent asking again with the same intent is answered with its pending request,
    # so the first one's intent is set apart on the owner connection: two pending approvals of
    # the same action on the same target, one per space, which is what an agent per space has.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET intent_hash=repeat('0', 64) WHERE execution_id=:e"
            ),
            {"e": here.execution_id},
        )
    there = runtime.execute(
        world["identity"], request(world, idempotency_key="retry-2").model_dump_json().encode()
    )
    assert there.approval_id != here.approval_id
    with admin_engine.begin() as conn:
        _tenant(conn, tenant)
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Customer Y")
        for table in ("executions", "approvals"):
            place(conn, tenant, table, "execution_id", there.execution_id, second)
    _assign(admin_engine, tenant, admin_id, world["canonical"], second)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert [item["approval_id"] for item in admin.get(API + "/approvals").json()["items"]] == [
            str(there.approval_id)
        ]
        page = detail(admin, here.approval_id).json()
        assert page["reviewing"] is False
        assert page["your_review_elsewhere"] == {"space_id": str(second), "name": "Customer Y"}
        assert detail(admin, there.approval_id).json()["your_review_elsewhere"] is None
        before = len(audit(admin_engine, tenant, "approval_scope.assigned"))
        assert admin.post(API + "/session/space", {"space_id": str(first)}).status_code == 200
        moved = admin.post(
            f"{API}/people/{admin_id}/scopes/assign",
            {"target": str(world["canonical"]), "action": ISOLATE},
        )
        assert moved.status_code == 200, moved.text
        assert len(audit(admin_engine, tenant, "approval_scope.assigned")) == before + 1
        assert admin.post(API + "/session/space", {"space_id": None}).status_code == 200
        mine = admin.get(API + "/approvals").json()["items"]
        assert [item["approval_id"] for item in mine] == [str(here.approval_id)]
        others = admin.get(API + "/approvals?view=others").json()["items"]
        assert [item["approval_id"] for item in others] == [str(there.approval_id)]
        now = detail(admin, here.approval_id).json()
        assert now["reviewing"] is True and now["continuation"]
        assert now["your_review_elsewhere"] is None


def test_the_detail_carries_the_cores_approval_link(db, runtime, admin_engine, world):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        assert detail(approver, view.approval_id).json()["link_path"] == (
            f"/approvals/{view.approval_id}"
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert detail(admin, view.approval_id).json()["link_path"] == (
            f"/approvals/{view.approval_id}"
        )


# When the message reached its approver, against the deadline (#678), driven through the real
# drain on the injected clock, never through hand-written notification rows.
def _hooked(db, world, connector, receiver):
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    return Runtime(
        db,
        [connector],
        clock=world["clock"],
        keys=keys,
        approval_url="http://127.0.0.1/approvals",
        notifications=[webhook(world, receiver, "soc")],
    )


def _drain(db, world, hooked):
    return deliver_pending(
        db,
        world["admin"],
        hooked.notifications,
        approval_url=hooked.approval_url or "",
        clock=world["clock"],
    )


def _expiry(admin_engine, approval_id):
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT expires_at FROM execbound.approvals WHERE approval_id=:a"),
            {"a": approval_id},
        ).scalar_one()


def _sweep(db, world, admin_engine, approval_id):
    world["clock"].value = _expiry(admin_engine, approval_id) + timedelta(seconds=301)
    assert recover(db, world["admin"], {}, clock=world["clock"]).expired == 1


def _in_time(db, world, admin_engine, hooked, view):
    world["clock"].value += timedelta(seconds=5)
    _drain(db, world, hooked)


def _inside_the_margin(db, world, admin_engine, hooked, view):
    world["clock"].value = _expiry(admin_engine, view.approval_id) - timedelta(seconds=10)
    _drain(db, world, hooked)


def _swept_first(db, world, admin_engine, hooked, view):
    _sweep(db, world, admin_engine, view.approval_id)
    _drain(db, world, hooked)


def _decided_first(db, world, admin_engine, hooked, view):
    decide_approval(db, world["human"], view.approval_id, "DENY", world["clock"])
    _drain(db, world, hooked)


def _approved_and_unused(db, world, admin_engine, hooked, view):
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    _sweep(db, world, admin_engine, view.approval_id)
    _drain(db, world, hooked)


def _invalidated_first(db, world, admin_engine, hooked, view):
    activate(
        db,
        world,
        endpoint_bundle(world["identity"].tenant_id, world["account"], mapping_version="map-v1"),
    )
    again = hooked.execute(world["identity"], request(world).model_dump_json().encode())
    assert again.state == "STALE_AUTHORIZATION"
    _drain(db, world, hooked)


@pytest.mark.parametrize(
    ("happened", "counts", "late", "notified"),
    [
        (_in_time, {"delivered": 1}, False, "notified 1 of 1 destinations"),
        (_inside_the_margin, {"lapsed": 1}, True, None),
        (_swept_first, {"lapsed": 1}, True, None),
        (_decided_first, {"closed": 1}, False, "notification failed"),
        (_approved_and_unused, {"closed": 1}, False, "notification failed"),
        (_invalidated_first, {"withdrawn": 1}, False, "notification failed"),
    ],
    ids=["in-time", "inside-the-margin", "swept", "decided", "approved-unused", "invalidated"],
)
def test_the_delivery_view_says_when_the_message_arrived(
    db, admin_engine, world, connector, receiver, happened, counts, late, notified
):
    hooked = _hooked(db, world, connector, receiver)
    view = pending(hooked, world)
    with console_client(db, hooked, admin_engine, world["human"]) as approver:
        before = detail(approver, view.approval_id).json()["item"]["delivery"]
        assert before["pending"] == 1 and before["last_delivered_at"] is None
        assert before["margin_seconds"] is None and before["late"] is False
        happened(db, world, admin_engine, hooked, view)
        read = detail(approver, view.approval_id)
        assert read.status_code == 200, read.text
        assert_no_secrets(read)
        item = read.json()["item"]
    delivery = item["delivery"]
    keys = ("delivered", "pending", "failed", "lapsed", "closed", "withdrawn")
    assert {key: delivery[key] for key in keys} == {key: counts.get(key, 0) for key in keys}
    assert delivery["late"] is late
    assert item["notified"] == notified
    if counts.get("delivered"):
        # Delivered five seconds after the request, 115 s before its 120 s deadline.
        assert delivery["margin_seconds"] == 115
        assert delivery["last_delivered_at"] is not None
    else:
        assert delivery["margin_seconds"] is None and delivery["last_delivered_at"] is None


def test_a_delivery_after_the_deadline_has_a_negative_margin_and_is_late(
    db, admin_engine, world, connector, receiver
):
    hooked = _hooked(db, world, connector, receiver)
    view = pending(hooked, world)
    world["clock"].value += timedelta(seconds=100)
    assert _drain(db, world, hooked)["delivered"] == 1
    with console_client(db, hooked, admin_engine, world["human"]) as approver:
        delivery = detail(approver, view.approval_id).json()["item"]["delivery"]
    assert (delivery["margin_seconds"], delivery["late"]) == (20, True)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approvals SET expires_at = expires_at - interval '30 seconds' "
                "WHERE approval_id=:a"
            ),
            {"a": view.approval_id},
        )
    with console_client(db, hooked, admin_engine, world["human"]) as approver:
        delivery = detail(approver, view.approval_id).json()["item"]["delivery"]
    assert (delivery["margin_seconds"], delivery["late"]) == (-10, True)


def test_nobody_notified_reads_no_delivery(db, runtime, admin_engine, world):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        item = detail(approver, view.approval_id).json()["item"]
        assert item["delivery"] is None and item["notified"] is None
        [listed] = approver.get(API + "/approvals").json()["items"]
        assert listed["delivery"] is None


def test_waiting_on_others_and_the_administrators_detail_carry_delivery(
    db, admin_engine, world, connector, receiver
):
    hooked = _hooked(db, world, connector, receiver)
    view = pending(hooked, world)
    world["clock"].value += timedelta(seconds=5)
    _drain(db, world, hooked)
    with console_client(db, hooked, admin_engine, world["admin"]) as admin:
        [row] = admin.get(API + "/approvals?view=others").json()["items"]
        assert row["delivery"]["delivered"] == 1 and row["delivery"]["margin_seconds"] == 115
        page = detail(admin, view.approval_id).json()
        assert page["reviewing"] is False
        assert page["item"]["delivery"] == row["delivery"]


def test_an_expired_detail_carries_the_quorum_it_reached(db, runtime, admin_engine, world):
    """The console chooses its lapse sentence from these facts (#678)."""
    activate(db, world, quorum_bundle(world))
    second_approver(admin_engine, db, world)
    partly = pending(runtime, world)
    decide_approval(db, world["human"], partly.approval_id, "APPROVE", world["clock"])
    world["clock"].value += timedelta(seconds=121)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        page = detail(approver, partly.approval_id).json()
    assert page["status"] == "expired"
    assert (page["quorum"]["recorded"], page["quorum"]["required"]) == (1, 2)
    assert page["quorum"]["mine"] == "APPROVE"
    # The same after the recovery run has ended it.
    world["clock"].value += timedelta(seconds=301)
    assert recover(db, world["admin"], {}, clock=world["clock"]).expired == 1
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        page = detail(approver, partly.approval_id).json()
    assert page["status"] == "expired" and page["item"]["approval_state"] == "EXPIRED"
    assert (page["quorum"]["recorded"], page["quorum"]["required"]) == (1, 2)


def test_an_approved_detail_that_lapsed_unused_reads_its_quorum_met(
    db, runtime, admin_engine, world
):
    view = pending(runtime, world)
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    world["clock"].value += timedelta(seconds=121 + 301)
    assert recover(db, world["admin"], {}, clock=world["clock"]).expired == 1
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        page = detail(approver, view.approval_id).json()
    assert page["status"] == "expired" and page["item"]["approval_state"] == "EXPIRED"
    assert page["quorum"]["recorded"] == page["quorum"]["required"] == 1
