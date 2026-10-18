# SPDX-License-Identifier: AGPL-3.0-only
"""Activity in the console API (#333): the overview, executions, the detail, reconcile, search.

Every route inherits the harness's refusals (a bearer credential refused and audited, no
session answered with a typed code) and the secret check over its responses. On top: the
overview's figures, series and comparison window for an administrator and for an approver in
scope; the list's filters, its bounds and its cursor at fifty; the detail's reasons with their
rule ids, its facts with their sources, its timeline and its approval; an approver never seeing
an unscoped execution in any route or search result, and another tenant's administrator seeing
nothing of this one; reconcile refusing an approver, a bad continuation and a body of the wrong
shape, and settling nothing without evidence; and search finding targets by hostname and
provider id, executions and approvals by id prefix, and agents by label, in scope.
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, refusals, rejections
from sqlalchemy import text
from test_execution import provision_identity, targets
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import pending
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution import admit, decide_approval
from execbound.execution.modes import set_enforcement_mode
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.provider.connector import MockConnector
from execbound.runtime import Runtime
from execbound.surfaces.console_api.errors import CODES
from execbound.surfaces.dashboard import calendar_window
from execbound_harness.demo import endpoint_ruleset_bundle

DAY = timedelta(days=1)
HOUR = timedelta(hours=1)
ROUTES = [
    (API + "/overview", "GET"),
    (API + "/executions", "GET"),
    (API + "/executions/00000000-0000-0000-0000-000000000000", "GET"),
    (API + "/executions/00000000-0000-0000-0000-000000000000/reconcile", "POST"),
    (API + "/search?q=ws01", "GET"),
]


def unscope(admin_engine, canonical: UUID) -> None:
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.approval_scopes SET active=false WHERE canonical_target_id=:c"),
            {"c": canonical},
        )


def executed(db, runtime, world):
    """The world's own target held, approved and executed: EXECUTED through the mock."""
    first = pending(runtime, world)
    decide_approval(db, world["human"], first.approval_id, "APPROVE", world["clock"])
    view = pending(runtime, world)
    assert view.state == "EXECUTED", view.state
    return view


def held(runtime, admin_engine, world):
    """A production workstation the pack sends to a person: PENDING_APPROVAL, in scope."""
    [production] = targets(admin_engine, world, count=1, production=True)
    view = runtime.execute(world["identity"], production.model_dump_json().encode())
    assert view.state == "PENDING_APPROVAL", view.state
    return view, production.target.value


def denied(runtime, admin_engine, world):
    """A production domain controller the pack forbids outright: DENIED, NOT_AUTHORIZED."""
    [tier_zero] = targets(admin_engine, world, count=1, production=True)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET role='domain_controller' "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"t": world["identity"].tenant_id, "r": UUID(tier_zero.target.value)},
        )
    view = runtime.execute(world["identity"], tier_zero.model_dump_json().encode())
    assert view.state == "DENIED"
    return view


def canonical_of(admin_engine, world, execution_id: UUID) -> UUID:
    with admin_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT canonical_target_id FROM execbound.executions "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": world["identity"].tenant_id, "e": execution_id},
        ).scalar_one()


@pytest.mark.parametrize("path,method", ROUTES)
def test_every_route_refuses_a_bearer_and_a_missing_session(
    db, runtime, seeded, admin_engine, world, path, method
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403, (path, results["bearer"].text)
    assert results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1, path
    missing = results["no_session"]
    assert missing.status_code == 401 and missing.json()["code"] == "SESSION_REQUIRED"
    assert missing.headers["content-type"].startswith("application/json")


def test_the_overview_counts_the_tenant_for_an_administrator_and_the_scope_for_an_approver(
    db, runtime, admin_engine, world, live_provider, connector
):
    ran = executed(db, runtime, world)
    refused = denied(runtime, admin_engine, world)
    waiting, production = held(runtime, admin_engine, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(API + "/overview")
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        body = response.json()
        assert body["range"] == "7d" and body["step_seconds"] == 6 * 3600
        assert body["figures"] == {
            "decisions": 3,
            "executed": 1,
            "denied": 1,
            "held": 1,
            "observed": 0,
            "stale": 0,
            "unknown": 0,
        }
        assert body["previous"]["decisions"] == 0
        assert len(body["series"]) == 28
        for figure in ("executed", "denied", "held"):
            assert sum(bucket[figure] for bucket in body["series"]) == body["figures"][figure]
        assert body["pending_approvals"] == 1 and body["unsettled"] == 0
        assert body["awaiting"] == [] and body["mode"] == "ENFORCE"
        assert body["monitoring"] == {
            "sources": 0,
            "reporting": 0,
            "stale": 0,
            "overdue": 0,
            "open_findings": 0,
        }
        assert body["since"] < body["until"]
        assert len(admin.get(API + "/overview?range=24h").json()["series"]) == 24
        assert admin.get(API + "/overview?range=24h").json()["step_seconds"] == 3600
        assert len(admin.get(API + "/overview?range=30d").json()["series"]) == 30
        for query in ("?range=1y", "?range=7D", "?window=7d", "?range=7d&range=7d"):
            wrong = admin.get(API + "/overview" + query)
            assert wrong.status_code == 400, query
            assert wrong.json()["code"] == "INVALID_REQUEST", query
    # The executed row's target leaves the approver's scope: their figures no longer count
    # it, an administrator's still do, and the pending one is what awaits them.
    assert canonical_of(admin_engine, world, ran.execution_id) == world["canonical"]
    unscope(admin_engine, world["canonical"])
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        body = approver.get(API + "/overview").json()
        assert body["figures"]["executed"] == 0 and body["figures"]["denied"] == 1
        assert body["figures"]["held"] == 1 and body["pending_approvals"] == 1
        assert body["monitoring"] is None
        [awaiting] = body["awaiting"]
        assert awaiting["execution_id"] == str(waiting.execution_id)
        assert awaiting["approval_id"] == str(waiting.approval_id)
        assert awaiting["action_label"] == "Isolate endpoint"
        assert awaiting["target"]["provider_id"] == production
        assert awaiting["agent"]["principal_id"] == str(world["identity"].principal_id)
        assert_no_secrets(approver.get(API + "/overview"))
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(API + "/overview").json()["figures"]["executed"] == 1
    assert refused.state == "DENIED"


@pytest.mark.parametrize(
    ("window", "step", "offset", "until", "since"),
    [
        # A week at 10:25 PM on a Saturday in New York (UTC-4) starts at midnight six days
        # before, so its seventh day is today.
        (DAY * 7, HOUR * 6, -240, "2026-09-27T02:25:00+00:00", "2026-09-20T04:00:00+00:00"),
        # Just after midnight, the week still ends with today.
        (DAY * 7, HOUR * 6, -240, "2026-09-27T04:05:00+00:00", "2026-09-21T04:00:00+00:00"),
        # Thirty days in Kathmandu (UTC+5:45) start at a local midnight too.
        (DAY * 30, DAY, 345, "2026-09-26T20:00:00+00:00", "2026-08-28T18:15:00+00:00"),
        # A day starts on the hour, twenty-three hours before the current one.
        (DAY, HOUR, -240, "2026-09-27T02:25:00+00:00", "2026-09-26T03:00:00+00:00"),
    ],
)
def test_a_calendar_window_starts_at_the_viewers_midnight_and_compares_like_with_like(
    window, step, offset, until, since
):
    now = datetime.fromisoformat(until)
    start, previous = calendar_window(now, window, step, timedelta(minutes=offset))
    assert start == datetime.fromisoformat(since)
    local = start + timedelta(minutes=offset)
    assert (local - datetime(2000, 1, 1, tzinfo=UTC)) % step == timedelta(0)
    # The week before is as long as this one has run so far, so a comparison made on the
    # first morning of a week does not set half a day against seven.
    assert previous == (start - window, now - window)


def test_the_overview_window_follows_the_viewers_calendar_when_given_their_offset(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        rolling = admin.get(API + "/overview").json()
        assert datetime.fromisoformat(rolling["until"]) - datetime.fromisoformat(
            rolling["since"]
        ) == timedelta(days=7)
        for query, buckets in (("?range=7d", 28), ("?range=30d", 30), ("?range=24h", 24)):
            body = admin.get(API + "/overview" + query + "&utc_offset=-240").json()
            since = datetime.fromisoformat(body["since"])
            assert len(body["series"]) == buckets, query
            assert datetime.fromisoformat(body["series"][0]["start"]) == since, query
            local = since - timedelta(hours=4)
            assert local.minute == 0 and (query == "?range=24h" or local.hour == 0), query
        for query in ("841", "-841", "abc", "", "1.5", "60&utc_offset=60", "+60"):
            wrong = admin.get(API + "/overview?utc_offset=" + query)
            assert wrong.status_code == 400, query
            assert wrong.json()["code"] == "INVALID_REQUEST", query


def test_the_list_filters_bounds_and_pages_at_fifty(db, runtime, admin_engine, world):
    set_enforcement_mode(db, world["admin"], "OBSERVE", "Console API test", world["clock"])
    requests = targets(admin_engine, world, count=55)
    for req in requests:
        assert admit(db, world["identity"], req, world["clock"]).view.state == "OBSERVED"
    set_enforcement_mode(db, world["admin"], "ENFORCE", "Console API test done", world["clock"])
    agent = str(world["identity"].principal_id)
    one = UUID(requests[0].target.value)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        first = admin.get(API + "/executions")
        assert first.status_code == 200, first.text
        assert_no_secrets(first)
        page = first.json()
        assert len(page["items"]) == 50 and page["next_cursor"]
        second = admin.get(API + "/executions?cursor=" + page["next_cursor"]).json()
        assert len(second["items"]) == 5 and second["next_cursor"] is None
        ids = {item["execution_id"] for item in page["items"] + second["items"]}
        assert len(ids) == 55
        item = page["items"][0]
        assert item["state"] == "OBSERVED" and item["state_label"] == "Observed"
        assert item["action"] == "endpoint.isolate" and item["action_label"] == "Isolate endpoint"
        assert item["agent"]["principal_id"] == agent and item["approval"] is None
        assert item["target"]["environment"] == "development"
        assert item["reconcile"] == {"available": False, "kind": None, "continuation": None}
        assert len(admin.get(API + "/executions?limit=8").json()["items"]) == 8
        assert len(admin.get(API + "/executions?state=OBSERVED").json()["items"]) == 50
        assert admin.get(API + "/executions?state=DENIED").json() == {
            "items": [],
            "next_cursor": None,
        }
        assert (
            len(admin.get(API + "/executions?action=endpoint.isolate&since=1h").json()["items"])
            == 50
        )
        assert len(admin.get(API + "/executions?agent=" + agent).json()["items"]) == 50
        assert len(admin.get(API + "/executions?agent=" + str(uuid4())).json()["items"]) == 0
        canonical = canonical_of(admin_engine, world, UUID(page["items"][0]["execution_id"]))
        [only] = admin.get(API + "/executions?target=" + str(canonical)).json()["items"]
        assert only["target"]["canonical_target_id"] == str(canonical)
        for query in (
            "?state=NOPE",
            "?action=endpoint.reboot",
            "?since=2h",
            "?limit=51",
            "?limit=0",
            "?limit=08",
            "?agent=abc",
            "?agent=" + agent.upper(),
            "?target=abc",
            "?cursor=%25%25",
            "?cursor=" + "A" * 201,
            "?other=1",
            "?state=OBSERVED&state=OBSERVED",
        ):
            wrong = admin.get(API + "/executions" + query)
            assert wrong.status_code == 400, (query, wrong.text)
            assert wrong.json()["code"] == "INVALID_REQUEST", query
    assert one


def test_the_detail_carries_reasons_facts_timeline_and_the_approval(
    db, runtime, admin_engine, world, live_provider, connector
):
    held = pending(runtime, world)
    refused = denied(runtime, admin_engine, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(API + f"/executions/{held.execution_id}")
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        body = response.json()
        assert body["state"] == "PENDING_APPROVAL" and body["state_label"] == "Held"
        assert body["approval"]["approval_id"] == str(held.approval_id)
        assert body["approval"]["state"] == "PENDING"
        assert body["approval"]["required_approvers"] == 1 and body["approval"]["recorded"] == 0
        assert body["reasons"] == [
            {
                "code": "APPROVAL_REQUIRED",
                "rule_id": None,
                "sentence": "A person has to approve it before it can run.",
                "rules": [],
            }
        ]
        assert body["obligations"] and all(
            obligation["sentence"] for obligation in body["obligations"]
        )
        assert {fact["name"] for fact in body["facts"]} >= {"is_production", "incident_severity"}
        for fact in body["facts"]:
            assert fact["source_kind"] in {"inventory", "incident"}
            assert fact["observed_at"] < fact["valid_until"]
            assert fact["source_object_id"] and fact["source_version"]
        assert [entry["state"] for entry in body["timeline"]] == ["ATTEMPTED", "PENDING_APPROVAL"]
        assert body["timeline"][0]["sentence"] == "Request received and the plan frozen."
        assert body["timeline"][1]["sentence"].startswith("Held for a person: ")
        assert body["timeline"][0]["actor"]["principal_id"] == str(world["identity"].principal_id)
        assert body["target"] == {
            "canonical_target_id": str(world["canonical"]),
            "provider_id": "device-01",
            "resource_class": "workstation",
            "environment": "production",
            "sample": False,
        }
        assert len(body["plan_hash"]) == 64 and body["valid_until"]
        assert body["reconcile"]["available"] is False
        assert body["limits"] and all(limit["rule_id"] for limit in body["limits"])
        assert body["checkpoint"] == [] and body["carriers"] == []
        assert body["observed_effect"] is None

        denial = admin.get(API + f"/executions/{refused.execution_id}").json()
        assert denial["state"] == "DENIED" and denial["state_label"] == "Denied"
        [reason] = denial["reasons"]
        assert reason["code"] == "NOT_AUTHORIZED" and reason["rule_id"] is None
        assert reason["sentence"].startswith("No rule in the active bundle permits")
        assert denial["timeline"][-1]["sentence"] == "Denied: NOT_AUTHORIZED."
        assert denial["approval"] is None

        for wrong in (str(uuid4()), "not-an-id", str(held.execution_id).upper()):
            missing = admin.get(API + "/executions/" + wrong)
            assert missing.status_code == 404 and missing.json()["code"] == "NOT_FOUND", wrong

    decide_approval(db, world["human"], held.approval_id, "APPROVE", world["clock"])
    assert pending(runtime, world).state == "EXECUTED"
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        body = approver.get(API + f"/executions/{held.execution_id}").json()
        assert body["state"] == "EXECUTED" and body["approval"]["recorded"] == 1
        # The provider's own answer settled it, and the row says so rather than falling back
        # to "a reason was recorded without a plain-language explanation" (#545).
        assert body["reasons"] == [
            {
                "code": "PROVIDER_RESPONSE",
                "rule_id": None,
                "sentence": "The provider's own response confirmed this outcome.",
                "rules": [],
            }
        ]
        decisions = [entry for entry in body["timeline"] if entry["kind"] == "decision"]
        assert len(decisions) == 1 and decisions[0]["sentence"].startswith("Approved by ")
        assert decisions[0]["actor"]["principal_id"] == str(world["human"].principal_id)
        assert body["timeline"][-1]["state"] == "EXECUTED"
        assert body["timeline"] == sorted(body["timeline"], key=lambda entry: entry["at"])
        assert body["reconcile"]["available"] is False


def test_a_denial_under_a_bundle_written_as_rules_names_the_rule_it_matches(
    db, runtime, admin_engine, world, live_provider, connector
):
    """The list and the record read the frozen bundle's rules over the frozen facts (#545).

    The kernel records `NOT_AUTHORIZED` and no rule id; under a bundle written as rules both
    routes name the deny rule the request matches, as a reading and never as a rule id.
    """
    bundle = endpoint_ruleset_bundle(
        world["identity"].tenant_id, world["account"], mapping_version="map-v1"
    )
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    refused = denied(runtime, admin_engine, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        listed = admin.get(API + "/executions?state=DENIED").json()["items"]
        [row] = [item for item in listed if item["execution_id"] == str(refused.execution_id)]
        record = admin.get(API + f"/executions/{refused.execution_id}").json()
    for reasons in (row["reasons"], record["reasons"]):
        [reason] = [item for item in reasons if item["code"] == "NOT_AUTHORIZED"]
        assert reason["rule_id"] is None
        assert reason["sentence"].startswith("This request matches the deny rule")
        assert "isolate-never-domain-controller" in reason["sentence"]
        assert "role is domain_controller" in reason["sentence"]


def test_an_approver_never_sees_an_unscoped_execution_anywhere(
    db, runtime, admin_engine, world, seeded, live_provider, connector
):
    ran = executed(db, runtime, world)
    waiting, _ = held(runtime, admin_engine, world)
    unscope(admin_engine, world["canonical"])
    prefix = str(ran.execution_id)[:8]
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        items = approver.get(API + "/executions").json()["items"]
        assert {item["execution_id"] for item in items} == {str(waiting.execution_id)}
        hidden = approver.get(API + f"/executions/{ran.execution_id}")
        assert hidden.status_code == 404 and hidden.json()["code"] == "NOT_FOUND"
        assert approver.get(API + "/search?q=" + prefix).json()["results"] == []
        assert approver.get(API + "/search?q=ws01").json()["results"] == []
        assert approver.get(API + "/overview").json()["figures"]["executed"] == 0
        found = approver.get(API + "/search?q=" + str(waiting.execution_id)[:8]).json()["results"]
        assert [result["kind"] for result in found] == ["execution"]
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(API + f"/executions/{ran.execution_id}").status_code == 200
        assert [r["kind"] for r in admin.get(API + "/search?q=" + prefix).json()["results"]] == [
            "execution"
        ]
    # Another tenant's administrator: this tenant's records do not exist for them.
    other = provision_identity(
        admin_engine, db, seeded["tenants"][1], "ADMIN", world["clock"].now()
    )
    with console_client(db, runtime, admin_engine, other) as stranger:
        assert stranger.get(API + "/executions").json() == {"items": [], "next_cursor": None}
        foreign = stranger.get(API + f"/executions/{ran.execution_id}")
        assert foreign.status_code == 404 and foreign.json()["code"] == "NOT_FOUND"
        assert stranger.get(API + "/search?q=" + prefix).json()["results"] == []
        assert stranger.get(API + "/overview").json()["figures"]["decisions"] == 0


def test_reconcile_needs_an_administrator_the_continuation_and_evidence(
    db, runtime, admin_engine, world, live_provider, connector
):
    [development] = targets(admin_engine, world, count=1)
    admission = admit(db, world["identity"], development, world["clock"])
    assert admission.ticket is not None and admission.view.state == "DISPATCH_COMMITTED"
    execution_id = admission.view.execution_id
    path = API + f"/executions/{execution_id}/reconcile"
    body = {"continuation": "x", "reason": "Lost the ticket holder"}
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        refused = approver.post(path, body)
        assert refused.status_code == 403 and refused.json()["code"] == "FORBIDDEN"
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        before = rejections(admin_engine, world["admin"])
        bogus = admin.post(path, body)
        assert bogus.status_code == 400 and bogus.json()["code"] == "INVALID_CONTINUATION"
        assert rejections(admin_engine, world["admin"]) == before + 1
        detail = admin.get(API + f"/executions/{execution_id}").json()
        assert detail["reconcile"]["available"] is True
        assert detail["reconcile"]["kind"] == "provider"
        continuation = detail["reconcile"]["continuation"]
        assert continuation
        # The continuation is the record's: another path refuses it, and a record from the
        # executor belongs to a grant, which this dispatch is not.
        elsewhere = admin.post(
            API + f"/executions/{uuid4()}/reconcile", {**body, "continuation": continuation}
        )
        assert elsewhere.status_code == 400 and elsewhere.json()["code"] == "INVALID_CONTINUATION"
        shaped = admin.post(path, {**body, "continuation": continuation, "record": "{}"})
        assert shaped.status_code == 400 and shaped.json() == {
            "code": "INVALID_BODY",
            "detail": CODES["INVALID_BODY"][1],
            "fields": ["record"],
        }
        assert admin.post(path, {"continuation": continuation}).json()["fields"] == ["reason"]
        assert admin.post(path, {**body, "continuation": continuation, "extra": 1}).json()[
            "fields"
        ] == ["extra"]
        # Without evidence nothing settles: the provider was never sent anything, so the
        # journal holds no terminal entry and the record stays unsettled.
        unsettled = admin.post(path, {**body, "continuation": continuation})
        assert unsettled.status_code == 200, unsettled.text
        assert_no_secrets(unsettled)
        assert unsettled.json() == {
            "execution_id": str(execution_id),
            "state": "INDETERMINATE",
            "state_label": "Unsettled",
        }
        assert admin.get(API + "/overview").json()["unsettled"] == 1
        # Cancelling when nothing was sent is the settlement the page offers; the
        # continuation still binds the same frozen record.
        cancelled = admin.post(
            path, {**body, "continuation": continuation, "cancel_if_missing": True}
        )
        assert cancelled.status_code == 200 and cancelled.json()["state"] == "FAILED_NOT_EXECUTED"
        after = admin.get(API + f"/executions/{execution_id}").json()
        assert after["reconcile"]["available"] is False and after["state_label"] == "Not executed"
        assert after["timeline"][-1]["sentence"].startswith("Failed before any effect")
        assert admin.get(API + "/overview").json()["unsettled"] == 0


def test_reconcile_recovers_a_lost_answer_from_the_providers_journal(
    db, world, admin_engine, live_provider
):
    live_provider.restart("delay_after_commit")
    slow = MockConnector(replace(live_provider.config, timeout_seconds=0.05))
    runtime = Runtime(db, [slow], clock=world["clock"])
    try:
        first = pending(runtime, world)
        decide_approval(db, world["human"], first.approval_id, "APPROVE", world["clock"])
        assert pending(runtime, world).state == "INDETERMINATE"
        path = API + f"/executions/{first.execution_id}/reconcile"
        with console_client(db, runtime, admin_engine, world["admin"]) as admin:
            detail = admin.get(API + f"/executions/{first.execution_id}").json()
            assert (
                detail["state_label"] == "Unsettled" and detail["reconcile"]["kind"] == "provider"
            )
            settled = admin.post(
                path,
                {
                    "continuation": detail["reconcile"]["continuation"],
                    "reason": "Recover synthetic lost response",
                },
            )
            assert settled.status_code == 200, settled.text
            assert settled.json()["state"] == "EXECUTED"
            after = admin.get(API + f"/executions/{first.execution_id}").json()
            assert after["timeline"][-1]["state"] == "EXECUTED"
            assert after["timeline"][-1]["actor"]["principal_id"] == str(
                world["admin"].principal_id
            )
            # The settling administrator is a person, named by kind and number (#678).
            assert after["timeline"][-1]["actor"]["kind"] == "ADMIN"
            assert after["timeline"][-1]["actor"]["number"] == 1
        assert runtime.status(world["identity"], first.execution_id).state == "EXECUTED"
    finally:
        slow.close()


def test_search_finds_targets_executions_approvals_and_agents_in_scope(
    db, runtime, admin_engine, world
):
    held = pending(runtime, world)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label='Triage agent A' WHERE principal_id=:p"),
            {"p": world["identity"].principal_id},
        )
    # Approval search uses explicit review permission even for an administrator.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes "
                "(tenant_id,approver_id,canonical_target_id,action,space_id) "
                "SELECT tenant_id,:p,canonical_target_id,action,space_id "
                "FROM execbound.approval_scopes WHERE approver_id=:h"
            ),
            {"p": world["admin"].principal_id, "h": world["human"].principal_id},
        )
    approval_prefix = str(held.approval_id)[:8]
    execution_prefix = str(held.execution_id)[:8]
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(API + "/search?q=ws01")
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        [target] = response.json()["results"]
        assert target == {
            "kind": "target",
            "id": str(world["canonical"]),
            "label": "ws01.example",
            "detail": "device-01; endpoint, workstation, production",
            "state": None,
            "state_label": None,
            # A row names its space only when the reader can see more than one; a tenant
            # with its one `Default` space sends null on every row.
            "space_name": None,
            "execution_id": None,
        }
        assert admin.get(API + "/search?q=DEVICE-0").json()["results"][0]["id"] == str(
            world["canonical"]
        )
        [approval] = admin.get(API + "/search?q=" + approval_prefix).json()["results"]
        assert approval["kind"] == "approval" and approval["id"] == str(held.approval_id)
        assert approval["label"] == "Approval: Isolate endpoint on device-01"
        assert approval["detail"] == f"{held.request_ref}; Held; approval pending"
        assert approval["state"] == "PENDING_APPROVAL" and approval["state_label"] == "Held"
        assert approval["execution_id"] == str(held.execution_id)
        [execution] = admin.get(API + "/search?q=" + execution_prefix).json()["results"]
        assert execution["kind"] == "execution" and execution["id"] == str(held.execution_id)
        assert execution["label"] == "Isolate endpoint on device-01"
        assert execution["detail"] == f"Request {held.request_ref}"
        assert execution["state_label"] == "Held"
        assert execution["execution_id"] == str(held.execution_id)
        [agent] = admin.get(API + "/search?q=triage%20AGENT").json()["results"]
        assert agent == {
            "kind": "agent",
            "id": str(world["identity"].principal_id),
            "label": "Triage agent A",
            # The handle beside the label, so two agents labelled alike stay apart (#678).
            "detail": "Agent 1",
            "state": None,
            "state_label": None,
            # A row names its space only when the reader can see more than one; a tenant
            # with its one `Default` space sends null on every row.
            "space_name": None,
            "execution_id": None,
        }
        assert admin.get(API + "/search?q=" + str(held.execution_id)).json()["results"]
        # A wildcard is a character, not a pattern; an empty or overlong term is refused.
        assert admin.get(API + "/search?q=%25").json()["results"] == []
        assert admin.get(API + "/search?q=_").json()["results"] == []
        for query in ("?q=", "?q=%20", "?q=" + "x" * 81, "?term=ws01", "?q=a&q=b"):
            wrong = admin.get(API + "/search" + query)
            assert wrong.status_code == 400 and wrong.json()["code"] == "INVALID_REQUEST", query
        assert (
            len(admin.get(API + "/search?q=" + str(held.execution_id)[:1]).json()["results"]) <= 20
        )
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        assert [r["kind"] for r in approver.get(API + "/search?q=ws01").json()["results"]] == [
            "target"
        ]
        assert approver.get(API + "/search?q=triage").json()["results"] == []
        assert [
            r["kind"] for r in approver.get(API + "/search?q=" + approval_prefix).json()["results"]
        ] == ["approval"]
        unscope(admin_engine, world["canonical"])
        assert approver.get(API + "/search?q=ws01").json()["results"] == []
        assert approver.get(API + "/search?q=" + approval_prefix).json()["results"] == []
        assert approver.get(API + "/search?q=" + execution_prefix).json()["results"] == []


def test_the_document_names_this_lanes_routes():
    """The shared base test holds the document to the console; these are this area's own."""
    from execbound.surfaces.console_api import console_api_document

    assert {
        "/api/console/v1/overview",
        "/api/console/v1/executions",
        "/api/console/v1/executions/{execution_id}",
        "/api/console/v1/executions/{execution_id}/reconcile",
        "/api/console/v1/search",
    } <= set(console_api_document()["paths"])


def test_records_carry_the_agents_kind_and_number(db, runtime, admin_engine, world):
    """An unlabelled agent is named by the console as "Agent 1": the list row and the detail
    carry its kind and number beside the id, and no label (#678)."""
    held = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        [row] = admin.get(API + "/executions").json()["items"]
        detail = admin.get(API + f"/executions/{held.execution_id}").json()
        overview = None
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        overview = approver.get(API + "/overview").json()
    expected = {
        "principal_id": str(world["identity"].principal_id),
        "label": None,
        "kind": "AGENT",
        "number": 1,
    }
    assert row["agent"] == expected
    assert detail["agent"] == expected
    assert detail["timeline"][0]["actor"] == expected
    # Home's awaiting list names the agent the same way.
    [awaiting] = overview["awaiting"]
    assert awaiting["agent"] == expected


def test_a_labelled_agent_carries_label_and_number(db, runtime, admin_engine, world):
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label='triage-bot' WHERE principal_id=:p"),
            {"p": world["identity"].principal_id},
        )
    pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        [row] = admin.get(API + "/executions").json()["items"]
    assert (row["agent"]["label"], row["agent"]["kind"], row["agent"]["number"]) == (
        "triage-bot",
        "AGENT",
        1,
    )


def test_the_timeline_names_an_unlabelled_approver_by_number(
    db, runtime, admin_engine, world, live_provider
):
    held = pending(runtime, world)
    decide_approval(db, world["human"], held.approval_id, "APPROVE", world["clock"])
    with admin_engine.connect() as conn:
        number = conn.execute(
            text("SELECT number FROM execbound.principals WHERE principal_id=:p"),
            {"p": world["human"].principal_id},
        ).scalar_one()
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        body = admin.get(API + f"/executions/{held.execution_id}").json()
    [decision] = [entry for entry in body["timeline"] if entry["kind"] == "decision"]
    assert decision["sentence"] == f"Approved by User {number}."
    assert (decision["actor"]["kind"], decision["actor"]["number"]) == ("HUMAN_APPROVER", number)
