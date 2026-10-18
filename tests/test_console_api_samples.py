# SPDX-License-Identifier: AGPL-3.0-only
"""The console's sample-target routes (#420, #545).

`GET /samples` is the status Home's guided setup and Getting started show, an administrator's
read, and core's own (#496): a plugin's `/welcome` does not carry it for core. An approver sees
the samples and their requests and can read or change none of the five routes; every mutation
takes the guards every mutation takes, and a personal access token is refused the two that
activate the starter bundle, adding and refreshing. The SM2, SM6 and SM9 cases here read the
status through `GET /samples`. `GET /samples/demo-configuration` (SM11, #247) is that status as
`execbound-demo` reads it.
"""

import json
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from console_api_fixtures import (
    API,
    ORIGIN,
    assert_no_secrets,
    console_client,
    console_config,
    refusals,
)
from fastapi.testclient import TestClient
from sample_fixtures import (
    agent_identity,
    agent_token,
    empty_workspace,
    offline_runtime,
    password_workspace,
    person,
)
from sample_fixtures import sample_key as sample_key
from sample_fixtures import sample_mock as sample_mock
from sample_fixtures import sample_runtime as sample_runtime
from space_fixtures import seat
from sqlalchemy import text
from test_console_api_tokens import bearer, minted_for, post
from test_human_surface import human_config as human_config
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_samples import Later, logged
from test_samples import captured as captured

from execbound import samples
from execbound.app import create_app
from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError
from execbound.execution.modes import set_approval_deadline, set_enforcement_mode
from execbound.execution.stops import activate_stop, release_stop
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.provider.connector import ConnectionConfig, MockConnector
from execbound.provider.sample_accounts import SampleProvider
from execbound.recovery_run import expire_approval
from execbound.requests import parse_request
from execbound.resolution.models import SystemClock
from execbound.runtime import Runtime
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

HOSTNAMES = ["dc-01.sample.invalid", "ws-dev-01.sample.invalid", "ws-prod-01.sample.invalid"]
# The one sentence a `SAMPLES_NOT_OFFERED` body carries, true of an install and of a refresh
# (#545): the console shows its own words for each, and this is what an API client reads.
NOT_OFFERED = (
    "Sample targets are added only to a workspace with no policy and no connections of its own, "
    "and are not re-created while a policy depends on them."
)


def ask(db, agent, host, key):
    return admit(
        db,
        agent,
        parse_request(
            json.dumps(
                {
                    "operation_ref": "endpoint.isolate",
                    "target": {"kind": "hostname", "value": host.hostname},
                    "arguments": {},
                    "idempotency_key": key,
                    "claimed_context": {"incident_id": str(host.incident_id)},
                }
            ).encode()
        ),
        SystemClock(),
    )


def by_effect(status):
    return {host.effect: host for host in status.hosts}


def fenced(conn, tenant):
    # Limits nothing on an `admin_engine` connection, whose owner bypasses row security
    # (see tenant_fence).
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def sample_accounts(admin_engine, tenant) -> int:
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.connector_accounts "
                    "WHERE tenant_id = :t AND sample"
                ),
                {"t": tenant},
            ).scalar_one()
        )


def test_sm2_api_an_approver_sees_the_samples_but_cannot_add_or_remove_them(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    approver = person(admin_engine, db, workspace)
    # Adding is tried before any samples exist too, the one state where one that got through
    # would write them.
    with console_client(db, runtime, admin_engine, approver) as reviewer:
        refused = reviewer.post(API + "/samples", {})
        assert (refused.status_code, refused.json()["code"]) == (403, "FORBIDDEN")
    assert sample_accounts(admin_engine, workspace.tenant_id) == 0
    # Then all three once the administrator has installed the samples. A removal or a refresh
    # that got through would answer 200, which the status code check already catches; the whole
    # status (its state, its bundle, its incidents) adds a catch only for a handler that writes
    # and still answers 403, which with no samples installed would have written nothing.
    installed = samples.install(db, workspace.admin, available=True)
    with (
        console_client(db, runtime, admin_engine, workspace.admin) as admin,
        console_client(db, runtime, admin_engine, approver) as reviewer,
    ):
        before = admin.get(API + "/samples").json()
        assert before["state"] == "removable"
        for path in ("/samples", "/samples/remove", "/samples/refresh"):
            refused = reviewer.post(API + path, {})
            assert refused.status_code == 403, path
            assert refused.json()["code"] == "FORBIDDEN", path
            # The route's own check, before the body is read: without it this would be a 400,
            # and the library's refusal alone would still answer the request above.
            unread = reviewer.post(API + path, {"force": True})
            assert (unread.status_code, unread.json()["code"]) == (403, "FORBIDDEN"), path
            assert admin.get(API + "/samples").json() == before, path
    assert sample_accounts(admin_engine, workspace.tenant_id) == 1
    denied_host = by_effect(installed)["deny"]
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes(tenant_id, approver_id, "
                "canonical_target_id, action, space_id) VALUES (:t, :p, :c, "
                "'endpoint.isolate', :s)"
            ),
            {
                "t": workspace.tenant_id,
                "p": approver.principal_id,
                "c": denied_host.canonical_target_id,
                "s": workspace.space_id,
            },
        )
    denied = ask(db, agent_identity(admin_engine, db, workspace), denied_host, "sample-dc")
    with console_client(db, runtime, admin_engine, approver) as reviewer:
        items = reviewer.get(API + "/executions").json()["items"]
    assert [(item["execution_id"], item["target"]["sample"]) for item in items] == [
        (str(denied.view.execution_id), True)
    ]


def test_sm_api_the_routes_take_the_guards_every_mutation_takes(
    db, admin_engine, seeded, sample_key
):
    """Adding the samples, removing them and refreshing them each refuse a request without the
    CSRF token, one from another origin and one naming a field the change does not take, and
    change nothing."""
    workspace = empty_workspace(admin_engine, db)
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        for path, state in (
            ("/samples", "absent"),
            ("/samples/remove", "removable"),
            ("/samples/refresh", "removable"),
        ):
            if path == "/samples/remove":
                # A refused removal changes nothing only where there is something to remove.
                samples.install(db, workspace.admin, available=True)
            # The whole status, not its state alone: a refresh that went through would still
            # read `removable`, with a new bundle and new incidents.
            before = admin.get(API + "/samples").json()
            assert before["state"] == state, path
            missing = admin.post(API + path, {}, csrf=None)
            assert missing.json().get("code") == "INVALID_CSRF", (path, missing.json())
            foreign = admin.post(API + path, {}, origin="http://evil.example")
            assert foreign.status_code == 403, path
            unknown = admin.post(API + path, {"force": True})
            assert unknown.status_code == 400 and unknown.json()["fields"] == ["force"], path
            assert admin.get(API + "/samples").json() == before, path


def test_the_status_route_is_an_administrators(db, admin_engine, seeded, sample_key):
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    approver = person(admin_engine, db, workspace)
    with console_client(db, runtime, admin_engine, approver) as reviewer:
        refused = reviewer.get(API + "/samples")
        assert refused.status_code == 403 and refused.json()["code"] == "FORBIDDEN"


def test_the_status_route_refuses_a_bearer_credential_and_a_missing_session(
    db, runtime, seeded, admin_engine, world
):
    results = refusals(db, runtime, seeded, admin_engine, world, API + "/samples", "GET")
    assert results["bearer"].status_code == 403 and results["audited"] == 1
    assert results["no_session"].status_code == 401


def test_sm_api_an_administrator_adds_and_removes_samples_and_home_reports_each_state(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        home = admin.get(API + "/samples")
        assert home.status_code == 200, home.text
        assert_no_secrets(home)
        assert (home.json()["state"], home.json()["offered"], home.json()["available"]) == (
            "absent",
            True,
            True,
        )
        assert admin.get(API + "/connection").json()["workstation"] is None

        added = admin.post(API + "/samples", {})

        assert added.status_code == 200, added.text
        assert_no_secrets(added)
        body = added.json()
        assert (body["state"], body["offered"], body["first_request"]) == ("removable", False, None)
        assert [host["hostname"] for host in body["hosts"]] == HOSTNAMES
        assert {host["hostname"]: host["effect"] for host in body["hosts"]} == {
            "dc-01.sample.invalid": "deny",
            "ws-dev-01.sample.invalid": "allow",
            "ws-prod-01.sample.invalid": "require approval",
        }
        assert body["stale_at"] is not None
        assert admin.post(API + "/samples", {}).json() == body
        assert admin.get(API + "/samples").json() == body
        dev = next(host for host in body["hosts"] if host["effect"] == "allow")
        assert admin.get(API + "/connection").json()["workstation"] == {
            "kind": "hostname",
            "value": dev["hostname"],
            "incident_id": dev["incident_id"],
        }
        policy = admin.get(API + "/policy").json()
        assert [(row["bundle_id"], row["sample"]) for row in policy["bundles"]] == [
            (body["bundle_id"], True)
        ]
        assert admin.get(API + "/policy/" + body["bundle_id"]).json()["sample"] is True

        removed = admin.post(API + "/samples/remove", {})

        assert removed.status_code == 200, removed.text
        assert (removed.json()["state"], removed.json()["offered"]) == ("absent", True)
        assert admin.post(API + "/samples/remove", {}).json() == removed.json()
        assert admin.get(API + "/samples").json() == removed.json()
        assert admin.get(API + "/connection").json()["workstation"] is None


def test_sm2_api_a_deployment_without_a_sample_key_says_so_and_adds_nothing(
    db, admin_engine, seeded
):
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, None)
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        home = admin.get(API + "/samples").json()
        assert (home["state"], home["offered"], home["available"]) == ("absent", False, False)
        refused = admin.post(API + "/samples", {})
        assert refused.status_code == 409 and refused.json()["code"] == "SAMPLES_UNAVAILABLE"
    assert sample_accounts(admin_engine, workspace.tenant_id) == 0


def test_sm2_api_a_workspace_with_a_connection_is_not_offered_samples(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) VALUES (:t, gen_random_uuid(), 'mock_entra', :s)"
            ),
            {"t": workspace.tenant_id, "s": workspace.space_id},
        )
    runtime = offline_runtime(db, sample_key)
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        assert admin.get(API + "/samples").json()["offered"] is False
        refused = admin.post(API + "/samples", {})
        assert refused.status_code == 409 and refused.json()["code"] == "SAMPLES_NOT_OFFERED"
        assert refused.json()["detail"] == NOT_OFFERED
    assert sample_accounts(admin_engine, workspace.tenant_id) == 0


def test_sm2_api_a_workspace_the_gateway_holds_a_configured_connector_for_is_not_offered_samples(
    db, admin_engine, seeded, sample_key
):
    """The gateway derives no sample connection in a tenant its private configuration holds a
    connector for, as the endpoint mock refuses one, so the console neither offers samples
    there nor adds them: nothing could reach them. Another workspace is offered them as ever."""
    workspace = empty_workspace(admin_engine, db)
    other = empty_workspace(admin_engine, db)
    configured = MockConnector(
        ConnectionConfig(
            workspace.tenant_id,
            uuid4(),
            "http://127.0.0.1:9",
            "d" * 43,
            "c" * 43,
            {"journal-v1": b"\x01" * 32},
        )
    )
    try:
        runtime = Runtime(
            db,
            [configured],
            keys=TokenKeys("samples-v1", {"samples-v1": b"\x03" * 32}),
            sample_providers=[SampleProvider("mock_crowdstrike", "http://127.0.0.1:9", sample_key)],
        )
        with console_client(db, runtime, admin_engine, workspace.admin) as admin:
            home = admin.get(API + "/samples").json()
            assert (home["state"], home["offered"], home["available"]) == (
                "absent",
                False,
                False,
            )
            refused = admin.post(API + "/samples", {})
            assert refused.status_code == 409 and refused.json()["code"] == "SAMPLES_UNAVAILABLE"
        assert sample_accounts(admin_engine, workspace.tenant_id) == 0
        with console_client(db, runtime, admin_engine, other.admin) as admin:
            home = admin.get(API + "/samples").json()
            assert (home["offered"], home["available"]) == (True, True)
            added = admin.post(API + "/samples", {})
            assert added.status_code == 200, added.text
        assert sample_accounts(admin_engine, other.tenant_id) == 1
    finally:
        configured.close()


def test_sm6_api_removal_is_refused_while_a_sample_request_waits_for_approval(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    held = ask(
        db,
        agent_identity(admin_engine, db, workspace),
        by_effect(installed)["require approval"],
        "sample-prod",
    )
    assert held.view.state == "PENDING_APPROVAL"
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        refused = admin.post(API + "/samples/remove", {})
        assert refused.status_code == 409 and refused.json()["code"] == "SAMPLES_BUSY"
        home = admin.get(API + "/samples").json()
        assert home["state"] == "present"
        assert home["first_request"]["execution_id"] == str(held.view.execution_id)
        assert home["first_request"]["state_label"] == "Held"
        items = admin.get(API + "/executions").json()["items"]
        assert [item["target"]["sample"] for item in items] == [True]
    assert sample_accounts(admin_engine, workspace.tenant_id) == 1


def test_the_refresh_route_refuses_a_bearer_credential_and_a_missing_session(
    db, runtime, seeded, admin_engine, world
):
    results = refusals(db, runtime, seeded, admin_engine, world, API + "/samples/refresh", "POST")
    assert results["bearer"].status_code == 403 and results["audited"] == 1
    assert results["no_session"].status_code == 401


def test_sm9_api_an_administrator_refreshes_the_sample_facts(db, admin_engine, seeded, sample_key):
    """One click re-creates the samples (#545): new incidents on the same three targets,
    facts fresh for another hour, the first request counted afresh and every request already
    made still listed. `GET /samples` and `GET /connection` answer the new set."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    denied = ask(
        db, agent_identity(admin_engine, db, workspace), by_effect(installed)["deny"], "sample-dc"
    )
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        before = admin.get(API + "/samples").json()
        assert before["first_request"]["execution_id"] == str(denied.view.execution_id)

        refreshed = admin.post(API + "/samples/refresh", {})

        assert refreshed.status_code == 200, refreshed.text
        assert_no_secrets(refreshed)
        body = refreshed.json()
        assert (body["state"], body["offered"], body["first_request"]) == ("removable", False, None)
        assert body["bundle_id"] != before["bundle_id"]
        assert [host["hostname"] for host in body["hosts"]] == HOSTNAMES
        old = {host["incident_id"] for host in before["hosts"]}
        assert old.isdisjoint(host["incident_id"] for host in body["hosts"])
        assert datetime.fromisoformat(body["stale_at"]) >= datetime.fromisoformat(
            before["stale_at"]
        )
        assert admin.get(API + "/samples").json() == body
        dev = next(host for host in body["hosts"] if host["effect"] == "allow")
        assert admin.get(API + "/connection").json()["workstation"] == {
            "kind": "hostname",
            "value": dev["hostname"],
            "incident_id": dev["incident_id"],
        }
        items = admin.get(API + "/executions").json()["items"]
        assert [(item["execution_id"], item["target"]["sample"]) for item in items] == [
            (str(denied.view.execution_id), True)
        ]
    assert sample_accounts(admin_engine, workspace.tenant_id) == 2


def test_sm9_api_refresh_without_samples_or_a_sample_key_adds_nothing(
    db, admin_engine, seeded, sample_key
):
    """A workspace with no samples is answered its status, as a removal answers it; a
    deployment without a sample key refuses as adding does. Neither writes a sample account."""
    workspace = empty_workspace(admin_engine, db)
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        answered = admin.post(API + "/samples/refresh", {})
        assert answered.status_code == 200, answered.text
        assert (answered.json()["state"], answered.json()["offered"]) == ("absent", True)
    with console_client(db, offline_runtime(db, None), admin_engine, workspace.admin) as admin:
        refused = admin.post(API + "/samples/refresh", {})
        assert refused.status_code == 409 and refused.json()["code"] == "SAMPLES_UNAVAILABLE"
    assert sample_accounts(admin_engine, workspace.tenant_id) == 0


def test_sm9_api_refresh_is_refused_while_a_persons_copy_of_the_starter_names_the_samples(
    db, admin_engine, seeded, sample_key
):
    """A draft a person made from the starter names the sample account, so a refresh, which
    would switch that account off under it, answers 409 `SAMPLES_NOT_OFFERED` and changes
    nothing."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    copy = samples.starter_bundle(workspace.tenant_id, installed.account_id).model_copy(
        update={"bundle_id": uuid4()}
    )
    create_bundle(db, workspace.admin, copy)
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        before = admin.get(API + "/samples").json()
        refused = admin.post(API + "/samples/refresh", {})
        assert refused.status_code == 409 and refused.json()["code"] == "SAMPLES_NOT_OFFERED"
        assert refused.json()["detail"] == NOT_OFFERED
        assert admin.get(API + "/samples").json() == before
    assert sample_accounts(admin_engine, workspace.tenant_id) == 1


def test_sm9_api_an_administrator_seated_in_a_space_may_not_refresh_the_samples(
    db, admin_engine, seeded, sample_key
):
    """An administrator seated in a space is refused 403 `FORBIDDEN`, as adding and removing
    the samples refuse them, and changes nothing. A copy of the starter stands meanwhile, which
    answers the workspace's administrator 409 `SAMPLES_NOT_OFFERED`: the seated administrator
    is refused before the refresh reads for it, so the answer never tells them whether a policy
    names the samples."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    seated = person(admin_engine, db, workspace, kind="ADMIN")
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        seat(conn, workspace.tenant_id, workspace.space_id, seated.principal_id, "ADMIN")
    copy = samples.starter_bundle(workspace.tenant_id, installed.account_id).model_copy(
        update={"bundle_id": uuid4()}
    )
    create_bundle(db, workspace.admin, copy)
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        before = admin.get(API + "/samples").json()
    with console_client(db, runtime, admin_engine, seated) as space_admin:
        refused = space_admin.post(API + "/samples/refresh", {})
        assert refused.status_code == 403 and refused.json()["code"] == "FORBIDDEN"
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        assert admin.get(API + "/samples").json() == before
        not_offered = admin.post(API + "/samples/refresh", {})
        assert not_offered.status_code == 409
        assert not_offered.json()["code"] == "SAMPLES_NOT_OFFERED"
    assert sample_accounts(admin_engine, workspace.tenant_id) == 1


def test_sm9_api_a_token_may_not_refresh_the_samples(db, admin_engine, seeded, sample_key):
    """Refreshing adds and activates the starter bundle again, which is activating a policy, so
    a personal access token is refused it exactly as it is refused `POST /samples`."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    samples.install(db, workspace.admin, available=True)
    token = minted_for(runtime, workspace.admin)
    with console_client(db, runtime, admin_engine, workspace.admin) as console:
        before = console.get(API + "/samples").json()
        with bearer(console, token) as client:
            refused = post(client, API + "/samples/refresh", token)
        assert refused.status_code == 403 and refused.json()["code"] == "TOKEN_NOT_ALLOWED"
        assert console.get(API + "/samples").json() == before
    assert sample_accounts(admin_engine, workspace.tenant_id) == 1


def test_sm9_api_refresh_waits_for_a_held_request_and_for_its_lapsed_approval_to_end(
    db, admin_engine, seeded, sample_key
):
    """`SAMPLES_BUSY` while the production workstation's request waits for approval, and still
    once its approval has lapsed (the Lapsed list shows it `PENDING`) until something ends it,
    which the recovery run does every fifteen minutes; then the refresh goes through. The
    second runtime's clock is 200 seconds on, past the workspace's two-minute default deadline
    and inside the five minutes the definer functions allow."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    held = ask(
        db,
        agent_identity(admin_engine, db, workspace),
        by_effect(installed)["require approval"],
        "sample-prod",
    )
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        waiting = admin.post(API + "/samples/refresh", {})
        assert waiting.status_code == 409 and waiting.json()["code"] == "SAMPLES_BUSY"
    later = Later(200)
    runtime = Runtime(
        db,
        [],
        clock=later,
        keys=TokenKeys("samples-v1", {"samples-v1": secrets.token_bytes(32)}),
        sample_providers=[SampleProvider("mock_crowdstrike", "http://127.0.0.1:9", sample_key)],
    )
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        before = admin.get(API + "/samples").json()
        assert before["state"] == "present"
        lapsed = admin.get(API + "/approvals", params={"view": "lapsed"}).json()["items"]
        assert [(item["execution_id"], item["approval_state"]) for item in lapsed] == [
            (str(held.view.execution_id), "PENDING")
        ]
        refused = admin.post(API + "/samples/refresh", {})
        assert refused.status_code == 409 and refused.json()["code"] == "SAMPLES_BUSY"
        assert admin.get(API + "/samples").json() == before
        assert expire_approval(db, workspace.admin, held.view.execution_id, later) is True
        refreshed = admin.post(API + "/samples/refresh", {})
        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()["state"] == "removable"


def pending(admin):
    return admin.get(API + "/approvals", params={"view": "pending"}).json()["items"]


def test_sm10_api_guided_setup_finds_the_held_request_under_the_workspaces_deadline(
    db, admin_engine, seeded, sample_key
):
    """What guided setup reads to state the deadline and link the approval (#545), all
    of it an administrator's already: the workspace's deadline from `GET /tenant`, and the held
    request in `GET /approvals` under the sample target's `provider_id`, made after the facts
    `GET /samples` says were recorded, closing on the workspace's two-minute default."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    host = by_effect(installed)["require approval"]
    held = ask(db, agent_identity(admin_engine, db, workspace), host, "sample-prod")
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        assert admin.get(API + "/tenant").json()["deadline"]["seconds"] == 120
        status = admin.get(API + "/samples").json()
        items = pending(admin)
    assert [(item["target"], item["execution_id"]) for item in items] == [
        (host.provider_id, str(held.view.execution_id))
    ]
    created = datetime.fromisoformat(items[0]["created_at"])
    assert created >= datetime.fromisoformat(status["observed_at"])
    assert items[0]["deadline_clock"] == "approval deadline"
    waited = datetime.fromisoformat(items[0]["expires_at"]) - created
    assert abs(waited - timedelta(seconds=120)) < timedelta(seconds=1)


def test_sm10_api_with_the_deadline_off_the_held_request_ends_no_later_than_the_facts(
    db, admin_engine, seeded, sample_key
):
    """Off is `null` in `GET /tenant` while `GET /session` reads the default 120, which is why
    guided setup reads the tenant's. The approval then ends when the plan's validity does,
    which is no later than the samples' `stale_at`: the earlier of the facts going stale and the
    agent's key expiring (`snapshot.py`). This agent's key lasts two hours, longer than the
    facts, so here it ends exactly at `stale_at`."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    set_approval_deadline(db, workspace.admin, None, "guided setup reads the tenant's deadline")
    ask(
        db,
        agent_identity(admin_engine, db, workspace),
        by_effect(installed)["require approval"],
        "sample-prod",
    )
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        assert admin.get(API + "/tenant").json()["deadline"]["seconds"] is None
        assert admin.get(API + "/session").json()["tenant"]["approval_deadline_seconds"] == 120
        status = admin.get(API + "/samples").json()
        (item,) = pending(admin)
    assert item["deadline_clock"] == "context validity"
    assert datetime.fromisoformat(item["expires_at"]) == datetime.fromisoformat(status["stale_at"])


def test_sm10_api_a_short_lived_agent_key_ends_the_held_request_before_the_facts_go_stale(
    db, admin_engine, seeded, sample_key
):
    """With the deadline off, the approval ends when the plan's validity does, the earlier of
    the facts going stale and the agent's key expiring. A console-issued key can last an hour
    or less, so a key that expires before the facts ends the request at the key's expiry,
    before `stale_at`: why guided setup says the request waits no later than `stale_at` and
    never promises it."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    set_approval_deadline(db, workspace.admin, None, "guided setup reads the tenant's deadline")
    agent = agent_identity(admin_engine, db, workspace, timedelta(minutes=30))
    ask(db, agent, by_effect(installed)["require approval"], "sample-prod")
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        status = admin.get(API + "/samples").json()
        (item,) = pending(admin)
    assert item["deadline_clock"] == "context validity"
    expires = datetime.fromisoformat(item["expires_at"])
    assert expires == agent.expires_at
    assert expires < datetime.fromisoformat(status["stale_at"])


DEMO = API + "/samples/demo-configuration"


def test_sm11_api_the_demo_configuration_is_the_samples_as_the_demo_reads_them(
    db, admin_engine, seeded, sample_key, tmp_path
):
    """`GET /samples/demo-configuration` hands an administrator `execbound-demo`'s configuration
    for the workspace's samples, as an attachment named `sandbox.json` that never caches and
    carries no credential, and what it hands over is what the demo loads (#247)."""
    from execbound_client.demo import Sandbox

    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        missing = admin.get(DEMO)
        status = admin.post(API + "/samples", {}).json()
        download = admin.get(DEMO)
        generation = admin.get(API + "/session").json()["generation"]
        own = admin.get(DEMO + "?generation=" + generation)
        other = admin.get(DEMO + f"?generation={uuid4()}")
        unknown = admin.get(DEMO + "?pool=24")
        admin.post(API + "/samples/remove", {})
        removed = admin.get(DEMO)
    assert (missing.status_code, missing.json()["code"]) == (404, "NOT_FOUND")
    assert download.status_code == 200, download.text
    assert_no_secrets(download)
    assert download.headers["content-disposition"] == 'attachment; filename="sandbox.json"'
    assert download.headers["cache-control"] == "no-store"
    hosts = {host["effect"]: host for host in status["hosts"]}

    def target(effect):
        return {
            "kind": "hostname",
            "value": hosts[effect]["hostname"],
            "incident_id": hosts[effect]["incident_id"],
        }

    document = download.json()
    assert document == {
        "workspace": "samples",
        "origin": "http://127.0.0.1",
        "tenant_id": str(workspace.tenant_id),
        # This deployment's mock is on a loopback address, which the person's machine may not
        # reach as the gateway does, so the file names none (`samples.demo_configuration`).
        "targets": {
            "workstation": target("allow"),
            "domain_controller": target("deny"),
            "production": target("require approval"),
            "pool": [],
        },
    }
    # A tab still showing this workspace gets it; one that names another session does not.
    assert own.status_code == 200 and own.json() == document
    assert (other.status_code, other.json()["code"]) == (409, "WORKSPACE_CHANGED")
    assert unknown.status_code == 400
    assert (removed.status_code, removed.json()["code"]) == (404, "NOT_FOUND")
    # The producer and its consumer together: the demo loads the download once the person has
    # added the one agent key file it needs, and reads it as samples, never as fixtures.
    document["credentials"] = {"agent_a": "agent-a.token"}
    (tmp_path / "sandbox.json").write_text(json.dumps(document), encoding="utf-8")
    (tmp_path / "agent-a.token").write_text("ebt1.placeholder\n", encoding="ascii")
    sandbox = Sandbox.load(tmp_path, {})
    assert (sandbox.workspace, sandbox.synthetic, sandbox.pool) == ("samples", False, ())
    assert sandbox.targets["workstation"].value == hosts["allow"]["hostname"]
    assert sandbox.providers == {}


def test_sm11_api_an_account_session_downloads_only_with_its_own_generation(
    db, admin_engine, seeded, sample_key, tmp_path
):
    """The path a real administrator takes: signed in to an account, by password here as by
    any provider, whose session can switch workspaces. A download link carries no workspace
    header, so the route takes the tab's session generation as the report's CSV does: without
    it, or with another session's, it answers 409 `WORKSPACE_CHANGED` and nothing of the
    samples, and with its own it hands the file over. The console's link names it
    (`SampleTargets.demoConfigurationUrl`)."""
    from execbound.surfaces.sessions import issue_session

    workspace = password_workspace(admin_engine, db, tmp_path)
    samples.install(db, workspace.admin, available=True)
    grant = issue_session(db, workspace.admin)
    assert grant.account_token is not None
    app = create_app(db, runtime=offline_runtime(db, sample_key), human=console_config())
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        client.cookies.set("eb_session", grant.token, domain="127.0.0.1")
        client.cookies.set("eb_csrf", grant.csrf_token, domain="127.0.0.1")
        client.cookies.set("eb_account", grant.account_token, domain="127.0.0.1")
        missing = client.get(DEMO)
        other = client.get(DEMO + f"?generation={uuid4()}")
        own = client.get(DEMO + f"?generation={grant.session_id}")
    for refused in (missing, other):
        assert (refused.status_code, refused.json()["code"]) == (409, "WORKSPACE_CHANGED")
        assert "content-disposition" not in refused.headers
        assert "sample.invalid" not in refused.text
    assert own.status_code == 200, own.text
    assert own.json()["tenant_id"] == str(workspace.tenant_id)
    assert own.headers["content-disposition"] == 'attachment; filename="sandbox.json"'


def test_sm11_api_the_demo_configuration_is_an_administrators(db, admin_engine, seeded, sample_key):
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    approver = person(admin_engine, db, workspace)
    samples.install(db, workspace.admin, available=True)
    with console_client(db, runtime, admin_engine, approver) as reviewer:
        refused = reviewer.get(DEMO)
    assert (refused.status_code, refused.json()["code"]) == (403, "FORBIDDEN")


def test_sm11_api_the_demo_configuration_refuses_a_bearer_credential_and_a_missing_session(
    db, runtime, seeded, admin_engine, world
):
    results = refusals(db, runtime, seeded, admin_engine, world, DEMO, "GET")
    assert results["bearer"].status_code == 403 and results["audited"] == 1
    assert results["no_session"].status_code == 401


def test_sm11_api_no_demo_configuration_where_this_deployment_cannot_serve_the_samples(
    db, admin_engine, seeded, sample_key
):
    """Samples left in a workspace this deployment no longer serves, because it holds no sample
    key or now holds a configured connector for the tenant, derive no connection, so every
    request the demo sent would be refused, and a refresh would be refused
    `SAMPLES_UNAVAILABLE`. The status says the configuration is not offered, so the card shows
    no link, and the download answers `NOT_FOUND` rather than a file the demo cannot use."""
    workspace = empty_workspace(admin_engine, db)
    samples.install(db, workspace.admin, available=True)
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        served = admin.get(API + "/samples").json()
        assert admin.get(DEMO).status_code == 200
        assert (served["available"], served["demo_available"]) == (True, True)
    configured = MockConnector(
        ConnectionConfig(
            workspace.tenant_id,
            uuid4(),
            "http://127.0.0.1:9",
            "d" * 43,
            "c" * 43,
            {"journal-v1": b"\x01" * 32},
        )
    )
    try:
        held = Runtime(
            db,
            [configured],
            keys=TokenKeys("samples-v1", {"samples-v1": b"\x03" * 32}),
            sample_providers=[SampleProvider("mock_crowdstrike", "http://127.0.0.1:9", sample_key)],
        )
        for runtime in (offline_runtime(db, None), held):
            with console_client(db, runtime, admin_engine, workspace.admin) as admin:
                status = admin.get(API + "/samples").json()
                download = admin.get(DEMO)
                refreshed = admin.post(API + "/samples/refresh", {})
            assert (download.status_code, download.json()["code"]) == (404, "NOT_FOUND")
            assert (refreshed.status_code, refreshed.json()["code"]) == (409, "SAMPLES_UNAVAILABLE")
            assert status["state"] == "removable"
            assert (status["available"], status["demo_available"]) == (False, False)
    finally:
        configured.close()


@pytest.mark.parametrize(
    "change",
    [
        "UPDATE execbound.operation_mappings SET active = false "
        "WHERE tenant_id = :t AND operation_ref = 'endpoint.isolate'",
        "UPDATE execbound.operation_mappings SET operation_ref = 'sample.contain' "
        "WHERE tenant_id = :t AND operation_ref = 'endpoint.isolate'",
        "UPDATE execbound.incidents SET status = 'CLOSED' "
        "WHERE tenant_id = :t AND incident_id = :deny",
        "UPDATE execbound.incidents SET status = 'CLOSED' "
        "WHERE tenant_id = :t AND incident_id = :allow",
    ],
)
def test_sm11_api_no_demo_configuration_while_a_request_it_names_could_not_be_decided(
    db, admin_engine, seeded, sample_key, change
):
    """The starter's own mapping of the isolation action not live, or a named target without
    an open incident: the decide beat's first request would be refused, so the status says the
    configuration is not offered and the download answers `NOT_FOUND`. Neither is reachable
    through a command; only the definer functions write the samples' mapping and incidents."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    hosts = by_effect(installed)
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        conn.execute(
            text(change),
            {
                "t": workspace.tenant_id,
                "deny": hosts["deny"].incident_id,
                "allow": hosts["allow"].incident_id,
            },
        )
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        status = admin.get(API + "/samples").json()
        download = admin.get(DEMO)
    assert (download.status_code, download.json()["code"]) == (404, "NOT_FOUND")
    assert (status["state"], status["available"], status["demo_available"]) == (
        "removable",
        True,
        False,
    )


@pytest.mark.parametrize("change", ["a persons policy", "observing"])
def test_sm11_api_no_demo_configuration_while_the_starter_is_not_what_decides_the_samples(
    db, admin_engine, seeded, sample_key, change
):
    """The decide beat expects what the starter makes of the three targets: the workstation
    executes, the domain controller is denied and production waits for a person. A policy a
    person made and activated in its place decides them as that person wrote it, even an
    unchanged copy, and while it names the samples their refresh, the demo's only advice when
    a run goes otherwise, is refused. A workspace observing rather than enforcing executes and
    holds nothing, and a refresh leaves its mode as it is. Either way the samples, their
    mapping and their incidents are all as they were, and the status still says what the
    starter's rules read on each target; it says the configuration is not offered, and the
    download answers `NOT_FOUND`."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    if change == "a persons policy":
        copy = samples.starter_bundle(workspace.tenant_id, installed.account_id).model_copy(
            update={"bundle_id": uuid4()}
        )
        create_bundle(db, workspace.admin, copy)
        validate_bundle(db, workspace.admin, copy.bundle_id)
        activate_bundle(db, workspace.admin, copy.bundle_id)
    else:
        set_enforcement_mode(db, workspace.admin, "OBSERVE", "watching before enforcing")
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        status = admin.get(API + "/samples").json()
        download = admin.get(DEMO)
    assert (download.status_code, download.json()["code"]) == (404, "NOT_FOUND")
    assert (status["state"], status["available"], status["demo_available"]) == (
        "removable",
        True,
        False,
    )
    assert sorted(host["effect"] for host in status["hosts"]) == [
        "allow",
        "deny",
        "require approval",
    ]
    assert all(host["incident_id"] is not None for host in status["hosts"])


def test_sm11_api_no_demo_configuration_while_the_emergency_stop_is_active(
    db, admin_engine, seeded, sample_key
):
    """Under an emergency stop admission refuses every new request with 423 `TENANT_STOPPED`
    before it reads a fact, the decide beat's first among them, and neither a refresh nor a new
    download changes that: only an administrator's release does. So while the stop is active
    the status says the configuration is not offered and that no refresh is what it waits for,
    and the download answers `NOT_FOUND`; once the stop is released, with nothing else changed,
    it is offered again."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:

        def read():
            status = admin.get(API + "/samples").json()
            download = admin.get(DEMO)
            return (status["demo_available"], status["demo_needs_refresh"], download.status_code)

        assert read() == (True, False, 200)
        activate_stop(db, workspace.admin, "exploring the stop")
        assert read() == (False, False, 404)
        # What the status says is what admission does to the demo's first request.
        with pytest.raises(ExecutionError) as refused:
            ask(db, agent, by_effect(installed)["allow"], "demo-stopped")
        assert refused.value.code == "TENANT_STOPPED"
        release_stop(db, workspace.admin, "done exploring")
        assert read() == (True, False, 200)


def test_sm11_api_no_demo_configuration_once_guided_setups_requests_used_the_samples(
    db, admin_engine, seeded, sample_mock, sample_runtime
):
    """Guided setup has the person's own agent isolate the sample workstation, which executes,
    and the production workstation, which executes once they approve it. Each moves its target
    past the version the samples' facts record, so the demo's own isolation of it would end
    `STALE_AUTHORIZATION`: from then on the status says the demo needs a refresh rather than
    that it is available, the card offers no file, and the download answers `NOT_FOUND`, until
    a refresh records the targets afresh. A denial reaches no provider and changes nothing, and
    while a request waits for its approval neither is offered, since a refresh is refused then
    and the request may yet change its target."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True, clock=sample_runtime.clock)
    hosts = by_effect(installed)
    token = agent_token(admin_engine, workspace)

    def read(admin):
        status = admin.get(API + "/samples").json()
        download = admin.get(DEMO)
        return (status["demo_available"], status["demo_needs_refresh"], download.status_code)

    with (
        TestClient(create_app(db, runtime=sample_runtime)) as gateway,
        console_client(db, sample_runtime, admin_engine, workspace.admin) as admin,
    ):

        def isolate(effect, key):
            answer = gateway.post(
                "/v1/execute",
                json={
                    "operation_ref": "endpoint.isolate",
                    "target": {"kind": "hostname", "value": hosts[effect].hostname},
                    "arguments": {},
                    "idempotency_key": key,
                    "claimed_context": {"incident_id": str(hosts[effect].incident_id)},
                },
                headers={"Authorization": "Bearer " + token},
            )
            assert answer.status_code in (200, 202), answer.text
            return answer.json()

        assert read(admin) == (True, False, 200)
        assert isolate("deny", "setup-dc")["state"] == "DENIED"
        assert read(admin) == (True, False, 200)
        held = isolate("require approval", "setup-prod")
        assert held["state"] == "PENDING_APPROVAL"
        assert read(admin) == (False, False, 404)
        decide_approval(
            db, workspace.admin, UUID(held["approval_id"]), "APPROVE", sample_runtime.clock
        )
        assert isolate("require approval", "setup-prod")["state"] == "EXECUTED"
        assert read(admin) == (False, True, 404)
        assert isolate("allow", "setup-dev")["state"] == "EXECUTED"
        assert read(admin) == (False, True, 404)
        refreshed = admin.post(API + "/samples/refresh", {})
        assert refreshed.status_code == 200, refreshed.text
        assert (refreshed.json()["demo_available"], refreshed.json()["demo_needs_refresh"]) == (
            True,
            False,
        )
        assert read(admin) == (True, False, 200)


def aged(admin_engine, tenant, interval: str) -> None:
    """The samples' facts as though recorded `interval` earlier, as `test_samples` ages them:
    nothing but a refresh records them again."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        for table in ("resources", "incidents"):
            conn.execute(
                text(
                    f"UPDATE execbound.{table} "
                    "SET observed_at = observed_at - CAST(:age AS interval) WHERE tenant_id = :t"
                ),
                {"t": tenant, "age": interval},
            )


def test_sm11_api_no_demo_configuration_once_the_sample_facts_are_stale(
    db, admin_engine, seeded, sample_key
):
    """The starter keeps the samples' facts for an hour and nothing records them again but a
    refresh, so from `stale_at` every request on them, the decide beat's first among them, is
    refused before any decision with 503 `EXECUTION_UNAVAILABLE`. From then the status says a
    refresh is what the demo waits for rather than that it is available, so the card offers no
    file, and the download answers `NOT_FOUND`, until a refresh records the facts again."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:

        def read():
            status = admin.get(API + "/samples").json()
            download = admin.get(DEMO)
            flags = (status["demo_available"], status["demo_needs_refresh"], download.status_code)
            return status, flags

        fresh, flags = read()
        assert flags == (True, False, 200)
        aged(admin_engine, workspace.tenant_id, "2 hours")
        stale, flags = read()
        assert datetime.fromisoformat(stale["stale_at"]) < datetime.now(UTC)
        assert flags == (False, True, 404)
        # Nothing else the demo needs moved: only the facts' age did.
        assert (stale["state"], stale["available"], stale["hosts"]) == (
            fresh["state"],
            fresh["available"],
            fresh["hosts"],
        )
        # What the status says is what admission does to the demo's first request.
        with pytest.raises(ExecutionError) as refused:
            ask(db, agent, by_effect(installed)["allow"], "demo-stale")
        assert refused.value.code == "EXECUTION_UNAVAILABLE"
        refreshed = admin.post(API + "/samples/refresh", {})
        assert refreshed.status_code == 200, refreshed.text
        assert (refreshed.json()["demo_available"], refreshed.json()["demo_needs_refresh"]) == (
            True,
            False,
        )
        assert read()[1] == (True, False, 200)


@pytest.mark.parametrize("console", ["http://127.0.0.1", "https://console.example"])
def test_sm11_api_the_demo_configuration_names_the_mock_that_serves_the_samples(
    db, admin_engine, seeded, sample_key, console
):
    """The file names the endpoint mock this deployment serves the samples from, so the
    boundary beat shows that mock refusing the agent's key, and names it whatever the
    console's own origin, loopback as in local development or public as on a deployment that
    publishes both: never the console, which would have the beat hand agent A's key to the
    gateway and call its refusal the mock's. A token reads it here, so one application serves
    either origin without a browser sign-in."""
    mock = "https://endpoint-mock.example"
    workspace = empty_workspace(admin_engine, db)
    runtime = Runtime(
        db,
        [],
        keys=TokenKeys("samples-v1", {"samples-v1": secrets.token_bytes(32)}),
        sample_providers=[SampleProvider("mock_crowdstrike", mock, sample_key)],
    )
    samples.install(db, workspace.admin, available=True)
    token = minted_for(runtime, workspace.admin)
    keys = TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)})
    app = create_app(db, runtime=runtime, human=HumanConfig(console, keys))
    with TestClient(app, base_url=console, follow_redirects=False) as client:
        download = client.get(DEMO, headers={"Authorization": f"Bearer {token}"})
    assert download.status_code == 200, download.text
    document = download.json()
    assert (document["origin"], document["providers"]) == (console, {"endpoint": mock})


def test_sm11_api_a_demo_configuration_the_secret_check_refuses_never_leaves(
    db, admin_engine, seeded, sample_key, monkeypatch, captured
):
    """The document is built from hostnames, identifiers and configured origins, so nothing in
    it should be a secret; the mock's origin is an operator's configuration all the same, so the
    route puts the document through the export's secret check before it leaves. A document the
    check refuses is a fault: answered 503 `UNAVAILABLE`, logged as `dependency.unavailable` with
    the code `PRIVATE_DATA` and nothing of what it found, and never sent."""
    workspace = empty_workspace(admin_engine, db)
    runtime = offline_runtime(db, sample_key)
    samples.install(db, workspace.admin, available=True)
    # An agent API key's shape, put together here so the file itself carries none.
    secret = ".".join(("eb1", str(uuid4()), str(uuid4()), secrets.token_urlsafe(18)))
    built = samples.demo_configuration

    def leaking(status, **names):
        document = built(status, **names)
        assert document is not None
        return {**document, "providers": {"endpoint": secret}}

    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        assert admin.get(DEMO).status_code == 200
        monkeypatch.setattr(samples, "demo_configuration", leaking)
        refused = admin.get(DEMO)
    assert (refused.status_code, refused.json()["code"]) == (503, "UNAVAILABLE")
    assert secret not in refused.text
    assert "content-disposition" not in refused.headers
    faults = logged(captured, "dependency.unavailable")
    assert [(record["level"], record["code"]) for record in faults] == [("ERROR", "PRIVATE_DATA")]
    assert secret.split(".")[1] not in captured.getvalue()
