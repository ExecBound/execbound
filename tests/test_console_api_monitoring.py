# SPDX-License-Identifier: AGPL-3.0-only
"""The monitoring area of the console API (#333).

Connections, sources, inventory, external activity, findings with acknowledge and alert
delivery come from `snapshot`; the Scout agent views from `agents_snapshot` and `agent_detail`.
The rows are seeded the way the page tests seed them: a fake Tines tenant collected with
inventory, a source-reported event evaluated into a finding, and a fake directory collected
into one agent with a grant. Every route is an administrator's, and every response passes the
secret check and carries none of the fixture's forbidden strings.
"""

import json
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import httpx
import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, refusals
from monitoring_fixtures import HOSTILE_NAME, collect
from secret_shapes import STRIPE
from space_fixtures import default_space, make_space, place, seat
from sqlalchemy import text
from test_console_api_tokens import backing_credential, bearer, minted, post
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_scout_run import AGENT_ONE, agent, detailed_scenario
from test_tines_collection import FIXTURE, KEY, SECRETS, scenario

from execbound.monitoring import collection, due
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import DetectionProfile
from execbound_harness.fake_tines import BASE_URL, serving, transport

ZERO = "00000000-0000-0000-0000-000000000000"
ROUTES = [
    (API + "/monitor", "GET"),
    (API + "/monitor/agents", "GET"),
    (API + f"/monitor/agents/{ZERO}", "GET"),
    (API + "/monitor/findings", "GET"),
    (API + f"/monitor/findings/{ZERO}", "GET"),
    (API + f"/monitor/findings/{ZERO}/acknowledge", "POST"),
    (API + "/monitor/findings/acknowledge", "POST"),
]


def seed_tines(db, world):
    """A collected fake Tines tenant: a connection, an instrumented source, inventory,
    observations and the findings their evaluation raises."""
    clock = world["clock"]
    connection_id = monitor_store.create_connection(
        db,
        world["admin"],
        label="Synthetic Tines tenant",
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint(KEY),
        team_id="7",
        clock=clock,
    )
    monitor_store.create_source(
        db,
        world["admin"],
        label="Phishing triage <b>source</b>",
        story_id="4001",
        expires_at=clock.now() + timedelta(hours=2),
        clock=clock,
    )
    spec = scenario(clock.now(), audit=list(FIXTURE["audit"]) + list(FIXTURE["ai_audit"]))
    with serving(spec) as server:
        with httpx.Client(
            transport=transport(server), trust_env=False, follow_redirects=False
        ) as http:
            collection.run(
                db,
                world["admin"],
                connection_id=connection_id,
                api_key=KEY,
                client=http,
                inventory=True,
                clock=clock,
            )
    monitor_store.evaluate_pending(db, world["admin"], limit=100, clock=clock)
    return connection_id


def finding_in_another_space(db, admin_engine, world):
    """Two spaces, an administrator narrowed to the first and one open finding in the second.

    Seeds the collected Tines tenant first. The oldest open finding moves to a new space,
    "Customer B"; the next stays in the default space, where the narrowed administrator is
    seated as `ADMIN`. The world's administrator holds no membership: workspace-wide.
    """
    seed_tines(db, world)
    tenant = world["admin"].tenant_id
    narrowed = provision_identity(admin_engine, db, tenant, "ADMIN", world["clock"].now())
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        own = default_space(conn, tenant)
        other = make_space(conn, tenant, "Customer B")
        seat(conn, tenant, own, narrowed.principal_id, "ADMIN")
        findings = [
            UUID(str(value))
            for value in conn.execute(
                text(
                    "SELECT finding_id FROM execbound.monitor_findings "
                    "WHERE tenant_id=:t AND acknowledged_at IS NULL "
                    "ORDER BY created_at, finding_id"
                ),
                {"t": tenant},
            ).scalars()
        ]
        assert len(findings) >= 2, "the seeded tenant raises at least two open findings"
        place(conn, tenant, "monitor_findings", "finding_id", findings[0], other)
    return {
        "tenant": tenant,
        "own": own,
        "other": other,
        "elsewhere": findings[0],
        "here": findings[1],
        "narrowed": narrowed,
    }


def acknowledgement(admin_engine, tenant, finding):
    """The finding's acknowledgement columns and the events acknowledging it."""
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        row = conn.execute(
            text(
                "SELECT acknowledged_at, acknowledged_by FROM execbound.monitor_findings "
                "WHERE tenant_id=:t AND finding_id=:f"
            ),
            {"t": tenant, "f": finding},
        ).one()
        events = [
            dict(payload)
            for payload in conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t "
                    "AND kind='monitor.finding_acknowledged' AND payload->>'finding_id'=:f "
                    "ORDER BY sequence"
                ),
                {"t": tenant, "f": str(finding)},
            ).scalars()
        ]
    return row.acknowledged_at, row.acknowledged_by, events


def seed_agent(db, world, **changes):
    monitor_store.set_profile(
        db,
        world["admin"],
        DetectionProfile(sensitive_actions=("identity.disable",), restricted_targets=()),
        clock=world["clock"],
    )
    connection_id = collect(db, world["admin"], world["clock"], **changes)
    with db.transaction(world["admin"].tenant_id) as conn:
        agent_id = conn.execute(
            text("SELECT agent_id FROM execbound.monitor_agents WHERE platform_ref=:r"),
            {"r": AGENT_ONE},
        ).scalar_one()
    return connection_id, agent_id


def test_the_monitor_routes_are_an_administrators(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        for path, method in ROUTES:
            response = approver.get(path) if method == "GET" else approver.post(path, {})
            assert response.status_code == 403 and response.json()["code"] == "FORBIDDEN", path


@pytest.mark.parametrize("path,method", ROUTES)
def test_every_monitor_route_refuses_a_bearer_credential_and_a_missing_session(
    db, runtime, seeded, admin_engine, world, path, method
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403 and results["audited"] == 1, path
    assert results["no_session"].status_code == 401, path


def test_the_snapshot_carries_every_view_as_metadata_and_never_the_fixture_secrets(
    db, runtime, admin_engine, world
):
    seed_tines(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(API + "/monitor")
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        view = response.json()
        connection = view["connections"][0]
        assert connection["label"] == "Synthetic Tines tenant"
        assert connection["health_state"] == "COLLECTING"
        assert connection["team_id"] == "7" and connection["base_url"] == BASE_URL
        assert "ai_audit" in connection["capabilities"]
        assert set(connection["capabilities"]["stories"]) == {"state", "at"}
        assert "key_fingerprint" not in json.dumps(connection)
        source = view["sources"][0]
        assert source["label"] == "Phishing triage <b>source</b>"
        assert source["story_id"] == "4001" and source["coverage"] == "No heartbeat"
        assert "token" not in json.dumps(source)
        stories = {row["name"]: row["coverage"] for row in view["stories"]}
        assert stories["Phishing triage"] == "Instrumented"
        assert "Outbound actions, no reporting source" in stories.values()
        assert "Coverage unknown" in stories.values()
        assert "Disabled in the platform" in stories.values()
        assert {row["name"] for row in view["credentials"]} >= {"okta_api"}
        collected = [row for row in view["observations"] if row["evidence"] == "collected"]
        assert collected and "StoryUpdated" in {row["operation_name"] for row in collected}
        assert view["findings"] and any(
            row["rule_version"] == "monitored-path-change.v1" for row in view["findings"]
        )
        assert view["open_findings"] == sum(
            1 for row in view["findings"] if row["acknowledged_at"] is None
        )
        assert view["profile"] is None
        # Every finding raised an intent to deliver it; the state is the worker's, not ours.
        assert {row["finding_id"] for row in view["deliveries"]} == {
            row["finding_id"] for row in view["findings"]
        }
        assert all(row["state"] == "PENDING" and row["attempts"] == 0 for row in view["deliveries"])
        for secret in SECRETS:
            assert secret not in response.text, secret
        assert len(view["observations"]) <= 200


def test_a_finding_is_acknowledged_once_by_the_administrator_and_an_unknown_one_is_404(
    db, runtime, admin_engine, world
):
    seed_tines(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        before = admin.get(API + "/monitor").json()
        open_findings = [row for row in before["findings"] if row["acknowledged_at"] is None]
        assert open_findings
        target = open_findings[0]["finding_id"]
        acknowledged = admin.post(API + f"/monitor/findings/{target}/acknowledge", {})
        assert acknowledged.status_code == 200, acknowledged.text
        assert_no_secrets(acknowledged)
        after = acknowledged.json()
        row = next(item for item in after["findings"] if item["finding_id"] == target)
        assert row["acknowledged_by"] == str(world["admin"].principal_id)
        assert row["acknowledged_at"] is not None
        assert after["open_findings"] == before["open_findings"] - 1
        # Acknowledging again changes nothing and answers the same view.
        again = admin.post(API + f"/monitor/findings/{target}/acknowledge", {})
        assert again.status_code == 200
        assert again.json()["open_findings"] == after["open_findings"]
        # A finding that is not this tenant's, and an address that is not an identifier.
        assert admin.post(API + f"/monitor/findings/{uuid4()}/acknowledge", {}).status_code == 404
        assert admin.post(API + "/monitor/findings/not-an-id/acknowledge", {}).status_code == 404
        assert (
            admin.post(API + f"/monitor/findings/{target.upper()}/acknowledge", {}).status_code
            == 404
        )
        # The body holds an optional note and nothing else.
        extra = admin.post(API + f"/monitor/findings/{target}/acknowledge", {"reason": "x"})
        assert extra.status_code == 400 and extra.json()["fields"] == ["reason"]


def test_the_agent_views_state_their_denominator_and_show_every_path(
    db, runtime, admin_engine, world
):
    connection_id, agent_id = seed_agent(
        db, world, scenario=detailed_scenario(agents=[agent(1, displayName=HOSTILE_NAME)])
    )
    monitor_store.link_agent(
        db,
        world["admin"],
        connection_id=connection_id,
        platform_ref=AGENT_ONE,
        principal_id=world["identity"].principal_id,
        clock=world["clock"],
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        listing = admin.get(API + "/monitor/agents")
        assert listing.status_code == 200, listing.text
        assert_no_secrets(listing)
        view = listing.json()
        assert view["tenant"]["enumerated"] == 1 and view["tenant"]["shown"] == 1
        assert view["consequential"] == ["identity.disable"]
        row = view["agents"][0]
        assert row["agent_id"] == str(agent_id)
        assert row["display_name"] == HOSTILE_NAME  # data, which the client renders as text
        assert row["identity_class"] == "agent_identity"
        assert row["sponsor_state"] == "present" and len(row["sponsors"]) == 1
        assert row["consequential"] >= 1 and row["governed"] >= 0
        assert row["linked_principal_id"] == str(world["identity"].principal_id)

        detail = admin.get(API + f"/monitor/agents/{agent_id}")
        assert detail.status_code == 200, detail.text
        assert_no_secrets(detail)
        body = detail.json()
        assert body["agent"]["display_name"] == HOSTILE_NAME
        assert body["agent"]["platform_ref"] == AGENT_ONE
        assert body["agent"]["connection_id"] == str(connection_id)
        reach = {(row["action"], row["path_kind"]): row for row in body["reach"]}
        grant = reach[("identity.disable", "grant")]
        assert grant["certainty"] == "inferred" and grant["effective"] == "inferred"
        assert grant["enforcement_mode"] == "unknown"
        assert any(row["value"] == "allAllowed" and row["inherited"] for row in body["grants"])
        assert any(row["actions"] == [] for row in body["grants"])
        assert body["unresolved"] >= 1
        assert "person@synthetic.invalid" not in detail.text and "A Person" not in detail.text
        # Another tenant's agent, or no agent at all, is an address that does not exist.
        assert admin.get(API + f"/monitor/agents/{uuid4()}").status_code == 404
        assert admin.get(API + "/monitor/agents/not-an-id").status_code == 404
        assert admin.get(API + "/monitor/agents/not-an-id").json()["code"] == "NOT_FOUND"
        assert UUID(row["agent_id"])


def test_mq1_acknowledging_outside_the_space_answers_as_unknown(db, runtime, admin_engine, world):
    """A narrowed administrator naming another space's finding is told what a made-up
    identifier is told, byte for byte, and nothing about the finding changes."""
    spaces = finding_in_another_space(db, admin_engine, world)
    with console_client(db, runtime, admin_engine, spaces["narrowed"]) as narrowed:
        elsewhere = narrowed.post(API + f"/monitor/findings/{spaces['elsewhere']}/acknowledge", {})
        unknown = narrowed.post(API + f"/monitor/findings/{uuid4()}/acknowledge", {})
        assert elsewhere.status_code == unknown.status_code == 404
        assert elsewhere.json()["code"] == "NOT_FOUND"
        assert elsewhere.content == unknown.content
        assert acknowledgement(admin_engine, spaces["tenant"], spaces["elsewhere"]) == (
            None,
            None,
            [],
        )
        # Their own space's finding is theirs to acknowledge.
        own = narrowed.post(API + f"/monitor/findings/{spaces['here']}/acknowledge", {})
        assert own.status_code == 200, own.text
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert (
            admin.post(API + f"/monitor/findings/{spaces['elsewhere']}/acknowledge", {}).status_code
            == 200
        )
    assert acknowledgement(admin_engine, spaces["tenant"], spaces["elsewhere"])[1] == (
        world["admin"].principal_id
    )


def test_mq2_a_token_acknowledgement_names_its_credential(db, runtime, admin_engine, world):
    """The event names the credential that acted: the personal access token's backing
    credential for the token, the session's own for the browser (T4.42)."""
    spaces = finding_in_another_space(db, admin_engine, world)
    tenant = spaces["tenant"]
    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            answered = post(
                client, API + f"/monitor/findings/{spaces['elsewhere']}/acknowledge", token
            )
            assert answered.status_code == 200, answered.text
            # The repeat is the idempotent 200 it always was, and appends nothing.
            again = post(
                client, API + f"/monitor/findings/{spaces['elsewhere']}/acknowledge", token
            )
            assert again.status_code == 200, again.text
        browser = console.post(API + f"/monitor/findings/{spaces['here']}/acknowledge", {})
        assert browser.status_code == 200, browser.text
    backing = str(backing_credential(admin_engine, token))
    _, _, by_token = acknowledgement(admin_engine, tenant, spaces["elsewhere"])
    assert [event["actor_credential_id"] for event in by_token] == [backing]
    _, _, by_browser = acknowledgement(admin_engine, tenant, spaces["here"])
    assert [event["actor_credential_id"] for event in by_browser] == [
        str(world["admin"].credential_id)
    ]
    assert backing != str(world["admin"].credential_id)


def test_cf8_an_acknowledgement_names_who_made_it(db, runtime, admin_engine, world):
    """The finding names the administrator who acknowledged it by kind and number (#678), on
    the acknowledgement's own answer and on the next read; the UUID stays beside it."""
    seed_tines(db, world)
    admin_id = str(world["admin"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        before = admin.get(API + "/monitor").json()
        target = next(row for row in before["findings"] if row["acknowledged_at"] is None)
        assert target["acknowledged_by_ref"] is None
        answer = admin.post(API + f"/monitor/findings/{target['finding_id']}/acknowledge", {})
        assert answer.status_code == 200, answer.text
        for view in (answer.json(), admin.get(API + "/monitor").json()):
            row = next(
                item for item in view["findings"] if item["finding_id"] == target["finding_id"]
            )
            assert row["acknowledged_by"] == admin_id
            ref = row["acknowledged_by_ref"]
            assert (ref["principal_id"], ref["kind"], ref["number"]) == (admin_id, "ADMIN", 1)


def test_mq4_findings_answer_by_state_and_refuse_anything_else(db, runtime, admin_engine, world):
    seed_tines(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        snapshot = admin.get(API + "/monitor").json()
        target = next(row for row in snapshot["findings"] if row["acknowledged_at"] is None)
        assert admin.post(API + f"/monitor/findings/{target['finding_id']}/acknowledge", {})
        snapshot = admin.get(API + "/monitor").json()
        answers = {}
        for state in ("open", "acknowledged", "all"):
            response = admin.get(API + f"/monitor/findings?state={state}")
            assert response.status_code == 200, response.text
            assert_no_secrets(response)
            answers[state] = response.json()
            assert answers[state]["state"] == state
        default = admin.get(API + "/monitor/findings")
        assert default.status_code == 200 and default.json()["state"] == "open"
        counts = answers["all"]["counts"]
        assert counts["open"] == snapshot["open_findings"] == len(answers["open"]["findings"])
        assert counts["acknowledged"] == 1 == len(answers["acknowledged"]["findings"])
        assert all(row["acknowledged_at"] is None for row in answers["open"]["findings"])
        assert [row["finding_id"] for row in answers["acknowledged"]["findings"]] == [
            target["finding_id"]
        ]
        newest = [row["created_at"] for row in answers["all"]["findings"]]
        assert newest == sorted(newest, reverse=True)
        assert answers["all"]["profile"] is None
        bad = admin.get(API + "/monitor/findings?state=closed")
        assert bad.status_code == 400 and bad.json()["code"] == "INVALID_REQUEST"
        assert admin.get(API + "/monitor/findings?state=open&x=1").status_code == 400


def test_mq5_one_finding_answers_by_identifier_only_where_visible(db, runtime, admin_engine, world):
    spaces = finding_in_another_space(db, admin_engine, world)
    with console_client(db, runtime, admin_engine, spaces["narrowed"]) as narrowed:
        here = narrowed.get(API + f"/monitor/findings/{spaces['here']}")
        assert here.status_code == 200, here.text
        assert here.json()["finding_id"] == str(spaces["here"])
        assert_no_secrets(here)
        unknown = narrowed.get(API + f"/monitor/findings/{uuid4()}")
        assert unknown.status_code == 404 and unknown.json()["code"] == "NOT_FOUND"
        for address in (
            str(spaces["elsewhere"]),
            str(spaces["here"]).upper(),
            "not-an-id",
        ):
            refused = narrowed.get(API + f"/monitor/findings/{address}")
            assert refused.status_code == 404 and refused.content == unknown.content, address
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(API + f"/monitor/findings/{spaces['elsewhere']}").status_code == 200


def test_mq6_markup_in_labels_travels_as_data(db, runtime, admin_engine, world):
    connection_id, agent_id = seed_agent(
        db, world, scenario=detailed_scenario(agents=[agent(1, displayName=HOSTILE_NAME)])
    )
    finding = uuid4()
    with db.transaction(world["admin"].tenant_id) as conn:
        monitor_store._finding(
            conn,
            world["admin"].tenant_id,
            None,
            None,
            "ungoverned-reach.v1",
            "Reach",
            world["clock"].now(),
            finding_id=finding,
            connection=connection_id,
            agent=agent_id,
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        one = admin.get(API + f"/monitor/findings/{finding}")
        assert one.status_code == 200, one.text
        body = one.json()
        assert body["agent"]["display_name"] == HOSTILE_NAME
        assert body["agent"]["agent_id"] == str(agent_id)
        assert body["agent"]["sponsor_count"] == 1 and "sponsors" not in body["agent"]
        assert body["connection_label"] == "Synthetic directory"
        assert body["source_label"] is None
        listed = admin.get(API + "/monitor/findings?state=all").json()["findings"]
        assert next(row for row in listed if row["finding_id"] == str(finding)) == body
        snapshot = admin.get(API + "/monitor").json()["findings"]
        assert next(row for row in snapshot if row["finding_id"] == str(finding)) == body
        detail = admin.get(API + f"/monitor/agents/{agent_id}").json()
        assert detail["agent"]["display_name"] == HOSTILE_NAME


def test_sr16_a_retained_new_agent_finding_is_served_under_its_agent(
    db, runtime, admin_engine, world
):
    """`new-agent.v1` is raised no more (#355); a finding an earlier release raised is still
    listed and served with the agent it names, alone and in the list."""
    connection_id, agent_id = seed_agent(db, world)
    finding = uuid4()
    with db.transaction(world["admin"].tenant_id) as conn:
        monitor_store._finding(
            conn,
            world["admin"].tenant_id,
            None,
            None,
            monitor_store.NEW_AGENT_RULE,
            "New agent identity first seen since the last collection",
            world["clock"].now(),
            finding_id=finding,
            connection=connection_id,
            agent=agent_id,
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        one = admin.get(API + f"/monitor/findings/{finding}")
        assert one.status_code == 200, one.text
        body = one.json()
        assert body["rule_version"] == "new-agent.v1"
        assert body["agent"]["agent_id"] == str(agent_id)
        assert body["observation_id"] is None
        assert body["connection_label"] == "Synthetic directory"
        listed = admin.get(API + "/monitor/findings?state=all").json()["findings"]
        assert next(row for row in listed if row["finding_id"] == str(finding)) == body


def test_mq7_the_connection_carries_its_freshness(db, runtime, admin_engine, world):
    connection = seed_tines(db, world)
    now = world["clock"].now()
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        fresh = admin.get(API + "/monitor").json()["connections"][0]
        assert fresh["reporting"] is True and fresh["overdue_since"] is None
        assert admin.get(API + "/tenant").json()["monitoring"]["overdue"] == 0
        assert admin.get(API + "/overview").json()["monitoring"]["overdue"] == 0
        with admin_engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"),
                {"t": str(world["admin"].tenant_id)},
            )
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET last_run_at=:at, last_sync_at=:at "
                    "WHERE connection_id=:c"
                ),
                {"at": now - timedelta(hours=25), "c": connection},
            )
        stopped = admin.get(API + "/monitor").json()["connections"][0]
        assert stopped["reporting"] is False
        assert stopped["overdue_since"] is not None
        assert admin.get(API + "/tenant").json()["monitoring"]["overdue"] == 1
        assert admin.get(API + "/overview").json()["monitoring"]["overdue"] == 1


def test_mc5_the_connection_carries_its_schedule_and_never_its_lease(
    db, runtime, admin_engine, world
):
    """Each connection's mode, its intervals with the defaults filled in, a waiting request
    and who made it, whether a run holds it now and when it is next due, by `due_at` itself;
    the lease's own id never leaves the database."""
    connection = seed_tines(db, world)
    admin = world["admin"]
    tenant = admin.tenant_id
    with console_client(db, runtime, admin_engine, admin) as client:
        row = client.get(API + "/monitor").json()["connections"][0]
        assert (row["kind"], row["credential_mode"]) == ("tines", "key_file")
        assert (row["collect_interval_seconds"], row["activity_interval_seconds"]) == (86400, 900)
        assert (row["collect_requested_at"], row["collect_requested_by"]) == (None, None)
        assert row["collecting"] is False
        with admin_engine.connect() as conn:
            stored = dict(
                conn.execute(
                    text(
                        "SELECT * FROM execbound.monitor_connections "
                        "WHERE tenant_id = :t AND connection_id = :c"
                    ),
                    {"t": tenant, "c": connection},
                )
                .mappings()
                .one()
            )
        expected = due.due_at(stored, world["clock"].now())
        assert expected is not None
        assert datetime.fromisoformat(row["next_due_at"]) == expected
        # A run holds the connection, and an administrator asks for a collection after it.
        lease = uuid4()
        assert due.claim(db, admin, connection, lease)
        with db.transaction(tenant) as conn:
            conn.execute(
                text("SELECT execbound.admin_request_collection(:a, :c)"),
                {"a": admin.principal_id, "c": connection},
            )
        answered = client.get(API + "/monitor")
        held = answered.json()["connections"][0]
        assert held["collecting"] is True
        assert held["collect_requested_at"] is not None
        assert held["collect_requested_by"]["principal_id"] == str(admin.principal_id)
        assert held["collect_requested_by"]["kind"] == "ADMIN"
        assert "collecting_lease" not in held and "collecting_until" not in held
        assert str(lease) not in answered.text
        # Not due before the run's lease ends.
        assert datetime.fromisoformat(held["next_due_at"]) > world["clock"].now()
        due.release(db, admin, connection, lease)
        assert client.get(API + "/monitor").json()["connections"][0]["collecting"] is False


def test_mc5_an_entra_connection_carries_its_own_default_and_no_activity_interval(
    db, runtime, admin_engine, world
):
    collect(db, world["admin"], world["clock"])
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        row = client.get(API + "/monitor").json()["connections"][0]
    assert (row["kind"], row["credential_mode"]) == ("entra_agent_id", "key_file")
    assert (row["collect_interval_seconds"], row["activity_interval_seconds"]) == (21600, None)
    assert row["next_due_at"] is not None


# The note and bulk acknowledgement over HTTP (MQ13, MQ14).


def test_mq13_the_note_over_http(db, runtime, admin_engine, world):
    spaces = finding_in_another_space(db, admin_engine, world)
    tenant = spaces["tenant"]
    noted, other = spaces["elsewhere"], spaces["here"]
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        answered = admin.post(
            API + f"/monitor/findings/{noted}/acknowledge", {"note": "  Looked at it.  "}
        )
        assert answered.status_code == 200, answered.text
        row = next(item for item in answered.json()["findings"] if item["finding_id"] == str(noted))
        assert row["acknowledgement_note"] == "Looked at it."
        assert admin.get(API + f"/monitor/findings/{noted}").json()["acknowledgement_note"] == (
            "Looked at it."
        )
        # A note shaped like a secret is refused by name and never repeated.
        secret = admin.post(API + f"/monitor/findings/{other}/acknowledge", {"note": STRIPE})
        assert secret.status_code == 400 and secret.json()["code"] == "INVALID_BODY"
        assert secret.json()["fields"] == ["note"]
        assert STRIPE not in secret.text
        long = admin.post(API + f"/monitor/findings/{other}/acknowledge", {"note": "x" * 501})
        assert long.status_code == 400 and long.json()["fields"] == ["note"]
        assert acknowledgement(admin_engine, tenant, other) == (None, None, [])
        # A note on a finding someone acknowledged first saves nothing.
        late = admin.post(API + f"/monitor/findings/{noted}/acknowledge", {"note": "Me too."})
        assert late.status_code == 409 and late.json()["code"] == "CONFLICT"
        _, _, events = acknowledgement(admin_engine, tenant, noted)
        assert [event.get("note") for event in events] == ["Looked at it."]
        # Without a note the repeat is still the idempotent 200.
        assert admin.post(API + f"/monitor/findings/{noted}/acknowledge", {}).status_code == 200


def bulk(client, ids, note=None):
    body: dict = {"finding_ids": [str(item) for item in ids]}
    if note is not None:
        body["note"] = note
    return client.post(API + "/monitor/findings/acknowledge", body)


def test_mq14_bulk_over_http(db, runtime, admin_engine, world):
    spaces = finding_in_another_space(db, admin_engine, world)
    tenant = spaces["tenant"]
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        more = [
            UUID(str(value))
            for value in conn.execute(
                text(
                    "SELECT finding_id FROM execbound.monitor_findings WHERE tenant_id=:t "
                    "AND acknowledged_at IS NULL AND finding_id <> ALL(CAST(:skip AS uuid[])) "
                    "ORDER BY created_at, finding_id LIMIT 2"
                ),
                {"t": tenant, "skip": [str(spaces["here"]), str(spaces["elsewhere"])]},
            ).scalars()
        ]
    assert len(more) == 2, "the seeded tenant raises at least four open findings"
    second, done = more
    unknown = uuid4()
    with console_client(db, runtime, admin_engine, spaces["narrowed"]) as narrowed:
        first = narrowed.post(API + f"/monitor/findings/{done}/acknowledge", {})
        assert first.status_code == 200, first.text
        ids = [spaces["here"], second, done, spaces["elsewhere"], unknown]
        answered = bulk(narrowed, ids, note="Batch reviewed.")
        assert answered.status_code == 200, answered.text
        assert_no_secrets(answered)
        assert answered.json() == {
            "results": [
                {"finding_id": str(spaces["here"]), "outcome": "acknowledged"},
                {"finding_id": str(second), "outcome": "acknowledged"},
                {"finding_id": str(done), "outcome": "already_acknowledged"},
                {"finding_id": str(spaces["elsewhere"]), "outcome": "unavailable"},
                {"finding_id": str(unknown), "outcome": "unavailable"},
            ]
        }
        # The batch's faults are the body's, named, and nothing is written.
        for faulty in (
            [second, second],
            [uuid4() for _ in range(51)],
            [],
            [str(uuid4()).upper()],
            ["not-an-id"],
        ):
            refused = narrowed.post(
                API + "/monitor/findings/acknowledge", {"finding_ids": [str(x) for x in faulty]}
            )
            assert refused.status_code == 400, (faulty, refused.text)
            assert refused.json()["code"] == "INVALID_BODY"
            assert refused.json()["fields"] == ["finding_ids"]
        secret = bulk(narrowed, [spaces["elsewhere"]], note=STRIPE)
        assert secret.status_code == 400 and secret.json()["fields"] == ["note"]
        assert STRIPE not in secret.text
        extra = narrowed.post(
            API + "/monitor/findings/acknowledge",
            {"finding_ids": [str(spaces["elsewhere"])], "reason": "x"},
        )
        assert extra.status_code == 400 and extra.json()["fields"] == ["reason"]
    assert acknowledgement(admin_engine, tenant, spaces["elsewhere"]) == (None, None, [])
    _, _, events = acknowledgement(admin_engine, tenant, second)
    assert [event["note"] for event in events] == ["Batch reviewed."]


def test_mq14_a_token_cannot_acknowledge_in_bulk(db, runtime, admin_engine, world):
    """Acknowledgement is final, so many at once needs a browser session; the token keeps the
    single-finding route, one audited finding per request."""
    spaces = finding_in_another_space(db, admin_engine, world)
    tenant = spaces["tenant"]
    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            refused = post(
                client,
                API + "/monitor/findings/acknowledge",
                token,
                {"finding_ids": [str(spaces["elsewhere"]), str(spaces["here"])]},
            )
            assert refused.status_code == 403 and refused.json()["code"] == "TOKEN_NOT_ALLOWED"
            assert acknowledgement(admin_engine, tenant, spaces["elsewhere"]) == (None, None, [])
            assert acknowledgement(admin_engine, tenant, spaces["here"]) == (None, None, [])
            one = post(
                client,
                API + f"/monitor/findings/{spaces['here']}/acknowledge",
                token,
                {"note": "From the pipeline."},
            )
            assert one.status_code == 200, one.text
    _, by, events = acknowledgement(admin_engine, tenant, spaces["here"])
    assert by == world["admin"].principal_id
    assert [event["actor_credential_id"] for event in events] == [
        str(backing_credential(admin_engine, token))
    ]
