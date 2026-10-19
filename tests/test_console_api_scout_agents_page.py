# SPDX-License-Identifier: AGPL-3.0-only
"""The console API of Scout's to-do list and the synthetic directory (#355, step 4): SR30 and SR31.

Real PostgreSQL. `POST /monitor/agents/{agent_id}/accept` accepts one to 50 of an actor's open
paths for a listed reason and period and `/withdraw` withdraws one, both behind a recently
verified factor and refused to a personal access token; `POST /monitor/connections/synthetic`
adds the workspace's synthetic directory, refused to a token, beside a directory and to an
administrator narrowed to some Spaces. Every answer that names the
synthetic directory says so, Agent connections refuses to govern or bind its actor, and every
answer passes the secret check.
"""

from contextlib import contextmanager
from datetime import timedelta
from typing import get_args
from uuid import UUID, uuid4

import httpx
import pytest
from console_api_fixtures import API, assert_no_secrets, console_client
from space_fixtures import default_space, make_space, seat, unseat
from sqlalchemy import text
from test_console_api_monitoring_connect import collector as collector
from test_console_api_monitoring_connect import with_entra
from test_console_api_step_up import RING, VERIFY, stale, step
from test_console_api_tokens import bearer, minted, post
from test_execution import registry as registry
from test_execution import world as world
from test_monitoring_store import FixedClock
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_scout_run import connect as connect_entra

from execbound import mfa
from execbound.assistant.tools import ToolContext, run_tool
from execbound.monitoring import graph, synthetic
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import DetectionProfile
from execbound.surfaces.console_api.monitoring import AcceptedPath
from execbound.surfaces.sessions import load_session

pytestmark = pytest.mark.integration

SYNTHETIC = API + "/monitor/connections/synthetic"
SESSION_SPACE = API + "/session/space"
ZERO = "00000000-0000-0000-0000-000000000000"


def accept(agent_id):
    return API + f"/monitor/agents/{agent_id}/accept"


def withdraw(agent_id):
    return API + f"/monitor/agents/{agent_id}/withdraw"


def collected(db, runtime, world, connection_id, times=2):
    """The synthetic directory collected `times`, an hour apart, with a profile that makes its
    reach consequential. The collections run on a clock of their own, so the console's sessions
    stay on the runtime's."""
    monitor_store.set_profile(
        db,
        world["admin"],
        DetectionProfile(
            sensitive_actions=("identity.disable", "identity.revoke_sessions"),
            restricted_targets=(),
        ),
        clock=runtime.clock,
    )
    clock = FixedClock(runtime.clock.now())
    for index in range(times):
        if index:
            clock.value += timedelta(hours=1)
        with httpx.Client() as unused:
            graph.run(
                db,
                world["admin"],
                connection_id=UUID(str(connection_id)),
                client=unused,
                clock=clock,
            )


def actor(admin_engine, tenant, ref):
    with admin_engine.connect() as conn:
        return str(
            conn.execute(
                text(
                    "SELECT agent_id FROM execbound.monitor_agents "
                    "WHERE tenant_id = :t AND platform_ref = :r"
                ),
                {"t": tenant, "r": ref},
            ).scalar_one()
        )


def open_paths(client, agent_id):
    detail = client.get(API + f"/monitor/agents/{agent_id}").json()
    return [
        {key: row[key] for key in ("action", "path_kind", "path_ref")}
        for row in detail["reach"]
        if row["open"]
    ]


def test_sr31_the_synthetic_directory_is_added_labelled_and_never_governed(
    db, runtime, admin_engine, world
):
    tenant = world["admin"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        added = client.post(SYNTHETIC, {})
        assert added.status_code == 201, added.text
        assert_no_secrets(added)
        answer = added.json()
        assert (answer["kind"], answer["credential_mode"], answer["label"]) == (
            "fixture",
            "synthetic",
            "Synthetic directory",
        )
        assert answer["base_url"] == synthetic.BASE_URL
        assert answer["collect_requested_at"] is not None
        again = client.post(SYNTHETIC, {})
        assert (again.status_code, again.json()["code"]) == (409, "CONNECTION_EXISTS")
        collected(db, runtime, world, answer["connection_id"])
        listing = client.get(API + "/monitor/agents")
        assert listing.status_code == 200, listing.text
        assert_no_secrets(listing)
        view = listing.json()
        assert view["tenant"]["per_source"] == {"entra": 0, "tines": 0, "synthetic": 6}
        assert view["tenant"]["unattributed"] == 3 and view["tenant"]["assessed"] is True
        assert all(row["synthetic"] and row["source"] == "fixture" for row in view["agents"])
        assert all(row["removal"] is None for row in view["agents"])
        # A workspace administrator may accept every one of them.
        assert all(row["administered"] for row in view["agents"])
        first = view["agents"][0]
        assert first["platform_ref"] == synthetic.OFFBOARDING
        assert first["driver"] == {"evidence": "network", "kind": "egress", "label": "Anthropic"}
        assert first["did"] >= synthetic.DAYS
        detail = client.get(API + f"/monitor/agents/{first['agent_id']}")
        assert detail.status_code == 200, detail.text
        assert_no_secrets(detail)
        assert detail.json()["agent"]["synthetic"] is True
        assert detail.json()["agent"]["source"] == "fixture"
        assert detail.json()["agent"]["administered"] is True
        assert synthetic.ANTHROPIC_ADDRESS not in detail.text
        findings = client.get(API + "/monitor/findings?state=all").json()["findings"]
        assert findings and all(row["synthetic"] for row in findings)
        snapshot = client.get(API + "/monitor").json()
        [listed] = snapshot["connections"]
        assert (listed["kind"], listed["label"]) == ("fixture", "Synthetic directory")
        # Agent connections labels it, and neither governs nor binds its actor.
        rows = client.get(API + "/agents").json()["agents"]
        assert {row["source_label"] for row in rows if row["source"] == "fixture"} == {
            "Synthetic directory"
        }
        discovered = client.get(API + f"/agents/{first['agent_id']}").json()
        assert discovered["discovered"]["agent"]["synthetic"] is True
        governed = client.post(API + f"/agents/{first['agent_id']}/govern", {"lifetime": "720"})
        assert (governed.status_code, governed.json()["code"]) == (409, "SYNTHETIC_ACTOR")
        bound = client.post(
            API + f"/agents/{first['agent_id']}/bind",
            {"target": str(world["identity"].principal_id)},
        )
        assert (bound.status_code, bound.json()["code"]) == (409, "SYNTHETIC_ACTOR")
        # Nor does a governed agent's page offer one to bind, since binding one is refused.
        picker = client.get(API + f"/agents/{world['identity'].principal_id}")
        assert picker.status_code == 200, picker.text
        assert picker.json()["binding"] is None
        listed = {row["agent_id"] for row in view["agents"]}
        assert len(listed) == 6
        assert not listed & {option["id"] for option in picker.json()["options"]}
    assert actor(admin_engine, tenant, synthetic.LATE)


def test_sr31_its_findings_and_its_collection_count_nowhere_outside_monitoring(
    db, runtime, admin_engine, world
):
    """Its findings are shown on Monitoring, labelled, and counted nowhere else: not on Home, not
    in the workspace's settings, not on the Spaces page and not in the weekly summary, which
    would carry them out of the console unlabelled. Nor does a late collection of it count as a
    quiet connection there, as Home does not count it as watching."""
    from execbound.surfaces import value

    tenant = world["admin"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        connection_id = client.post(SYNTHETIC, {}).json()["connection_id"]
        collected(db, runtime, world, connection_id)
        findings = client.get(API + "/monitor/findings?state=open").json()["findings"]
        assert len(findings) > 1 and all(row["synthetic"] for row in findings)
        # Two days late, overdue by every rule: by its own card's, and by the counts' rule for
        # a directory, which would count a connection of any other kind this late.
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET last_run_at = :late "
                    "WHERE connection_id = :c"
                ),
                {"late": runtime.clock.now() - timedelta(days=2), "c": connection_id},
            )
        [card] = client.get(API + "/monitor").json()["connections"]
        assert card["overdue_since"] is not None
        home = client.get(API + "/overview")
        assert home.status_code == 200, home.text
        assert (
            home.json()["monitoring"]["open_findings"],
            home.json()["monitoring"]["overdue"],
        ) == (
            0,
            0,
        )
        settings = client.get(API + "/tenant")
        assert settings.status_code == 200, settings.text
        health = settings.json()["monitoring"]
        assert (health["open_findings"], health["overdue"]) == (0, 0)
        spaces = client.get(API + "/spaces")
        assert spaces.status_code == 200, spaces.text
        assert [row["findings"] for row in spaces.json()["items"]] == [0]
    now = runtime.clock.now()
    with db.transaction(tenant) as conn:
        counts, reason = value.for_principal(
            conn, tenant, world["admin"].principal_id, now - timedelta(days=7), now, now
        )
    assert reason is None and counts is not None
    assert (counts.open_findings, counts.quiet_sources) == (0, 0)


def test_sr31_the_assistant_reads_its_findings_labelled(db, runtime, admin_engine, world):
    """The console assistant's findings tool says which findings the synthetic directory raised,
    so a model is never handed one that reads like a real incident."""
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        connection_id = client.post(SYNTHETIC, {}).json()["connection_id"]
        collected(db, runtime, world, connection_id)
        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
    result = run_tool(
        ToolContext(runtime=runtime, session=session), "list_findings", {"state": "all"}
    )
    assert result.data["count"] > 1
    assert all(row["synthetic"] is True for row in result.data["findings"])


def test_sr31_adding_it_is_refused_beside_a_directory_and_to_a_narrowed_administrator(
    db, runtime, admin_engine, world
):
    """`409 DIRECTORY_CONNECTED` for a workspace that ever connected Microsoft Entra, revoked
    since or not, and `403 FORBIDDEN` for an administrator a membership narrows to some Spaces,
    since the synthetic directory holds for every Space. Nothing is added either time."""
    admin = world["admin"]
    tenant = admin.tenant_id

    def synthetic_rows():
        with admin_engine.connect() as conn:
            return conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_connections "
                    "WHERE tenant_id = :t AND kind = 'fixture'"
                ),
                {"t": tenant},
            ).scalar_one()

    with admin_engine.begin() as conn:
        narrowing = make_space(conn, tenant, "Customer A")
        seat(conn, tenant, narrowing, admin.principal_id, "ADMIN")
    with console_client(db, runtime, admin_engine, admin) as client:
        narrowed = client.post(SYNTHETIC, {})
        assert (narrowed.status_code, narrowed.json()["code"]) == (403, "FORBIDDEN")
    assert synthetic_rows() == 0
    # The workspace's own administrator again, in a workspace that has connected a directory.
    with admin_engine.begin() as conn:
        unseat(conn, tenant, narrowing, admin.principal_id)
        conn.execute(
            text("DELETE FROM execbound.spaces WHERE tenant_id = :t AND space_id = :s"),
            {"t": tenant, "s": narrowing},
        )
    directory = connect_entra(db, admin, runtime.clock)
    with console_client(db, runtime, admin_engine, admin) as client:
        refused = client.post(SYNTHETIC, {})
        assert (refused.status_code, refused.json()["code"]) == (409, "DIRECTORY_CONNECTED")
        revoked = client.post(API + f"/monitor/connections/{directory}/revoke", {})
        assert revoked.status_code == 200, revoked.text
        still = client.post(SYNTHETIC, {})
        assert (still.status_code, still.json()["code"]) == (409, "DIRECTORY_CONNECTED")
    assert synthetic_rows() == 0


def test_sr31_monitoring_answers_for_the_workspace_whichever_space_it_shows(
    db, runtime, admin_engine, world
):
    """The synthetic directory holds for every Space, so Monitoring says whether one is present,
    and to a reader of every Space whether one can be added, for the workspace rather than for
    the Space the session looks at: a workspace administrator looking at another Space is not
    offered one beside an existing one, nor beside a directory connected, or connected once,
    elsewhere. A reader narrowed to some Spaces is told one is present, which stops every Space
    connecting a directory, and never whether any Space connected one."""
    admin = world["admin"]
    tenant = admin.tenant_id
    with admin_engine.begin() as conn:
        here = default_space(conn, tenant)
        other = make_space(conn, tenant, "Customer B")
    with console_client(db, runtime, admin_engine, admin) as client:

        def shown(space=None):
            if space is not None:
                chosen = client.post(SESSION_SPACE, {"space_id": str(space)})
                assert chosen.status_code == 200, chosen.text
            answer = client.get(API + "/monitor")
            assert answer.status_code == 200, answer.text
            return answer.json()

        def narrowed_to(space):
            with admin_engine.begin() as conn:
                seat(conn, tenant, space, admin.principal_id, "ADMIN")
            try:
                return shown()["synthetic_directory"]
            finally:
                with admin_engine.begin() as conn:
                    unseat(conn, tenant, space, admin.principal_id)

        assert shown(other)["synthetic_directory"] == {"present": False, "addable": True}
        assert narrowed_to(other) == {"present": False, "addable": False}
        shown(here)
        added = client.post(SYNTHETIC, {})
        assert added.status_code == 201, added.text
        elsewhere = shown(other)
        assert elsewhere["connections"] == []
        assert elsewhere["synthetic_directory"] == {"present": True, "addable": False}
        assert shown(here)["synthetic_directory"] == {"present": True, "addable": False}
        assert narrowed_to(other) == {"present": True, "addable": False}
        revoked = client.post(
            API + f"/monitor/connections/{added.json()['connection_id']}/revoke", {}
        )
        assert revoked.status_code == 200, revoked.text
        # A removed synthetic directory does not stop another being added.
        assert shown(other)["synthetic_directory"] == {"present": False, "addable": True}
        directory = connect_entra(db, admin, runtime.clock, space=here)
        assert shown(other)["synthetic_directory"] == {"present": False, "addable": False}
        assert client.post(API + f"/monitor/connections/{directory}/revoke", {}).status_code == 200
        assert shown(other)["synthetic_directory"] == {"present": False, "addable": False}
        assert narrowed_to(other) == {"present": False, "addable": False}


def test_sr31_its_schedule_out_of_a_directory_s_range_is_a_field_error(
    db, runtime, admin_engine, world
):
    """An interval the body admits but the synthetic directory's kind does not, an activity
    interval, is the schedule's field error, as for any kind, not the service unavailable."""
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        connection_id = client.post(SYNTHETIC, {}).json()["connection_id"]
        path = API + f"/monitor/connections/{connection_id}/schedule"
        changed = client.post(path, {"collect_interval_seconds": 7200})
        assert changed.status_code == 200, changed.text
        assert changed.json()["collect_interval_seconds"] == 7200
        refused = client.post(path, {"activity_interval_seconds": 900})
        assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY")
        assert refused.json()["fields"] == [
            "activity_interval_seconds",
            "collect_interval_seconds",
        ]


def test_sr31_a_directory_is_not_connected_beside_it_and_it_is_not_added_beside_one(
    db, runtime, admin_engine, world, collector
):
    config = with_entra(collector)
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as client:
        assert client.post(SYNTHETIC, {}).status_code == 201
        started = client.post(API + "/monitor/connections/entra/start", {"label": "Directory"})
        assert (started.status_code, started.json()["code"]) == (
            409,
            "SYNTHETIC_DIRECTORY_PRESENT",
        )
        options = client.get(API + "/monitor").json()
        connection_id = options["connections"][0]["connection_id"]
        removed = client.post(API + f"/monitor/connections/{connection_id}/revoke", {})
        assert removed.status_code == 200, removed.text
        assert removed.json()["revoked_at"] is not None
        started = client.post(API + "/monitor/connections/entra/start", {"label": "Directory"})
        assert started.status_code == 200, started.text


def test_sr30_accept_and_withdraw_answer_the_actor_as_the_server_holds_it(
    db, runtime, admin_engine, world
):
    tenant = world["admin"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        connection_id = client.post(SYNTHETIC, {}).json()["connection_id"]
        collected(db, runtime, world, connection_id, times=1)
        agent_id = actor(admin_engine, tenant, synthetic.OFFBOARDING)
        paths = open_paths(client, agent_id)
        assert paths
        for body, field in (
            ({"paths": paths, "reason_code": "NOT_LISTED", "days": 90}, None),
            ({"paths": paths, "reason_code": "BREAK_GLASS", "days": 7}, None),
            ({"paths": [], "reason_code": "BREAK_GLASS"}, None),
            (
                {
                    "paths": [
                        {"action": "identity.disable", "path_kind": "grant", "path_ref": "x"}
                    ],
                    "reason_code": "BREAK_GLASS",
                },
                ["paths"],
            ),
        ):
            refused = client.post(accept(agent_id), body)
            assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY"), body
            if field is not None:
                assert refused.json()["fields"] == field
        accepted = client.post(accept(agent_id), {"paths": paths, "reason_code": "BREAK_GLASS"})
        assert accepted.status_code == 200, accepted.text
        assert_no_secrets(accepted)
        body = accepted.json()
        rows = [row for row in body["reach"] if row["reason_code"] is not None]
        assert rows and all(row["accepted"] and not row["open"] for row in rows)
        assert all(
            row["accepted_by_ref"]["principal_id"] == str(world["admin"].principal_id)
            for row in rows
        )
        assert [entry["change"] for entry in body["acceptances"]] == ["accepted"] * len(paths)
        withdrawn = client.post(withdraw(agent_id), paths[0])
        assert withdrawn.status_code == 200, withdrawn.text
        assert withdrawn.json()["acceptances"][0]["change"] == "withdrawn"
        again = client.post(withdraw(agent_id), paths[0])
        assert (again.status_code, again.json()["code"]) == (409, "CONFLICT")
        unknown = client.post(accept(ZERO), {"paths": paths, "reason_code": "BREAK_GLASS"})
        assert (unknown.status_code, unknown.json()["code"]) == (404, "NOT_FOUND")


def test_sr30_an_acceptance_of_any_kind_the_command_line_records_is_withdrawn_from_the_console(
    db, runtime, admin_engine, world
):
    """`accept-reach --path-kind observation` records one the agent page offers to withdraw: the
    route takes every kind an acceptance can be recorded for, not only the kinds Accept offers."""
    tenant = world["admin"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        connection_id = client.post(SYNTHETIC, {}).json()["connection_id"]
        collected(db, runtime, world, connection_id, times=1)
        # Observed reach is derived by the scheduled pass, from what the collection read.
        monitor_store.derive_reach(db, world["admin"], clock=runtime.clock)
        agent_id = actor(admin_engine, tenant, synthetic.OFFBOARDING)
        detail = client.get(API + f"/monitor/agents/{agent_id}").json()
        observed = next(row for row in detail["reach"] if row["path_kind"] == "observation")
        path = {key: observed[key] for key in ("action", "path_kind", "path_ref")}
        monitor_store.accept_reach(
            db,
            world["admin"],
            connection_id=UUID(connection_id),
            platform_ref=synthetic.OFFBOARDING,
            action=path["action"],
            path_kind=path["path_kind"],
            path_ref=path["path_ref"],
            reason_code="VENDOR_MANAGED",
            clock=runtime.clock,
        )
        withdrawn = client.post(withdraw(agent_id), path)
        assert withdrawn.status_code == 200, withdrawn.text
        assert withdrawn.json()["acceptances"][0]["change"] == "withdrawn"
        assert withdrawn.json()["acceptances"][0]["path_kind"] == "observation"
        # A kind no acceptance is ever recorded for is still refused.
        refused = client.post(withdraw(agent_id), {**path, "path_kind": "anything"})
        assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY")
    # The route's kinds are the store's, which are the definer function's.
    kinds = get_args(AcceptedPath.model_fields["path_kind"].annotation)
    assert set(kinds) == monitor_store.ACCEPT_PATH_KINDS


@contextmanager
def stepped_down(db, runtime, admin_engine, world):
    """The administrator, signed in with an authenticator last verified over thirty minutes ago."""
    from console_api_fixtures import console_config

    with console_client(
        db, runtime, admin_engine, world["admin"], config=console_config(mfa=RING)
    ) as client:
        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
        mfa.confirm_enrollment(
            db, session, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock
        )
        stale(admin_engine, world["admin"].tenant_id, session.session_id)
        runtime.clock.value += timedelta(seconds=30)
        yield client, seed


def test_sr30_accepting_and_withdrawing_ask_for_a_recent_factor_and_refuse_a_token(
    db, runtime, admin_engine, world
):
    tenant = world["admin"].tenant_id
    agent_id = str(uuid4())
    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        with bearer(console, token) as client:
            for path, body in (
                (accept(agent_id), {"paths": [], "reason_code": "BREAK_GLASS"}),
                (withdraw(agent_id), {"action": "identity.disable"}),
                (SYNTHETIC, {}),
            ):
                refused = post(client, path, token, body)
                assert (refused.status_code, refused.json()["code"]) == (
                    403,
                    "TOKEN_NOT_ALLOWED",
                ), path
    with stepped_down(db, runtime, admin_engine, world) as (client, seed):
        for path, body in (
            (accept(agent_id), {"paths": [], "reason_code": "BREAK_GLASS"}),
            (withdraw(agent_id), {"action": "identity.disable", "path_kind": "grant"}),
        ):
            refused = client.post(path, body)
            assert (refused.status_code, refused.json()["code"]) == (401, "MFA_REQUIRED"), path
        # The token made nothing; adding the synthetic directory holds no credential and asks
        # for no factor.
        with admin_engine.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM execbound.monitor_connections "
                        "WHERE tenant_id = :t AND kind = 'fixture'"
                    ),
                    {"t": tenant},
                ).scalar_one()
                == 0
            )
        added = client.post(SYNTHETIC, {})
        assert added.status_code == 201, added.text
        verified = client.post(VERIFY, {"code": mfa.totp(seed, step(runtime))})
        assert verified.status_code == 200, verified.text
        client.csrf = verified.json()["csrf_token"]
        answered = client.post(accept(agent_id), {"paths": [], "reason_code": "BREAK_GLASS"})
        assert (answered.status_code, answered.json()["code"]) == (400, "INVALID_BODY")
