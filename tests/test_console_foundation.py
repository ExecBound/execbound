# SPDX-License-Identifier: AGPL-3.0-only
"""The console's foundation at the API (#678): the viewer's day, names and search.

Each `test_cf<N>_` test proves a row of the "Console foundation" acceptance group. The
viewer's day is the one rule Home, the live board and **Decided today** share: with the
viewer's `utc_offset` each counts from the viewer's midnight, and without it from UTC
midnight, as an old client and the server-rendered showcase expect.

The instants are chosen from the clock at run time rather than fixed: the world's credentials
last two hours from the moment the fixture made them, so the clock cannot be moved a day. An
execution's or a decision's time is moved instead, to one side or the other of the two
midnights, which is what the day boundary is about.
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from console_api_fixtures import API, console_client
from space_fixtures import seat_in_default
from sqlalchemy import text
from test_console_api_board import executed, frames, live_console
from test_console_api_board import quick as quick
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import pending
from test_mcp_surface import gateway as gateway
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import request
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound.execution import admit, decide_approval
from execbound.identity import authenticate
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.surfaces.dashboard import viewer_midnight
from execbound_harness.demo import endpoint_bundle

BOARD = API + "/board"
STREAM = API + "/board/stream"
DECIDED = API + "/approvals?view=decided"
WEST_OF_UTC = -240
WRONG = ("841", "-841", "1.5", "abc", "", "+60")


def straddle(now: datetime) -> tuple[datetime, bool]:
    """An instant between UTC midnight and the viewer's midnight at `WEST_OF_UTC`.

    Returns the instant and whether the viewer's day holds it. Before 04:00 UTC the viewer's
    day began the evening before, so an instant just before UTC midnight is in the viewer's
    today and not in UTC's; from 04:00 UTC it began after UTC midnight, so an instant just
    after UTC midnight is in UTC's today and not in the viewer's. Either way the instant is
    earlier than `now` and the two reads must disagree about it.
    """
    utc = viewer_midnight(now, None)
    viewer = viewer_midnight(now, timedelta(minutes=WEST_OF_UTC))
    if viewer < utc:
        return utc - timedelta(minutes=1), True
    return utc + timedelta(minutes=1), False


def move_execution(admin_engine, tenant, moment: datetime) -> None:
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET created_at=:at, changed_at=:at WHERE tenant_id=:t"
            ),
            {"at": moment, "t": tenant},
        )


def test_cf4_utc_offset_is_bounded_on_every_read(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(BOARD + f"?utc_offset={WEST_OF_UTC}").status_code == 200
        assert admin.get(BOARD + f"?window=1h&utc_offset={WEST_OF_UTC}").status_code == 200
        assert admin.get(DECIDED + f"&utc_offset={WEST_OF_UTC}").status_code == 200
        for value in (*WRONG, "60&utc_offset=60"):
            for route in (BOARD + "?", STREAM + "?", DECIDED + "&", API + "/overview?"):
                # The stream refuses before its first byte: a typed JSON answer, not an
                # event stream that opens and then says something went wrong.
                wrong = admin.get(route + "utc_offset=" + value)
                assert wrong.status_code == 400, (route, value)
                assert wrong.headers["content-type"].startswith("application/json"), route
                assert wrong.json()["code"] == "INVALID_REQUEST", (route, value)
        # Malformed is refused whatever the view, not only for the one that reads it.
        for view in ("pending", "lapsed"):
            wrong = admin.get(API + f"/approvals?view={view}&utc_offset=abc")
            assert wrong.status_code == 400, view
            assert wrong.json()["code"] == "INVALID_REQUEST", view


def test_cf4_the_board_counts_from_the_viewers_midnight(
    db, runtime, admin_engine, world, live_provider, quick
):
    executed(db, world)
    tenant = world["identity"].tenant_id
    moment, viewers = straddle(world["clock"].now())
    move_execution(admin_engine, tenant, moment)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        utc = admin.get(BOARD).json()["today"]["requests"]
        viewer = admin.get(BOARD + f"?utc_offset={WEST_OF_UTC}").json()["today"]["requests"]
    assert (utc, viewer) == ((0, 1) if viewers else (1, 0))

    # The stream's first frame agrees with the snapshot for the same offset.
    lines: list[str] = []
    with live_console(db, runtime, admin_engine, world["admin"]) as client:
        with client.stream("GET", STREAM + f"?utc_offset={WEST_OF_UTC}") as response:
            assert response.status_code == 200
            for line in response.iter_lines():
                lines.append(line)
                if line.startswith("data:"):
                    break
    [(name, data)] = frames(lines)
    assert name == "board"
    assert json.loads(data)["today"]["requests"] == viewer


def test_cf4_decided_today_starts_at_the_viewers_midnight(
    db, runtime, admin_engine, world, live_provider
):
    view = pending(runtime, world)
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    moment, viewers = straddle(world["clock"].now())
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.approvals SET decided_at=:at WHERE approval_id=:a"),
            {"at": moment, "a": view.approval_id},
        )
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        utc = [item["approval_id"] for item in approver.get(DECIDED).json()["items"]]
        viewer = [
            item["approval_id"]
            for item in approver.get(DECIDED + f"&utc_offset={WEST_OF_UTC}").json()["items"]
        ]
    held = [str(view.approval_id)]
    assert (utc, viewer) == (([], held) if viewers else (held, []))


@pytest.mark.parametrize("minutes", [-240, 0, 330, 840])
def test_a_utc_midnight_is_the_default_day(minutes):
    """Absent means UTC midnight, exactly as before: the showcase and an old client."""
    now = datetime(2026, 10, 8, 2, 0, tzinfo=UTC)
    assert viewer_midnight(now, None) == datetime(2026, 10, 8, tzinfo=UTC)
    assert viewer_midnight(now, timedelta(0)) == datetime(2026, 10, 8, tzinfo=UTC)
    start = viewer_midnight(now, timedelta(minutes=minutes))
    local = start + timedelta(minutes=minutes)
    assert (local.hour, local.minute) == (0, 0)
    assert start <= now < start + timedelta(days=1)


def second_world(registry, db, admin_engine, seeded):
    """The second seeded workspace, provisioned as the `world` fixture provisions the first: its
    own agent, administrator, approver, assigned target and active policy."""
    from uuid import uuid4

    identity = authenticate(db, seeded["tokens"][1])
    tenant = identity.tenant_id
    now = registry["clock"].now()
    admin = provision_identity(admin_engine, db, tenant, "ADMIN", now)
    human = provision_identity(admin_engine, db, tenant, "HUMAN_APPROVER", now)
    canonical = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.canonical_targets "
                "(tenant_id,canonical_target_id,created_at) VALUES (:t,:c,:n)"
            ),
            {"t": tenant, "c": canonical, "n": now},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resource_identities "
                "(tenant_id,account_id,provider,resource_type,resource_id,canonical_target_id) "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:c)"
            ),
            {"t": tenant, "a": registry["account"], "r": registry["target"], "c": canonical},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes "
                "(tenant_id,approver_id,canonical_target_id,action, space_id) "
                "VALUES (:t,:p,:c,'endpoint.isolate', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "p": human.principal_id, "c": canonical},
        )
        seat_in_default(conn, tenant, human.principal_id)
    bundle = endpoint_bundle(tenant, registry["account"], mapping_version="map-v1")
    create_bundle(db, admin, bundle, registry["clock"])
    validate_bundle(db, admin, bundle.bundle_id, registry["clock"])
    activate_bundle(db, admin, bundle.bundle_id, registry["clock"])
    return {**registry, "identity": identity, "admin": admin, "human": human}


def references(value) -> list[dict]:
    """Every object in an answer that names a principal, at any depth."""
    found: list[dict] = []
    if isinstance(value, dict):
        if "principal_id" in value and "number" in value:
            found.append(value)
        for item in value.values():
            found.extend(references(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(references(item))
    return found


def test_cf9_each_workspace_names_only_its_own_principals(db, runtime, admin_engine, world, seeded):
    other = second_world(registry=world, db=db, admin_engine=admin_engine, seeded=seeded)
    for place in (world, other):
        view = admit(db, place["identity"], request(place), place["clock"]).view
        assert view.state == "PENDING_APPROVAL", view.state
        place["held"] = view
    for place in (world, other):
        own = {str(place[key].principal_id): key for key in ("identity", "admin", "human")}
        held = place["held"]
        answers = []
        with console_client(db, runtime, admin_engine, place["human"]) as approver:
            for path in (
                "/executions",
                f"/executions/{held.execution_id}",
                "/approvals",
                f"/approvals/{held.approval_id}",
                "/overview",
            ):
                response = approver.get(API + path)
                assert response.status_code == 200, (path, response.text)
                answers.append(response.json())
        with console_client(db, runtime, admin_engine, place["admin"]) as admin:
            board = admin.get(BOARD).json()
        named = [ref for answer in answers for ref in references(answer)]
        assert named, "no answer named a principal"
        for ref in named:
            assert ref["principal_id"] in own, ref
            if own[ref["principal_id"]] == "identity":
                assert ref["number"] == 1, ref
        assert [lane["label"] for lane in board["agents"]] == ["Agent 1"]
        assert all(lane["handle"] is None for lane in board["agents"])


ADMIN_ONE = {"kind": "ADMIN", "label": None, "number": 1}


def ref_of(value) -> dict:
    return {key: value[key] for key in ("kind", "label", "number")}


def test_cf8_the_stop_names_its_administrator_to_administrators_alone(
    db, runtime, admin_engine, world
):
    admin_id = str(world["admin"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        stopped = admin.post(API + "/tenant/stop", {"reason": "Contain agent 7"})
        assert stopped.status_code == 200, stopped.text
        stop = stopped.json()["stop"]
        assert stop["stopped_by"] == admin_id
        assert stop["stopped_by_ref"]["principal_id"] == admin_id
        assert ref_of(stop["stopped_by_ref"]) == ADMIN_ONE
        assert ref_of(admin.get(API + "/tenant").json()["stop"]["stopped_by_ref"]) == ADMIN_ONE
        session_stop = admin.get(API + "/session").json()["stop"]
        assert session_stop["stopped_by"] == admin_id
        assert ref_of(session_stop["stopped_by_ref"]) == ADMIN_ONE
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        session_stop = approver.get(API + "/session").json()["stop"]
    # An approver's session learns that a stop is active and by which id, as before, and is
    # never told the administrator's name or number. A personal access token is an
    # administrator's alone and is refused `/session` (TOKEN_NOT_ALLOWED), so no token reads it.
    assert session_stop["stopped_by"] == admin_id
    assert session_stop["stopped_by_ref"] is None


def test_cf8_a_mode_and_a_deadline_change_name_who_made_them(db, runtime, admin_engine, world):
    admin_id = str(world["admin"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        changed = admin.post(API + "/tenant/mode", {"mode": "OBSERVE", "reason": "Trial"})
        assert changed.status_code == 200, changed.text
        mode = changed.json()["mode"]["changed"]
        assert mode["by"] == admin_id and ref_of(mode["by_ref"]) == ADMIN_ONE
        deadline = admin.post(API + "/tenant/deadline", {"deadline": "600", "reason": "Ten"})
        assert deadline.status_code == 200, deadline.text
        moved = deadline.json()["deadline"]["changed"]
        assert moved["by"] == admin_id and ref_of(moved["by_ref"]) == ADMIN_ONE
        read = admin.get(API + "/tenant").json()
    assert read["mode"]["changed"]["by_ref"]["principal_id"] == admin_id
    assert ref_of(read["deadline"]["changed"]["by_ref"]) == ADMIN_ONE


SEARCH = API + "/search?q="


def found(client, term: str, kind: str) -> list[dict]:
    from urllib.parse import quote

    response = client.get(SEARCH + quote(term))
    assert response.status_code == 200, (term, response.text)
    return [row for row in response.json()["results"] if row["kind"] == kind]


def test_cf12_an_unlabelled_agent_is_found_by_number_and_id_prefix_in_its_space(
    db, runtime, admin_engine, world, seeded
):
    from space_fixtures import make_space

    agent = str(world["identity"].principal_id)
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        for term in ("agent 1", "Agent #1", "AGENT1", agent[:8]):
            [result] = found(admin, term, "agent")
            assert (result["id"], result["label"], result["detail"]) == (agent, "Agent 1", "Agent")
        assert found(admin, "agent 2", "agent") == []
        # A label still finds it, and the handle is beside the label.
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.principals SET label='triage_bot%' WHERE principal_id=:p"),
                {"p": agent},
            )
        [labelled] = found(admin, "triage_bot%", "agent")
        assert (labelled["label"], labelled["detail"]) == ("triage_bot%", "Agent 1")
        # `%` and `_` match themselves, not anything.
        assert found(admin, "triage%bot", "agent") == []
        assert found(admin, "t_iage", "agent") == []
        # Under a space view the agent is not in, it is not offered.
        with admin_engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)}
            )
            other = make_space(conn, tenant, "Customer B")
        assert admin.post(API + "/session/space", {"space_id": str(other)}).status_code == 200
        for term in ("agent 1", agent[:8], "triage_bot%"):
            assert found(admin, term, "agent") == [], term
    # An approver gets no agent result at all.
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        for term in ("agent 1", "Agent #1", agent[:8]):
            assert found(approver, term, "agent") == [], term
    # Another workspace's Agent 1 is never offered here, by its number or its id.
    stranger = str(seeded["principals"][1])
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.post(API + "/session/space", {"space_id": None}).status_code == 200
        assert found(admin, stranger[:8], "agent") == []
        assert all(row["id"] == agent for row in found(admin, "agent 1", "agent"))


def test_cf12_a_person_is_found_by_number_and_id_prefix_by_who_manages_access(
    db, runtime, admin_engine, world, seeded
):
    from space_fixtures import default_space, seat

    from execbound.access_control import has_permission

    tenant = world["identity"].tenant_id
    person = world["human"]
    pid = str(person.principal_id)
    with admin_engine.begin() as conn:
        number = conn.execute(
            text("SELECT number FROM execbound.principals WHERE principal_id=:p"),
            {"p": person.principal_id},
        ).scalar_one()
        conn.execute(
            text("UPDATE execbound.principals SET email='dana@example.com' WHERE principal_id=:p"),
            {"p": person.principal_id},
        )
    stranger = provision_identity(
        admin_engine, db, seeded["tenants"][1], "HUMAN_APPROVER", world["clock"].now()
    )
    # An administrator who does not manage access: seated in a space, so not the owner.
    narrow = provision_identity(admin_engine, db, tenant, "ADMIN", world["clock"].now())
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        seat(conn, tenant, default_space(conn, tenant), narrow.principal_id, "ADMIN")
    with db.transaction(tenant) as conn:
        assert not has_permission(conn, tenant, narrow.principal_id, "access.manage")
        assert has_permission(conn, tenant, world["admin"].principal_id, "access.manage")

    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        for term in (f"user {number}", f"User #{number}", pid[:8]):
            [result] = found(admin, term, "person")
            assert (result["id"], result["label"], result["detail"]) == (
                pid,
                f"User {number}",
                "User",
            )
            assert result["execution_id"] is None and result["space_name"] is None
        # Never by the address it signs in with.
        assert found(admin, "dana@example.com", "person") == []
        assert found(admin, "dana", "person") == []
        # Another workspace's person is never offered, by its number or its id.
        mine = {pid, str(world["admin"].principal_id), str(narrow.principal_id)}
        for term in (f"user {number}", "user 1", str(stranger.principal_id)[:8]):
            assert all(row["id"] in mine for row in found(admin, term, "person")), term
        assert found(admin, str(stranger.principal_id)[:8], "person") == []
    for reader in (person, narrow):
        with console_client(db, runtime, admin_engine, reader) as client:
            for term in (f"user {number}", pid[:8]):
                assert found(client, term, "person") == [], (reader.kind, term)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET active=false WHERE principal_id=:p"),
            {"p": person.principal_id},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        [deactivated] = found(admin, f"user {number}", "person")
    assert (deactivated["id"], deactivated["detail"]) == (pid, "User, deactivated")


def carries_no_name(value, names: set[str]) -> None:
    """No `number` key at any depth, and no principal's label or handle in any string."""
    if isinstance(value, dict):
        assert "number" not in value, value
        for item in value.values():
            carries_no_name(item, names)
    elif isinstance(value, list):
        for item in value:
            carries_no_name(item, names)
    elif isinstance(value, str):
        for name in names:
            assert name not in value, (name, value)


def test_cf11_no_agent_answer_names_a_principal(
    api, gateway, db, runtime, admin_engine, world, seeded, live_provider
):
    """The agent surface is unchanged by the names: a denial over HTTP, the same record over
    MCP and a refusal before any plan carry no number or name of any principal, in a
    workspace whose agent is labelled and whose people are numbered."""
    from test_denial_categories import mcp_refusal
    from test_denial_notice import body

    token = seeded["tokens"][0]
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label='triage-bot' WHERE principal_id=:p"),
            {"p": world["identity"].principal_id},
        )
        conn.execute(
            text("UPDATE execbound.principals SET label='Dana Reyes' WHERE principal_id=:p"),
            {"p": world["human"].principal_id},
        )
        numbers = {
            row.number
            for row in conn.execute(
                text("SELECT number FROM execbound.principals WHERE tenant_id=:t"),
                {"t": world["identity"].tenant_id},
            )
        }
    names = {"triage-bot", "Dana Reyes"} | {
        f"{noun} {number}" for noun in ("Agent", "User") for number in numbers
    }
    pending = api.post("/v1/execute", json=body(request(world)))
    assert pending.status_code == 202, pending.text
    carries_no_name(pending.json(), names)
    decide_approval(db, world["human"], UUID(pending.json()["approval_id"]), "DENY", world["clock"])
    denied = api.get("/v1/executions/" + pending.json()["execution_id"])
    assert denied.json()["state"] == "DENIED"
    carries_no_name(denied.json(), names)
    from test_denial_notice import mcp_call

    carries_no_name(mcp_call(gateway, token, "execute", {"request": body(request(world))}), names)
    refusal = mcp_refusal(
        gateway, token, body(request(world, target={"kind": "hostname", "value": "ghost.example"}))
    )
    carries_no_name(json.loads(refusal), names)
