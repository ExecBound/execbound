# SPDX-License-Identifier: AGPL-3.0-only
"""SP22: only a workspace administrator reads and answers the workspace's requests and reports.

The data and closure requests queue holds every person's requests, from every space, with each
requester's name and id, and a response recorded there closes a request whoever filed it,
a workspace closure included. `observe-report` counts the observed decisions of every space,
and `rotation-readiness` lists the unsettled operations of every connector account. An
administrator narrowed to spaces (an actor without workspace-wide `access.manage` who holds any
membership, as `spaces.narrowed` and the definer functions since 0071 ask it) administers their
own spaces, and none of these is theirs.

On 8 October 2026 it was decided that the queue and both reports take workspace administrators
alone, as the workspace-wide settings do since 0074 (SP21). A narrowed administrator gets the
code an actor who is not an administrator already gets from each: `FORBIDDEN` from the queue,
from recording a response and from `account_change`'s `resolve` operation, and
`INVALID_IDENTITY` from the two reports. The refusal comes before any request is read and
before anything is written. A person's own requests, filed and read from their own account,
are unchanged, and so is a workspace administrator.

The console answers the queue and a response with 403, and the command line exits 2 with the
code. Workspace settings shows a narrowed administrator a note in place of the queue.
"""

import importlib.util
import json
import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from alembic import command
from console_api_fixtures import API, ORIGIN, console_client
from fastapi.testclient import TestClient
from space_fixtures import make_space, seat
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_dormant_catalog import alembic_config, empty_schema
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_spaces_directory import definitions, fenced
from test_spaces_directory import narrowed as narrowed

from execbound import accounts
from execbound.cli import main
from execbound.execution import observe_report
from execbound.execution.models import ExecutionError
from execbound.personal_tokens import issue_token
from execbound.rotation import rotation_readiness
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration

REQUESTS = API + "/account/requests"
RESOLVE = REQUESTS + "/resolve"
OUTSIDER = "Olive Outsider"


def session_of(db, identity, clock):
    """A console session for one person, as the console's own routes hold one."""
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


def requests_of(admin_engine, tenant) -> dict[str, dict]:
    """Every request of the tenant as it is stored, by id."""
    with admin_engine.connect() as conn:
        return {
            str(row["request_id"]): dict(row)
            for row in conn.execute(
                text(
                    "SELECT request_id, principal_id, kind, state, closed_at, closed_by, response "
                    "FROM execbound.account_requests WHERE tenant_id=:t"
                ),
                {"t": tenant},
            ).mappings()
        }


def resolutions(admin_engine, tenant) -> int:
    """How many `account.resolve` events the tenant's chain holds."""
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND kind='account.resolve'"
                ),
                {"t": tenant},
            ).scalar_one()
        )


@pytest.fixture
def filed(db, admin_engine, world, narrowed):
    """One request of each kind, none of them the narrowed administrator's.

    An approver seated only in a second space, which the narrowed administrator is not seated
    in, asks for their data and to close their account; the workspace administrator asks to
    close the workspace, which only an administrator may ask.
    """
    tenant, clock = world["admin"].tenant_id, world["clock"]
    outsider = provision_identity(admin_engine, db, tenant, "HUMAN_APPROVER", clock.now())
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("DELETE FROM execbound.space_members WHERE tenant_id=:t AND principal_id=:p"),
            {"t": tenant, "p": outsider.principal_id},
        )
        seat(conn, tenant, make_space(conn, tenant, "Elsewhere"), outsider.principal_id)
    person = session_of(db, outsider, clock)
    accounts.change(db, person, "profile", {"name": OUTSIDER}, clock=clock)
    for kind in ("data_access", "close_account"):
        accounts.change(db, person, "request", {"kind": kind}, clock=clock)
    admin = session_of(db, world["admin"], clock)
    accounts.change(db, admin, "request", {"kind": "close_workspace"}, clock=clock)
    by_kind = {row["kind"]: request for request, row in requests_of(admin_engine, tenant).items()}
    assert set(by_kind) == {"data_access", "close_account", "close_workspace"}
    return {"outsider": outsider, "requests": by_kind}


def response(request_id: str) -> dict[str, str]:
    return {"request_id": request_id, "state": "completed", "response": "Handled offline."}


# The queue and a response, through the store.


def test_sp22_a_space_administrator_reads_no_request_queue(db, world, narrowed, filed):
    clock = world["clock"]
    with pytest.raises(accounts.AccountError) as refused:
        accounts.request_queue(db, session_of(db, narrowed, clock), clock=clock)
    assert refused.value.code == "FORBIDDEN"
    # The workspace administrator reads every request, the outsider's name among them.
    queue = accounts.request_queue(db, session_of(db, world["admin"], clock), clock=clock)
    assert {str(row["request_id"]) for row in queue} == set(filed["requests"].values())
    assert OUTSIDER in {row["name"] for row in queue}


@pytest.mark.parametrize("kind", ["data_access", "close_account", "close_workspace"])
def test_sp22_a_space_administrator_records_no_response(
    db, admin_engine, world, narrowed, filed, kind
):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    request = filed["requests"][kind]
    before, recorded = requests_of(admin_engine, tenant), resolutions(admin_engine, tenant)
    for state in ("completed", "declined"):
        with pytest.raises(accounts.AccountError) as refused:
            accounts.change(
                db,
                session_of(db, narrowed, clock),
                "resolve",
                {**response(request), "state": state},
                clock=clock,
            )
        assert refused.value.code == "FORBIDDEN", state
    assert requests_of(admin_engine, tenant) == before
    assert before[request]["state"] == "pending" and before[request]["closed_by"] is None
    assert resolutions(admin_engine, tenant) == recorded
    # The workspace administrator records it as before.
    admin = session_of(db, world["admin"], clock)
    accounts.change(db, admin, "resolve", response(request), clock=clock)
    after = requests_of(admin_engine, tenant)[request]
    assert after["state"] == "completed"
    assert after["closed_by"] == world["admin"].principal_id
    assert resolutions(admin_engine, tenant) == recorded + 1


def test_sp22_the_definer_function_records_no_response_for_a_space_administrator(
    db, admin_engine, world, narrowed, filed
):
    """`account_change` itself, with nothing in front of it, as the store calls it."""
    tenant, clock = world["admin"].tenant_id, world["clock"]
    before, recorded = requests_of(admin_engine, tenant), resolutions(admin_engine, tenant)
    space_admin = session_of(db, narrowed, clock)
    for request in filed["requests"].values():
        with pytest.raises(DBAPIError) as failure, admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text("SELECT execbound.account_change(:s, :n, 'resolve', CAST(:d AS jsonb))"),
                {
                    "s": space_admin.session_id,
                    "n": clock.now(),
                    "d": json.dumps(response(request)),
                },
            )
        assert failure.value.orig.diag.message_primary == "FORBIDDEN", request
    assert requests_of(admin_engine, tenant) == before
    assert resolutions(admin_engine, tenant) == recorded
    # A workspace administrator's session goes through the same function as before.
    admin = session_of(db, world["admin"], clock)
    request = filed["requests"]["close_workspace"]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("SELECT execbound.account_change(:s, :n, 'resolve', CAST(:d AS jsonb))"),
            {"s": admin.session_id, "n": clock.now(), "d": json.dumps(response(request))},
        )
    assert requests_of(admin_engine, tenant)[request]["state"] == "completed"


def test_sp22_a_space_administrator_files_and_reads_their_own_requests(
    db, admin_engine, world, narrowed
):
    """Their own requests go through their own account, which this decision leaves alone."""
    tenant, clock = world["admin"].tenant_id, world["clock"]
    own = session_of(db, narrowed, clock)
    for kind in ("data_access", "close_account", "close_workspace"):
        accounts.change(db, own, "request", {"kind": kind}, clock=clock)
    mine = accounts.overview(db, own, clock=clock)["requests"]
    assert {row["kind"] for row in mine} == {"data_access", "close_account", "close_workspace"}
    assert {row["principal_id"] for row in requests_of(admin_engine, tenant).values()} == {
        narrowed.principal_id
    }
    # A workspace administrator answers one, and its requester reads the answer.
    admin = session_of(db, world["admin"], clock)
    queued = accounts.request_queue(db, admin, clock=clock)
    accounts.change(db, admin, "resolve", response(str(queued[0]["request_id"])), clock=clock)
    states = {row["state"] for row in accounts.overview(db, own, clock=clock)["requests"]}
    assert states == {"pending", "completed"}


# The two workspace-wide reports.


def test_sp22_a_space_administrator_reads_neither_workspace_report(db, world, narrowed):
    clock = world["clock"]
    with pytest.raises(ExecutionError) as refused:
        observe_report(db, narrowed, since_hours=24, clock=clock)
    assert refused.value.code == "INVALID_IDENTITY"
    with pytest.raises(ExecutionError) as refused:
        rotation_readiness(db, narrowed, clock)
    assert refused.value.code == "INVALID_IDENTITY"
    # Refused as an approver is.
    for read in (
        lambda actor: observe_report(db, actor, since_hours=24, clock=clock),
        lambda actor: rotation_readiness(db, actor, clock),
    ):
        with pytest.raises(ExecutionError) as refused:
            read(world["human"])
        assert refused.value.code == "INVALID_IDENTITY"
    # The workspace administrator reads both as before.
    assert observe_report(db, world["admin"], since_hours=24, clock=clock)["observed"] == 0
    assert rotation_readiness(db, world["admin"], clock).unsettled == ()


# The console and the command line.


def test_sp22_the_console_refuses_a_space_administrator_the_queue(
    db, runtime, admin_engine, world, narrowed, filed
):
    tenant = world["admin"].tenant_id
    before, recorded = requests_of(admin_engine, tenant), resolutions(admin_engine, tenant)
    outsider = str(filed["outsider"].principal_id)
    with console_client(db, runtime, admin_engine, narrowed) as client:
        queue = client.get(REQUESTS)
        assert queue.status_code == 403, queue.text
        assert queue.json()["code"] == "FORBIDDEN"
        for request in filed["requests"].values():
            assert request not in queue.text
            answer = client.post(RESOLVE, response(request))
            assert answer.status_code == 403, answer.text
            assert answer.json()["code"] == "FORBIDDEN"
            assert request not in answer.text
        assert OUTSIDER not in queue.text and outsider not in queue.text
        # Their own account page still reads, and holds none of the others' requests.
        account = client.get(API + "/account")
        assert account.status_code == 200, account.text
        assert account.json()["requests"] == []
    assert requests_of(admin_engine, tenant) == before
    assert resolutions(admin_engine, tenant) == recorded
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        queue = client.get(REQUESTS)
        assert queue.status_code == 200, queue.text
        assert {row["request_id"] for row in queue.json()} == set(filed["requests"].values())
        assert OUTSIDER in {row["name"] for row in queue.json()}
        request = filed["requests"]["close_workspace"]
        assert client.post(RESOLVE, response(request)).status_code == 200
    assert requests_of(admin_engine, tenant)[request]["state"] == "completed"


def test_sp22_a_space_administrator_s_token_reads_no_request_queue(
    db, runtime, admin_engine, world, narrowed, filed
):
    """A personal access token may read the queue, as its owner, through the same function."""
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        bare = TestClient(console.client.app, base_url=ORIGIN, follow_redirects=False)
        for owner, status in ((narrowed, 403), (world["admin"], 200)):
            session = session_of(db, owner, runtime.clock)
            token, _ = issue_token(db, session, "ci", timedelta(days=1), clock=runtime.clock)
            read = bare.get(REQUESTS, headers={"Authorization": f"Bearer {token}"})
            assert read.status_code == status, read.text
            if status == 403:
                assert read.json()["code"] == "FORBIDDEN"
                assert OUTSIDER not in read.text
            else:
                assert OUTSIDER in {row["name"] for row in read.json()}


def test_sp22_the_command_line_refuses_a_space_administrator_both_reports(
    db, admin_engine, world, narrowed, tmp_path, monkeypatch, capsys
):
    tenant = world["admin"].tenant_id
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    narrowed_file, admin_file = tmp_path / "narrowed.token", tmp_path / "admin.token"
    narrowed_file.write_text(credential(admin_engine, narrowed), encoding="utf-8")
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        main()
        return json.loads(capsys.readouterr().out)

    def refused(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        with pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == 2, argv
        captured = capsys.readouterr()
        assert captured.out == "", argv
        return captured.err

    common = ("--tenant", str(tenant), "--credential-file", str(narrowed_file))
    workspace = ("--tenant", str(tenant), "--credential-file", str(admin_file))
    for name in ("observe-report", "rotation-readiness"):
        assert "INVALID_IDENTITY" in refused(name, *common), name
    assert run("observe-report", *workspace)["observed"] == 0
    assert run("rotation-readiness", *workspace)["unsettled"] == []


# Migration 0075: `account_change` gains the check in place, and the downgrade takes it away.

BEFORE = "0074_workspace_settings_admin"
TARGET = "0075_workspace_requests_admin"
_FILE = Path(__file__).resolve().parents[1] / "migrations" / "versions" / f"{TARGET}.py"


def _migration():
    spec = importlib.util.spec_from_file_location("workspace_requests_admin_migration", _FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sp22_the_upgrade_adds_the_check_and_the_downgrade_restores_the_function(admin_engine):
    migration = _migration()
    names = tuple(migration.PATCHES)
    assert names == ("account_change",)
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            old = definitions(conn, names)
        assert set(old) == set(names)
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            new = definitions(conn, names)
        for name in names:
            body, *kept = new[name]
            # Signature, owner, grants, SECURITY DEFINER and search_path are as they were.
            assert kept == list(old[name][1:]), name
            assert "execbound_app=X/execbound_owner" in kept[0], name
            expected = old[name][0]
            for before, after in migration.PATCHES[name]:
                assert expected.count(before) == 1, name
                expected = expected.replace(before, after)
            assert body == expected and body != old[name][0], name
            assert "(0075)" in body and "'access.manage',NULL,false" in body, name
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert definitions(conn, names) == old
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            assert definitions(conn, names) == new
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
