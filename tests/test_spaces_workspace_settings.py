# SPDX-License-Identifier: AGPL-3.0-only
"""SP21: only a workspace administrator changes a setting that is the whole workspace's.

The enforcement mode, the approval deadline, the emergency stop and its release, the assistant
switch and the organization's MFA requirement each apply to every space of the tenant at once:
observe-only stops enforcement in every space, the deadline times every new approval, a stop
halts every space's admission and dispatch, and the requirement decides who must enrol. An
administrator narrowed to spaces (an actor without workspace-wide `access.manage` who holds any
membership, as `spaces.narrowed` and the definer functions since 0071 ask it) administers their
spaces, and changes none of these.

On 8 October 2026 it was decided that these take workspace administrators alone, as the tenant's
identity provider does since 0073 (SP20). A narrowed administrator gets the code an actor who is
not an administrator already gets from each: `INVALID_IDENTITY` from the four kernel functions,
which audit the refusal as they audit every other, and from the assistant switch, which writes
no event, and
`RECENT_AUTH_REQUIRED` from the `policy` operation of `account_security_change` and
`user_security_change`. Nothing is written. Reading each setting is unchanged, because a
narrowed administrator's own work depends on knowing that a stop is in force or that the
workspace only observes. A workspace administrator is unchanged.

The console answers the same with 403, and the command line exits 2 with the code, both through
the store functions. The account security page offers a narrowed administrator no requirement
form and answers its address 403 before anything is written.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from console_api_fixtures import API, ORIGIN, console_client, console_config
from space_fixtures import default_space, seat
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_dormant_catalog import alembic_config, empty_schema
from test_emergency_stop import audit
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential, form_values
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_spaces_directory import definitions, fenced
from test_spaces_directory import narrowed as narrowed
from test_workspace_accounts import adopt, enroll

from execbound import mfa
from execbound.assistant.client import ScriptedTransport
from execbound.assistant.config import AssistantConfig
from execbound.assistant.turns import AssistantError, set_tenant_switch
from execbound.cli import main
from execbound.envelope import KeyRing
from execbound.execution import (
    activate_stop,
    approval_deadline,
    enforcement_mode,
    release_stop,
    set_approval_deadline,
    set_enforcement_mode,
    stop_status,
)
from execbound.execution.models import ExecutionError
from execbound.passwords import sign_in_with_password
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration

RING = KeyRing("test", {"test": b"m" * 32})
TENANT = API + "/tenant"
ASSISTANT = API + "/assistant/settings"
PASSPHRASE = "a retained example passphrase"


def settings_row(admin_engine, tenant) -> dict:
    """Every workspace-wide setting the tenant's control row holds."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return dict(
            conn.execute(
                text(
                    "SELECT enforcement_mode, approval_deadline_seconds, stop_id, stopped_at, "
                    "stopped_by, stop_reason, assistant_enabled "
                    "FROM execbound.tenant_policy_control WHERE tenant_id=:t"
                ),
                {"t": tenant},
            )
            .mappings()
            .one()
        )


def changes(admin_engine, tenant) -> int:
    """How many setting changes the tenant's chain holds, of any of the five kinds."""
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t AND kind IN "
                    "('tenant.mode_changed','tenant.approval_deadline_changed',"
                    "'tenant.stop_activated','tenant.stop_released','tenant.assistant_changed',"
                    "'account_security.requirement_changed')"
                ),
                {"t": tenant},
            ).scalar_one()
        )


def refusals_of(admin_engine, identity) -> list[tuple[str, str]]:
    """The operation and reason of every `execution.rejected` event made with one credential."""
    return [
        (payload["operation"], payload["reason"])
        for payload in audit(admin_engine, identity.tenant_id, "execution.rejected")
        if payload.get("actor_credential_id") == str(identity.credential_id)
    ]


def requirement(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT requirement, changed_by FROM execbound.account_security_policy "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        ).one_or_none()


@pytest.fixture
def stopped(db, world):
    """A stop a workspace administrator set."""
    return activate_stop(db, world["admin"], "Contain agent 7", world["clock"])


# The kernel functions and the assistant switch.

SETTINGS = {
    "mode": lambda db, actor, clock: set_enforcement_mode(db, actor, "OBSERVE", "Trial", clock),
    "deadline": lambda db, actor, clock: set_approval_deadline(db, actor, 600, "Longer", clock),
    "stop": lambda db, actor, clock: activate_stop(db, actor, "Contain", clock),
}


@pytest.mark.parametrize("setting", sorted(SETTINGS))
def test_sp21_a_space_administrator_changes_no_kernel_setting(
    db, admin_engine, world, narrowed, setting
):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    before, recorded = settings_row(admin_engine, tenant), changes(admin_engine, tenant)
    with pytest.raises(ExecutionError) as refused:
        SETTINGS[setting](db, narrowed, clock)
    assert refused.value.code == "INVALID_IDENTITY"
    assert settings_row(admin_engine, tenant) == before
    assert changes(admin_engine, tenant) == recorded
    # Refused as an approver is: the refusal itself is audited, with the code.
    operation = {
        "mode": "set_enforcement_mode",
        "deadline": "set_approval_deadline",
        "stop": "activate_stop",
    }[setting]
    assert refusals_of(admin_engine, narrowed) == [(operation, "INVALID_IDENTITY")]
    # The workspace administrator changes it as before.
    SETTINGS[setting](db, world["admin"], clock)
    assert settings_row(admin_engine, tenant) != before
    assert changes(admin_engine, tenant) == recorded + 1


def test_sp21_a_space_administrator_cannot_resume_a_stop_a_workspace_administrator_set(
    db, admin_engine, world, narrowed, stopped
):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    before = settings_row(admin_engine, tenant)
    assert before["stop_id"] == stopped.stop_id
    with pytest.raises(ExecutionError) as refused:
        release_stop(db, narrowed, "Looks fine to me", clock)
    assert refused.value.code == "INVALID_IDENTITY"
    assert settings_row(admin_engine, tenant) == before
    assert audit(admin_engine, tenant, "tenant.stop_released") == []
    assert refusals_of(admin_engine, narrowed) == [("release_stop", "INVALID_IDENTITY")]
    # They still read that the stop is in force, which their own work depends on.
    assert stop_status(db, narrowed, clock).stop_id == stopped.stop_id
    released = release_stop(db, world["admin"], "Reviewed", clock)
    assert released.stop_id == stopped.stop_id
    assert settings_row(admin_engine, tenant)["stop_id"] is None


def test_sp21_a_space_administrator_cannot_switch_the_assistant(db, admin_engine, world, narrowed):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    before, recorded = settings_row(admin_engine, tenant), changes(admin_engine, tenant)
    for enabled in (True, False):
        with pytest.raises(AssistantError) as refused:
            set_tenant_switch(db, narrowed, enabled, "Pilot", clock)
        assert refused.value.code == "INVALID_IDENTITY", enabled
    assert settings_row(admin_engine, tenant) == before
    assert changes(admin_engine, tenant) == recorded
    assert set_tenant_switch(db, world["admin"], True, "Pilot", clock).enabled is True
    assert settings_row(admin_engine, tenant)["assistant_enabled"] is True
    # Nor turns it off once a workspace administrator has turned it on.
    with pytest.raises(AssistantError):
        set_tenant_switch(db, narrowed, False, "Off", clock)
    assert settings_row(admin_engine, tenant)["assistant_enabled"] is True


def test_sp21_a_space_administrator_reads_every_setting(db, world, narrowed, stopped):
    clock = world["clock"]
    assert enforcement_mode(db, narrowed, clock) == "ENFORCE"
    assert approval_deadline(db, narrowed, clock) == 120
    assert stop_status(db, narrowed, clock).stop_id == stopped.stop_id


# The organization's MFA requirement.


def enrolled(db, token: str, clock):
    """The session `token` opens, with a factor enrolled on it, which also verifies the factor
    there: a step-up as fresh as one can be."""
    session = load_session(db, token, clock=clock)
    seed = mfa.begin_enrollment(db, session, RING, clock=clock)
    code = mfa.totp(seed, int(clock.now().timestamp() // 30))
    mfa.confirm_enrollment(db, session, RING, code, clock=clock)
    return load_session(db, token, clock=clock)


def seated_as_admin(admin_engine, tenant, principal) -> None:
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        seat(conn, tenant, default_space(conn, tenant), principal, "ADMIN")


def workspace_session(db, admin_engine, world, *, seated: bool) -> str:
    """A session with no account behind it, which `account_security_change` serves."""
    tenant, clock = world["admin"].tenant_id, world["clock"]
    identity = provision_identity(admin_engine, db, tenant, "ADMIN", clock.now())
    if seated:
        seated_as_admin(admin_engine, tenant, identity.principal_id)
    return issue_session(db, identity, clock=clock).token


def account_session(db, admin_engine, world, *, seated: bool) -> str:
    """A session of a signed-in account, which `user_security_change` serves."""
    tenant, clock = world["admin"].tenant_id, world["clock"]
    email = f"{uuid4().hex[:12]}@example.test"
    principal, _ = enroll(admin_engine, tenant, email=email, kind="ADMIN")
    if seated:
        seated_as_admin(admin_engine, tenant, principal)
    adopt(db, tenant, principal)
    identity = sign_in_with_password(db, email, PASSPHRASE, clock=clock)
    token = issue_session(db, identity, clock=clock).token
    assert load_session(db, token, clock=clock).account_id is not None
    return token


SESSIONS = {"workspace": workspace_session, "account": account_session}


@pytest.mark.parametrize("kind", sorted(SESSIONS))
def test_sp21_a_space_administrator_sets_no_mfa_requirement(db, admin_engine, world, kind):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    function = "user_security_change" if kind == "account" else "account_security_change"
    space_admin = enrolled(db, SESSIONS[kind](db, admin_engine, world, seated=True), clock)
    recorded = changes(admin_engine, tenant)
    for wanted in ("optional", "admins", "all"):
        with pytest.raises(mfa.MfaError):
            mfa.manage_security(db, space_admin, "policy", wanted, clock=clock)
    assert requirement(admin_engine, tenant) is None
    # The definer function itself, with nothing in front of it, and a factor verified minutes
    # ago: the actor is refused with the code it already gives an approver.
    with pytest.raises(DBAPIError) as failure, admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(f"SELECT execbound.{function}(:s, :n, 'policy', CAST(:d AS jsonb))"),
            {
                "s": space_admin.session_id,
                "n": clock.now(),
                "d": json.dumps({"requirement": "optional"}),
            },
        )
    assert failure.value.orig.diag.message_primary == "RECENT_AUTH_REQUIRED"
    assert requirement(admin_engine, tenant) is None
    assert changes(admin_engine, tenant) == recorded
    # A workspace administrator signed in the same way sets it as before.
    workspace = enrolled(db, SESSIONS[kind](db, admin_engine, world, seated=False), clock)
    mfa.manage_security(db, workspace, "policy", "admins", clock=clock)
    assert requirement(admin_engine, tenant) == ("admins", workspace.identity.principal_id)
    with pytest.raises(mfa.MfaError):
        mfa.manage_security(db, space_admin, "policy", "optional", clock=clock)
    assert requirement(admin_engine, tenant)[0] == "admins"


def test_sp21_the_account_security_page_offers_a_space_administrator_no_requirement(
    db, runtime, admin_engine, world, narrowed
):
    tenant, clock = world["admin"].tenant_id, runtime.clock
    config = console_config(mfa=RING)
    for identity, sets in ((narrowed, False), (world["admin"], True)):
        with console_client(db, runtime, admin_engine, identity, config=config) as client:
            enrolled(db, client.client.cookies.get("eb_session"), clock)
            page = client.get("/account/security")
            assert page.status_code == 200, page.text
            assert ("Organization requirement" in page.text) is sets, identity
            assert ('action="/account/security/policy"' in page.text) is sets
            if sets:
                values = form_values(page.text, "/account/security/policy")[1]
            else:
                values = {"csrf": client.csrf}
            posted = client.client.post(
                "/account/security/policy",
                data={**values, "requirement": "optional" if not sets else "admins"},
                headers={"Origin": ORIGIN},
            )
            if sets:
                assert posted.status_code == 200, posted.text
                assert "Your security settings were updated." in posted.text
                assert requirement(admin_engine, tenant)[0] == "admins"
            else:
                assert posted.status_code == 403, posted.text
                assert requirement(admin_engine, tenant) is None


def test_a_requirement_check_that_fails_answers_the_page_s_problem(
    db, runtime, admin_engine, world, monkeypatch
):
    """The page asks whether this person sets the requirement before the change. A failure of
    that read, such as a database that drops the connection, is the page's own problem, as a
    failure of the change itself is, rather than a server error, and nothing is written."""
    tenant, clock = world["admin"].tenant_id, runtime.clock
    config = console_config(mfa=RING)
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as client:
        enrolled(db, client.client.cookies.get("eb_session"), clock)
        page = client.get("/account/security")
        values = form_values(page.text, "/account/security/policy")[1]

        def unavailable(*args, **kwargs):
            raise mfa.MfaError()

        monkeypatch.setattr(mfa, "sets_requirement", unavailable)
        posted = client.client.post(
            "/account/security/policy",
            data={**values, "requirement": "all"},
            headers={"Origin": ORIGIN},
        )
        assert posted.status_code == 200, posted.text
        assert "The security change could not be completed." in posted.text
    assert requirement(admin_engine, tenant) is None


# The console and the command line.


@pytest.fixture
def configured(runtime):
    """A runtime whose operator configured a model, so the assistant's routes exist."""
    runtime.assistant = AssistantConfig(api_key="console-test-key", person_hourly_turns=50)
    runtime.assistant_transport = ScriptedTransport([])
    return runtime


def test_sp21_the_console_refuses_a_space_administrator_every_workspace_change(
    db, configured, admin_engine, world, narrowed, stopped
):
    tenant = world["admin"].tenant_id
    config = console_config(assistant_enabled=True)
    before, recorded = settings_row(admin_engine, tenant), changes(admin_engine, tenant)
    with console_client(db, configured, admin_engine, narrowed, config=config) as client:
        # They read the page, and the stop on it, as before.
        view = client.get(TENANT)
        assert view.status_code == 200, view.text
        assert view.json()["stop"]["stop_id"] == str(stopped.stop_id)
        assert view.json()["mode"]["value"] == "ENFORCE"
        assert client.get(API + "/session").json()["stop"]["stop_id"] == str(stopped.stop_id)
        assert client.get(ASSISTANT).status_code == 200
        for path, body in (
            ("/mode", {"mode": "OBSERVE", "reason": "Trial"}),
            ("/deadline", {"deadline": "600", "reason": "Longer"}),
            ("/resume", {"reason": "Looks fine to me"}),
            ("/stop", {"reason": "Again"}),
        ):
            answer = client.post(TENANT + path, body)
            assert answer.status_code == 403, (path, answer.text)
            assert answer.json()["code"] == "FORBIDDEN", path
        answer = client.post(ASSISTANT, {"enabled": True, "reason": "Pilot"})
        assert answer.status_code == 403, answer.text
        assert answer.json()["code"] == "FORBIDDEN"
    assert settings_row(admin_engine, tenant) == before
    assert changes(admin_engine, tenant) == recorded
    with console_client(db, configured, admin_engine, world["admin"], config=config) as client:
        assert client.post(TENANT + "/resume", {"reason": "Reviewed"}).status_code == 200
        assert client.post(TENANT + "/mode", {"mode": "OBSERVE", "reason": "x"}).status_code == 200
        assert client.post(ASSISTANT, {"enabled": True, "reason": "Pilot"}).status_code == 200
    assert settings_row(admin_engine, tenant)["stop_id"] is None


def test_sp21_the_command_line_refuses_a_space_administrator(
    db, admin_engine, world, narrowed, stopped, tmp_path, monkeypatch, capsys
):
    tenant = world["admin"].tenant_id
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])
    narrowed_file, admin_file = tmp_path / "narrowed.token", tmp_path / "admin.token"
    narrowed_file.write_text(credential(admin_engine, narrowed), encoding="utf-8")
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    before, recorded = settings_row(admin_engine, tenant), changes(admin_engine, tenant)

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        main()
        return json.loads(capsys.readouterr().out)

    def refused(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        with pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == 2, argv
        return capsys.readouterr().err

    common = ("--tenant", str(tenant), "--credential-file", str(narrowed_file))
    for argv in (
        ("tenant-mode", *common, "--set", "OBSERVE", "--reason", "Trial"),
        ("tenant-approval-deadline", *common, "--set", "600", "--reason", "Longer"),
        ("tenant-resume", *common, "--reason", "Looks fine to me"),
        ("tenant-assistant", *common, "--set", "on", "--reason", "Pilot"),
    ):
        assert "INVALID_IDENTITY" in refused(*argv), argv
    assert settings_row(admin_engine, tenant) == before
    assert changes(admin_engine, tenant) == recorded
    # They read the stop that is in force.
    status = run("tenant-status", *common)
    assert status["stopped"] is True and status["stop_id"] == str(stopped.stop_id)
    workspace = ("--tenant", str(tenant), "--credential-file", str(admin_file))
    run("tenant-resume", *workspace, "--reason", "Reviewed")
    assert "INVALID_IDENTITY" in refused("tenant-stop", *common, "--reason", "Again")
    assert settings_row(admin_engine, tenant)["stop_id"] is None
    assert run("tenant-stop", *workspace, "--reason", "Incident 8")["stopped"] is True


# Migration 0074: the requirement's two functions gain the check in place, and the downgrade
# takes it away.

BEFORE = "0073_directory_workspace_admin"
TARGET = "0074_workspace_settings_admin"
_FILE = Path(__file__).resolve().parents[1] / "migrations" / "versions" / f"{TARGET}.py"


def _migration():
    spec = importlib.util.spec_from_file_location("workspace_settings_admin_migration", _FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sp21_the_upgrade_adds_the_check_and_the_downgrade_restores_each_function(admin_engine):
    migration = _migration()
    names = tuple(migration.PATCHES)
    assert set(names) == {"account_security_change", "user_security_change"}
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
            assert "(0074)" in body and "'access.manage',NULL,false" in body, name
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert definitions(conn, names) == old
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            assert definitions(conn, names) == new
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_sp21_a_space_administrator_is_refused_as_an_approver_is(db, admin_engine, world, narrowed):
    """The same code and the same audited refusal: nothing tells a narrowed administrator
    apart from anybody else who may not change the setting."""
    for actor in (world["human"], narrowed):
        with pytest.raises(ExecutionError) as refused:
            set_enforcement_mode(db, actor, "OBSERVE", "Trial", world["clock"])
        assert refused.value.code == "INVALID_IDENTITY"
        assert refusals_of(admin_engine, actor) == [("set_enforcement_mode", "INVALID_IDENTITY")]
