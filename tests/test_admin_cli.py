# SPDX-License-Identifier: AGPL-3.0-only
"""Owner and ADMIN administration commands: audited writes, secrets written once, no routes."""

import argparse
import json
import os
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scope_fixtures import audit_payloads
from sqlalchemy import text
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound import administration as admin
from execbound.cli import build_parser, main
from execbound.identity import AuthenticationFailed, authenticate
from execbound.passwords import PasswordError, redeem_reset, sign_in_with_password
from execbound.policy.models import MAX_GROUPS, LimitRule
from execbound.policy.preview import preview_bundle
from execbound.policy.store import (
    PolicyStoreError,
    create_bundle,
    load_active_bundle,
    retire_bundle,
)
from execbound_harness.demo import endpoint_bundle

# An executor's registered Ed25519 public key is public material, so fixed ones are safe.
FIRST_KEY = "a1" * 32
SECOND_KEY = "b2" * 32
THIRD_KEY = "c3" * 32


@pytest.fixture
def owner(seeded):
    engine = admin.owner_engine(os.environ["TEST_MIGRATION_DATABASE_URL"])
    yield engine
    engine.dispose()


@pytest.fixture
def cli_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])


def audit_kinds(engine, tenant):
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return [
            row[0]
            for row in conn.execute(
                text(
                    "SELECT kind FROM execbound.audit_events WHERE tenant_id=:t ORDER BY sequence"
                ),
                {"t": tenant},
            )
        ]


def run(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["execbound", *argv])
    main()
    return json.loads(capsys.readouterr().out)


def cli_help(command, option=None):
    """What `execbound --help` says about a command, or about one of its options."""
    parser = build_parser()[0]
    commands = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    if option is None:
        return next(item.help for item in commands._choices_actions if item.dest == command)
    return next(
        action.help
        for action in commands.choices[command]._actions
        if option in action.option_strings
    )


def refused(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["execbound", *argv])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    return capsys.readouterr()


def test_bootstrap_admin_then_issue_list_and_revoke(owner, admin_engine, db, tmp_path):
    tenant = admin.create_tenant(owner, "  Operator tenant ")
    first = admin.create_principal(owner, tenant, "ADMIN")
    agent = admin.create_principal(owner, tenant, "AGENT", actor=first)
    output = tmp_path / "agent.token"
    issued = admin.issue_credential(
        owner, tenant, agent, first, lifetime=timedelta(hours=2), output=output
    )
    assert issued.kind == "AGENT" and issued.output == output
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
    token = output.read_text(encoding="utf-8").strip()
    identity = authenticate(db, token)
    assert (identity.tenant_id, identity.principal_id, identity.kind) == (tenant, agent, "AGENT")
    assert identity.expires_at == issued.expires_at

    listed = admin.list_credentials(owner, tenant)
    assert [(item.credential_id, item.kind, item.revoked_at) for item in listed] == [
        (issued.credential_id, "AGENT", None)
    ]

    admin.revoke_credential(owner, tenant, issued.credential_id, first)
    with pytest.raises(AuthenticationFailed):
        authenticate(db, token)
    assert admin.list_credentials(owner, tenant)[0].revoked_at is not None
    with pytest.raises(admin.AdministrationError, match="Administration unavailable") as caught:
        admin.revoke_credential(owner, tenant, issued.credential_id, first)
    assert caught.value.code == "INVALID_CREDENTIAL"
    assert audit_kinds(admin_engine, tenant) == [
        "principal.created",
        "principal.created",
        "credential.issued",
        "credential.revoked",
    ]


def test_actor_rules_and_tenant_scoping(owner, tmp_path):
    tenant = admin.create_tenant(owner, "Scoped")
    other = admin.create_tenant(owner, "Other")
    first = admin.create_principal(owner, tenant, "ADMIN")
    with pytest.raises(admin.AdministrationError) as second:
        admin.create_principal(owner, tenant, "ADMIN")
    assert second.value.code == "INVALID_ACTOR"
    with pytest.raises(admin.AdministrationError) as agent_first:
        admin.create_principal(owner, other, "AGENT")
    assert agent_first.value.code == "INVALID_ACTOR"
    agent = admin.create_principal(owner, tenant, "AGENT", actor=first)
    with pytest.raises(admin.AdministrationError) as agent_actor:
        admin.create_principal(owner, tenant, "HUMAN_APPROVER", actor=agent)
    assert agent_actor.value.code == "INVALID_ACTOR"
    with pytest.raises(admin.AdministrationError) as foreign:
        admin.issue_credential(
            owner, other, agent, first, lifetime=timedelta(hours=1), output=tmp_path / "x"
        )
    assert foreign.value.code == "INVALID_ACTOR"
    assert not (tmp_path / "x").exists()
    with pytest.raises(admin.AdministrationError) as lifetime:
        admin.issue_credential(
            owner, tenant, agent, first, lifetime=timedelta(days=91), output=tmp_path / "y"
        )
    assert lifetime.value.code == "INVALID_LIFETIME"
    with pytest.raises(admin.AdministrationError) as unknown:
        admin.revoke_credential(owner, tenant, uuid4(), first)
    assert unknown.value.code == "INVALID_CREDENTIAL"


def test_issue_never_overwrites_and_leaves_no_row_on_failure(owner, tmp_path):
    tenant = admin.create_tenant(owner, "Files")
    first = admin.create_principal(owner, tenant, "ADMIN")
    existing = tmp_path / "existing.token"
    existing.write_text("keep\n", encoding="utf-8")
    with pytest.raises(admin.AdministrationError) as caught:
        admin.issue_credential(
            owner, tenant, first, first, lifetime=timedelta(hours=1), output=existing
        )
    assert caught.value.code == "OUTPUT_UNAVAILABLE"
    assert existing.read_text(encoding="utf-8") == "keep\n"
    assert admin.list_credentials(owner, tenant) == ()
    missing_principal = tmp_path / "missing.token"
    with pytest.raises(admin.AdministrationError) as unknown:
        admin.issue_credential(
            owner, tenant, uuid4(), first, lifetime=timedelta(hours=1), output=missing_principal
        )
    assert unknown.value.code == "INVALID_PRINCIPAL"
    assert not missing_principal.exists()


def test_owner_commands_through_the_cli_print_no_secret(
    owner, cli_env, monkeypatch, capsys, tmp_path
):
    created = run(monkeypatch, capsys, "tenant-create", "--name", "CLI tenant")
    tenant = created["tenant_id"]
    first = run(monkeypatch, capsys, "principal-create", "--tenant", tenant, "--kind", "ADMIN")
    output = tmp_path / "admin.token"
    issued = run(
        monkeypatch,
        capsys,
        "credential-issue",
        "--tenant",
        tenant,
        "--principal",
        first["principal_id"],
        "--actor",
        first["principal_id"],
        "--output",
        str(output),
    )
    token = output.read_text(encoding="utf-8").strip()
    assert token not in json.dumps(issued) and issued["token_file"] == str(output)
    listed = run(monkeypatch, capsys, "credential-list", "--tenant", tenant)
    assert [item["credential_id"] for item in listed] == [issued["credential_id"]]
    assert token not in json.dumps(listed)
    result = refused(
        monkeypatch,
        capsys,
        "credential-issue",
        "--tenant",
        tenant,
        "--principal",
        first["principal_id"],
        "--actor",
        str(uuid4()),
        "--output",
        str(tmp_path / "never.token"),
    )
    assert "INVALID_ACTOR" in result.err and not (tmp_path / "never.token").exists()


def test_bundle_lifecycle_through_the_cli(
    owner, cli_env, db, world, registry, admin_engine, monkeypatch, capsys, tmp_path
):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    credential_file = tmp_path / "admin.token"
    admin.issue_credential(
        owner, tenant, actor, actor, lifetime=timedelta(hours=1), output=credential_file
    )
    content = endpoint_bundle(tenant, registry["account"], mapping_version="map-v1")
    bundle_file = tmp_path / "bundle.json"
    payload = json.loads(content.model_dump_json())
    del payload["tenant_id"]
    del payload["bundle_id"]
    bundle_file.write_text(json.dumps(payload), encoding="utf-8")
    common = ["--tenant", str(tenant), "--credential-file", str(credential_file)]

    created = run(monkeypatch, capsys, "bundle-create", *common, "--input", str(bundle_file))
    bundle_id = created["bundle_id"]
    assert created["state"] == "DRAFT" and created["content_hash"]
    validated = run(monkeypatch, capsys, "bundle-validate", *common, "--bundle", bundle_id)
    assert validated["state"] == "VALIDATED"
    previous = str(world["bundle"].bundle_id)
    activated = run(monkeypatch, capsys, "bundle-activate", *common, "--bundle", bundle_id)
    assert activated["state"] == "ACTIVE"
    states = {
        item["bundle_id"]: (item["state"], item["active"])
        for item in run(monkeypatch, capsys, "bundle-list", *common)
    }
    # `ACTIVE` means "selected by at least one space" since migration 0041: the bundle the
    # space stopped selecting goes back to VALIDATED, so it can be selected again.
    assert states[bundle_id] == ("ACTIVE", True) and states[previous] == ("VALIDATED", False)
    assert str(load_active_bundle(db, world["admin"]).bundle_id) == bundle_id
    # The published help says what just happened, not the retirement it described before
    # spaces: the replaced bundle is VALIDATED again, and nothing was retired.
    assert "returns to VALIDATED" in cli_help("bundle-activate", "--bundle")
    for said in (cli_help("bundle-activate"), cli_help("bundle-activate", "--bundle")):
        assert "retire" not in said.lower(), said

    # A bundle a space selects cannot be retired; the one it stopped selecting can.
    result = refused(monkeypatch, capsys, "bundle-retire", *common, "--bundle", bundle_id)
    assert "INVALID_STATE" in result.err
    # And the help names that refusal, where it once promised a tenant left with no selection.
    assert "INVALID_STATE" in cli_help("bundle-retire", "--bundle")
    for said in (cli_help("bundle-retire"), cli_help("bundle-retire", "--bundle")):
        assert "selection" not in said, said
    retired = run(monkeypatch, capsys, "bundle-retire", *common, "--bundle", previous)
    assert retired["state"] == "RETIRED"
    with db.transaction(tenant) as conn:
        selection = conn.execute(
            text("SELECT bundle_id FROM execbound.space_policy_selection WHERE tenant_id=:t"),
            {"t": tenant},
        ).scalar_one()
    assert str(selection) == bundle_id
    assert str(load_active_bundle(db, world["admin"]).bundle_id) == bundle_id
    kinds = audit_kinds(admin_engine, tenant)
    assert kinds[-5:] == [
        "policy.bundle_created",
        "policy.bundle_validated",
        "policy.bundle_deselected",
        "policy.bundle_activated",
        "policy.bundle_retired",
    ]
    # Without --reason the event is what it always was; with one, it carries the reason.
    assert "reason" not in audit_payloads(admin_engine, tenant, "policy.bundle_activated")[-1]
    assert "audit event" in cli_help("bundle-activate", "--reason")
    second = run(monkeypatch, capsys, "bundle-create", *common, "--input", str(bundle_file))
    run(monkeypatch, capsys, "bundle-validate", *common, "--bundle", second["bundle_id"])
    blank = refused(
        monkeypatch,
        capsys,
        "bundle-activate",
        *common,
        "--bundle",
        second["bundle_id"],
        "--reason",
        "   ",
    )
    assert "INVALID_REASON" in blank.err
    activated = run(
        monkeypatch,
        capsys,
        "bundle-activate",
        *common,
        "--bundle",
        second["bundle_id"],
        "--reason",
        "Rollout 7",
    )
    assert activated["state"] == "ACTIVE"
    latest = audit_payloads(admin_engine, tenant, "policy.bundle_activated")[-1]
    assert (latest["bundle_id"], latest["reason"]) == (second["bundle_id"], "Rollout 7")


def test_bundle_commands_require_a_current_admin_and_report_file_problems(
    owner, cli_env, world, monkeypatch, capsys, tmp_path
):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    agent_file = tmp_path / "agent.token"
    admin.issue_credential(
        owner,
        tenant,
        world["identity"].principal_id,
        actor,
        lifetime=timedelta(hours=1),
        output=agent_file,
    )
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(json.dumps({"authorization_policies": "permit;"}), encoding="utf-8")
    result = refused(
        monkeypatch,
        capsys,
        "bundle-create",
        "--tenant",
        str(tenant),
        "--credential-file",
        str(agent_file),
        "--input",
        str(bundle_file),
    )
    assert "cedar_schema" in result.err and "mappings" in result.err
    assert "permit;" not in result.err
    valid = endpoint_bundle(tenant, UUID(int=1), mapping_version="map-v1")
    bundle_file.write_text(valid.model_dump_json(), encoding="utf-8")
    result = refused(
        monkeypatch,
        capsys,
        "bundle-create",
        "--tenant",
        str(tenant),
        "--credential-file",
        str(agent_file),
        "--input",
        str(bundle_file),
    )
    assert "INVALID_IDENTITY" in result.err
    result = refused(
        monkeypatch,
        capsys,
        "bundle-list",
        "--tenant",
        str(uuid4()),
        "--credential-file",
        str(agent_file),
    )
    assert "INVALID_IDENTITY" in result.err


def test_approver_assignment_lifecycle(owner, world, admin_engine):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    approver = world["human"].principal_id
    target = world["canonical"]
    admin.unassign_approver(owner, tenant, approver, target, "endpoint.isolate", actor)
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        active = conn.execute(
            text(
                "SELECT active FROM execbound.approval_scopes WHERE tenant_id=:t "
                "AND approver_id=:a AND canonical_target_id=:c AND action='endpoint.isolate'"
            ),
            {"t": tenant, "a": approver, "c": target},
        ).scalar_one()
    assert active is False
    admin.assign_approver(owner, tenant, approver, target, "endpoint.isolate", actor)
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        active = conn.execute(
            text(
                "SELECT active FROM execbound.approval_scopes WHERE tenant_id=:t "
                "AND approver_id=:a AND canonical_target_id=:c AND action='endpoint.isolate'"
            ),
            {"t": tenant, "a": approver, "c": target},
        ).scalar_one()
    assert active is True
    with pytest.raises(admin.AdministrationError) as wrong_kind:
        admin.assign_approver(
            owner, tenant, world["identity"].principal_id, target, "endpoint.isolate", actor
        )
    assert wrong_kind.value.code == "INVALID_PRINCIPAL"
    with pytest.raises(admin.AdministrationError) as unknown_target:
        admin.assign_approver(owner, tenant, approver, uuid4(), "endpoint.isolate", actor)
    assert unknown_target.value.code == "INVALID_TARGET"
    with pytest.raises(admin.AdministrationError) as bad_action:
        admin.assign_approver(owner, tenant, approver, target, "endpoint.reboot", actor)
    assert bad_action.value.code == "INVALID_ACTION"
    with pytest.raises(admin.AdministrationError) as already:
        admin.unassign_approver(owner, tenant, approver, uuid4(), "endpoint.isolate", actor)
    assert already.value.code == "INVALID_SCOPE"
    assert audit_kinds(admin_engine, tenant)[-2:] == [
        "approval_scope.revoked",
        "approval_scope.assigned",
    ]


def membership_rows(engine, tenant):
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return conn.execute(
            text(
                "SELECT group_id, principal_id FROM execbound.principal_group_members "
                "WHERE tenant_id=:t ORDER BY group_id, principal_id"
            ),
            {"t": tenant},
        ).all()


def test_group_lifecycle(owner, world, admin_engine):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    agent = world["identity"].principal_id
    group = admin.create_group(owner, tenant, "triage", actor)
    for duplicate in ("triage", "  triage  "):
        with pytest.raises(admin.AdministrationError) as taken:
            admin.create_group(owner, tenant, duplicate, actor)
        assert taken.value.code == "INVALID_NAME"
    for name in ("", "n" * (admin.MAX_GROUP_NAME_LENGTH + 1)):
        with pytest.raises(admin.AdministrationError) as bad_name:
            admin.create_group(owner, tenant, name, actor)
        assert bad_name.value.code == "INVALID_NAME"
    with pytest.raises(admin.AdministrationError) as agent_creates:
        admin.create_group(owner, tenant, "alerts", agent)
    assert agent_creates.value.code == "INVALID_ACTOR"
    alerts = admin.create_group(owner, tenant, "alerts", actor)
    listed = admin.list_groups(owner, tenant)
    assert [(item.group_id, item.name, item.members) for item in listed] == [
        (alerts, "alerts", ()),
        (group, "triage", ()),
    ]
    assert all(item.created_at.tzinfo is not None for item in listed)

    admin.assign_group(owner, tenant, group, agent, actor)
    assert membership_rows(admin_engine, tenant) == [(group, agent)]
    assert admin.list_groups(owner, tenant)[1].members == (agent,)
    for non_agent in (world["human"].principal_id, world["admin"].principal_id):
        with pytest.raises(admin.AdministrationError) as wrong_kind:
            admin.assign_group(owner, tenant, group, non_agent, actor)
        assert wrong_kind.value.code == "INVALID_PRINCIPAL"
    with pytest.raises(admin.AdministrationError) as unknown_principal:
        admin.assign_group(owner, tenant, group, uuid4(), actor)
    assert unknown_principal.value.code == "INVALID_PRINCIPAL"
    with pytest.raises(admin.AdministrationError) as already:
        admin.assign_group(owner, tenant, group, agent, actor)
    assert already.value.code == "INVALID_MEMBERSHIP"

    admin.unassign_group(owner, tenant, group, agent, actor)
    assert membership_rows(admin_engine, tenant) == []
    with pytest.raises(admin.AdministrationError) as gone:
        admin.unassign_group(owner, tenant, group, agent, actor)
    assert gone.value.code == "INVALID_MEMBERSHIP"
    with pytest.raises(admin.AdministrationError) as unknown_group:
        admin.assign_group(owner, tenant, uuid4(), agent, actor)
    assert unknown_group.value.code == "INVALID_GROUP"
    with pytest.raises(admin.AdministrationError) as not_admin:
        admin.assign_group(owner, tenant, group, agent, agent)
    assert not_admin.value.code == "INVALID_ACTOR"
    with pytest.raises(admin.AdministrationError) as foreign:
        admin.assign_group(owner, admin.create_tenant(owner, "Other"), group, agent, actor)
    assert foreign.value.code == "INVALID_ACTOR"
    assert membership_rows(admin_engine, tenant) == []
    assert audit_kinds(admin_engine, tenant)[-4:] == [
        "group.created",
        "group.created",
        "group.assigned",
        "group.revoked",
    ]


def test_group_membership_is_bounded(owner, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    agent = world["identity"].principal_id
    assert admin.MAX_GROUP_MEMBERSHIPS == MAX_GROUPS == 64
    groups = [
        admin.create_group(owner, tenant, f"group-{index:02d}", actor)
        for index in range(admin.MAX_GROUP_MEMBERSHIPS + 1)
    ]
    for group in groups[: admin.MAX_GROUP_MEMBERSHIPS]:
        admin.assign_group(owner, tenant, group, agent, actor)
    with pytest.raises(admin.AdministrationError) as caught:
        admin.assign_group(owner, tenant, groups[-1], agent, actor)
    assert caught.value.code == "INVALID_MEMBERSHIP"
    members = [item.members for item in admin.list_groups(owner, tenant)]
    assert members.count((agent,)) == admin.MAX_GROUP_MEMBERSHIPS and members.count(()) == 1
    # Another agent is not bounded by this principal's memberships.
    other = admin.create_principal(owner, tenant, "AGENT", actor=actor)
    admin.assign_group(owner, tenant, groups[-1], other, actor)
    assert admin.list_groups(owner, tenant)[-1].members == (other,)


def test_membership_changes_wait_for_the_tenant_fence(owner, db, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    agent = world["identity"].principal_id
    group = admin.create_group(owner, tenant, "fenced", actor)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with db.transaction(tenant) as conn:
            conn.execute(
                text(
                    "SELECT tenant_id FROM execbound.tenant_policy_control "
                    "WHERE tenant_id=:t FOR UPDATE"
                ),
                {"t": tenant},
            ).one()
            assignment = pool.submit(admin.assign_group, owner, tenant, group, agent, actor)
            with pytest.raises(TimeoutError):
                assignment.result(timeout=1.0)
        assert assignment.result(timeout=10.0) is None
    assert admin.list_groups(owner, tenant)[0].members == (agent,)


def test_group_commands_through_the_cli(owner, cli_env, world, monkeypatch, capsys):
    tenant = str(world["identity"].tenant_id)
    actor = str(world["admin"].principal_id)
    agent = str(world["identity"].principal_id)
    created = run(
        monkeypatch,
        capsys,
        "group-create",
        "--tenant",
        tenant,
        "--name",
        "triage",
        "--actor",
        actor,
    )
    group = created["group_id"]
    assert list(created) == ["group_id"] and str(UUID(group)) == group
    common = ["--tenant", tenant, "--group", group, "--principal", agent, "--actor", actor]
    assigned = run(monkeypatch, capsys, "group-assign", *common)
    assert assigned == {"group_id": group, "principal_id": agent, "assigned": True}
    listed = run(monkeypatch, capsys, "group-list", "--tenant", tenant)
    assert [(item["group_id"], item["name"], item["members"]) for item in listed] == [
        (group, "triage", [agent])
    ]
    unassigned = run(monkeypatch, capsys, "group-unassign", *common)
    assert unassigned == {"group_id": group, "principal_id": agent, "assigned": False}
    assert run(monkeypatch, capsys, "group-list", "--tenant", tenant)[0]["members"] == []
    result = refused(
        monkeypatch,
        capsys,
        "group-assign",
        "--tenant",
        tenant,
        "--group",
        str(uuid4()),
        "--principal",
        agent,
        "--actor",
        actor,
    )
    assert "Administration refused: INVALID_GROUP." in result.err


def executor_key_rows(engine, tenant):
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return conn.execute(
            text(
                "SELECT key_id, public_key, revoked_at FROM execbound.executor_keys "
                "WHERE tenant_id=:t ORDER BY created_at, key_id"
            ),
            {"t": tenant},
        ).all()


def executor_key_reasons(engine, tenant):
    """Each key with the reason its revocation was recorded under, oldest first.

    Kept apart from `executor_key_rows` because the two questions are different: that one
    asks what material a key carries and whether it is live, this one asks which kind of
    revocation retired it, which is what decides whether it still attests.
    """
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return conn.execute(
            text(
                "SELECT key_id, revocation_reason FROM execbound.executor_keys "
                "WHERE tenant_id=:t ORDER BY created_at, key_id"
            ),
            {"t": tenant},
        ).all()


def test_executor_key_lifecycle(owner, world, admin_engine):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    agent = world["identity"].principal_id
    # The operator supplies the key; uppercase hex is normalized rather than refused, and
    # nothing is generated or returned, so there is no secret to print or to lose.
    admin.register_executor_key(owner, tenant, "executor-v1", FIRST_KEY.upper(), actor)
    [registered] = admin.list_executor_keys(owner, tenant)
    assert (registered.key_id, registered.public_key, registered.revoked_at) == (
        "executor-v1",
        FIRST_KEY,
        None,
    )
    assert registered.created_at.tzinfo is not None
    for duplicate in (FIRST_KEY, SECOND_KEY):
        with pytest.raises(admin.AdministrationError) as taken:
            admin.register_executor_key(owner, tenant, "executor-v1", duplicate, actor)
        assert taken.value.code == "INVALID_KEY"
    for malformed in ("a" * 63, "a" * 65, "z" + "a" * 63, "", FIRST_KEY + "\n", " " + FIRST_KEY):
        with pytest.raises(admin.AdministrationError) as bad_key:
            admin.register_executor_key(owner, tenant, "executor-v2", malformed, actor)
        assert bad_key.value.code == "INVALID_KEY"
    for bad_id in ("", "e" * 65, "executor v1", "executor/v1", "executor-v1\n"):
        with pytest.raises(admin.AdministrationError) as bad_name:
            admin.register_executor_key(owner, tenant, bad_id, SECOND_KEY, actor)
        assert bad_name.value.code == "INVALID_KEY"
    assert executor_key_rows(admin_engine, tenant) == [("executor-v1", FIRST_KEY, None)]

    admin.rotate_executor_key(owner, tenant, "executor-v1", "executor-v2", SECOND_KEY, actor)
    old, new = admin.list_executor_keys(owner, tenant)
    # Rotation adds a key and stamps the old row; it never rewrites the material a proof
    # for a grant issued while that key was current is checked against.
    assert (old.key_id, old.public_key) == ("executor-v1", FIRST_KEY)
    assert old.revoked_at is not None and old.revoked_at >= old.created_at
    assert (new.key_id, new.public_key, new.revoked_at) == ("executor-v2", SECOND_KEY, None)
    for old_id, new_id in (
        ("executor-v1", "executor-v3"),
        ("never-registered", "executor-v3"),
        ("executor-v2", "executor-v1"),
        ("executor-v2", "executor-v2"),
    ):
        with pytest.raises(admin.AdministrationError) as rotation:
            admin.rotate_executor_key(owner, tenant, old_id, new_id, FIRST_KEY, actor)
        assert rotation.value.code == "INVALID_KEY"
    # A rotation onto a taken id revokes nothing: both statements share one transaction.
    assert executor_key_rows(admin_engine, tenant) == [
        ("executor-v1", FIRST_KEY, old.revoked_at),
        ("executor-v2", SECOND_KEY, None),
    ]

    admin.revoke_executor_key(owner, tenant, "executor-v2", actor)
    assert all(item.revoked_at is not None for item in admin.list_executor_keys(owner, tenant))
    for key_id in ("executor-v2", "executor-v1", "never-registered"):
        with pytest.raises(admin.AdministrationError) as gone:
            admin.revoke_executor_key(owner, tenant, key_id, actor)
        assert gone.value.code == "INVALID_KEY"

    other = admin.create_tenant(owner, "Other")
    for operation in (
        lambda: admin.register_executor_key(owner, tenant, "executor-v3", FIRST_KEY, agent),
        lambda: admin.rotate_executor_key(
            owner, tenant, "executor-v2", "executor-v3", FIRST_KEY, agent
        ),
        lambda: admin.revoke_executor_key(owner, tenant, "executor-v2", agent),
        lambda: admin.register_executor_key(owner, other, "executor-v3", FIRST_KEY, actor),
        lambda: admin.rotate_executor_key(
            owner, other, "executor-v1", "executor-v3", FIRST_KEY, actor
        ),
        lambda: admin.revoke_executor_key(owner, other, "executor-v1", actor),
    ):
        with pytest.raises(admin.AdministrationError) as refused_actor:
            operation()
        assert refused_actor.value.code == "INVALID_ACTOR"
    assert executor_key_rows(admin_engine, other) == []
    assert audit_kinds(admin_engine, tenant)[-3:] == [
        "executor_key.registered",
        "executor_key.rotated",
        "executor_key.revoked",
    ]


def test_registration_refuses_a_public_key_nobody_holds_the_private_half_of(owner, world):
    """A small-order or non-canonical Ed25519 encoding is thirty-two bytes of hex, so the
    column's CHECK constraint and the shape pattern admit it, and `cryptography` loads it
    as a public key: the identity point below verifies any message at all against one fixed
    signature. Registering one would hand the attested tier to a stranger, so the key ring
    never stores one — through registration or through rotation, in either case."""
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    admin.register_executor_key(owner, tenant, "executor-v1", FIRST_KEY, actor)
    forgeable = (
        "01" + "00" * 31,  # the identity point, order one
        "00" * 32,  # an order-four point
        "ec" + "ff" * 30 + "7f",  # the order-two point
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order eight
        "ed" + "ff" * 30 + "7f",  # y equal to the field prime: a non-canonical zero
    )
    for encoding in forgeable:
        for value in (encoding, encoding.upper()):
            with pytest.raises(admin.AdministrationError) as refused_key:
                admin.register_executor_key(owner, tenant, "executor-v2", value, actor)
            assert refused_key.value.code == "INVALID_KEY"
            with pytest.raises(admin.AdministrationError) as refused_rotation:
                admin.rotate_executor_key(owner, tenant, "executor-v1", "executor-v2", value, actor)
            assert refused_rotation.value.code == "INVALID_KEY"
    # Nothing was stored and nothing was retired: the original key is still the only one.
    listed = admin.list_executor_keys(owner, tenant)
    assert [(item.key_id, item.public_key, item.revoked_at) for item in listed] == [
        ("executor-v1", FIRST_KEY, None)
    ]


def test_registration_refuses_material_already_live_for_the_tenant(owner, world, admin_engine):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    admin.register_executor_key(owner, tenant, "executor-v1", FIRST_KEY, actor)
    # A second id carrying a registered key, or a rotation that pastes back the key it is
    # revoking, would leave the compromised private key minting attested evidence while the
    # audit chain showed a key ring change. Case cannot evade the check: the key is
    # normalized to lowercase before it is compared.
    for case in (FIRST_KEY, FIRST_KEY.upper()):
        with pytest.raises(admin.AdministrationError) as second_id:
            admin.register_executor_key(owner, tenant, "executor-v2", case, actor)
        assert second_id.value.code == "INVALID_KEY"
        with pytest.raises(admin.AdministrationError) as pasted:
            admin.rotate_executor_key(owner, tenant, "executor-v1", "executor-v2", case, actor)
        assert pasted.value.code == "INVALID_KEY"
    # The refused rotation revoked nothing: the registered key is still the live one.
    assert executor_key_rows(admin_engine, tenant) == [("executor-v1", FIRST_KEY, None)]

    other = admin.create_tenant(owner, "Other executor")
    other_actor = admin.create_principal(owner, other, "ADMIN")
    # The check is per tenant and only live rows reserve material: another tenant may
    # register the same public key, and a key revoked by a rotation may be registered again.
    admin.register_executor_key(owner, other, "executor-v1", FIRST_KEY, other_actor)
    admin.rotate_executor_key(owner, tenant, "executor-v1", "executor-v2", SECOND_KEY, actor)
    admin.register_executor_key(owner, tenant, "executor-v3", FIRST_KEY, actor)
    assert [item.public_key for item in admin.list_executor_keys(owner, tenant)] == [
        FIRST_KEY,
        SECOND_KEY,
        FIRST_KEY,
    ]
    assert [item.public_key for item in admin.list_executor_keys(owner, other)] == [FIRST_KEY]


def test_the_last_key_stays_while_an_active_bundle_declares_an_executor(
    owner, db, world, admin_engine
):
    from test_execution import activate

    from execbound.execution import store as execution_store

    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    admin.register_executor_key(owner, tenant, "executor-v1", FIRST_KEY, actor)
    flagged = (world["bundle"].mappings[0].model_copy(update={"external_executor": True}),)
    plain = (world["bundle"].mappings[0].model_copy(update={"external_executor": False}),)
    activate(db, world, mappings=flagged)
    with pytest.raises(admin.AdministrationError) as needed:
        admin.revoke_executor_key(owner, tenant, "executor-v1", actor)
    assert needed.value.code == "INVALID_STATE"
    assert "INVALID_STATE" in cli_help("executor-key-revoke", "--key-id")
    assert executor_key_rows(admin_engine, tenant) == [("executor-v1", FIRST_KEY, None)]
    with db.transaction(tenant) as conn:
        # Admission reads the active bundle without re-running component validation, so
        # the refusal above is what keeps a grant attestable rather than a redundant check.
        assert execution_store.active_bundle(conn, tenant).mappings[0].external_executor is True

    # Rotation is unaffected: it leaves a live key in the same transaction.
    admin.rotate_executor_key(owner, tenant, "executor-v1", "executor-v2", SECOND_KEY, actor)
    # So is revoking a key that is not the tenant's last one.
    admin.register_executor_key(owner, tenant, "executor-v3", THIRD_KEY, actor)
    admin.revoke_executor_key(owner, tenant, "executor-v3", actor)
    with pytest.raises(admin.AdministrationError) as last:
        admin.revoke_executor_key(owner, tenant, "executor-v2", actor)
    assert last.value.code == "INVALID_STATE"

    # Once the active bundle no longer declares an executor, the last key may go.
    activate(db, world, mappings=plain)
    admin.revoke_executor_key(owner, tenant, "executor-v2", actor)
    assert all(item.revoked_at is not None for item in admin.list_executor_keys(owner, tenant))

    # And retiring the flagged bundle leaves nothing active to refuse for.
    admin.register_executor_key(owner, tenant, "executor-v4", FIRST_KEY, actor)
    activate(db, world, mappings=flagged)
    with pytest.raises(admin.AdministrationError) as active:
        admin.revoke_executor_key(owner, tenant, "executor-v4", actor)
    assert active.value.code == "INVALID_STATE"
    # A bundle a space selects cannot be retired since migration 0041, so the way to stop
    # declaring an external executor is to select another bundle; the flagged one returns
    # to VALIDATED and then retires.
    flagged_id = world["bundle"].bundle_id
    plain = (world["bundle"].mappings[0].model_copy(update={"external_executor": False}),)
    activate(db, world, mappings=plain)
    retire_bundle(db, world["admin"], flagged_id, world["clock"])
    admin.revoke_executor_key(owner, tenant, "executor-v4", actor)
    assert all(item.revoked_at is not None for item in admin.list_executor_keys(owner, tenant))


def test_a_compromise_cuts_off_the_last_key_a_retirement_could_not(owner, db, world, admin_engine):
    """The one revocation that may leave the ring empty, and why it must be allowed to.

    `_keep_attestable` refuses to retire a tenant's last live key while its active bundle
    declares an external executor, because that would leave the tenant issuing grants
    nothing could attest. Under a compromise that guard would refuse the security action
    itself: an operator who cannot cut off a stolen key because it is the last one is
    worse off than before. So the compromise bypasses it, and what makes the result safe
    is admission, which now refuses to issue a grant for a tenant with no live key —
    `test_a_tenant_whose_last_key_is_cut_off_grants_nothing_new` in tests/test_checkpoint.py
    holds that half.
    """
    from test_execution import activate

    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    agent = world["identity"].principal_id
    admin.register_executor_key(owner, tenant, "executor-v1", FIRST_KEY, actor)
    flagged = (world["bundle"].mappings[0].model_copy(update={"external_executor": True}),)
    activate(db, world, mappings=flagged)
    with pytest.raises(admin.AdministrationError) as retirement:
        admin.revoke_executor_key(owner, tenant, "executor-v1", actor)
    assert retirement.value.code == "INVALID_STATE"
    assert executor_key_reasons(admin_engine, tenant) == [("executor-v1", None)]

    admin.report_executor_key_compromise(owner, tenant, "executor-v1", actor)
    [cut_off] = admin.list_executor_keys(owner, tenant)
    # The row stays and keeps its public key: what changed is the reason, which is what
    # the verifier reads, and it is recorded rather than inferred from the ring being empty.
    assert (cut_off.key_id, cut_off.public_key) == ("executor-v1", FIRST_KEY)
    assert cut_off.revoked_at is not None and cut_off.revocation_reason == "COMPROMISED"
    assert "COMPROMISED" in cli_help("executor-key-compromise", "--key-id")
    assert audit_kinds(admin_engine, tenant)[-1] == "executor_key.compromised"
    assert audit_payloads(admin_engine, tenant, "executor_key.compromised") == [
        {"key_id": "executor-v1"}
    ]

    # A key already cut off, and an id the tenant never registered. A key merely retired
    # is not on this list: rotate-first is what incident response does, and
    # `test_a_compromise_is_recordable_over_a_key_already_revoked` holds that half.
    admin.register_executor_key(owner, tenant, "executor-v2", SECOND_KEY, actor)
    admin.rotate_executor_key(owner, tenant, "executor-v2", "executor-v3", THIRD_KEY, actor)
    for key_id in ("executor-v1", "never-registered"):
        with pytest.raises(admin.AdministrationError) as gone:
            admin.report_executor_key_compromise(owner, tenant, key_id, actor)
        assert gone.value.code == "INVALID_KEY"
    for bad_id in ("", "e" * 65, "executor v1"):
        with pytest.raises(admin.AdministrationError) as bad_name:
            admin.report_executor_key_compromise(owner, tenant, bad_id, actor)
        assert bad_name.value.code == "INVALID_KEY"

    other = admin.create_tenant(owner, "Other compromise")
    for operation in (
        lambda: admin.report_executor_key_compromise(owner, tenant, "executor-v3", agent),
        lambda: admin.report_executor_key_compromise(owner, other, "executor-v3", actor),
    ):
        with pytest.raises(admin.AdministrationError) as refused_actor:
            operation()
        assert refused_actor.value.code == "INVALID_ACTOR"
    # A rotation is an ordinary retirement however it is being used, and the reasons say
    # which writer wrote each row, so an incident is never inferred from a rotation.
    assert executor_key_reasons(admin_engine, tenant) == [
        ("executor-v1", "COMPROMISED"),
        ("executor-v2", "RETIRED"),
        ("executor-v3", None),
    ]
    assert "RETIRED" in cli_help("executor-key-rotate", "--key-id")
    admin.report_executor_key_compromise(owner, tenant, "executor-v3", actor, now=None)
    assert executor_key_reasons(admin_engine, tenant)[-1] == ("executor-v3", "COMPROMISED")


def test_a_compromise_stamps_the_supplied_instant(owner, world):
    """As the other three writers do, so a scenario can place a cut-off around a grant."""
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    registered_at = datetime(2026, 9, 16, 9, 0, tzinfo=UTC)
    compromised_at = registered_at + timedelta(hours=2)
    admin.register_executor_key(owner, tenant, "executor-v1", FIRST_KEY, actor, now=registered_at)
    admin.report_executor_key_compromise(owner, tenant, "executor-v1", actor, now=compromised_at)
    [cut_off] = admin.list_executor_keys(owner, tenant)
    assert (cut_off.revoked_at, cut_off.revocation_reason) == (compromised_at, "COMPROMISED")
    admin.register_executor_key(owner, tenant, "executor-v2", SECOND_KEY, actor, now=registered_at)
    with pytest.raises(admin.AdministrationError) as naive:
        admin.report_executor_key_compromise(
            owner, tenant, "executor-v2", actor, now=compromised_at.replace(tzinfo=None)
        )
    assert naive.value.code == "INVALID_CLOCK"


def test_a_compromise_is_recordable_over_a_key_already_revoked(owner, world, admin_engine):
    """Rotate-first is what incident response actually does, and it must not foreclose this.

    An operator who suspects a key rotates or revokes it at once and confirms the theft
    afterwards, so by the time the compromise is known the row is already stamped RETIRED.
    Recording the compromise only over a live key left that operator with no remedy at
    all: the retired key went on attesting every grant it was holding for the rest of each
    report window, and a signed non-execution on that route refunds the reservation and
    releases the canonical claim.

    What the verifier reads is the reason and nothing else — a compromise is refused
    whatever the grant instant — so a compromise recorded over a retired row is identical
    in effect to one recorded at revocation time: both leave the row reading COMPROMISED,
    which is the whole of what it asks. `revoked_at` keeps the instant the key actually
    left the ring, because it is the record of when that happened and no longer decides
    anything; the audit chain is what carries when the compromise was reported.
    """
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    registered_at = datetime(2026, 9, 16, 9, 0, tzinfo=UTC)
    rotated_at = registered_at + timedelta(minutes=1)
    reported_at = registered_at + timedelta(hours=3)
    admin.register_executor_key(owner, tenant, "executor-v1", FIRST_KEY, actor, now=registered_at)
    admin.rotate_executor_key(
        owner, tenant, "executor-v1", "executor-v2", SECOND_KEY, actor, now=rotated_at
    )
    admin.report_executor_key_compromise(owner, tenant, "executor-v1", actor, now=reported_at)
    [rotated_away, replacement] = admin.list_executor_keys(owner, tenant)
    assert (rotated_away.revoked_at, rotated_away.revocation_reason) == (rotated_at, "COMPROMISED")
    assert audit_kinds(admin_engine, tenant)[-1] == "executor_key.compromised"
    assert audit_payloads(admin_engine, tenant, "executor_key.compromised") == [
        {"key_id": "executor-v1"}
    ]
    # A key revoked by the plain route takes a compromise the same way, and the
    # replacement is untouched by either: the two rows carry different material, and the
    # statement reaches the rows carrying the material of the key it was given.
    admin.revoke_executor_key(owner, tenant, "executor-v2", actor, now=reported_at)
    admin.report_executor_key_compromise(owner, tenant, "executor-v2", actor, now=reported_at)
    assert executor_key_reasons(admin_engine, tenant) == [
        ("executor-v1", "COMPROMISED"),
        ("executor-v2", "COMPROMISED"),
    ]

    # The two refusals that stay. An id the tenant never registered names no key at all,
    # and a key already cut off is already cut off: the act is total and permanent, so a
    # repeat would change no byte of state while appending an audit event asserting it
    # did — and one grep of the chain for the incident is the reason that kind exists.
    other = admin.create_tenant(owner, "Other ring")
    other_actor = admin.create_principal(owner, other, "ADMIN")
    admin.register_executor_key(owner, other, "executor-v1", THIRD_KEY, other_actor)
    for key_id in ("executor-v1", "executor-v2", "never-registered"):
        with pytest.raises(admin.AdministrationError) as refused:
            admin.report_executor_key_compromise(owner, tenant, key_id, actor)
        assert refused.value.code == "INVALID_KEY"
    # Nothing moved, here or in the tenant next door that holds an id with the same name.
    assert [
        (item.revoked_at, item.revocation_reason)
        for item in admin.list_executor_keys(owner, tenant)
    ] == [
        (rotated_at, "COMPROMISED"),
        (reported_at, "COMPROMISED"),
    ]
    assert executor_key_reasons(admin_engine, other) == [("executor-v1", None)]


def test_compromised_material_is_never_registrable_again(owner, world, admin_engine):
    """The private half is in someone else's hands, so the tenant may never hold it again.

    Registration refused material that was *live*, and a compromised row is revoked, so
    the stolen public key went back in under a fresh id — a live row carrying material
    someone else holds the private half of, which is exactly what the attested tier rests
    on, through a key ring the audit chain showed being repaired. A retired key is still
    re-registrable, which is what a scheduled rotation back to a key the operator still
    holds needs; a compromised one never is.

    The bar is per tenant and by material, so it also reaches every id that already
    carried the stolen key: cutting one off while a second id spelling the same public key
    stayed live would cut off nothing at all.
    """
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    admin.register_executor_key(owner, tenant, "executor-v1", FIRST_KEY, actor)
    admin.rotate_executor_key(owner, tenant, "executor-v1", "executor-v2", SECOND_KEY, actor)
    # The rotated-away material goes back in under a new id, which is allowed, and is then
    # discovered stolen. Both rows carry it, so both are cut off by the one report.
    admin.register_executor_key(owner, tenant, "executor-v3", FIRST_KEY, actor)
    admin.report_executor_key_compromise(owner, tenant, "executor-v1", actor)
    assert executor_key_reasons(admin_engine, tenant) == [
        ("executor-v1", "COMPROMISED"),
        ("executor-v2", None),
        ("executor-v3", "COMPROMISED"),
    ]
    for key_id in ("executor-v4", "executor-v5"):
        with pytest.raises(admin.AdministrationError) as reused:
            admin.register_executor_key(owner, tenant, key_id, FIRST_KEY, actor)
        assert reused.value.code == "INVALID_KEY"
    with pytest.raises(admin.AdministrationError) as rotated_back:
        admin.rotate_executor_key(owner, tenant, "executor-v2", "executor-v4", FIRST_KEY, actor)
    assert rotated_back.value.code == "INVALID_KEY"
    # The refused rotation retired nothing, and the tenant next door is not this tenant.
    assert executor_key_reasons(admin_engine, tenant) == [
        ("executor-v1", "COMPROMISED"),
        ("executor-v2", None),
        ("executor-v3", "COMPROMISED"),
    ]
    other = admin.create_tenant(owner, "Other holder")
    other_actor = admin.create_principal(owner, other, "ADMIN")
    admin.register_executor_key(owner, other, "executor-v1", FIRST_KEY, other_actor)
    # Material only this tenant retired is still its own to register again.
    admin.rotate_executor_key(owner, tenant, "executor-v2", "executor-v4", THIRD_KEY, actor)
    admin.register_executor_key(owner, tenant, "executor-v5", SECOND_KEY, actor)


def test_executor_key_changes_stamp_the_supplied_instant(owner, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    registered_at = datetime(2026, 9, 16, 9, 0, tzinfo=UTC)
    admin.register_executor_key(owner, tenant, "executor-v1", FIRST_KEY, actor, now=registered_at)
    [first] = admin.list_executor_keys(owner, tenant)
    assert first.created_at == registered_at
    handover = registered_at + timedelta(hours=1)
    admin.rotate_executor_key(
        owner, tenant, "executor-v1", "executor-v2", SECOND_KEY, actor, now=handover
    )
    old, new = admin.list_executor_keys(owner, tenant)
    # One instant for the whole handover, so a later task can build "revoked before the
    # grant" and "revoked after the grant" from these stamps without raw SQL.
    assert (old.revoked_at, new.created_at, new.revoked_at) == (handover, handover, None)
    revoked_at = handover + timedelta(hours=1)
    admin.revoke_executor_key(owner, tenant, "executor-v2", actor, now=revoked_at)
    assert admin.list_executor_keys(owner, tenant)[1].revoked_at == revoked_at
    naive = datetime(2026, 9, 16, 12, 0)
    # The clock is resolved before any statement runs, so a naive one is refused as
    # configuration rather than reaching the column that would store it.
    for operation in (
        lambda: admin.register_executor_key(
            owner, tenant, "executor-v3", THIRD_KEY, actor, now=naive
        ),
        lambda: admin.rotate_executor_key(
            owner, tenant, "executor-v2", "executor-v3", THIRD_KEY, actor, now=naive
        ),
        lambda: admin.revoke_executor_key(owner, tenant, "executor-v2", actor, now=naive),
    ):
        with pytest.raises(admin.AdministrationError) as clock:
            operation()
        assert clock.value.code == "INVALID_CLOCK"
    assert [item.key_id for item in admin.list_executor_keys(owner, tenant)] == [
        "executor-v1",
        "executor-v2",
    ]


def test_executor_key_changes_wait_for_the_tenant_fence(owner, db, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    with ThreadPoolExecutor(max_workers=1) as pool:
        with db.transaction(tenant) as conn:
            conn.execute(
                text(
                    "SELECT tenant_id FROM execbound.tenant_policy_control "
                    "WHERE tenant_id=:t FOR UPDATE"
                ),
                {"t": tenant},
            ).one()
            registration = pool.submit(
                admin.register_executor_key, owner, tenant, "executor-v1", FIRST_KEY, actor
            )
            with pytest.raises(TimeoutError):
                registration.result(timeout=1.0)
        assert registration.result(timeout=10.0) is None
    assert [item.key_id for item in admin.list_executor_keys(owner, tenant)] == ["executor-v1"]


def test_executor_key_commands_through_the_cli(owner, cli_env, world, monkeypatch, capsys):
    tenant = str(world["identity"].tenant_id)
    actor = str(world["admin"].principal_id)
    registered = run(
        monkeypatch,
        capsys,
        "executor-key-register",
        "--tenant",
        tenant,
        "--key-id",
        "executor-v1",
        "--public-key",
        FIRST_KEY,
        "--actor",
        actor,
    )
    assert registered == {"key_id": "executor-v1", "registered": True}
    listed = run(monkeypatch, capsys, "executor-key-list", "--tenant", tenant)
    assert [(item["key_id"], item["public_key"], item["revoked_at"]) for item in listed] == [
        ("executor-v1", FIRST_KEY, None)
    ]
    rotated = run(
        monkeypatch,
        capsys,
        "executor-key-rotate",
        "--tenant",
        tenant,
        "--key-id",
        "executor-v1",
        "--new-key-id",
        "executor-v2",
        "--public-key",
        SECOND_KEY,
        "--actor",
        actor,
    )
    assert rotated == {"key_id": "executor-v2", "previous_key_id": "executor-v1", "rotated": True}
    # A provisioning command answers with identifiers alone; only the list reads key material.
    assert FIRST_KEY not in json.dumps(registered) and SECOND_KEY not in json.dumps(rotated)
    listed = run(monkeypatch, capsys, "executor-key-list", "--tenant", tenant)
    assert [(item["key_id"], item["public_key"]) for item in listed] == [
        ("executor-v1", FIRST_KEY),
        ("executor-v2", SECOND_KEY),
    ]
    assert listed[0]["revoked_at"] is not None and listed[1]["revoked_at"] is None
    revoked = run(
        monkeypatch,
        capsys,
        "executor-key-revoke",
        "--tenant",
        tenant,
        "--key-id",
        "executor-v2",
        "--actor",
        actor,
    )
    assert revoked == {"key_id": "executor-v2", "revoked": True}
    assert all(
        item["revoked_at"] is not None
        for item in run(monkeypatch, capsys, "executor-key-list", "--tenant", tenant)
    )
    run(
        monkeypatch,
        capsys,
        "executor-key-register",
        "--tenant",
        tenant,
        "--key-id",
        "executor-v3",
        "--public-key",
        THIRD_KEY,
        "--actor",
        actor,
    )
    # A separate command, because it is a separate act: an operator cutting off a stolen
    # key cannot reach an ordinary retirement by leaving a flag off, or the reverse.
    compromised = run(
        monkeypatch,
        capsys,
        "executor-key-compromise",
        "--tenant",
        tenant,
        "--key-id",
        "executor-v3",
        "--actor",
        actor,
    )
    assert compromised == {"key_id": "executor-v3", "compromised": True}
    assert [
        (item["key_id"], item["revocation_reason"])
        for item in run(monkeypatch, capsys, "executor-key-list", "--tenant", tenant)
    ] == [("executor-v1", "RETIRED"), ("executor-v2", "RETIRED"), ("executor-v3", "COMPROMISED")]
    malformed = "nothex" * 10 + "abcd"
    result = refused(
        monkeypatch,
        capsys,
        "executor-key-register",
        "--tenant",
        tenant,
        "--key-id",
        "executor-v3",
        "--public-key",
        malformed,
        "--actor",
        actor,
    )
    assert "Administration refused: INVALID_KEY." in result.err and malformed not in result.err


def test_executor_key_register_from_a_file_through_the_cli(
    owner, cli_env, world, monkeypatch, capsys, tmp_path
):
    tenant = str(world["identity"].tenant_id)
    actor = str(world["admin"].principal_id)
    es256_public = ec.generate_private_key(ec.SECP256R1()).public_key()
    pem_file = tmp_path / "es256.pem"
    pem_file.write_text(
        es256_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    )
    registered = run(
        monkeypatch,
        capsys,
        "executor-key-register",
        "--tenant",
        tenant,
        "--key-id",
        "executor-es256",
        "--public-key-file",
        str(pem_file),
        "--algorithm",
        "ES256",
        "--actor",
        actor,
    )
    assert registered == {"key_id": "executor-es256", "registered": True}
    compressed = es256_public.public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex()
    listed = {
        item["key_id"]: item
        for item in run(monkeypatch, capsys, "executor-key-list", "--tenant", tenant)
    }
    assert listed["executor-es256"]["algorithm"] == "ES256"
    assert listed["executor-es256"]["public_key"] == compressed

    # A key file normally ends in a newline, which the raw hex shape check would otherwise
    # refuse; the CLI strips the file's content before handing it to registration.
    hex_file = tmp_path / "ed25519.hex"
    hex_file.write_text(FIRST_KEY + "\n")
    registered_hex = run(
        monkeypatch,
        capsys,
        "executor-key-register",
        "--tenant",
        tenant,
        "--key-id",
        "executor-v1",
        "--public-key-file",
        str(hex_file),
        "--actor",
        actor,
    )
    assert registered_hex == {"key_id": "executor-v1", "registered": True}
    listed = {
        item["key_id"]: item
        for item in run(monkeypatch, capsys, "executor-key-list", "--tenant", tenant)
    }
    assert listed["executor-v1"]["algorithm"] == "ED25519"
    assert listed["executor-v1"]["public_key"] == FIRST_KEY

    # A missing key file is a clean refusal, not a raw traceback out of the CLI.
    missing = tmp_path / "missing.pem"
    result = refused(
        monkeypatch,
        capsys,
        "executor-key-register",
        "--tenant",
        tenant,
        "--key-id",
        "executor-missing",
        "--public-key-file",
        str(missing),
        "--actor",
        actor,
    )
    assert "Administration refused: INVALID_KEY." in result.err
    assert "Traceback" not in result.err


def test_runtime_role_cannot_provision_executor_keys(seeded):
    engine = admin.owner_engine(os.environ["TEST_DATABASE_URL"])
    tenant, actor = seeded["tenants"][0], uuid4()
    try:
        # Every key is well formed, so the refusal is the connection and nothing else.
        for operation in (
            lambda: admin.register_executor_key(engine, tenant, "executor-v1", FIRST_KEY, actor),
            lambda: admin.rotate_executor_key(
                engine, tenant, "executor-v1", "executor-v2", SECOND_KEY, actor
            ),
            lambda: admin.revoke_executor_key(engine, tenant, "executor-v1", actor),
            lambda: admin.report_executor_key_compromise(engine, tenant, "executor-v1", actor),
            lambda: admin.list_executor_keys(engine, tenant),
        ):
            with pytest.raises(admin.AdministrationError) as caught:
                operation()
            assert caught.value.code == "INVALID_CONNECTION"
    finally:
        engine.dispose()


def test_runtime_role_cannot_use_the_owner_operations(seeded):
    engine = admin.owner_engine(os.environ["TEST_DATABASE_URL"])
    tenant, actor, group, principal = seeded["tenants"][0], uuid4(), uuid4(), uuid4()
    try:
        for operation in (
            lambda: admin.create_tenant(engine, "Runtime"),
            lambda: admin.create_group(engine, tenant, "triage", actor),
            lambda: admin.assign_group(engine, tenant, group, principal, actor),
            lambda: admin.unassign_group(engine, tenant, group, principal, actor),
            lambda: admin.list_groups(engine, tenant),
        ):
            with pytest.raises(admin.AdministrationError) as caught:
                operation()
            assert caught.value.code == "INVALID_CONNECTION"
    finally:
        engine.dispose()


def test_bundle_preview_reports_changed_decisions_without_writes(
    owner, cli_env, db, world, runtime, admin_engine, monkeypatch, capsys, tmp_path
):
    from test_replay_export import fingerprint

    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    pending = runtime.execute(world["identity"], request(world).model_dump_json().encode())
    assert pending.state == "PENDING_APPROVAL"
    candidate = world["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": "forbid(principal, action, resource);",
        }
    )
    create_bundle(db, world["admin"], candidate, world["clock"])
    credential_file = tmp_path / "admin.token"
    admin.issue_credential(
        owner, tenant, actor, actor, lifetime=timedelta(hours=1), output=credential_file
    )
    before = fingerprint(admin_engine)
    preview = run(
        monkeypatch,
        capsys,
        "bundle-preview",
        "--tenant",
        str(tenant),
        "--credential-file",
        str(credential_file),
        "--bundle",
        str(candidate.bundle_id),
    )
    assert preview["state"] == "DRAFT" and preview["window_seconds"] == 24 * 3600
    # A workspace-wide administrator's preview counts the whole workspace, and says so.
    assert preview["scope"] == "workspace"
    assert preview["considered"] == 1
    assert preview["complete"] is True, preview["issues"]
    [changed] = preview["changed"]
    assert changed["execution_id"] == str(pending.execution_id)
    assert changed["baseline_effect"] == "REQUIRE_APPROVAL"
    assert changed["candidate_effect"] == "DENY"
    assert preview["baseline_effects"] == {"REQUIRE_APPROVAL": 1}
    assert preview["candidate_effects"] == {"DENY": 1}
    assert fingerprint(admin_engine) == before

    class Later:
        def __init__(self, value):
            self.value = value

        def now(self):
            return self.value

    later = preview_bundle(
        db,
        world["admin"],
        candidate.bundle_id,
        window=timedelta(minutes=1),
        clock=Later(world["clock"].now() + timedelta(minutes=10)),
    )
    assert later.considered == 0 and later.changed == ()
    with pytest.raises(PolicyStoreError) as too_wide:
        preview_bundle(db, world["admin"], candidate.bundle_id, window=timedelta(days=31))
    assert too_wide.value.code == "INVALID_WINDOW"
    with pytest.raises(PolicyStoreError) as unknown:
        preview_bundle(db, world["admin"], uuid4(), window=timedelta(hours=1))
    assert unknown.value.code == "INVALID_BUNDLE"
    with pytest.raises(PolicyStoreError) as agent:
        preview_bundle(db, world["identity"], candidate.bundle_id, window=timedelta(hours=1))
    assert agent.value.code == "INVALID_IDENTITY"
    assert fingerprint(admin_engine) == before


def test_bundle_preview_replays_a_group_rule_over_captured_membership(
    owner, cli_env, db, world, admin_engine, monkeypatch, capsys, tmp_path
):
    from test_execution import targets
    from test_replay_export import fingerprint

    from execbound.execution import admit

    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    triage = admin.create_group(owner, tenant, "triage", actor)
    admin.assign_group(owner, tenant, triage, world["identity"].principal_id, actor)
    # Two development isolations by the member reserve at once under the active pack;
    # each capture records the membership the kernel counted with.
    reserved = [
        admit(db, world["identity"], req, world["clock"]) for req in targets(admin_engine, world, 2)
    ]
    assert all(item.ticket is not None for item in reserved)
    candidate = world["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "limits": (
                *world["bundle"].limits,
                LimitRule(
                    rule_id="triage",
                    action="endpoint.isolate",
                    scope="group",
                    group_id=triage,
                    window_seconds=3600,
                    max_targets=1,
                    budget="total",
                    on_exceed="DENY",
                ),
            ),
        }
    )
    create_bundle(db, world["admin"], candidate, world["clock"])
    credential_file = tmp_path / "admin.token"
    admin.issue_credential(
        owner, tenant, actor, actor, lifetime=timedelta(hours=1), output=credential_file
    )
    before = fingerprint(admin_engine)
    preview = run(
        monkeypatch,
        capsys,
        "bundle-preview",
        "--tenant",
        str(tenant),
        "--credential-file",
        str(credential_file),
        "--bundle",
        str(candidate.bundle_id),
    )
    assert preview["considered"] == 2
    assert preview["complete"] is True, preview["issues"]
    assert preview["baseline_effects"] == {"ELIGIBLE": 2}
    assert preview["candidate_effects"] == {"DENY": 1, "ELIGIBLE": 1}
    changed = {item["execution_id"]: item for item in preview["changed"]}
    first, second = (changed[str(item.view.execution_id)] for item in reserved)
    # The first isolation only gains the group rule's count; the second is the group's
    # second unit and is denied on the recorded membership, with nothing unknown: every
    # capture on this database carries the groups the kernel read.
    assert first["candidate_effect"] == "ELIGIBLE" and "EFFECT" not in first["differences"]
    assert second["candidate_effect"] == "DENY"
    assert second["candidate_reasons"] == ["HARD_LIMIT:triage"]
    assert all(
        "UNKNOWN_GROUP_MEMBERSHIP" not in item["candidate_reasons"] for item in preview["changed"]
    )
    assert fingerprint(admin_engine) == before


def test_administration_events_keep_replay_complete(owner, db, world, tmp_path):
    from execbound.replay.export import export_history
    from execbound.replay.simulate import simulate
    from execbound.replay.verify import verify_export

    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    approver = world["human"].principal_id
    issued = admin.issue_credential(
        owner, tenant, actor, actor, lifetime=timedelta(hours=1), output=tmp_path / "t"
    )
    admin.revoke_credential(owner, tenant, issued.credential_id, actor)
    admin.create_principal(owner, tenant, "AGENT", actor=actor)
    admin.unassign_approver(owner, tenant, approver, world["canonical"], "endpoint.isolate", actor)
    admin.assign_approver(owner, tenant, approver, world["canonical"], "endpoint.isolate", actor)
    group = admin.create_group(owner, tenant, "triage", actor)
    admin.assign_group(owner, tenant, group, world["identity"].principal_id, actor)
    admin.unassign_group(owner, tenant, group, world["identity"].principal_id, actor)
    admin.register_executor_key(owner, tenant, "executor-v1", FIRST_KEY, actor)
    admin.rotate_executor_key(owner, tenant, "executor-v1", "executor-v2", SECOND_KEY, actor)
    admin.revoke_executor_key(owner, tenant, "executor-v2", actor)
    admin.register_executor_key(owner, tenant, "executor-v3", THIRD_KEY, actor)
    admin.report_executor_key_compromise(owner, tenant, "executor-v3", actor)

    from execbound import provisioning

    account = admin.create_account(owner, tenant, "mock_entra", actor)
    admin.create_mapping(owner, tenant, account, "identity.disable", actor)
    admin.create_target(owner, tenant, actor)
    source = provisioning.create_context_source(
        owner, tenant, account, "inventory", ["inventory_sync"], actor
    )
    admin.create_resource(owner, tenant, account, "identity", "user-01", source, actor)
    history = export_history(db, world["admin"], world["clock"])
    kinds = {event.kind for event in history.events}
    assert {"credential.issued", "credential.revoked", "principal.created"} <= kinds
    assert {"approval_scope.assigned", "approval_scope.revoked"} <= kinds
    assert {"group.created", "group.assigned", "group.revoked"} <= kinds
    assert {
        "executor_key.registered",
        "executor_key.rotated",
        "executor_key.revoked",
        "executor_key.compromised",
    } <= kinds
    assert {"account.created", "mapping.created", "target.created", "resource.created"} <= kinds
    # Pinned shapes, because an export carries whatever the payload holds and public_key is
    # not in the verifier's forbidden-key list: a later change that put key material in a
    # payload would ship it into every export unchallenged.
    assert [
        (event.kind, set(event.payload))
        for event in history.events
        if event.kind.startswith("executor_key.")
    ] == [
        ("executor_key.registered", {"key_id", "algorithm"}),
        ("executor_key.rotated", {"key_id", "previous_key_id", "algorithm"}),
        ("executor_key.revoked", {"key_id"}),
        ("executor_key.registered", {"key_id", "algorithm"}),
        ("executor_key.compromised", {"key_id"}),
    ]
    assert not any(
        material in str(dict(event.payload))
        for event in history.events
        for material in (FIRST_KEY, SECOND_KEY, THIRD_KEY)
    )
    report = simulate(verify_export(history, history.head))
    assert report.complete, report.issues


# The bootstrap: a person by address with a set-password code, over the owner connection.


def test_person_invite_creates_the_first_administrator_and_writes_one_code(
    owner, admin_engine, db, tmp_path
):
    """This is the whole point of the command: an operator holding the owner connection and
    no credential gives themselves an administrator and a code, then signs in like anybody."""
    tenant = admin.create_tenant(owner, "Bootstrap tenant")
    output = tmp_path / "admin.code"
    invited = admin.invite_person(
        owner,
        tenant,
        "  Owner@Example.COM ",
        "ADMIN",
        label="The owner",
        origin="https://app.example.com",
        output=output,
    )
    assert invited.created is True
    assert invited.kind == "ADMIN"
    assert invited.email == "owner@example.com"
    assert invited.address == "https://app.example.com/set-password"
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
    code = output.read_text(encoding="utf-8").strip()
    assert code.startswith(f"ebp1.{tenant}.{invited.reset_id}.")
    # The code is in the file and nowhere in what the command reports.
    assert code not in json.dumps({**vars(invited), "output": str(output)}, default=str)
    kinds = audit_kinds(admin_engine, tenant)
    assert kinds == [
        "principal.created",
        "person.email_set",
        "principal.labelled",
        "password.reset_issued",
    ]

    redeem_reset(db, code, "a decent passphrase")
    identity = sign_in_with_password(db, "owner@example.com", "a decent passphrase")
    assert identity.principal_id == invited.principal_id
    assert identity.kind == "ADMIN"


def test_person_invite_finds_the_person_again_and_replaces_the_pending_code(
    owner, admin_engine, db, tmp_path
):
    tenant = admin.create_tenant(owner, "Second tenant")
    first = admin.invite_person(
        owner,
        tenant,
        "owner@example.com",
        "ADMIN",
        origin="https://app.example.com",
        output=tmp_path / "one.code",
    )
    again = admin.invite_person(
        owner,
        tenant,
        "Owner@example.com",
        "ADMIN",
        actor=first.principal_id,
        origin="https://app.example.com",
        output=tmp_path / "two.code",
    )
    assert again.created is False
    assert again.principal_id == first.principal_id
    with pytest.raises(PasswordError) as refused_first:
        redeem_reset(db, (tmp_path / "one.code").read_text().strip(), "a decent passphrase")
    assert refused_first.value.code == "INVALID_RESET"
    assert redeem_reset(db, (tmp_path / "two.code").read_text().strip(), "a decent passphrase")


def test_person_invite_needs_an_actor_once_a_tenant_has_an_administrator(
    owner, admin_engine, tmp_path
):
    tenant = admin.create_tenant(owner, "Third tenant")
    admin.invite_person(
        owner,
        tenant,
        "owner@example.com",
        "ADMIN",
        origin="https://app.example.com",
        output=tmp_path / "one.code",
    )
    with pytest.raises(admin.AdministrationError) as refused:
        admin.invite_person(
            owner,
            tenant,
            "second@example.com",
            "ADMIN",
            origin="https://app.example.com",
            output=tmp_path / "two.code",
        )
    assert refused.value.code == "INVALID_ACTOR"
    # And nothing was written: a code never outlives the row it belongs to.
    assert not (tmp_path / "two.code").exists()


def test_person_invite_refuses_an_address_another_tenant_holds(owner, admin_engine, tmp_path):
    first = admin.create_tenant(owner, "Fourth tenant")
    second = admin.create_tenant(owner, "Fifth tenant")
    admin.invite_person(
        owner,
        first,
        "owner@example.com",
        "ADMIN",
        origin="https://app.example.com",
        output=tmp_path / "one.code",
    )
    with pytest.raises(admin.AdministrationError) as refused:
        admin.invite_person(
            owner,
            second,
            "owner@example.com",
            "ADMIN",
            origin="https://app.example.com",
            output=tmp_path / "two.code",
        )
    assert refused.value.code == "EMAIL_TAKEN"
    assert not (tmp_path / "two.code").exists()


@pytest.mark.parametrize(
    ("email", "kind", "lifetime", "code"),
    [
        ("not-an-address", "ADMIN", timedelta(hours=24), "INVALID_EMAIL"),
        ("owner@example.com", "AGENT", timedelta(hours=24), "INVALID_KIND"),
        ("owner@example.com", "ADMIN", timedelta(minutes=30), "INVALID_LIFETIME"),
        ("owner@example.com", "ADMIN", timedelta(days=30), "INVALID_LIFETIME"),
    ],
)
def test_person_invite_refuses_bad_input_and_writes_nothing(
    owner, tmp_path, email, kind, lifetime, code
):
    tenant = admin.create_tenant(owner, f"Tenant {code} {lifetime}")
    output = tmp_path / f"{code}-{lifetime.total_seconds()}.code"
    with pytest.raises(admin.AdministrationError) as refused:
        admin.invite_person(
            owner,
            tenant,
            email,
            kind,
            lifetime=lifetime,
            origin="https://app.example.com",
            output=output,
        )
    assert refused.value.code == code
    assert not output.exists()


def test_person_invite_over_the_command_line_reports_identifiers_and_the_file(
    owner, monkeypatch, capsys, cli_env, tmp_path
):
    tenant = admin.create_tenant(owner, "Command tenant")
    output = tmp_path / "owner.code"
    answer = run(
        monkeypatch,
        capsys,
        "person-invite",
        "--tenant",
        str(tenant),
        "--email",
        "owner@example.com",
        "--kind",
        "ADMIN",
        "--label",
        "The owner",
        "--origin",
        "https://app.example.com",
        "--output",
        str(output),
    )
    assert answer["kind"] == "ADMIN"
    assert answer["email"] == "owner@example.com"
    assert answer["open"] == "https://app.example.com/set-password"
    assert answer["code_file"] == str(output)
    assert output.read_text(encoding="utf-8").strip() not in json.dumps(answer)


def space_events(engine, tenant, kind):
    """Every event of one kind with the space column it carries, newest last."""
    with engine.connect() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT payload, space_id FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND kind=:k ORDER BY sequence"
                ),
                {"t": tenant, "k": kind},
            ).mappings()
        ]


def test_space_lifecycle_through_the_owner_commands(owner, world, admin_engine):
    """SP14: an owner command writes the same event with the same payload as the console,
    so `execbound space-create` and the console are indistinguishable in the chain, except
    that the console's also names the credential that acted (`actor_credential_id`, a browser
    session's or a personal access token's) and an owner command, which acts over the owner
    connection with no credential, names none."""
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    listed = admin.list_spaces(owner, tenant)
    assert [item.name for item in listed] == ["Default"]
    assert listed[0].members == (world["human"].principal_id,)

    space = admin.create_space(owner, tenant, "Customer A", actor, detail="First customer")
    created = space_events(admin_engine, tenant, "space.created")
    assert created[-1]["payload"] == {
        "space_id": str(space),
        "name": "Customer A",
        "detail": True,
    }
    # The space travels on the row and never in the hashed payload's tenant identity.
    assert created[-1]["space_id"] == space

    for duplicate in ("Customer A", "  customer a  "):
        with pytest.raises(admin.AdministrationError) as taken:
            admin.create_space(owner, tenant, duplicate, actor)
        assert taken.value.code == "NAME_TAKEN"
    for name in ("", "n" * 81):
        with pytest.raises(admin.AdministrationError) as bad_name:
            admin.create_space(owner, tenant, name, actor)
        assert bad_name.value.code == "INVALID_NAME"

    admin.rename_space(owner, tenant, space, "Customer A2", actor)
    assert space_events(admin_engine, tenant, "space.renamed")[-1]["payload"] == {
        "space_id": str(space),
        "name": "Customer A2",
    }

    admin.assign_space(owner, tenant, space, world["human"].principal_id, "HUMAN_APPROVER", actor)
    assert space_events(admin_engine, tenant, "space.member_assigned")[-1]["payload"] == {
        "space_id": str(space),
        "principal_id": str(world["human"].principal_id),
        "role": "HUMAN_APPROVER",
    }
    admin.unassign_space(owner, tenant, space, world["human"].principal_id, actor)
    assert space_events(admin_engine, tenant, "space.member_unassigned")[-1]["payload"] == {
        "space_id": str(space),
        "principal_id": str(world["human"].principal_id),
    }

    admin.archive_space(owner, tenant, space, actor, "customer left")
    assert space_events(admin_engine, tenant, "space.archived")[-1]["payload"] == {
        "space_id": str(space),
        "reason": "customer left",
    }
    admin.unarchive_space(owner, tenant, space, actor, "customer returned")
    assert space_events(admin_engine, tenant, "space.unarchived")[-1]["payload"] == {
        "space_id": str(space),
        "reason": "customer returned",
    }
    assert [item.name for item in admin.list_spaces(owner, tenant)] == ["Customer A2", "Default"]


def test_space_commands_refuse_a_non_administrator_and_a_narrowed_one(owner, world):
    """Space administration is a **tenant** administrator's: an active ADMIN principal
    holding no membership at all."""
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    for impostor in (world["identity"].principal_id, world["human"].principal_id, uuid4()):
        with pytest.raises(admin.AdministrationError) as refused:
            admin.create_space(owner, tenant, "Customer B", impostor)
        assert refused.value.code == "INVALID_ACTOR"
    space = admin.create_space(owner, tenant, "Customer B", actor)
    # The last tenant administrator cannot be narrowed away, so the seat is refused.
    with pytest.raises(admin.AdministrationError) as last:
        admin.assign_space(owner, tenant, space, actor, "ADMIN", actor)
    assert last.value.code == "LAST_TENANT_ADMIN"
    # And an approver principal may never hold the ADMIN role in a space.
    with pytest.raises(admin.AdministrationError) as raised:
        admin.assign_space(owner, tenant, space, world["human"].principal_id, "ADMIN", actor)
    assert raised.value.code == "INVALID_ROLE"


def test_archiving_the_last_unarchived_space_is_refused(owner, world):
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    only = admin.list_spaces(owner, tenant)[0].space_id
    with pytest.raises(admin.AdministrationError) as refused:
        admin.archive_space(owner, tenant, only, actor, "closing")
    assert refused.value.code == "CONFLICT"
