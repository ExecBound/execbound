# SPDX-License-Identifier: AGPL-3.0-only
"""Pure command failure proofs: no live database, provider, or reused credentials."""

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from execbound.db import DormantGrantsRefused, UnsafeDatabaseRole, honour_claims
from execbound.identity import Identity
from execbound.monitoring import commands, worker
from execbound.monitoring.models import MonitorError, SourceGrant
from execbound.plugins import (
    PLUGIN_GRANTS_MISMATCH,
    PLUGIN_GRANTS_REFUSAL,
    RUNTIME_CHECK_REFUSAL,
)

OWNER_URL = "postgresql+psycopg://execbound_owner:test@127.0.0.1:55440/execbound"


@pytest.fixture
def command_context(tmp_path, monkeypatch):
    db = SimpleNamespace(
        engine=SimpleNamespace(
            url="postgresql+psycopg://execbound_app:test@127.0.0.1:55440/execbound"
        )
    )
    identity = Identity(uuid4(), uuid4(), uuid4(), "ADMIN", datetime.now(UTC) + timedelta(hours=8))
    output = tmp_path / "private.json"
    state = {"committed": False, "statements": []}

    class Owner:
        @contextmanager
        def begin(self):
            if state.get("before_begin"):
                state["before_begin"]()
            yield self
            state["committed"] = True

        def execute(self, statement, values):
            state["statements"].append((str(statement), values))

        def dispose(self):
            pass

    def authenticated(runtime, token):
        tenant, credential = (UUID(value) for value in token.split(".")[1:3])
        principal = next(
            values["p"]
            for sql, values in state["statements"]
            if "INSERT INTO execbound.principals" in sql
        )
        return Identity(tenant, principal, credential, "ADMIN", identity.expires_at)

    monkeypatch.setattr(commands, "create_engine", lambda *args, **kwargs: Owner())
    monkeypatch.setattr(commands, "authenticate", authenticated)
    monkeypatch.setattr(
        commands,
        "create_source",
        lambda runtime, admin, **kwargs: SourceGrant(
            admin.tenant_id, uuid4(), "source-secret-canary"
        ),
    )
    return db, identity, output, state


def recovery_directories(output):
    return list(output.parent.glob(f".{output.name}.recovery-*"))


def issue_source(db, identity, output):
    commands.create_source_file(
        db,
        identity,
        label="Synthetic",
        story_id="story-1",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        output=output,
    )


@pytest.mark.parametrize("limit", [0, -1, True, 51, 500, "2", 1.5])
@pytest.mark.parametrize("receiver", [None, object()])
def test_process_rejects_invalid_common_limit_before_any_stage(monkeypatch, limit, receiver):
    calls = []
    monkeypatch.setattr(worker, "evaluate_pending", lambda *a, **kw: calls.append("evaluate") or 0)
    monkeypatch.setattr(worker, "deliver_pending", lambda *a, **kw: calls.append("deliver") or 0)
    with pytest.raises(MonitorError) as exc:
        worker.process(object(), object(), receiver, limit=limit)
    assert exc.value.code == "INVALID_LIMIT"
    assert calls == []


@pytest.mark.parametrize("operation", ["init", "source"])
def test_existing_output_is_never_overwritten_or_provisioned(
    command_context, monkeypatch, operation
):
    db, identity, output, state = command_context
    output.write_text("existing-secret-canary", encoding="utf-8")
    monkeypatch.setattr(commands, "create_source", lambda *a, **kw: pytest.fail("must not issue"))
    with pytest.raises(FileExistsError):
        if operation == "init":
            commands.initialize_demo(db, OWNER_URL, output)
        else:
            issue_source(db, identity, output)
    assert output.read_text() == "existing-secret-canary"
    assert state["statements"] == []
    assert recovery_directories(output) == []


def test_init_durably_records_admin_recovery_before_attempting_database(command_context):
    db, identity, output, state = command_context

    def failure():
        recovery = recovery_directories(output)
        assert len(recovery) == 1
        pending = json.loads((recovery[0] / "admin-pending.json").read_text())
        assert pending["phase"] == "ADMIN_PROVISION_PENDING"
        assert pending["admin_token"].startswith("eb1." + pending["tenant_id"] + ".")
        assert pending["admin_principal_id"] and pending["admin_credential_id"]
        raise RuntimeError("database-secret-canary")

    state["before_begin"] = failure
    with pytest.raises(commands.ProvisioningError) as exc:
        commands.initialize_demo(db, OWNER_URL, output)
    assert exc.value.code == "RECOVERY_REQUIRED"
    assert "database-secret-canary" not in str(exc.value)
    assert output.exists()
    assert len(recovery_directories(output)) == 1


def test_init_postcommit_auth_failure_preserves_the_new_admin_credentials(
    command_context,
    monkeypatch,
):
    db, identity, output, state = command_context

    def fail_auth(*args):
        raise RuntimeError("authentication-secret-canary")

    monkeypatch.setattr(commands, "authenticate", fail_auth)
    with pytest.raises(commands.ProvisioningError) as exc:
        commands.initialize_demo(db, OWNER_URL, output)
    assert exc.value.code == "RECOVERY_REQUIRED"
    assert state["committed"]
    recovery = recovery_directories(output)[0]
    pending = json.loads((recovery / "admin-pending.json").read_text())
    assert pending["admin_token"]
    assert (recovery / "admin-committed.json").exists()
    assert not (recovery / "config-ready.json").exists()


@pytest.mark.parametrize("operation", ["init", "source"])
def test_final_file_write_failure_keeps_complete_issued_credentials(
    command_context,
    monkeypatch,
    operation,
):
    db, identity, output, state = command_context
    original = commands._flush_json

    def fail_final(handle, value):
        if handle.name == str(output):
            raise OSError("file-secret-canary")
        return original(handle, value)

    monkeypatch.setattr(commands, "_flush_json", fail_final)
    with pytest.raises(commands.ProvisioningError) as exc:
        if operation == "init":
            commands.initialize_demo(db, OWNER_URL, output)
        else:
            issue_source(db, identity, output)
    assert exc.value.code == "RECOVERY_REQUIRED"
    ready = json.loads((recovery_directories(output)[0] / "config-ready.json").read_text())
    assert ready["source_token"] == "source-secret-canary"
    assert ready["source_id"]
    if operation == "init":
        assert ready["admin_token"] and state["committed"]
    assert output.exists()


@pytest.mark.parametrize(
    "code",
    [
        "INVALID_INPUT",
        "INVALID_ADMIN",
        "SOURCE_CAPACITY",
        "SOURCE_EXISTS",
        "INVALID_SPACE",
        "SPACE_ARCHIVED",
    ],
)
def test_known_source_rejection_cleans_only_owned_empty_file_and_allows_retry(
    command_context,
    monkeypatch,
    code,
):
    db, identity, output, state = command_context

    def reject(*args, **kwargs):
        raise MonitorError(code)

    monkeypatch.setattr(commands, "create_source", reject)
    with pytest.raises(commands.ProvisioningError) as exc:
        issue_source(db, identity, output)
    assert exc.value.code == "NOT_PROVISIONED"
    assert not output.exists()
    assert (recovery_directories(output)[0] / "not-provisioned.json").exists()
    monkeypatch.setattr(
        commands,
        "create_source",
        lambda *args, **kwargs: SourceGrant(identity.tenant_id, uuid4(), "fresh-source-secret"),
    )
    issue_source(db, identity, output)
    assert json.loads(output.read_text())["source_token"] == "fresh-source-secret"
    assert len(recovery_directories(output)) == 2


def test_known_rejection_does_not_delete_a_now_nonempty_output(command_context, monkeypatch):
    db, identity, output, state = command_context

    def reject(*args, **kwargs):
        output.write_text("externally-written-secret", encoding="utf-8")
        raise MonitorError("INVALID_ADMIN")

    monkeypatch.setattr(commands, "create_source", reject)
    with pytest.raises(commands.ProvisioningError):
        issue_source(db, identity, output)
    assert output.read_text() == "externally-written-secret"


def test_uncertain_source_failure_retains_recovery_metadata(command_context, monkeypatch):
    db, identity, output, state = command_context

    def unknown(*args, **kwargs):
        raise MonitorError("MONITOR_UNAVAILABLE")

    monkeypatch.setattr(commands, "create_source", unknown)
    with pytest.raises(commands.ProvisioningError) as exc:
        issue_source(db, identity, output)
    assert exc.value.code == "RECOVERY_REQUIRED"
    assert output.exists()
    pending = json.loads((recovery_directories(output)[0] / "source-pending.json").read_text())
    assert pending["tenant_id"] == str(identity.tenant_id)
    assert pending["admin_principal_id"] == str(identity.principal_id)
    assert pending["story_id"] == "story-1" and pending["attempted_at"]
    assert pending["source_id"] is None and "source_token" not in pending


def test_grant_persistence_failure_retains_issued_source_selector(command_context, monkeypatch):
    db, identity, output, state = command_context
    original = commands._write_private_json

    def fail_ready(path, value):
        if path.name == "config-ready.json":
            raise OSError("disk-full-secret-canary")
        return original(path, value)

    monkeypatch.setattr(commands, "_write_private_json", fail_ready)
    with pytest.raises(commands.ProvisioningError) as exc:
        issue_source(db, identity, output)
    assert exc.value.code == "RECOVERY_REQUIRED"
    issued = json.loads((recovery_directories(output)[0] / "source-issued.json").read_text())
    assert issued["source_id"] and issued["story_id"] == "story-1"
    assert issued["admin_principal_id"] == str(identity.principal_id)


def test_success_publishes_only_after_recovery_copy_is_durable(command_context):
    db, identity, output, state = command_context
    commands.initialize_demo(db, OWNER_URL, output)
    final = json.loads(output.read_text())
    ready = json.loads((recovery_directories(output)[0] / "config-ready.json").read_text())
    assert final == ready
    assert final["source_token"] and final["admin_token"]
    assert state["committed"]


def test_demo_ports_are_arguments_so_two_runs_can_share_one_machine(command_context):
    db, _, output, _ = command_context
    commands.initialize_demo(db, OWNER_URL, output, gateway_port=8220, receiver_port=8221)
    config = json.loads(output.read_text())
    assert (config["gateway_port"], config["receiver_port"]) == (8220, 8221)


def test_default_demo_ports_are_unchanged(command_context):
    db, _, output, _ = command_context
    commands.initialize_demo(db, OWNER_URL, output)
    config = json.loads(output.read_text())
    assert (config["gateway_port"], config["receiver_port"]) == (
        commands.DEMO_GATEWAY_PORT,
        commands.DEMO_RECEIVER_PORT,
    )


@pytest.mark.parametrize(
    "ports",
    [
        (8120, 8120),
        (80, 8121),
        (8120, 65536),
        (8120, True),
        ("8120", 8121),
    ],
)
def test_invalid_demo_ports_are_refused_before_anything_is_written(command_context, ports):
    db, _, output, state = command_context
    gateway, receiver = ports
    with pytest.raises(ValueError):
        commands.initialize_demo(
            db, OWNER_URL, output, gateway_port=gateway, receiver_port=receiver
        )
    assert not output.exists()
    assert recovery_directories(output) == []
    assert state["statements"] == []


def test_dc17_the_commands_load_the_plugins_the_environment_names(monkeypatch, capsys):
    monkeypatch.setenv("EXECBOUND_PLUGINS", "no_such_plugin")
    monkeypatch.setattr("sys.argv", ["monitoring", "check-tines", "--env-file", "missing.env"])
    with pytest.raises(SystemExit) as exited:
        commands.main()
    assert exited.value.code == 2
    assert "Plugin refused: UNKNOWN_PLUGIN." in capsys.readouterr().err


def test_dc17_a_named_plugins_claims_are_honoured_before_any_command_runs(monkeypatch, capsys):
    from plugin_fixtures import install

    from execbound.db import honoured_claims

    install(monkeypatch, register=lambda registry: registry.claim("product_counts", {"SELECT"}))
    monkeypatch.setenv("EXECBOUND_PLUGINS", "sample_plugin")
    monkeypatch.setattr(commands.TinesConfig, "from_file", staticmethod(lambda path: None))
    # What the command itself finds when it runs, read there rather than after `main`
    # returns: `main` turns any exception into a generic exit, so the reading is recorded
    # inside and compared outside.
    seen = []

    def check_connection(config, client):
        seen.append(honoured_claims())
        return {"ok": True}

    monkeypatch.setattr(commands, "check_connection", check_connection)
    monkeypatch.setattr("sys.argv", ["monitoring", "check-tines", "--env-file", "unused.env"])
    commands.main()
    assert seen == [{"product_counts": frozenset({"SELECT"})}]


@pytest.mark.parametrize(
    ("honoured", "sentence"),
    [
        pytest.param({}, PLUGIN_GRANTS_REFUSAL, id="plugin-not-loaded"),
        pytest.param(
            {"product_counts": frozenset({"SELECT"})}, PLUGIN_GRANTS_MISMATCH, id="grants-missing"
        ),
    ],
)
def test_dc17_grants_present_or_missing_are_each_refused_with_their_own_sentence(
    tmp_path, monkeypatch, capsys, honoured, sentence
):
    """The database's grants are not what this process's plugins claim (#496): the monitoring
    commands refuse with the command line's sentence for the cause rather than their generic
    refusal, and still close the database."""
    honour_claims(honoured)
    closed = []

    def refused(db, token):
        raise DormantGrantsRefused("Unsafe dormant grants")

    monkeypatch.setattr(
        commands, "Database", lambda url: SimpleNamespace(close=lambda: closed.append(url))
    )
    monkeypatch.setattr(commands, "authenticate", refused)
    monkeypatch.setenv("DATABASE_URL", "unused")
    monkeypatch.delenv("EXECBOUND_PLUGINS", raising=False)
    credential_file = tmp_path / "admin.token"
    credential_file.write_text("unused", encoding="utf-8")
    argv = ["monitoring", "show-profile", "--credential-file", str(credential_file)]
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as exited:
        commands.main()
    assert exited.value.code == 2
    assert sentence in capsys.readouterr().err
    assert closed == ["unused"]


def test_any_other_runtime_check_refusal_reads_the_command_line_s_sentence(
    tmp_path, monkeypatch, capsys
):
    """A refusal of the runtime check that is not about grants, such as a database at another
    schema revision, prints the sentence `execbound` prints for it rather than the monitoring
    commands' generic refusal, and still closes the database."""
    closed = []

    def refused(db, token):
        raise UnsafeDatabaseRole("Database schema revision mismatch")

    monkeypatch.setattr(
        commands, "Database", lambda url: SimpleNamespace(close=lambda: closed.append(url))
    )
    monkeypatch.setattr(commands, "authenticate", refused)
    monkeypatch.setenv("DATABASE_URL", "unused")
    monkeypatch.delenv("EXECBOUND_PLUGINS", raising=False)
    credential_file = tmp_path / "admin.token"
    credential_file.write_text("unused", encoding="utf-8")
    argv = ["monitoring", "show-profile", "--credential-file", str(credential_file)]
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as exited:
        commands.main()
    assert exited.value.code == 2
    assert capsys.readouterr().err.splitlines()[0] == RUNTIME_CHECK_REFUSAL.strip()
    assert closed == ["unused"]
