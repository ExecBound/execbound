# SPDX-License-Identifier: AGPL-3.0-only
"""The boot module turns environment-supplied private material into files, provisions a
mock store, scrubs the environment and execs the real process without a shell."""

import base64
import io
import json
import logging
import os
import re
import sqlite3
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from plugin_fixtures import sample as sample

from execbound import boot, logging_schema
from execbound.provider.identity_store import IdentityStore
from execbound.provider.mock_store import MockStore

TENANT = uuid4()
ACCOUNT = uuid4()


@pytest.fixture(autouse=True)
def keep_umask():
    previous = os.umask(0o022)
    os.umask(previous)
    yield
    os.umask(previous)


@pytest.fixture
def environment(tmp_path):
    return {
        "EXECBOUND_BOOT_DIR": str(tmp_path / "boot"),
        "EXECBOUND_RUNTIME_CONFIG": str(tmp_path / "gateway.json"),
        "EXECBOUND_RUNTIME_CONFIG_JSON": json.dumps({"origin": "https://gateway.example"}),
        "EXECBOUND_MOCK_ACCOUNTS_PATH": str(tmp_path / "accounts.json"),
        "EXECBOUND_MOCK_ACCOUNTS_JSON": json.dumps([{"tenant_id": str(TENANT)}]),
        "SUPABASE_CA_B64": base64.b64encode(b"-----BEGIN CERTIFICATE-----\n").decode(),
        "EXECBOUND_ADMIN_TOKEN": "token-" * 5,
        "EXECBOUND_TENANT_ID": str(TENANT),
        "PATH": "/opt/execbound/bin",
    }


def capture():
    calls = []

    def execute(program, arguments):
        calls.append((program, list(arguments)))

    return calls, execute


@pytest.fixture
def captured():
    stream = io.StringIO()
    handler = logging_schema.capture_handler(stream)
    logger = logging.getLogger("execbound")
    logger.addHandler(handler)
    try:
        yield stream
    finally:
        logger.removeHandler(handler)


def logged(stream, name):
    return [
        json.loads(line)
        for line in stream.getvalue().splitlines()
        if line and json.loads(line)["event"] == name
    ]


def resources(*provider_ids, **flags):
    return json.dumps(
        [
            {
                "tenant_id": str(TENANT),
                "account_id": str(ACCOUNT),
                "provider_id": provider_id,
                "canonical_target_id": str(uuid4()),
                "version": "resource-v1",
                **flags,
            }
            for provider_id in provider_ids
        ]
    )


def test_materializes_files_expands_arguments_and_scrubs_the_environment(environment, tmp_path):
    calls, execute = capture()
    boot.run(
        [
            "execbound",
            "recover",
            "--tenant",
            "$EXECBOUND_TENANT_ID",
            "--dir",
            "${EXECBOUND_BOOT_DIR}",
        ],
        environment,
        execute=execute,
    )
    directory = tmp_path / "boot"
    assert (directory / "supabase-ca.crt").read_bytes() == b"-----BEGIN CERTIFICATE-----\n"
    assert json.loads((tmp_path / "gateway.json").read_text()) == {
        "origin": "https://gateway.example"
    }
    assert json.loads((tmp_path / "accounts.json").read_text()) == [{"tenant_id": str(TENANT)}]
    assert (directory / "admin.token").read_bytes() == b"token-token-token-token-token-\n"
    assert json.loads((directory / "monitor.json").read_text()) == {"admin_token": "token-" * 5}
    if sys.platform != "win32":
        for name in ("supabase-ca.crt", "admin.token", "monitor.json"):
            assert oct((directory / name).stat().st_mode & 0o777) == "0o600"
        assert oct((tmp_path / "gateway.json").stat().st_mode & 0o777) == "0o600"
    assert calls == [
        (
            "execbound",
            ["execbound", "recover", "--tenant", str(TENANT), "--dir", str(directory)],
        )
    ]
    for name in boot.CONSUMED:
        assert name not in environment
    assert environment["EXECBOUND_TENANT_ID"] == str(TENANT)
    assert environment["EXECBOUND_RUNTIME_CONFIG"] == str(tmp_path / "gateway.json")


def test_the_owner_connection_never_reaches_the_process_it_starts(environment, tmp_path):
    """The gateway's container carries the schema owner's URL and its server must not.

    The Community compose file gives the gateway service `MIGRATION_DATABASE_URL` so that a
    one-off `docker compose run` can apply migrations and administer the deployment. The
    long-running gateway is started through this module for exactly this reason: the process
    that answers requests from the network is handed an environment without it. Unlike
    everything in `CONSUMED`, it is written nowhere first.
    """
    calls, execute = capture()
    environment["MIGRATION_DATABASE_URL"] = "postgresql+psycopg://owner:secret@127.0.0.1/execbound"
    boot.run(["uvicorn", "execbound.app:create_app"], environment, execute=execute)
    assert "MIGRATION_DATABASE_URL" in boot.WITHHELD
    assert "MIGRATION_DATABASE_URL" not in environment
    assert not (tmp_path / "boot").joinpath("migration.url").exists()
    assert calls == [("uvicorn", ["uvicorn", "execbound.app:create_app"])]


def test_rewrites_files_on_restart(environment, tmp_path):
    _, execute = capture()
    boot.run(["uvicorn"], environment.copy(), execute=execute)
    environment["EXECBOUND_RUNTIME_CONFIG_JSON"] = json.dumps({"origin": "https://second.example"})
    boot.run(["uvicorn"], environment, execute=execute)
    assert json.loads((tmp_path / "gateway.json").read_text()) == {
        "origin": "https://second.example"
    }


def test_provisions_the_endpoint_mock_store_idempotently(tmp_path):
    store_path = tmp_path / "endpoint.sqlite"
    environment = {
        "EXECBOUND_BOOT_DIR": str(tmp_path / "boot"),
        "EXECBOUND_MOCK_PROVIDER": "mock_crowdstrike",
        "EXECBOUND_MOCK_DATABASE_PATH": str(store_path),
        "EXECBOUND_MOCK_RESOURCES_JSON": resources("workstation-01", "workstation-02"),
    }
    entries = json.loads(environment["EXECBOUND_MOCK_RESOURCES_JSON"])
    _, execute = capture()
    assert boot.run(["uvicorn"], environment.copy(), execute=execute) == 2
    assert boot.run(["uvicorn"], environment, execute=execute) == 2
    store = MockStore(store_path)
    for entry in entries:
        resource = store.resource(TENANT, UUID(entry["canonical_target_id"]))
        assert resource is not None
        assert resource.version == "resource-v1"
        assert resource.contained is False
    with sqlite3.connect(store_path) as connection:
        rows = connection.execute(
            "SELECT resource_provider_id, canonical_target_id FROM representations ORDER BY 1"
        ).fetchall()
    assert rows == [(entry["provider_id"], entry["canonical_target_id"]) for entry in entries]


def test_a_restart_keeps_what_the_mock_changed(tmp_path):
    """Booting twice with the same file must not undo what the mock did in between (#350).

    This is the whole defect at the level it bit: every start re-provisioned, so a
    contained endpoint read as uncontained again and its version went back to the seeded
    one while the gateway's inventory expected the receipt's. The second `boot.run` here
    is the restart.
    """
    store_path = tmp_path / "endpoint.sqlite"
    environment = {
        "EXECBOUND_BOOT_DIR": str(tmp_path / "boot"),
        "EXECBOUND_MOCK_PROVIDER": "mock_crowdstrike",
        "EXECBOUND_MOCK_DATABASE_PATH": str(store_path),
        "EXECBOUND_MOCK_RESOURCES_JSON": resources("workstation-01"),
    }
    canonical = UUID(
        json.loads(environment["EXECBOUND_MOCK_RESOURCES_JSON"])[0]["canonical_target_id"]
    )
    _, execute = capture()
    boot.run(["uvicorn"], environment.copy(), execute=execute)
    store = MockStore(store_path)
    store.reprovision_resource(TENANT, canonical, "acted-v2", contained=True)

    boot.run(["uvicorn"], environment.copy(), execute=execute)

    kept = store.resource(TENANT, canonical)
    assert kept is not None and kept.version == "acted-v2" and kept.contained


def test_reprovision_resets_one_target_and_a_stated_version_touches_nothing_else(
    tmp_path, captured
):
    """The operator's repair: exactly one target, and the flags survive a version change.

    A stranded target needs the version the inventory expects while keeping the
    containment it legitimately holds, so `--version` is deliberately narrower than a
    reset to the file: resetting `contained` from the file would contradict the audit
    chain again, which is the defect this command exists to repair.
    """
    store_path = tmp_path / "endpoint.sqlite"
    environment = {
        "EXECBOUND_BOOT_DIR": str(tmp_path / "boot"),
        "EXECBOUND_MOCK_PROVIDER": "mock_crowdstrike",
        "EXECBOUND_MOCK_DATABASE_PATH": str(store_path),
        "EXECBOUND_MOCK_RESOURCES_JSON": resources("workstation-01", "workstation-02"),
    }
    entries = json.loads(environment["EXECBOUND_MOCK_RESOURCES_JSON"])
    first, second = (UUID(entry["canonical_target_id"]) for entry in entries)
    _, execute = capture()
    boot.run(["uvicorn"], environment.copy(), execute=execute)
    store = MockStore(store_path)
    store.reprovision_resource(TENANT, first, "drifted-v9", contained=True)
    untouched = store.resource(TENANT, second)

    moved = boot.reprovision(
        environment, "endpoint", TENANT, first, version="expected-v3", reason="stranded by #350"
    )

    repaired = store.resource(TENANT, first)
    assert repaired is not None and repaired.version == "expected-v3"
    assert repaired.contained, "a stated version must not undo a containment the mock holds"
    assert store.resource(TENANT, second) == untouched
    assert moved == {"from_version": "drifted-v9", "to_version": "expected-v3"}

    # What it says it did, in the closed log catalog and with no credential in it.
    [record] = logged(captured, "mock.reprovisioned")
    assert record["tenant_id"] == str(TENANT)
    assert record["canonical_target_id"] == str(first)
    assert record["from_version"] == "drifted-v9" and record["to_version"] == "expected-v3"
    assert record["reason"] == "stranded by #350"
    assert str(second) not in captured.getvalue(), "the other target is never named"

    # Without a version it is the file's values in full, containment included.
    boot.reprovision(environment, "endpoint", TENANT, first, reason="full reset")
    reset = store.resource(TENANT, first)
    assert reset is not None and reset.version == "resource-v1" and not reset.contained


def test_reprovision_refuses_a_target_the_mock_never_held(tmp_path):
    store_path = tmp_path / "endpoint.sqlite"
    environment = {
        "EXECBOUND_BOOT_DIR": str(tmp_path / "boot"),
        "EXECBOUND_MOCK_PROVIDER": "mock_crowdstrike",
        "EXECBOUND_MOCK_DATABASE_PATH": str(store_path),
        "EXECBOUND_MOCK_RESOURCES_JSON": resources("workstation-01"),
    }
    _, execute = capture()
    boot.run(["uvicorn"], environment.copy(), execute=execute)
    with pytest.raises(boot.BootError):
        boot.reprovision(environment, "endpoint", TENANT, uuid4(), version="v2")
    with pytest.raises(boot.BootError):
        boot.reprovision(environment, "nonsense", TENANT, uuid4(), version="v2")


def test_provisions_the_identity_mock_store_with_flags(tmp_path):
    store_path = tmp_path / "identity.sqlite"
    environment = {
        "EXECBOUND_BOOT_DIR": str(tmp_path / "boot"),
        "EXECBOUND_MOCK_PROVIDER": "mock_entra",
        "EXECBOUND_MOCK_DATABASE_PATH": str(store_path),
        "EXECBOUND_MOCK_RESOURCES_JSON": resources("identity-disabled", account_enabled=False),
    }
    entry = json.loads(environment["EXECBOUND_MOCK_RESOURCES_JSON"])[0]
    _, execute = capture()
    assert boot.run(["uvicorn"], environment, execute=execute) == 1
    identity = IdentityStore(store_path).resource(TENANT, UUID(entry["canonical_target_id"]))
    assert identity is not None
    assert identity.account_enabled is False


def test_an_empty_resources_list_provisions_nothing(tmp_path):
    environment = {
        "EXECBOUND_BOOT_DIR": str(tmp_path / "boot"),
        "EXECBOUND_MOCK_DATABASE_PATH": str(tmp_path / "endpoint.sqlite"),
        "EXECBOUND_MOCK_RESOURCES_JSON": "[]",
    }
    _, execute = capture()
    assert boot.run(["uvicorn"], environment, execute=execute) == 0


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"SUPABASE_CA_B64": "not base64!"}, "SUPABASE_CA_B64 is not base64"),
        ({"SUPABASE_CA_B64": ""}, None),
        (
            {"EXECBOUND_RUNTIME_CONFIG": ""},
            "EXECBOUND_RUNTIME_CONFIG_JSON needs EXECBOUND_RUNTIME_CONFIG",
        ),
        ({"EXECBOUND_RUNTIME_CONFIG_JSON": "{"}, "EXECBOUND_RUNTIME_CONFIG_JSON is not JSON"),
        ({"EXECBOUND_MOCK_ACCOUNTS_JSON": "nope"}, "EXECBOUND_MOCK_ACCOUNTS_JSON is not JSON"),
        ({"EXECBOUND_ADMIN_TOKEN": "has space"}, "EXECBOUND_ADMIN_TOKEN is not a token"),
        ({"EXECBOUND_ADMIN_TOKEN": "x" * 161}, "EXECBOUND_ADMIN_TOKEN is not a token"),
        (
            {"EXECBOUND_MOCK_RESOURCES_JSON": "{}", "EXECBOUND_MOCK_DATABASE_PATH": "x"},
            "EXECBOUND_MOCK_RESOURCES_JSON must be a list",
        ),
        (
            {"EXECBOUND_MOCK_RESOURCES_JSON": "[{}]", "EXECBOUND_MOCK_DATABASE_PATH": "x"},
            "entry 0 has the wrong keys",
        ),
        (
            {
                "EXECBOUND_MOCK_RESOURCES_JSON": json.dumps(
                    [
                        {
                            "tenant_id": "nope",
                            "account_id": str(ACCOUNT),
                            "provider_id": "w",
                            "canonical_target_id": str(uuid4()),
                            "version": "v",
                        }
                    ]
                ),
                "EXECBOUND_MOCK_DATABASE_PATH": "x",
            },
            "entry 0 has a malformed identifier",
        ),
        (
            {"EXECBOUND_MOCK_RESOURCES_JSON": "[]"},
            "EXECBOUND_MOCK_RESOURCES_JSON needs EXECBOUND_MOCK_DATABASE_PATH",
        ),
        (
            {
                "EXECBOUND_MOCK_RESOURCES_JSON": "[]",
                "EXECBOUND_MOCK_DATABASE_PATH": "x",
                "EXECBOUND_MOCK_PROVIDER": "real",
            },
            "EXECBOUND_MOCK_PROVIDER is not a mock provider",
        ),
    ],
)
def test_refuses_malformed_material_without_starting(environment, changes, message):
    environment.update(changes)
    calls, execute = capture()
    if message is None:
        boot.run(["uvicorn"], environment, execute=execute)
        assert calls
        return
    with pytest.raises(boot.BootError, match=re.escape(message)):
        boot.run(["uvicorn"], environment, execute=execute)
    assert calls == []


def test_refuses_an_unset_variable_and_a_missing_command(environment):
    calls, execute = capture()
    with pytest.raises(boot.BootError, match="MISSING is not set"):
        boot.run(["execbound", "--tenant", "$MISSING"], environment, execute=execute)
    with pytest.raises(boot.BootError, match="no command to start"):
        boot.run([], environment, execute=execute)
    assert calls == []


def test_main_reports_a_refusal_on_stderr_and_exits_two(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("EXECBOUND_BOOT_DIR", str(tmp_path))
    monkeypatch.setenv("SUPABASE_CA_B64", "***")
    with pytest.raises(SystemExit) as excinfo:
        boot.main(["uvicorn"])
    assert excinfo.value.code == 2
    assert capsys.readouterr().err.strip() == "boot: SUPABASE_CA_B64 is not base64"


def test_materializes_the_jobs_token_map_owner_only_and_scrubs_it(environment, tmp_path):
    tokens = {str(TENANT): "eb1." + "a" * 30, str(uuid4()): "eb1." + "b" * 30}
    environment["EXECBOUND_JOBS_TOKENS_JSON"] = json.dumps(tokens)
    calls, execute = capture()
    boot.run(
        ["execbound", "recover", "--tenants-file", "$EXECBOUND_BOOT_DIR"],
        environment,
        execute=execute,
    )
    written = Path(environment["EXECBOUND_BOOT_DIR"]) / "jobs.json"
    assert json.loads(written.read_text(encoding="ascii")) == tokens
    if sys.platform != "win32":
        assert (written.stat().st_mode & 0o777) == 0o600
    assert "EXECBOUND_JOBS_TOKENS_JSON" not in environment
    assert calls == [
        ("execbound", ["execbound", "recover", "--tenants-file", str(tmp_path / "boot")])
    ]


@pytest.mark.parametrize(
    "raw,message",
    [
        ("[1]", "EXECBOUND_JOBS_TOKENS_JSON must map 1 to 64 tenants"),
        ("{}", "EXECBOUND_JOBS_TOKENS_JSON must map 1 to 64 tenants"),
        ("not json", "EXECBOUND_JOBS_TOKENS_JSON is not JSON"),
        (json.dumps({"nope": "eb1.x"}), "EXECBOUND_JOBS_TOKENS_JSON has a malformed tenant id"),
        (
            json.dumps({str(TENANT).upper(): "eb1.x"}),
            "EXECBOUND_JOBS_TOKENS_JSON has a malformed tenant id",
        ),
        (
            json.dumps({str(TENANT): "with space"}),
            "EXECBOUND_JOBS_TOKENS_JSON has a malformed token",
        ),
        (json.dumps({str(TENANT): 7}), "EXECBOUND_JOBS_TOKENS_JSON has a malformed token"),
        (json.dumps({str(uuid4()): "x" * 161}), "EXECBOUND_JOBS_TOKENS_JSON has a malformed token"),
        (
            json.dumps({str(uuid4()): "x" for _ in range(65)}),
            "EXECBOUND_JOBS_TOKENS_JSON must map 1 to 64 tenants",
        ),
    ],
    # Fixed ids: the values embed identifiers generated at import, and the evidence step
    # matches collected node ids against the junit run's, which is another process.
    ids=[
        "list",
        "empty",
        "not-json",
        "bad-key",
        "uppercase-key",
        "space-in-token",
        "number-token",
        "long-token",
        "too-many",
    ],
)
def test_refuses_a_malformed_jobs_token_map(environment, raw, message):
    environment["EXECBOUND_JOBS_TOKENS_JSON"] = raw
    calls, execute = capture()
    with pytest.raises(boot.BootError, match=re.escape(message)):
        boot.run(["uvicorn"], environment, execute=execute)
    assert calls == []
    assert not (Path(environment["EXECBOUND_BOOT_DIR"]) / "jobs.json").exists()


# A key file's contents no message, file name or log line may repeat.
KEY_SENTINEL = "TINES_API_KEY=SENTINEL-boot-key-file-4b81"
CONNECTION = UUID("0f9d2c1e-5b6a-4c3d-8e7f-a1b2c3d4e5f6")


def test_mc7_writes_the_collectors_key_files_owner_only_and_scrubs_them(environment, tmp_path):
    """One `<connection id>.env` per entry, in the boot directory's `key-files`, where
    `collect-due --key-files` reads them."""
    other = uuid4()
    files = {
        str(CONNECTION): "TINES_BASE_URL=https://fixture.tines.com\n" + KEY_SENTINEL + "\n",
        str(other): "ENTRA_DIRECTORY_ID=d\nENTRA_CLIENT_ID=c\nENTRA_CLIENT_SECRET=s\n",
    }
    environment["EXECBOUND_COLLECTOR_KEY_FILES_JSON"] = json.dumps(files)
    calls, execute = capture()
    boot.run(
        ["python", "-m", "execbound.monitoring.commands", "collect-due"],
        environment,
        execute=execute,
    )
    directory = Path(environment["EXECBOUND_BOOT_DIR"]) / "key-files"
    assert sorted(path.name for path in directory.iterdir()) == sorted(
        f"{name}.env" for name in files
    )
    for name, contents in files.items():
        written = directory / f"{name}.env"
        assert written.read_text(encoding="ascii") == contents
        if sys.platform != "win32":
            assert (written.stat().st_mode & 0o777) == 0o600
    if sys.platform != "win32":
        assert (directory.stat().st_mode & 0o777) == 0o700
    assert "EXECBOUND_COLLECTOR_KEY_FILES_JSON" not in environment
    assert len(calls) == 1


@pytest.mark.parametrize(
    "raw,message",
    [
        ("not json", "EXECBOUND_COLLECTOR_KEY_FILES_JSON is not JSON"),
        ("[]", "EXECBOUND_COLLECTOR_KEY_FILES_JSON must map connection ids to key files"),
        ("{}", "EXECBOUND_COLLECTOR_KEY_FILES_JSON must map connection ids to key files"),
        (
            json.dumps({"../escape": KEY_SENTINEL}),
            "EXECBOUND_COLLECTOR_KEY_FILES_JSON has a malformed connection id",
        ),
        (
            json.dumps({str(CONNECTION).upper(): KEY_SENTINEL}),
            "EXECBOUND_COLLECTOR_KEY_FILES_JSON has a malformed connection id",
        ),
        (
            json.dumps({str(CONNECTION): 7}),
            "EXECBOUND_COLLECTOR_KEY_FILES_JSON has a malformed key file",
        ),
        (
            json.dumps({str(CONNECTION): ""}),
            "EXECBOUND_COLLECTOR_KEY_FILES_JSON has a malformed key file",
        ),
        (
            json.dumps({str(CONNECTION): KEY_SENTINEL + "\u00e9"}),
            "EXECBOUND_COLLECTOR_KEY_FILES_JSON has a malformed key file",
        ),
        (
            json.dumps({str(CONNECTION): KEY_SENTINEL + "\x00"}),
            "EXECBOUND_COLLECTOR_KEY_FILES_JSON has a malformed key file",
        ),
        (
            json.dumps({str(CONNECTION): "K" * 16385}),
            "EXECBOUND_COLLECTOR_KEY_FILES_JSON has a malformed key file",
        ),
    ],
    ids=[
        "not-json",
        "list",
        "empty",
        "path-key",
        "uppercase-key",
        "number",
        "empty-file",
        "not-ascii",
        "nul",
        "too-long",
    ],
)
def test_mc7_refuses_malformed_key_files_without_writing_or_printing_them(
    environment, raw, message, capsys
):
    environment["EXECBOUND_COLLECTOR_KEY_FILES_JSON"] = raw
    calls, execute = capture()
    with pytest.raises(boot.BootError, match=re.escape(message)) as refused:
        boot.run(["uvicorn"], environment, execute=execute)
    assert calls == []
    assert KEY_SENTINEL not in str(refused.value)
    assert not (Path(environment["EXECBOUND_BOOT_DIR"]) / "key-files").exists()
    # Nothing at all is written before the refusal, core's own files included.
    assert not Path(environment["EXECBOUND_RUNTIME_CONFIG"]).exists()


def collector_private(tmp_path):
    """A collector private key file's text, as `collector-keygen` writes it."""
    from execbound.monitoring import sealing

    sealing.generate(tmp_path / "collector")
    return (tmp_path / "collector" / sealing.PRIVATE_FILE).read_text(encoding="utf-8")


def test_mc3_writes_the_collectors_private_key_owner_only_and_scrubs_it(environment, tmp_path):
    """`EXECBOUND_COLLECTOR_KEY_JSON` becomes the boot directory's `collector-private.json`,
    where `collect-due --collector-key` reads it, and leaves the environment before the exec."""
    contents = collector_private(tmp_path)
    environment["EXECBOUND_COLLECTOR_KEY_JSON"] = contents
    calls, execute = capture()
    boot.run(
        ["python", "-m", "execbound.monitoring.commands", "collect-due"],
        environment,
        execute=execute,
    )
    written = Path(environment["EXECBOUND_BOOT_DIR"]) / "collector-private.json"
    assert json.loads(written.read_text(encoding="utf-8")) == json.loads(contents)
    if sys.platform != "win32":
        assert (written.stat().st_mode & 0o777) == 0o600
    assert "EXECBOUND_COLLECTOR_KEY_JSON" not in environment
    assert len(calls) == 1


def test_mc4_writes_the_collectors_previous_key_beside_its_current_one(environment, tmp_path):
    """During a rotation the collector's group carries the key being retired as well,
    `EXECBOUND_COLLECTOR_PREVIOUS_KEY_JSON`, which becomes `collector-previous.json` beside the
    current key, so `collect-due` opens a key sealed to either."""
    current = collector_private(tmp_path)
    previous = collector_private(tmp_path / "previous")
    environment["EXECBOUND_COLLECTOR_KEY_JSON"] = current
    environment["EXECBOUND_COLLECTOR_PREVIOUS_KEY_JSON"] = previous
    calls, execute = capture()
    boot.run(
        ["python", "-m", "execbound.monitoring.commands", "collect-due"],
        environment,
        execute=execute,
    )
    directory = Path(environment["EXECBOUND_BOOT_DIR"])
    for name, contents in (
        ("collector-private.json", current),
        ("collector-previous.json", previous),
    ):
        written = directory / name
        assert json.loads(written.read_text(encoding="utf-8")) == json.loads(contents)
        if sys.platform != "win32":
            assert (written.stat().st_mode & 0o777) == 0o600
    assert "EXECBOUND_COLLECTOR_KEY_JSON" not in environment
    assert "EXECBOUND_COLLECTOR_PREVIOUS_KEY_JSON" not in environment
    assert len(calls) == 1


@pytest.mark.parametrize(
    "variable,written",
    [
        ("EXECBOUND_COLLECTOR_KEY_JSON", "collector-private.json"),
        ("EXECBOUND_COLLECTOR_PREVIOUS_KEY_JSON", "collector-previous.json"),
    ],
)
@pytest.mark.parametrize(
    "case",
    ["not-json", "list", "missing", "extra", "short", "wrong-id", "duplicate"],
)
def test_mc3_refuses_a_malformed_collector_key_without_writing_or_printing_it(
    environment, tmp_path, case, variable, written
):
    document = json.loads(collector_private(tmp_path))
    secret = document["private_key"]
    raw = {
        "not-json": "not json " + secret,
        "list": json.dumps([secret]),
        "missing": json.dumps({"private_key": secret}),
        "extra": json.dumps({**document, "note": "x"}),
        "short": json.dumps({**document, "private_key": secret[:20]}),
        "wrong-id": json.dumps({**document, "key_id": "ck1-0000000000000000"}),
        # The collector reads its file refusing a repeated name, so boot does too: a document
        # boot wrote and the collector refused would stop every collection pass.
        "duplicate": (
            f'{{"key_id": {json.dumps(document["key_id"])}, '
            f'"private_key": {json.dumps(secret[:20])}, "private_key": {json.dumps(secret)}}}'
        ),
    }[case]
    environment[variable] = raw
    calls, execute = capture()
    with pytest.raises(boot.BootError, match=variable) as refused:
        boot.run(["uvicorn"], environment, execute=execute)
    assert calls == []
    assert secret not in str(refused.value) and secret[:20] not in str(refused.value)
    assert not (Path(environment["EXECBOUND_BOOT_DIR"]) / written).exists()
    assert not Path(environment["EXECBOUND_RUNTIME_CONFIG"]).exists()


MAIL = {
    "host": "smtp.gmail.com",
    "port": 465,
    "tls": "tls",
    "username": "operator@example.com",
    "from": "operator@example.com",
}
APP_PASSWORD = "abcd efgh ijkl mnop"


def test_the_mail_password_is_merged_from_its_own_variable_and_scrubbed(environment, tmp_path):
    environment["EXECBOUND_RUNTIME_CONFIG_JSON"] = json.dumps(
        {"origin": "https://gateway.example", "mail": MAIL}
    )
    environment["EXECBOUND_MAIL_PASSWORD"] = APP_PASSWORD
    _, execute = capture()
    boot.run(["uvicorn"], environment, execute=execute)
    written = json.loads((tmp_path / "gateway.json").read_text(encoding="utf-8"))
    assert written == {
        "origin": "https://gateway.example",
        "mail": MAIL | {"password": APP_PASSWORD},
    }
    assert "EXECBOUND_MAIL_PASSWORD" in boot.CONSUMED
    assert "EXECBOUND_MAIL_PASSWORD" not in environment
    assert "EXECBOUND_RUNTIME_CONFIG_JSON" not in environment


def test_the_mail_password_is_ignored_while_there_is_no_mail_block(environment, tmp_path):
    # Set before the operator adds the block, the variable changes nothing and is scrubbed.
    environment["EXECBOUND_MAIL_PASSWORD"] = APP_PASSWORD
    _, execute = capture()
    boot.run(["uvicorn"], environment, execute=execute)
    assert json.loads((tmp_path / "gateway.json").read_text(encoding="utf-8")) == {
        "origin": "https://gateway.example"
    }
    assert "EXECBOUND_MAIL_PASSWORD" not in environment


@pytest.mark.parametrize(
    ("config", "password", "message"),
    [
        (
            {"origin": "https://gateway.example", "mail": MAIL},
            None,
            "the mail block has no password; set EXECBOUND_MAIL_PASSWORD",
        ),
        (
            {"origin": "https://gateway.example", "mail": MAIL | {"password": "inline"}},
            APP_PASSWORD,
            "EXECBOUND_MAIL_PASSWORD and a password in the mail block; keep one",
        ),
        (
            {"origin": "https://gateway.example", "mail": MAIL},
            "line\nbreak",
            "EXECBOUND_MAIL_PASSWORD is not a password",
        ),
        (
            {"origin": "https://gateway.example", "mail": "not an object"},
            APP_PASSWORD,
            "the mail block is not an object",
        ),
    ],
)
def test_refuses_a_mail_block_it_cannot_complete(environment, config, password, message):
    environment["EXECBOUND_RUNTIME_CONFIG_JSON"] = json.dumps(config)
    if password is not None:
        environment["EXECBOUND_MAIL_PASSWORD"] = password
    calls, execute = capture()
    with pytest.raises(boot.BootError, match=re.escape(message)) as refused:
        boot.run(["uvicorn"], environment, execute=execute)
    assert calls == []
    assert APP_PASSWORD not in str(refused.value) and "inline" not in str(refused.value)


def test_a_duplicate_key_is_refused_before_the_merge_hides_it(environment):
    environment["EXECBOUND_RUNTIME_CONFIG_JSON"] = (
        '{"origin": "https://a.example", "origin": "https://b.example", "mail": {}}'
    )
    environment["EXECBOUND_MAIL_PASSWORD"] = APP_PASSWORD
    _, execute = capture()
    with pytest.raises(boot.BootError, match="EXECBOUND_RUNTIME_CONFIG_JSON has a duplicate key"):
        boot.run(["uvicorn"], environment, execute=execute)


ASSISTANT = {"model": "claude-sonnet-5", "person_hourly_turns": 5}
ASSISTANT_KEY = "sk-ant-" + "b" * 32


def test_the_assistant_key_is_merged_into_its_block_and_scrubbed(environment, tmp_path):
    environment["EXECBOUND_RUNTIME_CONFIG_JSON"] = json.dumps(
        {"origin": "https://gateway.example", "assistant": ASSISTANT}
    )
    environment["EXECBOUND_ASSISTANT_API_KEY"] = ASSISTANT_KEY
    _, execute = capture()
    boot.run(["uvicorn"], environment, execute=execute)
    written = json.loads((tmp_path / "gateway.json").read_text(encoding="utf-8"))
    assert written == {
        "origin": "https://gateway.example",
        "assistant": ASSISTANT | {"api_key": ASSISTANT_KEY},
    }
    assert "EXECBOUND_ASSISTANT_API_KEY" in boot.CONSUMED
    assert "EXECBOUND_ASSISTANT_API_KEY" not in environment


def test_the_assistant_key_is_ignored_while_there_is_no_assistant_block(environment, tmp_path):
    environment["EXECBOUND_ASSISTANT_API_KEY"] = ASSISTANT_KEY
    _, execute = capture()
    boot.run(["uvicorn"], environment, execute=execute)
    assert json.loads((tmp_path / "gateway.json").read_text(encoding="utf-8")) == {
        "origin": "https://gateway.example"
    }
    assert "EXECBOUND_ASSISTANT_API_KEY" not in environment


@pytest.mark.parametrize(
    ("config", "key", "message"),
    [
        (
            {"origin": "https://gateway.example", "assistant": ASSISTANT},
            None,
            "the assistant block has no api_key; set EXECBOUND_ASSISTANT_API_KEY",
        ),
        (
            {"origin": "https://gateway.example", "assistant": ASSISTANT | {"api_key": "in"}},
            ASSISTANT_KEY,
            "EXECBOUND_ASSISTANT_API_KEY and an api_key in the assistant block; keep one",
        ),
        (
            {"origin": "https://gateway.example", "assistant": ASSISTANT},
            "line\nbreak",
            "EXECBOUND_ASSISTANT_API_KEY is not a key",
        ),
        (
            {"origin": "https://gateway.example", "assistant": "not an object"},
            ASSISTANT_KEY,
            "the assistant block is not an object",
        ),
    ],
)
def test_an_assistant_block_without_its_key_refuses_to_start_naming_the_variable(
    environment, config, key, message
):
    environment["EXECBOUND_RUNTIME_CONFIG_JSON"] = json.dumps(config)
    if key is not None:
        environment["EXECBOUND_ASSISTANT_API_KEY"] = key
    _, execute = capture()
    with pytest.raises(boot.BootError) as refused:
        boot.run(["uvicorn"], environment, execute=execute)
    assert str(refused.value) == message
    assert ASSISTANT_KEY not in str(refused.value)


# A plugin's own boot files and variables, through the sample plugin's boot entry: core boot
# asks the plugin's hook before it writes anything, writes what the hook returns after its own
# files, and scrubs the plugin's consumed variables with its own before the exec.
SAMPLE_TOKEN = "sample-" * 4


def test_a_plugins_boot_files_are_written_and_its_variables_never_reach_the_process(
    environment, tmp_path, sample
):
    environment[sample.BOOT_TOKEN] = SAMPLE_TOKEN
    environment["MIGRATION_DATABASE_URL"] = "postgresql+psycopg://owner:secret@127.0.0.1/execbound"
    started = []

    def execute(program, arguments):
        # What the started process would inherit: the environment as it stands at the exec.
        started.append((program, list(arguments), dict(environment)))

    sample.boot_run(["uvicorn", "--tenant", "$EXECBOUND_TENANT_ID"], environment, execute=execute)
    directory = tmp_path / "boot"
    assert (directory / sample.BOOT_FILE).read_bytes() == (SAMPLE_TOKEN + "\n").encode()
    assert (directory / boot.CA_FILE).read_bytes() == b"-----BEGIN CERTIFICATE-----\n"
    assert (directory / boot.TOKEN_FILE).read_bytes() == b"token-token-token-token-token-\n"
    if sys.platform != "win32":
        assert oct((directory / sample.BOOT_FILE).stat().st_mode & 0o777) == "0o600"
    [(program, arguments, inherited)] = started
    assert (program, arguments) == ("uvicorn", ["uvicorn", "--tenant", str(TENANT)])
    # The variable this test set is named on its own, so the check does not rest on what the
    # sample declares it consumes.
    for name in (sample.BOOT_TOKEN, *boot.CONSUMED, *sample.BOOT_CONSUMED, *boot.WITHHELD):
        assert name not in inherited, name
    assert inherited["EXECBOUND_TENANT_ID"] == str(TENANT)
    assert inherited["PATH"] == "/opt/execbound/bin"


def test_a_plugins_bad_boot_material_refuses_before_core_writes_anything(
    environment, tmp_path, sample
):
    environment[sample.BOOT_TOKEN] = "private value"
    calls, execute = capture()
    with pytest.raises(boot.BootError) as refused:
        sample.boot_run(["uvicorn"], environment, execute=execute)
    assert str(refused.value) == f"{sample.BOOT_TOKEN} is not a token"
    assert calls == []
    assert not (tmp_path / "boot").exists()
    assert not (tmp_path / "gateway.json").exists()
    assert not (tmp_path / "accounts.json").exists()


def test_a_plugins_boot_files_wait_for_cores_own_material_to_be_written(
    environment, tmp_path, sample
):
    environment[sample.BOOT_TOKEN] = SAMPLE_TOKEN
    environment["SUPABASE_CA_B64"] = "not base64!"
    calls, execute = capture()
    with pytest.raises(boot.BootError, match="^SUPABASE_CA_B64 is not base64$"):
        sample.boot_run(["uvicorn"], environment, execute=execute)
    assert calls == []
    assert not (tmp_path / "boot" / sample.BOOT_FILE).exists()


def test_a_boot_hook_is_handed_the_runtime_configuration_core_writes(environment, tmp_path):
    """The hook reads the configuration core is about to write, with the mail password
    already merged into it, rather than the variable as it arrived."""
    environment["EXECBOUND_RUNTIME_CONFIG_JSON"] = json.dumps(
        {"origin": "https://gateway.example", "mail": MAIL}
    )
    environment["EXECBOUND_MAIL_PASSWORD"] = APP_PASSWORD
    seen = []

    def files(hook_environment, directory, runtime_document):
        seen.append((dict(hook_environment), directory, runtime_document))
        return []

    _, execute = capture()
    boot.run(["uvicorn"], environment, execute=execute, files=files)
    [(hook_environment, directory, runtime_document)] = seen
    assert directory == tmp_path / "boot"
    assert hook_environment["EXECBOUND_MAIL_PASSWORD"] == APP_PASSWORD
    assert runtime_document == (tmp_path / "gateway.json").read_bytes()
    assert json.loads(runtime_document)["mail"] == MAIL | {"password": APP_PASSWORD}


def platform_app_text() -> str:
    """The platform app's credential file text, as an operator writes `scout-app.json`."""
    from execbound_harness import fake_graph

    return json.dumps(fake_graph.platform_app())


def test_mc3_writes_the_platform_apps_credential_owner_only_and_scrubs_it(environment):
    """`EXECBOUND_SCOUT_APP_JSON` becomes the boot directory's `scout-app.json`, where
    `collect-due --platform-app` reads it, and leaves the environment before the exec."""
    contents = platform_app_text()
    environment["EXECBOUND_SCOUT_APP_JSON"] = contents
    calls, execute = capture()
    boot.run(
        ["python", "-m", "execbound.monitoring.commands", "collect-due"],
        environment,
        execute=execute,
    )
    written = Path(environment["EXECBOUND_BOOT_DIR"]) / "scout-app.json"
    assert json.loads(written.read_text(encoding="utf-8")) == json.loads(contents)
    if sys.platform != "win32":
        assert (written.stat().st_mode & 0o777) == 0o600
    assert "EXECBOUND_SCOUT_APP_JSON" not in environment
    assert len(calls) == 1


@pytest.mark.parametrize("case", ["not-json", "missing", "extra", "short-key", "duplicate"])
def test_mc3_refuses_a_malformed_platform_app_without_writing_or_printing_it(environment, case):
    document = json.loads(platform_app_text())
    key = document["private_key_pem"]
    raw = {
        "not-json": "not json " + key,
        "missing": json.dumps({"client_id": document["client_id"], "private_key_pem": key}),
        "extra": json.dumps({**document, "note": "x"}),
        "short-key": json.dumps({**document, "private_key_pem": key[:300]}),
        "duplicate": (
            f'{{"client_id": {json.dumps(document["client_id"])}, '
            f'"certificate_pem": {json.dumps(document["certificate_pem"])}, '
            f'"private_key_pem": {json.dumps(key[:300])}, "private_key_pem": {json.dumps(key)}}}'
        ),
    }[case]
    environment["EXECBOUND_SCOUT_APP_JSON"] = raw
    calls, execute = capture()
    with pytest.raises(boot.BootError, match="EXECBOUND_SCOUT_APP_JSON") as refused:
        boot.run(["uvicorn"], environment, execute=execute)
    assert calls == []
    assert key[40:120] not in str(refused.value)
    assert not (Path(environment["EXECBOUND_BOOT_DIR"]) / "scout-app.json").exists()


@pytest.mark.parametrize(
    ("provider", "variable"),
    [
        ("google", "EXECBOUND_GOOGLE_CLIENT_SECRET"),
        ("github", "EXECBOUND_GITHUB_CLIENT_SECRET"),
        ("microsoft", "EXECBOUND_MICROSOFT_CLIENT_SECRET"),
    ],
)
def test_a_sign_in_client_secret_is_merged_from_its_own_variable_and_scrubbed(
    environment, tmp_path, provider, variable
):
    block = {
        "client_id": f"{provider}-client",
        "redirect_uri": f"https://gateway.example/login/{provider}/callback",
    }
    secret = "a" * 40
    environment["EXECBOUND_RUNTIME_CONFIG_JSON"] = json.dumps(
        {"origin": "https://gateway.example", "sign_in": {provider: block}}
    )
    environment[variable] = secret
    _, execute = capture()
    boot.run(["uvicorn"], environment, execute=execute)
    written = json.loads((tmp_path / "gateway.json").read_text(encoding="utf-8"))
    assert written["sign_in"] == {provider: block | {"client_secret": secret}}
    assert boot.SIGN_IN_SECRET_VARIABLES[provider] == variable
    assert variable in boot.CONSUMED
    assert variable not in environment
    # Both places at once is two answers to which secret is current, and refuses to start.
    environment["EXECBOUND_RUNTIME_CONFIG_JSON"] = json.dumps(
        {"origin": "https://gateway.example", "sign_in": {provider: block | {"client_secret": "x"}}}
    )
    environment[variable] = secret
    with pytest.raises(boot.BootError, match=variable):
        boot.run(["uvicorn"], environment, execute=execute)
