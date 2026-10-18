# SPDX-License-Identifier: AGPL-3.0-only
"""MC2, MC3 and MC4: a monitoring key sealed to the collector's own key (#678).

The gateway holds the collector's public key and seals a pasted Tines key to it in a canonical
envelope that binds the key to its tenant, connection and kind. Only the collector's private key
opens it, and the collector refuses an envelope that names another row. `collector-keygen`
writes the pair, `collect-due --collector-key` collects sealed connections, and
`collector-reseal` moves every sealed connection to a new collector key with its fingerprint
unchanged. Real PostgreSQL and the fake Tines API; no key reaches an output or a message.
"""

import ast
import base64
import gc
import hashlib
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from nacl.public import PrivateKey
from sqlalchemy import text
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins
from test_tines_collection import scenario

from execbound.monitoring import collection, commands, due, sealing
from execbound.monitoring.models import MonitorError
from execbound_harness import fake_tines
from execbound_harness.fake_tines import BASE_URL

ROOT = Path(__file__).resolve().parents[1]
# A key no output, message, log line or table may ever repeat.
SENTINEL = "SENTINEL-sealed-tines-key-51c0e8"


def keypair(tmp_path, name="collector"):
    """A collector key pair through `collector-keygen`'s own writer."""
    directory = tmp_path / name
    public = sealing.generate(directory)
    return public, sealing.read_private_file(directory / sealing.PRIVATE_FILE), directory


def row_for(tenant, connection, ciphertext, key_id, kind="tines", key=SENTINEL):
    return {
        "tenant_id": tenant,
        "connection_id": connection,
        "kind": kind,
        "credential_mode": "sealed",
        "sealed_ct": ciphertext,
        "sealed_key_id": key_id,
        "key_fingerprint": collection.fingerprint(key),
    }


def test_mc2_keygen_writes_an_owner_only_pair_whose_id_is_derived(tmp_path):
    public, ring, directory = keypair(tmp_path)
    written = json.loads((directory / sealing.PUBLIC_FILE).read_text(encoding="utf-8"))
    private = json.loads((directory / sealing.PRIVATE_FILE).read_text(encoding="utf-8"))
    raw = base64.b64decode(written["public_key"], validate=True)
    assert len(raw) == 32
    assert written["key_id"] == "ck1-" + hashlib.sha256(raw).hexdigest()[:16]
    assert public.key_id == written["key_id"] == private["key_id"]
    assert public.public_key == raw
    assert set(written) == {"key_id", "public_key"}
    assert set(private) == {"key_id", "private_key"}
    assert list(ring.key_ids()) == [public.key_id]
    if sys.platform != "win32":
        for name in (sealing.PUBLIC_FILE, sealing.PRIVATE_FILE):
            assert ((directory / name).stat().st_mode & 0o777) == 0o600
    # An existing output is never overwritten, and nothing beside it is written.
    before = {name: (directory / name).read_bytes() for name in os.listdir(directory)}
    with pytest.raises(FileExistsError):
        sealing.generate(directory)
    assert {name: (directory / name).read_bytes() for name in os.listdir(directory)} == before
    half = tmp_path / "half"
    half.mkdir()
    (half / sealing.PRIVATE_FILE).write_text("{}", encoding="utf-8")
    with pytest.raises(FileExistsError):
        sealing.generate(half)
    assert sorted(os.listdir(half)) == [sealing.PRIVATE_FILE]


def test_mc2_the_keygen_command_writes_the_pair_and_refuses_an_existing_output(
    tmp_path, monkeypatch, capsys
):
    output = tmp_path / "keys"
    monkeypatch.setattr(sys, "argv", ["commands", "collector-keygen", "--output", str(output)])
    commands.main()
    out = capsys.readouterr()
    public = json.loads((output / sealing.PUBLIC_FILE).read_text(encoding="utf-8"))
    private = json.loads((output / sealing.PRIVATE_FILE).read_text(encoding="utf-8"))
    # The command names the key id; neither key reaches its output.
    assert public["key_id"] in out.out
    assert public["public_key"] not in out.out + out.err
    assert private["private_key"] not in out.out + out.err
    with pytest.raises(SystemExit) as refused:
        commands.main()
    assert refused.value.code == 2
    assert "Output already exists" in capsys.readouterr().err


def test_mc3_a_sealed_key_opens_only_for_its_own_tenant_connection_and_kind(tmp_path):
    public, ring, _ = keypair(tmp_path)
    tenant, connection = uuid4(), uuid4()
    ciphertext = sealing.seal_for_collector(public, tenant, connection, "tines", SENTINEL)
    assert SENTINEL.encode() not in ciphertext
    own = row_for(tenant, connection, ciphertext, public.key_id)
    assert sealing.open_for_collector(ring, own) == SENTINEL
    # Two sealings of one key differ: a ciphertext says nothing about the key it holds.
    assert sealing.seal_for_collector(public, tenant, connection, "tines", SENTINEL) != ciphertext
    # The ciphertext copied to another connection, another tenant, or another kind opens and
    # is refused rather than used.
    for other in (
        row_for(tenant, uuid4(), ciphertext, public.key_id),
        row_for(uuid4(), connection, ciphertext, public.key_id),
        row_for(tenant, connection, ciphertext, public.key_id, kind="entra_agent_id"),
    ):
        with pytest.raises(MonitorError) as refused:
            sealing.open_for_collector(ring, other)
        assert refused.value.code == "SEALED_KEY_MISMATCH"
        assert SENTINEL not in str(refused.value) and SENTINEL not in repr(refused.value)


@pytest.mark.parametrize(
    "envelope",
    [
        {"v": 2},
        {"v": True},
        {"purpose": "gateway"},
        {"extra": "field"},
        {"key": ""},
        {"key": "has space"},
        {"key": 7},
    ],
    ids=["version", "boolean-version", "purpose", "extra", "empty-key", "space", "number"],
)
def test_mc3_an_envelope_that_is_not_exactly_the_collectors_is_refused(tmp_path, envelope):
    public, ring, _ = keypair(tmp_path)
    tenant, connection = uuid4(), uuid4()
    document = {
        "v": 1,
        "purpose": "collector",
        "tenant_id": str(tenant),
        "connection_id": str(connection),
        "kind": "tines",
        "key": SENTINEL,
        **envelope,
    }
    ciphertext = sealing._seal_bytes(public, json.dumps(document).encode())
    with pytest.raises(MonitorError) as refused:
        sealing.open_for_collector(ring, row_for(tenant, connection, ciphertext, public.key_id))
    assert refused.value.code == "SEALED_KEY_MISMATCH"


def test_mc3_an_unknown_key_or_a_damaged_ciphertext_is_refused_without_the_value(tmp_path):
    public, ring, _ = keypair(tmp_path)
    other, other_ring, _ = keypair(tmp_path, "other")
    tenant, connection = uuid4(), uuid4()
    ciphertext = sealing.seal_for_collector(public, tenant, connection, "tines", SENTINEL)
    for held, row in (
        # The row names a key this collector does not hold.
        (other_ring, row_for(tenant, connection, ciphertext, public.key_id)),
        # The row names this collector's key, but the ciphertext is sealed to another.
        (
            ring,
            row_for(
                tenant,
                connection,
                sealing.seal_for_collector(other, tenant, connection, "tines", SENTINEL),
                public.key_id,
            ),
        ),
        # Truncated, and cut below a sealed box's own overhead.
        (ring, row_for(tenant, connection, ciphertext[:-1], public.key_id)),
        (ring, row_for(tenant, connection, ciphertext[:40], public.key_id)),
        (sealing.CollectorKeyRing({}), row_for(tenant, connection, ciphertext, public.key_id)),
    ):
        with pytest.raises(MonitorError) as refused:
            sealing.open_for_collector(held, row)
        assert refused.value.code == "COLLECTOR_KEY_UNAVAILABLE"
        assert SENTINEL not in str(refused.value)


def test_mc3_a_malformed_key_file_is_refused_naming_no_value(tmp_path):
    public, _, directory = keypair(tmp_path)
    private = json.loads((directory / sealing.PRIVATE_FILE).read_text(encoding="utf-8"))
    cases = {
        "not-json": "not json",
        "list": "[]",
        "missing": json.dumps({"key_id": public.key_id}),
        "extra": json.dumps({**private, "note": "x"}),
        "short": json.dumps({**private, "private_key": base64.b64encode(b"x" * 31).decode()}),
        "not-base64": json.dumps({**private, "private_key": "%%%"}),
        "wrong-id": json.dumps({**private, "key_id": "ck1-0000000000000000"}),
    }
    for name, contents in cases.items():
        path = tmp_path / f"{name}.json"
        path.write_text(contents, encoding="utf-8")
        with pytest.raises(sealing.CollectorKeyError) as refused:
            sealing.read_private_file(path)
        assert private["private_key"] not in str(refused.value), name
    with pytest.raises(sealing.CollectorKeyError):
        sealing.read_public_key({"key_id": public.key_id, "public_key": "AAAA"})
    with pytest.raises(sealing.CollectorKeyError):
        sealing.read_public_key(
            {
                "key_id": "ck1-0000000000000000",
                "public_key": base64.b64encode(public.public_key).decode(),
            }
        )


def test_mc2_the_gateway_holds_the_public_key_only_and_cannot_open(tmp_path):
    """Built from a configuration with the `scout` block, the gateway holds nothing that opens
    a sealed key, and everything its configuration yields fails to open one."""
    from execbound.app import create_app
    from execbound.db import Database
    from execbound.surfaces.configuration import load_runtime

    public, ring, directory = keypair(tmp_path)
    private_bytes = ring.private_bytes(public.key_id)
    configuration = {
        "origin": "http://127.0.0.1:8000",
        "active_key_id": "state-v1",
        "continuation_keys": {"state-v1": "21" * 32},
        "connectors": [
            {
                "tenant_id": "00000000-0000-0000-0000-000000000001",
                "account_id": "00000000-0000-0000-0000-000000000002",
                "origin": "http://127.0.0.1:8001",
                "dispatch_token": "dispatch-test" * 3,
                "control_token": "control-test" * 3,
                "evidence_keys": {"proof": "31" * 32},
            }
        ],
        "scout": {
            "collector": json.loads((directory / sealing.PUBLIC_FILE).read_text(encoding="utf-8"))
        },
    }
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(configuration), encoding="utf-8")
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        runtime, human = load_runtime(path, db)
        app = create_app(db, runtime=runtime, human=human)
        assert human.scout is not None and human.scout.collector == public
        # Everything reachable from the application, its state and the runtime: no object
        # holds the private key's bytes, raw or encoded.
        encoded = base64.b64encode(private_bytes)
        seen: set[int] = set()
        stack: list[object] = [app, app.state, runtime, human]
        while stack:
            item = stack.pop()
            if id(item) in seen:
                continue
            seen.add(id(item))
            if isinstance(item, (bytes, bytearray, memoryview)):
                assert bytes(item) != private_bytes and encoded not in bytes(item)
                continue
            if isinstance(item, str):
                assert encoded.decode() not in item
                continue
            if isinstance(item, (int, float, bool, type(None))) or isinstance(item, type):
                continue
            stack.extend(gc.get_referents(item))
        assert len(seen) > 1000
        # Every key the gateway's configuration yields, tried as a collector key: none opens.
        tenant, connection = uuid4(), uuid4()
        ciphertext = sealing.seal_for_collector(
            human.scout.collector, tenant, connection, "tines", SENTINEL
        )
        row = row_for(tenant, connection, ciphertext, public.key_id)
        candidates = [public.public_key, *runtime_keys(configuration)]
        for candidate in candidates:
            attempt = sealing.CollectorKeyRing({public.key_id: PrivateKey(candidate)})
            with pytest.raises(MonitorError) as refused:
                sealing.open_for_collector(attempt, row)
            assert refused.value.code == "COLLECTOR_KEY_UNAVAILABLE"
    finally:
        db.close()


def runtime_keys(configuration):
    """Every 32-byte key material the gateway's configuration file carries."""
    found = []
    for value in (
        *configuration["continuation_keys"].values(),
        *configuration["connectors"][0]["evidence_keys"].values(),
    ):
        raw = bytes.fromhex(value)
        if len(raw) == 32:
            found.append(raw)
    return found


# The modules that may call the collector's half of `sealing`: the collector's commands;
# `due.py`, whose collection and re-seal functions only those commands run (the gateway imports
# `due.py` for its schedule rule, `due_at` and `intervals`, and runs neither); and `boot.py`,
# which checks the collector's key file before writing it on the one service whose environment
# carries it, and then replaces itself with that service's process. This holds which modules
# call the opening half, not what a process loads: `sealing` is one module, which the gateway
# loads for `seal_for_collector`. That the gateway holds no key that opens anything is
# `test_mc2_the_gateway_holds_the_public_key_only_and_cannot_open`.
COLLECTOR_HALF = {
    "execbound/monitoring/commands.py",
    "execbound/monitoring/due.py",
    "execbound/boot.py",
}
# What the gateway may take: the sealing call, the public key and its reader, and the shape of
# a key it seals.
GATEWAY_NAMES = {"seal_for_collector", "read_public_key", "CollectorPublicKey", "API_KEY"}


def test_mc2_nothing_the_gateway_loads_imports_the_collectors_half():
    """The console API, the pages, the app factory and every other module outside the
    collector's half import from `sealing` only the sealing half."""
    for path in sorted((ROOT / "src").rglob("*.py")):
        relative = path.relative_to(ROOT / "src").as_posix()
        if relative in COLLECTOR_HALF or relative == "execbound/monitoring/sealing.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name != "execbound.monitoring.sealing" for alias in node.names), (
                    relative
                )
            if isinstance(node, ast.ImportFrom):
                if node.module == "execbound.monitoring" and any(
                    alias.name == "sealing" for alias in node.names
                ):
                    raise AssertionError(f"{relative} imports the whole sealing module")
                if node.module == "execbound.monitoring.sealing":
                    names = {alias.name for alias in node.names}
                    assert names <= GATEWAY_NAMES, (relative, names - GATEWAY_NAMES)


@pytest.fixture
def clock():
    # A sealed connection is created and asked for by the database's own clock, so the
    # collector's clock reads a moment later, as it does when a pass follows a connect.
    return FixedClock(datetime.now(UTC) + timedelta(minutes=1))


@pytest.fixture
def tines():
    with fake_tines.serving(scenario(datetime.now(UTC))) as server:
        yield server


def sealed_connection(db, admin, public, key=SENTINEL, space=None):
    """A sealed Tines connection, written by the definer function the console's route calls."""
    connection = uuid4()
    with db.transaction(admin.tenant_id) as conn:
        space = (
            space
            or conn.execute(
                text(
                    "SELECT space_id FROM execbound.spaces WHERE tenant_id = :t "
                    "ORDER BY created_at, space_id LIMIT 1"
                ),
                {"t": admin.tenant_id},
            ).scalar_one()
        )
        conn.execute(
            text(
                "SELECT execbound.admin_create_sealed_connection(:a, :s, :c, 'Sealed tenant', "
                ":u, NULL, :k, :ct, :kid)"
            ),
            {
                "a": admin.principal_id,
                "s": space,
                "c": connection,
                "u": BASE_URL,
                "k": collection.fingerprint(key),
                "ct": sealing.seal_for_collector(public, admin.tenant_id, connection, "tines", key),
                "kid": public.key_id,
            },
        )
    return connection


def replace_key(db, admin, connection, public, key):
    """A new key for a sealed connection, written by the definer function the console's
    Replace key route calls, sealed to whichever collector key `public` is."""
    with db.transaction(admin.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.admin_replace_sealed_key(:a, :c, :k, :ct, :kid)"),
            {
                "a": admin.principal_id,
                "c": connection,
                "k": collection.fingerprint(key),
                "ct": sealing.seal_for_collector(public, admin.tenant_id, connection, "tines", key),
                "kid": public.key_id,
            },
        )


def connection_row(admin_engine, tenant, connection):
    with admin_engine.connect() as conn:
        return dict(
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


def tokens(server):
    """The key each request to the fake Tines tenant carried."""
    return {headers.get("X-User-Token") for _, _, headers in server.requests}


@pytest.mark.integration
def test_mc3_collect_due_opens_a_sealed_key_with_the_collectors_key(
    db, admin_engine, admins, tines, clock, tmp_path
):
    public, ring, _ = keypair(tmp_path)
    admin = admins[0]
    connection = sealed_connection(db, admin, public)
    with httpx.Client(transport=fake_tines.transport(tines), trust_env=False) as http:
        report = due.collect_due(db, key_files=None, collector=ring, client=http, clock=clock)
    counts = report["tenants"][str(admin.tenant_id)]
    assert (counts["collected"], counts["failed"], counts["no_key_file"]) == (1, 0, 0)
    row = connection_row(admin_engine, admin.tenant_id, connection)
    assert (row["last_outcome"], row["collecting_lease"]) == ("COMPLETE", None)
    # The request the connection was created with is answered.
    assert row["collect_requested_at"] is None
    assert tokens(tines) == {SENTINEL}


@pytest.mark.integration
def test_mc3_without_the_collectors_key_a_sealed_row_records_why_and_sends_nothing(
    db, admin_engine, admins, tines, clock, tmp_path
):
    public, ring, _ = keypair(tmp_path)
    _, other_ring, _ = keypair(tmp_path, "other")
    admin = admins[0]
    connection = sealed_connection(db, admin, public)
    with httpx.Client(transport=fake_tines.transport(tines), trust_env=False) as http:
        for held in (None, other_ring):
            report = due.collect_due(db, key_files=None, collector=held, client=http, clock=clock)
            counts = report["tenants"][str(admin.tenant_id)]
            assert (counts["collected"], counts["failed"]) == (0, 1)
            row = connection_row(admin_engine, admin.tenant_id, connection)
            assert (row["last_outcome"], row["last_error_code"], row["health_state"]) == (
                "ERROR",
                "COLLECTOR_KEY_UNAVAILABLE",
                "ERROR",
            )
            # Due again at once, as a refused run is; the next pass tries again.
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE execbound.monitor_connections SET last_run_at = NULL "
                        "WHERE tenant_id = :t AND connection_id = :c"
                    ),
                    {"t": admin.tenant_id, "c": connection},
                )
    assert tines.requests == []


@pytest.mark.integration
def test_mc3_a_ciphertext_copied_to_another_row_is_refused_and_never_sent(
    db, admin_engine, admins, tines, clock, tmp_path
):
    public, ring, _ = keypair(tmp_path)
    first, second = admins
    source = sealed_connection(db, first, public)
    target = sealed_connection(db, second, public, key="another-key-entirely")
    copied = connection_row(admin_engine, first.tenant_id, source)["sealed_ct"]
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET sealed_ct = :ct "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"ct": copied, "t": second.tenant_id, "c": target},
        )
        # Only the target is due.
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET collect_requested_at = NULL, "
                "collect_requested_by = NULL, last_run_at = now() "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": first.tenant_id, "c": source},
        )
    with httpx.Client(transport=fake_tines.transport(tines), trust_env=False) as http:
        due.collect_due(db, key_files=None, collector=ring, client=http, clock=clock)
    row = connection_row(admin_engine, second.tenant_id, target)
    assert (row["last_outcome"], row["last_error_code"]) == ("ERROR", "SEALED_KEY_MISMATCH")
    assert tines.requests == []


@pytest.mark.integration
def test_mc3_a_resealed_key_that_is_not_the_registered_one_is_refused(
    db, admin_engine, admins, tines, clock, tmp_path
):
    """The fingerprint binds the plaintext: a ciphertext re-sealed with another key for the
    same row opens and is refused before any request."""
    public, ring, _ = keypair(tmp_path)
    admin = admins[0]
    connection = sealed_connection(db, admin, public)
    forged = sealing.seal_for_collector(
        public, admin.tenant_id, connection, "tines", "a-key-nobody-registered"
    )
    held = connection_row(admin_engine, admin.tenant_id, connection)["sealed_ct"]
    with db.transaction(admin.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.collector_reseal(:c, :old, :oldct, :ct, :kid)"),
            {
                "c": connection,
                "old": public.key_id,
                "oldct": held,
                "ct": forged,
                "kid": public.key_id,
            },
        )
    with httpx.Client(transport=fake_tines.transport(tines), trust_env=False) as http:
        due.collect_due(db, key_files=None, collector=ring, client=http, clock=clock)
    row = connection_row(admin_engine, admin.tenant_id, connection)
    assert (row["last_outcome"], row["last_error_code"]) == ("ERROR", "KEY_MISMATCH")
    assert tines.requests == []


# A replacement key no output may repeat either.
REPLACEMENT = "SENTINEL-replacement-tines-key-7d41a2"


@pytest.mark.integration
def test_mc3_a_key_replaced_after_the_pass_read_its_connections_is_the_one_collected(
    db, admin_engine, admins, tines, clock, tmp_path, monkeypatch
):
    """A pass reads every due connection first and claims each in turn, perhaps minutes later.
    A key an administrator replaces in between is the key that run collects with: the claim
    answers the replacement's collection request, so a run that used the key it read first
    would leave the new key unused until the next interval."""
    public, ring, _ = keypair(tmp_path)
    admin = admins[0]
    connection = sealed_connection(db, admin, public)
    claim = due.claim

    def replaced_then_claimed(*arguments, **keywords):
        replace_key(db, admin, connection, public, REPLACEMENT)
        return claim(*arguments, **keywords)

    monkeypatch.setattr(due, "claim", replaced_then_claimed)
    with httpx.Client(transport=fake_tines.transport(tines), trust_env=False) as http:
        report = due.collect_due(db, key_files=None, collector=ring, client=http, clock=clock)
    counts = report["tenants"][str(admin.tenant_id)]
    assert (counts["collected"], counts["failed"]) == (1, 0)
    assert tokens(tines) == {REPLACEMENT}
    row = connection_row(admin_engine, admin.tenant_id, connection)
    assert (row["last_outcome"], row["collect_requested_at"]) == ("COMPLETE", None)


@pytest.mark.integration
def test_mc4_a_key_replaced_while_a_reseal_runs_is_never_overwritten(
    db, admin_engine, admins, tmp_path, monkeypatch
):
    """A re-seal reads a row, opens it and writes the same key sealed to the new collector key.
    A key an administrator replaces in between, through a gateway still sealing to the old
    collector key, is kept: the re-seal of the key it replaced is refused, and the next pass
    moves the new key."""
    old, old_ring, _ = keypair(tmp_path, "old")
    new, new_ring, _ = keypair(tmp_path, "new")
    admin = admins[0]
    connection = sealed_connection(db, admin, old)
    opened = due.open_for_collector

    def opened_then_replaced(ring, row):
        key = opened(ring, row)
        replace_key(db, admin, connection, old, REPLACEMENT)
        return key

    monkeypatch.setattr(due, "open_for_collector", opened_then_replaced)
    report = due.reseal_due(db, old_ring, new)
    assert (report["resealed"], report["failed"]) == (0, 1)
    row = connection_row(admin_engine, admin.tenant_id, connection)
    assert row["sealed_key_id"] == old.key_id
    assert row["key_fingerprint"] == collection.fingerprint(REPLACEMENT)
    assert sealing.open_for_collector(old_ring, row) == REPLACEMENT
    monkeypatch.setattr(due, "open_for_collector", opened)
    again = due.reseal_due(db, old_ring, new)
    assert (again["resealed"], again["failed"]) == (1, 0)
    row = connection_row(admin_engine, admin.tenant_id, connection)
    assert row["sealed_key_id"] == new.key_id
    assert sealing.open_for_collector(new_ring, row) == REPLACEMENT
    assert row["key_fingerprint"] == collection.fingerprint(REPLACEMENT)


def cli(monkeypatch, capsys, *arguments):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(sys, "argv", ["commands", *arguments])
    commands.main()
    return capsys.readouterr()


@pytest.mark.integration
def test_mc4_reseal_moves_every_sealed_row_to_the_new_key_and_leaves_the_rest(
    db, admin_engine, admins, tmp_path, monkeypatch, capsys
):
    old, old_ring, old_directory = keypair(tmp_path, "old")
    new, new_ring, new_directory = keypair(tmp_path, "new")
    stranger, _, _ = keypair(tmp_path, "stranger")
    first, second = admins
    moved = [
        (first, sealed_connection(db, first, old)),
        (second, sealed_connection(db, second, old, key="second-key")),
    ]
    # A revoked connection's key is moved too, so the old collector key can be retired.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET active = false, revoked_at = now() "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": second.tenant_id, "c": moved[1][1]},
        )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Another', now(), :p)"
            ),
            {"t": first.tenant_id, "s": (other_space := uuid4()), "p": first.principal_id},
        )
    left = sealed_connection(db, first, stranger, key="third-key", space=other_space)
    before = {
        connection: connection_row(admin_engine, admin.tenant_id, connection)
        for admin, connection in (*moved, (first, left))
    }
    out = cli(
        monkeypatch,
        capsys,
        "collector-reseal",
        "--old-key",
        str(old_directory / sealing.PRIVATE_FILE),
        "--new-key",
        str(new_directory / sealing.PUBLIC_FILE),
        "--all-tenants",
    )
    report = json.loads(out.out)
    assert (report["resealed"], report["other_key"], report["failed"]) == (2, 1, 0)
    for secret in (SENTINEL, "second-key", "third-key"):
        assert secret not in out.out + out.err
    for (admin, connection), key in zip(moved, (SENTINEL, "second-key"), strict=True):
        row = connection_row(admin_engine, admin.tenant_id, connection)
        assert row["sealed_key_id"] == new.key_id
        assert row["key_fingerprint"] == before[connection]["key_fingerprint"]
        assert sealing.open_for_collector(new_ring, row) == key
        # The old key opens nothing written after.
        with pytest.raises(MonitorError) as refused:
            sealing.open_for_collector(old_ring, row)
        assert refused.value.code == "COLLECTOR_KEY_UNAVAILABLE"
    assert connection_row(admin_engine, first.tenant_id, left) == before[left]
    # Run again, nothing is left under the old key.
    again = json.loads(
        cli(
            monkeypatch,
            capsys,
            "collector-reseal",
            "--old-key",
            str(old_directory / sealing.PRIVATE_FILE),
            "--new-key",
            str(new_directory / sealing.PUBLIC_FILE),
            "--all-tenants",
        ).out
    )
    assert (again["resealed"], again["already"], again["other_key"]) == (0, 2, 1)


@pytest.mark.parametrize(
    "arguments,message",
    [
        (["collector-reseal", "--old-key", "a", "--new-key", "b"], "give --all-tenants"),
        (["collector-keygen"], "--output"),
    ],
)
def test_mc4_the_key_commands_refuse_their_arguments_first(arguments, message, monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(sys, "argv", ["commands", *arguments])
    with pytest.raises(SystemExit) as refused:
        commands.main()
    assert refused.value.code == 2
    assert message in capsys.readouterr().err


def test_mc3_the_collectors_key_id_is_its_public_keys_digest():
    key = PrivateKey.generate()
    public = bytes(key.public_key)
    assert sealing.key_id(public) == "ck1-" + hashlib.sha256(public).hexdigest()[:16]


@pytest.mark.integration
def test_mc3_the_collect_due_command_reads_the_collectors_key_file(
    db, admin_engine, admins, tines, tmp_path, monkeypatch, capsys
):
    public, _, directory = keypair(tmp_path)
    admin = admins[0]
    connection = sealed_connection(db, admin, public)
    monkeypatch.setattr(
        commands,
        "_http_client",
        lambda: httpx.Client(
            transport=fake_tines.transport(tines), trust_env=False, follow_redirects=False
        ),
    )
    out = cli(
        monkeypatch,
        capsys,
        "collect-due",
        "--all-tenants",
        "--collector-key",
        str(directory / sealing.PRIVATE_FILE),
    )
    assert json.loads(out.out)["tenants"][str(admin.tenant_id)]["collected"] == 1
    assert SENTINEL not in out.out + out.err
    assert connection_row(admin_engine, admin.tenant_id, connection)["last_outcome"] == "COMPLETE"
    # A path that names no file is no key yet: the run goes on and records why on the row.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET last_run_at = NULL "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": admin.tenant_id, "c": connection},
        )
    absent = cli(
        monkeypatch,
        capsys,
        "collect-due",
        "--all-tenants",
        "--collector-key",
        str(tmp_path / "not-yet" / sealing.PRIVATE_FILE),
    )
    assert json.loads(absent.out)["tenants"][str(admin.tenant_id)]["failed"] == 1
    assert connection_row(admin_engine, admin.tenant_id, connection)["last_error_code"] == (
        "COLLECTOR_KEY_UNAVAILABLE"
    )
    # A collector key file that is not one refuses the run before any workspace is visited.
    broken = tmp_path / "broken.json"
    broken.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as refused:
        cli(monkeypatch, capsys, "collect-due", "--all-tenants", "--collector-key", str(broken))
    assert refused.value.code == 2


@pytest.mark.integration
def test_mc4_during_a_rotation_the_collector_opens_a_key_sealed_to_either(
    db, admin_engine, admins, tines, tmp_path, monkeypatch, capsys
):
    """`--collector-key` may be given more than once, so while a rotation is under way the
    collector opens what the gateway sealed to the old key and to the new one alike, and no
    connection records `COLLECTOR_KEY_UNAVAILABLE` between the re-seal and the collector's
    own redeploy. A path that names no file is still no key."""
    old, _, old_directory = keypair(tmp_path, "old")
    new, _, new_directory = keypair(tmp_path, "new")
    first, second = admins
    before = sealed_connection(db, first, old)
    after = sealed_connection(db, second, new, key="second-key")
    monkeypatch.setattr(
        commands,
        "_http_client",
        lambda: httpx.Client(
            transport=fake_tines.transport(tines), trust_env=False, follow_redirects=False
        ),
    )
    out = cli(
        monkeypatch,
        capsys,
        "collect-due",
        "--all-tenants",
        "--collector-key",
        str(new_directory / sealing.PRIVATE_FILE),
        "--collector-key",
        str(old_directory / sealing.PRIVATE_FILE),
        "--collector-key",
        str(tmp_path / "retired" / sealing.PRIVATE_FILE),
    )
    report = json.loads(out.out)
    for admin in admins:
        assert report["tenants"][str(admin.tenant_id)]["collected"] == 1
    assert tokens(tines) == {SENTINEL, "second-key"}
    for secret in (SENTINEL, "second-key"):
        assert secret not in out.out + out.err
    for admin, connection in ((first, before), (second, after)):
        row = connection_row(admin_engine, admin.tenant_id, connection)
        assert row["last_outcome"] == "COMPLETE"


def test_mc4_a_ring_refuses_two_keys_that_claim_one_id(tmp_path):
    """Two key files for one collector key are one key; two different keys under one id are
    not a ring, and are refused naming neither."""
    _, ring, directory = keypair(tmp_path)
    _, other, _ = keypair(tmp_path, "other")
    combined = sealing.combine(
        [ring, other, sealing.read_private_file(directory / sealing.PRIVATE_FILE)]
    )
    assert sorted(combined.key_ids()) == sorted([*ring.key_ids(), *other.key_ids()])
    [identifier] = ring.key_ids()
    impostor = PrivateKey.generate()
    forged = sealing.CollectorKeyRing({identifier: impostor})
    with pytest.raises(sealing.CollectorKeyError) as refused:
        sealing.combine([ring, forged])
    for raw in (bytes(impostor), ring.private_bytes(identifier)):
        assert base64.b64encode(raw).decode("ascii") not in str(refused.value)
