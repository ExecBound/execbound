# SPDX-License-Identifier: AGPL-3.0-only
"""Failed authentication leaves a bounded, attributed record; responses never change (AF1-AF14)."""

import json
import os
import secrets
import sys
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_human_surface import credential, form_values
from test_human_surface import human_config as human_config
from test_monitoring_http import monitor_web as monitor_web
from test_monitoring_http import post_event
from test_monitoring_transport import valid_event
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound import administration as admin
from execbound import identity as identity_module
from execbound.app import create_app
from execbound.cli import main
from execbound.db import TABLES, check_runtime
from execbound.runtime import Runtime
from execbound.surfaces.limits import RequestLimits
from execbound.surfaces.tokens import TokenKeys

MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2026-07-28",
}
ORIGIN = {"Origin": "http://127.0.0.1"}
COLUMNS = "surface, reason, tenant_id, subject_kind, subject_id, count"


def rows(engine, tenant=None):
    """Attributed rows of one tenant, or the unattributed rows when no tenant is given."""
    with engine.begin() as conn:
        if tenant is None:
            query = (
                f"SELECT {COLUMNS} FROM execbound.authentication_failures "
                "WHERE tenant_id IS NULL ORDER BY surface, reason"
            )
            result = conn.execute(text(query))
        else:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)}
            )
            query = (
                f"SELECT {COLUMNS} FROM execbound.authentication_failures "
                "WHERE tenant_id=:t ORDER BY surface, reason"
            )
            result = conn.execute(text(query), {"t": tenant})
        return [dict(row) for row in result.mappings()]


def wrong_secret(tenant, subject, prefix="eb1"):
    return f"{prefix}.{tenant}.{subject}.{secrets.token_urlsafe(32)}"


def bearer(token):
    return {"Authorization": "Bearer " + token}


def missing():
    return "/v1/executions/" + str(uuid4())


def unchanged_401(response):
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.fixture
def api(db, runtime, human_config, seeded):
    app = create_app(db, runtime=runtime, human=human_config)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        yield client


def test_af1_af2_wrong_secret_is_attributed_per_surface_with_unchanged_responses(
    api, seeded, admin_engine
):
    tenant, cred = seeded["tenants"][0], seeded["credentials"][0]
    token = wrong_secret(tenant, cred)
    for _ in range(2):
        unchanged_401(api.get(missing(), headers=bearer(token)))
    assert rows(admin_engine, tenant) == [
        {
            "surface": "http",
            "reason": "MISMATCH",
            "tenant_id": tenant,
            "subject_kind": "credential",
            "subject_id": cred,
            "count": 2,
        }
    ]
    envelope = {"jsonrpc": "2.0", "id": "probe", "method": "tools/list", "params": {}}
    response = api.post("/mcp/", json=envelope, headers={**bearer(token), **MCP_HEADERS})
    assert response.status_code == 401 and response.json() == {"detail": "Invalid credentials"}
    assert [(r["surface"], r["count"]) for r in rows(admin_engine, tenant)] == [
        ("http", 2),
        ("mcp", 1),
    ]
    assert rows(admin_engine) == []


def test_af3_af4_unknown_and_malformed_tokens_are_counted_without_identifiers(
    api, seeded, admin_engine
):
    tenant = seeded["tenants"][0]
    unchanged_401(api.get(missing(), headers=bearer(wrong_secret(tenant, uuid4()))))
    shapes = [
        "garbage",
        "eb1.x.y.z",
        f"eb1.{tenant}.{seeded['credentials'][0]}",
        "hs1." + "a" * 100,
        "eb1." + "b" * 200,
    ]
    for shape in shapes:
        unchanged_401(api.get(missing(), headers=bearer(shape)))
    unchanged_401(api.get(missing(), headers={"Authorization": "Basic abc"}))
    assert rows(admin_engine, tenant) == []
    assert rows(admin_engine) == [
        {
            "surface": "http",
            "reason": "MALFORMED",
            "tenant_id": None,
            "subject_kind": None,
            "subject_id": None,
            "count": len(shapes) + 1,
        },
        {
            "surface": "http",
            "reason": "UNKNOWN",
            "tenant_id": None,
            "subject_kind": None,
            "subject_id": None,
            "count": 1,
        },
    ]


def test_af5_expired_and_revoked_credentials_are_attributed(api, seeded, admin_engine):
    with admin_engine.begin() as conn:
        for index, column in ((0, "revoked_at"), (1, "expires_at")):
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"),
                {"t": str(seeded["tenants"][index])},
            )
            conn.execute(
                text(
                    f"UPDATE execbound.credentials SET {column} = :when "
                    "WHERE tenant_id=:t AND credential_id=:c"
                ),
                {
                    "when": datetime.now(UTC) - timedelta(seconds=1),
                    "t": seeded["tenants"][index],
                    "c": seeded["credentials"][index],
                },
            )
    unchanged_401(api.get(missing(), headers=bearer(seeded["tokens"][0])))
    unchanged_401(api.get(missing(), headers=bearer(seeded["tokens"][1])))
    assert [(r["reason"], r["subject_id"]) for r in rows(admin_engine, seeded["tenants"][0])] == [
        ("REVOKED", seeded["credentials"][0])
    ]
    assert [(r["reason"], r["subject_id"]) for r in rows(admin_engine, seeded["tenants"][1])] == [
        ("EXPIRED", seeded["credentials"][1])
    ]


def test_af6_human_sign_in_failures_record_on_the_human_surface(api, world, admin_engine):
    tenant, human = world["identity"].tenant_id, world["human"]

    def attempt(value):
        _, values = form_values(api.get("/login").text, "/session")
        values["credential"] = value
        return api.post("/session", data=values, headers=ORIGIN)

    wrong = attempt(wrong_secret(tenant, human.credential_id))
    unknown = attempt(wrong_secret(tenant, uuid4()))
    for response in (wrong, unknown):
        assert response.status_code == 401 and response.json() == {"detail": "Invalid credentials"}
    assert rows(admin_engine, tenant) == [
        {
            "surface": "human",
            "reason": "MISMATCH",
            "tenant_id": tenant,
            "subject_kind": "credential",
            "subject_id": human.credential_id,
            "count": 1,
        }
    ]
    assert [(r["surface"], r["reason"]) for r in rows(admin_engine)] == [("human", "UNKNOWN")]
    # A valid agent token on a human route is a rejection under a verified principal, not a failure.
    world_agent = credential(admin_engine, world["identity"])
    assert api.get("/approvals", headers=bearer(world_agent)).status_code == 403
    assert len(rows(admin_engine, tenant)) == 1


def test_af7_monitoring_source_failures_record_on_the_monitor_surface(
    monitor_web, admin_engine, db
):
    client, admin_identity, source, _ = monitor_web
    tenant = admin_identity.tenant_id
    wrong = client.post(
        "/v1/monitor/events",
        json=valid_event() | {"occurred_at": datetime.now(UTC).isoformat()},
        headers={"Authorization": "Bearer " + wrong_secret(tenant, source.source_id, "mo1")},
    )
    assert wrong.status_code == 401 and wrong.json()["code"] == "INVALID_SOURCE"
    # The intake parses the event before the lookup, so every case posts a valid event.
    unknown = client.post(
        "/v1/monitor/events",
        json=valid_event() | {"occurred_at": datetime.now(UTC).isoformat()},
        headers={"Authorization": "Bearer " + wrong_secret(tenant, uuid4(), "mo1")},
    )
    assert unknown.status_code == 401 and unknown.json()["code"] == "INVALID_SOURCE"
    malformed = client.post(
        "/v1/monitor/events",
        json=valid_event() | {"occurred_at": datetime.now(UTC).isoformat()},
        headers={"Authorization": "Bearer garbage"},
    )
    assert malformed.status_code == 401
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "UPDATE execbound.monitor_sources SET created_at = :earlier, expires_at = :when "
                "WHERE tenant_id=:t AND source_id=:s"
            ),
            {
                "earlier": datetime.now(UTC) - timedelta(hours=2),
                "when": datetime.now(UTC) - timedelta(seconds=1),
                "t": tenant,
                "s": source.source_id,
            },
        )
    expired = post_event(client, source)
    assert expired.status_code == 401 and expired.json()["code"] == "INVALID_SOURCE"
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "UPDATE execbound.monitor_sources SET expires_at = :later, revoked_at = :now "
                "WHERE tenant_id=:t AND source_id=:s"
            ),
            {
                "later": datetime.now(UTC) + timedelta(hours=1),
                "now": datetime.now(UTC),
                "t": tenant,
                "s": source.source_id,
            },
        )
    revoked = post_event(client, source)
    assert revoked.status_code == 401 and revoked.json()["code"] == "INVALID_SOURCE"
    attributed = [
        (r["reason"], r["subject_kind"], r["subject_id"]) for r in rows(admin_engine, tenant)
    ]
    assert attributed == [
        ("EXPIRED", "source", source.source_id),
        ("MISMATCH", "source", source.source_id),
        ("REVOKED", "source", source.source_id),
    ]
    assert [(r["surface"], r["reason"], r["count"]) for r in rows(admin_engine)] == [
        ("monitor", "MALFORMED", 1),
        ("monitor", "UNKNOWN", 1),
    ]


def test_af8_a_broken_recorder_never_changes_the_response(api, seeded, admin_engine, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("recording store unavailable")

    monkeypatch.setattr(identity_module, "_write_failure", broken)
    tenant, cred = seeded["tenants"][0], seeded["credentials"][0]
    unchanged_401(api.get(missing(), headers=bearer(wrong_secret(tenant, cred))))
    assert rows(admin_engine, tenant) == [] and rows(admin_engine) == []


def test_af9_tenants_see_only_their_rows_and_never_the_unattributed_ones(
    api, seeded, admin_engine, db
):
    for index in range(2):
        unchanged_401(
            api.get(
                missing(),
                headers=bearer(
                    wrong_secret(seeded["tenants"][index], seeded["credentials"][index])
                ),
            )
        )
    unchanged_401(api.get(missing(), headers=bearer("garbage")))
    owner = admin.owner_engine(os.environ["TEST_MIGRATION_DATABASE_URL"])
    try:
        for index in range(2):
            listed = admin.list_failures(owner, seeded["tenants"][index], since=timedelta(hours=1))
            assert [(item.reason, item.subject_id, item.count) for item in listed] == [
                ("MISMATCH", seeded["credentials"][index], 1)
            ]
        unattributed = admin.list_failures(owner, None, since=timedelta(hours=1))
        assert [(item.surface, item.reason, item.count) for item in unattributed] == [
            ("http", "MALFORMED", 1)
        ]
        # The human fixture seeds further credentials in the tenant; only the one hit counts.
        summary = {
            item.credential_id: item.failures_24h
            for item in admin.list_credentials(owner, seeded["tenants"][0])
        }
        assert summary.pop(seeded["credentials"][0]) == 1 and set(summary.values()) <= {0}
    finally:
        owner.dispose()
    with db.transaction(seeded["tenants"][1]) as conn:
        foreign = conn.execute(
            text("SELECT count(*) FROM execbound.authentication_failures WHERE tenant_id=:t"),
            {"t": seeded["tenants"][0]},
        ).scalar_one()
        assert foreign == 0
        with pytest.raises(DBAPIError):
            conn.execute(text("DELETE FROM execbound.authentication_failures"))


def test_af10_af11_limits_bound_recording_and_one_row_counts_many_attempts(
    db, world, connector, seeded, human_config, admin_engine
):
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    tenant, cred = seeded["tenants"][0], seeded["credentials"][0]
    limited = Runtime(
        db, [connector], clock=world["clock"], keys=keys, limits=RequestLimits(client_requests=2)
    )
    with TestClient(
        create_app(db, runtime=limited, human=human_config), base_url="http://127.0.0.1"
    ) as client:
        for _ in range(2):
            unchanged_401(client.get(missing(), headers=bearer(wrong_secret(tenant, cred))))
        refused = client.get(missing(), headers=bearer(wrong_secret(tenant, cred)))
        assert refused.status_code == 429
    assert [r["count"] for r in rows(admin_engine, tenant)] == [2]
    generous = Runtime(
        db, [connector], clock=world["clock"], keys=keys, limits=RequestLimits(client_requests=1000)
    )
    with TestClient(
        create_app(db, runtime=generous, human=human_config), base_url="http://127.0.0.1"
    ) as client:
        for _ in range(50):
            unchanged_401(client.get(missing(), headers=bearer(wrong_secret(tenant, cred))))
    assert [r["count"] for r in rows(admin_engine, tenant)] == [52]


def test_af12_migration_round_trip_and_runtime_privileges(db, seeded, admin_engine):
    assert "authentication_failures" in TABLES
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.authentication_failures "
                "(failure_id, surface, reason, window_start, count, first_at, last_at) "
                "VALUES (:f, 'http', 'MALFORMED', :w, 1, :w, :w)"
            ),
            {"f": uuid4(), "w": datetime.now(UTC)},
        )
    try:
        with pytest.raises(RuntimeError):
            command.downgrade(config, "0009_context_contracts")
    finally:
        command.upgrade(config, "head")
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM execbound.authentication_failures"))
    command.downgrade(config, "0009_context_contracts")
    command.upgrade(config, "head")
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)


def test_af13_failures_leave_the_audit_chain_and_replay_untouched(
    api, seeded, world, admin_engine, db
):
    from execbound.replay.export import export_history
    from execbound.replay.simulate import simulate
    from execbound.replay.verify import verify_export

    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        before = conn.execute(
            text("SELECT sequence FROM execbound.audit_heads WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    for _ in range(3):
        unchanged_401(
            api.get(
                missing(), headers=bearer(wrong_secret(tenant, world["identity"].credential_id))
            )
        )
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        after = conn.execute(
            text("SELECT sequence FROM execbound.audit_heads WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    assert after == before
    history = export_history(db, world["admin"], world["clock"])
    assert simulate(verify_export(history, history.head)).complete


def test_af14_attributed_and_unattributed_failures_answer_identically(api, seeded, admin_engine):
    tenant, cred = seeded["tenants"][0], seeded["credentials"][0]
    attributed = api.get(missing(), headers=bearer(wrong_secret(tenant, cred)))
    unattributed = api.get(missing(), headers=bearer(wrong_secret(tenant, uuid4())))

    def strip(r):
        return (
            r.status_code,
            r.content,
            {k: v for k, v in r.headers.items() if k.lower() not in {"date", "x-request-id"}},
        )

    assert strip(attributed) == strip(unattributed)
    assert len(rows(admin_engine, tenant)) == 1 and len(rows(admin_engine)) == 1


def test_failures_command_lists_tenant_and_unattributed_windows(
    api, seeded, admin_engine, monkeypatch, capsys
):
    tenant, cred = seeded["tenants"][0], seeded["credentials"][0]
    unchanged_401(api.get(missing(), headers=bearer(wrong_secret(tenant, cred))))
    unchanged_401(api.get(missing(), headers=bearer("garbage")))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        main()
        return json.loads(capsys.readouterr().out)

    listed = run("failures", "--tenant", str(tenant))
    assert [(r["surface"], r["reason"], r["subject_id"], r["count"]) for r in listed] == [
        ("http", "MISMATCH", str(cred), 1)
    ]
    unattributed = run("failures", "--unattributed", "--since-hours", "1")
    assert [
        (r["surface"], r["reason"], r["tenant_id"] if "tenant_id" in r else None)
        for r in unattributed
    ] == [("http", "MALFORMED", None)]
    credentials = run("credential-list", "--tenant", str(tenant))
    assert {c["credential_id"]: c["failures_24h"] for c in credentials}[str(cred)] == 1
    monkeypatch.setattr(sys, "argv", ["execbound", "failures"])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2 and "INVALID_TENANT" in capsys.readouterr().err
    monkeypatch.setattr(
        sys, "argv", ["execbound", "failures", "--tenant", str(tenant), "--since-hours", "0"]
    )
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2 and "INVALID_WINDOW" in capsys.readouterr().err
