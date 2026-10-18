# SPDX-License-Identifier: AGPL-3.0-only
"""The world the demo beats run against: a gateway with its console over real HTTP, and the
private directory the beats read (#207, #247).

`execbound-demo`, the client package's `execbound_client.demo`, runs the boundary, decide and
budget beats from a private directory that holds the agent credential files and a
`sandbox.json`. `console` serves the gateway at one loopback origin, `private` writes that
directory for the world's tenant, `approve_pending` makes the decision a person makes on their
phone, and `provision_mock` gives the protected mock every registry resource at the registry's
version, which the assistant's tests need too.

A test module that uses `private` imports `console` beside it (or defines its own, which
`private` then resolves to), and takes `world`, `live_provider` and the rest from
`test_runtime`, as every module that drives the gateway does.
"""

import json
import secrets
import socket
import threading
import time
from contextlib import contextmanager
from uuid import uuid4

import pytest
import uvicorn
from scope_fixtures import agent
from sqlalchemy import text
from test_execution import targets
from test_human_surface import credential

from execbound.app import create_app
from execbound.execution import decide_approval
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys


@pytest.fixture
def console(db, runtime):
    """The gateway with its console mounted, served over real HTTP at one origin."""
    with served(db, runtime) as origin:
        yield origin


@contextmanager
def served(db, runtime):
    """`create_app` over one runtime, served over real HTTP at one loopback origin, which is
    also the console's own origin, so a download names the origin it was fetched from."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        human = HumanConfig(origin, TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}))
        app = create_app(db, runtime=runtime, human=human)
        server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started
        try:
            yield origin
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive()


def approve_pending(db, world):
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        approval_id = conn.execute(
            text(
                "SELECT approval_id FROM execbound.approvals "
                "WHERE tenant_id=:t AND state='PENDING' ORDER BY created_at DESC LIMIT 1"
            ),
            {"t": tenant},
        ).scalar_one_or_none()
    if approval_id is not None:
        decide_approval(db, world["human"], approval_id, "APPROVE", world["clock"])
    return approval_id


def selector(req):
    return {
        "kind": req.target.kind,
        "value": req.target.value,
        "incident_id": str(req.claimed_context.incident_id),
    }


def domain_controller(engine, world):
    """A Tier-0 resource the harness policy forbids outright."""
    tenant = world["identity"].tenant_id
    resource, incident, canonical = uuid4(), uuid4(), uuid4()
    p = {
        "t": tenant,
        "a": world["account"],
        "r": resource,
        "i": incident,
        "c": canonical,
        "s": world["inventory"],
        "z": world["incident_source"],
        "n": world["clock"].now(),
    }
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO execbound.canonical_targets VALUES (:t,:c,:n)"), p)
        conn.execute(
            text(
                "INSERT INTO execbound.resources "
                "(tenant_id,account_id,provider,resource_type,resource_id,provider_id,"
                "version,source_id,role,environment,criticality,observed_at) "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,CAST(:r AS text),"
                "'v1',:s,'domain_controller','production',4,:n)"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resource_identities "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:c)"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.incidents "
                "(tenant_id,account_id,provider,resource_type,incident_id,resource_id,"
                "source_id,version,status,severity,observed_at) "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:i,:r,:z,'v1','OPEN','CRITICAL',:n)"
            ),
            p,
        )
    return {"kind": "canonical", "value": str(resource), "incident_id": str(incident)}


def provision_mock(live_provider, engine, world):
    """The protected mock holds every registry resource at the registry's version."""
    tenant, account = world["identity"].tenant_id, world["account"]
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT ri.canonical_target_id, r.provider_id, r.version "
                "FROM execbound.resource_identities ri JOIN execbound.resources r "
                "ON r.tenant_id=ri.tenant_id AND r.resource_id=ri.resource_id "
                "WHERE ri.tenant_id=:t"
            ),
            {"t": tenant},
        ).all()
    for canonical, provider_id, version in rows:
        if live_provider.store.resource(tenant, canonical) is None:
            live_provider.store.provision_resource(tenant, canonical, version)
            live_provider.store.provision_representation(tenant, account, provider_id, canonical)


@pytest.fixture
def private(tmp_path, console, world, seeded, admin_engine, db, live_provider):
    """A private directory in the documented layout for the world's tenant."""
    pool = [selector(req) for req in targets(admin_engine, world, 24)]
    tier0 = domain_controller(admin_engine, world)
    with admin_engine.begin() as conn:
        for table in ("resources", "resource_facts", "incidents"):
            conn.execute(
                text(f"UPDATE execbound.{table} SET demo_fixture=true WHERE tenant_id=:t"),
                {"t": world["identity"].tenant_id},
            )
    provision_mock(live_provider, admin_engine, world)
    second = agent(admin_engine, db, world)
    for name, token in (
        ("agent-a.token", seeded["tokens"][0]),
        ("agent-b.token", credential(admin_engine, second)),
        ("admin.token", credential(admin_engine, world["admin"])),
    ):
        (tmp_path / name).write_text(token + "\n", encoding="ascii")
    (tmp_path / "bundle.json").write_text(
        json.dumps(world["bundle"].model_dump(mode="json")), encoding="utf-8"
    )
    sandbox = {
        "origin": console,
        "tenant_id": str(world["identity"].tenant_id),
        "credentials": {
            "agent_a": "agent-a.token",
            "agent_b": "agent-b.token",
            "admin": "admin.token",
        },
        "providers": {"mock CrowdStrike": live_provider.config.origin},
        "bundle": "bundle.json",
        "targets": {
            "workstation": pool[0],
            "domain_controller": tier0,
            "production": {
                "kind": "hostname",
                "value": "ws01.example",
                "incident_id": str(world["incident"]),
            },
            "pool": pool[1:],
        },
    }
    (tmp_path / "sandbox.json").write_text(json.dumps(sandbox, indent=1), encoding="utf-8")
    return tmp_path
