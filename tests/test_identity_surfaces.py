# SPDX-License-Identifier: AGPL-3.0-only
"""All identity operations through real Chromium and both maintained MCP clients."""

import asyncio
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID, uuid4

import httpx2
import pytest
from identity_fixtures import ACTIONS, add_target, identity_request
from identity_fixtures import identity_connector as identity_connector
from identity_fixtures import identity_provider as identity_provider
from identity_fixtures import identity_world as identity_world
from identity_fixtures import registry as registry
from identity_fixtures import world as world
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_surfaces import agent_http as agent_http
from test_browser_surfaces import browser_gateway as browser_gateway
from test_browser_surfaces import capture_reviews, open_activity, open_approval, sign_in
from test_browser_surfaces import chromium as chromium
from test_browser_surfaces import human_page as human_page
from test_execution import activate
from test_identity_execution import invocations
from test_identity_execution import runtime as runtime

from execbound.execution import decide_approval
from execbound.operations import operation


def production(engine, world):
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET environment='production' WHERE account_id=:a"),
            {"a": world["account"]},
        )


@pytest.mark.parametrize("action", ACTIONS)
def test_identity_browser_approval_all_operations(
    human_page, agent_http, identity_world, identity_provider, admin_engine, action, tmp_path
):
    world, page = identity_world, human_page
    production(admin_engine, world)
    body = identity_request(world, action).model_dump(mode="json")
    first = agent_http.post("/v1/execute", json=body)
    assert first.status_code == 202 and first.json()["state"] == "PENDING_APPROVAL"
    # An assignment for another identity action cannot reveal or approve this one.
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.approval_scopes SET active=false WHERE action=:a"), {"a": action}
        )
    sign_in(page, admin_engine, world)
    expect(page.get_by_text("Nothing is waiting for you.").first).to_be_visible()
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.approval_scopes SET active=true WHERE action=:a"), {"a": action}
        )
    open_approval(page, first.json()["approval_id"])
    expect(page.get_by_role("heading", level=2, name=world["provider_id"])).to_be_visible()
    expect(page.get_by_text(operation(action).label).first).to_be_visible()
    expect(page.get_by_role("rowheader", name="privilege class", exact=True)).to_be_visible()
    expect(page.get_by_role("cell", name="standard", exact=True)).to_be_visible()
    approve = page.get_by_role("button", name=re.compile(r"^Approve\b"))
    capture_reviews(page, action + "-approval", [approve], tmp_path / "ui-review")
    approve.click()
    expect(page.get_by_text("Nothing is waiting for you.").first).to_be_visible()
    executed = agent_http.post("/v1/execute", json=body)
    assert executed.status_code == 200 and executed.json()["state"] == "EXECUTED"
    assert agent_http.post("/v1/execute", json=body).json() == executed.json()
    open_activity(page)
    expect(page.get_by_text(operation(action).label).first).to_be_visible()
    expect(page.get_by_text("Executed", exact=True).first).to_be_visible()
    capture_reviews(
        page,
        action + "-activity",
        [page.get_by_role("link", name="Activity").first],
        tmp_path / "ui-review",
    )
    assert len(invocations(identity_provider)) == 1


@pytest.mark.parametrize("action", ACTIONS)
def test_current_and_legacy_mcp_match_http_for_every_identity_action(
    browser_gateway, agent_http, identity_world, identity_provider, seeded, db, admin_engine, action
):
    world = identity_world
    production(admin_engine, world)
    body = identity_request(world, action).model_dump(mode="json")

    async def check():
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + seeded["tokens"][0]}, trust_env=False
        ) as http:
            async with Client(
                streamable_http_client(browser_gateway + "/mcp/", http_client=http)
            ) as client:
                pending = await client.call_tool("execute", {"request": body})
                assert (
                    not pending.is_error
                    and pending.structured_content["state"] == "PENDING_APPROVAL"
                )
                first = pending.structured_content
                http.headers["Authorization"] = "Bearer " + seeded["tokens"][1]
                foreign = await client.call_tool(
                    "execution_status", {"execution_id": first["execution_id"]}
                )
                assert foreign.is_error and foreign.structured_content["code"] == "NOT_FOUND"
                http.headers["Authorization"] = "Bearer " + seeded["tokens"][0]
                decide_approval(
                    db, world["human"], UUID(first["approval_id"]), "APPROVE", world["clock"]
                )
                result = agent_http.post("/v1/execute", json=body)
                assert result.json()["state"] == "EXECUTED"
                retry = await client.call_tool("execute", {"request": body})
                assert not retry.is_error and retry.structured_content == result.json()
                assert client.protocol_version == "2026-07-28"
                return result.json()

    # Works even when this module's real browser fixture has a live driver loop.
    with ThreadPoolExecutor(max_workers=1) as pool:
        executed = pool.submit(lambda: asyncio.run(check())).result(timeout=20)
    completed = subprocess.run(
        [sys.executable, "tests/mcp_legacy_probe.py"],
        input=json.dumps(
            {
                "url": browser_gateway + "/mcp/",
                "token": seeded["tokens"][0],
                "other_token": seeded["tokens"][1],
                "request": body,
            }
        ),
        capture_output=True,
        text=True,
        timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    assert completed.returncode == 0, "Maintained MCP client did not complete"
    result = json.loads(completed.stdout)
    assert result["protocol"] == "2025-11-25"
    assert result["first"] == executed == result["retry"]
    assert result["foreign_error"] and result["foreign"]["code"] == "NOT_FOUND"
    assert len(invocations(identity_provider)) == 1


@pytest.mark.parametrize("action", ACTIONS)
def test_http_mcp_concurrent_approved_identity_actions_share_tenant_cap(
    browser_gateway, agent_http, identity_world, identity_provider, seeded, db, admin_engine, action
):
    world = identity_world
    second = add_target(admin_engine, world)
    identity_provider.store.provision_resource(
        world["identity"].tenant_id, second["canonical"], "resource-v1"
    )
    identity_provider.store.provision_representation(
        world["identity"].tenant_id, world["account"], second["provider_id"], second["canonical"]
    )
    production(admin_engine, world)
    activate(
        db,
        world,
        limits=tuple(
            rule.model_copy(update={"max_targets": 1})
            if rule.action == action and rule.scope == "tenant"
            else rule
            for rule in world["bundle"].limits
        ),
    )
    bodies = [
        identity_request(target, action, idempotency_key=str(uuid4())).model_dump(mode="json")
        for target in (world, second)
    ]
    for body in bodies:
        pending = agent_http.post("/v1/execute", json=body).json()
        assert pending["state"] == "PENDING_APPROVAL"
        decide_approval(db, world["human"], UUID(pending["approval_id"]), "APPROVE", world["clock"])
    barrier = Barrier(2)

    def rest():
        barrier.wait(timeout=10)
        return agent_http.post("/v1/execute", json=bodies[0]).json()["state"]

    async def mcp():
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + seeded["tokens"][0]}, trust_env=False
        ) as http:
            async with Client(
                streamable_http_client(browser_gateway + "/mcp/", http_client=http)
            ) as client:
                barrier.wait(timeout=10)
                result = await client.call_tool("execute", {"request": bodies[1]})
                assert not result.is_error
                return result.structured_content["state"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second_result = pool.submit(rest), pool.submit(lambda: asyncio.run(mcp()))
        assert sorted([first.result(timeout=20), second_result.result(timeout=20)]) == [
            "DENIED",
            "EXECUTED",
        ]
    assert len(invocations(identity_provider)) == 1
