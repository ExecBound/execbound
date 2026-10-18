# SPDX-License-Identifier: AGPL-3.0-only
"""A personal access token reaches no agent route.

An administrator's `ebp1.` token is a person's credential for the console API, and among the
writes it may make there is issuing an agent's key. What keeps it off the agent surface is
that every agent route authenticates through `identity.authenticate`, which parses only an
agent's `eb1.` credential, so a live token is malformed there. That was read, not executed;
this file executes it.

A real token is minted for an administrator and presented as the bearer at every route
`test_route_authority` declares an agent route, in the construction that serves it: the
execution, status, outcome, listing and identity routes, the MCP mount's tool listing and
each tool it advertises, and the two Arcade hooks where an `arcade` block is configured. Each
answer must be the 401 an `ebp1.` token nobody holds is given, with the same unattributed
failure counter and nothing else: no execution (the frozen plan lives on its row), no
execution key, event, impact or claim, no approval, no audit event, and the token's own row
never looked up. The same request with the agent's own key then gets past authentication, so
what refused the token was the credential and not the request. The routes and the tools are
read from the inventory and the MCP surface, so an agent route or a tool added later is
presented with a token here without anyone editing this file.
"""

import secrets
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_human_surface import human_config as human_config
from test_resolution import request
from test_route_authority import AGENT, ARCADE, ARCADE_BLOCK, ASSISTANT, PLUGINS, SAMPLE, SERVED
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound.app import create_app
from execbound.personal_tokens import issue_token
from execbound.surfaces.mcp import TOOLS
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration

ORIGIN = "http://127.0.0.1"
API = "/api/console/v1"

# The constructions `test_route_authority` pins that declare an agent route: the deployment
# with no optional block, and one whose `arcade` block adds the two hooks. The other two
# declare none, which the first test below holds.
CONSTRUCTIONS: dict[str, dict[tuple[str, str], str]] = {"plain": SERVED, "arcade": ARCADE}
AGENT_ROUTES = sorted(
    (construction, route)
    for construction, inventory in CONSTRUCTIONS.items()
    for route, authority in inventory.items()
    if authority == AGENT
)

# Everything an agent request could leave behind besides a failure counter. A plan is frozen
# on its execution's row, so no execution is no plan.
LEDGER = (
    "executions",
    "execution_keys",
    "execution_events",
    "execution_impact",
    "resource_claims",
    "approvals",
    "approval_notifications",
    "approval_decisions",
    "arcade_hooks",
    "agent_runs",
    "audit_events",
)
MCP_VERSION = "2026-07-28"
MCP_META = {
    "io.modelcontextprotocol/protocolVersion": MCP_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
}


@dataclass(frozen=True)
class Call:
    """One request at one agent route, sent with whichever bearer the test presents."""

    method: str
    path: str
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        """The method and path, and for an MCP message what it asks for; never the body."""
        asked = [self.headers[name] for name in ("MCP-Method", "MCP-Name") if name in self.headers]
        return " ".join([self.method, self.path, *asked])


def mcp(method: str, params: dict[str, Any]) -> Call:
    """One JSON-RPC message to the MCP mount, framed as `test_action_listing` frames one."""
    return Call(
        "POST",
        "/mcp/",
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": {"_meta": MCP_META, **params}},
        {
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_VERSION,
            "MCP-Method": method,
            **({"MCP-Name": params["name"]} if "name" in params else {}),
        },
    )


def calls(route: tuple[str, str], world) -> list[Call]:
    """The requests that present a bearer at one route, each well formed, so that what refuses
    a token is its credential. A route this table does not name gets a bare request of its
    method, which still meets the route's authentication before anything else."""
    path, method = route
    if method == "MOUNT":
        arguments: dict[str, dict[str, Any]] = {
            "execute": {"request": request(world).model_dump(mode="json")},
            "execution_status": {"execution_id": str(uuid4())},
        }
        return [mcp("tools/list", {})] + [
            mcp("tools/call", {"name": tool.name, "arguments": arguments.get(tool.name, {})})
            for tool in TOOLS
        ]
    concrete = path.format(**{**SAMPLE, "execution_id": str(uuid4())})
    if method == "GET":
        return [Call("GET", concrete)]
    bodies: dict[tuple[str, str], Any] = {
        ("/v1/execute", "POST"): request(world).model_dump(mode="json"),
        # A report a token holder might forge; the secret names no grant.
        ("/v1/executions/{execution_id}/outcome", "POST"): {
            "report_secret": secrets.token_urlsafe(32)
        },
    }
    return [Call(method, concrete, bodies.get(route, {}))]


def send(client: TestClient, call: Call, token: str):
    headers = {"Authorization": "Bearer " + token, **call.headers}
    if call.method == "GET":
        return client.get(call.path, headers=headers)
    return client.post(call.path, json=call.body, headers=headers)


def answer(response) -> tuple[int, bytes, str | None]:
    """What a caller learns from a refusal: the status, the body and the challenge."""
    return response.status_code, response.content, response.headers.get("www-authenticate")


def ledger(admin_engine) -> tuple[dict[str, int], Counter[tuple[Any, ...]]]:
    """Every row count an agent request could change, and the failure counters by key."""
    with admin_engine.connect() as conn:
        counts = {
            table: int(conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one())
            for table in LEDGER
        }
        failures: Counter[tuple[Any, ...]] = Counter()
        for row in conn.execute(
            text(
                "SELECT surface, reason, tenant_id, subject_kind, subject_id, count "
                "FROM execbound.authentication_failures"
            )
        ):
            failures[tuple(row[:5])] += int(row[5])
    return counts, failures


def last_used(admin_engine, token_id: UUID):
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT last_used_at FROM execbound.personal_access_tokens WHERE token_id=:k"),
            {"k": token_id},
        ).scalar_one()


def minted(runtime, administrator) -> tuple[str, UUID]:
    """A real token for a signed-in administrator, through the store the console uses."""
    grant = issue_session(runtime.db, administrator, clock=runtime.clock)
    session = load_session(runtime.db, grant.token, clock=runtime.clock)
    token, view = issue_token(runtime.db, session, "ci", timedelta(days=1), clock=runtime.clock)
    return token, UUID(view["token_id"])


def test_only_the_constructions_built_here_declare_an_agent_route():
    """An assistant or plugins block that one day adds an agent route fails here until its
    construction is added above, rather than leaving that route untested with a token."""
    for inventory in (ASSISTANT, PLUGINS):
        assert AGENT not in inventory.values()
    assert {route for _, route in AGENT_ROUTES} >= {
        ("/v1/execute", "POST"),
        ("/v1/executions/{execution_id}", "GET"),
        ("/v1/executions/{execution_id}/outcome", "POST"),
        ("/v1/actions", "GET"),
        ("/mcp", "MOUNT"),
        ("/pre", "POST"),
        ("/post", "POST"),
    }
    assert {tool.name for tool in TOOLS} == {"execute", "execution_status", "list_actions"}


@pytest.mark.parametrize(
    "construction,route",
    AGENT_ROUTES,
    ids=[f"{construction}:{route[1]} {route[0]}" for construction, route in AGENT_ROUTES],
)
def test_a_personal_access_token_is_refused_at_every_agent_route(
    construction, route, db, runtime, human_config, world, seeded, admin_engine
):
    token, token_id = minted(runtime, world["admin"])
    # An `ebp1.` token of the same shape that nobody holds: the refusal to match.
    unknown = f"ebp1.{world['admin'].tenant_id}.{uuid4()}.{secrets.token_urlsafe(32)}"
    blocks = {"arcade": ARCADE_BLOCK} if construction == "arcade" else {}
    app = create_app(db, runtime=runtime, human=human_config, **blocks)
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        for call in calls(route, world):
            before = ledger(admin_engine)
            refused = send(client, call, token)
            between = ledger(admin_engine)
            guessed = send(client, call, unknown)
            after = ledger(admin_engine)
            where = call.label
            assert refused.status_code == 401, (where, refused.status_code, refused.text)
            assert answer(refused) == answer(guessed), (where, "answered unlike an unknown token")
            # Nothing admitted, planned, reserved, claimed, put up for approval or audited.
            assert between[0] == before[0], (where, "the token left rows", between[0])
            assert after[0] == between[0], (where, "an unknown token left rows", after[0])
            # The failure counter an unknown token leaves, naming no tenant and no token.
            counted = between[1] - before[1]
            assert counted == after[1] - between[1], (where, "counted unlike an unknown token")
            assert all(key[2:] == (None, None, None) for key in counted), (where, counted)
            # The route never looked the token up, so it never stamped it as used.
            assert last_used(admin_engine, token_id) is None, (where, "the token was looked up")
            # The same request with the agent's own key gets past authentication.
            allowed = send(client, call, seeded["tokens"][0])
            assert allowed.status_code != 401, (where, allowed.status_code, allowed.text)
        # And the token was live all along: the console API takes it as its owner.
        owned = client.get(API + "/agents", headers={"Authorization": "Bearer " + token})
        assert owned.status_code == 200, owned.text
