# SPDX-License-Identifier: AGPL-3.0-only
"""Every route declares the authority it needs, and an agent credential is refused at each one.

The credential boundary rests on a route inventory that was read once, by hand. A route
added later could be reachable by a protected agent and nothing would notice, so the inventory
lives here instead of in a document: a new route fails this file until it is classified, and a
route that needs a signed-in human or an administrator is exercised with an agent credential
rather than assumed to refuse one.

The inventory is pinned for four constructions, because three blocks of the private
configuration file add routes: a deployment without them serves the set below, one with
`arcade` serves that set and the two hooks, one with `assistant` serves it and the
assistant's routes, and one whose `plugins` block names the sample plugin serves it and the
five routes the sample adds. No answer is left to be inferred from another. A `signups`
block adds nothing here any more: `/signup*` is a plugin's own, pinned in that plugin's
route authority tests (#496).
"""

import ast
import secrets
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from plugin_fixtures import sample as sample
from signal_fixtures import insert_source
from sqlalchemy import text
from test_human_surface import human_config as human_config
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_signal_envelope import body as signal_body

from execbound.app import create_app
from execbound.arcade import ArcadeBlock
from execbound.assistant.config import AssistantConfig
from execbound.plugins import load_plugins
from execbound.surfaces import console_api as console_api_package
from execbound.surfaces.console_api.token_rules import (
    TOKEN_ALLOWED,
    TOKEN_BODY_LIMITS,
    TOKEN_REFUSED,
    token_allowed,
)
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

PUBLIC = "public"
AGENT = "agent"
SOURCE = "monitoring source"
SIGNAL_SOURCE = "signal source"
SESSION = "signed-in human or administrator"

# Every route the application serves, with the authority it requires. A route missing from this
# map, or one whose methods change, fails the first test below.
AUTHORITY = {
    ("/account/link/{provider}", "POST"): SESSION,
    ("/health/live", "GET"): PUBLIC,
    ("/assets/account-security.js", "GET"): PUBLIC,
    ("/mfa", "GET"): SESSION,
    ("/account/security", "GET"): SESSION,
    ("/account/security/password", "POST"): SESSION,
    ("/account/security/{operation}", "POST"): SESSION,
    ("/account/security/passkey/{kind}/{stage}", "POST"): SESSION,
    ("/health/ready", "GET"): PUBLIC,
    ("/assets/app.css", "GET"): PUBLIC,
    ("/login", "GET"): PUBLIC,
    ("/session", "POST"): PUBLIC,
    # Regular sign-in: the password form, the two halves of a configured provider's flow
    # and the page a one-time code sets a password on. All five run before a session exists,
    # so all five are public, and each carries the CSRF cookie, the exact Origin and the rate
    # limits. The provider routes are one pair however many providers are configured, and a
    # name that is not one of them answers 404.
    ("/session/password", "POST"): PUBLIC,
    ("/login/{provider}", "POST"): PUBLIC,
    ("/login/{provider}/callback", "GET"): PUBLIC,
    ("/set-password", "GET"): PUBLIC,
    ("/set-password", "POST"): PUBLIC,
    # A customer's own identity provider (#177, #241). The two halves of the flow and the
    # invitation form run before a session exists, so they are public and carry the CSRF
    # cookie, the exact Origin and the rate limits; the self-link needs a session and is a
    # navigation, which is why it takes no CSRF field and a cross-site one answers 401. All
    # five exist whatever the private configuration says and answer 404 without a key ring,
    # so there is no fifth construction to pin. `/login/directory/callback` is declared before
    # `/login/{provider}/callback`, which would otherwise match it.
    ("/login/directory/callback", "GET"): PUBLIC,
    ("/login/directory/{provider_id}", "POST"): PUBLIC,
    ("/login/directory/{provider_id}/link", "GET"): SESSION,
    ("/invite", "GET"): PUBLIC,
    ("/invite", "POST"): PUBLIC,
    # Teammate invitations (#487). `/join`, not `/invite`: that address already belongs to
    # the customer-directory one-time code above, registered first in `app.py`.
    ("/join", "GET"): PUBLIC,
    ("/join", "POST"): PUBLIC,
    # The weekly summary's one-click unsubscribe (#678): no session, by RFC 8058's design.
    ("/weekly-summary/unsubscribe/{link}", "GET"): PUBLIC,
    ("/weekly-summary/unsubscribe/{link}", "POST"): PUBLIC,
    ("/join/accept", "POST"): PUBLIC,
    ("/join/confirm", "POST"): SESSION,
    ("/assets/invite.js", "GET"): PUBLIC,
    ("/v1/me", "GET"): AGENT,
    ("/v1/execute", "POST"): AGENT,
    ("/v1/actions", "GET"): AGENT,
    ("/v1/executions/{execution_id}", "GET"): AGENT,
    ("/v1/executions/{execution_id}/outcome", "POST"): AGENT,
    ("/mcp", "MOUNT"): AGENT,
    ("/v1/monitor/events", "POST"): SOURCE,
    ("/v1/signals", "POST"): SIGNAL_SOURCE,
    # The pages that stay server-rendered, because they run before a session exists or
    # because a phone whose console does not load still has to decide (#333).
    ("/session/logout", "POST"): SESSION,
    ("/approvals/{approval_id}/classic", "GET"): SESSION,
    ("/approvals/{approval_id}/decide", "POST"): SESSION,
}

# Where the pages the console replaced used to answer (#333). Each is a permanent
# redirect and nothing else: no session is read, no row is touched and the answer is a
# `Location` header, so a bookmark arrives without anyone having to be signed in first.
REDIRECTS = {
    ("/admin/approvers", "GET"): PUBLIC,
    ("/admin/credentials", "GET"): PUBLIC,
    ("/admin/people", "GET"): PUBLIC,
    ("/admin/people/{principal_id}", "GET"): PUBLIC,
    ("/admin/settings", "GET"): PUBLIC,
    ("/policy/rules", "GET"): PUBLIC,
    ("/monitor/{view}", "GET"): PUBLIC,
    ("/next", "GET"): PUBLIC,
    ("/next/{route:path}", "GET"): PUBLIC,
}

# What an `arcade` block adds, and nothing else. Both hooks authenticate the same agent
# credential the execution routes do, through the same `checked_request`; what makes them
# their own surface is the shape of the answer and not the authority behind it.
ARCADE = {
    ("/pre", "POST"): AGENT,
    ("/post", "POST"): AGENT,
}
# One declared tool is not needed to serve the routes; the block is what adds them.
ARCADE_BLOCK = ArcadeBlock(deadline_seconds=4.0)

# The console: its own document at every one of its routes, its build's files, and its API
# (#333). The document needs a session exactly as a page did; the build's files are
# as public as `/assets/app.css`, because a stylesheet and a font are nobody's tenant.
CONSOLE = {
    ("/console/{file:path}", "GET"): PUBLIC,
    # The mark, where a browser asks for it without being told to. The same two files the
    # build serves under `/console/`, and public for the same reason: an icon is nobody's
    # tenant, and the pages that run before a session exists link it.
    ("/favicon.ico", "GET"): PUBLIC,
    ("/favicon.svg", "GET"): PUBLIC,
    ("/", "GET"): SESSION,
    ("/activity", "GET"): SESSION,
    ("/agents", "GET"): SESSION,
    ("/agents/{agent_id}", "GET"): SESSION,
    ("/approvals", "GET"): SESSION,
    ("/approvals/{approval_id}", "GET"): SESSION,
    ("/approvers", "GET"): SESSION,
    ("/access", "GET"): SESSION,
    ("/api/console/v1/access", "GET"): SESSION,
    ("/api/console/v1/access/users/{principal_id}/roles", "POST"): SESSION,
    ("/api/console/v1/access/groups", "POST"): SESSION,
    ("/api/console/v1/access/groups/{group_id}", "POST"): SESSION,
    ("/api/console/v1/access/groups/{group_id}/delete", "POST"): SESSION,
    ("/api/console/v1/access/groups/{group_id}/members", "POST"): SESSION,
    ("/api/console/v1/access/groups/{group_id}/roles", "POST"): SESSION,
    ("/api/console/v1/approval-rules", "GET"): SESSION,
    ("/api/console/v1/approval-coverage", "GET"): SESSION,
    ("/api/console/v1/approval-coverage/unrouted", "GET"): SESSION,
    ("/api/console/v1/approval-rules", "POST"): SESSION,
    ("/api/console/v1/approval-rules/{rule_id}", "POST"): SESSION,
    ("/api/console/v1/approval-rules/{rule_id}/disable", "POST"): SESSION,
    ("/ask", "GET"): SESSION,
    ("/ask/{turn_id}", "GET"): SESSION,
    ("/board", "GET"): SESSION,
    ("/report", "GET"): SESSION,
    ("/credentials", "GET"): SESSION,
    ("/monitor", "GET"): SESSION,
    ("/monitor/agents/{agent_id}", "GET"): SESSION,
    ("/people", "GET"): SESSION,
    ("/people/{person_id}", "GET"): SESSION,
    ("/policy", "GET"): SESSION,
    ("/policy/{bundle_id}", "GET"): SESSION,
    ("/policy/{bundle_id}/rules", "GET"): SESSION,
    ("/settings", "GET"): SESSION,
    ("/help", "GET"): SESSION,
    ("/api/console/v1/account", "GET"): SESSION,
    ("/api/console/v1/account/profile", "POST"): SESSION,
    ("/api/console/v1/account/requests", "POST"): SESSION,
    ("/api/console/v1/account/requests", "GET"): SESSION,
    ("/api/console/v1/account/requests/resolve", "POST"): SESSION,
    ("/spaces", "GET"): SESSION,
    ("/tenant", "GET"): SESSION,
    ("/welcome", "GET"): SESSION,
    ("/api/console/v1/people/{principal_id}/email", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/password-link", "POST"): SESSION,
    # The tenant's own directory, on a person (#177, #241).
    ("/api/console/v1/people/{principal_id}/directory-invite", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/directory-invite/revoke", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/directory-link", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/directory-unlink", "POST"): SESSION,
    ("/api/console/v1/settings/password", "POST"): SESSION,
    ("/api/console/v1/session", "GET"): SESSION,
    ("/api/console/v1/session/verify", "POST"): SESSION,
    ("/api/console/v1/session/verify/passkey/options", "POST"): SESSION,
    ("/api/console/v1/session/verify/passkey", "POST"): SESSION,
    ("/api/console/v1/session/workspace", "POST"): SESSION,
    ("/api/console/v1/session/workspaces", "GET"): SESSION,
    ("/api/console/v1/client-errors", "POST"): SESSION,
    ("/api/console/v1/board", "GET"): SESSION,
    ("/api/console/v1/board/stream", "GET"): SESSION,
    ("/api/console/v1/approvals", "GET"): SESSION,
    ("/api/console/v1/approvals/{approval_id}", "GET"): SESSION,
    ("/api/console/v1/approvals/{approval_id}/decision", "POST"): SESSION,
    ("/api/console/v1/settings", "GET"): SESSION,
    ("/api/console/v1/settings/sessions/revoke-others", "POST"): SESSION,
    ("/api/console/v1/tenant", "GET"): SESSION,
    ("/api/console/v1/tenant/sign-in", "GET"): SESSION,
    ("/api/console/v1/tenant/sign-in", "POST"): SESSION,
    ("/api/console/v1/tenant/sign-in/{provider_id}/state", "POST"): SESSION,
    ("/api/console/v1/tenant/mode", "POST"): SESSION,
    ("/api/console/v1/tenant/deadline", "POST"): SESSION,
    ("/api/console/v1/tenant/stop", "POST"): SESSION,
    ("/api/console/v1/tenant/resume", "POST"): SESSION,
    ("/api/console/v1/monitor", "GET"): SESSION,
    ("/api/console/v1/monitor/setup/verify", "POST"): SESSION,
    ("/api/console/v1/monitor/agents", "GET"): SESSION,
    ("/api/console/v1/monitor/agents/{agent_id}", "GET"): SESSION,
    ("/api/console/v1/monitor/findings", "GET"): SESSION,
    ("/api/console/v1/monitor/findings/{finding_id}", "GET"): SESSION,
    ("/api/console/v1/monitor/findings/{finding_id}/acknowledge", "POST"): SESSION,
    ("/api/console/v1/monitor/findings/acknowledge", "POST"): SESSION,
    # Connecting monitoring from the console (#678): the same routes whether or not the
    # deployment configured a collector key; without one the changes answer
    # CONNECT_UNAVAILABLE.
    ("/api/console/v1/monitor/connect", "GET"): SESSION,
    ("/api/console/v1/monitor/connections/tines", "POST"): SESSION,
    ("/api/console/v1/monitor/connections/{connection_id}/key", "POST"): SESSION,
    ("/api/console/v1/monitor/connections/{connection_id}/collect", "POST"): SESSION,
    ("/api/console/v1/monitor/connections/{connection_id}/schedule", "POST"): SESSION,
    ("/api/console/v1/monitor/connections/{connection_id}/revoke", "POST"): SESSION,
    ("/api/console/v1/monitor/connections/entra/start", "POST"): SESSION,
    # Reporting sources from the console (#678): minting and rotation answer
    # CONNECT_UNAVAILABLE without console connect, but every route is served everywhere.
    ("/api/console/v1/monitor/sources", "POST"): SESSION,
    ("/api/console/v1/monitor/sources/{source_id}", "GET"): SESSION,
    ("/api/console/v1/monitor/sources/{source_id}/rotate", "POST"): SESSION,
    ("/api/console/v1/monitor/sources/{source_id}/revoke", "POST"): SESSION,
    ("/api/console/v1/agents", "GET"): SESSION,
    ("/api/console/v1/agents", "POST"): SESSION,
    ("/api/console/v1/agents/{row_id}", "GET"): SESSION,
    ("/api/console/v1/agents/{principal_id}/label", "POST"): SESSION,
    ("/api/console/v1/agents/{principal_id}/credentials/issue", "POST"): SESSION,
    ("/api/console/v1/agents/{principal_id}/credentials/{credential_id}/revoke", "POST"): SESSION,
    ("/api/console/v1/agents/{principal_id}/credentials/{credential_id}/delete", "POST"): SESSION,
    ("/api/console/v1/agents/{principal_id}/deactivate", "POST"): SESSION,
    ("/api/console/v1/agents/{principal_id}/reactivate", "POST"): SESSION,
    ("/api/console/v1/agents/{principal_id}/unbind", "POST"): SESSION,
    ("/api/console/v1/agents/{row_id}/bind", "POST"): SESSION,
    ("/api/console/v1/agents/{row_id}/govern", "POST"): SESSION,
    ("/api/console/v1/people", "GET"): SESSION,
    ("/api/console/v1/people", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}", "GET"): SESSION,
    ("/api/console/v1/people/{principal_id}/label", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/credentials/issue", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/credentials/{credential_id}/revoke", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/scopes/assign", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/scopes/unassign", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/sessions/end", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/deactivate", "POST"): SESSION,
    ("/api/console/v1/people/{principal_id}/reactivate", "POST"): SESSION,
    ("/api/console/v1/credentials", "GET"): SESSION,
    ("/api/console/v1/credentials/expiring", "GET"): SESSION,
    ("/api/console/v1/credentials/issue", "POST"): SESSION,
    ("/api/console/v1/credentials/{credential_id}/revoke", "POST"): SESSION,
    ("/api/console/v1/credentials/{credential_id}/delete", "POST"): SESSION,
    ("/api/console/v1/approvers", "GET"): SESSION,
    ("/api/console/v1/approvers/assign", "POST"): SESSION,
    ("/api/console/v1/approvers/unassign", "POST"): SESSION,
    ("/api/console/v1/welcome/example", "POST"): SESSION,
    ("/api/console/v1/connection", "GET"): SESSION,
    ("/api/console/v1/samples", "GET"): SESSION,
    ("/api/console/v1/samples", "POST"): SESSION,
    ("/api/console/v1/samples/remove", "POST"): SESSION,
    ("/api/console/v1/samples/refresh", "POST"): SESSION,
    ("/api/console/v1/samples/demo-configuration", "GET"): SESSION,
    ("/api/console/v1/setup", "GET"): SESSION,
    ("/api/console/v1/overview", "GET"): SESSION,
    ("/api/console/v1/report", "GET"): SESSION,
    ("/api/console/v1/settings/weekly-summary", "POST"): SESSION,
    ("/api/console/v1/report.csv", "GET"): SESSION,
    ("/api/console/v1/executions", "GET"): SESSION,
    ("/api/console/v1/executions/{execution_id}", "GET"): SESSION,
    ("/api/console/v1/executions/{execution_id}/reconcile", "POST"): SESSION,
    ("/api/console/v1/search", "GET"): SESSION,
    ("/api/console/v1/policy", "GET"): SESSION,
    ("/api/console/v1/policy", "POST"): SESSION,
    ("/api/console/v1/policy/{bundle_id}", "GET"): SESSION,
    ("/api/console/v1/policy/{bundle_id}/compare", "GET"): SESSION,
    ("/api/console/v1/policy/{bundle_id}/ruleset", "GET"): SESSION,
    ("/api/console/v1/policy/{bundle_id}/validate", "POST"): SESSION,
    ("/api/console/v1/policy/{bundle_id}/preview", "POST"): SESSION,
    ("/api/console/v1/policy/{bundle_id}/activate", "POST"): SESSION,
    ("/api/console/v1/policy/{bundle_id}/retire", "POST"): SESSION,
    ("/api/console/v1/policy/{bundle_id}/rules", "GET"): SESSION,
    ("/api/console/v1/policy/{bundle_id}/rules", "POST"): SESSION,
    # Spaces: the list and the create, one space and its five changes, and the one
    # mutation that changes which space a session is looking at.
    ("/api/console/v1/spaces", "GET"): SESSION,
    ("/api/console/v1/spaces", "POST"): SESSION,
    ("/api/console/v1/spaces/{space_id}", "GET"): SESSION,
    ("/api/console/v1/spaces/{space_id}/rename", "POST"): SESSION,
    ("/api/console/v1/spaces/{space_id}/archive", "POST"): SESSION,
    ("/api/console/v1/spaces/{space_id}/unarchive", "POST"): SESSION,
    ("/api/console/v1/spaces/{space_id}/members/assign", "POST"): SESSION,
    ("/api/console/v1/spaces/{space_id}/members/unassign", "POST"): SESSION,
    ("/api/console/v1/session/space", "POST"): SESSION,
    # Teammate invitations (#487): the service itself re-checks `access.manage` inside
    # its own fenced transaction on every call, so the route's own authority is the same session
    # every console API route needs, never a role this file assumes.
    ("/api/console/v1/teammate-invitations", "GET"): SESSION,
    ("/api/console/v1/teammate-invitations", "POST"): SESSION,
    ("/api/console/v1/teammate-invitations/{id}/resend", "POST"): SESSION,
    ("/api/console/v1/teammate-invitations/{id}/revoke", "POST"): SESSION,
    # Personal access tokens: an administrator's own, under `/settings/tokens`, and the
    # workspace's, under `/tenant/tokens`.
    ("/api/console/v1/settings/tokens", "GET"): SESSION,
    ("/api/console/v1/settings/tokens/issue", "POST"): SESSION,
    ("/api/console/v1/settings/tokens/{token_id}/revoke", "POST"): SESSION,
    ("/api/console/v1/settings/tokens/{token_id}/delete", "POST"): SESSION,
    ("/api/console/v1/tenant/tokens", "GET"): SESSION,
    ("/api/console/v1/tenant/tokens/{token_id}/revoke", "POST"): SESSION,
}

# What an `assistant` block adds on top of the console, and nothing else (#330). Without the
# block these addresses do not exist, which is why they are their own construction rather than
# rows of `CONSOLE`: a deployment that configured no model has no assistant to refuse.
ASSISTANT = {
    ("/api/console/v1/assistant/turns", "GET"): SESSION,
    ("/api/console/v1/assistant/turns", "POST"): SESSION,
    ("/api/console/v1/assistant/turns/{turn_id}", "GET"): SESSION,
    ("/api/console/v1/assistant/turns/{turn_id}/events", "GET"): SESSION,
    ("/api/console/v1/assistant/turns/{turn_id}/opened", "POST"): SESSION,
    ("/api/console/v1/assistant/settings", "GET"): SESSION,
    ("/api/console/v1/assistant/settings", "POST"): SESSION,
    ("/api/console/v1/assistant/rules", "POST"): SESSION,
}
ASSISTANT_BLOCK = AssistantConfig(api_key="route-inventory-key")

# What a `plugins` block naming the sample plugin adds, and nothing else (#238, #496): its page,
# its console page and its console API area, each mounted after core's, and the two
# workspace-scoped approval addresses, which core mounts only where a plugin registered approval
# links (#496). Which routes a plugin adds is the plugin's own, so this pins the
# sample's; the construction is what shows that naming a plugin changes no core route.
PLUGINS = {
    ("/sample-plugin/hello", "GET"): PUBLIC,
    ("/sample-plugin", "GET"): SESSION,
    ("/api/console/v1/sample-plugin", "GET"): SESSION,
    ("/workspaces/{tenant_id}/approvals/{approval_id}", "GET"): SESSION,
    ("/workspaces/{tenant_id}/approvals/{approval_id}/classic", "GET"): SESSION,
}

# What the application serves with no `arcade` block and no `assistant` block: the pages that
# stay, the redirects that keep old addresses arriving, and the console.
SERVED = {**AUTHORITY, **REDIRECTS, **CONSOLE}

# Microsoft Entra admin consent's two browser routes (#678), served only where the private
# configuration's `scout` block names the platform app, and answering 404 everywhere else. Both
# run before any session can travel (Microsoft's callbacks are cross-site), so both are public:
# the binding cookie, a live attempt and its state are what admit a request.
ENTRA_CONSENT = {
    ("/connect/entra/signed-in", "POST"): PUBLIC,
    ("/connect/entra/consented", "GET"): PUBLIC,
}


ZERO = "00000000-0000-0000-0000-000000000000"
SAMPLE = {
    "link": "ebw1.malformed",
    "tenant_id": ZERO,
    "provider": "google",
    "operation": "enroll",
    "kind": "register",
    "stage": "start",
    "group_id": "00000000-0000-0000-0000-000000000000",
    "rule_id": "00000000-0000-0000-0000-000000000000",
    "execution_id": ZERO,
    "approval_id": ZERO,
    "credential_id": ZERO,
    "bundle_id": ZERO,
    "finding_id": ZERO,
    "connection_id": ZERO,
    "source_id": ZERO,
    "view": "connections",
    "agent_id": ZERO,
    "principal_id": ZERO,
    "row_id": ZERO,
    "route": "activity",
    "file": "tokens.css",
    "turn_id": ZERO,
    "person_id": ZERO,
    "provider_id": ZERO,
    "space_id": ZERO,
    "invitation_id": ZERO,
    "id": ZERO,
    "token_id": ZERO,
}


def served(app):
    """(path, method) for every route, following the routers the application includes."""

    def walk(routes):
        for route in routes:
            included = getattr(route, "original_router", None)
            if included is not None:
                yield from walk(included.routes)
            elif hasattr(route, "methods"):
                for method in route.methods or ():
                    yield (route.path, method)
            elif getattr(route, "routes", None) is not None:
                yield (route.path, "MOUNT")

    return {pair for pair in walk(app.routes) if pair[1] != "HEAD"}


@pytest.fixture
def surface(db, runtime, human_config):
    return create_app(db, runtime=runtime, human=human_config)


@pytest.fixture
def hook_surface(db, runtime, human_config):
    return create_app(db, runtime=runtime, human=human_config, arcade=ARCADE_BLOCK)


@pytest.fixture
def plugins_surface(db, runtime, human_config, sample):
    runtime.plugins = load_plugins({"sample_plugin": {}})
    return create_app(db, runtime=runtime, human=human_config)


@pytest.fixture
def assistant_surface(db, runtime):
    config = HumanConfig(
        "http://127.0.0.1",
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        assistant_enabled=True,
    )
    runtime.assistant = ASSISTANT_BLOCK
    return create_app(db, runtime=runtime, human=config)


def test_every_served_route_declares_the_authority_it_needs(surface):
    """A new route is a new place to get the boundary wrong; classify it here first."""
    assert served(surface) == set(SERVED)


def test_a_scout_block_serves_exactly_the_same_routes(db, runtime, surface, tmp_path):
    """Console connect configured or not, the console API's inventory is the same: its routes
    are served either way and refuse with CONNECT_UNAVAILABLE where no collector key or platform
    app was given (#678). A block that names the platform app adds the two browser routes of
    its consent, and nothing else."""
    from execbound.monitoring import sealing
    from execbound.surfaces.human import ScoutConfig, ScoutEntra

    collector = sealing.generate(tmp_path / "collector")
    keys = TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)})
    configured = HumanConfig("http://127.0.0.1", keys, scout=ScoutConfig(collector=collector))
    assert served(create_app(db, runtime=runtime, human=configured)) == served(surface)
    both = HumanConfig(
        "http://127.0.0.1",
        keys,
        scout=ScoutConfig(
            collector=collector,
            entra=ScoutEntra(
                "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", "organizations", "Synthetic Scout"
            ),
        ),
    )
    with_entra = served(create_app(db, runtime=runtime, human=both))
    assert with_entra == set(SERVED) | set(ENTRA_CONSENT)
    assert with_entra - served(surface) == set(ENTRA_CONSENT)


def test_an_arcade_block_adds_the_two_hooks_and_changes_nothing_else(surface, hook_surface):
    """The second construction, so the block's effect on the inventory is pinned both ways."""
    assert served(hook_surface) == set(SERVED) | set(ARCADE)
    assert served(hook_surface) - served(surface) == set(ARCADE)


@pytest.mark.parametrize(
    "path,method",
    sorted(route for route, authority in CONSOLE.items() if authority == SESSION),
)
def test_a_console_route_refuses_an_agent_credential(surface, seeded, path, method):
    concrete = path.replace(":path}", "}").format(**SAMPLE)
    headers = {"Authorization": "Bearer " + seeded["tokens"][0], "Origin": "http://127.0.0.1"}
    with TestClient(surface, base_url="http://127.0.0.1", follow_redirects=False) as client:
        response = (
            client.get(concrete, headers=headers)
            if method == "GET"
            else client.post(concrete, data={}, headers=headers)
        )
    assert response.status_code in {400, 401, 403}, response.status_code


def test_an_assistant_block_adds_its_routes_and_changes_nothing_else(surface, assistant_surface):
    """The third construction: what configuring a model adds, pinned both ways. Without the
    block the addresses do not exist at all: absent, not disabled."""
    assert served(assistant_surface) == set(SERVED) | set(ASSISTANT)
    assert served(assistant_surface) - served(surface) == set(ASSISTANT)


@pytest.mark.parametrize("path,method", sorted(ASSISTANT))
def test_an_assistant_route_refuses_an_agent_credential(assistant_surface, seeded, path, method):
    """An agent credential reaches no assistant route, as it reaches no other console route."""
    concrete = path.format(**SAMPLE)
    headers = {"Authorization": "Bearer " + seeded["tokens"][0], "Origin": "http://127.0.0.1"}
    with TestClient(assistant_surface, base_url="http://127.0.0.1", follow_redirects=False) as c:
        response = (
            c.get(concrete, headers=headers)
            if method == "GET"
            else c.post(
                concrete, content=b"{}", headers={**headers, "Content-Type": "application/json"}
            )
        )
    assert response.status_code in {400, 401, 403}, response.status_code


def test_a_plugins_block_adds_the_sample_routes_and_changes_nothing_else(surface, plugins_surface):
    """The fourth construction. The inventory is read from the route list alone, so it needs no
    console build: the console pages are declared either way and only answer 503 without one."""
    assert served(plugins_surface) == set(SERVED) | set(PLUGINS)
    assert served(plugins_surface) - served(surface) == set(PLUGINS)


@pytest.mark.parametrize(
    "path,method",
    sorted(route for route, authority in PLUGINS.items() if authority == SESSION),
)
def test_a_plugin_route_refuses_an_agent_credential(plugins_surface, seeded, path, method):
    """What naming a plugin adds refuses an agent credential as core's own routes do, the two
    workspace-scoped approval addresses included: their handlers are core's, mounted only
    where a plugin registered approval links (#496)."""
    concrete = path.format(**SAMPLE)
    headers = {"Authorization": "Bearer " + seeded["tokens"][0], "Origin": "http://127.0.0.1"}
    with TestClient(plugins_surface, base_url="http://127.0.0.1", follow_redirects=False) as c:
        response = (
            c.get(concrete, headers=headers)
            if method == "GET"
            else c.post(concrete, data={}, headers=headers)
        )
    assert response.status_code in {400, 401, 403}, response.status_code


def test_an_unknown_credential_reaches_neither_hook(hook_surface):
    """The hooks are agent routes, exercised with an agent credential like the rest."""
    unknown = f"eb1.{ZERO}.{ZERO}.{secrets.token_urlsafe(32)}"
    with TestClient(hook_surface, base_url="http://127.0.0.1") as client:
        for path, _ in sorted(ARCADE):
            response = client.post(path, json={}, headers={"Authorization": "Bearer " + unknown})
            assert response.status_code == 401, (path, response.status_code)


@pytest.mark.parametrize(
    "path,method",
    sorted(route for route, authority in AUTHORITY.items() if authority == SESSION),
)
def test_a_session_route_refuses_an_agent_credential(surface, seeded, path, method):
    concrete = path.format(**SAMPLE)
    headers = {"Authorization": "Bearer " + seeded["tokens"][0], "Origin": "http://127.0.0.1"}
    with TestClient(surface, base_url="http://127.0.0.1", follow_redirects=False) as client:
        response = (
            client.get(concrete, headers=headers)
            if method == "GET"
            else client.post(concrete, data={}, headers=headers)
        )
    assert response.status_code in {400, 401, 403}, response.status_code


def test_the_monitoring_intake_refuses_an_agent_credential(surface, seeded):
    headers = {"Authorization": "Bearer " + seeded["tokens"][0]}
    with TestClient(surface, base_url="http://127.0.0.1") as client:
        response = client.post("/v1/monitor/events", json={}, headers=headers)
    assert response.status_code in {400, 401, 403}, response.status_code


def test_the_signal_intake_refuses_an_agent_credential(surface, seeded):
    # A well-formed envelope, so what refuses is the credential and not the body.
    headers = {"Authorization": "Bearer " + seeded["tokens"][0]}
    with TestClient(surface, base_url="http://127.0.0.1") as client:
        response = client.post("/v1/signals", json=signal_body(), headers=headers)
    assert response.status_code == 401, response.status_code


def test_a_producer_token_reaches_nothing_but_the_signal_intake(surface, seeded, admin_engine):
    """A live `sg1.` token is refused on every other route that needs a credential."""
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        _, token = insert_source(conn, tenant, principal, datetime.now(UTC))
    needs_credential = sorted(
        route
        for route, authority in SERVED.items()
        if authority != PUBLIC and route != ("/v1/signals", "POST")
    )
    with TestClient(surface, base_url="http://127.0.0.1", follow_redirects=False) as client:
        for path, method in needs_credential:
            # The MCP mount answers at its own root; `/mcp` alone is a redirect to it.
            concrete = path.format(**SAMPLE) + ("/" if method == "MOUNT" else "")
            headers = {"Authorization": "Bearer " + token, "Origin": "http://127.0.0.1"}
            response = (
                client.get(concrete, headers=headers)
                if method == "GET"
                else client.post(concrete, data={}, headers=headers)
            )
            assert response.status_code in {400, 401, 403}, (path, method, response.status_code)


def test_an_unknown_credential_reaches_nothing_that_needs_one(surface):
    unknown = f"eb1.{ZERO}.{ZERO}.{secrets.token_urlsafe(32)}"
    needs_credential = sorted(
        route for route, authority in SERVED.items() if authority != PUBLIC and route[1] != "MOUNT"
    )
    with TestClient(surface, base_url="http://127.0.0.1", follow_redirects=False) as client:
        for path, method in needs_credential:
            concrete = path.format(**SAMPLE)
            headers = {"Authorization": "Bearer " + unknown, "Origin": "http://127.0.0.1"}
            response = (
                client.get(concrete, headers=headers)
                if method == "GET"
                else client.post(concrete, data={}, headers=headers)
            )
            assert response.status_code in {400, 401, 403}, (path, method, response.status_code)


# Every `/api/console/v1` route core serves, wherever it is declared: the console's own area
# (`CONSOLE`), the two session routes that predate the console (`AUTHORITY`) and the
# assistant's area when a model is configured (`ASSISTANT`). `REDIRECTS` and `ARCADE` carry
# none today but are included so a route added to one of them later is not missed silently.
# A plugin's console API routes (`PLUGINS` for the sample) are that plugin's to classify.
TOKEN_CLASSIFIED_COLLECTIONS = (AUTHORITY, CONSOLE, ASSISTANT, REDIRECTS, ARCADE)
API_ROUTES = {
    route
    for collection in TOKEN_CLASSIFIED_COLLECTIONS
    for route in collection
    if route[0].startswith("/api/console/v1")
}
PLUGIN_API_ROUTES = {route for route in PLUGINS if route[0].startswith("/api/console/v1")}


def test_every_console_api_route_says_whether_a_token_may_call_it(sample):
    """Fail closed: a route no one has classified is refused to a token, and this test names it.

    Core's table classifies exactly the routes core serves: every one of them, and nothing
    that core does not serve. A plugin classifies the routes its own console areas add and
    only those (`Registry.token_routes`, #496): the sample's here, and any other plugin's in
    that plugin's own tests.
    """
    assert not TOKEN_ALLOWED & TOKEN_REFUSED
    assert API_ROUTES == TOKEN_ALLOWED | TOKEN_REFUSED
    assert token_allowed("/api/console/v1/not/a/route", "GET") is False
    loaded = load_plugins({"sample_plugin": {}})
    assert loaded.allowed_token_routes | loaded.refused_token_routes == PLUGIN_API_ROUTES


_ROUTE_PREFIX = "/api/console/v1"


def _route_of(function: ast.AST) -> tuple[str, str] | None:
    """The `(path, METHOD)` this function's own `@routes.<method>("...")` decorator names,
    prefixed the way `token_rules.py` spells it, or `None` if it carries no such decorator or
    the decorator's path is not a literal string (as the token routes' dynamically registered
    `@routes.post(path, ...)` is; no such route raises `TOKEN_NOT_ALLOWED`, so this is never
    asked to resolve one)."""
    for decorator in getattr(function, "decorator_list", ()):
        if (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and isinstance(decorator.func.value, ast.Name)
            and decorator.func.value.id == "routes"
            and decorator.args
            and isinstance(decorator.args[0], ast.Constant)
            and isinstance(decorator.args[0].value, str)
        ):
            return _ROUTE_PREFIX + decorator.args[0].value, decorator.func.attr.upper()
    return None


def _routes_refusing_token_not_allowed(tree: ast.AST) -> set[tuple[str, str]]:
    """Every route a `raise ApiError("TOKEN_NOT_ALLOWED")` in this module's tree belongs to.

    A refusal is not always written in the decorated handler itself: `settings.py`'s
    `change_mode` defines a nested `apply` and raises from inside it. This is resolved by
    carrying the stack of enclosing `def`/`async def` nodes through a manual walk and, on a
    matching call, searching that stack from the innermost function outward for the nearest
    one carrying the route decorator -- sturdy against a refusal nested inside its route this
    way, however deep, though it would still need extending for one raised from a helper
    defined outside the route function entirely and called by name; no route does that today.
    """
    found: set[tuple[str, str]] = set()
    stack: list[ast.AST] = []

    def visit(node: ast.AST) -> None:
        is_function = isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        if is_function:
            stack.append(node)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ApiError"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "TOKEN_NOT_ALLOWED"
        ):
            for ancestor in reversed(stack):
                route = _route_of(ancestor)
                if route is not None:
                    found.add(route)
                    break
            else:
                raise AssertionError(
                    f"TOKEN_NOT_ALLOWED raised outside any route: {ast.dump(node)}"
                )
        for child in ast.iter_child_nodes(node):
            visit(child)
        if is_function:
            stack.pop()

    visit(tree)
    return found


def test_the_body_ruled_routes_are_allowed_and_raise_their_refusal_once_each():
    """`TOKEN_BODY_LIMITS` (`token_rules.py`) names every route whose allowed rule narrows
    further on the request body. Each must be allowed at the route level, since the body check
    only tightens it further, never widens a refusal into an allowance; and the exact set of
    routes that can still raise `TOKEN_NOT_ALLOWED`, found by parsing every module in this
    package except `guards.py`'s own general check, must equal it -- not fewer (a route that
    lost its check without the reference losing its claim), and not more (a refusal the
    reference never mentions)."""
    assert TOKEN_BODY_LIMITS.keys() <= TOKEN_ALLOWED
    package_dir = Path(console_api_package.__file__).parent
    found: set[tuple[str, str]] = set()
    for path in sorted(package_dir.rglob("*.py")):
        if path.name == "guards.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        found |= _routes_refusing_token_not_allowed(tree)
    assert found == TOKEN_BODY_LIMITS.keys()


@pytest.mark.parametrize(
    "route",
    [
        ("/api/console/v1/approvals/{approval_id}/decision", "POST"),
        ("/api/console/v1/policy/{bundle_id}/activate", "POST"),
        ("/api/console/v1/tenant/resume", "POST"),
        ("/api/console/v1/agents/{principal_id}/reactivate", "POST"),
        ("/api/console/v1/people", "POST"),
        ("/api/console/v1/access/users/{principal_id}/roles", "POST"),
        ("/api/console/v1/tenant/sign-in", "POST"),
        ("/api/console/v1/settings/password", "POST"),
        ("/api/console/v1/session", "GET"),
        ("/api/console/v1/people/{principal_id}/credentials/issue", "POST"),
        ("/api/console/v1/people/{principal_id}/password-link", "POST"),
        ("/api/console/v1/session/space", "POST"),
        ("/api/console/v1/session/workspace", "POST"),
        ("/api/console/v1/approvers/assign", "POST"),
        ("/api/console/v1/approval-rules", "POST"),
        ("/api/console/v1/teammate-invitations", "POST"),
        ("/api/console/v1/samples", "POST"),
        ("/api/console/v1/samples/refresh", "POST"),
        ("/api/console/v1/spaces/{space_id}/unarchive", "POST"),
        ("/api/console/v1/executions/{execution_id}/reconcile", "POST"),
        ("/api/console/v1/spaces/{space_id}/members/assign", "POST"),
        ("/api/console/v1/credentials/{credential_id}/revoke", "POST"),
        ("/api/console/v1/settings/tokens/issue", "POST"),
    ],
)
def test_the_design_exceptions_are_refused(route):
    assert route in TOKEN_REFUSED


# Prefixes where a person, their access or their sign-in is decided. A read is never the
# exception (approvers and approval rules, for one, are freely listable), but a token that could
# write here could make itself, or another token's owner, an administrator, or end someone's
# sign-in by proxy.
PERSON_AND_ACCESS_PREFIXES = (
    "/api/console/v1/people",
    "/api/console/v1/access",
    "/api/console/v1/approvers",
    "/api/console/v1/approval-rules",
    "/api/console/v1/invitations",
    "/api/console/v1/teammate-invitations",
    "/api/console/v1/tenant/sign-in",
    "/api/console/v1/settings",
    "/api/console/v1/account",
    "/api/console/v1/session",
    "/api/console/v1/spaces/{space_id}/members",
)


def test_token_allowed_writes_never_touch_people_access_or_sign_in():
    """A regression net for the classification above, not a new rule: nothing here is allowed to
    have moved a write into one of these prefixes without a reviewer noticing."""
    violations = [
        (path, method)
        for path, method in TOKEN_ALLOWED
        if method != "GET" and path.startswith(PERSON_AND_ACCESS_PREFIXES)
    ]
    assert violations == []
