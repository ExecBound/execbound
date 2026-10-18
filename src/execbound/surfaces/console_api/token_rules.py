# SPDX-License-Identifier: AGPL-3.0-only
"""Which console API routes a personal access token may call.

A token carries its administrator's authority except where an audit log would only report,
after the fact, what these refusals prevent: deciding an approval or settling an uncertain
execution, loosening enforcement, changing people, access or sign-in, reading or switching a
browser session or a person's workspace, managing tokens or the owner's own account, and
changing a monitoring credential (connecting, re-keying or revoking a connection; minting,
rotating or revoking a reporting source) or acknowledging several findings at once. Two routes
add a rule on their body (`/tenant/mode`, `/credentials/issue`), checked in the route.

The tables below classify every route core serves under `/api/console/v1`
(`tests/test_route_authority.py`'s `CONSOLE`, `AUTHORITY` and `ASSISTANT` collections, not
`CONSOLE` alone): a route added later is refused to tokens until it is classified here. A
plugin classifies the routes its own console areas add, and only those, with
`Registry.token_routes` (#496); `token_allowed` reads core's table first and then the loaded
plugins' own. The six token-management routes (`console_api/tokens.py`) are themselves
classified below, in `TOKEN_REFUSED`: a token manages no token, its own or another's.
`TOKEN_ALLOWED` is a literal list, and `tests/test_route_authority.py` names any served core
`/api/console/v1` route that is in neither set; a plugin's own route inventory test does the
same for the routes it adds.
"""

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from execbound.plugins import LoadedPlugins

P = "/api/console/v1"

TOKEN_REFUSED: frozenset[tuple[str, str]] = frozenset(
    {
        # Token management (`console_api/tokens.py`): a token can read and write as its
        # owner but can never mint, list, revoke or delete a token, its own or another's.
        (P + "/settings/tokens", "GET"),
        (P + "/settings/tokens/issue", "POST"),
        (P + "/settings/tokens/{token_id}/revoke", "POST"),
        (P + "/settings/tokens/{token_id}/delete", "POST"),
        (P + "/tenant/tokens", "GET"),
        (P + "/tenant/tokens/{token_id}/revoke", "POST"),
        # Approvals and settlement: a token never decides, and settling whether an uncertain
        # execution happened can refund its impact budget, the same kind of judgment on the
        # evidence.
        (P + "/approvals/{approval_id}/decision", "POST"),
        (P + "/executions/{execution_id}/reconcile", "POST"),
        # Loosening enforcement.
        (P + "/policy/{bundle_id}/activate", "POST"),
        (P + "/tenant/resume", "POST"),
        (P + "/agents/{principal_id}/reactivate", "POST"),
        # An archived space takes no new work, so unarchiving undoes a deliberate stop the
        # way reactivating an agent does: loosening.
        (P + "/spaces/{space_id}/unarchive", "POST"),
        # `POST /samples` installs and activates the starter policy bundle, which is activating
        # a policy, and `POST /samples/refresh` installs and activates it again (#545).
        # Reading their status (`GET /samples`) is allowed, as `/connection` is, and
        # `/samples/remove` only tightens (removes what it added) and is allowed.
        (P + "/samples", "POST"),
        (P + "/samples/refresh", "POST"),
        # People, access and sign-in: closes approval by proxy and new administrators.
        (P + "/people", "POST"),
        (P + "/people/{principal_id}/label", "POST"),
        (P + "/people/{principal_id}/email", "POST"),
        (P + "/people/{principal_id}/password-link", "POST"),
        (P + "/people/{principal_id}/directory-invite", "POST"),
        (P + "/people/{principal_id}/directory-invite/revoke", "POST"),
        (P + "/people/{principal_id}/directory-link", "POST"),
        (P + "/people/{principal_id}/directory-unlink", "POST"),
        (P + "/people/{principal_id}/credentials/issue", "POST"),
        (P + "/people/{principal_id}/credentials/{credential_id}/revoke", "POST"),
        (P + "/people/{principal_id}/scopes/assign", "POST"),
        (P + "/people/{principal_id}/scopes/unassign", "POST"),
        (P + "/people/{principal_id}/sessions/end", "POST"),
        (P + "/people/{principal_id}/deactivate", "POST"),
        (P + "/people/{principal_id}/reactivate", "POST"),
        (P + "/access/users/{principal_id}/roles", "POST"),
        (P + "/access/groups", "POST"),
        (P + "/access/groups/{group_id}", "POST"),
        (P + "/access/groups/{group_id}/delete", "POST"),
        (P + "/access/groups/{group_id}/members", "POST"),
        (P + "/access/groups/{group_id}/roles", "POST"),
        (P + "/approval-rules", "POST"),
        (P + "/approval-rules/{rule_id}", "POST"),
        (P + "/approval-rules/{rule_id}/disable", "POST"),
        (P + "/approvers/assign", "POST"),
        (P + "/approvers/unassign", "POST"),
        (P + "/teammate-invitations", "POST"),
        (P + "/teammate-invitations/{id}/resend", "POST"),
        (P + "/teammate-invitations/{id}/revoke", "POST"),
        (P + "/tenant/sign-in", "POST"),
        (P + "/tenant/sign-in/{provider_id}/state", "POST"),
        # A space's member roster carries a role, narrowed from the person's workspace role,
        # the same kind of grant `/access` makes; assigning or removing it is a role change.
        (P + "/spaces/{space_id}/members/assign", "POST"),
        (P + "/spaces/{space_id}/members/unassign", "POST"),
        # The cross-cutting credential list revokes a credential of any non-ADMIN holder,
        # including a HUMAN_APPROVER's own sign-in credential; that changes a person's
        # sign-in, the same as the `/people` routes above. An agent's own credential stays
        # revocable by token through the agent-scoped revoke route below.
        (P + "/credentials/{credential_id}/revoke", "POST"),
        # Acknowledgement is final, so silencing many findings in one request needs a browser
        # session; a token keeps the single-finding route.
        (P + "/monitor/findings/acknowledge", "POST"),
        # A monitoring connection that holds a credential is created or re-keyed behind a
        # verified factor a token cannot give, and revoking one silences what it watches: a
        # stolen token must not blind the defender (#678). Asking for a collection and
        # changing a schedule within its bounds do neither, and are allowed below.
        (P + "/monitor/connections/tines", "POST"),
        (P + "/monitor/connections/entra/start", "POST"),
        (P + "/monitor/connections/{connection_id}/key", "POST"),
        (P + "/monitor/connections/{connection_id}/revoke", "POST"),
        # Minting or rotating a reporting source issues an intake credential behind a verified
        # factor, and revoking one silences its story (#678). Reading one is allowed below.
        (P + "/monitor/sources", "POST"),
        (P + "/monitor/sources/{source_id}/rotate", "POST"),
        (P + "/monitor/sources/{source_id}/revoke", "POST"),
        # The browser session and switching a person's workspace.
        (P + "/session", "GET"),
        (P + "/session/space", "POST"),
        (P + "/session/verify", "POST"),
        (P + "/session/verify/passkey/options", "POST"),
        (P + "/session/verify/passkey", "POST"),
        (P + "/session/workspace", "POST"),
        (P + "/session/workspaces", "GET"),
        # The owner's own account.
        (P + "/settings/password", "POST"),
        (P + "/settings/sessions/revoke-others", "POST"),
        (P + "/settings/weekly-summary", "POST"),
        (P + "/account/profile", "POST"),
        (P + "/account/requests", "POST"),
        (P + "/account/requests/resolve", "POST"),
    }
)

TOKEN_ALLOWED: frozenset[tuple[str, str]] = frozenset(
    {
        (P + "/access", "GET"),
        (P + "/account", "GET"),
        (P + "/account/requests", "GET"),
        (P + "/agents", "GET"),
        (P + "/agents", "POST"),
        (P + "/agents/{principal_id}/credentials/issue", "POST"),
        (P + "/agents/{principal_id}/credentials/{credential_id}/delete", "POST"),
        (P + "/agents/{principal_id}/credentials/{credential_id}/revoke", "POST"),
        (P + "/agents/{principal_id}/deactivate", "POST"),
        (P + "/agents/{principal_id}/label", "POST"),
        (P + "/agents/{principal_id}/unbind", "POST"),
        (P + "/agents/{row_id}", "GET"),
        (P + "/agents/{row_id}/bind", "POST"),
        (P + "/agents/{row_id}/govern", "POST"),
        (P + "/approvals", "GET"),
        (P + "/approvals/{approval_id}", "GET"),
        (P + "/approval-rules", "GET"),
        # Decision coverage and unrouted approvals are reads, like the rules and the approvers
        # matrix, and carry counts only (#678).
        (P + "/approval-coverage", "GET"),
        (P + "/approval-coverage/unrouted", "GET"),
        (P + "/approvers", "GET"),
        # The assistant: every route takes only the acting person's own session and turns, and
        # drafting a rule writes nothing (the administrator still submits it through the rules
        # page); enabling or disabling the assistant is a workspace toggle like `/tenant/mode`.
        (P + "/assistant/rules", "POST"),
        (P + "/assistant/settings", "GET"),
        (P + "/assistant/settings", "POST"),
        (P + "/assistant/turns", "GET"),
        (P + "/assistant/turns", "POST"),
        (P + "/assistant/turns/{turn_id}", "GET"),
        (P + "/assistant/turns/{turn_id}/events", "GET"),
        (P + "/assistant/turns/{turn_id}/opened", "POST"),
        (P + "/board", "GET"),
        (P + "/board/stream", "GET"),
        (P + "/client-errors", "POST"),
        (P + "/connection", "GET"),
        (P + "/credentials", "GET"),
        (P + "/credentials/expiring", "GET"),
        (P + "/credentials/issue", "POST"),
        (P + "/credentials/{credential_id}/delete", "POST"),
        (P + "/executions", "GET"),
        (P + "/executions/{execution_id}", "GET"),
        (P + "/monitor", "GET"),
        (P + "/monitor/agents", "GET"),
        (P + "/monitor/agents/{agent_id}", "GET"),
        (P + "/monitor/findings", "GET"),
        (P + "/monitor/findings/{finding_id}", "GET"),
        (P + "/monitor/findings/{finding_id}/acknowledge", "POST"),
        (P + "/monitor/setup/verify", "POST"),
        (P + "/monitor/connect", "GET"),
        (P + "/monitor/connections/{connection_id}/collect", "POST"),
        (P + "/monitor/connections/{connection_id}/schedule", "POST"),
        (P + "/monitor/sources/{source_id}", "GET"),
        (P + "/overview", "GET"),
        (P + "/people", "GET"),
        (P + "/people/{principal_id}", "GET"),
        (P + "/policy", "GET"),
        (P + "/policy", "POST"),
        (P + "/policy/{bundle_id}", "GET"),
        (P + "/policy/{bundle_id}/compare", "GET"),
        (P + "/policy/{bundle_id}/ruleset", "GET"),
        (P + "/policy/{bundle_id}/preview", "POST"),
        # The value report reads what its owner reads (#678).
        (P + "/report", "GET"),
        (P + "/report.csv", "GET"),
        (P + "/policy/{bundle_id}/retire", "POST"),
        (P + "/policy/{bundle_id}/rules", "GET"),
        (P + "/policy/{bundle_id}/rules", "POST"),
        (P + "/policy/{bundle_id}/validate", "POST"),
        (P + "/samples", "GET"),
        # The same status as `execbound-demo`'s configuration, a read like it (#247).
        (P + "/samples/demo-configuration", "GET"),
        (P + "/samples/remove", "POST"),
        # Setup progress reads records the token's owner may read, in the Space it names, and
        # writes nothing, as `/samples` reads (#678).
        (P + "/setup", "GET"),
        (P + "/search", "GET"),
        (P + "/settings", "GET"),
        (P + "/spaces", "GET"),
        (P + "/spaces", "POST"),
        (P + "/spaces/{space_id}", "GET"),
        (P + "/spaces/{space_id}/archive", "POST"),
        (P + "/spaces/{space_id}/rename", "POST"),
        (P + "/teammate-invitations", "GET"),
        (P + "/tenant", "GET"),
        (P + "/tenant/deadline", "POST"),
        (P + "/tenant/mode", "POST"),
        (P + "/tenant/sign-in", "GET"),
        (P + "/tenant/stop", "POST"),
        (P + "/welcome/example", "POST"),
    }
)


_PARAMETER = re.compile(r"\{[^}]+\}")


def route_shape(path: str) -> str:
    """The URLs a route template matches, whatever its parameters are called:
    `/agents/{row_id}` and `/agents/{agent_id}` are one shape, `/agents/{}`."""
    return _PARAMETER.sub("{}", path)


# The shape of every path core classifies, under any method. A plugin can never classify any
# method of a path of one of these shapes (`Registry.token_routes` refuses it), and
# `token_allowed` decides core's answer for them before a plugin's set is read, so a plugin's
# classification cannot loosen core's even where registration was bypassed. A shape rather
# than a spelling, because a plugin route that names core's parameter differently matches the
# same requests, and the guard is asked about whichever of the two the router matched.
CORE_SHAPES: frozenset[str] = frozenset(
    route_shape(path) for path, _ in TOKEN_ALLOWED | TOKEN_REFUSED
)


def token_allowed(path: str, method: str, plugins: "LoadedPlugins | None" = None) -> bool:
    """Whether a personal access token may call this route: core's table, then the loaded
    plugins' own classification of their routes. Any method of a path whose shape core
    classifies is decided by core alone, and a route in neither is refused."""
    if (path, method) in TOKEN_ALLOWED:
        return True
    if route_shape(path) in CORE_SHAPES or plugins is None:
        return False
    return (path, method) in plugins.allowed_token_routes


# The two routes above whose allowed rule narrows further on the request body, checked in the
# route itself (`settings.py`'s `change_mode`, `credentials.py`'s `issue_credential`) rather
# than here: a token stays fully authorized at the route level, and `TOKEN_NOT_ALLOWED` is
# raised only when the body asks for the one thing this table would otherwise have to refuse
# outright. The console API reference states each limit beside the plain rule, from this
# mapping alone (`tests/test_route_authority.py` holds both halves: that each key is allowed,
# and that the refusal it names is raised exactly once, in that route).
TOKEN_BODY_LIMITS: dict[tuple[str, str], str] = {
    (P + "/tenant/mode", "POST"): (
        "Personal access tokens: allowed to switch to enforcing only; switching to "
        "observe-only is refused."
    ),
    (P + "/credentials/issue", "POST"): (
        "Personal access tokens: allowed to issue a key for an agent only; a person's "
        "credential is refused."
    ),
}
