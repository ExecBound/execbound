# Connect an agent host

An agent reaches ExecBound in one of two ways: as an MCP server with three tools, or over plain HTTP. Either way it authenticates with its own API key, and either way ExecBound decides before anything happens.

## Before you start

- **An agent and its API key.** Add the agent in the console under **Agent connections**, then issue its key from the agent's page or from **API keys**; [Authentication](https://docs.execbound.ai/api/agent#description/authentication) in the API reference has the steps. Give each tool its own agent, so its activity is its own and its key can be revoked alone.
- **The gateway address.** Your deployment's address, written `https://execbound.example.com` below; on the hosted service, the address the Quickstart gives.
- **Somewhere safe for the key.** The examples below read it from an environment variable, `EXECBOUND_CREDENTIAL`. Keep it in the host's secret configuration, not in a file or prompt the agent can read back.

## Check the key

`GET /v1/me` proposes nothing and records nothing, so it is the way to test a key:

```sh
curl -s https://execbound.example.com/v1/me \
  -H "Authorization: Bearer $EXECBOUND_CREDENTIAL"
```

It answers with the agent the key belongs to: `tenant_id`, `principal_id`, `credential_id`, `"kind": "AGENT"` and `expires_at`. A 401 means the key is wrong, revoked or expired.

## MCP

ExecBound serves a Streamable HTTP MCP server at `<gateway>/mcp/`. It is stateless, answers in JSON, and authenticates with a static header, `Authorization: Bearer <API key>`. It does not offer OAuth, so a host that can only connect to OAuth servers cannot use it yet.

| Tool | Arguments | What it does |
| --- | --- | --- |
| `execute` | `{"request": <action request>}` | Proposes one action. The request is the same body `POST /v1/execute` takes. |
| `execution_status` | `{"execution_id": "<uuid>", "continuation": "<optional>"}` | Reads the agent's own execution. |
| `list_actions` | none | Lists the actions the agent's space offers, with their arguments and the target kinds each accepts, exactly as `GET /v1/actions` does. |

The `execute` tool's description tells the model to pass `reference`, the ticket, case or run the action answers, and to re-send the identical request to progress it after a decision. It also tells the model to call `list_actions` for the `operation_ref` values its space offers and their arguments, and, on a denial, to stop and give you the `request_ref` rather than guess why.

### Claude Code

```sh
claude mcp add --transport http execbound https://execbound.example.com/mcp/ \
  --header "Authorization: Bearer <API key>"
```

The header is stored in the host's own configuration file in your home directory.

### Cursor

In `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "execbound": {
      "url": "https://execbound.example.com/mcp/",
      "headers": {"Authorization": "Bearer ${env:EXECBOUND_CREDENTIAL}"}
    }
  }
}
```

### OpenAI Agents SDK

```python
import os

from agents import Agent
from agents.mcp import MCPServerStreamableHttp

async with MCPServerStreamableHttp(
    name="execbound",
    params={
        "url": "https://execbound.example.com/mcp/",
        "headers": {"Authorization": "Bearer " + os.environ["EXECBOUND_CREDENTIAL"]},
    },
) as execbound:
    agent = Agent(
        name="responder",
        instructions=(
            "Act only through ExecBound; put uncertain outcomes in front of a person. "
            "On a denial, stop and give the person its request_ref."
        ),
        mcp_servers=[execbound],
    )
```

### Any other MCP client

- **Server URL:** `https://execbound.example.com/mcp/`
- **Transport:** Streamable HTTP
- **Header:** `Authorization: Bearer <API key>`

### What has been tested

| Host | Evidence |
| --- | --- |
| Any MCP client using the official SDK | Tested in CI against the server with the official MCP SDK, version 2.3.0 and the older 1.30 client. |
| OpenAI Agents SDK | Tested in CI as a tool over the HTTP API; the MCP configuration above is not yet tested. |
| Claude Code, Cursor | Configuration only. Neither has been run against ExecBound in a recorded trial. |

## Plain HTTP

`POST /v1/execute` proposes one action:

```sh
curl -s https://execbound.example.com/v1/execute \
  -H "Authorization: Bearer $EXECBOUND_CREDENTIAL" \
  -H "Content-Type: application/json" \
  -d '{
    "operation_ref": "endpoint.isolate",
    "target": {"kind": "hostname", "value": "workstation-01.example.com"},
    "arguments": {},
    "reference": "INC-1042",
    "claimed_context": {"incident_id": "<the incident this action responds to>"}
  }'
```

- `operation_ref` names an action the agent's space offers, and the target must exist in your workspace's inventory. `GET /v1/actions` (the MCP tool `list_actions`) lists the actions the space offers, each with its arguments, the values they accept and the target kinds it takes; it never lists targets, and a listed action is not permission. An action the space does not offer, or an unknown target, is answered 503 `EXECUTION_UNAVAILABLE`, the same answer as any other unavailable execution, so the answer reveals nothing about what exists beyond the listing. When it persists for an action and a target that are right, the agent should stop and tell a person: stale trusted facts do not fix themselves.
- `reference` is the ticket, case or run the action answers. ExecBound derives the idempotency key from it, so re-sending the same request never acts twice. Send `idempotency_key` instead if you manage keys yourself, never both.
- `claimed_context.incident_id` names the incident the action responds to. It is a pointer, not a fact: ExecBound reads the incident's severity and status from its own trusted sources.

The [API reference](https://docs.execbound.ai/api/agent) has every field, and the [action catalog](ACTION_CATALOG.md) lists every action and its arguments.

## Handle the answer

| State | Status | What the agent should do |
| --- | --- | --- |
| `EXECUTED` | 200 | Done. |
| `DENIED` | 200 | Stop and tell a person the `request_ref`; the reason is recorded for them and is not sent to the agent. Re-sending the same request returns the same answer. When `denial` is `busy` or `limit`, a new request after the other request settles or the limit resets is decided afresh, and whether to make one is the person's call. |
| `OBSERVED` | 200 | Nothing ran: the workspace or mapping is observe-only. `observed` says what would have been decided. |
| `PENDING_APPROVAL` | 202 | Wait for a person. Read the status with the `continuation`, then re-send the identical request once it is approved. |
| `DISPATCH_COMMITTED`, `INDETERMINATE` | 202 | The action may have happened. Do not propose it again under a new reference; re-send the identical request or read the status until it settles. |
| `STALE_AUTHORIZATION` | 200 | The approval or the trusted context expired first. Propose it again if it is still needed. |
| `FAILED_NOT_EXECUTED` | 200 | The provider refused; nothing changed. |
| `FAILED_EFFECT_UNKNOWN` | 200 | The call failed and whether the change happened is not known. Put it in front of a person. |

A denial tells the agent that it was denied, the request's reference and one of three categories, and never the reason itself. The answer carries `denial` and `notice`, one fixed sentence for the category:

- `busy`: another request holds the target. "Denied because another request holds this target. Re-sending this request returns this same answer; a new request after that one settles may be decided differently. A person can find it by searching the console for EB-12."
- `limit`: a shared limit covering the request is spent, whatever else denied it. "Denied because a shared limit is spent. Re-sending this request returns this same answer; a new request after the limit resets is decided afresh. A person can find it by searching the console for EB-12."
- `withheld`: every other denial. "Denied. The reason is recorded for a person, who can find it by searching the console for EB-12. Re-sending this request returns this same answer."

The reason is kept for people on purpose, so an agent that is mistaken, prompt-injected or compromised learns nothing about the policy from its denials: no category names the rule, the limit, its window, a count, a fact or the other request. `busy` and `limit` tell the agent when waiting is worth a new request, which is why it is told them; a limit is reported whatever else denied the request, so it says nothing about whether the policy allows the target. The person finds the reason by searching the console for that reference. Re-sending the same request returns the same answer; a new request may be decided differently, and whether to make one is the person's call.

Reading a pending approval's status:

```sh
curl -s https://execbound.example.com/v1/executions/<execution_id> \
  -H "Authorization: Bearer $EXECBOUND_CREDENTIAL" \
  -H "X-Execution-Continuation: <continuation>"
```

A status read never acts. Once the approval is recorded, re-sending the identical execute request is what runs it, and it must happen before the approval's deadline. A continuation lasts at most two minutes; re-sending the request also renews it. The [API reference](https://docs.execbound.ai/api/agent#description/errors) lists every error code and the rate limits.
