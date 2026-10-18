# execbound-client

A Python client for the ExecBound gateway with the retry, approval and uncertainty semantics the gateway expects, so an agent built on the Claude Agent SDK, the OpenAI Agents SDK or plain Python cannot easily get them wrong. It depends on `httpx` only and declares Python 3.11 or later; it uses no syntax newer than 3.11 and is tested in the repository's CI on 3.13. MCP remains the zero-code route for hosts that speak it; this package is for agents that call HTTP.

Not published to PyPI; install it from a checkout of the repository:

```sh
pip install ./clients/python
```

## What it gets right

| Behavior | Why it matters |
| --- | --- |
| One idempotency key per intended action, derived from the intent with `intent_key` and reused on every retry | The key scopes durable intent; a new key can act twice and consume new impact. There is no way to generate a key without a ticket, case or run reference. |
| Poll a pending approval with the returned continuation, then send the same request again | Status reads never dispatch; only a retry of the same intent progresses an approved execution before its deadline. |
| Return the stale intent when an approval expires mid-poll | The continuation is void once the approval expires; the client resends once and returns `STALE_AUTHORIZATION` with `approval_state: EXPIRED` instead of raising. That intent is over; a new key starts a new one. |
| Raise `ExecBoundUncertain` for `DISPATCH_COMMITTED` and `INDETERMINATE`, and retry a 503 only under the same key | The provider may have acted. Hand an uncertain execution to an administrator for reconciliation; never resend under a new key. A 503 raises `ExecBoundError` (`UNAVAILABLE` when the gateway sent no code) and is not proof that nothing was done, so a later retry reuses the key. |
| Back off on 429 `RATE_LIMITED` using `Retry-After` | Refusals are cheap for the gateway and consume nothing; hammering only extends the window. |
| Read the stable `code` field, not the message text | Messages are generic on purpose; codes are the contract. |
| List the actions the agent's space offers with `list_actions` instead of guessing an `operation_ref` | The gateway answers an action the space does not offer as it answers any other unavailable execution, 503 `EXECUTION_UNAVAILABLE`, so a wrong guess looks like an outage. A listed action is not permission: every request is still decided. |
| Send `claimed_context.incident_id` as a selector, nothing more | Claims select independently verified context; they never grant authority. The endpoint contracts require an incident, so a request without one is refused before any decision. |

The client invents no fields, ignores unknown response fields, and never sends tenant, principal or role: identity comes from the credential. The wire body and codes are in the repository's `docs/API_REFERENCE.md`.

## Configuration

The base URL and the credential come from the environment or a private file, never from command-line arguments:

| Variable | Meaning |
| --- | --- |
| `EXECBOUND_URL` | The gateway origin, for example `https://app.execbound.ai` |
| `EXECBOUND_CREDENTIAL` | The agent credential issued by the tenant's administrator |
| `EXECBOUND_CREDENTIAL_FILE` | A private file holding that credential, used when the variable is unset |

```python
from execbound_client import ExecBoundClient, action_request, intent_key

client = ExecBoundClient.from_environment()
key = intent_key("endpoint.isolate", "hostname", "ws01.example", "INC-4711")
request = action_request(
    "endpoint.isolate", "hostname", "ws01.example", key, incident_id="<the incident id>"
)
outcome = client.run_to_completion(request, approval_wait_seconds=300)
print(outcome.state, outcome.execution_id, outcome.approval_url)
```

`run_to_completion` sends the request, polls a pending approval every `poll_seconds`, resends the same request once a decision is recorded, and returns an `Outcome` (`state`, `execution_id`, `approval_state`, `approval_url`, and the `pending`, `expired` and `uncertain` flags). A pending approval that outlives `approval_wait_seconds` is returned while still pending; call again later with the same request and key.

`list_actions` reads the actions the agent's own space offers (`GET /v1/actions`): each `operation_ref`, the catalog action and label it performs, its arguments and the values or range each accepts, the target kinds it takes and whether an incident is required. It never names a target, a rule or a limit. A listed action is not permission, and listed does not mean connected: a listed action whose provider is not connected is still refused.

```python
listing = client.list_actions()
for action in listing["actions"]:
    print(action["operation_ref"], action["label"], action["target_kinds"])
```

The asynchronous client has the same interface:

```python
from execbound_client import AsyncExecBoundClient

async with AsyncExecBoundClient.from_environment() as client:
    outcome = await client.run_to_completion(request)
```

## As a tool

`execbound_action` and `execbound_action_async` take string arguments and return a short JSON summary for the model: `outcome` is `final`, `pending`, `expired`, `uncertain` or `refused`, with the execution id, the state and the approval URL, and on a denial the `request_ref`, the gateway's `denial` category (`busy`, `limit` or `withheld`) and its `notice`, one fixed sentence saying a person can find the reason by searching the console for that reference; for `busy` and `limit` it also says a new request after the other request settles or the limit resets is decided afresh. The reason itself is never sent to an agent. `execbound_list_actions` and `execbound_list_actions_async` take the client alone and return the listing for the model: `outcome` `listed` with each action's fields, keeping only the fields the gateway defines and only values of the types it defines, or `refused` with the status and code, a 429 included, since the listing is not retried. From it a model learns which actions it can name instead of guessing. Wrap each in your framework's tool abstraction, taking the asynchronous pair wherever the framework runs tools on its event loop, so that a held action waits for a person without stopping the agent. The two examples in this directory each wrap the pair as two tools in a few dozen lines: `examples/claude_agent_sdk_tool.py` wraps `execbound_list_actions_async` and `execbound_action_async` with an `AsyncExecBoundClient`, because the Claude Agent SDK runs its tools on the agent's event loop, and `examples/openai_agents_tool.py` wraps `execbound_list_actions` and `execbound_action`, plain functions the OpenAI Agents SDK runs in a worker thread. CI runs both as written, through claude-agent-sdk 0.2.153 and openai-agents 0.22.2 with a scripted model standing in for the real one, which lists the space's actions and then asks for the action the listing names, against a real gateway, and checks that the agent's event loop kept running while the held action waited (`tests/test_sdk_examples.py`); the [integrations page](../../docs/INTEGRATIONS.md) records what that does and does not show. Two rules matter more than the framework: derive the key from the ticket or run, never from the model's wording, and put `uncertain` outcomes in front of a person.

## The demo, from your own machine

The package installs `execbound-demo`, which runs the demo's beats from your own machine against one of two kinds of workspace: a Community workspace that has added its sample targets, or an isolated workspace holding only synthetic fixtures. Public installation is not available yet. If you have an ExecBound source checkout, install from its root:

```sh
pipx install "./clients/python[mcp]"
```

It reads a private directory holding `sandbox.json`, a compatibility filename for the demo configuration, and the agent API key files that file names, and takes the gateway origin from `EXECBOUND_URL`. Make the directory yours alone before saving a key in it, and each key file too (`chmod 700` the directory and `chmod 600` the keys): a key issued for sample targets outlives the demo and keeps its agent's authority once the workspace connects a real provider. Nothing sensitive goes on the command line and nothing is printed but identifiers and states; `demo-record.json` beside the files holds the same. The file's `workspace` field says which kind of workspace it describes. Its optional `providers` names the mocks the `boundary` beat sends agent A's key to, to show each refusing it, so the command refuses a file that names a loopback address there unless the gateway's own origin is one too: behind a gateway published elsewhere, that address is whatever listens on the port on your machine. The console's download never names a mock at a loopback address, since nothing the gateway holds says whether your machine reaches the mock there (the Community bundle publishes the gateway's port alone, and keeps its mocks on loopback inside its own network); where yours does, you may add it. An origin in the file that your machine cannot reach fails the `boundary` beat, which says which one. A refusal of the `decide` beat's first request names the gateway's status and code, and only `EXECUTION_UNAVAILABLE`, which stale facts or facts that no longer name the target cause, says to refresh them; an agent key the gateway no longer accepts, an emergency stop and an agent whose space has no policy each say what to do instead, since no refresh changes them.

- **Sample targets** (`"workspace": "samples"`). An administrator adds the sample targets from Getting started and downloads the file with **Download demo configuration** on the Sample targets card; a personal access token may download it too (`GET /api/console/v1/samples/demo-configuration`). It names the three sample targets by hostname with their open incidents and the endpoint mock that serves them, unless that mock's address is a loopback one, and holds no credential. The card offers it, and the route answers it rather than 404 `NOT_FOUND`, only while the demo can run on the samples: this deployment serves them, the starter policy is the one in force (the default space selects it and the workspace enforces it rather than observing), no emergency stop is active, each of the three has an open incident, the starter policy's own isolation mapping is live, their facts are current (the starter policy keeps them for an hour, after which every request on the samples is refused before any decision until you refresh them), no request on the samples waits for approval or provider evidence, and none since their facts were recorded has isolated one. Once a policy of your own decides the samples, it decides the demo's requests as you wrote it, so the card stops offering the file. Both beats a samples file runs send as one agent, so issue one agent API key on the API keys page, save it as `agent-a.token`, one line, and add `"credentials": {"agent_a": "agent-a.token"}` to the file; a second agent's key is accepted as `agent_b` and never sent. Requests on samples carry no `synthetic_demo` mark, so the command refuses a samples file that names any target but a sample hostname (`*.sample.invalid`) or names an `admin` key file. The production isolation waits for the administrator who added or last refreshed the samples, since review of them is theirs. The beats need the samples as their facts record them, and an isolation of one that executes changes it, whether a run of this command made it or your own agent did: guided setup has your agent isolate the sample workstation and, once you approve it, the production one. Once that has happened, or the facts have gone stale, the card says to refresh the sample facts in place of the file, and before each run after the first, refresh them on the card and download the file again; a run on an old file stops and says so.
- **Synthetic fixtures** (no `workspace` field). An isolated workspace holding only synthetic fixtures, such as a hosted sandbox, has a download of its own. It needs two agents' API keys, saved as `agent-a.token` and `agent-b.token`, one line each, and named as `"credentials": {"agent_a": "agent-a.token", "agent_b": "agent-b.token"}`, since its budget beat splits the requests between them. Every request is marked `synthetic_demo`, which the gateway refuses in any workspace holding real data, its targets may be named any way the gateway accepts, and `credentials` may also name an `admin` file, which this command accepts and never uses.

| Beat | What it shows |
| --- | --- |
| `boundary` | The agent credential opens the agent routes and nothing else: no human session, no provider call. |
| `decide` | A workstation isolation allowed and executed once, the domain controller denied, a claim the inventory does not hold refused before any decision, and the production isolation waiting for a person on a phone; the agent's own attempt to approve is refused. |
| `budget` | The same isolation split across both credentials over HTTP and MCP until the shared tenant budget refuses. Needs the `mcp` extra and a workspace of synthetic fixtures: the samples hold one target the starter policy lets an agent isolate and the shared tenant total is twenty isolations in fifteen minutes, so on samples the beat refuses before sending anything and exits 2. |

`all` runs the beats the workspace carries in order, stopping at the first that fails: all three on synthetic fixtures, and `boundary` and `decide` on sample targets, after which it says that `budget` was not run. The recorded demo has a fourth beat, replay, which needs the gateway's database and so is not part of this command.

## The same key over MCP

An MCP host does not run this client, so the gateway offers the same derivation server-side: an `execute` call that passes `reference` (the ticket, case or run id) instead of `idempotency_key` gets the key `intent_key` would have produced, byte for byte. A Python client and an MCP host given the same ticket therefore land on the same intent, and a retry through either path progresses it. The Tines governed-action story sends `reference` too, so the same ticket lands on the same intent there as well.

With the `mcp` extra, `execbound_client.mcp` drives that surface with the official MCP SDK. `list_actions(origin, token)` calls the gateway's `list_actions` tool and returns the space's listing as the gateway sent it, unknown fields included; pass it to `summarize_listing` before a model reads it. `run_action(origin, token, request)` drives one action through `execute` and `execution_status`, polling a pending approval with its continuation and resending the same request to progress it. Both authenticate with the agent credential alone, and a refusal raises `McpRefused` with the tool's name and the stable code; a listing tool that answers anything but a listing raises it with `UNEXPECTED_RESPONSE`.

## Approval deadlines

An approval is decided by a person on the console within its deadline (a tenant setting: 120 seconds unless an administrator raised it or turned it off, in which case the frozen plan's validity is the deadline). The client waits for `approval_wait_seconds` and renews its two-minute status continuation on its own by resending the same intent. If nobody decides, the intent ends as `STALE_AUTHORIZATION` with `approval_state: EXPIRED`; `Outcome.expired` is true, `summarize` reports `expired`, and a new key is needed to try again. Have the approver signed in before the agent sends.

## Tests

`tests/test_client_package.py` in the repository drives both clients against an in-process gateway with a real provider process: a production target pends, a decision is recorded mid-flight, the same request is resent and the provider records exactly one mutation; an approval that expires mid-poll returns the stale view; a forbidden action is refused with its code; rate limiting backs off; an uncertain result raises; every request body the client can build passes the gateway's strict parser; and both clients list the space's actions as the gateway answers them and raise a refused listing's code. Over a stand-in transport, both listing tools keep only the fields a listing defines, of the types it defines, and a malformed listing is refused. `tests/test_examples.py` drives `execbound_client.mcp` against a real gateway: an action held for a person and then executed once, the space's listing, and a refused listing's code; a stand-in MCP server shows the listing returned as sent with nothing but the credential, an answer that is not a listing refused, and a server that offers no listing tool refused before any call.
