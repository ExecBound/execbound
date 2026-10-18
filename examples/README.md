# Integration examples

Runnable examples of an agent calling ExecBound correctly: over plain HTTP, over MCP with the official Python SDK, and through a framework-neutral tool function you can wrap in whatever agent framework you use. They run against the local demonstration with synthetic fixtures. They are not named host compatibility trials.

## Run the demonstration

```sh
uv run execbound seed-validation --seed demo-1 --output local-data/demo-1
uv run python scripts/validation_demo.py serve --private local-data/demo-1
```

Keep that terminal open. The fixture manifest `local-data/demo-1/fixture.json` lists the target labels (for example `workstation-01`); `credentials.json` holds the expiring agent tokens the examples read. Trusted context in the fixtures expires 300 seconds after seeding, so run an example promptly or reseed.

In a second terminal:

```sh
uv run python examples/mcp_agent.py --private local-data/demo-1 --list
uv run python examples/plain_http.py --private local-data/demo-1 --target workstation-01 --action endpoint.isolate --key ticket-4711
uv run python examples/mcp_agent.py --private local-data/demo-1 --target workstation-01 --action endpoint.isolate --key ticket-4712
```

The first prints the actions the agent's space offers, each `operation_ref` with its arguments and the target kinds it accepts, and never a target; the other two request one of them. A listed action is not permission: every request is still decided.

A production target needs a human decision. The example prints the approval URL; open `http://127.0.0.1:8100/login?setup=1` with the first tenant's reviewer credential, the one labelled `human_endpoint` in `local-data/demo-1/credentials.json`, approve, and the example (still polling) sends the same request again and prints the executed view. If you approve after the example gave up waiting, rerun it with the same key.

## What the examples get right

| Behavior | Why it matters |
| --- | --- |
| One idempotency key per intended action, reused on every retry | The key scopes durable intent; a new key can act twice and consume new impact. |
| Poll a pending approval with the returned `continuation`, then send the same request again | Status reads never dispatch; only a retry of the same intent progresses an approved execution before its deadline (a tenant setting, 120 seconds by default), and the same retry renews a two-minute continuation under a longer deadline. |
| Treat `DISPATCH_COMMITTED`, `INDETERMINATE` and a 503 after a send as uncertain | The provider may have acted. Hand the execution to an administrator for reconciliation; never resend under a new key. |
| Back off on 429 `RATE_LIMITED` using `Retry-After` | Refusals are cheap for the gateway and consume nothing; hammering only extends the window. |
| Read the stable `code` field, not the message text | Messages are generic on purpose; codes are the contract. |
| Send `claimed_context.incident_id` as a selector, nothing more | Claims select independently verified context; they never grant authority. |
| Over MCP, pass `reference` (the ticket) and let the gateway derive the key | The derivation is byte for byte the client's `intent_key`, so an MCP host and the Python client given the same ticket land on the same intent and either path progresses it. A caller with its own key management keeps `idempotency_key`; the two are never sent together. |

## Files

- The client itself is the installable package in [`clients/python/`](../clients/python/README.md) (`execbound_client`): `ExecBoundClient` and `AsyncExecBoundClient` with `execute`, `status`, `list_actions` and `run_to_completion`; `action_request` to build the strict wire body; `intent_key` to derive the idempotency key from the ticket or run; `execbound_list_actions` and `execbound_action`, plain functions returning a short JSON summary for a model, each with an asynchronous twin. Depends only on `httpx`. The examples here import it.
- `plain_http.py`: command-line use of the client against the fixtures.
- `mcp_agent.py`: the same flow through the MCP surface; the flow itself is `execbound_client.mcp.run_action` (the package's `mcp` extra), including `tools/list` and `execution_status` with the continuation, and this file is the command line around it. The flow uses two of the gateway's three tools, `execute` and `execution_status`; the third, `list_actions`, lists the actions the agent's space offers, and `--list` prints that listing through `execbound_client.mcp.list_actions`.
- `execbound-demo` from the client package runs the demo beats from your own machine against a workspace that has added its sample targets, with the demo configuration downloaded from the Sample targets card on Getting started, or against an isolated workspace holding only synthetic fixtures; [the client's guide](../clients/python/README.md) says what each kind of workspace runs and what the configuration holds.

## Wrapping the tools in a framework

`execbound_list_actions(client)` and `execbound_action(client, operation_ref, target_kind, target_value, idempotency_key, incident_id=None)` are deliberately plain functions with string arguments and a JSON string result, and `execbound_list_actions_async` and `execbound_action_async` are their twins for a framework that runs its tools on the agent's event loop. Register both with your framework's tool decorator or schema: the listing tells the model which actions its space offers, so it need not guess an `operation_ref`, and the action tool requests one. Two rules matter more than the framework: derive the idempotency key from the task or ticket the agent is working on, never from the model's phrasing, and route an `uncertain` outcome to a person.

[`clients/python/examples/`](../clients/python/examples/) wraps both as two tools for the Claude Agent SDK (`claude_agent_sdk_tool.py`, on the asynchronous client, since that SDK runs its tools on the agent's event loop) and for the OpenAI Agents SDK (`openai_agents_tool.py`). CI runs both as written against a real gateway, through the SDK versions [`clients/python/README.md`](../clients/python/README.md) names, with a scripted model standing in for the real one (`tests/test_sdk_examples.py`). Wrappers for other frameworks are not included or verified here; the gateway's contract is the same through any of them.

## Tests

`tests/test_examples.py` drives both examples against an in-process gateway: a production target goes pending, a human decision is recorded mid-flight, the same request is sent again and the provider records exactly one mutation; a forbidden action returns `DENIED` without a provider call; a rate refusal is retried after `Retry-After`; the MCP example completes the same flow through the SDK, and its `--list` prints the space's listing, or a refused listing's code. `tests/test_sdk_examples.py` runs the two wrappers in `clients/python/examples/` through their SDKs: the scripted model lists the space's actions and asks for the one the listing names, the held action waits for a person without stopping the agent's event loop, and the same ticket asked again acts once.
