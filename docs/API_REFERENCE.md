# Interface reference

The [Tines monitoring guide](TINES_MONITORING.md) documents the separate source-authenticated HTTP endpoint, ADMIN pages, operator commands, local worker/receiver, tests and current delivery limits.

This reference describes the current private gateway, mock-provider and CLI interfaces. Source contracts live in [requests.py](../src/execbound/requests.py), [runtime.py](../src/execbound/runtime.py) and [surfaces/](../src/execbound/surfaces/). The app disables `/docs`, `/redoc` and the OpenAPI URL; the [agent API reference](https://docs.execbound.ai/api/agent) is the published OpenAPI description of the agent routes, generated from the models the gateway validates with, and its [Errors](https://docs.execbound.ai/api/agent#description/errors) section lists every code they answer. There is no public policy-administration or replay API.

## Application modes and authentication

The factory is `execbound.app:create_app`. A normal launch with only `DATABASE_URL` serves health and identity and the two credential-gated intakes, `POST /v1/monitor/events` and `POST /v1/signals`. Setting `EXECBOUND_RUNTIME_CONFIG` to the private gateway JSON composes execution, MCP and human surfaces. `execbound seed-validation` and `scripts/validation_demo.py` set up the complete mode for you.

Gateway API credentials are opaque tokens, presented as exactly one `Authorization: Bearer <token>` header. They are checked against retained digests and current expiry, revocation, principal/tenant status. Tokens are not JWTs. Execution/status require `AGENT`; human pages require a separately established human session. An agent's token is its API key, and [Get an API key](#get-an-api-key) says where one comes from.

Do not send tenant, principal, role or account override headers, extra query parameters, compressed bodies, duplicate security headers or hidden identity fields. The configured human origin also determines the accepted Host header. Errors are deliberately bounded and do not expose raw provider/SQL diagnostics.

## Get an API key

An agent calls the gateway with its own API key: a token of the form `eb1.<tenant>.<credential>.<secret>`, which the CLI and the audit chain call an agent credential. People never use one; they sign in to the console. An administrator issues it.

**In the console:**

1. Add the agent under **Agent connections**, with **Add agent**, if it is not there yet.
2. Open **API keys** in the sidebar and choose **Issue an API key**. Pick the agent, or **New agent…** with a name such as "Coding agent on my laptop", and a lifetime from one hour to 90 days, or **Never**. The agent's own page does the same from step 1 of **Connect this agent** (**Issue API key**), and then shows the configuration for its host.
3. Copy the key from the dialog. It is shown once and never stored, and closing the dialog loses it.

**From the CLI**, on an installation you run yourself:

```sh
uv run execbound credential-issue --tenant <tenant> --principal <agent> \
  --actor <admin> --output agent.token
```

This writes the key once to a new file and prints only identifiers. The [CLI table](#cli-and-operator-scripts) lists its options.

Send the key on every call as exactly one header. `GET /v1/me` confirms it works without proposing anything, and answers with the tenant, principal, credential identifier, kind and expiry:

```sh
curl -sS https://<gateway>/v1/me -H "Authorization: Bearer $EXECBOUND_CREDENTIAL"
```

The Python client reads the key from `EXECBOUND_CREDENTIAL`, or from the file named by `EXECBOUND_CREDENTIAL_FILE`, and the host recipes the console shows use the same names. MCP clients send the same header to `/mcp/`.

A key issued to never expire carries the expiry `9999-12-31T00:00:00Z`, which the console shows as Never, and stays valid until it is revoked. Only an agent's key can have it, and only from the console; `credential-issue` keeps its 90-day limit.

A key does not rotate in place, and issuing one never revokes another. To replace a key, issue a new one, give it to the agent, then revoke the old one on **API keys** or the agent's page, or with `credential-revoke`. A lost key is replaced the same way. A revoked or expired key can be deleted from **API keys** or the agent's page: it leaves every list, and the audit chain keeps its issue, revoke and delete events.

In the console an agent and its keys read by number, such as **Agent 3** and **Key 12**, counted per workspace. Every interface, export and audit record still identifies them by their UUIDs.

An API key opens only the agent routes below and cannot sign in to the console. The console's own API, at `/api/console/v1/`, accepts a signed-in person's session or an administrator's own personal access token, `Authorization: Bearer ebp1.<tenant>.<token>.<secret>`, created from **My account → Personal access tokens**; an agent's `eb1` key is still refused there. The [console API reference](https://docs.execbound.ai/api/console) is published beside this one, generated from the same models, with its own Authentication section stating what a token can and cannot do; it lists core's console API, and not a plugin's own console areas. Among them, `GET /api/console/v1/monitor/connect` and the `/api/console/v1/monitor/connections/...` routes connect Tines monitoring from the console and act on a connection; the key `POST /monitor/connections/tines` takes is sealed for the monitoring collector and is never returned, and connecting, replacing a key and revoking refuse a personal access token ([surfaces](SURFACES.md)).

## Gateway HTTP routes

| Method and path | Authority | Behavior |
| --- | --- | --- |
| `GET /health/live` | None | `{"status":"ok"}`; process liveness |
| `GET /health/ready` | None | `{"status":"ready","version":"<package version>","commit":"<source commit or null>"}` after database revision/grant/RLS checks; `commit` comes from `EXECBOUND_COMMIT` (set at image build) or the platform's own `RENDER_GIT_COMMIT`, and is null when neither states a commit id; a gateway started from a private configuration adds `keys` (`current`, `refused`, `failed` or `disabled`), the outcome of the last key reload check; a process with a plugin loaded adds `plugins` and `plugin_api`, and a process that serves the console adds `"console":"<edition>"`, the console edition its packaged build names (`core` or `hosted`); does not probe providers |
| `GET /v1/me` | Any current gateway credential | `tenant_id`, `principal_id`, `credential_id`, `kind`, `expires_at` |
| `GET /v1/actions` | AGENT | The operations the agent's own space offers: each `operation_ref`, its catalog action and label, its arguments with the values or range each accepts, the target kinds it accepts and whether an incident is required. Never a target, a rule, a limit, a placement or an account. A listed action is not permission, and listed does not mean connected. No body and no query string; an archived space answers 423 `SPACE_ARCHIVED`, a space with no active policy lists nothing, and an emergency stop does not stop it |
| `POST /v1/execute` | AGENT | Strict action body; executes, denies or returns pending/uncertain state through shared runtime. For an externally executed operation it answers a `checkpoint` object instead of dispatching ([External execution checkpoint](CHECKPOINT.md)) |
| `GET /v1/executions/{execution_id}` | AGENT owning the execution | Scoped status; optional `X-Execution-Continuation` header. Never carries a `checkpoint`: only the admission that issued a grant describes one |
| `POST /v1/executions/{execution_id}/outcome` | AGENT holding the grant's report secret | An external executor's report of what it did with its grant; settles the execution at the tier the evidence supports |
| `POST /v1/monitor/events` | A monitoring source's token, bound to one instrumented story, never an agent's; minted by `create-source` or, where the deployment configures console connect, from the console's Monitoring page, and living at most 30 days | One source-reported tool result or heartbeat of at most 16 KiB, never authority to execute anything. Tool results retain an observation; a heartbeat only updates source freshness and returns 202 with `observation_id: null` and `duplicate: false`, including on retry |
| `POST /v1/signals` | A security signal producer's `sg1.` token, never an agent's | One `execbound.security-signal.v1` envelope of at most 8 KiB, read within five seconds, through eight intake slots; answers 202 accepted, 200 for a retry of an accepted envelope, and otherwise a refusal with its code; a request refused before its envelope is parsed (a shape outside the bounds, not exactly one bearer credential, or eight envelopes already being read: 400, 401 or 429) carries no code. Served with or without the private configuration; the token opens no other route ([Security signals](SIGNALS.md#what-a-producer-sends)) |
| `POST /pre` | AGENT | Present only when the private configuration carries an `arcade` block. A control point's Pre-Execution hook, answered `OK`, `CHECK_FAILED` or `RATE_LIMIT_EXCEEDED` ([Arcade logic extension](ARCADE.md)) |
| `POST /post` | AGENT | Present under the same condition. The Post-Execution hook; settles the correlated execution where the report states a result, and answers `OK` for anything it can decide |

A deployment with no `arcade` block serves exactly the rows above it, which is what says the hook surface is absent unless someone configured it; `tests/test_route_authority.py` asserts the served set in both constructions. The two hook routes take the same request discipline as the agent routes — no query parameters, none of the four identity headers, no `content-encoding`, no duplicated `content-type` or `content-length`, and a non-AGENT principal refused and audited — and a different **body** rule: the monitoring intake's, which is `application/json` and `application/json; charset=utf-8` compared case-insensitively and nothing else, each route under its own byte bound (16 KiB for `/pre`, the configured `post_bytes` for `/post`). `surfaces/http.read_body` and what the agent routes accept do not change.

Admitted execution responses also include a stable, tenant-unique `request_ref` such as `EB-1042`. Optional `external_case` metadata groups requests without changing retry identity or authority; see [Request references](REQUEST_REFERENCES.md) for the schema and search behavior.

Status IDs use canonical lowercase UUID text. Status and identity have no request body. Execution content type is exactly `application/json`; the original body is capped at **16 KiB** and read within five seconds. Strings, numbers and unknown fields are validated strictly; duplicate JSON keys, floats and nonfinite numbers are rejected.

### Action request

This illustrative endpoint request uses a demo mapping name. The selected resource must actually exist in the authenticated tenant's registry; use the fixture helper below for a runnable request.

```json
{
  "operation_ref": "endpoint.isolate",
  "target": {"kind": "hostname", "value": "workstation.example.test"},
  "arguments": {},
  "idempotency_key": "review-one",
  "claimed_context": {"incident_id": "11111111-1111-4111-8111-111111111111"}
}
```

An action that declares arguments must carry exactly them. `endpoint.lift_isolation` takes one enumerated `reason`:

```json
{
  "operation_ref": "endpoint.lift_isolation",
  "target": {"kind": "hostname", "value": "workstation.example.test"},
  "arguments": {"reason": "false_positive"},
  "idempotency_key": "review-two",
  "claimed_context": {"incident_id": "11111111-1111-4111-8111-111111111111"}
}
```

| Field | Contract |
| --- | --- |
| `operation_ref` | Required, 1–80 characters, pattern `^[a-z][a-z0-9_.-]{0,79}$`; tenant mapping reference, not an arbitrary provider operation |
| `target.kind` | `canonical`, `hostname` or `provider_id`; identity actions reject hostname selectors |
| `target.value` | Canonical UUID; bounded ASCII DNS hostname normalized to lowercase without final dot; or case-sensitive provider ID matching `[A-Za-z0-9._:-]{1,128}` |
| `arguments` | Required object of 0 to 16 keys matching `^[a-z][a-z0-9_]{0,62}$`, each holding a string of 1–254 characters, a signed 64-bit integer or a boolean; no nesting, lists, nulls, floats or coercion. Resolution then requires exactly the resolved action's declared arguments, types and value domains ([Action catalog](ACTION_CATALOG.md#arguments)); send `{}` for an action that declares none |
| `idempotency_key` | 1–128 characters from letters, digits, `.`, `_`, `:`, `-`; scoped to tenant/principal. Exactly one of `idempotency_key` and `reference` is required; a caller with its own key management sends the key |
| `reference` | The ticket, case or run id this action responds to (1–200 characters, stripped). The gateway derives the idempotency key from it byte for byte as the Python client's `intent_key` does (the slug of the reference plus the first 32 hex characters of SHA-256 over the JSON list of operation, target kind, target value and reference), so a model-driven host and a Python client given the same ticket land on the same intent. A key beside a reference is refused unless it is the derived one. The Tines governed-action story sends a reference and no key for this reason, so it lands on the same intent as a Python client given the same ticket |
| `run_id` | Optional UUID or null; must resolve to a valid server-issued run belonging to this principal |
| `claimed_context` | Optional strict object; untrusted claims described below; defaults to empty |

The parser permits an absent `claimed_context`, but **all current action paths require `claimed_context.incident_id`** to select an independently verified incident linked to the resolved resource. The illustrative UUID above must be replaced with a real incident selector from the authenticated tenant's fixtures. It supplies a reference, not trusted severity or authority; an absent, foreign, stale or unrelated incident fails resolution.

Other optional claims are `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `environment` (`development`, `staging`, `production`), `role` (`workstation`, `server`, `domain_controller`) and integer `criticality` (0–4). All claim fields are nullable at the parser boundary. Their values never replace independent inventory/incident facts or assign authority.

The `canonical` selector contains the registry's account resource UUID (`resource_id`). Resolution then maps that representation to `canonical_target_id` for shared claims. Do not assume these UUIDs are interchangeable.

### Execution response and retries

All successful execution/status payloads contain these fields; approval fields may be null:

| Field | Meaning |
| --- | --- |
| `execution_id` | Durable scoped execution UUID |
| `state` | One of the [execution states](ARCHITECTURE.md#state-and-recovery) |
| `plan_hash` | 64 lowercase hexadecimal characters binding the frozen plan |
| `approval_id` | Associated approval UUID or null |
| `approval_state` | Current approval lifecycle state or null |
| `continuation` | Optional signed status metadata for a pending approval |
| `approval_url` | Optional configured human approval page for pending work |
| `observed` | Only on an `OBSERVED` view: `effect`, `reasons`, `obligation_ids` and `mode` (`tenant` or `mapping`), the decision the kernel would have made for an observing tenant; a record, never authorization |
| `denial` | Only on a `DENIED` view: `busy` when another request holds the target, `limit` when a shared limit covering the request is spent, whatever else denied it, `withheld` for every other denial. It never names the rule, the limit, a fact or another execution; see [Denials](#denials) |
| `notice` | Only on a `DENIED` view: one fixed sentence built from `denial` and the request's reference alone. For `withheld`, `"Denied. The reason is recorded for a person, who can find it by searching the console for EB-12. Re-sending this request returns this same answer."`; `busy` and `limit` have their own, in [Denials](#denials). The reason is never sent to the agent |
| `checkpoint` | Only on the admission that granted or re-granted an externally executed operation: exactly `{"grant": …, "act": …}` |

### The checkpoint object

An operation whose owner-provisioned mapping declares an external executor is answered with a grant rather than dispatched. The object has exactly two keys, and they are different kinds of thing: **`grant` is what admission committed and retained**, and **`act` is a token the presenter mints for this one answer** and re-mints on every later one. `act` is always present as a key and is `null` when the deployment holds no continuation keys or the act window has already closed, because the reservation and the claim are committed either way and the caller must be told what it is holding.

```json
{
  "checkpoint": {
    "grant": {
      "operation_id": "…", "provider": "mock_crowdstrike", "provider_operation": "contain",
      "resource_provider_id": "device-01", "action": "endpoint.isolate", "arguments": {},
      "precondition_class": "UNAVAILABLE", "expected_version": null,
      "act_expires_at": "…", "report_expires_at": "…",
      "regranted": false, "report_secret": "…",
      "binding": {
        "operation_id": "…", "account_id": "…", "intent_hash": "…", "plan_hash": "…"
      },
      "provider_command": {"…": "present exactly when expected_version is"}
    },
    "act": "<signed continuation, or null>"
  }
}
```

`expected_version` is present exactly when `precondition_class` is not `UNAVAILABLE`. `report_secret` is returned once, on the first answer only, and is `null` on a re-grant, which sets `regranted` to true; the row retains only its digest, so a caller that lost the first response has no re-mint. `binding` is `{operation_id, account_id, intent_hash, plan_hash}`, the four fields an executor's own record binds against the frozen command, and is always present; none of it is secret and none of it confers authority. `provider_command` is the `ProviderCommand` ExecBound would have sent had it dispatched (same target, action, arguments and version, built by the same function as a dispatch's), present exactly when `expected_version` is; a provider that speaks ExecBound's own provider protocol accepts it verbatim, and it is added to the answer by the runtime's presenter rather than carried on the grant model itself. `act` is a continuation at the `execution.checkpoint_outcome` audience binding tenant, principal, credential, execution, operation, plan hash and expiry; nothing in ExecBound verifies that audience today, and the outcome route does not accept it. A grant is neither an execution nor an approval: ExecBound dispatched nothing, and `approval_id` and `approval_state` are null unless the same execution went through an approval.

### The outcome report

```json
{
  "report_secret": "<the secret the first grant returned>",
  "outcome": "EXECUTED",
  "reason": "EXECUTED",
  "record": {"version": "…", "key_id": "…", "record": {}, "signature": "…"}
}
```

`outcome` is `EXECUTED`, `FAILED_NOT_EXECUTED`, `FAILED_EFFECT_UNKNOWN` or `UNKNOWN`. `reason` is `EXECUTED`, `VERSION_MISMATCH`, `CANCELLED_NOT_EXECUTED`, `TARGET_NOT_FOUND` or `REPORTED_FAILURE`, and is absent for `UNKNOWN`. Outcome and reason are paired by a table rather than checked for agreement: each reason names exactly one outcome, `REPORTED_FAILURE` names `FAILED_EFFECT_UNKNOWN` and nothing else, and every other spelling is `INVALID_REQUEST` at the parser before an execution row is read. `FAILED_EFFECT_UNKNOWN` and `REPORTED_FAILURE` are outside the **verified** vocabulary (no signed executor record, no ES256 attestation and no provider journal admits either), so a report presenting evidence beside `REPORTED_FAILURE` is refused at the parser too. Exactly one of `record` (the executor's Ed25519-signed envelope), `attestation` (a compact ES256 JWS, the form Tines' `JWT_SIGN` produces), `journal` (the provider's `SignedJournal` for this exact command, verified under a journal key the operator configured for the account) and `reported_at` (its own clock, retained as a reported time and never a confirmation time, carried exactly when none of the other three is) is carried. Unknown fields are refused, so an act grant cannot be presented here as a second authenticator. The refusals are `INVALID_REQUEST` and `INVALID_RECORD` (400), `INVALID_REPORT` (403), `NOT_FOUND` (404), `INVALID_STATE`, `REPORT_WINDOW_CLOSED` and `INVALID_KEY_RING` (409). `INVALID_RECORD` also answers two kinds of evidence that would verify but are not accepted for the grant: an ES256 attestation in the flattened form a settlement stores it, sent as a `record` or a `journal` rather than as the compact token in `attestation`, and a `journal` for a grant whose `precondition_class` is `UNAVAILABLE`, which carries no `provider_command`. What each outcome settles, and what a settled row still accepts, is in [External execution checkpoint](CHECKPOINT.md).

`PENDING_APPROVAL`, `DISPATCH_COMMITTED` and `INDETERMINATE` return **202**. Other views return **200**, including a policy `DENIED` view, an `OBSERVED` view, which records what an observing tenant would have decided and carries no continuation or approval page, and a settled `FAILED_EFFECT_UNKNOWN` view. A 2xx response therefore does not necessarily mean a provider effect occurred. Terminal states are `DENIED`, `EXECUTED`, `FAILED_NOT_EXECUTED`, `FAILED_EFFECT_UNKNOWN`, `STALE_AUTHORIZATION`, `OBSERVED`; `ATTEMPTED`/`RESERVED` are internal nonterminal stages.

Retry the same request/key to retrieve or progress the same intent after approval. The approval deadline is the earlier of the tenant's configured deadline after creation (120 seconds unless an ADMIN set another value between 120 and 3,600, or turned it off) and the frozen context expiry; both human decision and subsequent agent retry must precede it, and with the deadline off the context expiry alone applies. Status reads never dispatch. A changed intent under the same key conflicts, once the changed request passes the check every new one does: a changed request naming an operation the agent's space does not offer is refused 503 `EXECUTION_UNAVAILABLE`, as an unknown operation is ([threat model](THREAT_MODEL.md#b1-protected-agent-to-gateway), T1.17). Equivalent unresolved intent cannot bypass ownership with a new key, alias, run or protocol; a new key after completed work can represent a new consequential action and consume new impact. Never use this as uncertain-operation recovery.

Pending status continuations are bounded by approval expiry, credential expiry and two minutes from issue; under a longer tenant deadline a client renews one by resending the same request, which returns the same pending execution with a fresh continuation. They bind tenant, principal, credential, audience, execution/approval IDs, plan and nonce. They supplement current authentication and are not execution/approval authority. Internal tickets and provider proof/secrets are not returned.

| HTTP status | Typical meaning |
| --- | --- |
| 400 | Invalid/ambiguous input, malformed identifier or continuation |
| 401 | Missing/invalid/expired/revoked authentication |
| 403 | Wrong principal kind or human authority |
| 404 | Execution absent from the caller's scope |
| 409 | `IDEMPOTENCY_CONFLICT`, `INVALID_STATE`; `REPORT_WINDOW_CLOSED` for a report after its deadline, `INVALID_KEY_RING` for a tenant whose executor key ring will not load, and `INVALID_BUNDLE` when the active bundle cannot authorize the request in the deployment it is running in. None of the five is the transient dependency fault a 503 names, and they do not clear the same way: `INVALID_STATE` and `REPORT_WINDOW_CLOSED` are final for the row that got them, `INVALID_KEY_RING` and `INVALID_BUNDLE` stand until an administrator changes something, and `IDEMPOTENCY_CONFLICT` until the caller sends a different idempotency key. A busy target is not a 409: it is a 200 `DENIED` view (see [Denials](#denials)) |
| 423 | `TENANT_STOPPED`: the tenant's emergency stop is active, so nothing new is admitted, decided or dispatched until an administrator resumes it; a retry of a pending approval answers 202 with its unchanged view plus `tenant_stopped: true`; human pages show a banner, hide the decide form and answer 423 to a submitted decision |
| 429 | Gateway/runtime/session capacity reached, or `RATE_LIMITED` for a credential, sign-in or peer window (with `Retry-After`) |
| 503 | Unsafe/unavailable state, policy, database, connector or other dependency; also `TOO_MANY_GRANTS`, which refuses a ninth outstanding checkpoint grant for one principal and clears as its grants settle. An operation the agent's space does not offer (one nobody maps, one the tenant maps but the space's policy does not name, one reached through another space's account, or one the policy names at a mapping that has since changed), an unknown target, a claimed incident the inventory does not hold on the target and stale trusted context are all answered this same `EXECUTION_UNAVAILABLE`. What the space offers is checked before arguments are validated or a target is read, so every operation outside it costs the same statements, bad arguments are refused 400 `INVALID_REQUEST` only for an operation the space offers, and every refusal after the mapping is read costs the same statements whatever its cause, so the answer does not say which. That keeps an agent from mapping what exists beyond its own space ([threat model](THREAT_MODEL.md#b1-protected-agent-to-gateway), T1.17). The `execution.rejected` audit event records the cause, for people only: a resolution refusal as its own code (`INVALID_OPERATION`, `INVALID_TARGET`, `INVALID_CONTEXT`, `INVALID_RUN` and the rest, with `INVALID_CONFIGURATION` for another space's account and `INVALID_BUNDLE` for a policy naming a mapping that has since changed), a refusal raised as an execution error as that error's code (`NO_ACTIVE_BUNDLE`, `CONNECTOR_UNAVAILABLE` and the rest), and an unexpected database or value error as `DEPENDENCY_OR_CONTEXT_UNAVAILABLE`, the reason every resolution refusal carried before September 28, 2026. `INVALID_CONFIGURATION` is audit-only: wherever admission raises it, for another space's account, for a request held for approval and re-sent after its account or agent left the space, or for an agent in more than 64 groups, the agent is answered `EXECUTION_UNAVAILABLE` |

Every response carries `X-Request-Id`: the request's header when it was a UUID, otherwise a fresh identifier, which the structured logs use to correlate records. Execution-domain errors use `{"detail":"Execution unavailable","code":"..."}`. Authentication/header/session errors may have only `detail`. Callers should use status and documented code when present, not parse message text. [Error and refusal codes](ERROR_CODES.md) lists every code with its status. A transport failure or 503 after possible commitment is not proof of non-execution; use scoped status and administrator reconciliation.

### Denials

An agent is told that a request was denied, the request's reference and one of three categories, and never the reason itself. The recorded reason (`NOT_AUTHORIZED`, `HARD_LIMIT:<rule id>`, `HUMAN_DENIED`, `RESOURCE_BUSY` and the rest), the rules a denial matched, the facts they read and any reviewer's comment reach people only, on the record a person finds by searching the console for the same `request_ref`. `ExecutionView` has no reasons field. The runtime's presenter adds `denial` and `notice`, and `denial` is read from the recorded `DENIED` transition, so the first answer, a re-send and a status read carry the same category:

| `denial` | When | `notice` |
| --- | --- | --- |
| `busy` | The recorded reason is `RESOURCE_BUSY` alone: another request holds the target. The busy check runs after the policy decision, so the policy otherwise allowed the request | "Denied because another request holds this target. Re-sending this request returns this same answer; a new request after that one settles may be decided differently. A person can find it by searching the console for EB-12." |
| `limit` | At least one recorded reason is a `HARD_LIMIT:<rule id>`, whatever else is recorded beside it, `NOT_AUTHORIZED` included: a shared limit covering the request is spent | "Denied because a shared limit is spent. Re-sending this request returns this same answer; a new request after the limit resets is decided afresh. A person can find it by searching the console for EB-12." |
| `withheld` | Every other denial | "Denied. The reason is recorded for a person, who can find it by searching the console for EB-12. Re-sending this request returns this same answer." |

`busy` and `limit` tell an honest agent when waiting is worth a new request; neither names the rule, the limit, its window, a count, a fact or the other execution, and both facts are ones an agent could learn by trying again later anyway. `limit` is given whenever a spent limit is among the recorded reasons, because the policy records every limit that covers a request whatever it decides about the request; a limit's being spent therefore tells the agent nothing about whether a rule would allow the target, and the sentence promises only that a new request after the limit resets is decided afresh, never that it is decided differently ([threat model](THREAT_MODEL.md#b1-protected-agent-to-gateway), T1.16). A view with no reference gets the same sentences with "in the console" in place of the search. What the view has always shown stays: `approval_state` is `DENIED` after a reviewer refused, `INVALIDATED` when a request that held an approval was then denied and null when the first decision denied it, so an agent can tell a person's refusal from the rest, but never the reviewer's comment. Every notice promises that re-sending the same request returns the same answer. A new request may be decided differently, once a busy target is released, a budget's window moves on, a policy or fact changes or a person is asked again, and whether to make one is the person's call. The protected agent may be mistaken, prompt-injected or compromised, and its denials must not give it a map of the policy; a reviewer's words stay with people ([threat model](THREAT_MODEL.md#b1-protected-agent-to-gateway), T1.16). A target another execution still holds is answered this way too, as a `DENIED` with `denial` `busy`, never as a 409. An `OBSERVED` view is the deliberate exception, from an observing tenant or from an observe-only mapping in an enforcing one: its `observed.reasons` carries the reason codes, rule ids included, because observe mode exists to show a tenant what enforcement would do and nothing runs under it.

## Client package

`clients/python/` is the installable client (`execbound-client`, import `execbound_client`, Python 3.11 or later, `httpx` only) with synchronous and asynchronous clients (whose `list_actions` reads `GET /v1/actions`), `action_request`, `intent_key`, the tool functions and, behind its `mcp` extra, `execbound_client.mcp` (whose `list_actions` calls the MCP tool of that name and whose `run_action` drives one action). It encodes the six caller behaviors from the examples plus two more: an approval that expires mid-poll is returned as the stale intent rather than raised, and the actions the agent's space offers are listed rather than guessed. Not published to PyPI; see its [README](../clients/python/README.md).

## Examples

Runnable examples of a caller that handles idempotency keys, pending approvals, the same-request retry, uncertain outcomes and rate refusals correctly, over plain HTTP and over MCP with the official SDK, plus a framework-neutral tool function, live under [examples/](../examples/README.md). They run against the local demonstration and are exercised by `tests/test_examples.py`; they are not named host compatibility trials.

## MCP

Connect using **Streamable HTTP at `/mcp/`**, with the same bearer credential and a compatible MCP client. The server is stateless, uses JSON responses and exposes exactly three tools:

| Tool | Arguments | Result |
| --- | --- | --- |
| `execute` | `{"request": <ActionRequest>}` | Same execution view as HTTP, including a `checkpoint` object for an externally executed operation. The tool description tells the model to pass `reference` (the ticket, case or run id) and to re-send the identical request to progress the same action, never a new reference or key; it also states that a pending approval is not execution and that a checkpoint grant is neither an execution nor an approval, to call `list_actions` for the `operation_ref` values its space offers and their arguments, and that a denial's reason is kept for a person, so on `DENIED` it stops and gives the person the `request_ref` rather than guessing why. Every call is logged as `mcp.call` with the tool, the protocol revision and the client's name and version, identifiers only |
| `execution_status` | `{"execution_id":"<UUID>","continuation":"<optional token>"}` | Same scoped status view |
| `list_actions` | `{}`, or no `arguments` at all | The same listing as `GET /v1/actions`; any argument is refused `INVALID_REQUEST` |

There is no MCP tool for the outcome report; an executor reports over HTTP.

The `execute` tool schema is generated from `ActionRequest`, so it describes the wire shape of `arguments` as an object of bounded scalars. The schema deliberately lists no per-action argument names or domains; `list_actions` and `GET /v1/actions` list those of the operations the agent's own space offers, and the [action catalog](ACTION_CATALOG.md#production-catalog) documents every action's. A `tools/call` may leave `arguments` out, as MCP allows; when it is sent it must be an object. Tool results provide JSON text content and `structuredContent`; tool errors set `isError` and contain a bounded error payload. A denied or pending execution is a valid execution result, not necessarily a protocol error. The raw authenticated envelope is capped at **24 KiB**; the nested action still follows its 16-KiB contract. Unknown/duplicate envelope fields and conflicting protocol security input are rejected before dispatch.

The pinned server/client is MCP **2.3.0**, with the maintained **1.30.0** client installed separately from `tests/mcp-legacy.txt` for compatibility tests. Exact observed protocol versions and evidence live in [Surfaces](SURFACES.md) and the validation manifest. This does not establish compatibility with every named MCP host, OAuth discovery or federated login.

For a running fresh manual fixture, this helper selects private credentials without printing them:

```sh
uv run python scripts/validation_request.py --private local-data/demo-1 --target workstation-25 --action endpoint.isolate --key review-one --protocol http
uv run python scripts/validation_request.py --private local-data/demo-1 --target workstation-25 --action endpoint.isolate --key review-one --protocol mcp
```

Default selection is tenant 0 / `agent-0`; optional `--tenant 1` and `--agent agent-1` select other seeded actors. [Integration examples](../examples/README.md) show how to create that fixture with `seed-validation` and review its pending request.

## Human routes

These are server-rendered form workflows, not agent tools or a general JSON administration API. Use the rendered forms so CSRF and signed state correspond to the current session and frozen execution. A failed request that accepts `text/html` gets an HTML error page carrying the same status code and generic copy; other clients get the JSON error.

| Method and path | Purpose |
| --- | --- |
| `GET /login` | The sign-in page and its CSRF state: the address and password form, one button for every provider the `sign_in` block configured, the tenant's own directory when the browser carries the hint cookie a previous sign-in through it set, and, only at `/login?setup=1`, a field for a setup credential. `?review=<address>` names the console page to return to after signing in, kept as a signed five-minute hint in the closed grammar [Surfaces](SURFACES.md) describes; an address the grammar cannot use is ignored and deletes any earlier hint |
| `POST /session` | Exchange a setup credential, an issued HUMAN_APPROVER or ADMIN token such as the `state/admin.token` quickstart writes, for a session; the setup form posts here |
| `POST /session/password` | Sign in with an address and a password; one sentence for every refusal |
| `POST /login/{provider}` | Start a configured provider's flow (Google, GitHub, Microsoft); a name no block configured answers 404 |
| `GET /login/{provider}/callback` | Complete it; the transient `__Host-eb_signin` cookie is deleted on first use. A success answers 200 with a page that moves the browser on to the landing page, not a 303, so the SameSite=Strict session is sent with the next request. Where a loaded plugin registered `Registry.provider_signup`, a flow carrying that plugin's own `provider_signup` intent cookie — set only by a page that started this same flow as a signup, never by `/login` itself — dispatches here to that plugin's completion instead; a mismatched or unregistered intent is refused rather than falling through to an ordinary sign-in |
| `GET /set-password`, `POST /set-password` | Redeem a one-time set-password code, `ebp1.<tenant>.<reset>.<secret>`, typed into the form and never in the address |
| `POST /login/directory/{provider_id}` | Start the tenant's own OpenID Connect flow; the sign-in address an administrator distributes |
| `GET /login/directory/callback` | Complete it. One redirect URI for every tenant of this deployment, which is the value a customer registers at Entra ID or Okta. A success answers 200 with the same onward page as a provider's callback |
| `POST /connect/entra/signed-in` | Microsoft's `form_post` of a directory administrator's id_token during a Microsoft Entra consent the console started; served only where the configuration's `scout.entra` names the platform app, 404 elsewhere. Takes Microsoft's origin and no other, and the binding cookie the start set; a verified Global Administrator or Privileged Role Administrator of a directory no workspace has connected answers a 303 to that directory's admin consent page, and every refusal a page that moves the browser to `/monitor?view=connections&connect=refused` |
| `GET /connect/entra/consented` | Microsoft's redirect after the administrator approved; served and refused as above. Reads only the keys Microsoft documents for it and ignores any other; creates the consented connection and answers a page that moves the browser to `/monitor?view=connections&connect=done` |
| `GET /login/directory/{provider_id}/link` | A signed-in person binds their own directory account: a workspace administrator through a draft (the test sign-in that verifies it) or later, anybody else, an administrator narrowed to spaces included, only through an enabled provider, a draft or verified one answering them 404. A navigation, so a cross-site one carries no session cookie and answers 401 |
| `GET /invite`, `POST /invite` | Redeem a one-time invitation code, `ebv1.<tenant>.<invitation>.<secret>`; the sign-in that follows binds the subject to the invited person |
| `POST /session/logout` | Revoke the current session; the console's Sign out submits this form, as every page did |
| `GET /approvals/{approval_id}/classic` | The server-rendered approval page: the frozen plan, the facts with their sources, the obligations, the applicable limits, the decisions so far and the decision form. Every approval notification links it from its footer and the console's own approval route links it from its error boundary, so a phone whose console does not load, or that blocks scripts, still decides |
| `POST /approvals/{approval_id}/decide` | Assigned HUMAN_APPROVER submits `csrf`, `state` and `decision`; the same route the classic page's form posts to |
| `GET /assets/app.css` | Packaged stylesheet for the pages above, on the console's tokens and type |
| `GET /console/{file}` | The console build's own files: the hashed ones immutable, the rest revalidating by `ETag` |
| `GET /favicon.ico`, `GET /favicon.svg` | The mark, where a browser asks for it whatever a document says; the console build's own bytes, revalidating by `ETag` |

The hosted service adds public pages of its own, among them sign-up, onboarding and a public showcase; they are documented with the hosted service.

Every other address a person opens is the console, which serves its own document at core's 24 addresses, `/`, `/activity`, `/agents`, `/agents/{id}`, `/approvals`, `/approvals/{id}`, `/approvers`, `/access`, `/ask`, `/ask/{id}`, `/board`, `/credentials`, `/monitor`, `/monitor/agents/{id}`, `/people`, `/people/{id}`, `/policy`, `/policy/{id}`, `/policy/{id}/rules`, `/settings`, `/help`, `/spaces`, `/tenant` and `/welcome`, and reads `/api/console/v1/` ([surfaces](SURFACES.md#how-the-console-is-served)). A plugin's console edition adds its own addresses where that plugin is loaded, and a plugin that registers approval links adds the workspace-scoped approval address `/workspaces/{tenant_id}/approvals/{id}`. The addresses the console replaced redirect permanently: `/admin/people`, `/admin/people/{id}`, `/admin/credentials`, `/admin/approvers`, `/admin/settings`, `/policy/rules`, `/monitor/{view}` and `/next` with everything under it.

Lists show the latest 50 scoped executions. Decision and reconciliation forms redirect with 303 on success. Sessions expire after 15 idle minutes and no later than the credential; a page load after half that lifetime renews the session (never past eight hours from sign-in or the credential's expiry) and re-issues the cookies, and at most five are active per credential. The decision form stays valid for the session and the approval, not for a fixed two minutes. Cookie digests and CSRF digests are retained server-side. Exact origin, fresh persisted authority and signed form bindings are rechecked around sensitive work. HTTPS origins use Secure `__Host-` cookies and HSTS. See [Surfaces](SURFACES.md) before changing page behavior.

## Protected provider protocol

These endpoints belong to separate mock processes and are inaccessible with an agent's gateway token. All listed operations are POST with strict JSON:

| Provider | Path | Credential / action |
| --- | --- | --- |
| Endpoint | `/v1/contain` | Account dispatch credential / `endpoint.isolate` |
| Endpoint | `/v1/lift_containment` | Account dispatch credential / `endpoint.lift_isolation` |
| Identity | `/v1/disable` | Account dispatch credential / `identity.disable` |
| Identity | `/v1/enable` | Account dispatch credential / `identity.enable` |
| Identity | `/v1/revoke_sessions` | Account dispatch credential / `identity.revoke_sessions` |
| Identity | `/v1/reset_password` | Account dispatch credential / `identity.reset_password` |
| Both | `/v1/journal` | Matching dispatch or control credential / exact operation evidence lookup |
| Both | `/v1/cancel` | Control credential only / atomic no-effect tombstone if possible |

Each service registers one dispatch path per catalog binding of its configured provider. Commands freeze operation/account/tenant/resource identity, expected version, action, the action's normalized arguments and intent/plan hashes. The strict schemas in [provider/models.py](../src/execbound/provider/models.py) are the wire authority, and [the executor protocol](protocol/EXECUTOR_PROTOCOL.md) is the normative text written from them. Terminal evidence must bind the complete command and valid HMAC, with operation-specific state transitions verified before settlement. There is no public provisioning, failure-injection, reset or arbitrary passthrough route. Details: [Provider](PROVIDER.md), [Identity provider](IDENTITY_PROVIDER.md).

## CLI and operator scripts

All commands run from the repository root with the locked environment. Use `--help` for the exact argument parser. Tokens belong in private files, not command-line arguments.

| Command | Arguments / boundary |
| --- | --- |
| `uv run execbound seed-demo` | Optional `--output` (default `local-data/demo.json`); local identity-only synthetic seed; owner connection |
| `uv run execbound seed-validation` | Required `--output`, optional `--seed`, `--gateway-port`, `--endpoint-port`, `--identity-port`; complete local fixture; owner connection |
| `uv run execbound audit-export` | Required `--tenant`, `--credential-file`, `--output`; optional `--checkpoint`; current ADMIN + restricted DB connection, read-only export |
| `uv run execbound replay` | Required `--input`, `--trusted-head`, `--output`; optional `--candidate`; offline files only, new output directory |
| `uv run execbound tenant-create` | Required `--name`; owner connection; prints the new tenant ID; two tenants may share a name |
| `uv run execbound mock-reprovision` | Required `--provider endpoint\|identity`, `--tenant`, `--target`; optional `--version`, `--reason`. **Run inside the mock's own environment** (`EXECBOUND_MOCK_DATABASE_PATH`, and `EXECBOUND_MOCK_RESOURCES_JSON` when no version is stated), never against the gateway: it opens no gateway database. Resets exactly the one target named. **`--version` sets the version and touches nothing else**, which is what a target stranded by version drift needs, because resetting the containment or the disabled account it legitimately holds would contradict the audit chain. Without `--version` it resets to the resources file's values in full. Refuses a target the mock never held, and logs `mock.reprovisioned` with the tenant, the target, the old and new version and the reason |
| `uv run execbound tenant-stop` / `tenant-resume` | Required `--tenant`, `--credential-file`, `--reason`; current workspace administrator (an administrator seated in spaces is refused `INVALID_IDENTITY`) + restricted connection; activates or releases the tenant emergency stop inside the tenant fence, audited, printing the stop identifier |
| `uv run execbound tenant-status` | Required `--tenant`, `--credential-file`; current ADMIN; whether the emergency stop is active, with its identifier, time, administrator and reason, the enforcement mode and the approval deadline (`approval_deadline_seconds`, null when off) |
| `uv run execbound tenant-mode` | Required `--tenant`, `--credential-file`, `--set ENFORCE\|OBSERVE`, `--reason`; current workspace administrator; switches the tenant's enforcement mode inside the fence, audited as `tenant.mode_changed`; a no-op is refused, and a reason shaped like a password, key or token is `INVALID_REASON` |
| `uv run execbound tenant-approval-deadline` | Required `--tenant`, `--credential-file`, `--set <seconds\|off>`, `--reason`; current workspace administrator; sets how long a new approval may wait, 120 to 3600 seconds or off (the frozen plan's validity alone), inside the fence, audited as `tenant.approval_deadline_changed`; anything else is `INVALID_DEADLINE`, the current value `INVALID_STATE`, a reason shaped like a password, key or token `INVALID_REASON`; pending approvals keep their expiry |
| `uv run execbound observe-report` | Required `--tenant`, `--credential-file`; optional `--since-hours` (default 24); current workspace administrator (an administrator seated in spaces is refused `INVALID_IDENTITY`); counts observed admission decisions from the audit chain by effect, action and reason and lists every limit-driven outcome that relied on the assumed-executed projection |
| `uv run execbound rotation-readiness` | Required `--tenant`, `--credential-file`; current workspace administrator (an administrator seated in spaces is refused `INVALID_IDENTITY`); unsettled operations per account and the latest approval and session expiries that still depend on the current keys |
| `uv run execbound reconcile` | Required `--tenant`, `--credential-file`, `--execution`, `--reason`; optional `--cancel-if-missing`; current ADMIN with the private configuration's connectors; settles one committed or indeterminate execution from the provider's journal through the same path as the console form and prints the resulting view. **Not the administrator exit for a checkpoint grant**: it looks the account up in the live connector inventory and refuses, and the connector path refuses a grant in every mode. Use the Activity page's settlement control |
| `uv run execbound recover` | Exactly one of `--all-tenants`, `--tenants-file` (a JSON object of tenant id to jobs token, at most 64) or both `--tenant` and `--credential-file`; optional `--limit` (1 to 50) and `--grace-seconds` (60 to 86400); `--cancel-unattempted` only with `--tenant` or `--tenants-file`; `--budget-seconds` (1 to 3600, default 480) only with `--all-tenants`. `--all-tenants` holds no credential: it checks the schema and the directory's policies before visiting anything, walks every active workspace in the directory of tenants as that workspace's scheduler principal, then settles, sending nothing, queued notifications whose approval is closed or whose destination is gone, and retires thirty-day-old assistant text there, starts no workspace once the budget is spent, and prints `visited`, `inactive`, `failed` and `not_reached` with an entry for each workspace where something happened or that failed; it refuses `--tenant`, `--credential-file`, `--tenants-file` and `--cancel-unattempted` beside it. The other two modes run as a current ADMIN; a refused tenant in the map is reported as `{"skipped": code}`, as a refused workspace is in `--all-tenants`, and neither changes the exit code 0, nor does a database at another schema revision under `--tenants-file`, which skips every tenant in the map (`--all-tenants` checks the schema first and exits 2). A database whose grants do not match what this process's plugins claim stops the run in every mode with exit code 2 and a sentence saying which is wrong. Every mode reaches accounts through the private configuration's runtime, sample accounts included, and runs one bounded recovery per workspace through the reconciliation path, printing counts and the run identifier. It also sweeps unreported checkpoint grants into retained uncertainty without settling, refunding or releasing anything, and releases the canonical claim a settlement on an executor's bare word left held once the act window has passed |
| `uv run execbound notify` | Exactly one of `--all-tenants`, `--tenants-file` (as for `recover`) or both `--tenant` and `--credential-file`; optional `--limit` (1 to 50). `--all-tenants` holds no credential: it drains every workspace an email, Slack, Teams or webhook destination in the private configuration names, and prints `visited`, `inactive`, `failed` and `not_reached` with each workspace's counts where anything was delivered, failed or closed; it refuses `--tenant` and `--credential-file` beside it. The other two forms run as a current ADMIN. Every form delivers pending approval notifications with the private configuration's destinations, with lease, retry and backoff, printing counts. A refused tenant in the map is reported as `{"skipped": code}` with the exit code 0, and so is every tenant under `--tenants-file` when the database is at another schema revision; `--all-tenants` checks the schema first and exits 2 there with the runtime check's sentence. A database whose grants do not match what this process's plugins claim stops the run in every form with exit code 2 and a sentence saying which is wrong |
| `uv run execbound notifications` | Required `--tenant`, `--credential-file`; optional `--state`; current ADMIN; lists approval notifications with their `kind` (`approval.pending`, `approval.reminder` for a reminder, or `approval.closed` for an outcome message), delivery state, attempts and error codes |
| `uv run execbound export-events` / `export-status` / `export-resume` | Required `--tenant`, `--credential-file`; `export-events` takes `--limit` (1 to 1000) and `export-resume` takes `--destination`; current ADMIN with the private configuration's `security-events` destinations; ordered, at-least-once export of the sanitized audit chain and failure summaries through per-destination cursors |
| `uv run execbound principal-create` | Required `--tenant`, `--kind`; `--actor` (an ADMIN principal) required except for a tenant's first ADMIN; owner connection, audited |
| `uv run execbound credential-issue` | Required `--tenant`, `--principal`, `--actor`, `--output`; optional `--lifetime-hours` (default 8, maximum 2160); writes the token once to a new exclusively created file, owner-only where the platform carries POSIX modes ([Operations](OPERATIONS.md#administer-tenants-credentials-approvers-and-bundles)), and prints only identifiers; owner connection, audited |
| `uv run execbound credential-list` | Required `--tenant`; owner connection; identifiers, kinds, timestamps and each credential's authentication failures in the last 24 hours, never digests |
| `uv run execbound credential-revoke` | Required `--tenant`, `--credential`, `--actor`; owner connection, audited |
| `uv run execbound approver-assign` / `approver-unassign` | Required `--tenant`, `--approver`, `--target`, `--action`, `--actor`; `--action` accepts every action in the [action catalog](ACTION_CATALOG.md), so a new action is assignable as soon as it is released; the approver must be a HUMAN_APPROVER and the target a known canonical target; owner connection, audited |
| `uv run execbound group-create` | Required `--tenant`, `--name` (1 to 80 characters after trimming, unique within the tenant, and `INVALID_NAME` when shaped like a password, key or token), `--actor`; owner connection, audited as `group.created`; prints the new group ID |
| `uv run execbound group-assign` / `group-unassign` | Required `--tenant`, `--group`, `--principal`, `--actor`; the principal must be an active AGENT (`INVALID_PRINCIPAL`) and the group must exist (`INVALID_GROUP`); a repeated, missing or 65th membership is `INVALID_MEMBERSHIP`; both take the tenant fence so the change is ordered against every decision; owner connection, audited as `group.assigned` / `group.revoked` |
| `uv run execbound group-list` | Required `--tenant`; owner connection; each group's identifier, name, creation time and sorted member identifiers |
| `uv run execbound executor-key-register` | Required `--tenant`, `--key-id`, `--public-key` (an executor's Ed25519 public key as 64 lowercase hex characters; uppercase is normalized), `--actor`; owner connection, audited as `executor_key.registered`; refuses a taken id, material already live for the tenant, material already recorded compromised, any encoding nobody holds the private half of and an id shaped like a password, key or token (`INVALID_KEY`) |
| `uv run execbound executor-key-rotate` | Required `--tenant`, `--key-id`, `--new-key-id`, `--public-key`, `--actor`; registers the replacement and retires the old row as `RETIRED` in one transaction, so a proof for a grant issued while the old key was current still verifies; audited as `executor_key.rotated`; a new id shaped like a password, key or token is `INVALID_KEY`, the old id never is |
| `uv run execbound executor-key-revoke` | Required `--tenant`, `--key-id`, `--actor`; retires one live key as `RETIRED`; refused while it is the tenant's last live key and an active bundle declares an external executor; audited as `executor_key.revoked` |
| `uv run execbound executor-key-compromise` | Required `--tenant`, `--key-id`, `--actor`; records `COMPROMISED`, which the verifier reads **retroactively**, over a live or already retired row, for every id of the tenant carrying that public key; it may leave the ring empty, and admission then refuses new grants for the tenant until a replacement is registered; audited as `executor_key.compromised`. See [Operations](OPERATIONS.md#register-and-cut-off-executor-keys) for what it costs |
| `uv run execbound executor-key-list` | Required `--tenant`; owner connection; each key's id, registered public key, creation and revocation times and revocation reason; writes and audits nothing |
| `uv run execbound account-create` | Required `--tenant`, `--provider` (a provider the action catalog binds), `--actor`; owner connection, audited as `account.created`; prints the new account ID |
| `uv run execbound mapping-create` | Required `--tenant`, `--account`, `--action` (catalog action bound for the account's provider), `--actor`; optional `--ref` (operation ref, default the action name, unique per tenant), `--mapping-version` (default `map-v1`) and `--contract-version` (a catalog contract version serving the action; one that does not serve it is `INVALID_CONTRACT`, and a version the catalog does not hold is a usage error; an operation ref or mapping version shaped like a password, key or token is `INVALID_REFERENCE` or `INVALID_VERSION`); provider operation and schema version come from the catalog, and the contract is the catalog's default for the action unless `--contract-version` names another; audited as `mapping.created`; prints the mapping |
| `uv run execbound target-create` | Required `--tenant`, `--actor`; owner connection, audited as `target.created`; prints the canonical target ID |
| `uv run execbound resource-create` | Required `--tenant`, `--account`, `--resource-type`, `--provider-id`, `--source` (an active inventory context source of the account), `--actor`; optional `--target` (existing canonical target, else a new one), `--hostname` (endpoints only), `--version` (default `resource-v1`), `--alias-days` (default 365), `--role`, `--privilege-class`, `--environment`, `--criticality` (checked against the contract domains); creates the resource, its identity and its `provider_id` and hostname aliases; audited as `resource.created`; prints the resource, target and aliases |
| `uv run execbound account-list` / `mapping-list` / `resource-list` | Required `--tenant`; owner connection; accounts with provider and state, mappings with their catalog-derived fields, resources with target and unexpired aliases |
| `uv run execbound failures` | `--tenant` or `--unattributed`; optional `--since-hours` (default 24, maximum 2160); owner connection; failed-authentication windows by surface, reason, minute and verified subject, never tokens or addresses |
| `uv run execbound ruleset-compile` | Required `--tenant`, `--input`, `--output`; optional `--ref` (repeatable: compile over these active mappings only, else every active one) and `--signal-mappings` (a JSON array of signal mapping entries carried into the bundle, never compiled); owner connection, reads the tenant's active mappings, writes the bundle document the rules compile to and nothing else; rules name the catalog action, and a mapping whose ref is another name for its action carries that action; refuses to overwrite, refuses a tenant with no mapping or a `--ref` naming no active mapping, reports a bad rule, two mappings that cannot share a bundle or a bad signal mappings file at its field location |
| `uv run execbound signal-source-create` | Required `--tenant`, `--actor`, `--label`, `--producer`, `--version-min`, `--version-max`, `--output` and one of `--principal` (repeatable, up to 64 active agents) or `--group`; optional `--capability` (repeatable, default `resource_compromise.v1`), `--space` (default the tenant's only space), `--offered`, `--input-path` (`independent`, the default, or `agent_forwarded`), `--attests-liveness` and `--hours` (the token's lifetime, 1 to 720, default 720); owner connection, audited as `signal_source.created`; writes the `sg1.` token once to a new owner-only file and prints the source id, the expiry and the file ([Security signals](SIGNALS.md#register-a-producer)) |
| `uv run execbound signal-source-rotate` | Required `--tenant`, `--source`, `--actor`, `--output`; optional `--hours` (default 720) and `--grace-seconds` (0 to 3600, default 600); owner connection, audited as `signal_source.rotated`; writes a new token once and keeps the old one working for the grace window, never past its own expiry; refuses a revoked source (`INVALID_STATE`) |
| `uv run execbound signal-source-revoke` / `signal-source-list` | Required `--tenant`, and `--source` and `--actor` to revoke; owner connection; revocation is immediate and final, ends a grace window too and is audited as `signal_source.revoked`; the list shows every source's registration and health and never a digest |
| `uv run execbound bundle-create` | Required `--tenant`, `--credential-file`, `--input`; JSON bundle file (`tenant_id` and `bundle_id` may be omitted); current ADMIN + restricted connection, audited DRAFT; content holding text shaped like a password, key or token is `INVALID_TEXT` at its location |
| `uv run execbound bundle-validate` / `bundle-activate` / `bundle-retire` | Required `--tenant`, `--credential-file`, `--bundle`; `bundle-activate` also takes an optional `--reason`, recorded in the `policy.bundle_activated` event and refused as `INVALID_REASON` when blank, longer than 500 characters or shaped like a secret; current ADMIN + restricted connection; audited lifecycle transitions; a quorum rule naming an unknown obligation is refused with its field location (`quorum.<n>.obligation`); a limit rule naming an action outside the catalog, an unknown group, an unknown or inactive account, or a selector fact no serving contract declares or a value outside its domain is refused at `limits.<n>.action`, `limits.<n>.group_id`, `limits.<n>.account_id` or `limits.<n>.selector`; a mapping's `action` other than its row's at `mappings.<n>.action`; and a signal mapping the source registrations or the bundle's space cannot support at `signal_mappings`, `signal_mappings.<n>`, `signal_mappings.<n>.capability`, `signal_mappings.<n>.admitted_sources.<m>` or `signal_mappings.<n>.thresholds.<m>` ([Security signals](SIGNALS.md#map-its-verdicts)) |
| `uv run execbound bundle-list` | Required `--tenant`, `--credential-file`; current ADMIN; lifecycle state and active selection per bundle |
| `uv run execbound bundle-preview` | Required `--tenant`, `--credential-file`, `--bundle`; optional `--window-hours` (default 24, maximum 720); current ADMIN; read-only in-memory replay of the candidate against recent frozen history, listing decisions whose effect would change, each with the candidate's effective approver requirement; the output's `scope` is `workspace` for a workspace-wide administrator, and an administrator narrowed to some Spaces gets only the decisions recorded in those Spaces, with `scope` `spaces`; a candidate group rule over captures without recorded membership marks the affected decisions `UNKNOWN_GROUP_MEMBERSHIP` |
| `uv run python scripts/local_setup.py` | Optional `--postgres-bin`; prepare local DB/roles/private environment, no migration |
| `uv run python scripts/validation_demo.py serve` | Required `--private`; foreground manual gateway/providers |
| `uv run python scripts/validation_demo.py run` | Required `--private` and `--output`; automatic browser/provider/replay demonstration |
| `uv run python scripts/validation_request.py` | Required `--private`, `--target`, `--action`, `--key`; optional `--tenant`, `--agent`, `--protocol` |
| `uv run python scripts/validation_evidence.py` | Required `--junit`, `--collected`, `--evidence`, `--output`; validate and hash the evidence allowlist |
| `uv run python scripts/admission_benchmark.py` | Required `--private`, `--output`; optional `--seconds`, `--concurrency`, `--tenants`; denied-admission throughput and latency per concurrency level against fresh fixtures |
| `uv run alembic upgrade head` | Separate owner migration connection; explicitly apply reviewed migrations; a database that holds a plugin's grants is migrated with that plugin's own upgrade command instead, because Alembic grants nothing |

The hosted service's plugin adds commands of its own, present only where that plugin is loaded; they are documented with the hosted service.

Bundle create/validate/activate/retire/list functions live in [policy/store.py](../src/execbound/policy/store.py) and back the `bundle-*` commands; tenant, principal, credential, approver-assignment and principal-group operations live in [administration.py](../src/execbound/administration.py) and back the owner-connection commands; the administration pages ([surfaces/admin_pages.py](../src/execbound/surfaces/admin_pages.py)) make the same principal, credential and assignment changes through the `SECURITY DEFINER` functions of migration `0021_admin_functions`, which refuse administrator principals and credentials. Bundles may carry `context_settings` that tune a context contract's max age and permitted writers; see [Context contracts](CONTEXT_CONTRACTS.md). Limit rules may be scoped to a principal group, a connector account or a selector over a trusted fact and may span several actions; see [Policy](POLICY.md). Every administrative change appends an audit event under the acting ADMIN principal; a tenant's first ADMIN is audited as its own actor. Bundle management is also available on the policy pages. No inventory sync service or HTTP interface provisions inventory or incident context: `resources` columns, `incidents` and `resource_facts` rows are written only through the owner connection, by `context-import` from adapter-produced manifests, and context sources by `context-source-create` and `context-source-deactivate` ([provisioning.py](../src/execbound/provisioning.py); see [Context contracts](CONTEXT_CONTRACTS.md#provisioning-trusted-context)). Security signals are the exception: a producer the owner registered with `signal-source-create` posts them to `POST /v1/signals`, `signal_admit` is their one writer, and they count only through a bundle's `signal_mappings` ([Security signals](SIGNALS.md)).
