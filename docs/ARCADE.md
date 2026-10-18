# Arcade logic extension

Arcade is a tool-calling layer for enterprise agents, and it exposes webhooks at points in the tool lifecycle so a customer can supply its own decision logic. This guide describes ExecBound as the decision service behind its Pre- and Post-Execution hooks: what the deployment decides, what it cannot, what an operator has to configure and what it costs when a platform lies or says nothing. Acceptance cases AL1 to AL34 are in the [acceptance inventory](ACCEPTANCE_TESTS.md#arcade-logic-extension).

**Most of what is described here is fixture-tested, and one live trial measured part of it.** The work is developed against a loopback fixture caller and the protected mocks, as the [checkpoint](CHECKPOINT.md) was. A live trial on 18 September 2026 against an Arcade playground project observed blocking twice, and state end to end on one live call; [Enforcement mode and evidence class](#enforcement-mode-and-evidence-class) says what it established and what it did not. Nothing else about how a real Arcade deployment behaves is claimed. That includes the hook contract itself, which was read on 17 September 2026 from a **beta** published schema (`logic_extensions/http/1.0/schema.yaml`, `info.version: 1.1.1-beta`).

**This is an enforced budget and an enforced approval over a cooperative execution, and it is never prevention.** ExecBound sends nothing, sees nothing at the vendor, and claims nothing about an agent that reaches a vendor without going through Arcade — that is Arcade's claim about its own product, cited here and never asserted.

## Placement: the Gate placement, with the grant suppressed

Nothing about placement is new. An operation is externally executed because its bundle mapping carries `external_executor`; admission reserves impact, takes the canonical target claim, consumes any approval in the same fenced transaction and answers a checkpoint object instead of a dispatch ticket. All of that is [External execution checkpoint](CHECKPOINT.md) and the extension changes none of it.

What does not fit is the **exchange**. A hook response carries an enumerated code, a message string and an override this deployment never sets, so there is nowhere in it to put a grant. The checkpoint object cannot reach the caller, and the party that returns later is the platform on the same channel with a body ExecBound did not shape and no signature in it. So the extension reads the report secret out of the grant, retains it on a correlation row of its own for the life of that grant, and discards the act continuation.

The one-line answer: **not the Gate protocol; the Gate placement, carried by ExecBound's own correlation instead of by a grant.**

The extension is a **translator**. It turns a hook into the wire body `ActionRequest` already defines and calls `Runtime.execute`, and it turns a post hook into the body the outcome route already defines and calls `Runtime.report`. It evaluates no policy, opens no transaction of its own around a decision, has no other path into the kernel, and everything it decides by itself can only refuse.

## The tool map

**The map is owner-provisioned and no hook field selects it.** An Arcade tool is a `toolkit`, a `name` and a `version`; an ExecBound action is reached through `operation_ref`, the tenant's own key into `operation_mappings`, from which the provider, resource type, action, provider operation, schema version, context contract and connector account all come. The map is one declaration per governed tool, held in the private configuration file beside `preconditions` and `connectors` and read the same way — deployment configuration, outside the serialized operation composite, so no released action spec, provider binding, bundle hash or frozen plan moves because of it.

```json
{
  "arcade": {
    "deadline_seconds": 4.0,
    "post_bytes": 1048576,
    "tools": [
      {
        "toolkit": "endpoint_mock",
        "name": "ContainDevice",
        "versions": ["1.0"],
        "operation_ref": "endpoint.isolate",
        "target": {"kind": "provider_id", "input": "device_id"},
        "incident": {"input": "incident_id"},
        "inputs": ["device_id", "incident_id"],
        "arguments": {},
        "expect": {"destructive": true, "read_only": false}
      }
    ],
    "ungoverned_toolkits": ["gmail"]
  }
}
```

Five rules make that declaration safe to trust, and each is a refusal rather than an inference:

- **Exact versions, no wildcard.** `versions` is an explicit list of at most 32 entries. A tool at an undeclared version is not governed by the declaration made for another version, because a vendor can change what a tool does across versions and a wildcard would carry the operator's decision forward into a tool they never saw.
- **A declared input set, and nothing else admitted.** `inputs` lists every key the deployment understands, and an `inputs` object carrying any other key is `UNDECLARED_INPUT` before any kernel call. ExecBound decides on the fields it modelled and Arcade executes the whole object, so a field ExecBound does not model could change what the vendor does; refusing an undeclared key bounds that and fails closed on vendor schema drift.
- **One declared target key, extracted by name.** `target.input` names exactly one top-level key of `inputs`, and `target.kind` is one of `canonical`, `hostname` or `provider_id`. There is no expression language, no path syntax and no fallback, because a second place that can choose a target is a second place that can decide authority. Everything else in `inputs` is ignored for selection. The kernel keeps its own refusals: an identity resource named by hostname is refused there, which is where that refusal belongs.
- **One declared incident key, optional, extracted the same way.** `incident.input` names one top-level key whose value is the id of the incident the agent says it is acting under. It is optional because a contract may set `incident="none"`, and it is what a tool mapped to a released action needs: each of the four context contracts the production catalog releases sets `incident="required"`, and `resolution.registry.incident` reads that id from `ActionRequest.claimed_context.incident_id` alone. The value is validated through `ClaimedContext` itself over the same strict JSON path `parse_request` uses, so what the map admits is what an `ActionRequest` admits — the alternate UUID spellings pydantic accepts included, each the same id afterwards. An absent key, an explicit null and a value that model refuses are all `INVALID_INCIDENT` before any kernel call.
- **Arguments are canonical arguments, and the bound is the catalog's rather than the wire's.** `arguments` maps declared input keys to the action's typed arguments, at most sixteen, and no two inputs may map to one argument. `Arguments` accepts any string of 1 to 254 characters on the wire; it is the **resolved action's catalog spec** that refuses everything but its own enumerated values, afterwards. So what makes an argument unable to carry a secret, markup or a second selector is the catalog, one layer further in than an edge check, and a deployment that maps an input to an argument the action does not declare is refused at resolution.

### What a claimed incident buys, and what it does not

It buys the ability to make a claim; it buys no fact. `registry.incident` selects the incident row under the mapping's own `tenant_id`, `account_id`, `provider` and `resource_type`, and under `i.resource_id = :target` — the already-resolved target — inside a transaction opened on the authenticated tenant with forced row-level security on `execbound.incidents`. An id naming nothing, an incident of another tenant, an incident of another connector account and an incident standing against another resource each resolve no row and the request is refused.

**What is not bound is which of the target's incidents it is.** A second incident of the same tenant standing against the same endpoint satisfies the query, and so does an older or a closed one. The contract then freezes `incident_status` and `incident_severity` *from that row*, and what refuses a closed or low-severity incident is the tenant's policy pack reading those facts — the synthetic endpoint pack requires `incident_status == "OPEN"` and `incident_severity == "CRITICAL"` among its conditions — together with the incident source's staleness window. Read it as: the declaration lets an agent say which incident it is acting under, the kernel refuses a claim about the wrong target or the wrong tenant, and the policy pack decides whether an incident in that state justifies the action.

The other four fields of `ClaimedContext` — `severity`, `environment`, `role` and `criticality` — are never set from a hook. Each is a fact a contract resolves from a trusted source, and a control point asserting one would reach policy through a surface that evaluates none.

### What metadata may and may not do

Reported metadata arrives from Arcade on every call and is therefore caller-supplied input, so it decides nothing. It may not select a mapping, choose an action, choose a target, choose an incident, move a tool between governed and ungoverned, set a precondition class or promote an evidence tier. It may do exactly two things:

- It is **retained** as reported attributes on the correlation row and shown on the human pages as inert text, so an approver can see what the platform said about the tool it is being asked about.
- It may **only refuse**. Where the declaration carries `expect`, a hook whose reported `behavior` contradicts it — a tool mapped to `endpoint.isolate` reporting `read_only: true` — is denied, because the deployment's map and the platform's self-description disagree about what the action does. A fact the report omits or reports as null contradicts nothing. A caller that lies in that direction denies its own action, which charges nothing and performs nothing, so the check can only cost the caller.

### Governed, ungoverned and undeclared

`ungoverned_toolkits` names one toolkit exactly, and a toolkit may not be named as both governed and ungoverned. A tool of an ungoverned toolkit answers `OK` with **no kernel call, no execution row, no reservation and no audit event**. That is an explicit standing decision by the operator, and obligation 5 states what it costs.

A tool that matches neither a governed declaration nor an ungoverned toolkit is `UNMAPPED_TOOL`. The default for anything undeclared is refusal, so passing always requires someone to have written it down.

The reason an ungoverned pass appends nothing is the **lock**, not the volume. `append_event` takes `audit_heads … FOR UPDATE`, the per-tenant serializing structure, and measured admission throughput under that fence is about forty per second per tenant with median latency growing with concurrency. An ungoverned pass is the success path of every tool call in the project, and nothing establishes that a logic extension can be scoped to a subset of tools, so appending would put the project's entire tool traffic behind the tenant's audit head inside a five-second hook — to record calls the deployment has explicitly decided not to govern. Limitation 7 states the residual.

### `context.user_id` and `authorization`

`context.user_id` is **attribution**, not identity and not a budget scope. It is Arcade's end user, reported per call, retained on the correlation row and displayed as inert text. It cannot be an ExecBound identity, because identity comes from authentication; and it cannot be a limit scope, because `LimitScope` is exactly `principal`, `tenant`, `group`, `account` and `selector`, a selector is one trusted fact of the frozen plan, and a budget keyed on a caller-reported string is a budget the caller can evade. One Arcade project is one ExecBound principal and one autonomous budget.

`authorization[].oauth2.at` carries access-token claims when the token is a JWT. ExecBound holds no key that could verify them, so they could never be authority, and they are third-party identity material this system has no reason to hold: they are **not parsed, not retained and not logged**. `context.secrets` carries names and no values, so this integration hands ExecBound no token value it would have to refuse to store.

### The block joins the configuration shape

The `arcade` block is part of `_Configuration.shape()`, the tuple a key reload may not change, for the reason `preconditions` is already in it. A file whose tool map differs from the running one would otherwise be accepted as a key rotation: either the map silently changes under a live deployment, or the operator is told the change took effect while the running deployment still holds the old map. A changed block is `CONFIGURATION_CHANGED` and needs a restart.

`deadline_seconds` is **required with no default** and is bounded above by thirty seconds; `post_bytes` defaults to one MiB and is bounded between one KiB and eight MiB. The existing minimum of one connector relaxes to zero exactly when an `arcade` block is present, so a deployment that dispatches nothing has none to declare. Configuration validation refuses, each as the same opaque invalid-configuration answer every invalid file gets: an `operation_ref` outside the character class `ActionRequest.operation_ref` itself admits; a toolkit named as both governed and ungoverned; a `target.input` or an `incident.input` outside its own `inputs` list; an argument mapped from an undeclared input; two inputs mapped to one argument; a duplicate tool declaration; and a block with no `deadline_seconds`.

## The pre hook

`POST /pre` authenticates as an AGENT, maps, calls `Runtime.execute` and answers one of three codes.

| What the kernel answered | Hook code |
| --- | --- |
| `DISPATCH_COMMITTED` with a grant **whose report secret this Arcade execution's own correlation row now holds** | `OK` |
| `OBSERVED` — the tenant is in `OBSERVE` | `OK` |
| An ungoverned toolkit, with no kernel call made | `OK` |
| `DISPATCH_COMMITTED` with no secret for this Arcade execution: a re-grant for a second Arcade id, or a row whose first delivery was lost | `CHECK_FAILED` |
| `DENIED`, `PENDING_APPROVAL`, `STALE_AUTHORIZATION`, or any state other than the two above | `CHECK_FAILED` |
| `TENANT_STOPPED`, `INVALID_BUNDLE`, `TOO_MANY_GRANTS`, `CONNECTOR_UNAVAILABLE`, `EXECUTION_UNAVAILABLE`, `IDEMPOTENCY_CONFLICT`, an unmapped tool, an undeclared input key, a bad incident claim, a metadata contradiction, a malformed hook, the extension's own deadline | `CHECK_FAILED` |
| `BUSY` (the runtime's capacity bound) or `RATE_LIMITED` (the surface rate limiter) | `RATE_LIMIT_EXCEEDED` |

A tenant emergency stop is refused ahead of both `OK` rows, because a hard denial wins over a permit.

**The last row inverts what one might expect, and the reason is in the code.** A shared impact ceiling denies with `HARD_LIMIT:<rule_id>` on the transition and the audit record, and `ExecutionView` has no reasons field, so a denied caller is told the state and nothing about why — deliberately, because messages are generic and codes are the contract. Answering `RATE_LIMIT_EXCEEDED` for a budget ceiling would need a new channel telling a caller which rule stopped it, which no other caller of this kernel gets. `BUSY` and `RATE_LIMITED` mean what Arcade's enum means and arrive fast, because the capacity bound is acquired non-blocking and refuses rather than queues.

**`error_message` lands in the agent's context, so it is bounded, inert and derived from nothing untrusted**: a stable ExecBound code, the ExecBound execution id where one exists, and, for a pending approval, the deployment's approvals page. It never carries an input value, a vendor string, a policy rule body, a report secret or a continuation token, and the continuation the runtime mints for a pending approval is discarded rather than passed on — what progresses an approved execution here is the agent's next tool call, arriving as another pre hook.

**The extension answers inside its own deadline, not Arcade's.** A `CHECK_FAILED` blocks whatever failure mode the project is configured with, while a timeout blocks only if fail-closed is set, so answering rather than timing out is how the overload case stops depending on a setting ExecBound cannot see. The deadline is `asyncio.wait_for` around the threadpool call and answers `CHECK_FAILED` rather than the retryable code, because an abandoned decision may still have committed and inviting an immediate retry would invite a refusal. The cost is stated rather than hidden: **an abandoned decision may still commit, leaving a reservation for an action Arcade then blocked.** That is retained uncertainty with an administrator exit, never a refund, and the cap of eight bounds how much of it one principal accumulates.

There is no default deadline to inherit. The arithmetic an operator owns is in the measurement below.

### The boundary rewrites the application's own refusals

`create_app`'s outermost middleware answers a bare 429 `{"detail": "Service busy"}` when its 32-slot capacity bound is full, and its handlers answer a bare 503 `{"detail": "Service unavailable"}` for a dependency failure. Neither is a hook result, neither carries a `code`, and the route never runs — so without a rewrite the whole decision table is bypassed exactly when the deployment is under load. The `create_arcade` boundary therefore rewrites per route, and the two routes get **opposite** rules:

| Path | What the boundary does with a non-hook answer |
| --- | --- |
| `POST /pre` | 429 becomes `200 {"code": "RATE_LIMIT_EXCEEDED"}`; every answer that is neither a 200 nor a 401 becomes `200 {"code": "CHECK_FAILED"}`, with no `detail` key surviving — a malformed body included |
| `POST /post` | Nothing. A 400, 429, 500 or 503 passes through with its own status and body |
| Both | 401 passes through unchanged |

The asymmetry is the rule: **on the way in an answer is better than an error, because an answer blocks; on the way out an error is better than an answer, because an error is retried.** A malformed or unreadable post *body* is not an error under that rule — it is silence, answered `OK`, because no retry of an unreadable body will read differently.

### The granting-path measurement

`scripts/admission_benchmark.py` runs **denied** admissions deliberately, so every request takes the full serialized path with no provider effect: it reserves nothing, takes no canonical claim, consumes no approval, loads no executor key ring and mints no grant. An eligible pre hook does all five. So that benchmark is a **floor on the granting path and not a budget for it**, and acceptance row AL32 measures the granting path itself — the eligible pre hook end to end at one, four and sixteen concurrent callers of one tenant, with the reservation, the canonical claim, an approval consumption, the key ring load, the closing attestation check and the secret mint inside the timed region. It asserts that the fixture deployment's configured `deadline_seconds` exceeds the measured maximum, and reports medians and a maximum beside the denied-path figures; the two are read together or neither means anything. Limitation 11 says what it does not establish.

## The post hook

`POST /post` reads under the deployment's own `post_bytes` bound. `output` is typed as opaque, validated for nothing, dropped before anything else happens, never retained and never logged.

| Post hook | Reported to the kernel | State | Tier | Impact | Canonical claim |
| --- | --- | --- | --- | --- | --- |
| `success: true` | `EXECUTED`, reason `EXECUTED`, the extension's own clock | `EXECUTED` | `ASSERTED` | Confirmed | Held, released by the scheduled run once the act window has passed |
| `success: false`, with or without `execution_code` and `execution_error` | `FAILED_EFFECT_UNKNOWN`, reason `REPORTED_FAILURE`, the same clock | `FAILED_EFFECT_UNKNOWN` | `ASSERTED` | **Confirmed** | Held, released by the same run at the same boundary |
| `success` absent | `UNKNOWN` | `INDETERMINATE` | none | Charged | Held |
| A body ExecBound could not read — oversized, or malformed | nothing | unchanged | none | Charged | Held |
| No post hook at all | nothing | Swept to `INDETERMINATE` at the report window | none | Charged | Held |

**The first two rows cost a caller exactly the same, and that is the whole design.** Both confirm the reservation, both leave the canonical claim standing until the act window closes, and both close the execution to anything but a restatement. There is nothing to be gained by choosing one over the other, so there is nothing to lie about: what a report decides is what the tenant's history says happened, never what the tenant's budget looks like afterwards.

**`success: false` and an absent `success` are not the same statement, and one of them is not a statement.** `success` is optional in the published schema, so its absence is not a quiet failure and not a quiet success; it is a post hook that states no result. Settling on it would write "the control point reported failure" into a tamper-evident history when the control point reported nothing, and it would invert the gradient: closing a row frees the intent and a cap slot, so making silence close a row would make saying nothing the cheapest way to close one. Under this rule the opposite holds — a platform that states a result is better off than one that stays quiet.

That rule decides the other rows the same way: **a post hook that states no result leaves exactly what no post hook leaves.** An absent `success`, a body past `post_bytes`, a body that will not parse and no post hook at all are all silence, and all four end in retained uncertainty with the impact charged, the claim held and the administrator exit as the only way out.

`success: true` beside an `execution_error` is a platform message inconsistent with itself. It is retained on the correlation row, appends no audit event and changes no settlement.

**The post hook answers `OK` for anything it can decide**, a body it could not read included. Its only non-200 answers are the 401, the frame refusal and the transport-level 429 and 5xx the boundary passes through unchanged, which exist precisely so a settlement Arcade could redeliver is redelivered. The post hook's own `tool` and `context` select nothing: **correlation is the only route from a post hook to an execution.**

### Why a large post hook must not be refused

`post_bytes` is a bound on what ExecBound reads and never a reason to answer 4xx. A 4xx is not retried under the published contract, so refusing a large report would lose the settlement it carried and leave the row open, charged and holding its target. An oversized body is therefore recorded as an unreadable report and answered `OK`, with no part of `output` retained or logged.

### Two recorded contradictions

Four arrivals are recorded rather than settled. Two of them append to the tenant's hash chain under `execution.control_point_contradiction`, **exactly when they move the correlation row** from no contradiction recorded to one recorded, so a duplicate appends nothing and one correlation row produces at most one of each kind:

- A post hook whose correlation row is a **denial** — evidence that a denied call ran anyway, and the only evidence any of the [operator obligations](#operator-obligations) was missed.
- A post hook whose `inputs` **differ** from the inputs the decision froze — evidence that something changed the call after ExecBound decided on it.

Both are missing or contradictory evidence and neither is a proven bypass. The other two arrivals — an observing tenant's post hook, and one with no correlation row at all, including one that overtakes its own pre hook — are recorded bounded and answered `OK`.

Each contradiction carries the post hook's reported `toolkit`, `tool_name` and `tool_version`. A reported identity shaped like a credential is withheld instead: the contradiction is appended with `tool_identity: WITHHELD` and none of the three, because the event export refuses a window holding such text for good, and refusing the hook would lose the contradiction itself.

The contradiction kind is informational to replay, so a tenant holding both kinds still exports with no `UNKNOWN_EVENT_SEMANTICS`.

### The report secret at rest

The extension holds the grant's report secret on the correlation row for the life of the grant. It is nulled at settlement and cleared opportunistically whenever the extension next reads a row whose report window has closed. Two facts belong beside that:

- **The usable life of the secret is the report window, not the row's.** `_reportable` refuses every report past it, so a secret read out of the table afterwards authenticates nothing.
- **The stored life is the row's unless something clears it.** The residual — the bytes of a row nobody touches again — is limitation 8, stated rather than described as a sweep the extension does not have.

A reader of that table can close such a row and, once the act window has passed, cause the scheduled run to release its canonical claim. What no reader of it can do is reduce what the tenant is charged: both statements the carrier can make confirm the impact.

## Duplicate delivery and the idempotency key

Retries are optional at the extension level and only for transient failures, a 4xx is not retried, duplicate deliveries are therefore possible, and nothing in the published material documents ordering or an idempotency guarantee. So:

- The correlation row is inserted **before** the kernel call and completed after it, so a crash between the kernel's commit and the correlation write leaves a row naming the Arcade execution and the derived key and holding no secret.
- The idempotency key is Arcade's `execution_id` **verbatim** when it already matches `^[A-Za-z0-9._:-]{1,128}$`, and a refusal otherwise. A digest would make a correlation row unreadable beside Arcade's own logs at exactly the moment an operator is comparing the two, and refusal is this deployment's default for anything unrecognized.
- **The `OK` rule is keyed on what the kernel returned, not on what the extension previously recorded.** A governed pre hook answers `OK` on a `DISPATCH_COMMITTED` answer only when this Arcade execution's own correlation row holds the grant's report secret — either because this answer minted it, or because an earlier delivery of the same Arcade id already retained it. That single condition refuses the concurrent second Arcade id, the abandoned-deadline row and the crashed row with no special case.

The invariant it buys rests on a kernel fact rather than on the extension's bookkeeping: the kernel mints a grant's report secret exactly once and a re-grant carries none, so **at most one Arcade execution id is ever answered `OK` for one ExecBound grant**, even after a crash, a missed deadline or a lost row. What it does not claim is that Arcade acts once on that one answer.

The correlation row is keyed `(tenant_id, principal_id, arcade_execution_id)` — `execution_keys`' own scope with Arcade's id in the place of the derived key. Limitation 15 says what happens without the principal in that key, and it is not hypothetical.

## Approvals against a synchronous hook

The first hook of an approval-requiring tool is `CHECK_FAILED` carrying the approvals page and the execution id. A retry under a new Arcade id adopts the same pending execution by intent hash; a human decision inside the deadline makes the next retry consume the approval exactly once and answer `OK`, and it is answered that execution's **first** grant with its own secret. The duplicate-delivery guard never touches this path, because a pending execution carries no grant.

**Most approvals on this path will expire.** The deadline is the tenant's configured one (120 seconds unless an ADMIN set another value) and the extension does not move it. An operator who wants a human in the loop on a governed tool should expect the agent to be told `CHECK_FAILED` and to retry, not to wait.

## The credential boundary

**Arcade presents an ExecBound agent credential as its bearer token.** There is no credential translation step, no credential of the extension's own, and no second authentication path into the kernel. mTLS, which Arcade also offers, is not used for ExecBound's own check: an operator may terminate it in front of the process, and it changes nothing ExecBound verifies.

- The credential lives in Arcade's extension configuration, so **Arcade holds an ExecBound credential** and its rotation is an operator step.
- The credential's expiry is a ceiling on the act window and the report window alike, so a short-lived credential shortens the time in which a post hook is still accepted. Size it to outlive the report window.
- A credential of one tenant presented to another tenant's deployment reaches only its own tenant's objects, because the mapping lookup is `(tenant, operation_ref)`.

**The extension sets no `override`, in either hook, ever.** `override.secrets` would make ExecBound a supplier of credential material into an executing tool; `override.inputs` would mean ExecBound changing what executes after deciding on something else, so the frozen plan would describe a request that no longer exists; `override.output` would let ExecBound rewrite what the agent is told a tool returned. Refusing all three is one rule rather than three exceptions.

That decision is also why **a precondition class cannot mean anything on this path**. The class is deployment configuration keyed by the provider binding, and a grant does carry a real class and a real version — but the hook response has no field for a grant and this deployment sets no override, so Arcade never receives the version, has nothing to compare and can condition on nothing. **A class declared for a binding an Arcade deployment serves is an overclaim on every page and report that shows it.** Declare none for such a binding and accept `UNAVAILABLE`, which is the honest default. A deployment that serves the same provider binding through both a Gate story and Arcade has one declaration for both carriers and must choose the weaker.

## Deployment

The hook surface is two routes on the existing application, gated on the `arcade` block being present, and a **separate public process** in front of them.

| Piece | What it is |
| --- | --- |
| `execbound.arcade.boundary:create_arcade` | The process factory. It mirrors `create_app`'s signature, so `uvicorn --factory` with no arguments builds the database and runtime from `EXECBOUND_RUNTIME_CONFIG` exactly as the gateway does |
| `POST /pre`, `POST /post` | The hooks. Every other method and raw path this process holds answers 404, and a websocket is closed |
| `GET /health` | **Not a third readiness implementation.** The boundary maps the path onto the application's existing `/health/ready`: unauthenticated, naming no tenant, 200 with the database up and 503 with it down |
| A separate service | Its own process, with its health check at `/health` and a private configuration (`EXECBOUND_RUNTIME_CONFIG`), the gateway's file or a copy of its own, which must hold the gateway's tool map |

Two costs belong in a runbook rather than in a diagram:

- **A second service doubles the deployment's pooled connections** against the database. It is a public process holding a runtime, so it opens its own pool; the pooler has to have room for both.
- **Where each process reads its own copy of the private configuration, the two copies must hold the same tool map**, or the processes will disagree about it, which is a disagreement nothing downstream would notice, because each process answers correctly for the map it holds. Such a deployment changes the tool map in both copies, and keeps them apart where the services' copies differ in other sections.

## What holds, and what cannot be prevented

| Property | What holds, and its limit |
| --- | --- |
| The decision | The same kernel, context freshness, Cedar sets, limit rules and denial precedence; no hook field reaches the decision, and the tool map is deployment configuration rather than caller input |
| Budget consumption | The pre hook writes the same `UNRESOLVED` impact row with the same retained scope attributes, so a tool call charges principal, tenant, group, account and selector limits and shares them with every agent and adapter in the tenant; no ceiling can be promised across paths ExecBound never sees |
| Target exclusivity | The pre hook takes the same canonical claim, so a second governed call on that target is denied `RESOURCE_BUSY` while it stands; it bounds ExecBound-mediated changes and never the vendor's own console |
| Approval | Unchanged: scoped, expiring, quorum-aware, server-side, consumed in the same transaction as the reservation — and usually expired before a human sees it |
| Single settlement | One correlation row per Arcade execution, a state machine with no edge back into `DISPATCH_COMMITTED`, and a settled row closed to everything the platform can send but a restatement of its own settlement. The one exception is the administrator's correction, which no control point and no holder of a report secret reaches |
| Audit and replay | A governed decision is an ordinary capture in the tenant's hash chain and replays as one; an ungoverned pass appends nothing at all |
| Two recorded contradictions | A post hook against a denial, and a post hook whose inputs differ from the frozen ones; each appended once, both missing or contradictory evidence, never a proven bypass |

| Cannot be prevented | What happens instead |
| --- | --- |
| An agent that reaches a vendor without going through Arcade | ExecBound has no record at all |
| A second logic extension overriding inputs after ExecBound decided | ExecBound decided on the inputs it was shown. A post hook carrying different inputs records the difference; one that omits them establishes nothing |
| An input field the map does not declare | Refused, which is the control — at the cost that a vendor adding an optional field breaks the tool until an operator declares it |
| A fail-open configuration | The extension cannot read it. A post hook arriving for a denial is the only evidence, and it arrives after the fact |
| A tool that executes twice on one decision | The budget is charged once and the claim held once. What the duplicate-delivery rule bounds is how many Arcade executions are told to proceed, not how many times Arcade acts on one answer |
| A vendor change between the hook and the execution | Nothing detects it. Whatever class the deployment declared, no version reaches Arcade |
| A tool failure the platform reports | Settled terminally at `FAILED_EFFECT_UNKNOWN`, tier `ASSERTED`, with the impact confirmed. What cannot be prevented is not a wedge but the **overcharge**: a tool that genuinely did nothing is charged as though it had, for the length of each rule's own window, until an administrator signs the correction on that row from the Activity page's settlement control |
| A tool failure reported in a tenant whose only executor key is revoked as compromised | The bare word still settles the row and frees the target at the act window, and the correction is unreachable because no key can attest at that grant instant |
| A tool failure the platform does not report, or reports in a body ExecBound cannot read | Retained uncertainty with the impact charged and the intent unavailable until an administrator settles it |
| Recalling an answered `OK` | Nothing recalls it. The emergency stop refuses new decisions and cannot reach one already given |

### Enforcement mode and evidence class

The mode this integration **targets** is Integrated. Measured against that mode's own evidence list: blocking is documented and is Arcade's claim; the exact request is bound at decision time but its equality with the executed request is not verifiable, and the contradicted-decision record is the only instrument that would ever show a difference; failing closed is a customer configuration the extension cannot read; credentials are protected by Arcade's own design; state is real — the same reservation, the same claim, the same shared budget — and receipts are not. The [September 18 trial](trials/2026-09-18-arcade-logic-extension.md) moved three of those from documented to measured: **blocking** was observed twice, **state** was observed end to end on one live call (reservation, canonical claim, shared budget, asserted settlement and an administrator's attested correction), and **credentials** arrived in the hook body exactly as Arcade's design implies. Two did not move, and they are the two that decide the mode: **failing closed** remains a customer setting the extension cannot read, and there are still **no receipts**, because a post hook is a runtime report and a settlement at tier `ASSERTED` says the platform's authenticated word. So the mode a real deployment can claim is **Advisory** rather than the Integrated it targets, and the reason is not a missing trial: it is that the decision can be skipped by a configuration ExecBound cannot see, and that nothing the platform sends can ever be attested. The mode is maintained per action path, so an ungoverned toolkit is `Unknown` even in a deployment whose governed tools are later qualified.

The evidence class does not depend on a trial. A post-hook `output` is runtime-reported and is not a provider-signed receipt; a settlement at tier `ASSERTED` says the platform's authenticated word and nothing about the vendor's effect. `FAILED_EFFECT_UNKNOWN` carries that discipline into the state vocabulary: its **name** is the evidence class of the statement that produced it, for the same reason the tiers exist: a reader who sees it should not have to look anything up to know that nobody established what happened at the vendor.

## Operator obligations

The extension cannot verify a single thing about how Arcade is configured. It does not see the failure mode, the timeout, whether another extension is registered, whether the project routes every tool through it, or whether it is enabled at all. No probe would tell it, and a heartbeat would only prove that Arcade can reach the extension, not that it consults it before acting. So these are obligations, and for every one of them about **Arcade's** side, nothing checks it.

1. **Register an executor key for the tenant, held by an administrator, keep it somewhere no control point can reach, and install in this order: key, then bundle activation, then Arcade.** Arcade never holds a key. The ordering is not advice: `_checkpoint` refuses an externally executed mapping in a tenant with no unrevoked key at validation *and* at activation, so an operator who configures Arcade first has a project whose every governed tool is refused, and one who activates first finds the activation refused.
2. **Set the failure mode to fail closed.** ExecBound cannot read this setting, and the only signal that it was not set is a post hook arriving for a decision ExecBound denied — after the tool has run.
3. **Keep Arcade's hook timeout above the extension's own budget.** The extension's answer blocks under either failure mode, so it should arrive first. Under load the deployment now answers `RATE_LIMIT_EXCEEDED` or `CHECK_FAILED` instead of a bare 429 or 503, so this obligation is about the timeout alone rather than about overload as well.
4. **Register one logic extension, or accept that another can change inputs after this one decided.** Whether project- and tenant-level extensions both execute is not established by the published sources, and this integration assumes the worse case.
5. **Take the toolkit and tool strings from the wire, not from the dashboard, and declare every governed tool and every ungoverned toolkit, governing only tools whose outputs are bounded.** The map compares `toolkit`, `name` and `version` exactly and folds no case, and Arcade's tool catalog **displays a toolkit under a different capitalisation from the one it sends**: the catalog prints `GitHub` where the hook body carries `Github`. A map written from the catalog page refuses every call of that tool as `UNMAPPED_TOOL`, and the refusal names neither the toolkit nor the field, so it presents exactly like obligation 9's trap. The September 18 trial lost a run to it. Read the identity off a hook body or off the agent's own tool identity before declaring it. An undeclared tool is refused. An ungoverned toolkit passes tools the vendor adds to it later, its calls leave no tenant audit event, and no coverage may be claimed for it. A governed tool whose post hook exceeds `post_bytes` leaves retained uncertainty on every call.
6. **Know that observe-only makes the extension permissive.** A tenant in `OBSERVE` answers `OK` to every governed tool while recording what ExecBound would have decided. An operator who reads the recorded decisions as blocks would be wrong.
7. **Size the credential to outlive the report window**, and rotate it in Arcade's configuration as an operator task. The window is `min(the attempt + 24 hours, the credential's expiry)`, and the second term is the one that usually binds: measured on a fixture credential with an hour of life left, the window came out at exactly one hour, not a day.
8. **Know what a reported failure costs, and what correcting one takes.** It settles terminally, which is what keeps the project working, and the charge is `CONFIRMED` and therefore **windowed**: it counts against each limit rule for that rule's own window and then stops, and the canonical claim is released by the scheduled run once the act window has passed. Silence is the expensive one — an `UNRESOLVED` row counts against every windowed rule for that action with no time filter at all, and against the cap of eight. A reported failure can be corrected by an administrator signing a non-execution with a key registered before the grant; that is a human act on one row, performed from the Activity page's settlement control on that row, and it is unavailable in a tenant whose ring has been revoked as compromised (limitation 14). An operator who wants a human to see every failed governed call before it is charged should pair the tool with an approval obligation rather than rely on correcting afterwards.
9. **Govern only operations whose account has no connector in the process that serves the hooks, and give that process a configuration with no connector for it.** An externally executed operation has no connector by construction — the executor holds the vendor credential and ExecBound sends nothing — so a Gate mapping on an account the running deployment can dispatch to is a deployment contradicting its own bundle, and admission refuses it `INVALID_BUNDLE` before the execution row is inserted. The refusal names neither the account nor the connector, so an operator who marks an existing, already-connected operation as externally executed sees every governed tool call fail with nothing pointing at the cause. This is the trap the September 18 trial fell into: the hook process was given the gateway's own configuration file, inherited its connector for the governed account, and refused every call until the connectors were removed, after which the same request granted. The [checkpoint guide](CHECKPOINT.md) carries the refusal in its table; it is repeated here because it is an installation step and not a runtime condition.

10. **Establish these three wire facts against the deployment before trusting it, because each one costs a settlement or a tool.** They are measured in `execbound_harness.fake_arcade.HOOK_CONTRACT`, which is what the contract walk asserts against, and each is narrower than the published schema:
   - **`success` is optional on the wire, and every settlement this integration makes rests on it.** A deployment that omits it leaves every governed call it granted in retained uncertainty, which is limitation 2 and the heaviest cost here. If a real deployment does not send it, this integration is not fit for that project, and that should be discovered against a fixture rather than in a tenant.
   - **`execution_id` is unconstrained on the wire and bounded here**, because it becomes the kernel's idempotency key verbatim. An id outside `^[A-Za-z0-9._:-]{1,128}$` is refused rather than mangled, so a platform minting ids outside that class blocks every governed tool call.
   - **The framing is `application/json` or `application/json; charset=utf-8`, compared case-insensitively and with the space.** `application/json;charset=utf-8` without the space is a **400**, and on `/post` the boundary passes that 400 through unchanged: the published contract does not retry a 4xx, so the settlement that request carried is lost and the row stays open, charged and holding its target. This is the one divergence whose cost is silent, so measure it rather than assume it.

## Limitations

Read these as part of the guide, not as a footnote.

1. **ExecBound decides on the fields the map declares, and Arcade executes the whole `inputs` object.** The declared-input allowlist bounds this by refusing anything undeclared, so the residual is a brittle tool rather than a smuggled field: a vendor adding an optional input breaks every governed call of that tool until an operator declares it.
2. **Silence leaves retained uncertainty; a statement is charged for a window and correcting it is a human act.** Both are real and the first is heavier. A post hook that states no result leaves the execution `INDETERMINATE` with the impact `UNRESOLVED`, which `usage` counts against every windowed rule for that action **with no time filter at all**, so it never ages out; the claim is held, every later attempt at that intent is adopted, it counts against the cap of eight, and an administrator's signed settlement is the only exit. Eight such rows wedge the project. A post hook that does state a failure settles terminally, which drains all of that, and the impact it writes is `CONFIRMED`, counted only while its `confirmed_at` lies inside each rule's own window — so the liar's charge is bounded where silence's is not. The change that would narrow the silent half, a write-off that releases retained uncertainty without settling it, is not built.
3. **A per-user or per-tool principal split is still wanted, and the extension does not add one.** With one principal per Arcade project, one user's silent tool wedges that intent for every user, and eight silent rows anywhere in the project stop the whole project. It is left out deliberately: per-user principals need per-user credentials inside Arcade, and a principal is the scope an approval, a pending intent and a grant are all keyed to, so multiplying principals multiplies every one of those.
4. **A human-in-the-loop approval will usually expire** against a synchronous hook and a 120-second deadline. The extension does not move that deadline.
5. **No precondition reaches Arcade**, whatever class a deployment declares, so a concurrent change between the hook and the execution is undetectable and no settled record can say whether it happened.
6. **The extension cannot verify anything about Arcade's configuration.** The obligations above are obligations, and a post hook arriving for a denial is the only evidence any of them was missed — after the tool has run, and only for a deployment whose bypassed calls still send post hooks at all.
7. **The tenant's hash chain cannot say how many ungoverned calls passed**, and neither can the correlation table, because an ungoverned pass writes nothing anywhere. A **governed** call the map refuses is countable: the refusal opens the correlation row and records `decision` `CHECK_FAILED` on it with the toolkit, the tool, the version and the reported metadata, as a plain insert rather than an audit event, because an event per refused call would put the project's refused traffic behind the tenant's audit head. Two things still are not countable there: a call whose `execution_id` falls outside the kernel's idempotency class, which is the correlation key's own third part and so has nothing to key a row on, and **which** code refused, since the row records the decision and not the reason for the map's refusals and the kernel's alike. The operator's own declaration and Arcade's logs are the record. A tenant that needs the count should bring Arcade in as a monitored source, where source-reported observation is what the model is for, rather than as enforcement chain volume.
8. **A live grant's report secret is at rest** in the correlation row — a property this carrier introduces rather than inherits, since a Gate secret is returned and never stored. It is usable only inside the report window and is nulled at settlement and cleared opportunistically afterwards, so the bytes of a row nobody touches again outlive their usefulness. A reader of that table can close such a row and, once the act window has passed, cause the scheduled run to release its canonical claim; what no reader of it can do is reduce what the tenant is charged.
9. **A lost response between the kernel's commit and the correlation write leaves a grant nothing can report**, which is the same residual and the same remedy — the administrator exit — that a Gate caller losing its first response already has. What this adds is that the next hook for that intent fails closed rather than telling Arcade to proceed.
10. **A tier says who spoke, and `ATTESTED` is reachable here.** `reconcile` reaches `_settle` with verified evidence and writes `ATTESTED` for any row carrying a report window, which is the administrator exit obligation 1 requires, so Arcade-carried executions will routinely end at `ATTESTED`, signed by the tenant's own administrator. What is true is the narrower statement: **no report Arcade sends can ever be attested**, because the hook body carries no signature and mTLS authenticates a channel rather than a statement.
11. **The granting path is measured here and only here.** AL32 measures it rather than leaving it open, and what that measurement does **not** establish is the number a hosted deployment would see: it is a fixture deployment against a workstation's PostgreSQL, with no gateway service sharing the connection pool and no hosted network in it. The hosted figure stays open evidence.
12. **The contract is beta.** `1.1.1-beta`, read from public documentation on one day, with a `/health` endpoint the schema declares and the guide does not mention, tool scoping that may or may not exist, an optional `success` that this integration's availability depends on, and no documented ordering or idempotency guarantee. Anyone opening this later must re-read it.
13. **The kernel carries a vocabulary that exists for this carrier, and it is deliberately not general in one direction only.** `FAILED_EFFECT_UNKNOWN` and `REPORTED_FAILURE` are outside the **verified** vocabulary: no verifier can construct them and no signed record can carry them. They are not outside the report route, which is one route for both carriers, so a Gate executor can send the new statement **unsigned** and gets the same bargain Arcade does — the row closes, the impact is confirmed, the claim is held to the act window, nothing is refunded — and its tenant gets the same correction. A key buys an executor nothing new, and a bare word buys both carriers the same thing. Every state list, page filter and replay projection has one more state to keep in agreement.
14. **A tenant whose executor key is revoked as compromised loses more than it used to.** Revocation as `COMPROMISED` freezes attested reporting and administrator settlement for every grant issued before it, and no newly registered key can unfreeze them, because a key is weighed against `dispatch_attempted_at`. The platform's bare word — which needs no key, only a report secret that sits at rest in the correlation table — still settles such a row, confirms its impact and lets the scheduled run free its target, and the correction is unreachable in exactly that tenant. The result is a charged, closed, uncorrectable row where there used to be an open one. The operator answer is obligation 1's.
15. **Two Arcade projects of one tenant can collide on an Arcade execution id, and the correlation row is keyed to survive it.** `arcade_execution_id` is the platform's own string and carries no ExecBound scope, and two independently configured deployments minting the same id needs no misbehaviour from either. Keyed on the tenant alone, the second project's pre hook opened no row, completed the **first** project's row with its own execution and its own secret, read the held flag back off it and was answered `OK`; both grants then stranded, each holding a claim and a cap slot. The row is keyed `(tenant_id, principal_id, arcade_execution_id)` for that reason. What two projects of a tenant still share is deliberate: the canonical target claim, so one project's unsettled grant on an endpoint blocks the other's, and the shared limit scopes, which exist to count a tenant's spend across its agents. The grant cap is not among them — `outstanding_grants` counts by principal.
