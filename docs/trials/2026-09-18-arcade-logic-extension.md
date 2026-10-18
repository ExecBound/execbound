# Arcade logic extension trial, 18 September 2026

The first trial of the [Arcade logic extension](../ARCADE.md) against a real Arcade deployment. It
was run to answer the three wire divergences the guide names in
[operator obligation 10](../ARCADE.md#operator-obligations) — each a requirement this integration
imposes that Arcade's published schema does not guarantee — and to test whether Arcade honours an
ExecBound refusal, which [the guide](../ARCADE.md#enforcement-mode-and-evidence-class) cites as
Arcade's claim about its own product and deliberately never asserts.

**All three divergences resolved favourably, and the refusal was honoured.** The first session did
not reach the grant; a second session the same day did, and drove one live tool call through the
whole chain: grant, platform-reported failure, asserted settlement and an administrator's signed
correction. What still rests on fixtures alone is narrow and named below.

## Environment

Host: Arcade cloud (`app.arcade.dev`), a lab test organization, one project
Version: Arcade cloud as served on 18 September 2026; `Github` toolkit 5.0.0
Date: 18 September 2026
Transport: HTTPS webhook from Arcade cloud to a `create_arcade` hook process on loopback, behind a Cloudflare Quick Tunnel (`cloudflared` 2026.9.1), per the temporary-origin procedure in [the Tines monitoring guide](../TINES_MONITORING.md)
Gateway commit: `7b45d71`, schema `0033_reported_failure`, 47 tenant tables
Fixture seed: `seed-validation` synthetic tenant `352ca991-e7c5-56f9-84ab-ba6ebd3dcb35`, Gate bundle with `external_executor` on `endpoint.isolate`, one registered executor key, one imported OPEN/CRITICAL incident on the target

Second session, same day, 18:30 UTC: gateway commit `f662a76`, schema `0037_agent_bindings`,
`seed-validation` tenant `3613441f-5404-581e-ac7f-20179de845e1`, a fresh Cloudflare Quick Tunnel,
and a hook process configured per operator obligation 9 with **no connectors at all**. Tool
`Github/SetStarred@5.0.0`, target selected by `provider_id` from the call's `name`, claimed incident
read from its `owner`.

No real organizational data was involved. The first session's only vendor effect was starring a
public GitHub repository, which is reversible. The second session's calls reached GitHub only as a
lookup for an owner that does not exist, so nothing at the vendor changed.

## Scenarios

### Arcade honours an ExecBound refusal

With both hooks pointed at ExecBound and `On Failure: Block request`, a governed call was refused
`CHECK_FAILED` / `EXECUTION_UNAVAILABLE` (the tool map declared no incident, so `registry.incident`
refused before policy). Arcade blocked the tool and reported to the agent:

> Tool execution was denied by an extension policy: EXECUTION_UNAVAILABLE

Two such calls produced two correlation rows with `decision=CHECK_FAILED`, no execution row, and
`execution.rejected` / `DEPENDENCY_OR_CONTEXT_UNAVAILABLE` in the tenant's hash chain.

### The three wire divergences

| Obligation 10 item | Measured |
| --- | --- |
| `success` is optional on the wire while every settlement rests on it | **Present**, `true`, on a successful call |
| `execution_id` is unconstrained on the wire and bounded here to `^[A-Za-z0-9._:-]{1,128}$` | Inside the class: `tc_3JUB5yaho8839LQvOCCfr43gGSn` |
| `application/json;charset=utf-8` without the space is a 400 that travels on `/post` | Arcade sends exactly `application/json` |

The post hook's top-level keys are `context`, `execution_id`, `inputs`, `output`, `success`, `tool` —
the shape the extension models, with nothing unmodelled.

### Fail-open, and the post hook after a failure

With the pre hook unreachable and `On Failure: Allow request`, Arcade ran the tool, confirming the
customer configuration the extension cannot read. Arcade sent a post hook in **both** the failing
case (GitHub answered Not Found) and the succeeding one, so the post hook is not conditional on the
tool succeeding.

### Uncorrelated reports

Each post hook for a call ExecBound never granted was recorded as `execution.rejected` /
`UNCORRELATED_REPORT` on the `surface` operation, opened no correlation row and settled nothing —
the guide's stated handling, observed.

### The hook body carries live credentials

`context.authorization` and `context.secrets` arrive **populated**. This is why `parse_pre_hook`
pops `context.authorization` before any model binds it and why the post path does the same for
`output`: a code path that retained the raw body would retain a third party's access token. The
capture endpoint used for this measurement held the raw body briefly and was scrubbed afterwards.

### `error_message` reaches the calling agent

Arcade relayed ExecBound's `error_message` verbatim into the agent's own output. `routes._message`
builds it as `f"{code} execution={view.execution_id}"`, with `approvals=<url>` appended for a pending
approval. The design then described this field as inert text for humans; in a real deployment it is a
channel to the agent, and [the guide](../ARCADE.md#the-pre-hook) now treats it as one. Nothing sensitive leaks today — the report secret never goes there — but what
may go in it should be chosen on that basis.

### The incident declaration works against a released contract

Every released context contract sets `incident="required"`. Declaring the incident as a mapped input
(as the integration does) was measured to satisfy the contract: with an incident
imported onto the target and the inventory facts present, the refusal moved from
`EXECUTION_UNAVAILABLE` to a later stage, so the claim resolved.

### The grant, the settlement and the correction, on one live call

The second session drove `Github/SetStarred@5.0.0` from the playground with the claimed incident in
`owner` and the ExecBound target in `name`. One call, four steps, all four measured:

| Step | Measured |
| --- | --- |
| Pre hook | `{"code":"OK"}`; execution `DISPATCH_COMMITTED`, Arcade execution id `tc_3JVplicGm7CNTXk9xmZKRgZjVOa`, correlation row holding its report secret, impact reserved, one canonical claim held |
| Report window | **18:30:42 to 01:02:52, about six and a half hours, not 24** |
| Post hook | 18:30:43.18, **about 400 ms after the grant**: `success: false`, `UPSTREAM_RUNTIME_NOT_FOUND` |
| Settlement | `FAILED_EFFECT_UNKNOWN` / tier `ASSERTED` / reason `REPORTED_FAILURE`; impact `CONFIRMED`; report secret nulled; claim still held |
| Correction | An ADMIN signed a non-execution with the tenant's registered executor key and submitted it through the Activity page's settlement control: `FAILED_NOT_EXECUTED` / tier **`ATTESTED`**, impact `NONEXECUTION`, `confirmed_at` cleared, claim **released** |

The settlement control was offered on the correctable row and withheld from a settled `EXECUTED`
row beside it, which is `_correctable` deciding rather than the page.

**Obligation 7 is not a footnote.** The report window came out at roughly six and a half hours
rather than a day, because `min(attempt + 24 hours, the credential's expiry)` was bound by the
credential in both sessions' fixtures. An operator who sizes a credential for convenience is
shortening the window in which a platform's report is still accepted.

### `UNMAPPED_TOOL`: the tool catalog's display name is not the wire name

The first governed call of the second session was refused `UNMAPPED_TOOL` with a map that named the
toolkit exactly as the dashboard's tool catalog prints it, **`GitHub`**. The wire sends **`Github`**.
The map compares exactly and folds no case, so every governed call of that tool was refused, and the
refusal named neither the toolkit nor the field. Correcting the single letter made the identical
call grant.

This is the same shape as operator obligation 9 and costs the same to diagnose: a deployment
misconfiguration that presents as a blanket refusal with nothing pointing at the cause. An operator
writing a tool map from the dashboard will hit it. Take the toolkit string from a hook body or from
the agent's own tool identity, never from the catalog page.

### A refusal before the kernel left no correlation row, and now leaves one

`INVALID_INCIDENT` was measured to open **no row in `arcade_hooks` at all**, where the kernel-stage
`EXECUTION_UNAVAILABLE` beside it opened one with `decision=CHECK_FAILED`. Every refusal the tool
map raises behaved that way, so the correlation table was not a log of governed tool calls and an
operator counting refusals from it undercounted by exactly the class a vendor's schema drift
produces.

**Fixed on 19 September 2026.** A refusal the map raises now
opens the row and records `decision` `CHECK_FAILED` on it, carrying the toolkit, the tool, the
version and the reported metadata. It is a plain insert and not an audit event, deliberately: an
event per refused call would put a project's refused tool traffic behind the tenant's audit head,
which is the cost the ungoverned branch already refuses to pay.

One refusal stays unrecorded and cannot be otherwise: an `execution_id` outside the kernel's
idempotency class is the correlation key's own third part, so there is nothing to key a row on. A
malformed body is audited instead, as the agent route audits a body it could not read. What is still
not stored, for the map's refusals and the kernel's alike, is **which** code refused; the tool
identity on the row is what distinguishes drift from a bad call.

### The end user's own identity arrives

`reported_user_id` carried the playground user's real email address, where every
fixture had carried a synthetic string. It is stored as inert text and reaches no decision, but a
deployment should know that a correlation row holds a person's address.

### `error_message` reaches the agent, but not reliably

The first session measured Arcade relaying the code verbatim. In the second, one refusal was relayed
verbatim (`UNMAPPED_TOOL`, quoted by the agent with the inputs it had sent) and another was
paraphrased away into "the GitHub starring tool isn't permitted in this environment", losing the
code entirely. The relay is therefore real but model-dependent: it is a channel to the agent that
must be treated as one, and it is not a diagnostic an operator can rely on receiving.

## Not established

- **A settlement from a vendor success, on the platform.** Every live call in both sessions failed
  upstream by construction, because the incident claim has to occupy one of `SetStarred`'s two
  string inputs and the other is the target, so no live call could name a repository that exists.
  `EXECUTED` / `ASSERTED` was driven end to end against the hook process on loopback, so what is
  unproven is the platform half of that one path rather than the settlement itself.
- **A governed tool whose vendor call can also succeed.** This is a real constraint rather than a
  gap in the trial: every released context contract sets `incident="required"`, the claimed incident
  must arrive as a declared input, and a vendor tool with only two semantically required string
  inputs has no room for it. Governing such a tool means displacing a field the vendor needs. A tool
  with a spare input, or a contract that sets `incident="none"`, would settle this.
- **Whether Arcade prevents an agent reaching a vendor without it.** Out of scope, and Arcade's own
  claim.
- **Latency in a hosted deployment.** The figures in AL32 are a workstation measurement. The
  400 ms between grant and post hook recorded above is a round trip through Cloudflare to a
  workstation and says nothing about a hosted deployment either.

## Operator notes confirmed in passing

- A Gate bundle cannot be **activated** in a tenant with no unrevoked executor key, exactly as
  [operator obligation 1](../ARCADE.md#operator-obligations) states. The refusal was met before the obligation was read.
- Arcade's extension edit form keeps a stored bearer token when the field is left empty
  ("leave empty to keep existing"), so editing endpoints does not silently drop authentication.
- Arcade's pre-stage timeout defaults to 5 seconds against the `arcade` block's required
  `deadline_seconds`; a deployment should keep its deadline below the platform's timeout so
  ExecBound answers first.
- **Obligation 9 works, and it is the whole of what the first session's `INVALID_BUNDLE` was.**
  The second session gave the hook process a configuration with an empty connector list and
  changed nothing else about the bundle or the mapping. The identical request granted.
- The playground's own model errored after one tool call completed ("The assistant couldn't
  respond"). Both hooks had already landed and the record settled; it is a playground artifact and
  not a property of the integration, but it is a reminder that the agent's transcript is not
  evidence of what the kernel did.
