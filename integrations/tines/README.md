# The ExecBound governed-action story for Tines

`execbound-governed-action.json` asks ExecBound to authorize a consequential action **before**
anything is dispatched, and reports what the kernel decided. It is a caller, not part of the
kernel: it holds no policy, and the decision is made by ExecBound and, when a person is
required, in the ExecBound console.

One story covers the six catalog actions, because the action is an input with
`endpoint.isolate` as its default. It is declared for Send to Story so a team calls it from the
story they already have.

Apache-2.0, like everything else here that is client code or an example, and the scripts
that generate these stories.

Download the stories and import each into Tines:
[execbound-governed-action.json](execbound-governed-action.json), the Execute story,
[execbound-gate.json](execbound-gate.json), the Gate story below, and
[execbound-monitor.json](execbound-monitor.json), the Monitor example further down.
The Execute and Gate stories can also be downloaded, unchanged, from Getting started in the
console: choose **Tines story** as an agent's host on **Connect this agent**.

## What it cannot do, by design

- **It cannot approve.** There is exactly one outbound call in the whole story and it is
  `POST <origin>/v1/execute`. A pending answer is reported to the caller and waited on; no
  branch turns it into a send.
- **It cannot escalate its own authority.** Every field it sends is the intent. The claim
  selects an incident; it never grants anything, and ExecBound resolves it against trusted
  inventory rather than believing it.
- **It cannot retry into a second effect.** The idempotency key is derived by the gateway from
  the `reference`, and the story refuses to run without one: `Has reference?` is the only way
  from `Prepare` to `Execute`, and a request without one exits at `Refused: no reference` with
  `code: MISSING_REFERENCE` before any call is made. An uncertain answer is reported as
  uncertain and never re-sent under a new key.

## What the story sends

`POST <origin>/v1/execute` with the strict body from [`docs/API_REFERENCE.md`](../../docs/API_REFERENCE.md).
The Execute and Gate HTTP actions serialize their bodies with `TO_JSON` and set the
`Content-Type` header explicitly. Keep the action's `content_type` option unset: Tines smart
validation can otherwise convert a digit-only identifier such as `000123` into a number.
`PENDING_APPROVAL`, `DISPATCH_COMMITTED` and `INDETERMINATE` answer 202; everything terminal
answers 200; refusals carry `code`. Only a re-send of the same request progresses a decided
intent, so the story waits by re-sending and needs no status route.

**It sends `reference` and no `idempotency_key`.** The gateway derives the key from the
reference, which means this story and the Python client, given the same ticket, land on the
same intent. (An earlier design had the story derive its own key, deliberately not
byte-identical to the client's, which made mixing the two callers unsupported. Sending the
reference removes that divergence entirely.)

| Field | Rule |
| --- | --- |
| `operation_ref` | default `endpoint.isolate` |
| `target_kind` | `hostname` (default), `provider_id` or `canonical` |
| `target_value` | stripped; lower-cased only when the kind is `hostname`, because a provider id is case-sensitive |
| `reference` | required: the ticket, case or alert id behind the intent |
| `incident_id` | required UUID; sent only as `claimed_context.incident_id` |
| `arguments` | object, default `{}` (`endpoint.lift_isolation` needs `{"reason": "false_positive"}` or `remediated`) |
| `external_case` | optional object: `source`, `case_id`, and optional HTTPS `url`; [source-reported case association](../../docs/REQUEST_REFERENCES.md), never a retry key or trusted incident |
| `wait_seconds` | optional; how long to wait for a human decision before reporting `pending`. Defaults to the `execbound_wait_seconds` resource. **Pass `0` from an AI Agent tool call** |

**Two ways in, one shape read.** A direct webhook post delivers the event as the body; a Send to Story delivers it wrapped under `body`. `Prepare` reads `entry.body.<field>` first and falls back to `entry.<field>`, so the same file serves both. The first run from an AI Agent story reached the gateway with every field empty before this was so.

Every nested value uses **formula syntax** (`=OBJECT(...)`, `=prepare.arguments`) rather than a
pill, because a pill stringifies an object and the gateway's strict parser would refuse the
body.

## Installing it

1. **Create a Text credential named `execbound`** holding an agent's API key (from the
   console's API keys page), and **set its allowed hosts to `<your gateway's host>/v1/execute`**.
   Tines refuses to interpolate a credential into a request to a host outside that list, so the
   token cannot be sent anywhere else even by a modified story. A credential with an empty
   allowed-hosts list is refused everywhere, with `This credential can only be used in
   cryptographic functions when domain restriction is disabled` in the action log.
2. **Create three Text resources**: `execbound_origin` (your gateway's origin, for example
   `https://gateway.example.com`, no trailing slash), `execbound_poll_seconds` (`30`) and
   `execbound_wait_seconds` (your tenant's approval deadline in seconds: `tenant-approval-deadline`
   sets it, and a tenant that never set one has 120).
3. **Import the story** into a real team, not a personal one.
4. **Set the webhook path and secret** on the `Entry` action. They are deliberately empty in
   this file (a committed webhook secret would let anyone post into the tenant that exported
   it), and Tines does **not** generate them on import. Opening the action in the UI assigns
   them. A Send to Story caller never uses the webhook URL, so this step matters only if you
   want to POST to the story directly.
5. **Enable Send to Story** with `Entry` as the entry action and both `Outcome` and
   `Refused: no reference` as exits. This
   cannot be done in the import payload: an import carrying `send_to_story_enabled: true`
   fails with a 500. Set it afterwards, in the UI or with `PUT /api/v1/stories/{id}`.
6. Wire your own notification to `Outcome`.

## Calling it from a Tines AI Agent

This is the caller the story is really for: an AI Agent action deciding, from an alert or a
conversation, that a host should be isolated, and asking ExecBound rather than doing it. The
agent gets the story as a **Send to Story tool**. Attaching one is a UI step on the agent action;
the API exposes no tool field on an `LLMAgent`.

Configure the tool with this description and input schema, verbatim. The failure mode of an
agent tool is a loose schema, so every field says what the model must not invent:

> **Tool description.** Ask ExecBound to authorize a consequential action. You do not perform the
> action; ExecBound decides, and when a person is required they decide in the ExecBound console.
> Call this once per ticket. If the answer is `pending`, do not call again unless you are told a
> decision was made, and then call with the **same** `reference`. If the answer is `uncertain`,
> stop and hand the ticket to an administrator; never call again with a new `reference`.

| Input | Type | The model must |
| --- | --- | --- |
| `operation_ref` | one of `endpoint.isolate`, `endpoint.lift_isolation`, `identity.disable`, `identity.enable`, `identity.revoke_sessions`, `identity.reset_password` | choose from this list only |
| `target_kind` | `hostname`, `provider_id` or `canonical` | use `hostname` unless given another |
| `target_value` | string | copy the host or account exactly as given |
| `reference` | string | **use the ticket, case or alert id it was given; never invent one** |
| `incident_id` | UUID | copy the incident id it was given |
| `arguments` | object | `{}` unless the action needs one |
| `wait_seconds` | integer | send `0` |

`wait_seconds: 0` matters: a tool call has a timeout and the agent cannot act on a pending
answer anyway, so the story returns `pending` at once with the approval URL instead of polling
for the tenant's deadline. The `message` in every outcome is written for the model that reads
it.

**What the story cannot protect against, and what does.** Its "cannot retry into a second
effect" rule holds because the key is derived from the `reference`. A model that invents a fresh
reference each call is asking for a fresh intent, and the story cannot tell. The schema above
and the tool description are the first line; the real backstop is ExecBound's own **shared
impact limits**, which cap how many targets any caller can reach in a window regardless of how
many intents it opens. That is the point of putting the limit in the kernel rather than in the
caller.

**One Tines-side gate to decide on.** The story exports with
`send_to_story_skill_use_requires_confirmation: true`, which makes Tines ask a person to
confirm before an agent may invoke the story at all. That is a second approval in front of
ExecBound's. Keep it as defence in depth, or turn it off so the demonstration shows ExecBound
as the decision point; the file leaves it on.

## The caller story that goes with it

`execbound-ai-agent-caller.json` (`ExecBound: AI Agents`) is the story an alert lands in. Five
actions, built entirely by API and committed beside the governed story:

`Alert` (webhook, headers off) → `Triage agent` (AI Agent, task mode, an output schema **and an
exact JSON example in the prompt**) → `Act?` (regex `^true$` on `<<triage_agent.output.should_act>>`)
→ `Govern via ExecBound` (Send to Story) → `Result`.

The caller story's export is [`execbound-ai-agent-caller.json`](execbound-ai-agent-caller.json), beside these two.

The governed call is not optional in this shape: an agent that decides to act cannot skip the
checkpoint. That is a stronger demonstration than a tool the agent may choose to call.

Three things that cost a run each to learn:

- **The Send to Story `story` option must be the slug pill**, `<<STORY.execbound_govern_an_action>>`.
  The integer story id is accepted at save and fails at run time with `Couldn't find the target story.`
- **An AI Agent whose `mode` is empty is accepted at save and rejected at run time** with
  `Invalid Options: mode must be one of task or chat`. Set `task` explicitly.
- **The output schema is a hint, not an enforcer.** Without an example in the prompt the model
  returned `isolate_endpoint`, `hostname` and `ticket_id` for `endpoint.isolate`, `target_value` and
  `reference`. The example fixed it; the Send to Story payload also tolerates those synonyms with
  `DEFAULT(...)` chains, and maps a few plausible operation names onto the catalog.

## What comes back

`Outcome` emits the same shape as the Python client's `summarize`, so downstream logic is the
same whichever caller a team uses: `outcome` (`final`, `pending`, `expired`, `uncertain`,
`refused`), `state`, `execution_id`, `approval_state`, `approval_url`, `code`, `reference`,
`idempotency_key`, `attempts` and a `message`.

`code` falls back to the gateway's `detail` when a response carries no code, so an
authentication failure reports *why* rather than reading as an unexplained refusal.
Tines' status-0 failure envelope carries no gateway decision. It reports
`TRANSPORT_UNCERTAIN`, or `RETRIES_EXHAUSTED` when the platform has consumed its retry
budget, and exits without another story resend. `attempts` counts the story's own loop;
it does not include Tines' built-in HTTP retries.

HTTP 5xx responses also report `uncertain`, including an intermediary's HTML error page.
When there is no gateway code or detail, `code` is `HTTP_RESPONSE_UNCERTAIN`. These responses
exit without another story resend, except for the existing bounded same-reference 503 loop.

**`uncertain` is not `refused`.** A refusal states that nothing happened; an uncertain answer
states that whether anything happened is not established. A server error, or no answer at all, is
uncertain for that reason, and its message says to hand the intent to an administrator and
never re-send it under a new key.

## Tested against

| | |
| --- | --- |
| Tines live host | Schema 30, standard library 96, action runtime 88, Community Edition |
| ExecBound | Latest recovery trial: version `0.1.0`, hosted at `https://app.execbound.ai` |
| Latest trial | 2026-09-22 UTC; synthetic pilot, protected endpoint mock, response recovery and alternate-story credential probes |

The [dated trial](../../docs/trials/2026-09-21-tines-governed-action.md) records real Tines
runs for allow, hard denial, human approval/refusal, same-reference retry, pending polling,
wait-boundary resume and bounded unavailable-response handling. The AI caller also returned
allow, deny and pending. Independent authenticated mock journals report one mutation per
successful operation and no journal for denied operations. The live trial exposed two fixes
now in this export: read cumulative seconds from Tines' two-argument `DATE_DIFF` result, and
read the gateway's flat `approval_state` and `approval_url` fields.

The earlier 18 September import established wire-body normalization and authentication
refusal only. Its sanitized body remains in `tests/fixtures/tines-governed-action-body.json`,
parsed by the gateway's `ActionRequest` model in `tests/test_tines_story.py`.

The [shared-impact follow-up](../../docs/trials/2026-09-21-tines-shared-impact.md) also proved
that ten Tines actions and ten actions from a second HTTP agent fill the same tenant limit:
both callers' next requests were denied, and retries added no charge or mock mutation.

The [fault and expiry follow-up](../../docs/trials/2026-09-21-tines-fault-expiry.md) records
approval expiry with no provider effect, malformed-target refusal, and controlled 503,
429-exhaustion and DNS-failure cases in an isolated Tines graph. It also records the status-0
classification correction. The fault graph held no gateway credential and injected no
outage into the hosted gateway.

The [response-recovery follow-up](../../docs/trials/2026-09-22-tines-response-recovery.md)
dropped the caller's response after a confirmed mock effect. The corrected story returned
`uncertain`; a same-reference retry recovered the existing result with one mutation and one
charge. Another story's direct provider calls without a provider credential returned 401,
and its gateway call still obeyed policy. A reviewer signed in on Android Chrome approved a
request through the same flow.

The integration remains **platform-validated / Advisory** for the named cases in
[the manifest](../../docs/INTEGRATIONS.md). A cold signed-out phone return, gateway-to-provider
response loss before settlement, and real vendor qualification are separate evidence gaps.
The mock provider is not a real CrowdStrike integration. A caller with its own vendor
credential can skip the voluntary story. See
[The Gate story: keep your vendor credential in Tines](#the-gate-story-keep-your-vendor-credential-in-tines)
for the story that does exactly that.

## The Gate story: keep your vendor credential in Tines

`execbound-gate.json` (`ExecBound: Gate an action`) asks ExecBound for a decision exactly as the
Execute story does, then acts once at the caller's own vendor with the caller's own credential
and reports what happened. `tines_gate_story.py`, beside this file, generates it from the
Execute story, copying the decision half by action name, so both stories send the same wire
body and wait the same way; the act half is new.

### When to use it

| | Execute | Gate |
| --- | --- | --- |
| Vendor credential | ExecBound's connector | The customer's workflow |
| Who calls the vendor | ExecBound, after the decision | The workflow, after the grant |
| Enforced | Decision, approval, budget, target claim, dispatch, precondition, settlement from the provider journal | Decision, approval, budget and target claim. Settlement at the tier the evidence supports |
| Cooperative | Only that the caller asks at all | Asking, honouring a denial, acting once, acting only on the granted target, reporting truthfully |
| Choose when | The action may run on ExecBound's credential | The credential must stay in the workflow platform |

Both are Advisory for Tines: nothing forces a story to call ExecBound.

### What it does

`Prepare` reads the same inputs as the Execute story, from `entry.body.<field>` with a fallback
to `entry.<field>`, and refuses to run without a `reference`. `Execute` sends
`POST <origin>/v1/execute` with the `execbound_gate` credential, sending the Execute story's own
wire body and no `idempotency_key`.

**Branches on the answer:**

| Answer | The story does |
| --- | --- |
| Refusal (`code`) | Exit `refused`. The vendor is never called |
| `DENIED` | Exit `denied`. The vendor is never called |
| `PENDING_APPROVAL` | Re-send the same request under the Execute story's wait logic. Exit `pending` at `wait_seconds`, or `expired` when the approval lapses |
| `DISPATCH_COMMITTED`, grant with a report secret | Continue to the act branch below |
| `DISPATCH_COMMITTED`, `regranted: true` | Exit `needs_administrator` with the execution id. The story cannot tell whether an earlier run already acted, and it holds nothing to report with, so it never acts |
| 5xx, or Tines' status-0 envelope | Exit `uncertain` with the Execute story's own classification, and never re-send under a new reference |

**Act.** If `act_expires_at` has passed, the story does not act: it signs and reports
`FAILED_NOT_EXECUTED` with reason `CANCELLED_NOT_EXECUTED`, which releases the charge and the
target. Otherwise it sends `grant.provider_command` verbatim to
`<vendor_origin>/v1/<grant.provider_operation>` with the `execbound_gate_vendor` credential. No
value from `Prepare` reaches this call, so a caller cannot widen what the grant describes.

**Classify the vendor's answer and report:**

| Vendor answer | Report |
| --- | --- |
| 200 with a `SignedJournal` (executed, version mismatch or target not found) | The journal, settling `PROVIDER_VERIFIED` |
| 400, 401 or 403, refused before any effect | A signed non-execution, `CANCELLED_NOT_EXECUTED`, settling `ATTESTED` |
| 409 (`OPERATION_CONFLICT`) | `UNKNOWN`, then exit `needs_administrator`. A journal already exists for this operation id under a different command, so whether this grant's effect is the one recorded is not established |
| 5xx, status 0 or timeout | Never re-send the effect. Look the journal up with `POST <vendor_origin>/v1/journal` and the same command. Report it if found; otherwise report `UNKNOWN` and exit `needs_administrator` |

The report goes to `POST <origin>/v1/executions/{execution_id}/outcome` with the `execbound_gate`
credential, retried up to three times on a transport failure or a 5xx: safe, because a settled
row answers a restatement with its own view. `INVALID_REPORT`, `INVALID_RECORD`, `INVALID_STATE`
and `REPORT_WINDOW_CLOSED` stop the story at `needs_administrator` with the code. A report the
gateway never answered, or answered without a code, stops there with `REPORT_NOT_ACCEPTED`.

Every HTTP action in the story sets `emit_failure_event: true`. Tines' default emits an event
for an HTTP error status but none for a timeout or a DNS failure, which ends the run silently:
in the live trial a vendor call that timed out left its grant unreported until an
administrator settled it. With the option set, a transport failure emits status 0, and the
table above sends it to the journal lookup.

The signed non-execution's `reported_at` comes from the Tines clock, which the story formats to
the whole second, and ExecBound compares it with the grant instant at one-second precision, so
the Tines clock must not trail the gateway's.

`Outcome` emits the Execute story's summary shape plus `path: "gate"`, `tier` and
`vendor_status`. `tier` names the tier a report settled at only when the gateway accepted the
report, and is null otherwise. A report of `UNKNOWN` is accepted and settles nothing, so its
outcome is `needs_administrator`, with the code `VENDOR_OUTCOME_UNKNOWN`. A reference that
already settled, sent again, gets its recorded state back with outcome `final` (or `uncertain`
for `FAILED_EFFECT_UNKNOWN`), no tier and no vendor call. Neither the report secret nor the
signature ever appears in an outcome.

### Installing it

1. **Create three Text credentials:**

   | Name | Kind | Reach |
   | --- | --- | --- |
   | `execbound_gate` | Text credential, the Gate principal's agent credential | Allowed host: the gateway's `/v1/execute` and `/v1/executions/` paths |
   | `execbound_gate_vendor` | Text credential, the vendor's dispatch token | Allowed host: the vendor. The control token is never needed, and journal lookup accepts the dispatch token |
   | `execbound_gate_signing` | Text credential, ES256 private key PEM | No host restriction, because Tines requires that for cryptographic functions |

2. **Create five Text resources**, none secret: `execbound_origin`, `execbound_vendor_origin`,
   `execbound_gate_key_id`, `execbound_poll_seconds` and `execbound_wait_seconds`. The key id
   resource must equal the `--key-id` an administrator registers below.
3. **Import the story into a dedicated team**, not one that also holds unrelated credentials.
   The signing credential cannot be host-restricted, so any story in the team that can read it
   can sign with it.
4. **On the ExecBound side.** On the hosted service these are ours to do: send us the public
   key and the actions to gate. On your own deployment, an administrator does them:
   - Register the executor's ES256 public key for the tenant:
     ```sh
     execbound executor-key-register --tenant <tenant> --key-id tines-gate-1 \
       --algorithm ES256 --public-key-file tines.pub.pem --actor <admin>
     ```
   - Create a Gate account with no connector, and a bundle mapping the Gate actions with
     `external_executor`, an approval rule a normal (non-admin) reviewer can decide, and a
     shared tenant limit that also covers an Execute account.
   - Declare `ENFORCED_BY_PROVIDER` for each binding the Gate uses where the vendor genuinely
     offers a conditional write (see [Preconditions](../../docs/CHECKPOINT.md#preconditions));
     an undeclared binding grants no version at all.
   - If the vendor signs journals, add a `checkpoint_providers` entry for the Gate account:
     tenant, account, provider and the provider's journal key id. It holds no URL and no
     dispatch or control token, and the gateway never calls this provider.

### What the story cannot do, by design

- **It cannot build a vendor call from its own input.** The vendor call's body is
  `grant.provider_command` alone; nothing `Prepare` reads from the caller reaches it, so a
  caller cannot widen what the grant describes.
- **It cannot act on a re-grant.** `Regranted?` exits at `needs_administrator` without touching
  the vendor, because the story cannot tell whether an earlier run already acted and holds no
  secret to report with.
- **It cannot re-send an effect whose outcome it does not know.** A lost vendor response is
  answered by a journal lookup with the same command, never by a second call to the provider.
- **It cannot approve.** The vendor is called only after ExecBound has already granted; no
  branch turns a pending or refused answer into an act.

### What it cannot protect against

- **The report secret lives in Tines' event data** for as long as `keep_events_for` keeps it,
  set to one hour here rather than the Execute story's one day. Anyone who can read those
  events can report for that grant within its window; without the signing key or a provider
  journal, the most they can do is settle at `ASSERTED`, which confirms the charge and releases
  nothing.
- **The signing credential cannot be host-restricted.** Tines refuses a credential in a
  cryptographic function when domain restriction is enabled, so any story in the team holding
  `execbound_gate_signing` can produce a valid attestation for any grant it can read.
- **Any other story holding `execbound_gate_vendor` can call the vendor directly, without
  asking ExecBound at all.** Gate is cooperative: nothing here stops that story, and monitoring
  can report the missing checkpoint only as an observation, never as a proven bypass.

### Recovery

`needs_administrator` means stop: never resend under a new reference and never repeat the
vendor call. An administrator settles the execution from the Activity page's settlement
control, either by looking the journal up at the vendor with the same command
(`POST <vendor_origin>/v1/journal`) and pasting it in, or with a signed record.

### Tested against

| | |
| --- | --- |
| Tines live host | Schema 30, standard library 95, action runtime 88, Community Edition |
| ExecBound | Version `0.1.0` |
| Trial | 2026-09-24 UTC; synthetic pilot, protected endpoint mock, local gateway and mock behind temporary Cloudflare quick tunnels |

The [dated trial](../../docs/trials/2026-09-24-tines-gate.md) records real Tines runs for
allow, deny, human review and refusal, approval expiry, a stable retry, an act window closing
before acting, a lost first response settled by an administrator, a lost vendor response
recovered by journal lookup, a replayed grant and a wrong-scope report, credential reach across
the Gate/Execute boundary before and after owner-provisioned separation, the cooperative
bypass, and shared impact across the Gate and Execute paths together. A `JWT_SIGN` probe run
first settled what a real Tines credential emits into an ES256 attestation.

The integration is **platform-validated / Advisory** for the cases named there. A real vendor,
the report window's own closing, and the seeded 20-target shared-impact rule's own number
remain separate evidence gaps; see the trial's "Not established" section and
[the manifest](../../docs/INTEGRATIONS.md) for the rest.

## The Monitor story: report what your own stories do

`execbound-monitor.json` (`ExecBound: Monitor an action (example)`) is for a story that acts on
its own, with its own vendor credential, and that you want ExecBound to **see** rather than
govern. After each consequential action it reports the result to
`POST <monitor origin>/v1/monitor/events`, and every five minutes it reports a heartbeat.
ExecBound turns those into observations, findings and alerts. Nothing here authorizes
anything: a report never approves, settles, reserves or limits, and a source-reported success
is not a verified effect.

It is generated by `tines_monitor_story.py`, beside this file, and is an
**example to copy from**: its `Act` action stands for your own vendor call. Keep the
reporting actions and replace `Act`.

### What it does

| Action | Does |
| --- | --- |
| `Entry`, `Prepare`, `Has target?` | Reads `target`, stamps `attempted_at` before the action, and only continues with a target the intake accepts (letters, digits, `.`, `_`, `:`, `-`, at most 96) |
| `Act` | The example's consequential action. Never retried, because a second send could be a second effect |
| `Build result` | The observation: `kind: tool_result`, the catalog action, the target, and the outcome from `Act`'s status: 2xx `success`, status 0 (a timeout or DNS failure) `unknown`, anything else `error` |
| `Heartbeat`, `Build heartbeat` | Scheduled every five minutes, so a broken reporting path shows as a stale source rather than as silence |
| `Report` | Sends either body with the `execbound_monitor_source` credential, retried three times on 429 and 5xx. A tool-result retry resends identical text, which ExecBound records once; a heartbeat only refreshes the source's freshness |
| `Reported`, `Reporting failed` | The two exits. Route `Reporting failed` to your own alerting |

**Identifiers come from Tines.** `story_id` is `META.story.id` and a result's `event_id` is
built from the incoming event's id, so re-running `Build result` on the same event rebuilds the
same body, and a new attempt of the action is a new observation. A heartbeat's `event_id` is
per minute for compatibility with the envelope. Heartbeats update the source's receipt-time
freshness without storing observations: each accepted heartbeat, including a retry, returns
202 with `observation_id: null` and `duplicate: false`. They still share the source's rate limit.

**How the report's answer is read:**

| Status | Exit and reason |
| --- | --- |
| 202, tool result | `Reported`, `recorded` |
| 202, heartbeat | `Reported`, `refreshed`: the source's freshness was updated and no observation stored |
| 200 | `Reported`, `duplicate`: the same event was already recorded |
| 401 | `Reporting failed`, `auth_lost`: the source token expired, was revoked, or was rotated past its grace window |
| 409 | `Reporting failed`, `conflict`: the same `event_id` with different content. ExecBound keeps the original and records an integrity finding |
| 0 | `Reporting failed`, `unreachable`: no answer at all, after the retries |
| Anything else | `Reporting failed`, `not_recorded`, with the intake's `code` when it sent one |

**Bodies are sent as JSON text.** Both requests use `=TO_JSON(...)` with an explicit
`Content-Type: application/json` header and no `content_type` option. With `content_type: json`
Tines "smart validates" the payload and sends a digit-only string as a number. In the live trial
it sent the story id `"147205"` that way, and the intake's strict parser refused every report
with `INVALID_EVENT` until the story was changed.

### Instrumenting your own story

1. **Register one source per story.** On your own deployment an administrator runs
   `python -m execbound.monitoring.commands create-source --credential-file <admin token file>
   --label <label> --story-id <the story's Tines id> --hours <lifetime> --output <new token file>`,
   and `rotate-source` to replace a source's token.
   A source token is bound to one story id, and coverage matches a discovered story to its
   source by that id, so one reporting story shared by several stories would leave the others
   showing as gaps.
2. **Create a Text credential** `execbound_monitor_source` holding the source token, restricted
   to the monitoring origin's host, and a Text resource `execbound_monitor_origin` holding that
   origin. The Tines management key is never the reporting token.
3. **Copy `Build result`, `Heartbeat`, `Build heartbeat`, `Report`, `Recorded?`, `Not recorded?`
   and both exits into your story.** Stamp `attempted_at` before your action as `Prepare` does,
   link your action's output to `Build result`, set the `action` your action actually performs,
   and map its result the way `Build result` maps `Act`'s status. Report errors as well as
   successes. Name an action only when the story performs that operation; otherwise report
   `unknown` rather than guess.
4. **Keep `emit_failure_event` on your own action.** Without it a timeout emits no event, the
   run stops, and the result is never reported.

The heartbeat joins the same `Report` action as the result path, so the two are one connected
Tines flow, which matters on Community Edition's three flows.

### What it cannot protect against

- **A story that does not report is invisible to Monitor** except through collection coverage,
  which lists a story with outbound actions and no source as a gap.
- **Anyone holding the source token can report for that story,** including heartbeats that keep
  a broken story looking fresh. Keep the credential host-restricted, and rotate or revoke it
  like any other.
- **Source tokens last at most 24 hours when issued from the command line,** so ongoing
  instrumentation needs a daily `rotate-source` and a credential update inside the grace window.
- **Findings reach only the authenticated loopback receiver today.** Email, Slack, Teams and
  HTTPS webhook delivery of findings is not built; findings are always visible in
  the console.

### Tested against

| | |
| --- | --- |
| Tines live host | Schema 30, standard library 97, action runtime 88, Community Edition |
| ExecBound | Version `0.1.0`, monitor events v1 |
| Trial | 2026-09-26 UTC; local monitoring service, intake-only origin and a lab vendor stub behind temporary Cloudflare quick tunnels, loopback alert receiver |

The [dated trial](../../docs/trials/2026-09-26-tines-monitor.md) records real Tines runs for
success, error and unknown results, a duplicate retry, scheduled heartbeats, a heartbeat stopped
until the source read stale and then resumed, an unreachable intake and its recovery, token
rotation inside and past the grace window, collection coverage, and a revoked source.

## Recognizing a request

The outcome's `request_ref` is the same `EB-…` handle shown in notifications and the console.
An optional `external_case` is passed as a JSON object, including when Send to Story wraps
its input under `body`. Keep `reference` stable across retries and distinct for separate
consequential requests in the same case. The case ID may repeat; it is for grouping only.
