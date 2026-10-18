# Tines Execute trial, 21 September 2026

The existing governed-action story and AI caller reached the hosted gateway with a valid
AGENT credential. Allow, policy denial, human approval and refusal, same-reference retry,
pending polling and the wait boundary ran in Tines. Two defects in the story were found,
fixed in the lab tenant, reproduced by failing regression tests and corrected in the
committed export. This is a bounded platform trial of **Execute / Advisory**, not completion
of every planned Tines case or qualification of a real endpoint vendor.

Later the same day, the [shared-impact follow-up](2026-09-21-tines-shared-impact.md)
proved the common tenant limit across Tines and a second HTTP agent, including retry
accounting. The unrun shared-impact case below describes the state at this initial trial;
the follow-up closes that case only. The [fault and expiry trial](2026-09-21-tines-fault-expiry.md)
subsequently exercised expiry and malformed input at the gateway plus isolated Tines HTTP
and DNS faults. The [response-recovery trial](2026-09-22-tines-response-recovery.md) of
22 September then covered a response lost after a recorded effect and two direct
credential-bypass probes. The remaining limitations below are historical; each follow-up
states exactly which cases it closes.

Host: Tines Community Edition lab tenant, one test team; the governed-action story and the AI caller story
Version: Tines export schema 30, standard library 96, action runtime 88; ExecBound 0.1.0
Date: 2026-09-21, scenario events 22:30–22:39 UTC; independent journal inspection afterwards
Transport: HTTPS webhook into Tines, HTTP Request to the hosted gateway's `/v1/execute`; AI caller uses Send to Story
Gateway commit: `c1818de46a0e7c72dbe5a0258731fe84dab4daeb`, reported by hosted readiness before the trial
Fixture seed: existing synthetic pilot tenant on the hosted gateway, `endpoint.isolate`, protected `mock_crowdstrike` provider, workstation/domain-controller/production inventory and trusted incident fixtures

## Custody and changes

The existing story's Text credential was invalid. It was updated to the existing pilot
AGENT A credential, retaining its restriction to the gateway's `/v1/execute`, team and
access settings. No new principal or credential was issued. Provider credentials remained
outside the Tines story. The separate existing HUMAN_APPROVER credential was used through
the gateway's normal HTTPS login and approval forms, with their CSRF and continuation
values, in an independent cookie session. No user browser cookies were extracted.

The logged-in console user is an ADMIN: the browser showed the held requests and correctly
offered no approval authority. Activity was inspected in **All spaces / Last hour**, because
these existing pilot principals belong to the default space, not the `tines` space.

Only the options of `Within deadline?`, `Deadline passed?` and `Outcome` were changed in
the live governed story. Wiring, webhook secrets, destination resources, caller and disabled
monitoring story were preserved. The three changed option objects were compared back to
the committed export and matched exactly. No hosted application deploy, migration, policy
change or real endpoint operation was performed.

Both live exports still reported `send_to_story_skill_use_requires_confirmation: true`.
The tested AI caller uses a wired Send-to-Story action after its triage agent, not an optional
agent skill invocation; the flag alone does not establish that Tines asked a human first.

Export custody:

- Sanitized committed `integrations/tines/execbound-governed-action.json`, UTF-8/LF SHA-256:
  `a2d5c3318a1c76b57129dd72fdf32e45998eeb915047df998fe70759f21f42ef`.
- Final private governed export, JSON sorted keys with compact separators, SHA-256:
  `43cc1112e421dc3da7b70c6861923e957f5910604227bda0337447c443d04c3a`.
- Final private AI caller export, same digest encoding, SHA-256:
  `cdfb18f263e84752bb8746ca9e51a82d78b1d0ec945761615ef2247b66306407`.

Raw exports, event captures, input receipts, reviewer results and signed provider evidence
are retained privately by the operator. They contain secrets and are not portable artifacts. This record retains only
synthetic correlation identifiers and observations; neither raw exports nor webhook URLs
belong in version control. The committed export retains its sanitized installation metadata;
the runtime versions above describe the actual host, not an untested metadata upgrade.

## Scenarios

References below have prefix `TINES-20260921-`. An event is the story's final `Outcome`
unless identified as a caller `Result` or missing-reference exit. Event IDs can be located
in the named Tines story; execution IDs correlate with console Activity and the journal table
below. A webhook's 201 acknowledgement was never used as evidence of execution.

| Case | Observed result | Tines evidence |
| --- | --- | --- |
| Invalid configured credential (`deny-01`) | HTTP 401 became `refused`, code `Invalid credentials`; no execution ID. This was authentication refusal, not policy denial. | Event `1310407667`, run `6862a25e-b9af-446c-8b47-28d370ded4a0` |
| Hard denial (`deny-02`, `dc01.pilot.example`) | `DENIED`; console stated no permitting rule or a matching deny. No dispatch transition or provider journal. | Event `1310413388`, run `7ea2a9e1-0274-4c5e-8da9-06fe65ceb492`; execution `2a652d18-a403-4d65-b63b-9b895f3b9484` |
| Allowed (`allow-01`, `ws01.pilot.example`) | `EXECUTED`; authenticated mock journal reports one mutation. | Event `1310414271`, run `3b3264a4-2590-4ad1-8818-6ce2c7a7558f`; execution `383f4785-8d8d-462a-8309-864a60c5f5e6` |
| Repeat identical allowed request | Same execution and operation, still one journal mutation and one dispatch transition. | Event `1310423664`, run `f6a790e8-e15a-4b21-991b-28320e4be527` |
| Approval (`approval-01`, `ws25.pilot.example`) | Initially `PENDING_APPROVAL`. After reviewer APPROVE, identical intent returned `EXECUTED`; journal reports one mutation. | Final event `1310434712`, run `3ec8a6e1-81fe-469b-b46d-576e2ee72b0d`; execution `4b2a7f9d-c0d0-4d15-bf56-c6a87f2a85a0`; approval `ea1be35a-a702-48c9-9910-cd95952ac250` |
| Poll pending until wait boundary | After the formula fix, `wait_seconds: 90` returned `pending` after three polls, about 99 seconds including action scheduling. It did not create another execution. | Event `1310432009`, run `5c7387ee-90db-443d-b845-febbb36c58d5` |
| Immediate pending | Same intent with `wait_seconds: 0` returned `pending`, attempts 0. | Event `1310431593`, run `cecb808d-5775-4972-919f-575bfb0e4e47` |
| Missing reference | Empty reference returned `MISSING_REFERENCE` before Execute, with no generated replacement reference. | Exit event `1310423647`, run `9fc3547a-6fac-4ef1-84b3-acb304ec768e` |
| Unknown fixture target | A syntactically valid unknown hostname returned HTTP 503 / `EXECUTION_UNAVAILABLE`. Initial request plus three retries stopped with `uncertain`, attempts 3, no execution ID. | Event `1310431963`, run `7d0b74c4-c7d6-434d-a935-11b3f691fc6f` |
| Pending link after Outcome fix (`reviewer-deny`) | `PENDING_APPROVAL`, `approval_state: PENDING`, usable `/approvals` URL, attempts 0. | Event `1310437123`, run `1fe33698-2687-464b-8eaa-c83990851934`; execution `cf9c145c-df7f-454a-8fc0-9f1c44cb5dd9` |
| Reviewer DENY then same-reference resume | `DENIED`, `approval_state: DENIED`; no reservation/dispatch transition and no journal. | Event `1310444663`, run `b0e67175-5675-43fb-a69d-c1f90c7db8f8`; approval `68e33fab-2aca-4429-9880-cf1f1e64d454` |
| AI caller allowed (`ai-allow`, `ws03.pilot.example`) | Triage chose to act, preserved the supplied ticket reference and passed the governed `EXECUTED` result back. | Caller Result `1310440919`, run `5e215ad8-fa3f-4cf2-aabb-a01e5f695d38`; execution `fe01c254-720d-43b2-be6b-7a1bba8c0cf2` |
| AI caller hard denied (`ai-deny`) | Same chain returned `DENIED` for the domain controller. | Caller Result `1310440932`, run `cdb07bff-b220-4db6-80ee-cde25162d6ec`; execution `e5e0b4bf-c42b-4fdb-aaef-46f236df52bd` |
| AI caller pending (`reviewer-deny`, before refusal) | Same pending execution, attempts 0, approval state and URL preserved through Send to Story. | Caller Result `1310440912`, run `245e6dd7-c23b-49aa-a73e-f974d2a66f5b` |

### Independent execution evidence

Execution rows and transitions were read in a PostgreSQL **read-only transaction**, scoped
to the synthetic tenant. The frozen command for each row was then sent only to the protected
mock provider's read-only `/v1/journal` lookup. `MockConnector.lookup` authenticated each
returned journal against its configured key and exact command. No dispatch or cancel API
was called by this inspection. Successful records each report `mutation_count: 1`.

| Execution | Operation | Independent journal |
| --- | --- | --- |
| `2a652d18-a403-4d65-b63b-9b895f3b9484` | `1093cb6e-528b-48dd-bffb-8daf7b4cee13` | Absent; transitions ATTEMPTED → DENIED |
| `383f4785-8d8d-462a-8309-864a60c5f5e6` | `70e04715-cb41-4bf8-b4ce-c9891d58532d` | EXECUTED, one mutation; one RESERVED and one DISPATCH_COMMITTED transition after the retry |
| `4b2a7f9d-c0d0-4d15-bf56-c6a87f2a85a0` | `52698d83-27ab-433b-bb1c-b1396613561c` | EXECUTED, one mutation; PENDING_APPROVAL precedes RESERVED and DISPATCH_COMMITTED |
| `cf9c145c-df7f-454a-8fc0-9f1c44cb5dd9` | `6ea1ed43-9bb0-412d-a85d-61de72284693` | Absent; ATTEMPTED → PENDING_APPROVAL → DENIED |
| `fe01c254-720d-43b2-be6b-7a1bba8c0cf2` | `2dee69be-3d20-47ec-b492-2d705d22e034` | EXECUTED, one mutation |
| `e5e0b4bf-c42b-4fdb-aaef-46f236df52bd` | `b5d15660-591e-4738-b135-7b9af39493fa` | Absent; ATTEMPTED → DENIED |

These are operation-specific journal counts, not a network request counter. Impact-ledger
charges were not separately inspected. The approval's journal was read after completion,
not sampled immediately before the human decision; its state history orders the dispatch
after approval. No real CrowdStrike system participated.

The console's execution drawer reported **no declared dispatch precondition** for this
pilot binding. The trial therefore makes no claim of atomic precondition enforcement or
protection against a target changing between evaluation and dispatch. Qualify the binding's
declared precondition separately before making that claim.

## Defects found and corrected

The first pending run stopped with `wrong number of arguments (given 3, expected 2)`.
Both deadline branches called `DATE_DIFF` with three arguments and compared it as a number.
Tines documents a two-date function returning an object; the fix reads cumulative seconds
with `GET(DATE_DIFF(prepare.started_at, NOW()), "seconds")`. It deliberately does not read
`units.seconds`, which wraps within a minute. Both branches then ran at the 90-second
boundary. See the official [DATE_DIFF](https://www.tines.com/stories/docs/formulas/functions/date-diff/)
and [GET](https://www.tines.com/stories/docs/formulas/functions/get/) references.

`Outcome` also read nonexistent `execute.body.approval.state` and `.url`. The HTTP response
uses flat `approval_state` and `approval_url` fields. Before correction, pending outcomes
lost the state/link; afterwards the direct and AI caller results retained both, and reviewer
denial retained `DENIED`. Each defect had a regression test observed failing before the fix.

## Limits and next proof

- Shared impact across a second AGENT using HTTP/SDK and Tines remains the **next unrun
  scenario**. Use an isolated synthetic window and retain ledger evidence; do not lower the
  live tenant's controls just to obtain a denial.
- No induced HTTP 429, dropped post-commit response, committed-but-uncertain provider effect,
  approval expiry, malformed-target syntax or actual bypass attempt was exercised. The
  unknown-target 503 proves bounded unavailable-response handling, not any of those cases.
- Reviewer decisions used normal HTTPS forms in a separate test session. Neither a physical
  phone nor a mobile browser approval flow was tested.
- The story remains **Advisory**. Participating requests go through the gateway, but an
  alternate independently credentialed story can avoid it. This trial neither tests nor
  prevents that bypass. The AI output schema remains a hint; three successful samples do
  not establish reliable model behavior for every input.
- This is the existing **Execute** path. A Tines **Gate** executor retaining vendor
  connectors in Tines is separate work; this story does not implement it. Monitoring,
  specialist signals and other catalog actions were not tested here.

## Retained state and resumption

The lab tenant's two enabled stories kept the corrected options and the restricted pilot
credential for continued testing. The disabled monitoring story and all three resources
were left as found. The three successful synthetic endpoints remain isolated in the mock;
no cleanup calls were issued under new references. Both approvals created here reached
terminal decisions. Their history and any time-window impact charges remain intact.

Rollback exports and the evidence scripts were kept privately.
Before resuming, recheck credential expiry, gateway commit, fresh fixture context and the
current tenant policy. Complete the shared-impact case and remaining fault/phone cases
before calling the Tines Execute trial complete or proceeding to a Gate trial.
