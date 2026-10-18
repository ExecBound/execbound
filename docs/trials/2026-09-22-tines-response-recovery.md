# Tines response recovery and credential-boundary trial, 22 September 2026

A response deliberately lost after a protected-mock effect exposed a caller bug: Tines
received HTTP 502 and the governed-action recipe reported `refused`. The gateway and
independently authenticated provider journal already recorded success. The corrected recipe
reported the same dropped response as `uncertain`; a subsequent same-reference call recovered
`EXECUTED` with the original execution and request handle. All three calls retained one
provider mutation, one confirmed impact row and the same signed-journal digest.

Earlier records cover the [initial Execute cases](2026-09-21-tines-governed-action.md),
[shared impact](2026-09-21-tines-shared-impact.md) and
[fault responses and expiry](2026-09-21-tines-fault-expiry.md).

Host: Tines Community Edition lab tenant, the governed-action story; the AI caller story as the alternate story
Version: Tines schema 30, standard library 96, action runtime 88; ExecBound 0.1.0
Date: 2026-09-22 UTC
Transport: live Tines HTTP actions through an authenticated temporary response-dropping relay; direct HTTPS for alternate-story probes
Gateway commit: `a513c8f93b89fd9feb1a5b21a06f8dbb42790f8c`; hosted schema `0049_unused_groups`
Fixture seed: synthetic pilot tenant, bundle `b8138742-1833-4935-94cc-5750172cb710`, protected endpoint mock

## Isolation and method

The original story graph, runtime resources, credentials and links were retained. Nineteen
temporary actions copied the committed governed-action graph with prefixed names and event
references. Its Execute action used a temporary relay credential. The relay held a newly
issued two-hour AGENT credential and accepted only one exact synthetic request, one route
and a bounded number of calls. Provider dispatch and journal-verification credentials stayed
outside Tines. No real vendor action, hosted migration or gateway deployment was performed.

The relay forwarded to the fixed hosted gateway, saved its HTTP 200 `EXECUTED` response,
then closed the response socket. Cloudflare returned HTTP 502 with an HTML body to Tines.
This is a real caller-side transport failure after a recorded effect, not a fabricated
gateway decision. The second call used the corrected graph while the relay still dropped
responses. The third used the same graph with normal response forwarding. All three
request bodies had SHA-256 `65182cb69d266b12dc70e255dbcefcb05612763766be96437bddc1019c158991`.
The workstation and server clocks differed; cross-clock timestamps are not latency evidence.
The relay's control flow and saved upstream result establish the order of effect and drop.

The tenant refused response-enabled webhooks and had no spare active flow. No plan upgrade
was made. The completed recovery graph was removed before the final bypass graph ran in
the existing AI caller story. These deterministic test actions had no connection to the
AI agent or its original workflow. An attempted secondary monitoring-story setup stayed
disabled and was restored during cleanup.

## Scenarios

| Case | Observed result |
| --- | --- |
| Original recipe; response closed after successful mock isolation | HTTP 502 HTML; incorrect `refused`, null code, attempts 0. Outcome event `1318987206`, run `f364964c-82c4-4500-985e-fa9bab72d340`. |
| Corrected recipe; same reference, response closed again | `uncertain`, `HTTP_RESPONSE_UNCERTAIN`, attempts 0; administrator handoff and no new-key instruction. Outcome event `1319031073`, run `321519fa-33ba-4dff-a77f-a602395316a7`. |
| Corrected recipe; same reference, response forwarded | `final`, `EXECUTED`, original `EB-79` and execution ID. Outcome event `1319036970`, run `31e7a860-a3ed-4078-a321-5664556a8ac4`. |
| Alternate story sends the frozen command directly to the protected mock without authorization | HTTP 401, `Provider request unavailable`; event `1319066885`. |
| Alternate story sends that command with an ExecBound AGENT credential | HTTP 401, same refusal; event `1319066818`. The temporary credential's domain restrictions allowed the protected mock as a destination, so the refusal came from the provider rather than Tines interpolation. |
| Alternate story calls the gateway directly for the protected domain-controller fixture | HTTP 200 carrying `DENIED`, `EB-80`; no dispatch transition, impact or provider journal. Event `1319067570`. |

The three final bypass probes share run `9681efc4-50e4-41ca-9234-001e1727d4f3`.
An initial unauthenticated probe also returned 401; the two credentialed actions did not
send until their temporary credential's explicit domain restrictions were configured.

## Independent effect evidence

Recovery reference `TINES-RECOVERY-20260922-lost-ack` targeted `ws24.pilot.example`:

- Request: `EB-79`; execution `5f6ebc57-6932-4760-8efa-68e6942a386b`.
- Provider operation: `fa060bb3-3f6c-4916-8be3-e218a08fbdef`.
- Exactly one `DISPATCH_COMMITTED` transition and one `EXECUTED` transition.
- One `CONFIRMED` impact row and independent journal mutation count **1** after the first
  drop, corrected drop, successful recovery and final bypass probes.
- Unchanged journal SHA-256: `57c9f1795ec33396787eab9ac082cd8bad63de5029cb0a6649e0e85aec5a53a4`.

Alternate reference `TINES-RECOVERY-20260922-alternate-deny` targeted `dc01.pilot.example`:
`EB-80`, execution `c66c3139-b6ce-4310-8b3e-3f8b05bcf6fa`, operation
`2fa478af-35fa-4537-89b8-7507f88c7bc2`. It has only ATTEMPTED and DENIED transitions.

The [sanitized evidence](2026-09-22-tines-response-recovery.json) retains selected Tines
outcomes, request hashes, execution/impact snapshots and journal digests. Raw events,
signed journals, credentials and private operator configuration are excluded.

## Fix and cleanup

All HTTP 5xx responses now classify as uncertain, even with a non-JSON body. Other than
the existing bounded 503 recovery loop, they exit directly without another story resend.
The refusal branch excludes all 5xx statuses. A missing gateway error code falls back to
`HTTP_RESPONSE_UNCERTAIN`; status-0 and native retry-exhaustion behavior is preserved.

Ten new regression cases failed before the fix; all 33 story tests passed afterward.
The live corrected 502 case validates the formula in Tines itself, beyond static wiring
tests. Other newly covered 5xx statuses were checked locally, not separately injected live.

All 30 temporary actions, two Tines credentials and the short-lived AGENT credential were
removed or revoked. Both temporary local processes were stopped. Fresh exports established
that the original graphs and links in all three stories were restored, together with their
enabled/disabled and entry/exit settings. The three corrected option/description blocks were
then installed in the lab tenant's working governed story; a final export differed only in
those blocks. Its original destination, credential reference and wiring were preserved.

The saved pilot AGENT keys had been revoked before this trial. They were not reactivated
or substituted into the original Tines credential. Future lab runs need a currently valid
scoped credential; this trial's temporary key is no longer usable.

## What this qualifies

This closes the named **Tines-to-gateway** lost-response/recovery gap and proves the
protected mock rejects these two direct credential-bypass attempts. It also shows a
different story still encounters gateway policy. It does not prove every possible Tines
path is governed: a caller with its own valid vendor credential can bypass the voluntary
story. The manifest remains **Execute / platform-validated / Advisory**.

Gateway-to-provider response loss after an unconfirmed mutation, every vendor connector,
provider atomic preconditions, a credential-retaining Tines Gate executor and customer
environments are outside this run. Gate remained a separate qualification, since recorded in the
[Tines Gate trial](2026-09-24-tines-gate.md).

An earlier signed-in Android Chrome approval of `EB-76` was verified separately and is not
part of this record.
A cold signed-out email-to-login-to-approval return on a physical phone remains unrun.
Next: the separate Gate work.

## Platform references

[Tines HTTP Request configuration](https://www.tines.com/stories/docs/actions/types/http-request/)
documents retry controls; [Cloudflare Tunnel troubleshooting](https://developers.cloudflare.com/tunnel/troubleshooting/)
describes origin connection failures behind 502 responses. The exact 502 HTML envelope and
its classification above were observed live. [Tines credential domain restrictions](https://www.tines.com/docs/credentials/credential-configuration/domain-restriction/)
explain why outbound use requires explicit destinations.
