# Tines fault-response and approval-expiry trial, 21–22 September 2026

Approval expiry and malformed-target refusal passed against the hosted gateway. An isolated
Tines fault graph exposed a caller defect: a native transport failure with status `0` was
reported as `refused`. The corrected export routes that envelope directly to `uncertain`,
preserves the reference, and returns `TRANSPORT_UNCERTAIN` or `RETRIES_EXHAUSTED`.

The corrected graph passed both native-failure cases. The temporary graph was removed,
and the correction was installed in the lab tenant's working story.

Host: Tines Community Edition lab tenant, one test team, the governed-action story
Version: Tines schema 30, standard library 96, action runtime 88; ExecBound 0.1.0
Date: 2026-09-21 to 2026-09-22 UTC; September 21 in US Eastern time
Transport: live Tines HTTP actions; isolated fault webhook and reserved `.invalid` DNS name for failures; original governed story to HTTPS `/v1/execute` for expiry and malformed input
Gateway commit: `c1818de46a0e7c72dbe5a0258731fe84dab4daeb`; repository baseline `8d9315c`
Fixture seed: existing synthetic pilot tenant, active bundle `b8138742-1833-4935-94cc-5750172cb710`, protected endpoint mock

## Scope and isolation

The fault graph copied the committed governed story's options and links into unconnected
temporary actions, prefixing action names and their event references with `Proof`. Its
HTTP action used a secret-protected Tines webhook as the destination and carried only a
Content-Type header. It had **no ExecBound credential or provider access**. The receiver
returned controlled JSON with HTTP 503 or 429 and independently retained each request body.
The DNS case used `https://execbound-fault.invalid/v1/execute` with the same synthetic body.

No gateway rate-limit flood, new public deployment or change to the original story's
destination was required. These were real Tines transport and routing observations against
injected faults, not a gateway outage or a response lost after a vendor mutation. The
original story remained connected to ExecBound during the isolated tests.

[Tines' HTTP Request documentation](https://www.tines.com/stories/docs/actions/types/http-request/)
describes its configured retry count, backoff and failure-event options. The exact status-0
envelopes below were observed in this tenant; they were not inferred from that documentation.
The fixture used the documented [webhook response controls](https://www.tines.com/stories/docs/actions/types/webhook/).

## Scenarios

| Case | Observed result |
| --- | --- |
| Controlled 503 | Four identical requests, three story retries about 32 seconds apart; `uncertain`, attempts 3, original reference preserved. Outcome event `1310882520`. |
| Controlled 429, original export | Six identical requests over 365.941 seconds, then native `status: 0` with `retries_exhausted`. The story stopped, but incorrectly returned `refused` with a null code. Outcome event `1310959174`. |
| DNS failure, original export | Native `status: 0` with `connection_error`; incorrectly returned `refused`. Outcome event `1310973704`. |
| DNS failure, corrected graph | `uncertain`, `TRANSPORT_UNCERTAIN`, same reference and administrator handoff instruction; no story retry. Outcome event `1311003246`. |
| Controlled 429, corrected graph | Six identical requests over 345.327 seconds; `uncertain`, `RETRIES_EXHAUSTED`, no extra story retry. Outcome event `1311055678`, run `32d0db8d-8da8-4808-ab6b-a3f0c3e04512`. |
| Malformed hostname through the original story | `INVALID_REQUEST`, `refused`, no execution ID. Outcome event `1310940766`, run `e0a06f8f-2004-4461-a37a-548876066168`. |
| Approval left undecided until its deadline, then resumed through the original story | Same execution, `STALE_AUTHORIZATION`, approval `EXPIRED`, outcome `expired`; zero impact rows and no provider journal before or after expiry. |

All fault references begin `TINES-FAULT-20260921-`; their suffixes are `503`, `429`,
`dns-before`, `dns-after` and `429-after`. Every received body in each HTTP case was identical.
The story's `attempts` counts its own resend loop, not Tines' built-in retries: the exhausted
429 case has attempts 0 even though the fixture received six requests.

### Approval expiry

Reference `TINES-EXPIRY-20260921-deadline` targeted `ws25.pilot.example` using the existing
AGENT A credential. The tenant's shared-impact window had fallen below its hard limit
naturally before admission. No limit or clock was changed.

- Execution: `12c68413-2a8e-4b7b-be0e-5a509f624fc8`.
- Operation: `c08a68d4-45dc-41c7-adfd-9791bd9f2ab2`.
- Approval: `3c4240e0-e320-418c-a61e-35ff2a24d409`.
- Created: `2026-09-21T23:55:54.313384Z`; deadline: `2026-09-22T00:05:54.313391Z`.
- Pending Tines event: `1310883590`, run `9ff250f4-fad1-4dfe-8546-94c27506d48a`.
- Expired Tines event: `1311004965`, run `5264cc5b-52da-4357-b56b-f1d50cbd0fc7`.

A read-only snapshot after the deadline still showed persisted PENDING state; the deadline
had elapsed, but no actor had yet materialized the transition. The same-reference resume
then recorded `ATTEMPTED → PENDING_APPROVAL → STALE_AUTHORIZATION` and the EXPIRED approval.
No reservation or dispatch transition occurred. Independent authenticated, command-bound
mock journal lookups returned no journal in all three snapshots. This proves expiry on
resume, not that a background sweeper had already processed the row. (The scheduled
recovery run also ends an approval past its deadline once a grace period has passed; see
[Recovery](../RECOVERY.md).)

## Correction and verification

A new `Transport uncertain?` condition routes status 0 directly from Execute to Outcome.
Refused excludes 0. Outcome maps `HTTP-0` to `uncertain` and supplies a diagnostic code.
The existing 503 retry loop and native five-retry 429 budget are unchanged. A native failure
cannot enter another story resend loop after exhausting that budget.

The regression test failed against the original export, then passed with the correction.
Captured DNS and retry-exhaustion envelopes are retained as synthetic fixtures. The local
story, manifest and fragment suite passed 68 tests. These tests pin the export and wiring;
the live observations establish the platform's behavior.

## Evidence and cleanup

The [sanitized evidence JSON](2026-09-21-tines-fault-expiry.json) retains request receipt
IDs and timestamps, body hashes, Tines Outcome events and the three read-only expiry
snapshots. Raw exports and detailed events are retained privately.
The committed evidence uses an explicit
field allowlist and passed the repository's secret scanner.

All twenty temporary actions, including the fault receiver and the candidate routing
condition, were disabled and removed after their runs completed. A fresh export confirmed
that the original actions and links were unchanged. Only then were the two corrected
option blocks and the new transport condition installed in the working story. Its options
and named links matched the committed export; its existing webhook, gateway URL and
credential reference were preserved. No new Tines story or credential was created.
A final resume through that updated story again returned the same expired execution
(event `1311062832`, run `b5f0d15f-050c-4c5e-8f1f-ea0e62dc3b58`).

## Remaining limits

Execute remains **Advisory** with a protected mock provider. A response lost after a real
effect, a physical-phone reviewer flow and an actual alternate-story bypass still require
their own evidence. The fault receiver performed no vendor action and cannot prove those
cases. No real CrowdStrike integration was exercised.

An operator's attempted phone setup exposed sign-in and onboarding friction before a fresh
approval was submitted. The token-based reviewer had no email or Google identity attached;
the operator also reported a Google device-account-picker error. The phone test is therefore
blocked on a usable reviewer flow, not passed by the earlier scripted browser checks. The
findings and the acceptance criteria for resuming it were recorded separately; the
request-reference proposal they led to is now [request references](../REQUEST_REFERENCES.md).

The hosted pilot's missing precondition declaration remains unchanged. The current bootstrap
generates six declarations for the two mock providers; that typed declaration block and
ten existing stale-version tests passed, but the declarations were not applied here. No
hosted configuration, schema or deployment was changed, and earlier records are not upgraded
to an atomic-precondition claim.

Tines Gate, which retains the customer's vendor connector in Tines, remains a separate
implementation against the existing checkpoint protocol. This correction adds no Gate
grant handling, report-secret custody or external outcome reporting.
