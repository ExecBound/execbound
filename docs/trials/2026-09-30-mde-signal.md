# Defender for Endpoint signal trial, September 30, 2026

Status: live platform trial. The scenarios support the integration register's `platform-validated` state for the local Defender-to-gateway path described here. The row was promoted on October 1, 2026. S7, the Windows alert-resolution transition from `Medium` to `None`, was pending then and was established on October 3, 2026 in a follow-up run recorded [below](#s7-october-3-2026). The same day, the committed Tines governed-action story sent the baseline, quiet and compromised requests to the hosted gateway, with the producer posting to it over HTTPS; that stage is recorded in [Hosted Tines stage, October 3, 2026](#hosted-tines-stage-october-3-2026). The first run was on September 30 local time, crossing October 1 UTC.

Host: Microsoft Defender for Endpoint in a dedicated Entra lab tenant, machines API at `api.security.microsoft.com`; one Windows and one Linux Azure VM onboarded to it, called the Windows host and the Linux host below. The token of the producer's reader application contained exactly `Machine.Read.All`.

Version: `execbound-mde-producer` 0.1.0; ExecBound 0.1.0, security-signal v1, `endpoint-isolation.v2`.

Date: October 1, 2026 UTC, preflight at 00:03:18 through offline replay at 00:24:41.

Transport: Defender was read over HTTPS. The producer posted to `http://127.0.0.1:8900/v1/signals`; agent requests and the console used the same loopback gateway. The protected endpoint and identity mocks listened on loopback ports 8901 and 8902. Nothing was exposed publicly.

Gateway commit: `d5238ac247082c4c83ef909ad1ad3db28e911d84`.

Fixture seed: `seed-validation --seed mde-trial-1`, on a separate local PostgreSQL 17.11 cluster. Tenant 0 had its own inventory and incident sources. The Windows host stood for `workstation-01`, and for `domain-controller` in S5; the Linux host stood for `workstation-02`. No hosted database, hosted gateway or real endpoint dispatch provider was used.

## Scenarios

Times are UTC on October 1. The actual order was S1 through S6, S8, then S9. S7 was not attempted because the live API continued to return `Medium` and the manual alert-resolution step was pending.

| Scenario | Time | Request or check | Observed result |
| --- | --- | --- | --- |
| Initial setup discrepancy | 00:03:19 | Baseline request using a provider-ID alias absent from the fixture | HTTP 503; audit `INVALID_TARGET`. Retained as setup evidence, then the helper was corrected to use the seeded canonical resource ID. |
| S1 baseline | 00:06:13 | `endpoint.isolate` on `workstation-02`, without the signal policy | HTTP 200, `EXECUTED`, EB-1. The protected mock recorded one mutation. |
| S2 missing | 00:06:44 | `isolate.corroborated` on `workstation-02`, before the producer ran | HTTP 503, `EXECUTION_UNAVAILABLE`; audit `INVALID_CONTEXT`; no approval. |
| S3 quiet | 00:07:44 | Same host with Defender `None`, mapped to `no_detection` | HTTP 202, `PENDING_APPROVAL`, EB-2. No additional mutation. |
| S4 compromised | 00:07:44 | `workstation-01` with Defender `Medium`, mapped to `compromised` | HTTP 200, `EXECUTED`, EB-3; no approval. The protected mock recorded one mutation. |
| S5 denied | 00:08:37 | Temporarily map the Windows observation to `domain-controller`, then request isolation | HTTP 200, `DENIED`, EB-4 despite `compromised`; no approval and no mutation. The producer mapping was restored afterward. |
| S6 console | 00:11:22–23 | Authenticated approver and administrator views in Chromium | Signal evidence rendered as described below. |
| S7 resolved | Not run on October 1 | Resolve the Windows test alert, observe `None`, then submit a new Windows request | Not attempted in this run; no simulated verdict was substituted. Established on October 3; see [S7, October 3, 2026](#s7-october-3-2026). |
| S8 stale | 00:21:39 | Linux request after the producer had stopped at 00:12:19, beyond the 300-second freshness limit | HTTP 503; audit `INVALID_CONTEXT`; no approval. |
| S8 approval | 00:13:31 and 00:21:40 | A same-intent request, then the original S3 retry | `STALE_AUTHORIZATION`, approval `EXPIRED`. Later observations had not extended S3's original deadline. At 00:22:44, the console showed expiry and no Approve button. No approval submission is claimed for this case. |
| S9 preparation | 00:23:16 | Restart the producer, accept fresh observations, then request Linux isolation | HTTP 202, fresh `PENDING_APPROVAL`, EB-5. |
| S9 approval | 00:23:19 | Open EB-5 as the approver, revoke the source, then click its enabled Approve button before expiry | HTTP 200, execution `STALE_AUTHORIZATION`, approval `INVALIDATED`. The server re-attested the evidence and prevented dispatch. |
| S9 revoked | 00:23:32 | New Linux request after source revocation | HTTP 503; audit `INVALID_CONTEXT`. The running producer logged `INVALID_SOURCE` and stopped. A subsequent Linux subprocess check confirmed exit status 2 at 00:24:36. |

Protected endpoint mutation counts after S5, S8 and S9 were identical: `workstation-01` 1, `workstation-02` 1, `domain-controller` 0. These two mutations belong to S4 and S1 respectively. No stale, revoked or denied request added an action.

## What people saw

Headless Chromium visited the running console with the fixture's scoped approver and administrator credentials through its local setup login. The approver's S3 page displayed `no_detection`, `MDE lab`, and `resource_compromise.v1`. The administrator's S4 activity drawer displayed `Medium`, confidence 1000 of 1000, producer `execbound-mde-producer` version 0.1.0, and observation and receipt times. The signal records disclosure was opened to inspect those fields. Neither page displayed the attribute name `mde_machine_id`.

These were automated checks of the actual local console and database, not a human usability test or a hosted phone-login test. Raw page text and request responses remain private because they can contain source identifiers and short-lived fixture continuations.

## Replay

The producer, gateway and both provider servers were stopped before export and replay. A process check found no remaining trial server or producer. The audit export ended at sequence 57. Offline replay exited successfully at 00:24:41 and reported `Evidence completeness: complete` for the exported history.

The report contained five admission decisions, each reproducing its recorded policy effect:

- Two `ELIGIBLE`, with outcome `EXECUTED` from recorded gateway evidence: S1 and S4.
- Two `REQUIRE_APPROVAL`, with outcome `NOT_EXECUTED` from recorded transitions: S3 and S9 preparation.
- One `DENY`, with outcome `NOT_EXECUTED`: S5.

The pre-admission refusals are audit evidence, not separate policy decisions in replay. Their audit rows were sequence 20 (`INVALID_TARGET`, setup), 29 (`INVALID_CONTEXT`, S2), 48 (`INVALID_CONTEXT`, S8), and 57 (`INVALID_CONTEXT`, S9). Replay did not execute providers or create authorization. Its accompanying exported head establishes internal consistency; this run does not claim an independently attested external checkpoint. Complete replay evidence does not make the unrun S7 scenario complete.

## What running it corrected

- The trial procedure's example ports were already in use on the host. This isolated trial used ports 8900–8902, checked free beforehand, and its own database cluster.
- `seed-validation` does not install provider-ID aliases. The initial alias request was rejected correctly. The helper now selects the fixture's canonical resource ID, matching the existing validation harness; policy and identity resolution were not weakened.
- Request output is now allowlisted for console display. Complete responses stay private because pending responses carry a bound continuation.
- A distinct request reference can join an existing pending intent. It does not guarantee a fresh approval, and new signal receipts do not extend a frozen approval deadline.
- An expired approval cannot be clicked in the console. The trial procedure now records expiry and the retry separately, then uses an additional unexpired approval after revocation to test server-side re-attestation.
- Replay reports the admitted decisions it captured. It does not turn pre-admission refusals or an unrun scenario into policy-decision rows.

## What this does not establish

- S7 is established by the October 3 follow-up run below, on a fresh fixture, not by this run's history.
- This was one lab tenant and two API-reported machines. Only `Medium` and `None` were observed; `High` was not qualified by a safe live test.
- All consequential actions reached the protected mock provider. No real endpoint was isolated and no organizational or customer system was used.
- Tines was not in this run's path, and neither was the hosted service. The hosted Tines stage below covers the baseline, quiet and compromised requests only.
- Sensor liveness, VM power state and the truth of Defender's verdict were not attested. The gateway enforced the operator's reviewed interpretation of the returned score.
- The machines API returned `Active` health for both hosts during reads. That value does not establish that the sensor was currently delivering telemetry.
- Local private files were kept on the Linux filesystem with owner-only access; this does not qualify Windows filesystem secret-permission behavior.
- Lab housekeeping after the run, such as powering the VMs down, is outside this record.

## S7, October 3, 2026

A follow-up run established S7 on a fresh fixture, because S9 had revoked the first run's source.

Version: `execbound-mde-producer` 0.1.0; ExecBound 0.1.0, security-signal v1, `endpoint-isolation.v2`.

Date: October 3, 2026 UTC, fixture seeded at 03:56:19, replay at 05:23:00.

Gateway commit: `64315147f278048cfc82fec512658481e10ce9c6`.

Fixture seed: `seed-validation --seed mde-s7-20261003` on its own local PostgreSQL 17.11 cluster, with newly registered inventory, incident and signal sources and a freshly compiled signal bundle admitting the new source. The Windows host again stood for `workstation-01` and the Linux host for `workstation-02`. Transport was as in the first run: Defender over HTTPS, the producer and the agent on the loopback gateway at port 8900, the protected mocks on 8901 and 8902.

Both VMs stayed deallocated throughout. The machines API reported their stored risk scores regardless, which is the liveness limit this record already names; S7 concerns the verdict the API returns, not the host's power state.

| Step | Time (UTC) | What happened | Observed result |
| --- | --- | --- | --- |
| Before | 03:57:14 | With the producer posting and Defender returning `Medium` for the Windows host, request `isolate.corroborated` on `workstation-01` | HTTP 200, `EXECUTED`, EB-1, no approval. The frozen signal record held verdict `Medium`, mapped to `compromised`. |
| Resolve | about 05:13 | The Windows host's open `Medium` test alert was resolved in the Defender portal by the lab's operator. The reader application cannot resolve alerts | A poll every 30 seconds read `Medium` at 05:20:15 and `None` at 05:20:46. |
| S7 | 05:22:15 | After one more producer cycle, the same request on `workstation-01` | HTTP 202, `PENDING_APPROVAL`, EB-2, approval `PENDING`. The frozen signal record held verdict `None`, mapped to `no_detection`. The approval was left pending. |

The same request on the same host moved from direct isolation to review once Defender's verdict fell, with nothing else changed: the producer, the source, the mapping and the bundle were the same for both decisions.

The producer and the gateway were stopped before export. Offline replay at 05:23:00 reported `Evidence completeness: complete` and reproduced both admission decisions: `ELIGIBLE` with outcome `EXECUTED` from recorded gateway evidence (Before), and `REQUIRE_APPROVAL` with outcome `PENDING` from the recorded transition (S7).

This run adds no claim about the `High` band, sensor liveness, a hosted or Tines path, or real endpoint isolation; the limits above still apply.

## Hosted Tines stage, October 3, 2026

The committed Tines governed-action story carried the baseline, quiet and compromised requests to the hosted gateway. The producer posted Defender's verdicts to the same gateway over HTTPS from the operator's workstation, independently of the story. The answers matched the local run's.

Host: the Tines Community Edition lab tenant's governed-action story, export schema 30, standard library 97, action runtime 88; Defender for Endpoint as above; the hosted service's gateway, over HTTPS.

Version: `execbound-mde-producer` 0.1.0; ExecBound 0.1.0, security-signal v1, `endpoint-isolation.v2`.

Date: October 3, 2026 UTC, preflight at 17:15 through offline replay at 17:36.

Gateway commit: `071677a49d8536ddf9d0299b9d0eec8691e7bc1b`, reported by hosted readiness before the stage, with the hosted database at `0069_provider_signup`, the revision that code expects.

Fixture: the hosted pilot's synthetic tenant, in its default space, with its protected mock endpoint provider and its existing inventory and incident sources. Its `workstation-01` (`ws01.pilot.example`) stood for the Windows host and its `workstation-02` (`ws02.pilot.example`) for the Linux host, the provider ids the local runs used. No customer tenant, real endpoint or real provider was involved.

### What the stage set up, and put back

- The pilot held no live agent credential. A six-hour credential for the story's existing agent went into the story's Text credential, which kept its one allowed host, the gateway's `/v1/execute`. It was revoked when the stage ended, as was a six-hour administrator credential used for the policy commands.
- A mapping, `isolate.corroborated`, to `endpoint.isolate` under `endpoint-isolation.v2`. A signal source, `MDE lab - hosted`, vouching for that agent alone, for twelve hours, without liveness. A signal bundle compiled from the committed scenario rules and thresholds, admitting that source. The source was revoked when the stage ended; the mapping remains, named by no active bundle.
- The two hosts' inventory and incident context was re-imported at the registry's versions, which equalled each host's last receipt, and again after each isolation at the version its receipt reported.
- The story's `Execute` action still carried an earlier `content_type` option, which the committed export had since removed. It was set to the committed export's options before the run. Afterwards every action's options and every link of the live story matched the committed file, except the webhook's path and secret, which the committed file leaves empty.
- The signal bundle was selected in the default space for S3 and S4 only. The pilot's existing six-action bundle was selected again at 17:29:26, after S3's approval deadline had passed, and the signal bundle returned to `VALIDATED`.

### Scenarios

Each request was one post to the story's webhook with `wait_seconds` 0; the story's own actions prepared it, called `/v1/execute` and reported the outcome. Times are UTC on October 3.

| Scenario | Time | Request through the story | Gateway answer | Story outcome |
| --- | --- | --- | --- | --- |
| S1 baseline | 17:18:31 | `endpoint.isolate` on `ws02.pilot.example`, under the pilot's existing policy | HTTP 200, `EXECUTED`, EB-81 | `final`, event 1410623151 |
| Signal policy | 17:24:26 | The signal bundle selected in the default space | | |
| S3 quiet | 17:24:34 | `isolate.corroborated` on `ws02.pilot.example`, with Defender returning `None` | HTTP 202, `PENDING_APPROVAL`, EB-82, approval `PENDING` | `pending`, event 1410645873 |
| S4 compromised | 17:24:44 | `isolate.corroborated` on `ws01.pilot.example`, with Defender returning `Medium` | HTTP 200, `EXECUTED`, EB-83, no approval | `final`, event 1410646482 |

The gateway's frozen records agree: S3 holds verdict `None`, mapped to `no_detection`, and S4 holds verdict `Medium`, mapped to `compromised`. S1 and S4 are each one `EXECUTED` operation carrying the protected mock's authenticated receipt, under the provider-enforced precondition.

The Windows host had read `None` since the alert resolution above. It was started at 17:12, and Microsoft's documented detection test was run on it at 17:12:50 through the VM's run command. A 30-second poll read `None` at 17:19:28 and `Medium` at 17:19:59. The Linux host stayed deallocated and read `None`. The Windows host was deallocated at 17:25:53, after S4.

The producer posted every 60 seconds from 17:18 until it was stopped at 17:29:42: twelve cycles, 24 records accepted, none refused and no conflicting duplicate. The source was revoked at 17:29:49.

S3's approval deadline was 17:29:03. As in the local run, the signal's 300-second validity bounded it, not the pilot's 600-second approval deadline. The pilot's configured approval email delivered its notification at 17:26:13, and the approval was left undecided past its deadline.

### Replay

The audit export at 17:30:01 covered the pilot's whole history through sequence 733, its earlier trials included. Offline replay first reported `partial / unresolved`. Four `principal.labelled` events, written when people and agents were given names, were unknown to replay, so every decision after the first was `UNRESOLVED` with `INCOMPLETE_PRIOR_HISTORY`, the stage's three among them. Replay now treats that kind as informational, because no policy, capture or admission reads a label. On the same export, replay at 17:36:35 reported `Evidence completeness: complete` over 104 decisions and reproduced the stage's three: `ELIGIBLE` with outcome `EXECUTED` from recorded gateway evidence (S1 and S4), and `REQUIRE_APPROVAL` with outcome `PENDING` from the recorded transition (S3).

### What this stage does not establish

- It covers S1, S3 and S4. The missing, denied, resolved, stale and revoked cases rest on the local runs above.
- The lab is Tines Community Edition with one test team. The story was reached through its webhook; its Send to Story callers, the AI Agent caller among them, were not used.
- No approval was decided, so no hosted approval through the console is claimed.
- The limits above still apply: one lab tenant and two machines, `Medium` and `None` only, no sensor liveness, the protected mock endpoint, and no real isolation.

## Next action

The trial's planned stages are complete. The `High` band, sensor liveness and real endpoint isolation remain outside it.
