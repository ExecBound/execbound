# Tines Monitor live trial, 26 September 2026

The Monitor example story acts at a vendor with its own credential and reports
each result, and a scheduled heartbeat, to ExecBound's monitoring intake. This trial ran it in
a real Tines tenant against a local monitoring service: success, error and unknown results, a
duplicate retry, scheduled heartbeats, a heartbeat stopped until the source read stale and
then resumed, an unreachable intake and its recovery, token rotation inside and past the grace
window, collection coverage of the tenant, and a revoked source. Every finding was delivered to
the authenticated loopback receiver.

Host: a Tines Community Edition lab tenant; the trial story "ExecBound: Monitor an action (example)", id `147205`, imported through the Tines API from the committed `integrations/tines/execbound-monitor.json` and deleted afterwards, with its two credentials and two resources
Version: Tines export schema 30, standard library 97, action runtime 88 (the tenant's own export fields); ExecBound `0.1.0`, monitor events v1
Date: 2026-09-26 UTC, 00:24 to 01:02
Transport: Tines HTTP Request actions to the intake-only origin (`execbound.monitoring.ingress`, loopback 8622) and to a loopback lab vendor stub (loopback 8623) kept with the trial's private evidence, each behind a Cloudflare quick tunnel run only for the trial; the monitoring service on loopback 8620 and the loopback alert receiver on 8621 were never exposed
Gateway commit: `88c5ded` (`main` at the start of the trial). The trial changed no server code; the story changed once during the trial, below
Fixture seed: `init-demo` on a local database, a synthetic tenant with an eight-hour ADMIN credential; its synthetic `lab-story` source was revoked before the trial so it could not age into a finding. The story's source `e350211b-c956-47f7-a5b2-efbb40b40e5a` was registered with `create-source --story-id 147205 --hours 12`, heartbeat interval 300 seconds. No hosted database, hosted gateway or real vendor was used

## One live fix

The first two reports, a result at 00:29 and the scheduled heartbeat at 00:30, were both refused
400 `INVALID_EVENT`, and both runs took `Reporting failed` with `reason: not_recorded` and the
code. The bodies Tines built were correct. The requests were sent with `content_type: json`,
and Tines' JSON "smart validation" sends a digit-only string as a number, so the story id
`"147205"` arrived as `147205`, which the strict intake refuses. The same trap is recorded for
text templates from the 14 September trial; this trial shows a formula object does not avoid
it. The story was changed to send `=TO_JSON(...)` text with the explicit
`Content-Type: application/json` header and no `content_type`. The live actions were updated in
place from the regenerated file and checked action by action against it. Every later report
was accepted.

The cause was then confirmed directly. The vendor action was set back to `content_type: json`
for one run, with the target `12345`. The stub received a non-string target and answered 400.
Restored to the committed form, the target `67890` arrived as a string and was answered 200.
Both runs reported, as `error` and `success`.

At the time of this trial the Execute and Gate stories still sent `content_type: json`, and the
gateway's strict parser refuses a numeric `reference` or target `value`, so a digit-only ticket
number or provider id sent through either story would have been refused. Both stories were
changed on 30 September 2026 to send `TO_JSON` text with an explicit header, as
[their guide](../../integrations/tines/README.md#what-the-story-sends) describes.

## Scenarios

**Import.** The committed file imported through `POST /api/v1/stories/import` as story `147205`.
Its export matched the committed file action for action, including every option, the
heartbeat's `*/5 * * * *` schedule and the links. The webhook's path and secret, blank in the
file, were set through the API. The story was disabled straight after import and enabled only
once the source, credentials and resources existed.

**Success** (target `lab-ws-01`, Tines run `2f48135b-1a99-427f-a098-8c3a393ef42b`, 00:30:33):
vendor 200, report 202, observation `614d43e8-ab0c-534a-9d38-8af5c5ef4a8e` with `event_id`
`tines-147205-1348829066` and outcome `success`. Evaluation matched `sensitive-action.v2` and finding
`50d4e3d1-264a-57c1-b791-47daa47a0d32` was delivered on the first attempt.

**Error** (`fail-ws-02`, 00:30:55): vendor 503, observation `90e9cf6c-…` with outcome `error`, a
`sensitive-action.v2` finding delivered. The action was not retried.

**Unknown** (`hang-ws-03`, 00:31:26): the stub held the request for 45 seconds. Tines gave up at
thirty seconds and, because `emit_failure_event` is on, emitted status 0. The observation
`0fa00d18-…` records `unknown`, and a finding was delivered. The stub's own log shows it
answered 200 fifteen seconds after Tines stopped waiting: an effect the story could not know
about, which is what `unknown` is for.

**Retry** (00:32:28): the success run's `Build result` event was re-emitted through the Tines
API. The report sent identical text and was answered 200 with `duplicate: true` and the same
observation id; the story exited `Reported` with `duplicate`. No new observation, finding or
delivery followed.

**Heartbeat.** Scheduled heartbeats were recorded at 00:35, 00:40 and 00:45, each with its
per-minute `event_id` (`hb-147205-20260926T0035` and so on) and outcome `NO_MATCH`. The source
read `REPORTING`.

**Intake down** (`lab-ws-04`, 00:35:58). The intake-only origin was stopped with the tunnel
left up. The report retried for about two minutes and then took `Reporting failed` with
`reason: unreachable`, status 0. The origin was restarted and the run's `Build result` event
re-emitted: the report was answered 202, a new observation, which shows none of the failed
attempts had reached the intake.

**Rotation** (00:38:37). `rotate-source --grace-minutes 2` issued a new token while the Tines
credential still held the old one. A result at 00:38:40 and the 00:40 heartbeat were both
accepted inside the grace window. At 00:40:53, past it, the old token was refused 401
`INVALID_SOURCE` and the story took `Reporting failed` with `reason: auth_lost`; the intake
counted one authentication failure with reason `MISMATCH`. The Tines credential was updated
with the new token and the refused run's event re-emitted; it was recorded 202.

**Collection coverage** (00:41:56). A read-only collection connection ran one inventory
collection of the tenant: stories, actions and credentials `available`, audit and AI audit
`unsupported` on this plan; four stories, 39 actions and five credentials. The trial story was
`instrumented`. "ExecBound: govern an action", which has an outbound action and no source, was
`discovered_only` with one `instrumentation-gap.v1` finding. "ExecBound: AI Agents" was
`coverage_unknown`, because its AI agent action type is in neither the outbound nor the local
list, and the disabled smoke test story was `disabled`.

**Heartbeat stopped** (00:45:10). The `Heartbeat` action alone was disabled after the 00:45
heartbeat was recorded, and nothing else was sent. The evaluation at 00:55:42, a little over
two intervals after the last heartbeat at 00:45:07, set the source `STALE` and recorded one
`source-health.v1` finding, "Source stopped reporting", which was delivered.

**Resumed** (00:56:31). The action was re-enabled. The 01:00 heartbeat was recorded, and the
next evaluation, at 01:00:24, set the source back to `REPORTING` with no finding and nothing to
deliver.

**Auth lost** (01:00:32). The source was revoked. The next result, `lab-ws-07`, was refused 401
`INVALID_SOURCE` and the story took `Reporting failed` with `reason: auth_lost`; the intake
counted one failure with reason `REVOKED`.

## Totals

Twelve observations: eight results and four heartbeats. Ten findings: eight
`sensitive-action.v2`, one `instrumentation-gap.v1`, one `source-health.v1`. Ten deliveries, all
`DELIVERED` on the first attempt, and ten receiver files, each written only after its
HMAC-SHA256 signature verified and each naming the finding its delivery carried. The lab
vendor received ten requests from Tines. Eight became observations; the other two are the
00:29 result refused before the fix and the result sent after revocation, and both of those
runs exited `Reporting failed` naming why. Every identifier, state, status, code and time is in
the [accompanying JSON](2026-09-26-tines-monitor.json).

## What this qualifies

The Monitor path from a real Tines story: reporting results and heartbeats with a source token
held in a host-restricted Tines credential, the outcome mapping from the story's own HTTP
result, idempotent retry, source freshness in both directions, finding evaluation and signed
delivery, rotation with a grace window, revocation, and coverage of the tenant against its
registered sources. The manifest promotes the Tines instrumented-stories row to
**Monitor / Observed / platform-validated** for these cases.

## Not established

- **Alert delivery beyond the loopback receiver.** Findings reach email, Slack, Teams or an
  HTTPS webhook nowhere, and the scheduled `monitor-process` job evaluates without delivering.
  Delivery was proved only to the authenticated local receiver.
- **Ongoing operation.** The trial ran for about forty minutes. Sources are issued from the
  command line for at most 24 hours, so a story instrumented for longer needs a daily rotation;
  nothing here exercised that cadence or a hosted intake.
- **A real vendor.** The vendor was a loopback stub. What the story observed is what the stub
  answered, and a source-reported result is never a verified effect.
- **Conflicting reuse from the story.** The story's event ids make a same-id, different-content
  report hard to produce by design; the 409 path and its integrity finding are covered by the
  intake's own tests and by TM4's classification, not by a live run.
- **Audit-log collection**, which this Community Edition tenant's plan does not expose.

## Cleanup

The trial story `147205`, its credentials `execbound_monitor_source` and `execbound_lab_vendor`,
and its resources `execbound_monitor_origin` and `execbound_lab_vendor_origin` were deleted. A
throwaway probe story, `147202`, imported before the trial to read `META` and the schedule
export shape, was deleted at 00:25. The tenant's three earlier stories, credentials and
resources were not modified; the only write to them was a no-op description update to the
disabled smoke test story that confirmed the API key could write. The local services, the
stub and both tunnels were stopped. The source was revoked. The private configuration, tokens,
receipts and the stub's token are kept privately, outside version control.
