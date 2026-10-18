# Tines Gate live trial, 24 September 2026

The Tines Gate story asks ExecBound for a decision exactly as the Execute story
does, then acts once at the caller's own vendor with the caller's own credential. This trial
ran the whole grant, act, report and reconcile surface against a real Tines tenant: allow,
deny, human review and refusal, approval expiry, a stable retry, an act window closing before
acting, a lost first response, a lost vendor response, a replayed grant and a wrong-scope
report, credential reach across the Gate/Execute boundary, a cooperative bypass, and shared
impact across the Gate and Execute paths together. A `JWT_SIGN` probe ran first to settle what
Tines actually emits into an ES256 attestation.

Host: a Tines Community Edition lab tenant; the trial story "ExecBound: Gate an action (trial)", id `146602`, imported from the committed `integrations/tines/execbound-gate.json`; a separate bypass probe story, id `146607`. Both were deleted afterwards, the three trial credentials and two trial resources deleted, `execbound_origin` restored to its prior value, and the tenant's own "ExecBound: AI Agents" story, disabled during the trial for the Community Edition flow limit, re-enabled.
Version: Tines export schema 30, standard library 95, action runtime 88 (the committed export's own fields); ExecBound `0.1.0`
Date: 2026-09-24 UTC (the `JWT_SIGN` probe ran 2026-09-23 18:35 UTC)
Transport: Tines HTTP Request actions to a local gateway (loopback 8100) and a local protected endpoint mock (loopback 8101), each behind a Cloudflare quick tunnel run only for the trial; direct HTTPS through the same tunnel for the lost-first-response grant, the replay and wrong-scope reports, the credential-reach probes, the Execute side of shared impact, and the administrator exit
Gateway commit: `962ac9e` (kernel and gateway code unchanged through `3ed642b`; the two later commits touch only the story, its README and its tests); local schema `0056_gate_evidence`. No hosted database, hosted gateway or real vendor was used
Fixture seed: `gate-trial-live-1` from `src/execbound_harness/gate_demo.py`, synthetic tenant `bc7df1d7-f9a9-5513-b496-435a8e97c529`; seeded bundle `dd0f5a0a-92e8-5f07-a349-162a5c7a6019`, separation bundle `a05b22c1-6ff9-4fe6-ae43-0318711cb508`, shared-impact bundle `8763818e-43f1-4672-8710-4610d26836a4`

## Story commits and two live fixes

Allow, deny, approval expiry, review approve and review refuse ran the story at `962ac9e`.
The stable retry's first re-send exited `refused` there, a story defect fixed in `0a9eeee`,
and its re-run at that commit exits `final`. Act window closed and lost first response also
ran at `0a9eeee`. Lost vendor response's first run stalled at `0a9eeee` (below), was fixed in
`3ed642b`, and its re-run, the replay and wrong-scope case, credential reach, bypass, shared
impact and the final allow all ran at `3ed642b`. The live Tines story was updated in place at
each fix and verified action-by-action equal to the committed export before the next case ran.

Both fixes are recorded in the acceptance evidence, not only here:

- **Stable retry.** A retried settled reference answered 200 `EXECUTED` and the story's
  `Outcome` switch had no branch for it, so it exited `refused`. Fixed in `0a9eeee` (final and
  uncertain mapping, the "already recorded" message).
- **Lost vendor response.** Tines' default `emit_failure_event` emits nothing for a timeout or
  a DNS failure, so the first lost-vendor-response run stopped silently at the vendor call with
  its grant unreported: no exit event at all. Fixed in `3ed642b` (`emit_failure_event: true` on
  every HTTP action, plus `REPORT_NOT_ACCEPTED` for a report the gateway never answered).

## The `JWT_SIGN` probe

Run first, in the same lab tenant, with a throwaway story and credentials. An unrestricted
credential emitted header `{alg: ES256, kid}` only, no `typ`; claims exactly as supplied, no
added `iat`; an integer `version`; `reported_at` carrying an explicit `+00:00` offset; and a
64-byte `r||s` signature that verified. A host-restricted credential used in the same formula
failed: "This credential can only be used with HTTP Request Actions, Webhooks or Receive Email
Actions in IMAP mode." This settles the checkpoint guide's limitation 12 (a Tines signing
credential cannot be host-restricted) and is why the story's own `execbound_gate_signing`
credential carries no host restriction.

## Scenarios

**Allow** (reference `GATE-TRIAL-allow-62e78e37`, request `EB-1`): grant, one vendor act, one
journal report, settled `EXECUTED` at `PROVIDER_VERIFIED`, one dispatch and one journal
mutation, claim released.

**Deny** (`GATE-TRIAL-deny-09b2b179`, `EB-2`, target `gate-domain-controller`): `DENIED`, the
vendor was never called, no impact row.

**Review by a normal account, approval expiry, approve and refuse.** The reviewer throughout is
a signed-in `HUMAN_APPROVER` person on a password account, never a reviewer token. Approval
expiry (`GATE-TRIAL-review-approve-c254d679`, `EB-3`) expired at the default 120-second
deadline: `STALE_AUTHORIZATION`, no vendor call. The tenant's approval deadline was then raised
to 900 seconds for the two review cases that follow. Review approve
(`GATE-TRIAL-review-approve-f2da3668`, `EB-4`) was decided `CONSUMED` (decision
`09d2e3e3-5ef4-4d9e-a0f9-d333952197ed`), then settled `EXECUTED` at `PROVIDER_VERIFIED` with one
dispatch. Review refuse (`GATE-TRIAL-review-refuse-978f424e`, `EB-5`) was decided `DENIED`
(decision `00761bde-18ec-4353-b757-6772643a5c23`) and the vendor was never called.

**Stable retry** of the allow reference (`GATE-TRIAL-allow-62e78e37`, `EB-1`, same execution
`f6e742a4-0f28-4c9d-a9b7-19b632cb47ad`): the first re-send exited `refused` although the row
was already `EXECUTED` (the story defect above); the re-run after the fix exits `final`,
state `EXECUTED`, "This reference already has a recorded result; this run did not call the
vendor," one vendor dispatch in total across both the original run and the retries.

**Act window closed** (`GATE-TRIAL-act-window-closed-d15d864c`, `EB-6`, target
`gate-workstation-02`): the vendor was never called; ExecBound settled a Tines-signed ES256
non-execution, `FAILED_NOT_EXECUTED` at `ATTESTED`, impact `NONEXECUTION`, claim released.

**Lost first response** (`GATE-TRIAL-lost-first-43263f65`, `EB-7`, target
`gate-workstation-03`): the direct grant was discarded; the story's own retry received a
re-grant carrying no secret and exited `needs_administrator` with `REGRANTED_WITHOUT_SECRET`,
no vendor call, impact `UNRESOLVED`. An administrator's registered Ed25519 key
(`trial-admin-settle-1`) then signed `CANCELLED_NOT_EXECUTED`, and the grant settled
`FAILED_NOT_EXECUTED` at `ATTESTED` through `POST /api/console/v1/executions/{id}/reconcile`,
the Activity settlement control's own route, driven over HTTP with a console session opened
from the administrator setup credential. No password was entered and the settlement page
itself was not clicked.

**Lost vendor response**, run twice. First, with Tines' defaults
(`GATE-TRIAL-lost-vendor-response-8feccdbf`): the vendor call hit Tines' 30-second timeout and
Tines emitted no event at all, so the run stopped with the grant unreported. That grant
(execution `9e5645be-6409-4afe-8a8e-e4463157a7ae`) was settled afterwards by the administrator
exit with the vendor's own journal: `EXECUTED` at `PROVIDER_VERIFIED`, one mutation. After the
`emit_failure_event: true` fix, the re-run (`GATE-TRIAL-lost-vendor-response-85224316`, `EB-9`,
target `gate-workstation-05`) timed out the same way, but the timeout now emitted status 0; the
story looked the journal up with the same command, found it, and settled `EXECUTED` at
`PROVIDER_VERIFIED` with one dispatch.

**Replay and wrong scope.** Two grants, A (`EB-10`) and B (`EB-11`). Presenting A's secret and
A's journal as a report for B was refused 403 `INVALID_REPORT`. Presenting B's own secret with
A's journal was refused 400 `INVALID_RECORD`. B was untouched by either refusal
(`DISPATCH_COMMITTED`, impact `UNRESOLVED`) and both then settled `EXECUTED` at
`PROVIDER_VERIFIED`, each from its own journal, one dispatch and one mutation apiece.

**Credential reach.** Before any separation was provisioned, a direct `/v1/execute` call with
the Gate credential's execute operation on an execute-path target was dispatched by ExecBound
and `EXECUTED`: the seeded bundle never provisioned the separation that a Gate principal serves
Gate mappings only (checkpoint guide limitation 9: owner provisioning, not a control). The
same call through the Gate story exited `uncertain` with `EXECUTION_UNAVAILABLE` after
retrying a 503 for about 97 seconds: a target outside the mapping's account answering 503
with no row, for either
principal: existing Execute-path behaviour, which the [interface reference](../API_REFERENCE.md)
documents in its 503 row as the answer an unknown target gets. Separation was then provisioned live, the owner's way: `bundle-create`,
`bundle-validate` and `bundle-activate` with the administrator credential, adding two Cedar
forbids keyed on the principal and on `resource.account`
(bundle `a05b22c1-6ff9-4fe6-ae43-0318711cb508`, state `ACTIVE`). The seeded bundle itself
failed `bundle-validate` first, `INVALID_COMPONENT`, because `_with_max_age` had written a
context setting for every catalog contract while the bundle maps only one and `install_bundle`
never checks that; the activated copy keeps settings for the mapped contract only. After
separation, both cross-path direct calls answered `DENIED`, and the Gate credential's execute
operation through the Gate story on an execute-path target (`EB-15`) exited `final`, `DENIED`,
no vendor call.

**Bypass** (a separate ad hoc story, id `146607`, not the committed Gate story): with the
`execbound_gate_vendor` credential, the mock executed and ExecBound holds no execution for the
operation at all. Without it, the mock answered 401. This is why Gate is Advisory: nothing
here stops a story that already holds the vendor credential from acting without asking.

**Shared impact** (bundle `8763818e-43f1-4672-8710-4610d26836a4`): the seeded 20-target,
900-second tenant rule could not be filled cleanly: 11 untouched targets could not reach 20,
and the 900-second window was rolling earlier charges out mid-case; so the owner added a
stricter tenant rule, `trial-shared-isolation`, a 7,200-second window with a ceiling of the 8
already charged plus 5 more. Two Gate grants and three direct Execute dispatches filled 13 of
13; the next request on each path, Gate and Execute alike, was denied
`HARD_LIMIT:trial-shared-isolation`.

**The final allow**, on the committed story (`GATE-TRIAL-allow-final-story-32265e1e`, `EB-16`,
target `gate-workstation-10`): `EXECUTED` at `PROVIDER_VERIFIED`, one dispatch. Its decision
request and journal report are the committed fixtures
`tests/fixtures/tines-gate-decision-body.json` and
`tests/fixtures/tines-gate-journal-report.json`, parsed in
`tests/test_tines_gate_captured.py` by the gateway's own `ActionRequest` parser and outcome
report model; the journal parses as `SignedJournal`, whose record's command is a
`ProviderCommand` with `provider_operation: contain`.

Every state, tier, code, count, reference, execution id and Tines run guid captured for each
case above is in the [accompanying JSON](2026-09-24-tines-gate.json).

## What this qualifies

Gate's grant, act, report and reconcile surface ran against a real Tines Community Edition
tenant: the decision half (shared with the Execute story), signing an attestation with a
Tines-native `JWT_SIGN` credential, acting once at a caller-held vendor credential, settling at
`PROVIDER_VERIFIED` from a provider journal found either by direct report or by lookup after a
lost response, refusing a replayed or wrong-scope report, and never acting on a re-grant. It
also proved the cooperative bypass and the credential-reach gap that the
[checkpoint guide](../CHECKPOINT.md) named in advance.
The manifest promotes this row to **Gate / Advisory / platform-validated** for the cases above.

## Not established

The report window's closing is covered offline only, because the
route authenticates the credential before it reads the deadline. A real vendor was not
exercised: the protected mock signs journals with an HMAC key in the gateway's own private
configuration (checkpoint guide limitation 11). The Execute side of shared impact and
credential reach went by direct HTTP with the Execute credential, not through the Execute
story, because the tenant's Execute story was configured for a different gateway. The seeded
20-target, 900-second shared-impact rule's own number was not exercised; the trial ran against
an owner-added stricter rule instead. The settlement page's control markup was not exercised;
the administrator exit ran through its HTTP route with a console session, not a click.

The seed's separation and its bundle validation, as they shipped at the trial commit
(`962ac9e`), were not established: both were found missing or failing during the trial (the
credential-reach and shared-impact cases above) and provisioned or worked around live. They
were fixed after the trial: the password reviewer is now seeded through
`invite_person`/`assign_approver`, the two Cedar separation forbids are in the seeded bundle,
context settings are kept for mapped contracts only, and the trial harness's gateway readiness
probe sends the tunnel host. The trial harness and its runbook are not published. A retry of the
seed after a part-way failure needs a new seed name, because the reviewer is seeded in its own
transactions after the main seed transaction commits.

## Cleanup

Both trial stories (`146602`, `146607`) were deleted, the three trial credentials and two
trial resources were deleted, `execbound_origin` was restored to its prior value, and the
`ExecBound: AI Agents` story, disabled during the trial for the Community Edition's
one-webhook-flow limit, was re-enabled. The local gateway, local protected mock and both
Cloudflare quick tunnels were stopped. No hosted database, hosted gateway or real vendor was
touched at any point.
