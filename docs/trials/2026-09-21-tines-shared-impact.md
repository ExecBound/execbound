# Tines and HTTP shared-impact trial, 21 September 2026

**Passed:** ten actions from a second AGENT over HTTP and ten from Tines consumed the
same tenant limit. Further requests from both callers were denied specifically by that
limit. Retrying successful requests, including a Tines request through HTTP with the same
identity, reused the original execution without another impact charge or provider mutation.

This extends the [initial Tines Execute trial](2026-09-21-tines-governed-action.md).
The integration remains **Execute / Advisory** and the provider remains a protected mock.

Host: Tines Community Edition lab tenant, one test team, the governed-action story
Version: Tines schema 30, standard library 96, action runtime 88; ExecBound 0.1.0
Date: 2026-09-21, execution events 23:40:40–23:41:59 UTC, followed by read-only evidence capture
Transport: Tines webhook to HTTP Request to `/v1/execute`; second AGENT directly over HTTPS to the same gateway
Gateway commit: `c1818de46a0e7c72dbe5a0258731fe84dab4daeb`, hosted readiness; local repository baseline `d12e570`
Fixture seed: existing synthetic pilot tenant, bundle `b8138742-1833-4935-94cc-5750172cb710`, protected `mock_crowdstrike`, existing trusted incidents and endpoint fixtures

## Policy and custody

The active bundle was read before the run. It limits `endpoint.isolate` to **10 autonomous
targets per principal per 3,600 seconds**, then requires approval, and **20 total targets
per tenant per 900 seconds**, then denies. Both windows began with zero relevant charges
and no unresolved impact. The policy, principals, credentials and Tines story were not
changed. The trial did not reset counters, seed new data, deploy or apply migrations.

AGENT A (`b5de6d4f-34c4-4120-9ccc-c09fa53197ad`) used the existing restricted Tines Text
credential. AGENT B (`5736047f-6077-46d9-9c95-9beda6bcfabe`) used its existing private HTTP
credential. Both authenticated as distinct AGENT principals in the same tenant. Neither
credential is an administrator, reviewer or provider credential.

The Tines export still reported schema/library/runtime versions 30/96/88, and its Execute,
Outcome and deadline action options matched the committed sanitized export. Its UTF-8/LF
SHA-256 remains `a2d5c3318a1c76b57129dd72fdf32e45998eeb915047df998fe70759f21f42ef`.

## Scenarios

Every reference begins `TINES-SHARED-20260921-`. AGENT B used references `b-14` through
`b-23` for `ws14.pilot.example` through `ws23.pilot.example`. Tines used `a-04` through
`a-13` for `ws04.pilot.example` through `ws13.pilot.example`.

| Step | Result | Tenant confirmed charges | Unresolved |
| --- | --- | ---: | ---: |
| Baseline | No impact in either applicable window | 0 | 0 |
| B: ten direct HTTP actions | Ten EXECUTED outcomes | 10 | 0 |
| A: ten Tines actions on different targets | Ten EXECUTED outcomes in Tines | 20 | 0 |
| A: `overflow-a` on `ws24.pilot.example` | DENIED by `HARD_LIMIT:tenant-total-endpoint-isolate` | 20 | 0 |
| B: `overflow-b` on `ws02.pilot.example` | Same hard-limit denial | 20 | 0 |
| Repeat A's `a-04` through Tines and directly over HTTP as A | Same execution `dad05c55-ea0c-4329-9e52-a99d4c88ae30`, EXECUTED | 20 | 0 |
| Repeat B's `b-14` over HTTP as B | Same execution `9c46d0fd-43af-47e5-ae6a-1b629436e978`, EXECUTED | 20 | 0 |

At the end, each principal held ten confirmed charges. The twenty successful operations
addressed twenty distinct canonical targets. Each had exactly one impact row and one
`RESERVED → DISPATCH_COMMITTED → EXECUTED` transition sequence. Both denied executions
had only `ATTEMPTED → DENIED`, zero impact rows and no approval. The principal limit would
also require approval for an eleventh autonomous target, but the recorded tenant hard denial
won; no approval was offered to override it.

Key Tines correlations:

| Observation | Event | Story run | Execution |
| --- | --- | --- | --- |
| First `a-04` success | `1310788561` | `b0dcd73a-4f79-441a-ab18-dd093809887f` | `dad05c55-ea0c-4329-9e52-a99d4c88ae30` |
| `overflow-a` hard denial | `1310790895` | `bd8da7b5-09dc-4afa-a6c6-c99f3d8cc27e` | `876ba16c-99f6-4a07-a4ed-5a715a6f2389` |
| Same `a-04` retry | `1310790921` | `4878b3cb-b328-4e06-bb80-4c3045c0b9ce` | `dad05c55-ea0c-4329-9e52-a99d4c88ae30` |

The HTTP overflow execution was `53a00809-7fc9-43f4-84ce-d1a1928fe103`. Both denied
operations returned no approval ID. A webhook acknowledgement alone counted as no proof;
Tines Outcome events and the gateway's retained state established the results.

## Evidence

The [sanitized evidence JSON](2026-09-21-tines-shared-impact.json) holds the four counter
snapshots, all 22 execution/operation/target correlations, state transitions, denial reasons,
per-execution impact row counts and hashes of the authenticated provider journals. Its
SHA-256 is `4f0b214b0ad74b834149f5139d22e0d65e8768c0a934355a79a5306b93eb2735`.

Execution and impact rows were read in tenant-scoped PostgreSQL **read-only transactions**.
For each retained frozen command, an independent read of the protected mock's `/v1/journal`
authenticated the response against the configured key and exact command. All twenty
successful journals reported `mutation_count: 1`; both denied operations had no journal.
The evidence capture called neither dispatch nor cancellation. These are operation-specific
mutation counts, not a network-request counter.

The first snapshot used the local machine clock, which was about ten seconds behind the
hosted event timestamps. Subsequent snapshots use the database clock and count only
confirmed timestamps within the window and no later than that snapshot. The baseline was
well clear of either boundary; the whole mutation sequence took less than 90 seconds,
well inside the 900-second window. No expiry of an earlier charge explains the result.

Raw signed evidence, exports, requests and replies are retained
privately. The committed
JSON uses an explicit field allowlist and passed the repository's secret scanner. Full
exports and credentials are not included. Successful assertions during capture checked
the exact counter sequence, two distinct principals, twenty distinct successful targets,
one impact row and journal mutation per success, and no impact or journal for hard denials.

## Limits and retained state

This establishes shared accounting across participating Tines and HTTP callers on the
same tenant policy. It does not establish protection against a story bypassing ExecBound,
cross-tenant pooling, every possible concurrent race, another operation or a real endpoint
vendor. The missing declared precondition noted in the initial trial is unchanged.

The twenty test endpoints remain isolated in the mock. Their impact charges and history
were preserved. The 15-minute tenant window and one-hour principal window age normally;
the trial did not refund them. Later tests must account for the remaining principal limits,
even after the tenant window has cleared.

Next: finish isolated fault-response, expiry and phone-approval cases, then qualify the
binding's declared precondition. The Tines Gate path retaining customer connectors in
Tines remains a separate implementation after this Execute baseline.
