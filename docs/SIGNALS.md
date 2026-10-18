# Security signals

A security signal is evidence an out-of-process detector attests about the target of a request, read by ExecBound as trusted context. The first capability is `resource_compromise.v1`: is the host itself compromised, according to an EDR. This guide describes the code as it is, and how to run it.

A producer can submit envelopes inside its registered scope and nothing else. It never reads the database, sees a decision, approves, dispatches or is called by ExecBound. What its verdict means is your mapping in the bundle, and that mapping is re-applied to the frozen records every time a decision is evaluated.

A signal is one input to one decision and nothing more. It does not change a path's placement, its enforcement mode, the freshness of other facts, the precondition class or the outcome's assurance, and a producer reporting that an action happened is never proof of a provider effect: it cannot settle an execution.

Inside the kernel a signal is a third source kind of the [context contracts](CONTEXT_CONTRACTS.md), beside inventory and incidents. Absence is never clean: a missing, stale, revoked, unmapped or foreign signal leaves the fact unresolved, which is `INVALID_CONTEXT`, and no approval rescues it.

## Register a producer

Registration is an owner command over `MIGRATION_DATABASE_URL`, audited under `--actor`, which must be an active ADMIN of the tenant, because a producer bears authority. It is never a runtime or console action, and on the hosted service only ExecBound holds that connection.

```bash
execbound signal-source-create --tenant <tenant> --actor <admin> --label "Defender for Endpoint" \
  --producer execbound-mde-producer --version-min 0.1.0 --version-max 0.9.9 \
  --principal <agent> --output ./producer.token
```

It prints the new source id, the token's expiry and the file. The registration says what the producer may send and whom it may vouch for:

- `--label` is how people see the producer: 1 to 96 characters of letters, digits, space and `._:-`, starting with a letter or digit.
- `--producer` is the name its envelopes must carry, and `--version-min` and `--version-max` the range of producer versions accepted, each three integers compared as numbers, never as text.
- `--capability`, repeatable, names what it answers. `resource_compromise.v1` is the only capability and the default.
- `--principal` (repeatable, up to 64 active agents) or `--group` (one principal group), exactly one of the two, names the agents the source may vouch for. A record applies only to a request from one of them; group membership is read at each decision.
- `--space` and `--offered` place the source like a connector account: owned by one space, and usable by every space when offered. Without `--space` the source goes to the tenant's only space, and a tenant with several must name one.
- `--input-path independent` (the default) says the producer observes the subject on a path the agent does not control. An EDR observes the host itself, so it is independent by construction. `agent_forwarded` is recorded, but no mapping can admit such a source today, because the only mapping mode is `required` and a `required` mapping admits only an independent source.
- `--attests-liveness` says the producer can show it is still observing each subject. Only such a source may map a verdict to `clean`. Defender for Endpoint's machines API cannot, so its source is registered without the flag and its quietest verdict maps to `no_detection` ([the producer's README](../integrations/mde-producer/README.md#what-it-needs)).
- Both are your statements at registration, which ExecBound records and cannot check ([R31](THREAT_MODEL.md#residual-risks)): registering a producer the agent feeds as `independent` lets a compromised runtime choose what it judges, and `--attests-liveness` on a producer that cannot show its sensor still reports lets a silent host read `clean`.
- `--hours` is the token's lifetime, 1 to 720 hours, 720 by default.

The token has the form `sg1.<tenant>.<source>.<secret>`, 121 characters, and only its SHA-256 digest is stored, in a column the runtime role cannot read. It is written once, with a newline, to a new file created with mode 0600; the command refuses an existing path, and nothing else ever shows the token. It opens `POST /v1/signals` and no other route, and an agent's token never opens that one.

The token file is written before the registration commits and removed if the registration fails. If the command was interrupted, look for the source id, the token's third dot-separated field (`cut -d. -f3 producer.token` prints only that), in `signal-source-list`: if it is absent, delete the file and run the command again. If the file is gone but the command's reply was lost, the list shows whether the source exists; rotate it for a new token, or revoke it.

```bash
execbound signal-source-rotate --tenant <tenant> --source <source> --actor <admin> --output ./producer-2.token
execbound signal-source-revoke --tenant <tenant> --source <source> --actor <admin>
execbound signal-source-list --tenant <tenant>
```

- `signal-source-rotate` writes a new token the same way, with its own `--hours` (720 by default), and keeps the old one working for `--grace-seconds`, 0 to 3,600 and 600 by default, never past the old token's own expiry and not at all once that has passed. The source id, its registration version and every bundle entry naming it stay as they were. An interrupted rotation is recovered as a registration is: `rotated_at` in the list says whether it committed.
- A token expires without the registration ending. When `signal-source-list` shows `expires_at` passed, every envelope is refused `INVALID_SOURCE` until you rotate; the source and the bundle entries that admit it stay valid, and validation does not read the expiry. Only revocation is final.
- `signal-source-revoke` stops every token at once, a rotation's grace included, and every fact the source attested fails at the next decision. A revoked source cannot be rotated or revoked again (`INVALID_STATE`); register a new one and activate a bundle that admits it.

`signal-source-list` shows every registration with its health: records accepted (`record_count`), the last acceptance and refusal with its code, conflicts and rate refusals, beside the scope, the expiry, the last rotation and the end of a grace window. It never shows a digest. Health is never an input to a decision. A refused credential is not a source's refusal: it is counted on the `signal` surface of `execbound failures`.

Creating, rotating and revoking a source are audited as `signal_source.created`, `signal_source.rotated` and `signal_source.revoked` in the source's space, never with the token or its digest, and are informational to replay. A command that refuses exits 2 with `Provisioning refused: <code>.`: `INVALID_LABEL`, `INVALID_PRODUCER` (either also for a label or producer shaped like a password, key or token, which `signal_source.created` would carry), `INVALID_VERSION`, `INVALID_CAPABILITY`, `INVALID_SCOPE` (a repeated agent, or more than 64), `INVALID_LIFETIME`, `INVALID_GRACE`, `INVALID_SPACE`, `INVALID_PRINCIPAL` (not an active agent), `INVALID_GROUP`, `INVALID_ACTOR`, `INVALID_TENANT`, `INVALID_SOURCE`, `INVALID_STATE`, `OUTPUT_UNAVAILABLE`, `INVALID_CONNECTION` (`MIGRATION_DATABASE_URL` does not connect as the schema owner) or `PROVISIONING_UNAVAILABLE` (the database refused or could not be reached). An unset or malformed `MIGRATION_DATABASE_URL`, or a token file that could not be written after it was created, exits 2 with `Owner connection or output file unavailable.` and no code. An `--input-path` other than the two above, or neither or both of `--principal` and `--group`, is a usage error before anything is read.

## Map its verdicts

The fact lives in a second contract version for isolation, which a mapping opts into:

```bash
execbound mapping-create --tenant <tenant> --account <account> --action endpoint.isolate \
  --ref isolate.corroborated --contract-version endpoint-isolation.v2 --actor <admin>
```

`endpoint-isolation.v2` is v1's facts plus `compromise`, over `clean`, `no_detection`, `suspect`, `compromised`, least to most restrictive. It binds the incident claim, so a request names its incident in `claimed_context.incident_id`. `endpoint.isolate`'s default stays v1: a mapping reaches v2 only through `--contract-version`, which refuses a catalog version that does not serve the action as `INVALID_CONTRACT`; a version the catalog does not hold is a usage error. Operation refs are unique per tenant, so the v2 mapping takes its own ref, here `isolate.corroborated`, beside a v1 `endpoint.isolate`; agents send that ref, and `GET /v1/actions` lists it once their space's active bundle names it.

The bundle carries the reading as `signal_mappings`. Write its entries to their own file, as a JSON array:

```json
[
  {
    "context_contract_version": "endpoint-isolation.v2",
    "capability": "resource_compromise.v1",
    "admitted_sources": ["<source id>"],
    "thresholds": [
      {"verdict": "None", "value": "no_detection"},
      {"verdict": "Informational", "value": "no_detection"},
      {"verdict": "Low", "value": "suspect"},
      {"verdict": "Medium", "value": "compromised"},
      {"verdict": "High", "value": "compromised"}
    ]
  }
]
```

| Field | Meaning |
| --- | --- |
| `context_contract_version`, `capability` | The contract whose fact this entry reads and the capability that fact is stored under; one entry per pair, at most 32 entries in a bundle |
| `admitted_sources` | 1 to 4 source ids, stored sorted |
| `thresholds` | 1 to 32 rows, each a producer `verdict` (compared exactly, case included), an optional `minimum_confidence` from 0 to 1000 (default 0) and the capability `value` it reads as; no two rows share a verdict and a floor, and rows are stored sorted by verdict and then floor |
| `minimum_correlation`, `combination`, `mode` | Optional and fixed today: `resource`, `most_restrictive` and `required` |

A record with a verdict whose confidence reaches a row's floor, and no higher floor for that verdict, reads as that row's value. A verdict no row names, or a confidence below every floor for it, is never read as quiet: the fact is unresolved. With several admitted sources, every one must report, and the most restrictive value wins; the fact names the source that produced it, ties going to the lowest source id as text. A `clean` result needs every record it rests on to come from a source that attests liveness.

Freshness is the contract's: 300 seconds from observation by default, with a 3,600-second ceiling. A `context_settings` entry for `endpoint-isolation.v2` and source kind `signal` may set `max_age_seconds` from 1 to 3,600, and its `permitted_writers` must be exactly `["signal_mappings"]`: admission is by source id in the mapping, so writer labels do not apply to this kind. Through `ruleset-compile`, the setting goes in the rules file's `context` array, beside `rules`, and the compiler carries it into the bundle as `context_settings`. A complete rules file with one rule and the setting:

```json
{
  "version": 1,
  "rules": [
    {"id": "isolate-open-incident", "action": "endpoint.isolate", "effect": "ALLOW",
     "when": [{"kind": "fact", "name": "incident_status", "operator": "is", "values": ["OPEN"]}]}
  ],
  "context": [
    {"context_contract_version": "endpoint-isolation.v2", "source_kind": "signal",
     "max_age_seconds": 600, "permitted_writers": ["signal_mappings"]}
  ]
}
```

Rules read the fact like any other. In the example scenario ([`integrations/mde-producer/scenario/rules.json`](../integrations/mde-producer/scenario/rules.json), which these rules match), a host is isolated without review only when it is `compromised`, everything else goes to review, and a domain controller is never isolated; save these rules as `rules.json`:

```json
{
  "version": 1,
  "rules": [
    {"id": "isolate-open-incident", "action": "endpoint.isolate", "effect": "ALLOW",
     "when": [{"kind": "fact", "name": "incident_status", "operator": "is", "values": ["OPEN"]}]},
    {"id": "isolate-never-domain-controller", "action": "endpoint.isolate", "effect": "DENY",
     "when": [{"kind": "fact", "name": "role", "operator": "is", "values": ["domain_controller"]}]},
    {"id": "isolate-review-unless-compromised", "action": "endpoint.isolate", "effect": "REVIEW",
     "when": [{"kind": "fact", "name": "compromise", "operator": "is_not", "values": ["compromised"]}]}
  ]
}
```

Then compile those rules over the one mapping and carry the signal mappings file:

```bash
execbound ruleset-compile --tenant <tenant> --input rules.json --ref isolate.corroborated \
  --signal-mappings signal-mappings.json --output bundle.json
```

`--ref`, repeatable, chooses the mappings; without it every active mapping is compiled. Rules name the catalog action, never the ref: the compiled bundle's mapping for `isolate.corroborated` carries `"action": "endpoint.isolate"`, which validation holds to the tenant's mapping row. One bundle serves one action under one contract version and describes the `Endpoint` entity one way, so a tenant that also maps `endpoint.isolate` or `endpoint.lift_isolation` on v1 must leave them out with `--ref`; the compiler names the two mappings that cannot share a bundle, at `mappings.<n>`, and validation and activation refuse such a bundle as `INVALID_COMPONENT` without a location. `--signal-mappings` is carried into the bundle, never compiled, and a file the model refuses is reported at its field locations. `bundle-create`, `bundle-validate` and `bundle-activate` follow as for any bundle, and later rule edits carry `signal_mappings` into the new draft.

Validation and activation check the mappings against the registrations, at field locations that count the stored, sorted order. They refuse a bundle that maps `endpoint-isolation.v2` with no entry for its fact (`signal_mappings`); an entry for a contract version none of the bundle's mappings uses (`signal_mappings.<n>`) or for a capability the contract does not store (`signal_mappings.<n>.capability`); a source that is unknown, inactive or revoked, not registered for the capability or its subject kind, `agent_forwarded`, or unusable by the bundle's own space, by every space when the bundle is offered, or by the space activating it (`signal_mappings.<n>.admitted_sources.<m>`); and a row reading `clean` while any admitted source does not attest liveness (`signal_mappings.<n>.thresholds.<m>`). Each is `INVALID_COMPONENT`. Admission does not repeat these checks: a source revoked after activation fails its facts at the next decision instead of taking the bundle down.

## What a producer sends

`POST /v1/signals` with exactly one `Authorization: Bearer sg1.…` header, exactly one `Content-Type` of `application/json` or `application/json; charset=utf-8`, no `Content-Encoding`, no query string and no `x-tenant-id`, `x-principal-id` or `x-role` header. The body is one `execbound.security-signal.v1` envelope of at most 8,192 bytes, which must arrive within 5 seconds. The JSON Schema is [`integrations/schemas/security-signal.v1.schema.json`](../integrations/schemas/security-signal.v1.schema.json).

```json
{
  "schema_version": "execbound.security-signal.v1",
  "source_event_id": "device-01:1727524800",
  "producer": {"name": "execbound-mde-producer", "version": "0.1.0"},
  "capability": "resource_compromise.v1",
  "verdict": "Medium",
  "confidence": 1000,
  "subject": {
    "kind": "resource",
    "account_id": "<connector account id>",
    "provider": "mock_crowdstrike",
    "resource_type": "endpoint",
    "provider_id": "device-01"
  },
  "observed_at": "2026-09-28T12:00:00+00:00"
}
```

- The wire carries no tenant, space or principal: the token names the tenant and the source, and the registration says the rest. Unknown fields are refused, and there is no field for a prompt, a tool result or a reasoning trace.
- `source_event_id` is the producer's own identifier, 1 to 128 characters of letters, digits and `._:-`. The first write wins per source and event id: a retry of the same content answers its first receipt, whatever the time now, and different content is refused.
- The subject is the host exactly as the registry holds it: the connector `account_id` and its `provider`, the `resource_type`, and the resource's `provider_id`. The account and provider must be one of the tenant's connector accounts; a record applies only to the resource those four name.
- `verdict` is the producer's own label, 1 to 64 characters of letters, digits, space and `_.:-`, with no space at either end. `confidence` is an integer from 0 to 1000.
- `observed_at`, and the optional `expires_at`, are RFC 3339 times with an offset or `Z` and at most six fractional digits; `expires_at` must be later than `observed_at` and can shorten the record's freshness, never lengthen it.
- The optional `action` limits the record to requests for that catalog action. The envelope also carries `request_reference`, but the intake refuses it as `INVALID_ENVELOPE` today: a request's `reference` is the agent's own string, so a record scoped by it could be claimed by any agent that names it. A request-scoped capability will need to bind the record to something the agent does not choose.
- `severity`, up to 16 `attributes` (a bounded text, a 64-bit integer or a boolean each) and the opaque `evidence_ref` and `evidence_digest` are stored and never read by a decision. Nothing fetches or links `evidence_ref`.
- The parser refuses a body that is not UTF-8 or opens with a byte order mark, a repeated key, a number with a fraction or an exponent, `NaN` or `Infinity`, a control or invisible character in free text, and a time that is not a real instant. The intake refuses secret-shaped text anywhere in the envelope without quoting it back.

At the intake, `observed_at` more than 60 seconds after receipt is `FUTURE_OBSERVATION`, and 3,600 seconds or more before it is `STALE_ON_ARRIVAL`. A source may send 600 envelopes a minute, counting every envelope its token authenticates, a retry or a refused one included, and hold 500,000 records; nothing prunes them yet ([threat model](THREAT_MODEL.md#residual-risks) R32).

A producer must report every covered host inside the freshness window, 300 seconds by default: a host with no fresh record fails closed. Keep producers on NTP. A record stamped later than the gateway's own clock refuses every decision about its host until the gateway's clock passes it, and resolution never falls back to the older record it replaced; the intake accepts up to 60 seconds of such skew. A producer whose clock runs behind loses that much freshness.

| Status | Answer |
| --- | --- |
| 202 | Accepted and stored: `source_event_id`, `received_at` on the gateway's clock, `duplicate: false` and `source_id` |
| 200 | A retry of an accepted envelope, answered with its first `received_at` and `duplicate: true` |
| 400 | A request outside the bounds above, with no code; or `INVALID_ENVELOPE`, `FUTURE_OBSERVATION`, `STALE_ON_ARRIVAL` or `INVALID_SIGNAL` |
| 401 | No bearer credential, or more than one; or `INVALID_SOURCE`, whatever the credential's problem |
| 403 | `CAPABILITY_REFUSED`, `SUBJECT_REFUSED`, `INCOMPATIBLE_PRODUCER` or `INVALID_SUBJECT` |
| 409 | `CONFLICTING_DUPLICATE`: the same event id with other content; the first is kept |
| 429 | Eight envelopes are already being read, answered at once with no code; or `SOURCE_RATE_LIMIT` or `SOURCE_CAPACITY` |
| 503 | `SIGNAL_UNAVAILABLE`: the database could not be reached, or the gateway's clock is more than 300 seconds from the database's |

A refusal with a code answers `{"detail": "Signal refused", "code": "<code>"}`; one refused before the envelope is parsed carries no code. Every request logs `request.completed` with the surface `signal` and the status. An accepted envelope also logs `signal.intake`, with the status and the source id. Only a refusal that carries a code logs `signal.refused`, with the code and, once the writer has found the source the token names, its source id. An uncoded refusal logs `request.completed` alone, except a 401 for an `Authorization` header that was sent but is not exactly one bearer credential, which also logs `authentication.refused`. Every credential refusal, that one and `INVALID_SOURCE`, logs `authentication.refused` with the surface `signal` and its reason, which is where the reason appears. None of them ever carries the token or the envelope.

## How a decision reads it

When a request is resolved, the same statement that reads the target, its inventory and its incident reads, for each source the bundle admits, that source's newest record about the resolved resource: the same account, provider, resource type and provider id and the mapped capability, observed within the 3,600-second ceiling, from a source whose principal scope holds the agent and which the agent's space owns or is offered. A record naming an action applies only to that action. A record naming a request reference is never read, even by a request that names that reference, because the agent chooses its own reference; the intake refuses one, so only a record written beneath it could carry one. Newest means the latest observation, then the later receipt, then the event id in byte order, so an older observation arriving late never replaces a newer one. A record from another space, another agent's scope or another resource is never read.

The fact is then built, or the request refused as `INVALID_CONTEXT` before any plan exists (audited, and the agent answered `EXECUTION_UNAVAILABLE`): every admitted source must have such a record, from a source still active, unrevoked and independent, observed and received no later than the decision; each verdict must map; the most restrictive value is taken; `clean` needs every source to attest liveness; and the fact must still be valid. Its observation is the earliest record's, and its validity ends at the earliest of each record's observation plus the effective max age and its producer's `expires_at`.

The plan freezes the fact (its value, the determining source, that source's registration version, the host's provider id and the writer label `signal_mappings`) and the records it rested on, one per admitted source: the source id, its registration version, whether the source attests liveness, the event id and record digest, the producer's name and version, the verdict, the confidence, the observation, the receipt and, when sent, the producer's expiry. Evaluation re-applies the evaluated bundle's own mapping to those frozen records and denies, as `INVALID_CONTEXT`, a plan they do not reproduce. Resolution's reading is never trusted on its own.

Re-attestation reads the records again when a person decides, when the agent retries and inside the transaction that commits dispatch. The records and times are outside the binding a pending approval rests on, so a producer re-reporting the same verdict, or a verdict the mapping reads alike, keeps the approval. A changed value or determining source, a revoked source or a record gone stale makes it `STALE_AUTHORIZATION`, and an approval never outlives the fact's validity. After dispatch nothing a producer sends changes the execution, its answer to a retry, its impact or its claim: settlement never reads a signal (`tests/test_signal_execution.py::test_a_record_after_dispatch_changes_nothing`).

## What people see

- **An approver**, on the console's approval detail, sees the fact's value, the producer's label and the capability. Never the records or the envelope's attributes.
- **An administrator**, on an execution's detail in Activity, also sees the frozen records, every field listed above. Anyone else who can open that execution sees the label and the capability without the records.
- **An administrator**, on a draft's rules page, reads a rule on a signal fact like any other, with its condition and its sentence, and the add-a-rule form offers the fact with every value the capability declares, not only the ones a source's verdict table maps to, because a rule is written about the fact and not about one producer's verdict table (`tests/test_console_api_rules_signal.py`).
- **The classic approval page** lists a signal fact as kind `signal` with the producer's label and the capability, and below them the host's provider id and the registration version. Never the records or the envelope's attributes.

The producer's label is shown to a reader whose spaces own the source, and to every reader once the source is offered tenant-wide. Anyone else who can open the row sees the fact named by its kind instead, as Security signal on the console and as kind `signal` on the classic page, beside its value and capability (`tests/test_signal_views.py::test_a_label_of_another_spaces_source_is_withheld_from_a_reader_of_this_one`); an administrator still reads the frozen records, which carry the source's id and producer name and never its label. A plan names only sources its agent's space owns or is offered, so this happens only after a source changes space or loses its offer.

The records travel in the plan and in its decision capture (`execution.evaluated`), which replay reads. The envelope's severity, attributes, evidence reference and digest stay in `security_signals`: no plan, audit event, agent answer or view carries them.

## Replay

The frozen records reproduce every decision with the producer offline; nothing is read from `security_signals` and no detector re-runs, because today's detector is not historical evidence. A candidate bundle's mapping is re-applied to the frozen records, so a threshold change, or an entry admitting fewer of the frozen sources, can be previewed over history, and each reading replays as the live kernel would decide. A verdict the candidate's table does not map is a denial, `INVALID_CONTEXT`, as it would be live.

A candidate is `UNRESOLVED` with `SIGNAL_EVIDENCE_UNAVAILABLE` when it needs a record the plan never froze (it admits a source the plan did not read), or a liveness attestation the frozen records do not carry (it has a row reading `clean` over a source that does not attest liveness, which the store would never have activated). The candidate's budgets count earlier executions by its own reading, and an earlier unit it cannot read leaves a later decision under a rule selecting on the signal fact `UNRESOLVED`, counted only at a lower bound. Each fact keeps its frozen validity, so a candidate that shortens freshness replays as a certain `DENY` and cannot be previewed ([Replay](REPLAY.md), [threat model](THREAT_MODEL.md) R33).

## Failure codes

| Code | Where | Meaning |
| --- | --- | --- |
| `INVALID_ENVELOPE` | intake, 400 | The body is not a valid envelope, carries secret-shaped text, or carries a `request_reference`. Not recorded against any source |
| `INVALID_SOURCE` | intake, 401 | The token is malformed, unknown, wrong, revoked or expired, or the tenant is inactive. Counted on the `signal` authentication-failure surface, never against the source's health |
| `CAPABILITY_REFUSED`, `SUBJECT_REFUSED` | intake, 403 | A capability or subject kind outside the registration. No envelope reaches either today, because the schema and every registration admit one of each |
| `INCOMPATIBLE_PRODUCER` | intake, 403 | Another producer name, or a version outside the registered range |
| `INVALID_SUBJECT` | intake, 403 | The subject's account and provider are not one of the tenant's connector accounts |
| `FUTURE_OBSERVATION`, `STALE_ON_ARRIVAL` | intake, 400 | Observed more than 60 seconds ahead of receipt, or 3,600 seconds or more before it |
| `INVALID_SIGNAL` | intake, 400 | A value the stored record's own checks refuse |
| `CONFLICTING_DUPLICATE` | intake, 409 | The same event id with other content; counted as a conflict |
| `SOURCE_RATE_LIMIT`, `SOURCE_CAPACITY` | intake, 429 | Over 600 envelopes in the source's minute, counted as a rate refusal; or 500,000 records held |
| `SIGNAL_UNAVAILABLE` | intake, 503 | The database could not be reached or the clocks disagree |
| `INVALID_COMPONENT` | validation and activation | A `signal_mappings` entry the registrations, the bundle's space or the liveness rule (a `clean` row needs every admitted source to attest liveness) cannot support, at its field location |
| `INVALID_COMPONENT`, no location | validation and activation | A bundle whose mappings serve one action under two contract versions or describe one entity two ways; `ruleset-compile` names the pair at `mappings.<n>` |
| `INVALID_CONTEXT` | decision | The fact is missing, stale, unmapped, revoked or foreign; refused before a plan, or denied at evaluation |
| `STALE_AUTHORIZATION` | approval and dispatch | Since the plan was frozen, the value or its determining source changed, the record went stale or the source was revoked |
| `SIGNAL_EVIDENCE_UNAVAILABLE` | replay | A candidate needs a record, or a liveness attestation, the plan never froze |

Every intake refusal from `CAPABILITY_REFUSED` to `SOURCE_CAPACITY` is recorded as the source's last refusal, which `signal-source-list` shows.

## Evidence and limits

Acceptance group SG1 to SG17 in the [acceptance inventory](ACCEPTANCE_TESTS.md#security-signals-sg1-to-sg17) names the test behind each rule, and the [threat model](THREAT_MODEL.md#b13-security-signal-producer-to-gateway)'s boundary B13 (T13.1 to T13.18) and residual risks R30 to R33 say what each holds and what it does not. The producer-facing rows live in `tests/signal_conformance.py`, which every producer runs against its own envelopes. A Defender for Endpoint producer is in [integrations/mde-producer](../integrations/mde-producer/README.md). Its entry in `integrations/manifest.json` lists what its one lab trial established and what it did not: no sensor liveness, no `High` band, no real endpoint isolation, and a local gateway only.

A record authenticates its source, not its verdict: a mistaken or compromised detector, or a stolen token, is enforced as the mapping reads it until the source is revoked (T13.18, R30), and a source's input path and liveness attestation are taken on the registering owner's word (R31).

Not built yet: a Connections page and a registration form in the console; `endpoint-recovery.v2`, so one bundle cannot yet map `endpoint.isolate` on v2 beside `endpoint.lift_isolation`; principal- and run-subject capabilities, and with them a signal rule condition and agent attributes; advisory mode; combination rules other than most restrictive; Monitor surfacing of records; and pruning of old records.
