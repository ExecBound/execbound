# Executor protocol, version 1

The wire objects ExecBound exchanges with an executor. For an executor it dispatches to (chapter 1 of the specification): the command it sends, and the signed terminal record the executor returns for that command. For an executor that keeps its own vendor credential and asks first (chapter 2): the report it sends after acting, and the signed statement that report can carry. They are published here as JSON Schemas generated from the models in the [`execbound-protocol`](../../README.md) package, with ExecBound's golden contracts as conformance vectors for chapter 1 and checkpoint report vectors for chapter 2, so an executor can be built and checked without reading the server. The protected mock providers in the `execbound-connectors` package are the reference implementations of chapter 1.

[The executor protocol](../../../docs/protocol/EXECUTOR_PROTOCOL.md) is the normative specification: the routes an executor serves, the transaction it runs, the report it sends, every field of these objects and how ExecBound verifies what it receives. [The provider guide](../../../docs/PROVIDER.md) is chapter 1 as narrative, and [the external execution checkpoint](../../../docs/CHECKPOINT.md) is chapter 2.

## Conformance

The `execbound_protocol.conformance` module, in the package these schemas are generated from, checks an executor against the vectors here: it sends each vector's command and the commands derived from it, and checks every answer as ExecBound's connector reads it. Load a vector file with `load_vectors`, describe the executor with `Executor` (its origin through `http_send`, an account's two credentials, and a function that puts the vector's target at its expected version), and run `check` for each vector. The specification's conformance section lists each check and what the module leaves out. Both protected mocks pass it in ExecBound's own tests.

The `execbound_protocol.checkpoint_conformance` module checks the reports an executor of chapter 2 writes. Load `vectors/checkpoint-report-v1.json` with its `load_vectors`; for each vector, hand your executor the vector's grant and scenario, capture the report body it would send, and run `check` with the vector, that body and your executor's key ring. A ring names each key's scheme and a function that verifies a signature under it (`RingKey`), because the protocol package holds no cryptographic library: build it from the vector file's public test keys or, when your executor signs with keys of its own, from their public halves, with any library that verifies Ed25519 and ES256. `settlement` is section 2.8 of the specification as a pure function, and `refused` reads a refusal vector and finds its fault at the check it names. The specification's section 2.10 lists each check, the refusal code each corresponds to, and what the module leaves out. In ExecBound's own tests, the outcome route settles the report the vectors' executor writes for each vector, for a fresh grant the gateway issued and signed with keys of the test's own, as the vector says, and refuses each refusal, written the same way, with its code. The keys must be the test's own, because ExecBound refuses the published ones, as below.

## Licence

Apache-2.0, under [`protocol/LICENSE`](../../LICENSE), like the package the schemas are generated from. The ExecBound server, which enforces the protocol, is AGPL-3.0-only.

## What is here

| File | What it is | Source |
|---|---|---|
| `command.schema.json` | The command ExecBound sends to an executor for one operation | `ProviderCommand` in `execbound_protocol.provider` |
| `journal.schema.json` | The terminal record an executor writes for exactly one command | `JournalRecord` |
| `signed-journal.schema.json` | That record with the key id and the signature the executor returns | `SignedJournal` |
| `checkpoint-report.schema.json` | The report an executor holding its own vendor credential sends after acting on a grant | `OutcomeReport` in `execbound_protocol.report` |
| `executor-record.schema.json` | The statement a signed report makes: the four values the grant binds, the outcome, the reason and the executor's time | `ExecutorRecord` in `execbound_protocol.executor` |
| `signed-outcome.schema.json` | That statement signed with Ed25519, as a report's `record` carries it | `SignedOutcome` |
| `jws-header.schema.json` | The protected header of the ES256 compact JWS a report's `attestation` carries | `JwsHeader` |
| `jws-claims.schema.json` | That JWS's payload: the same statement under the same domain separator | `JwsClaims` |
| `vectors/endpoint-contract-v1.json` | A frozen `endpoint.isolate` dispatch, the command it became, the signed journal a provider returned for it and the public test key that verifies it | [`tests/fixtures/endpoint-contract-v1.json`](../../../tests/fixtures/endpoint-contract-v1.json), byte for byte |
| `vectors/endpoint-recovery-contract-v1.json` | The same for `endpoint.lift_isolation`, whose record carries the containment it lifted | [`tests/fixtures/endpoint-recovery-contract-v1.json`](../../../tests/fixtures/endpoint-recovery-contract-v1.json), byte for byte |
| `vectors/identity-contract-v1.json` | The same for `identity.disable`, `identity.enable` and `identity.revoke_sessions` | [`tests/fixtures/identity-contract-v1.json`](../../../tests/fixtures/identity-contract-v1.json), byte for byte |
| `vectors/identity-credential-contract-v1.json` | The same for `identity.reset_password`, whose record carries the credential's generation and forced change but never a password | [`tests/fixtures/identity-credential-contract-v1.json`](../../../tests/fixtures/identity-credential-contract-v1.json), byte for byte |
| `vectors/checkpoint-report-v1.json` | Chapter 2: for every row of the settlement table, a grant, what happened at the vendor, the report the vectors' executor sent and what it settles; reports the outcome route refuses, with their codes; and the test keys they are signed with | Written by [`tests/checkpoint_vectors.py`](../../../tests/checkpoint_vectors.py) |

The schemas are JSON Schema draft 2020-12, as Pydantic writes it. The vectors are synthetic: every identifier is made up, and `test_verification_key_hex` is public test key material that authenticates nothing anywhere. ExecBound refuses it as a journal key: a deployment that configures it for a connector or a Gate account does not load. Together they cover every action the catalog binds to the two providers ExecBound dispatches to over this protocol, and the vectors of one provider name one tenant, one account, one key and one target, so a single account configured on an executor serves all of them. ExecBound's compatibility tests settle every contract unchanged against the current server, so the vectors are what version 1 means in bytes.

The checkpoint report vectors are synthetic in the same way. Their keys, `executor_keys` and `journal_keys`, are public test material, private halves included, so that an executor under test can sign as the vectors' executor did, and ExecBound refuses every one of them. Registering either executor key, in any spelling, is refused as `INVALID_KEY`; a ring that already holds one, registered before that refusal, verifies nothing under it, so a report it signed is `INVALID_RECORD` and settles nothing; and a deployment that configures the journal key does not load. Sign the reports an executor sends a workspace with a key of its own. Each vector is for its own grant of `endpoint.isolate`, all on one account and one target. Most grants are under `ENFORCED_BY_PROVIDER`, so they carry the `provider_command` a provider's journal binds; four are under `UNAVAILABLE` and `ASSERTED_BY_EXECUTOR`, and the two under `UNAVAILABLE` carry no version and no command, as ExecBound answers one. Every grant was issued at an instant with microseconds, so a statement signed in the grant's own second can be dated before that instant. The refusals share one grant, and each names its `code` and the module's `check` that finds its fault; a refusal whose fault needs another kind of grant, a journal under `UNAVAILABLE`, carries its own beside its report, under the same `execution_id`, `granted_at` and `grant` a vector names its grant with, and `load_vectors` reads a file in which no refusal does so as it always did. A report is written as the JSON object it is, except that an attestation is written as its three segments, `{"protected", "payload", "signature"}`, which the loader joins with dots into the compact token the report carries, and a body the route refuses before it parses it is written as `report_text`. The reports are canonical JSON, and the ES256 signatures are deterministic (RFC 6979), so the file regenerates byte for byte, and `tests/test_executor_protocol_v1.py` holds the committed file byte for byte to what `tests/checkpoint_vectors.py` writes. ExecBound's outcome route settles the report the vectors' executor writes for each vector, for a fresh grant the gateway issued and with keys of the test's own, as the vector says, so these vectors are what the settlement table means in bytes.

## Versions

`version: 1` on every object is the protocol's major version. This directory is version 1 as `execbound-protocol` 0.1.0 defines it, and ExecBound 0.1.0 serves it.

- **An additive change keeps the major.** A new optional field, or a new reason value an old executor may ignore, is version 1 still: the schemas here are regenerated in place, and the change is recorded with the ExecBound release that introduced it.
- **A change an old executor cannot ignore is a new major.** The object becomes version 2, its schemas go in a new directory beside this one, and this directory stays as it is. ExecBound refuses an object whose version it does not serve, as the models already do.

## What the schemas cannot say

The models check more than a schema can express. An executor must also meet these rules, which the parser and the verifier enforce:

- **The bytes.** A message is UTF-8 JSON of at most 32,768 bytes. A repeated key, a number with a fraction or an exponent, and `NaN` or `Infinity` are refused.
- **The binding.** A command's `provider_operation` is the [action catalog](../../../docs/ACTION_CATALOG.md)'s binding for its `provider` and `action`, and the action's catalog entry admits its `arguments`.
- **The command hash.** A record's `command_hash` is the SHA-256, in lowercase hex, of the canonical JSON of its `command`: sorted keys, no whitespace, UTF-8 rather than escapes, integers only, and every field written, defaults included. The protocol package's `canonical_json` is that serialization.
- **The outcome.** `EXECUTED` records exactly one mutation and a `resulting_version` other than the command's `expected_version`. Every other outcome records none. `VERSION_MISMATCH` carries the version the executor found, which differs from the expected one, and `CANCELLED_NOT_EXECUTED` and `TARGET_NOT_FOUND` carry no version.
- **The transitions.** Which transition an `EXECUTED` record carries depends on the provider and the action, and each one's `before` and `after` must be the change that action makes.
- **The signature.** `signature` is HMAC-SHA256, in lowercase hex, under the account's evidence key that `key_id` names, over the canonical JSON of the version, the key id and the record as the model serializes it, which leaves an absent transition out rather than writing `null`. The protocol package's `signature` function builds that message. It authenticates evidence between ExecBound and an executor it trusts; it is not public nonrepudiation.

The checkpoint report has rules of its own that its schema cannot say:

- **The bytes.** A report is UTF-8 JSON of at most 16,384 bytes, sent as `application/json` with no parameter, with the same refusals as above.
- **One piece of evidence.** A report carries exactly one of `reported_at`, `record`, `attestation` and `journal`. An `UNKNOWN` outcome carries no reason and only `reported_at`.
- **The pairing.** Each reason names the one outcome it may accompany, and a report with signed evidence carries only a reason signed evidence can state, never `REPORTED_FAILURE`. The specification's chapter 2 has the table.
- **The evidence inside.** The schema leaves `record` and `journal` as objects because the report's parser does: a `record` is a signed outcome (`signed-outcome.schema.json`), a `journal` is a signed journal (`signed-journal.schema.json`) for exactly the grant's `provider_command`, and an `attestation` is a compact JWS of at most 4,096 characters whose header and payload decode to `jws-header.schema.json` and `jws-claims.schema.json`. The verifier, which is the server's, checks a signed outcome or an attestation under a key the tenant registered and a journal under a key the operator configured for the account, never one the executor holds, and checks what each binds against the grant.
- **The executor's signatures.** A signed outcome's `signature` is Ed25519, in lowercase hex, over the canonical JSON of `{"domain": "execbound.executor.outcome", "version", "key_id", "record"}`; the protocol package's `sign_outcome` builds and signs it. An attestation is ES256 over its first two segments as RFC 7515 defines it.

## Not published yet

- Registration and a pull transport, through which an executor behind a firewall would fetch its commands rather than serve a route. They are designed, not specified and not served.

## Regenerating

Never edit these files by hand. After a deliberate change to one of the models, rewrite the directory from a checkout of the repository and commit what changed:

```sh
uv run python tests/test_executor_protocol_v1.py
```

`tests/test_executor_protocol_v1.py` fails while a schema here differs from its model, a chapter 1 vector differs from its frozen fixture, the checkpoint report vectors differ from what `tests/checkpoint_vectors.py` writes, or the directory holds a file it does not write. It also checks that every vector meets the schemas, the checkpoint report vectors' reports and their evidence included, and that a report in each of its shapes meets the report's. `tests/test_outcome_report_protocol.py` holds the server to the same report model: the route parses every report through it.
