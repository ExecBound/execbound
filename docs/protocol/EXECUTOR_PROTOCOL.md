# The executor protocol

This is the normative specification of how ExecBound and an executor exchange a consequential action. An executor is a service that performs one action on one target at a vendor, under a decision ExecBound made. It meets ExecBound in one of two ways, and each has a chapter:

1. **The executor protocol.** ExecBound dispatches: it sends the executor a frozen command over HTTPS, and the executor runs it in one transaction and answers with a signed record of what happened.
2. **The checkpoint report.** The executor keeps its own vendor credential and asks ExecBound first: it receives a grant for one act, acts, and reports what happened.

A third, registration and the pull transport, is not specified yet.

| Part | Version | Served by |
| --- | --- | --- |
| The executor protocol | 1 | Unreleased; served by the main branch |
| The checkpoint report | 1 | Unreleased; served by the main branch |
| Registration and the pull transport | none | Not yet specified |

No ExecBound release has been published yet. The main branch serves both version 1 parts, as ExecBound 0.1.0 and `execbound-protocol` 0.1.0.

## Conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals, as shown here.

This document is written from the code that enforces it. The models in the Apache-2.0 [`execbound-protocol`](../../protocol/README.md) package parse every object named here, and the gateway parses with them, so where a model checks more than a sentence here states, the model decides. A requirement here that no code can check, because it concerns what an executor does at its own vendor, is marked **cooperative**: ExecBound depends on it and cannot detect its breach.

The JSON Schemas generated from those models, and the conformance vectors, are published in [`protocol/executor/v1/`](../../protocol/executor/v1/README.md). The two protected mock providers in the `execbound-connectors` package, the endpoint mock and the identity mock, are the reference implementations of chapter 1, as configured accounts with no sample key: the endpoint mock's [sample-account mode](../PROVIDER.md#sample-accounts), which creates a sample account's target the first time a dispatch names it, is a demonstration extension outside version 1. [Providers and the credential boundary](../PROVIDER.md) and [the external execution checkpoint](../CHECKPOINT.md) describe the same behaviour as narrative, with the reasons behind it.

**Canonical JSON** is the serialization every hash and signature in this document is over: keys sorted, no whitespace, UTF-8 rather than escapes, and no number other than an integer. The package's `canonical_json` function is that serialization. A **digest** is a SHA-256 hash in lowercase hexadecimal, 64 characters.

## 1. The executor protocol, version 1

### 1.1 Roles and trust

ExecBound's gateway decides an action, freezes the command it authorizes and dispatches it. The executor holds the vendor credential, or is the vendor, and performs the command. Neither the protected agent that asked for the action nor any caller input can reach the executor: the command is built only from fields the gateway committed when it froze the plan, and the executor's origin, credentials and keys come from the gateway's private configuration.

ExecBound dispatches over this protocol to the providers its connection configuration admits, which today are `mock_crowdstrike` and `mock_entra`. The action catalog binds other providers too; ExecBound reaches those through a connector of its own rather than over this protocol.

### 1.2 Accounts, credentials and keys

An executor serves one or more **accounts**. Each account belongs to one tenant and has:

- a **dispatch credential**, a bearer token of 16 to 256 visible ASCII characters;
- a **control credential**, a different bearer token of the same form;
- an **evidence key** of at least 32 bytes, named by a **key id** of 1 to 64 characters from `a-z`, `A-Z`, `0-9`, `_`, `.` and `-`.

The gateway holds both tokens and a ring of evidence keys by key id. The executor holds the evidence key it signs with and SHOULD hold only the SHA-256 digest of each token, comparing a presented token's digest in constant time. An executor MUST NOT accept one token as both credentials of an account, or as a credential of two accounts.

An evidence key authenticates evidence between ExecBound and an executor it trusts. It is a shared secret: it is not public nonrepudiation, and anyone holding the gateway's ring could sign a record. A record verifies only while the key it was signed under is in the gateway's ring, so an operator rotating an account's key keeps the old one there for as long as a record signed under it may still need to settle.

### 1.3 Routes

An executor MUST serve these routes, each by `POST` only. It MUST NOT serve, to either credential, a route that provisions or resets a target, injects a failure or changes the journal: every guarantee in this chapter rests on the target and the journal changing only through the transaction of section 1.6.

| Route | Method | Credential | What it answers |
| --- | --- | --- | --- |
| `/v1/{provider_operation}` | POST | The account's dispatch credential only | Runs the transaction of section 1.6 and answers its signed journal |
| `/v1/journal` | POST | The account's dispatch or control credential | The retained signed journal for the command's operation, or 404 when the journal holds none |
| `/v1/cancel` | POST | The account's control credential only | The retained signed journal for the operation, or a new cancellation tombstone |

An executor serves one dispatch route for each catalog binding of the provider it serves. The reference implementations refuse to start when the catalog binds an action they cannot execute, rather than serve a route that cannot run. The dispatch routes the catalog binds today:

| Provider | Action | Dispatch route |
| --- | --- | --- |
| `mock_crowdstrike` | `endpoint.isolate` | `/v1/contain` |
| `mock_crowdstrike` | `endpoint.lift_isolation` | `/v1/lift_containment` |
| `mock_entra` | `identity.disable` | `/v1/disable` |
| `mock_entra` | `identity.enable` | `/v1/enable` |
| `mock_entra` | `identity.reset_password` | `/v1/reset_password` |
| `mock_entra` | `identity.revoke_sessions` | `/v1/revoke_sessions` |

### 1.4 The request

Every request carries exactly one `Authorization: Bearer <token>` header, and its body is one command (section 1.5).

An executor:

- MUST authenticate the credential before it acts on anything the body says, and refuse a request with no `Authorization` header, a malformed one, a token no account holds, or a token of the wrong role for the route.
- MUST take the tenant and the account from the credential, and refuse a command whose `tenant_id`, `account_id` or `provider` is not the credential's account's.
- MUST refuse a request with more than one `Authorization` header, any query string, or any `x-tenant-id`, `x-account-id`, `x-principal-id` or `x-role` header. Scope comes from the credential and from nothing a request can add.
- MUST refuse a body over 32,768 bytes, a body that is not UTF-8 JSON, a repeated key, a number with a fraction or an exponent, `NaN` or `Infinity`, and any field section 1.5 does not name.
- MUST refuse, on a dispatch route, a command whose `provider_operation` is not that route's.

The gateway sends `Content-Type: application/json`, `Accept: application/json` and `Accept-Encoding: identity`, makes one attempt per command, follows no redirect, uses no proxy from its environment and gives up after its configured timeout, at most 30 seconds. It reaches an executor over HTTPS with certificate verification, or over cleartext HTTP only at a literal loopback address.

### 1.5 The command

The gateway derives the command only from the fields it committed when it froze the plan, and never from a caller's claims, retry keys or addresses. A command is a JSON object with these fields and no others, and the gateway always writes every one:

| Command field | Type | Meaning |
| --- | --- | --- |
| `version` | the integer `1` | The protocol's major version. `true`, `"1"` and `1.0` are refused |
| `tenant_id` | UUID | The tenant; equal to the credential's account's |
| `account_id` | UUID | The account; equal to the credential's account |
| `canonical_target_id` | UUID | ExecBound's identity for the target, shared by every account in the tenant |
| `provider` | name | The provider binding's provider, such as `mock_crowdstrike` |
| `action` | action name | The catalog action, such as `endpoint.isolate` |
| `provider_operation` | name | The operation the catalog binds `action` to for `provider`; it names the dispatch route |
| `arguments` | object | The action's arguments, normalized as the catalog defines them: at most 16 named values, each a string of 1 to 254 characters, a signed 64-bit integer or a boolean |
| `resource_provider_id` | string, 1 to 128 characters | The target as the vendor names it |
| `expected_version` | string, 1 to 80 characters | The version of the target the decision was made against |
| `operation_id` | UUID | The durable operation; the journal's key |
| `execution_id` | UUID | The ExecBound execution the operation belongs to |
| `intent_hash` | digest | The frozen intent's hash |
| `plan_hash` | digest | The frozen plan's hash |

A name matches `^[a-z][a-z0-9_]{0,62}$` and an action name `^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$`. An executor MUST refuse a command whose `provider_operation` is not the [action catalog](../ACTION_CATALOG.md)'s binding for its `provider` and `action`, or whose `arguments` the action's catalog entry does not admit.

The **command hash** is the digest of the canonical JSON of the command with every field written, defaults included. It binds the whole command: echoing the intent and plan hashes alone cannot hide a changed target or expected version.

### 1.6 The transaction

A dispatch runs one transaction. An executor MUST, within one atomic unit of work that no other dispatch or cancellation of the same account's journal or the same target can interleave with:

1. **Check the journal.** Look up the operation by tenant, account and `operation_id`. If the journal holds a record and its command is exactly this command, answer that retained record, unchanged, and do nothing else. If it holds a record for a different command, refuse the request as a conflict and do nothing else.
2. **Find the target.** Resolve the account's `resource_provider_id` to the target, and check that it is the command's `canonical_target_id`. If there is none, the record is `TARGET_NOT_FOUND`.
3. **Check the version.** If the target's current version is not `expected_version`, the record is `VERSION_MISMATCH`, carrying the version found.
4. **Mutate at most once.** Otherwise apply exactly one mutation, conditional on the version still being `expected_version`, and move the target to a new version different from `expected_version`. The record is `EXECUTED`, with one mutation, the new version and the transition the action requires. An action whose state already holds still executes: it records one mutation and moves the version.
5. **Write the terminal record before commit.** Append the record to the journal in the same unit of work as the mutation, so a committed mutation always has its record and a record never describes a mutation that did not commit.

An executor MUST NOT answer a record until the unit of work that wrote it has committed; it signs the record after the commit. A failure anywhere before the commit MUST leave neither a mutation nor a record, and is answered as a refusal.

Every dispatch whose command is admitted ends in a retained record, including `TARGET_NOT_FOUND` and `VERSION_MISMATCH`, so the same operation cannot execute later, after the target appears or its version returns. The journal is append-only: an executor MUST NOT change or delete a retained record.

**Cancellation** (`/v1/cancel`) runs the same discipline. If the journal holds a record for the operation, it answers that record, whatever its outcome. Otherwise it appends a `CANCELLED_NOT_EXECUTED` tombstone with no mutation, and a later dispatch of that operation answers the tombstone without touching the target. Whichever of a dispatch and a cancellation commits first decides.

**Lookup** (`/v1/journal`) answers the retained record, or 404 when the journal holds none. It changes nothing. A changed command under a retained operation conflicts here as it does on dispatch.

A deployment may declare `ENFORCED_BY_PROVIDER` (section 2.5) for a binding whose executor performs this transaction, with the version check inside the same unit of work as the write. Both reference implementations do.

### 1.7 The journal record and the signed journal

The record states what the transaction did. It is a JSON object with these fields:

| Record field | Type | Meaning |
| --- | --- | --- |
| `version` | the integer `1` | The protocol's major version |
| `command` | command | The command exactly as received |
| `command_hash` | digest | The command hash of `command` |
| `outcome` | one of four values | What the transaction did, below |
| `occurred_at` | RFC 3339 time with an offset | When the executor wrote the record, by its clock |
| `resulting_version` | string of 1 to 80 characters, or `null` | The target's version after the transaction, below |
| `mutation_count` | `0` or `1` | How many mutations the transaction applied |
| `identity_transition` | object, when required | The identity's state before and after |
| `endpoint_transition` | object, when required | The endpoint's state before and after |
| `credential_transition` | object, when required | The credential's state before and after |

| Outcome | Mutations | `resulting_version` | Settles as |
| --- | --- | --- | --- |
| `EXECUTED` | 1 | The new version, different from `expected_version` | `EXECUTED`; the reserved impact is confirmed |
| `VERSION_MISMATCH` | 0 | The version found, different from `expected_version` | `STALE_AUTHORIZATION`; the reserved impact is released |
| `CANCELLED_NOT_EXECUTED` | 0 | `null` | `FAILED_NOT_EXECUTED`; the reserved impact is released |
| `TARGET_NOT_FOUND` | 0 | `null` | `FAILED_NOT_EXECUTED`; the reserved impact is released |

A transition field is present exactly when the outcome is `EXECUTED` and the row below requires it, and absent otherwise: it is left out, never written as `null`.

| Transition | Required on an `EXECUTED` record for | `before` and `after` | Rule |
| --- | --- | --- | --- |
| `identity_transition` | Every action of the `mock_entra` provider | `{account_enabled, session_generation}` | `identity.disable` sets `account_enabled` to false and `identity.enable` to true, and both keep `session_generation`; `identity.revoke_sessions` keeps `account_enabled` and adds one to `session_generation`; `identity.reset_password` keeps both |
| `credential_transition` | `identity.reset_password` | `{password_generation, must_change_password}` | `password_generation` goes up by one, and `after.must_change_password` is the command's `require_change_at_next_sign_in` argument |
| `endpoint_transition` | `endpoint.lift_isolation` | `{contained}` | `after.contained` is false |

`endpoint.isolate` carries no transition, so its records keep the endpoint contract's original bytes. `session_generation` and `password_generation` are integers from 0 to 9,223,372,036,854,775,807.

The executor answers the record inside a **signed journal**:

| Signed journal field | Type | Meaning |
| --- | --- | --- |
| `version` | the integer `1` | The protocol's major version |
| `key_id` | key id | The evidence key the signature is under |
| `record` | record | The record |
| `signature` | 64 lowercase hexadecimal characters | HMAC-SHA256 under that key |

The signature is HMAC-SHA256, under the account's evidence key, over the UTF-8 bytes of the canonical JSON of `{"version": 1, "key_id": <key_id>, "record": <record>}`, where the record is serialized with every field it carries and without an absent transition. The package's `signature` function computes it.

An executor MUST answer a signed journal with status 200, `Content-Type: application/json`, no content encoding other than `identity`, and a body of at most 32,768 bytes. The reference implementations also send `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` with every answer.

### 1.8 Refusals

A refusal is any answer other than 200 with a signed journal. An executor MUST NOT mutate the target, append a record or return a signed journal for a request it refuses.

ExecBound reads no refusal's status or body: every one is no evidence (section 1.9). The statuses are therefore a convention, and the reference implementations answer each refusal with these, always with the same body, `{"detail": "Provider request unavailable"}`, so that a refusal discloses nothing about the command, the retained record or the store:

| Refused | Reference answer |
| --- | --- |
| A missing, malformed or unknown credential | 401 |
| A credential of the wrong role for the route | 401 |
| A repeated `Authorization` header, a query string, or an `x-tenant-id`, `x-account-id`, `x-principal-id` or `x-role` header | 400 |
| A body over the bound, malformed JSON, a repeated key, a number that is not an integer, an unknown field, an unserved version, an action the catalog does not bind to the operation, or arguments the action does not admit | 400 |
| A command whose `provider_operation` is not the route's | 400 |
| A command naming another tenant, account or provider than the credential's | 403 |
| `/v1/journal` for an operation the journal does not hold | 404 |
| A command that differs from the retained command under the same `operation_id` | 409 |
| Anything the executor cannot complete, its own store failing included | 503 |

A 401 also carries `WWW-Authenticate: Bearer`. A 404 from `/v1/journal` is the one refusal ExecBound reads by its status: it means the journal holds no record, which proves nothing about the target.

### 1.9 What ExecBound does with the answer

This section is informative: it describes the gateway, not the executor.

Before it sends anything, the gateway consumes the execution's one send attempt. It then verifies the answer with the same checks as the package's `check_journal`: strict parsing, a key id in the account's ring, the signature, the account, tenant and provider, and the complete command equal to the one it sent. A record that passes settles the execution as the outcome table in section 1.7 says, and is retained with its digest.

Anything else leaves the execution uncertain: a refusal, a timeout, a lost connection, an answer that does not verify, or one whose record binds another command. Its impact stays reserved and its target stays claimed, and nothing sends the command again. An administrator settles an uncertain execution with a fresh authority check and an audited reason, by asking `/v1/journal` or, when that shows nothing, by cancelling, which then answers the outcome or a tombstone. A missing record never releases anything.

### 1.10 Conformance

The `execbound_protocol.conformance` module is how an executor shows that it keeps this chapter. It sends each published vector's command to the executor, with the commands derived from it, and checks every answer as the gateway reads it. Both reference implementations pass it, and deliberately broken copies of them fail it at the check that names their fault (`tests/test_executor_protocol_conformance.py`).

The module needs the executor's origin or a function that posts a request, the dispatch and control credentials of an account for the vectors' tenant and account, a function that puts the vector's target at its expected version in the state its transitions start from, and a journal that has never seen the vectors' operations. The account signs with the vectors' public test key unless the caller names another ring; that key is for conformance alone, and ExecBound refuses it as any deployment's journal key (section 2.10). Given a function that counts the mutations the executor applied to the target, every check also asserts the count; without one, only what the wire shows is checked.

| Check | What it asserts |
| --- | --- |
| `unknown-lookup` | `/v1/journal` answers 404 for an operation the journal has never seen |
| `dispatch` | The vector's command is answered 200 with a signed journal that verifies under the ring and binds the command, and whose record equals the vector's in every field except `occurred_at` and `resulting_version`, which the executor chooses |
| `repeat` | The same command again is answered the retained signed journal, unchanged, with no second mutation |
| `lookup` | `/v1/journal` answers the same signed journal to the dispatch credential and to the control credential |
| `conflict` | A command that differs under the same `operation_id`, at the version the target is now at, is refused, and the retained record is unchanged |
| `version-mismatch` | A new operation at the vector's expected version records `VERSION_MISMATCH` with no mutation, carrying the version the first dispatch produced |
| `target-not-found` | A new operation naming a target the executor does not hold records `TARGET_NOT_FOUND` with no mutation, and keeps that record for its operation |
| `cancel` | A cancellation before dispatch records `CANCELLED_NOT_EXECUTED`, a later dispatch of that operation is answered the tombstone without acting, and cancelling the executed operation answers its record |
| `credentials` | A dispatch with the control credential and a cancellation with the dispatch credential are refused, and neither leaves a record |
| `follow-up` | A new operation at the version the first dispatch produced executes, so nothing after that dispatch moved the target |

The module does not check the refusals that need a request it cannot shape (a repeated header, a query string, an identity header, an oversized or malformed body) or any binding no vector covers, and it does not check chapter 2, which section 2.10's module does. The vectors cover every binding of section 1.3: `endpoint.isolate`, `endpoint.lift_isolation`, `identity.disable`, `identity.enable`, `identity.reset_password` and `identity.revoke_sessions`. The reference implementations' own tests check the rest of section 1.4 and section 1.8.

## 2. The checkpoint report, version 1

### 2.1 The exchange

Here the executor holds its own vendor credential and ExecBound sends nothing to the vendor. ExecBound decides, reserves the impact and claims the target exactly as it does for an action it dispatches, then stops before any connector and describes the one act the executor may perform. The operation is externally executed because the policy bundle's mapping for it says so; no request field, header or credential can move an operation into or out of this placement.

1. The executor sends the action request an agent would, `POST /v1/execute`, with its own agent credential.
2. ExecBound answers 202, state `DISPATCH_COMMITTED`, with a `checkpoint` object, `{"grant": …, "act": …}`. A denial is answered 200, state `DENIED`, with no `checkpoint`; a request that needs a person is answered 202, state `PENDING_APPROVAL`, with no `checkpoint`, and the same request sent again after the decision is answered the grant. In a tenant that is only observing, the answer is `OBSERVED` and grants nothing.
3. The executor acts once at its vendor, inside the act window, as the grant's precondition class requires.
4. The executor reports with `POST /v1/executions/{execution_id}/outcome`, inside the report window, using the same agent credential and the grant's report secret.

**This is cooperative.** ExecBound enforces the decision, the budget, the target claim, the approval and the audit. It cannot stop an executor that never asks, ignores a denial, acts twice or reports falsely; [what is enforced and what is cooperative](../CHECKPOINT.md#what-is-enforced-and-what-is-cooperative) states each property and its limit.

### 2.2 The grant

`grant` is what ExecBound committed and retained for the execution:

| Grant field | Meaning |
| --- | --- |
| `operation_id` | The operation the grant names; the only execution it can settle |
| `provider` | The provider binding's provider, as the plan froze it |
| `provider_operation` | The provider operation the plan froze; with `provider`, the binding the precondition class is declared for |
| `resource_provider_id` | The target as the vendor names it |
| `action` | The catalog action |
| `arguments` | The action's normalized arguments |
| `precondition_class` | `ENFORCED_BY_PROVIDER`, `ASSERTED_BY_EXECUTOR` or `UNAVAILABLE` (section 2.5) |
| `expected_version` | The version the plan froze; present exactly when the class is not `UNAVAILABLE`, and `null` otherwise |
| `act_expires_at` | When the act window closes (section 2.4) |
| `report_expires_at` | When the report window closes (section 2.4) |
| `regranted` | False on the first answer, true on every later one |
| `report_secret` | The secret that settles the grant, 32 to 128 characters from `A-Z`, `a-z`, `0-9`, `_` and `-`; on the first answer only, and `null` on a re-grant |
| `binding` | `{operation_id, account_id, intent_hash, plan_hash}`: the four values a signed report binds. None of it is secret and none of it confers authority |
| `provider_command` | The command of section 1.5 ExecBound would have sent had it dispatched, with the same serialization and command hash; present exactly when `expected_version` is |

An executor MUST keep the report secret from the first answer: ExecBound keeps only its digest and never sends it again, and a lost secret leaves only the administrator's settlement (section 2.8). A retry of the same request while the grant is live answers the same grant with `regranted: true` and no secret, under the precondition class it was issued under, and reserves, claims and charges nothing again. One principal may hold at most eight unsettled grants; a ninth request is refused `TOO_MANY_GRANTS` and leaves nothing reserved.

An executor that speaks chapter 1 MAY accept `provider_command` verbatim. An executor for any other vendor reads the target, the action, the arguments and the version out of the grant.

### 2.3 The act token

`act` is a signed continuation token for this one answer, at the `execution.checkpoint_outcome` audience, binding the tenant, the principal, the credential, the execution, the operation, the plan hash and the act window's end. It is `null` when the deployment holds no continuation keys or the act window has already closed. Nothing in ExecBound verifies it today, and the report route does not accept it: a report is authenticated by the agent credential and the report secret, and by nothing else.

### 2.4 Two windows

| Window | Length | What it bounds |
| --- | --- | --- |
| Act | The shortest of 15 minutes from the grant, the frozen plan's validity and the credential's expiry | When the executor may act |
| Report | The shorter of 24 hours from the grant and the credential's expiry | When ExecBound accepts a report |

An executor MUST act at most once on a grant, and MUST NOT act after `act_expires_at` (**cooperative**). The report window is longer so that an executor whose vendor call is queued or retried can still report. A grant still unreported when its report window closes is moved to uncertainty: its impact stays charged and its target stays claimed until an administrator settles it. An executor SHOULD use an agent credential that outlives the report window, because the report route authenticates the credential before it reads the execution.

### 2.5 Precondition classes

How much a frozen expected version is worth depends on the vendor. Each provider binding has a class, declared by the deployment and keyed by provider and provider operation, and the grant carries the one in force when it was issued. A binding the deployment declares nothing for is `UNAVAILABLE`.

| Class | What the grant carries | What the executor does | What a report means |
| --- | --- | --- | --- |
| `ENFORCED_BY_PROVIDER` | `expected_version` | MUST use the vendor's conditional write with `expected_version`, and report `VERSION_MISMATCH` when the vendor refuses it (**cooperative**) | The mismatch reported is the vendor's own refusal; signed, it settles `STALE_AUTHORIZATION` and releases the impact and the claim |
| `ASSERTED_BY_EXECUTOR` | `expected_version` | MUST read the target's version and MUST NOT act when it differs, reporting `VERSION_MISMATCH` (**cooperative**) | An assertion about a race the executor says it observed, not proof |
| `CHECKED_BY_CONNECTOR` | Nothing: no grant is issued | Nothing: the class describes a read and comparison ExecBound's own connector makes on its own path, and a grant would vouch for a check nobody made | A deployment that declares it for a binding reached through a checkpoint has every grant for that binding refused |
| `UNAVAILABLE` | No `expected_version`, and no `provider_command` | Acts without a version | A concurrent change to the target cannot be detected; the class the grant carries is what records that the question had no answer. The outcome route takes no journal for it (section 2.6) |

Declaring a class is a statement about the vendor's API that ExecBound cannot verify. A deployment SHOULD declare a class only for a vendor whose behaviour it has checked, and SHOULD pair an `UNAVAILABLE` binding with an approval rule. A grant already issued keeps the class it was issued under: a retry that finds the binding declared otherwise, `CHECKED_BY_CONNECTOR` included, is answered the same grant under its own class and with no secret, because an issued grant cannot be recalled.

### 2.6 The report

```http
POST /v1/executions/{execution_id}/outcome
Authorization: Bearer <the agent credential that asked>
Content-Type: application/json
```

`Content-Type` is `application/json`, with no parameter. The body is strict JSON of at most 16,384 bytes with exactly these fields, and an unknown field is refused, so nothing can be added to a report as a second authenticator:

| Report field | Contract |
| --- | --- |
| `report_secret` | Required: the secret the first grant returned |
| `outcome` | `EXECUTED`, `FAILED_NOT_EXECUTED`, `FAILED_EFFECT_UNKNOWN` or `UNKNOWN` |
| `reason` | The reason, paired with `outcome` by the table below; absent for `UNKNOWN` |
| `reported_at` | The executor's own time, as an RFC 3339 time with an offset; present exactly when none of `record`, `attestation` and `journal` is |
| `record` | An Ed25519-signed outcome (section 2.7), and no other envelope: an ES256 statement goes in `attestation`, and in `record` it is refused, the flattened form a settlement stores it in included |
| `attestation` | An ES256 compact JWS of the same statement (section 2.7) |
| `journal` | The provider's signed journal of section 1.7 for exactly the grant's `provider_command`. A journal is refused under a grant that carries no `provider_command`, which is every grant under `UNAVAILABLE`, whatever command it binds |

A report carries exactly one of `reported_at`, `record`, `attestation` and `journal`. An `UNKNOWN` report carries no reason and no signed evidence, only `reported_at`, because nothing signed can state an unknown result. Each reason names the one outcome it may accompany:

| Reason | Outcome | Signed evidence may carry it |
| --- | --- | --- |
| `EXECUTED` | `EXECUTED` | yes |
| `VERSION_MISMATCH` | `FAILED_NOT_EXECUTED` | yes |
| `CANCELLED_NOT_EXECUTED` | `FAILED_NOT_EXECUTED` | yes |
| `TARGET_NOT_FOUND` | `FAILED_NOT_EXECUTED` | yes |
| `REPORTED_FAILURE` | `FAILED_EFFECT_UNKNOWN` | no |

`FAILED_NOT_EXECUTED` states that the vendor did not act. `FAILED_EFFECT_UNKNOWN` with `REPORTED_FAILURE` states that the call failed and whether the vendor acted is not established. A signed `record`, `attestation` or `journal` states its own outcome, which MUST agree with the report's `outcome` and `reason`.

The report's JSON Schema is `checkpoint-report.schema.json` in [`protocol/executor/v1/`](../../protocol/executor/v1/README.md), generated from the `OutcomeReport` model in the package's `execbound_protocol.report` module, which is the model the route parses every report with. A schema cannot state the rule of one piece of evidence or the pairing of outcome and reason; the model refuses both, and that directory's README lists them with the other rules its schemas leave out.

### 2.7 Signed evidence

An executor that signs registers its public key with the tenant first, as an administrator's act ([Operations](../OPERATIONS.md#register-and-cut-off-executor-keys)). A key is Ed25519 or ES256; the scheme comes from the registered key and never from the evidence, and a key verifies only its own scheme. A key attests a grant only when it was registered at or before the grant and its revocation, if any, came after the grant; a key reported compromised attests nothing, whenever it was revoked. ExecBound never holds an executor's private key.

The statement both schemes sign is the **executor record**:

| Executor record field | Type | Meaning |
| --- | --- | --- |
| `version` | the integer `1` | The record's major version |
| `operation_id` | UUID | `grant.binding.operation_id` |
| `account_id` | UUID | `grant.binding.account_id` |
| `intent_hash` | digest | `grant.binding.intent_hash` |
| `plan_hash` | digest | `grant.binding.plan_hash` |
| `outcome` | `EXECUTED` or `FAILED_NOT_EXECUTED` | What happened |
| `reason` | A reason signed evidence may carry | Paired with `outcome` as section 2.6 says |
| `reported_at` | RFC 3339 time with an offset | The executor's time; not earlier than the second the grant was issued in |

The four bound values MUST equal the grant's `binding`, so a record settles exactly the operation it names and cannot be replayed onto another grant.

**Ed25519.** `record` is the signed outcome:

| Signed outcome field | Type | Meaning |
| --- | --- | --- |
| `version` | the integer `1` | The envelope's major version |
| `key_id` | key id | The registered key that signed |
| `record` | executor record | The statement |
| `signature` | 128 lowercase hexadecimal characters | The Ed25519 signature |

The signature is over the UTF-8 bytes of the canonical JSON of `{"domain": "execbound.executor.outcome", "version": 1, "key_id": <key_id>, "record": <record>}`. The domain separator keeps the message apart from the journal's of section 1.7, whose shape is otherwise alike. The package's `sign_outcome` function builds and signs it.

**ES256.** `attestation` is a compact JWS of at most 4,096 characters: three unpadded base64url segments in their canonical spelling, joined by dots. Its protected header has exactly these members:

| JWS header member | Meaning |
| --- | --- |
| `alg` | `ES256` |
| `kid` | The registered key's id |

Its payload has exactly these claims, the executor record's fields under the same domain separator:

| JWS claim | Meaning |
| --- | --- |
| `domain` | `execbound.executor.outcome` |
| `version` | The integer `1` |
| `operation_id` | As in the executor record |
| `account_id` | As in the executor record |
| `intent_hash` | As in the executor record |
| `plan_hash` | As in the executor record |
| `outcome` | As in the executor record |
| `reason` | As in the executor record |
| `reported_at` | As in the executor record |

The signature is ES256 over the protected and payload segments joined by a dot, as RFC 7515 defines it, 64 bytes. Any other header member or claim, `typ` and `iat` included, is refused.

**A provider's journal.** `journal` is the signed journal a chapter 1 provider returned for exactly `provider_command`. ExecBound verifies it under a journal key the operator configured for the grant's account, which the executor never holds, so an executor cannot produce this tier from anything of its own. Its record's `occurred_at` MUST NOT be earlier than the instant the grant was issued. It is compared with that exact instant, not with the second it falls in as a signed statement's `reported_at` is, because a provider stamps its journal to the microsecond where an executor signs whole seconds: a journal from before the grant describes some other attempt.

The four objects of this section are published beside the report's schema, generated from the package's `execbound_protocol.executor` module: `executor-record.schema.json` from `ExecutorRecord`, `signed-outcome.schema.json` from `SignedOutcome`, and `jws-header.schema.json` and `jws-claims.schema.json` from `JwsHeader` and `JwsClaims`. A journal meets `signed-journal.schema.json` of chapter 1.

### 2.8 What each report settles

| Report | State | Tier | Impact | Target claim |
| --- | --- | --- | --- | --- |
| Signed `EXECUTED` | `EXECUTED` | `ATTESTED` | Confirmed | Released |
| Signed `VERSION_MISMATCH` | `STALE_AUTHORIZATION` | `ATTESTED` | Released | Released |
| Signed `CANCELLED_NOT_EXECUTED` or `TARGET_NOT_FOUND` | `FAILED_NOT_EXECUTED` | `ATTESTED` | Released | Released |
| A provider's journal | As the journal's outcome, the same three rows | `PROVIDER_VERIFIED` | As the attested rows | Released |
| Unsigned `EXECUTED` | `EXECUTED` | `ASSERTED` | Confirmed | Held; a recovery run after the act window releases it |
| Unsigned `REPORTED_FAILURE` | `FAILED_EFFECT_UNKNOWN` | `ASSERTED` | Confirmed | Held; a recovery run after the act window releases it |
| Unsigned non-execution | `INDETERMINATE` | none | Charged | Held |
| `UNKNOWN` | `INDETERMINATE` | none | Charged | Held |

`ATTESTED` means the executor's statement is authenticated and non-repudiable; it does not prove the vendor acted. `PROVIDER_VERIFIED` rests on the provider's own signed journal, a party other than the executor. `ASSERTED` is the executor's authenticated word, which can confirm a charge and never refunds one or frees a target early.

The checkpoint report vectors of section 2.10 hold every row of this table in bytes, and ExecBound's outcome route settles the report the vectors' executor writes for each of them, for a fresh grant the gateway issued, as its row says.

A settled execution accepts only a restatement of its own tier, outcome and reason, answered with the same view and recording nothing new. An `INDETERMINATE` one is still reportable. An administrator can settle an unsettled grant from a record signed by a registered key, and can correct an unsigned `REPORTED_FAILURE` with a signed non-execution; [the checkpoint guide](../CHECKPOINT.md#what-a-settled-row-is-closed-to) has both.

### 2.9 Refusals

A report the route refuses settles nothing and leaves the grant as it was. The answer is `{"code", "detail"}`:

| Refusal | Code | Status |
| --- | --- | --- |
| A malformed body, an unknown field, an unpaired outcome and reason, or more than one piece of evidence | `INVALID_REQUEST` | 400 |
| Signed evidence that is not the envelope its field names (an attestation's stored form in `record` among them), that does not verify, or that contradicts the body it accompanies; a `journal` under a grant that carries no `provider_command` | `INVALID_RECORD` | 400 |
| A report secret that does not match | `INVALID_REPORT` | 403 |
| Another principal's or another tenant's execution | `NOT_FOUND` | 404 |
| An execution whose mapping is not externally executed, or a settled one sent anything but a restatement | `INVALID_STATE` | 409 |
| The report window has closed | `REPORT_WINDOW_CLOSED` | 409 |
| The tenant's executor key ring cannot be loaded | `INVALID_KEY_RING` | 409 |

After `INVALID_REPORT` or `INVALID_RECORD`, the same report sent correctly settles. After `REPORT_WINDOW_CLOSED`, only an administrator can.

### 2.10 Conformance

The `execbound_protocol.checkpoint_conformance` module is how an executor shows that its reports keep this chapter. Its vectors, `vectors/checkpoint-report-v1.json` in [`protocol/executor/v1/`](../../protocol/executor/v1/README.md), are each one grant as ExecBound answers it, what happened at the vendor, the report the vectors' own executor sent for it and what that report settles. They cover every row of section 2.8: each reason signed evidence may carry, as an Ed25519 record, as an ES256 attestation and as a provider's journal; each reason unsigned; and the unknown result. They also cover a statement signed in the grant's own second before its exact instant, and grants under each of the three classes a grant can carry. Beside them are reports section 2.9 refuses as `INVALID_REQUEST` or `INVALID_RECORD`, each naming the check of the module that finds its fault. They share one grant, because a refused report leaves its grant as it was, except a journal under an `UNAVAILABLE` grant, which needs a grant with no `provider_command` and carries one of its own.

A harness hands its executor each vector's grant and scenario and gives the module the report body the executor would send. The module reads that body as the outcome route reads it, then asks what it would settle through its `settlement` function, which is section 2.8 as a pure function of a report and whether its evidence verified. It needs the executor's key ring, each key as its scheme and a function that verifies a signature under it, because the protocol package holds no cryptographic library; the vector file publishes the private halves of its test keys, so an executor can sign as the vectors' executor did, and an executor that signs with keys of its own names their public halves in the ring instead. Provider journal keys are HMAC keys, which the module verifies itself, and default to the vectors' own.

ExecBound's outcome route settles every vector exactly as the vector says, over HTTP and on real PostgreSQL, for a grant the gateway issued and the report the vectors' executor writes for that grant, and it refuses every refusal with its code (`tests/test_checkpoint_report_server.py`). Deliberately broken executors fail the module at the check that names their fault (`tests/test_checkpoint_report_conformance.py`).

**ExecBound refuses the published test keys.** Every key the vector files publish is held by everyone who holds the files, so none of them authenticates anybody: chapter 2's `conformance-ed25519` and `conformance-es256` executor keys, whose private halves the file carries, its `conformance-journal` key, chapter 1's `test_verification_key_hex`, and the three keys outside every ring that the vectors' executor signs the refusals with. Registering or rotating onto either executor key, in any spelling registration reads, is refused as `INVALID_KEY`. A tenant's ring that already holds one, from before that refusal, verifies nothing under it: a report signed with it is `INVALID_RECORD` (section 2.9) and settles nothing, the ring's other keys go on attesting, and admission does not count it as a key a grant could be attested by. A deployment that configures a published journal key, for a connector, a Gate account or as its sample key, in any form HMAC-SHA256 reads as the same key, refuses to load and refuses a key reload that brings one in. So the server's own test above signs each vector's scenario with keys generated for the run, registered and configured as an administrator would, and checks those reports against their own ring; `tests/test_published_test_keys.py` holds the vectors' own signed reports refused over the same route, and the set ExecBound refuses equal to the keys the files publish. An executor checks its reports against the vectors with the published keys, or with its own, and signs every report it sends a workspace with a key of its own.

| Report check | What it asserts | Refused as |
| --- | --- | --- |
| `body` | The body is strict UTF-8 JSON of at most 16,384 bytes, and an object | `INVALID_REQUEST` |
| `evidence` | It carries exactly one of `reported_at`, `record`, `attestation` and `journal` | `INVALID_REQUEST` |
| `pairing` | Its outcome and reason pair as section 2.6's table says, an `UNKNOWN` report carries no reason and nothing signed, and signed evidence carries only a reason signed evidence may carry | `INVALID_REQUEST` |
| `model` | The published report model admits it: no field the model does not name, and every field of its shape | `INVALID_REQUEST` |
| `secret` | It presents the grant's report secret | `INVALID_REPORT` |
| `signature` | Its signed evidence is the envelope its field names, and verifies under a key of the ring whose scheme is the envelope's, or for a journal under a journal key | `INVALID_RECORD` |
| `binding` | The evidence binds the grant: the four values of `grant.binding` and a time not before the second the grant was issued in, or for a journal exactly the grant's `provider_command` and a time not before the instant the grant was issued | `INVALID_RECORD` |
| `agreement` | The evidence states the outcome and reason the body does | `INVALID_RECORD` |
| `tier` | It presents evidence of the tier the vector's report does: signed, a provider's journal, the executor's word, or none for `UNKNOWN` | Accepted; settles at another tier |
| `settlement` | It settles, by section 2.8, exactly as the vector says | Accepted; settles otherwise |
| `statement` | It states the vector's outcome and reason | Accepted; records another reason |

The module does not check what needs the exchange itself (the agent credential, the content type, the execution id the route is addressed to), whether a key was registered by the grant and not revoked before it or reported compromised, which the ring the harness passes must already reflect, a report after the first (a settled execution's restatement, the administrator's settlement and the correction), or when the executor acted, which is cooperative.

## 3. Registration and the pull transport

Not yet specified. It arrives with the customer-run executor package, which is designed and not built. Until then an executor serves the routes of chapter 1 and ExecBound reaches it.

## Versions and changes

`version: 1` on every object is its major version. A new optional field, or a new value an older executor may ignore, keeps the major: the schemas are regenerated in place and the change is listed below with the ExecBound release that introduced it. A change an older executor cannot ignore is version 2 of that object, in a new schema directory beside `protocol/executor/v1/`, and ExecBound refuses an object whose version it does not serve.

| Part | Change | ExecBound release |
| --- | --- | --- |
| The checkpoint report, version 1 | The outcome route refuses a `record` or a `journal` that is an ES256 attestation in the flattened form a settlement stores, as `INVALID_RECORD`, before any signature is checked, and settles nothing. Section 2.6 already made a `record` an Ed25519 signed outcome and a `journal` a provider's journal, so this brings the route to what version 1 says and changes no object: the major stays 1 | Unreleased; served by the main branch |
| The checkpoint report, version 1 | The outcome route refuses a `journal` under a grant that carries no `provider_command`, every grant under `UNAVAILABLE`, as `INVALID_RECORD`, and settles nothing; it used to settle one that bound the command ExecBound would have sent. Section 2.6 already made a journal one of exactly the grant's `provider_command`, so this too brings the route to what version 1 says and changes no object: the major stays 1. A grant issued by an ExecBound version before this change recorded no class and is read as before, within a report window, at most a day, of the last grant such a version issued | Unreleased; served by the main branch |
| The checkpoint report, version 1 | A retry's answer describes the grant under the precondition class it was issued under, as section 2.5 says a grant carries, where it used to carry the declaration in force at the retry, so it never shows a version or a `provider_command` the grant was not issued with; a retry that finds the binding declared `CHECKED_BY_CONNECTOR`, which used to answer 503, is answered the same way. No object changes: the major stays 1 | Unreleased; served by the main branch |
| The checkpoint report vectors | A refusal may carry a grant of its own, under the `execution_id`, `granted_at` and `grant` keys a vector names its grant with, where every refusal used to share one; the journal under an `UNAVAILABLE` grant is the first that does. `load_vectors` reads a file in which no refusal does so as before, but an older `load_vectors` cannot read the new file. No released version of `execbound-protocol` reads the file, because the package has not been released. | Unreleased; served by the main branch |
