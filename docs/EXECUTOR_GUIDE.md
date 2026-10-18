# Build an external executor

An external executor is a workflow or service of your own that performs an action with its own vendor credential, after ExecBound has decided it. ExecBound resolves the request, applies policy, asks a person when a rule says to, charges the shared limits and claims the target, exactly as it does for an action it performs itself. Then, instead of calling the vendor, it hands your executor a grant for one act. Your executor acts once and reports what happened, and the report settles the request; step 6 names the two kinds of report that leave it uncertain instead.

Use an executor when the vendor credential has to stay where it is, such as inside a SOAR platform. When it can move, let ExecBound perform the action: the credential is then out of every caller's reach, and the outcome is checked by ExecBound itself. An executor is cooperative. ExecBound enforces the budget, the approval and the audit, but it cannot stop an executor that never asks, ignores a denial or acts twice. [The external execution checkpoint](CHECKPOINT.md) sets out every guarantee and its limit; this page is the steps.

The [Tines guide](../integrations/tines/README.md#the-gate-story-keep-your-vendor-credential-in-tines) is one complete executor built this way, as a Tines story that signs its reports with `JWT_SIGN`.

## Before you start

You need four things, all set up by an administrator:

- **A principal of its own for the executor.** Give the executor an agent principal and an API key that it uses for nothing else. A principal that can request both externally executed actions and actions ExecBound performs would let a stolen executor credential act through ExecBound too, and nothing but this separation prevents it.
- **A connector account with no connector.** Create the account the action is mapped through with `account-create`, and do not configure a connector for it. Admission refuses an externally executed mapping whose account has a connector configured.
- **A key pair for signing reports.** The executor keeps the private key, and ExecBound is given only the public half. Use Ed25519, or ES256 when your platform cannot sign Ed25519.
- **A credential that outlives the report window.** The executor reports with the same credential it asked with, for up to a day after it was granted, so an API key that expires sooner cuts the window short.

## 1. Register the executor's public key

```sh
uv run execbound executor-key-register --tenant <tenant> --key-id soar-2026 --public-key <64 hex characters> --actor <admin>
uv run execbound executor-key-register --tenant <tenant> --key-id tines-gate-2026 --algorithm ES256 --public-key-file es256-public.pem --actor <admin>
```

An Ed25519 key is 64 lowercase hex characters. An ES256 key can be an SPKI PEM, a P-256 JSON Web Key, or compressed SEC1 hex. A policy that maps an action to an external executor cannot be activated while the workspace has no registered key, because a grant nobody could sign a report for would have no way to settle. [Operations](OPERATIONS.md#register-and-cut-off-executor-keys) covers rotation, retirement and reporting a key compromised.

## 2. Mark the mapping as externally executed

In the policy bundle, set `external_executor` on the mapping reference of each action the executor performs. The rest of the reference is the one the mapping already has; only the flag is new:

```json
{
  "operation_ref": "endpoint.isolate",
  "account_id": "<the account with no connector>",
  "mapping_version": "<the mapping's version>",
  "schema_version": "action.v1",
  "context_contract_version": "endpoint-isolation.v1",
  "external_executor": true
}
```

Validate and activate the bundle as usual. Nothing in a request can choose this placement: it comes only from the bundle, so an agent cannot move an action between ExecBound's own dispatch and an executor.

## 3. Say what the vendor guarantees

Each vendor operation has a precondition class, declared in the private configuration file ([the checkpoint](CHECKPOINT.md#declaring-a-class) has the block's shape). It tells the executor, and every page that shows the grant, how far a concurrent change to the target can be detected:

| Class | The grant carries | What the executor does |
| --- | --- | --- |
| `ENFORCED_BY_PROVIDER` | The version the decision was made against | Uses the vendor's conditional write with that version, and reports `VERSION_MISMATCH` when the vendor refuses it |
| `ASSERTED_BY_EXECUTOR` | The same version | Reads the target's version, refuses to act on a mismatch and reports `VERSION_MISMATCH`; the report is its word, not proof |
| `UNAVAILABLE` | No version | Acts without one. A concurrent change cannot be detected, so pair the action with an approval rule |

Whatever the class, a `VERSION_MISMATCH` reported with `reported_at` alone leaves the grant uncertain until it is settled (step 6).

An operation you declare nothing for is `UNAVAILABLE`. Declare a class only when you have checked that the vendor's API really behaves that way, because ExecBound cannot check it.

## 4. Ask for a decision

The executor sends the request an agent would, to `POST /v1/execute` with its own API key ([interfaces](API_REFERENCE.md#action-request)), and branches on the answer:

| Answer | What the executor does |
| --- | --- |
| 202, `DISPATCH_COMMITTED`, with `checkpoint` | Act once, then report (steps 5 and 6). The budget is already charged and the target already claimed |
| 202, `PENDING_APPROVAL`, no `checkpoint` | Wait for the reviewer, then send the same request again. The same execution answers with its grant once it is approved |
| 200, `DENIED` | Stop. There is nothing to act on and nothing to report. A person finds the reason by searching the console for the `request_ref` |
| An error code | See [error and refusal codes](ERROR_CODES.md#execution-codes). `TOO_MANY_GRANTS` means eight of the executor's grants are still unsettled: not yet reported, reported `UNKNOWN` or as an unsigned non-execution, or swept when their report window closed. Each stays counted until a report or an administrator settles it (step 6) |

The `checkpoint` object has two parts. Store `grant.report_secret` straight away: it is sent once, on the first answer only, and a report cannot settle without it. A retry of the same request returns the same grant with a new `act` token but no secret. From `grant`, read what to do: `resource_provider_id`, `action` and `arguments`; `expected_version` when the class carries one; `provider_command`, which is exactly what ExecBound would have sent had it performed the action itself; and the two deadlines, `act_expires_at` and `report_expires_at`. The `binding` names the four values a signed report must repeat.

## 5. Act once, before `act_expires_at`

Call the vendor once, with your own connector and credential. The act window is at most 15 minutes from the grant, and shorter when the decision's context or the API key expires sooner. The grant authorizes one act inside that window and none after it. ExecBound cannot stop a late act, and by then the target may be another request's: a verified report frees it at once, an asserted success or reported failure at the first recovery run after the full 15 minutes have passed, and a report that leaves the grant uncertain does not free it until the grant is settled.

## 6. Report the outcome, before `report_expires_at`

Send `POST /v1/executions/{execution_id}/outcome` with the same API key, the `report_secret`, an `outcome` and its `reason`, and one piece of evidence. The body's JSON Schema, `checkpoint-report.schema.json`, is published with the schemas of the signed record and the JWS in the protocol's [schema directory](../protocol/executor/v1/README.md). The pairs are fixed:

| `outcome` | `reason` | Means |
| --- | --- | --- |
| `EXECUTED` | `EXECUTED` | The vendor performed the action |
| `FAILED_NOT_EXECUTED` | `VERSION_MISMATCH` | The target changed since the decision, so the write was refused and nothing happened. Reported with a `record`, `attestation` or `journal`, the request ends `STALE_AUTHORIZATION`; with `reported_at` alone, the grant stays uncertain |
| `FAILED_NOT_EXECUTED` | `CANCELLED_NOT_EXECUTED` or `TARGET_NOT_FOUND` | The vendor was not reached, or the target does not exist |
| `FAILED_EFFECT_UNKNOWN` | `REPORTED_FAILURE` | The call failed, and whether the vendor acted is not known |
| `UNKNOWN` | none | The executor does not know yet. Report again once it does |

The evidence decides how much the report settles:

| Evidence | Settles as | The target claim |
| --- | --- | --- |
| `record`, an Ed25519-signed record, or `attestation`, an ES256 JWS | Attested: ExecBound verified who said it | Released |
| `journal`, the vendor's own signed journal of the grant's `provider_command` | Provider-verified. A grant under `UNAVAILABLE` carries no command, and a journal for it is refused | Released |
| `reported_at` alone, with `EXECUTED` or `REPORTED_FAILURE` | Asserted: the executor's word. The charge is confirmed | Held until a recovery run after the full 15-minute act window |
| `reported_at` alone, with a non-execution, or an `UNKNOWN` report | Nothing. The grant stays uncertain and still charged until a later report or an administrator settles it, and a non-execution settles only with one of the signed forms above | Held while the grant is uncertain |

A signed record binds the operation, the account and both hashes from `grant.binding`, so it can settle only this grant. With the `execbound_protocol` package and an Ed25519 key held as a `cryptography` private key:

```python
from datetime import UTC, datetime
from uuid import UUID

from execbound_protocol.executor import ExecutorRecord, sign_outcome

grant = response["checkpoint"]["grant"]
record = ExecutorRecord(
    operation_id=UUID(grant["binding"]["operation_id"]),
    account_id=UUID(grant["binding"]["account_id"]),
    intent_hash=grant["binding"]["intent_hash"],
    plan_hash=grant["binding"]["plan_hash"],
    outcome="EXECUTED",
    reason="EXECUTED",
    reported_at=datetime.now(UTC),
)
signed = sign_outcome(record, "soar-2026", private_key)
report = {
    "report_secret": report_secret,
    "outcome": "EXECUTED",
    "reason": "EXECUTED",
    "record": signed.model_dump(mode="json"),
}
```

The signed `reported_at` may not be earlier than the second the grant was issued in, so keep the executor's clock in time with the gateway's. A report that was accepted and is sent again unchanged answers with the same view, settled or uncertain, so an executor whose answer was lost can safely resend it.

## 7. Check the reports against the published vectors

Before a workspace relies on your executor, check the reports it writes with the protocol package. The [schema directory](../protocol/executor/v1/README.md) publishes `vectors/checkpoint-report-v1.json`: for every kind of report in step 6, a grant as ExecBound answers it, what happened at the vendor, the report that settles it and what that report settles, which ExecBound's own outcome route is tested to agree with. The `execbound_protocol.checkpoint_conformance` module reads a report as the outcome route does and checks what it would settle. Hand your executor each vector's grant and scenario, capture the body it would send, and check it with your key's public half:

```python
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from execbound_protocol.checkpoint_conformance import RingKey, check, load_vectors

public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))


def verify(signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True


vectors = load_vectors(Path("checkpoint-report-v1.json").read_bytes())
for vector in vectors.vectors:
    # Your own harness: give the executor vector.grant.wire and vector.scenario, and capture
    # the body it would send to the outcome route.
    body = report_from_my_executor(vector)
    check(vector, body, {"soar-2026": RingKey("ED25519", verify)})
```

`check` raises `Nonconformance` naming the check that failed, such as `signature` for a key outside the ring or `tier` for a report that should have been signed and was not. Check the vectors for the evidence your executor sends: one that always signs has no unsigned report to check, and one that never relays a provider's journal skips the `journal-` vectors. An ES256 key is a `RingKey("ES256", …)` whose function checks the JWS's raw 64-byte signature over its first two segments. [The executor protocol](protocol/EXECUTOR_PROTOCOL.md#210-conformance) lists every check and what the module leaves out. The vector file's own keys are for this check alone: ExecBound refuses to register them and attests nothing they sign, so the key your executor signs a workspace's reports with is the one you registered in step 1.

## When something goes wrong

| Situation | What to do |
| --- | --- |
| The first answer was lost, and with it the report secret | Nothing the executor can send settles the grant. An administrator settles it from the request's record in the console, with a record signed by a registered key |
| `INVALID_REPORT` (403) | The secret is wrong. Nothing settled; report again with the right one |
| `INVALID_RECORD` (400) | The signature did not verify, the record does not match the grant, or the evidence is not one this grant admits: an ES256 attestation goes in `attestation`, as the compact token, and never in `record` or `journal`, and a grant whose `precondition_class` is `UNAVAILABLE` takes no `journal`. Nothing settled; sign or report the evidence the grant admits |
| `REPORT_WINDOW_CLOSED` (409) | Stop retrying. Only an administrator can settle it now, from the console |
| The vendor's outcome is not known | Report `UNKNOWN` and report again once it is, or `FAILED_EFFECT_UNKNOWN` with `REPORTED_FAILURE` if it never will be. A reported failure is charged as a success would be; an administrator can correct it later with a signed record that the action did not happen |
| A grant is never reported | The recovery run leaves it uncertain when its report window closes, with its charge and its target claim kept, until an administrator settles it |
| The private key may have leaked | Report it compromised with `executor-key-compromise`, register a replacement, and read [what a compromise costs](CHECKPOINT.md#what-a-compromise-costs-stated-rather-than-discovered) first |
