# SPDX-License-Identifier: AGPL-3.0-only
"""The prose that opens the agent API reference: the introduction and the sections a caller
reads before any route, the way an API reference is laid out elsewhere.

Scalar renders `info.description` as the reference's Introduction and lists its `##` headings
in the sidebar ahead of the endpoints, so authentication, errors and limits sit on the same page
as the routes. The errors table is built from `ERROR_STATUS` and `ERROR_MEANINGS`: a code the
gateway can answer that this module cannot explain fails `tests/test_agent_openapi.py`, and so
does an explanation for a code the gateway no longer has.
"""

import json

from execbound.execution.models import DenialCategory
from execbound.requests import MAX_REQUEST_BYTES
from execbound.runtime import denial_notice
from execbound.surfaces.limits import RequestLimits
from execbound.surfaces.mcp import MAX_MCP_BYTES

# What each execution error code means to the caller, and what the caller should do.
ERROR_MEANINGS: dict[str, tuple[str, str]] = {
    "INVALID_REQUEST": (
        "The body, path or headers are malformed: an unknown field, a missing `reference` or "
        "`idempotency_key`, a query string, an identity header, the wrong content type, or a "
        "body over the size limit.",
        "Fix the request.",
    ),
    "INVALID_CONTINUATION": (
        "The continuation is malformed, belongs to another execution, or has expired. It also "
        "means the approval was decided.",
        "Re-send the identical execute request.",
    ),
    "INVALID_RECORD": (
        "An outcome report's signed evidence did not verify against the grant, or verified but "
        "is not accepted for it: an attestation in the form a settlement stores it, sent as a "
        "`record` or a `journal`, or a provider's journal for a grant whose precondition class "
        "is `UNAVAILABLE`.",
        "Report again with a record signed for this execution.",
    ),
    "INVALID_IDENTITY": (
        "The key is not an agent's, or the agent is deactivated.",
        "Use an agent's API key, or reactivate the agent.",
    ),
    "INVALID_REPORT": (
        "An outcome report's secret did not match the grant.",
        "Report with the secret the grant carried.",
    ),
    "NOT_FOUND": (
        "No execution with this id belongs to this agent.",
        "Check the id; an agent reads only its own executions.",
    ),
    "DEMO_UNAVAILABLE": (
        "`synthetic_demo` was set in a workspace that holds real data.",
        "Leave `synthetic_demo` out.",
    ),
    "IDEMPOTENCY_CONFLICT": (
        "The same `reference` or `idempotency_key` was used for a different action, target or "
        "arguments.",
        "Use a new reference for a new intent.",
    ),
    "INVALID_STATE": (
        "The execution is not in a state that allows this, such as reporting on one that holds "
        "no grant.",
        "Read the execution's status first.",
    ),
    "REPORT_WINDOW_CLOSED": (
        "The grant's report window has closed.",
        "An administrator settles it from the console.",
    ),
    "INVALID_KEY_RING": (
        "The workspace's executor key ring cannot be read, so no record can be attested.",
        "An administrator repairs the key ring.",
    ),
    "INVALID_BUNDLE": (
        "The active policy cannot authorize requests in this deployment, for example a Gate "
        "mapping on an account ExecBound also executes for.",
        "An administrator corrects the policy or the mapping.",
    ),
    "TENANT_STOPPED": (
        'The workspace is under an emergency stop; the body also carries `"tenant_stopped": true`.',
        "Wait for an administrator to lift the stop.",
    ),
    "SPACE_ARCHIVED": (
        "The agent's space is archived and takes no new work.",
        "Move the agent to an active space.",
    ),
    "BUSY": (
        "The gateway is at its concurrency limit. No `Retry-After` is sent.",
        "Retry with backoff.",
    ),
    "RATE_LIMITED": (
        "This API key has used its request allowance for the window.",
        "Wait for the `Retry-After` seconds.",
    ),
    "EXECUTION_UNAVAILABLE": (
        "Execution is unavailable. An action your space does not offer, an unknown target, run "
        "or context all get this same answer on purpose, so it reveals nothing about what "
        "exists beyond what `GET /v1/actions` lists.",
        "Check the action against `GET /v1/actions` and the target. If they are right, retry "
        "later; if the answer persists, stop and tell a person, because stale trusted facts do "
        "not fix themselves.",
    ),
    "NO_ACTIVE_BUNDLE": (
        "The agent's space has no active policy, so every request is refused.",
        "An administrator activates a policy.",
    ),
    "TOO_MANY_GRANTS": (
        "This agent already holds the maximum of eight unsettled checkpoint grants.",
        "Report the outcomes of the grants it holds.",
    ),
    "CONNECTOR_UNAVAILABLE": (
        "The provider account the action needs is not connected.",
        "An administrator connects the account.",
    ),
    "INVALID_APPROVAL": (
        "The approval does not match the plan it was given for.",
        "Re-send the request; a changed plan needs a new approval.",
    ),
    "INVALID_OWNER": (
        "An internal ownership check failed.",
        "Retry later, and report the request id if it persists.",
    ),
    "INVALID_CLOCK": ("The decision could not read a trustworthy time.", "Retry later."),
    "INVALID_EVIDENCE": (
        "Evidence from a provider or executor did not verify.",
        "Retry later, and report the request id if it persists.",
    ),
}

# Every reason a DENIED execution records, as the console shows it on the record: the codes
# `policy/evaluate.py` denies with, `RESOURCE_BUSY` from admission and `HUMAN_DENIED` from a
# reviewer. Only those: `APPROVAL_REQUIRED` holds a request rather than denying it, and a
# decision carrying `INVALID_APPROVAL` ends the request as stale (`CHANGED_OBLIGATIONS`),
# never as denied. The agent itself is never told which one: its answer carries the state,
# the request's reference, `denial` (`busy` for `RESOURCE_BUSY` alone, `limit` when any
# reason is a `HARD_LIMIT`, `withheld` otherwise) and `notice` (`runtime.denial_notice`), and
# nothing finer (THREAT_MODEL.md T1.16).
DECISION_REASONS: tuple[tuple[str, str], ...] = (
    (
        "NOT_AUTHORIZED",
        "No rule in the active policy permits this action for this plan, or a deny rule "
        "matched it.",
    ),
    (
        "HARD_LIMIT:<rule id>",
        "The named budget is spent, and it denies rather than asking for approval.",
    ),
    ("INVALID_CONTEXT", "The trusted context expired before the decision was made."),
    ("INVALID_ARGUMENTS", "The arguments are not the ones the action accepts."),
    ("INVALID_IDENTITY", "The agent's identity or key did not hold."),
    (
        "INVALID_BUNDLE",
        "The active policy cannot authorize this request: it names the action at a mapping that "
        "has since changed, or it is not this workspace's.",
    ),
    ("INVALID_USAGE", "The shared impact counters could not be read."),
    ("POLICY_ERROR", "The policy could not be evaluated."),
    ("DEPENDENCY_UNAVAILABLE", "Something the decision needs could not be reached."),
    ("RESOURCE_BUSY", "Another operation still holds this target."),
    ("HUMAN_DENIED", "A reviewer refused it. The reviewer's comment stays with people."),
)

# What each denial category says, in the words the guide's table gives it; the categories are
# `models.DenialCategory` and the sentences `runtime.denial_notice`.
DENIAL_CATEGORIES: tuple[tuple[DenialCategory, str], ...] = (
    (
        "busy",
        "Another request holds the target. The policy otherwise allowed this one, because a "
        "busy target is found after the decision.",
    ),
    (
        "limit",
        "A shared limit covering this request is spent. Given whenever a spent limit is among "
        "the recorded reasons, whatever else is, so it says nothing about whether the policy "
        "allows this target.",
    ),
    (
        "withheld",
        "Every other denial: a rule, a reviewer, stale context or anything the decision could "
        "not read.",
    ),
)

# Each state an agent can be answered with, its status, and what the agent should do next.
STATES: tuple[tuple[str, int, str], ...] = (
    ("EXECUTED", 200, "Done."),
    (
        "DENIED",
        200,
        "Stop and tell a person the `request_ref`; the reason is recorded for them and is "
        "not sent to the agent. Re-sending the same request returns the same answer. When "
        "`denial` is `busy` or `limit`, a new request after the other request settles or the "
        "limit resets is decided afresh, and whether to make one is the person's call.",
    ),
    (
        "OBSERVED",
        200,
        "Nothing ran: the workspace or mapping is observe-only. `observed` says what would "
        "have been decided.",
    ),
    (
        "PENDING_APPROVAL",
        202,
        "Wait for a person. Read the status with the `continuation`, then re-send the "
        "identical request once it is approved.",
    ),
    (
        "DISPATCH_COMMITTED",
        202,
        "The action may have happened. Re-send the identical request or read the status until "
        "it settles; never propose it again under a new reference.",
    ),
    ("INDETERMINATE", 202, "As `DISPATCH_COMMITTED`: the outcome is not established yet."),
    (
        "STALE_AUTHORIZATION",
        200,
        "The approval or the trusted context expired first. Propose it again if it is still "
        "needed.",
    ),
    ("FAILED_NOT_EXECUTED", 200, "The provider refused; nothing changed."),
    (
        "FAILED_EFFECT_UNKNOWN",
        200,
        "The call failed and whether the change happened is not known. Put it in front of a "
        "person.",
    ),
)


def _table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def introduction(codes_by_status: dict[int, list[str]]) -> str:
    """The Markdown Scalar renders as the reference's Introduction and its sections."""
    limits = RequestLimits()
    errors = _table(
        ("Status", "Code", "What it means", "What to do"),
        [
            (str(status), f"`{code}`", *ERROR_MEANINGS[code])
            for status, codes in codes_by_status.items()
            for code in codes
        ],
    )
    states = _table(
        ("State", "Status", "What the agent should do"),
        [(f"`{state}`", str(status), advice) for state, status, advice in STATES],
    )
    reasons = _table(
        ("Reason", "Meaning"), [(f"`{reason}`", meaning) for reason, meaning in DECISION_REASONS]
    )
    notice = json.dumps(denial_notice("EB-12"))
    categories = _table(
        ("`denial`", "When", "`notice`"),
        [
            (f"`{category}`", when, json.dumps(denial_notice("EB-12", category)))
            for category, when in DENIAL_CATEGORIES
        ],
    )
    rate_limits = _table(
        ("Limit", "Value", "Answer when exceeded"),
        [
            (
                "Requests per API key",
                f"{limits.agent_requests} per {limits.agent_window_seconds} seconds, across HTTP "
                "and MCP",
                "429 `RATE_LIMITED` with `Retry-After`",
            ),
            (
                "Requests per client address",
                f"{limits.client_requests:,} per {limits.client_window_seconds} seconds",
                "429 `RATE_LIMITED` with `Retry-After`",
            ),
            (
                "Requests in flight",
                "32 per gateway process, and at most as many executions at once as the "
                "database pool serves",
                "429 `BUSY`, or `Service busy`",
            ),
            (
                "Action and outcome body",
                f"{MAX_REQUEST_BYTES // 1024} KiB, read within 5 seconds",
                "400 `INVALID_REQUEST`",
            ),
            ("MCP message", f"{MAX_MCP_BYTES // 1024} KiB", "400 `Invalid request`"),
            ("Unsettled checkpoint grants", "8 per agent", "503 `TOO_MANY_GRANTS`"),
            (
                "Continuation lifetime",
                "At most 2 minutes, and never past the approval's or the key's expiry",
                "400 `INVALID_CONTINUATION`",
            ),
        ],
    )
    return f"""\
The agent API is how an agent asks to perform a consequential action. The agent proposes one \
action on one target; ExecBound checks who the agent is, the trusted context and the \
workspace's policy, asks a person when a rule says to, and only then performs the action with \
a credential the agent never holds. Every decision is recorded.

The hosted service answers at `https://app.execbound.ai`, and a self-hosted deployment serves \
the same routes at its own address. An MCP host reaches the same API as three tools; see \
[MCP](#description/mcp). The [quickstart](https://docs.execbound.ai/start-here/quickstart) and \
[Connect an agent host](https://docs.execbound.ai/guides/connect-an-agent) walk through a first \
request.

Before a first request, `GET /v1/actions` (or the MCP tool `list_actions`) lists the actions \
the agent's space offers: each `operation_ref`, its arguments and their values, the target \
kinds it accepts and whether an incident is required. A listed action is not permission, \
every request is still decided, and targets are never listed.

## Authentication

Every request carries the agent's API key in one header:

```http
Authorization: Bearer <API key>
```

A key looks like `eb1.<tenant>.<credential>.<secret>`. It identifies one agent in one \
workspace, and it is all the gateway reads to decide who is asking: an identity header such as \
`X-Tenant-Id` or `X-Principal-Id` is refused rather than trusted.

### Get an API key

An administrator issues keys in the console of the deployment the agent will call.

1. Open **Agent connections** and **Add agent**, naming the agent after the tool that will use \
the key. Or open **API keys**, choose **Issue an API key** and **New agent…** to create the \
agent and its key together.
2. On the agent's page, under **Connect this agent**, choose a lifetime, from one hour to 90 \
days or **Never**, and **Issue API key**.
3. Copy the key into the tool's secret configuration. It is shown once and never again; \
ExecBound keeps only its hash.

Give each tool its own agent and key, so its activity is its own and its key can be revoked \
alone.

### Check a key

`GET /v1/me` proposes nothing and records nothing. With `<gateway>` standing for the \
deployment's address:

```sh
curl https://<gateway>/v1/me -H "Authorization: Bearer $EXECBOUND_CREDENTIAL"
```

It answers with the agent the key belongs to. A 401 means the key is missing, malformed, \
unknown, revoked or expired.

### Rotate or revoke a key

To replace a key, issue a new one, update the tool, then revoke the old one under **API \
keys**. Issuing a key never revokes another. A revoked or expired key can be deleted from the \
list; the audit history keeps it.

An API key opens only the routes below. It cannot sign in to the console, and it can never \
approve a request: approvals are a signed-in person's decision.

## Requests

- **Bodies** are exactly `application/json`, at most {MAX_REQUEST_BYTES // 1024} KiB, with no \
unknown fields, duplicate keys or floating-point numbers. A query string or a \
`Content-Encoding` header is refused.
- **Idempotency.** Send exactly one of `reference`, the ticket, case or run the action answers, \
or `idempotency_key`. ExecBound derives the key from a reference. Re-sending the identical \
request returns the same execution and never acts twice; reusing a reference for a different \
action is refused.
- **Correlation.** Send a UUID as `X-Request-Id` to match a call with your logs. Every answer \
echoes one.

## Responses

A final or observed state is answered 200; a state that is not final yet is answered 202.

{states}

**Approvals.** A request a rule sends for review answers 202 with `PENDING_APPROVAL`, a \
`continuation` and the approval page's address. Read its status with \
`X-Execution-Continuation: <continuation>`; a status read never acts. Once a person approves \
it, re-send the identical execute request, before the approval's deadline, and that is what \
runs it. A continuation lasts at most two minutes, and re-sending the request renews it.

**Why a request was denied.** An agent is told that a request was denied, the request's \
reference and one of three categories, and never the reason itself. The reason is recorded \
for a person, who finds the record by searching the console for that reference. This is \
deliberate: the agent is the party being governed, and one that is mistaken, prompt-injected \
or compromised gets no map of the policy from its denials, neither the rule that matched, the \
fact that put the target out of bounds nor the budget that is spent, and a reviewer's words \
stay with people. A `DENIED` answer carries `denial` and `notice`, one fixed sentence built \
from the category and the reference alone:

```json
{{
  "request_ref": "EB-12",
  "execution_id": "…",
  "state": "DENIED",
  "plan_hash": "…",
  "approval_id": null,
  "approval_state": null,
  "denial": "withheld",
  "notice": {notice}
}}
```

{categories}

`busy` and `limit` tell the agent when waiting is worth a new request: when another request \
holds the target, a new request after that one settles may be decided differently, and when a \
shared limit is spent, a new request after the limit resets is decided afresh. `busy` is \
decided after the policy, so it also says the policy otherwise allowed the request. `limit` is \
given whenever a spent limit is among the recorded reasons, whatever else is, because every \
limit that covers a request is checked whatever the policy decides; so it says nothing about \
whether a rule would allow the target, and its sentence does not promise a different \
decision. The category never names the rule, the limit, its window, a count, a fact or the \
other execution.

The view has always shown whether a person was involved, and still does: `approval_state` is \
`DENIED` when a reviewer refused the request, `INVALIDATED` when a request that held an \
approval was then denied, and null when the first decision denied it. The reviewer's comment \
never reaches the agent.

On a denial, stop and give the person the `request_ref` rather than guessing why. Re-sending \
the same request returns the same answer. A new request may be decided differently, for \
example once a busy target is released, a budget's window moves on or someone changes the \
policy, and whether to make one is the person's call. A target another execution still holds \
is answered the same way, as a `DENIED` with `denial` `busy` whose recorded reason is \
`RESOURCE_BUSY`, and never as an error. Observe mode is the one exception, whether the whole \
workspace observes or only the mapping an action goes through: nothing runs, and \
`observed.reasons` shows what enforcement would have decided, because showing that is what \
observe mode is for.

The reasons a denial records, which a person reads on its record in the console:

{reasons}

## Errors

An execution error is JSON with a stable code:

```json
{{"detail": "Execution unavailable", "code": "IDEMPOTENCY_CONFLICT"}}
```

An authentication or header error carries `detail` only: `Invalid credentials` (401, with \
`WWW-Authenticate: Bearer`), `Invalid request` (400) or `Forbidden` (403). A denial is not an \
error: it is answered 200 with `"state": "DENIED"`.

A 4xx is the caller's to fix. A 503 invites a retry later, and one that persists needs a \
person, because stale trusted facts do not fix themselves. A 503 or a dropped connection \
after a request may have been committed is not proof that nothing happened: re-send the \
identical request, which returns the same execution rather than acting twice.

{errors}

## Rate limits

{rate_limits}

A refusal for a rate limit happens before anything is read or written, so it uses no impact \
budget, approval or audit record. `GET /v1/me` is not rate limited, so it is the safe way to \
check a key.

## MCP

The same key opens a Streamable HTTP MCP server at `/mcp/`, stateless and answering in JSON. \
It authenticates with the same static header and does not offer OAuth.

| Tool | Arguments | What it does |
| --- | --- | --- |
| `execute` | `{{"request": <the execute body>}}` | Proposes one action; answers as \
`POST /v1/execute` does. |
| `execution_status` | `{{"execution_id": "<uuid>", "continuation": "<optional>"}}` | Reads \
the agent's own execution. |
| `list_actions` | `{{}}` | Lists the actions the agent's space offers; answers as \
`GET /v1/actions` does. |

The `execute` tool's description tells the model to call `list_actions` for the \
operation_ref values its space offers, and on a denial to stop and give the person the \
`request_ref` rather than guess why.

[Connect an agent host](https://docs.execbound.ai/guides/connect-an-agent) has the \
configuration for each MCP host.
"""
