# Request references and external cases

Each admitted request has a stable, tenant-unique handle such as **EB-1042**. The same
handle appears in the execution response, approval queue, activity, notification and
signed-in record. Search accepts the handle, an external case ID, target, execution or
approval UUID prefix, and delivery UUID prefix. Search stays within the current space
and the reader's permissions; a direct record link checks membership across their spaces. For a
person whose account belongs to several workspaces, each of which numbers its own requests, the
console names the workspace beside a record's reference ("EB-12 · Contoso SOC"); this is display
only, and the reference, search and every address are unchanged.

The handle is a label, not a credential. UUIDs remain the immutable protocol and audit
identifiers. Technical details on the record retain execution, approval and delivery IDs;
email keeps them in diagnostic headers instead of listing them in the body. Notifications
do not expose external case metadata. The signed webhook's existing version 1 body is
unchanged.

## Send optional case information

HTTP and MCP accept `external_case` alongside the existing action request:

```json
{
  "operation_ref": "endpoint.isolate",
  "target": {"kind": "hostname", "value": "ws25.example.test"},
  "arguments": {},
  "reference": "INC-4821/isolate/ws25/attempt-1",
  "external_case": {
    "source": "tines",
    "case_id": "INC-4821",
    "url": "https://your-tenant.tines.com/cases/4821"
  }
}
```

This illustrates the case fields; supply any incident claim required by your operation's
trusted-context contract separately. A case label never replaces that context.

`source` is a lowercase identifier of up to 40 characters. `case_id` is up to 80 ASCII
letters, digits, spaces or `._:/()-`, beginning with a letter or digit. The optional URL
must use HTTPS with a DNS hostname and no credentials, query, fragment, custom port,
control characters or IP literal. The page names the destination and opens it in a new
tab without an opener or referrer. The gateway never fetches it. Validation does not
establish that a case or destination is trustworthy; the page labels both as caller-reported.
A case whose source, ID or link carries text shaped like a credential (a bearer value, an
ExecBound credential, a key, a JWT, a database URL or a webhook address) is refused as
`INVALID_REQUEST`, and the answer and the audit record never quote it. The case is copied
into the audit chain, and the event export refuses a window holding such text for good.

The Tines governed-action template accepts the same `external_case` object through direct
webhooks and Send to Story. It returns `request_ref` in its outcome. Python's
`action_request`, synchronous and asynchronous tool helpers accept `external_case`; an
`Outcome` exposes `request_ref`. Existing clients can keep sending no case information.

## Retry identity and relationships

`reference` and `external_case.case_id` have different jobs. The existing `reference`
derives the retry key. Reuse it for a retry of the same action; choose a distinct action
reference for a genuinely separate request. The external case groups requests by exact
`source` and `case_id`, so one incident can contain several actions and targets.

The first accepted request retains its case information. Changing or omitting that metadata
on a retry does not mutate the record, change the plan, or create a new request. Case metadata
is excluded from the wire hash and from canonical intent and plan hashes. It cannot select
policy, approve a request, affect impact accounting, or settle an outcome.

The request timeline combines transitions, review decisions and notification queue/delivery
events. Technical details show current delivery state and attempt counts, without exposing
recipient addresses. Related-case views show up to 20 recent accessible requests. They
apply the parent view's tenant, space and review-scope restrictions, even for an administrator
using the Approvals page. Case-ID search is case-insensitive; grouping is exact.

## Storage and rollout

Migration `0046_request_references` adds a positive `executions.request_number`, unique
within the tenant. New requests allocate the next number under the existing tenant write
fence; a unique index provides the database guard. The runtime can neither renumber nor
delete executions. This introduces no second lock order or independent authorization path.

The migration backfills historical requests in creation-time/UUID order, starting at one
per tenant. References can repeat across tenants and are never a global lookup key. New
execution audit events carry the reference; the initial event also retains supplied case
metadata. Historical audit events and already exported evidence are not rewritten.

Case information remains in the immutable frozen request JSON, with a tenant/source/case
index for related reads. There is no external case synchronization, case creation, or
case-level approval. Customers keep that workflow in Tines or their ticket system.

Apply the migration before deploying the matching gateway and database jobs. As with other
schema changes, the old runtime intentionally fails readiness at a mismatched schema head.
Verify the exact deployed commit. A successful physical-phone
approval remains a separate qualification from automated browser and server tests.
