# Error and refusal codes

When ExecBound refuses something, it says why with a code: a short upper-case name such as `INVALID_STATE` that stays the same from release to release. A caller should act on the HTTP status and the code, never on the text beside them, which is a generic sentence and may change. This page lists the codes the agent API, MCP, the console API, the owner commands and the two intake APIs refuse with, and the reasons a request's own record carries. A test holds it to the code, so a code any of them can return that is missing here fails the build, as does a row for a code nothing returns, and the status beside each code is the one the interface answers with (in the monitoring API's table, the one its intake would give it; see [the monitoring API](#the-monitoring-api)).

## How a code is delivered

**The agent API** answers an execution refusal with its status and a JSON body: `{"detail": "Execution unavailable", "code": "IDEMPOTENCY_CONFLICT"}`. An authentication failure answers 401, and a refusal of the headers or the session may carry only `detail`. A `DENIED` decision is not an error: it is answered 200 with the execution's view (see [why a request was denied](#why-a-request-was-denied)).

**MCP** returns the same body as the tool's result, marked as an error.

**The console API** answers every refusal with its status and `{"code": "…", "detail": "…"}`, where `detail` is the one sentence that code always has, and `fields` names the faulty fields of an invalid body. An execution code reaches the console as the generic code for its status, such as `CONFLICT` for a 409, except where the console names the fault itself: one a person can fix, such as `INVALID_REASON` or `INVALID_COMMENT`, becomes `INVALID_BODY` naming the field, and a decision from a reviewer whose own decision on that approval is already recorded is `ALREADY_DECIDED`.

**The execution commands** an administrator runs (`tenant-stop`, `tenant-resume`, `tenant-mode`, `tenant-approval-deadline`, `observe-report`, `recover`, `reconcile`, `notify` and the `export-*` commands) print an execution code after a phrase naming what refused it, such as `Emergency stop refused: INVALID_REASON.`, and exit 2. The other owner commands do the same with codes of their own, listed under [command codes](#command-codes).

**The monitoring and signal intake APIs**, which a monitored platform and a security signal producer call, answer with their status and a JSON body that names the code; see [the monitoring API](#the-monitoring-api) and [the signal intake API](#the-signal-intake-api).

A 503 after a request may have been committed is not proof that nothing happened. Read the execution's status, and reconcile it if its outcome is uncertain.

## Execution codes

What the agent API and MCP answer, and the execution commands print. A code that has no status of its own is answered 503. Several codes below are raised only by an administrator's command or by a console action. The console turns the ones a person can fix, such as `INVALID_REASON` and `INVALID_COMMENT`, into `INVALID_BODY` naming the field, and answers most of the rest with the generic code for their status ([how a code is delivered](#how-a-code-is-delivered)).

| Code | Status | When |
| --- | --- | --- |
| `INVALID_REQUEST` | 400 | The body, an identifier or a parameter is malformed, ambiguous or out of bounds, or an action the agent's space offers was sent with arguments it does not accept. Fix the request; resending it unchanged gets the same answer. |
| `INVALID_CONTINUATION` | 400 | A status continuation did not verify: expired, issued for another request, or not one ExecBound issued. Resend the original request to get a fresh one. |
| `INVALID_RECORD` | 400 | An external executor's outcome report carried signed evidence that is malformed, did not verify against the tenant's executor keys or the journal key, contradicts the report, or verifies but is not admitted for the grant: an attestation in the form a settlement stores it, sent as a `record` or a `journal`, or a provider's journal for a grant issued `UNAVAILABLE`. Nothing settled. |
| `INVALID_IDENTITY` | 403 | The credential is not an agent's where an agent is required, or the acting administrator, scheduler or reviewer is no longer current: revoked, deactivated or in an inactive workspace. Changing the enforcement mode, the approval deadline or the emergency stop, and reading `observe-report` or `rotation-readiness`, also needs a workspace administrator, so an administrator seated in spaces reads this too. |
| `INVALID_REPORT` | 403 | An outcome report did not authenticate against the grant it names. |
| `NOT_FOUND` | 404 | No execution or approval with this id belongs to the caller's scope. |
| `IDEMPOTENCY_CONFLICT` | 409 | The idempotency key was used before for a different request. Send a new key for a new request. |
| `INVALID_STATE` | 409 | The execution or approval is not in a state that allows this: already decided, settled, reported or expired. Final for that row. |
| `REPORT_WINDOW_CLOSED` | 409 | An outcome report arrived after its grant's report deadline. Final for that row. |
| `INVALID_KEY_RING` | 409 | The workspace's executor key ring cannot be loaded, so no record can be checked against it. An administrator has to repair the keys. |
| `INVALID_BUNDLE` | 409 | The active policy bundle cannot authorize this request in the deployment it is running in: it names an action at a mapping that has since changed, or it asks for something the deployment cannot do. It stands until an administrator changes the policy or the deployment. |
| `DEMO_UNAVAILABLE` | 409 | The synthetic demonstration path was used against a workspace that is not the demonstration's own. |
| `TENANT_STOPPED` | 423 | The workspace's emergency stop is active. Nothing new is admitted, decided or dispatched until an administrator releases it; a pending approval's status answers 202 with `tenant_stopped: true`. |
| `SPACE_ARCHIVED` | 423 | The agent's space, or the space a decision belongs to, is archived and takes no new work. |
| `BUSY` | 429 | The gateway is at its limit of requests in progress. Try again shortly. |
| `RATE_LIMITED` | 429 | A credential, sign-in or client address sent too many requests in its window. Wait for the `Retry-After` header. |
| `EXECUTION_UNAVAILABLE` | 503 | Execution is unavailable. An operation the agent's space does not offer, an unknown target, a claimed incident the inventory does not hold and stale trusted context are all answered this way on purpose, so that an agent cannot map what lies beyond its space; the request's record says which, for people (see [refused before admission](#why-a-request-was-refused-before-admission)). It is also the answer for an unexpected fault. |
| `NO_ACTIVE_BUNDLE` | 503 | The agent's space has no active policy bundle, so nothing can be decided. |
| `CONNECTOR_UNAVAILABLE` | 503 | The connector the mapping names is not configured or could not be reached. A request that was already committed to dispatch may still have reached the provider; reconcile it. |
| `TOO_MANY_GRANTS` | 503 | The agent already holds eight outstanding checkpoint grants. It clears as those grants settle. A grant reported `UNKNOWN` or as an unsigned non-execution, or swept unreported, stays counted until a report or an administrator settles it. |
| `INVALID_APPROVAL` | 503 | The approval the request relies on no longer holds: it expired, or its reviewer's role or scope changed before it was used. |
| `INVALID_EVIDENCE` | 503 | The provider's evidence for an operation did not verify against what was dispatched. The operation's outcome stays uncertain until it is reconciled. |
| `INVALID_OWNER` | 503 | A dispatch was attempted without the ticket admission issued for it. |
| `INVALID_CLOCK` | 503 | The deployment's clock gave a time with no time zone. A configuration fault. |
| `INVALID_CONFIGURATION` | 503 | A configuration does not allow this: an operation reached through an account another space owns, an agent in more than 64 groups, or a notification destination without what it needs to send. On the agent's path it is recorded for people only, and the agent is answered `EXECUTION_UNAVAILABLE`. |
| `INVALID_DECISION` | 503 | An approval decision was neither approve nor deny, or named no approval. |
| `INVALID_COMMENT` | 503 | A reviewer's comment was empty, longer than 500 characters, not printable, or shaped like a credential. |
| `INVALID_REASON` | 503 | The reason given for an emergency stop, a mode change or a reconciliation is missing, too long, or shaped like a credential. |
| `INVALID_MODE` | 503 | The enforcement mode is neither `ENFORCE` nor `OBSERVE`. |
| `INVALID_DEADLINE` | 503 | The approval deadline is out of bounds. |
| `INVALID_WINDOW` | 503 | The observation report's window is outside 0 to 2,160 hours. |
| `INVALID_LIMIT` | 503 | A batch size is out of bounds for the command: an event export, a notification delivery or a recovery run. |
| `INVALID_GRACE` | 503 | The recovery run's grace period is outside one minute to one day. |
| `INVALID_NOTIFICATION` | 503 | An approval notification could not be built for a webhook destination. |
| `UNSAFE_JOB_POLICY` | 503 | `recover --all-tenants`, the scheduled recovery pass, stopped before visiting any workspace: the row security policies on the directory of tenants (`job_tenants`) are not exactly the two that migration `0064_scheduled_jobs` made, with `owner_list` applying only to the role that owns `job_tenants_page`. It prints `Recovery refused: UNSAFE_JOB_POLICY.` and exits 2. The [jobs service](OPERATIONS.md#the-jobs-service) that runs the pass keeps running, logs each run as failed with that line, and meets the same refusal every time. Restore them as the migration made them. |

## Why a request was denied

A `DENIED` execution records its reasons. People see them on the request's record, which they find by searching the console for the request's reference. The agent is never told the reason: its answer carries the state, the reference and one of three categories, `busy`, `limit` or `withheld`, with a fixed sentence ([interfaces](API_REFERENCE.md#denials)).

| Code | When |
| --- | --- |
| `NOT_AUTHORIZED` | No rule in the active policy permits this action for this plan, or a deny rule matched it. |
| `HARD_LIMIT:<rule id>` | The named budget is spent, and that rule denies rather than asking for approval. The agent's category is `limit`. |
| `INVALID_CONTEXT` | The trusted context expired before the decision was made. |
| `INVALID_ARGUMENTS` | The arguments are not the ones the action accepts. |
| `INVALID_IDENTITY` | The agent's identity or key did not hold. |
| `INVALID_BUNDLE` | The active policy cannot authorize this request: it names the action at a mapping that has since changed, or it is not this workspace's. |
| `INVALID_USAGE` | The shared impact counters could not be read. |
| `POLICY_ERROR` | The policy could not be evaluated. |
| `DEPENDENCY_UNAVAILABLE` | Something the decision needs could not be reached. |
| `RESOURCE_BUSY` | Another operation still holds this target. The agent's category is `busy`. |
| `HUMAN_DENIED` | A reviewer refused it. The reviewer's comment stays with people. |

## Why a request was refused before admission

A request refused while it was being resolved, before any decision, is answered `EXECUTION_UNAVAILABLE` (bad arguments to an offered action aside, which are `INVALID_REQUEST`). Its `execution.rejected` [audit event](AUDIT_EVENTS.md) records the cause as one of these codes, for people only. When admission refuses with an execution error instead, such as `NO_ACTIVE_BUNDLE`, the event records that error's code, which is listed under [execution codes](#execution-codes).

| Code | When |
| --- | --- |
| `INVALID_OPERATION` | The agent's space does not offer the action: nobody maps it, the space's policy does not name it, or it is reached through another space's account. |
| `INVALID_ARGUMENTS` | The arguments are not the ones the action accepts. |
| `INVALID_TARGET` | The target is unknown or ambiguous, or a hostname was given for an identity action. |
| `INVALID_CONTEXT` | Trusted context the action requires is missing, expired or contradictory, or a claimed incident is not held on the target. |
| `INVALID_IDENTITY` | The agent's identity did not hold while the request was resolved. |
| `INVALID_CLOCK` | The deployment's clock gave a time with no time zone. |
| `INVALID_RUN` | The agent run the request names is not live: unknown, not yet issued, or expired. |
| `STALE_AUTHORIZATION` | A request held for approval was sent again after what it was frozen with changed: the active bundle, the target, the trusted context, or the approval's expiry. |
| `DEPENDENCY_UNAVAILABLE` | Something resolution needs could not be reached. |
| `INVALID_CONFIGURATION` | The action is mapped through an account another space owns. |
| `INVALID_BUNDLE` | The space's policy names the action at a mapping reference that has since changed. |
| `DEPENDENCY_OR_CONTEXT_UNAVAILABLE` | Admission met an unexpected database or value error, which is recorded with this generic reason rather than a cause. Before September 28, 2026 every resolution refusal but bad arguments was recorded this way, so an older record does not say which cause it was. |

## Console API codes

Every refusal of the console API carries one of these, with the status beside it and the sentence it always has.

| Code | Status | Sentence |
| --- | --- | --- |
| `INVALID_REQUEST` | 400 | The request was not understood. |
| `INVALID_BODY` | 400 | The body has a field that is missing, unknown or out of bounds. `fields` names which. |
| `INVALID_FACTOR` | 400 | That code could not be used. A second-factor code asked for in place was wrong, already used, or refused while too many attempts have failed. |
| `INVALID_PRINCIPAL` | 400 | That principal cannot be changed from here. |
| `INVALID_CONTINUATION` | 400 | What you are acting on changed since it was read; open it again. |
| `SIGNAL_MAPPING_ONLY` | 400 | An action here is served only by a signal mapping. |
| `MAPPINGS_CONFLICT` | 400 | Two mappings for an action here cannot share one policy. |
| `SESSION_REQUIRED` | 401 | Sign in to continue. |
| `MFA_REQUIRED` | 401 | Verify your identity to continue. |
| `FORBIDDEN` | 403 | This is not yours to do. |
| `TOKEN_NOT_ALLOWED` | 403 | A personal access token can't do this. Sign in to the console to do it. |
| `INVALID_CSRF` | 403 | The request did not carry the session's token. |
| `INVALID_ORIGIN` | 403 | The request came from somewhere else. |
| `DIRECTORY_REQUIRED` | 403 | Use this workspace's organization sign-in to continue. |
| `NOT_FOUND` | 404 | There is nothing here. |
| `METHOD_NOT_ALLOWED` | 405 | This address does not take that method. |
| `CONFLICT` | 409 | Something changed first. Also the code for any execution code answered 409. |
| `INVALID_BUNDLE` | 409 | This bundle's content cannot be used as it stands. |
| `WORKSPACE_CHANGED` | 409 | The workspace changed. Reload before continuing. |
| `ALREADY_DECIDED` | 409 | Your decision on this approval is already recorded. |
| `SPACE_ARCHIVED` | 409 | This space takes no new work. |
| `LAST_ADMIN` | 409 | Keep at least one active workspace Administrator. |
| `GROUP_IN_USE` | 409 | Remove group members and roles, then disable its approval rules before deleting it. |
| `APPROVAL_EXPIRED` | 409 | This approval has expired; the agent must ask again. |
| `ASSISTANT_OFF` | 409 | The assistant is not turned on for this tenant. |
| `INVALID_PROPOSAL` | 409 | The assistant could not draft that rule. |
| `PLAN_LIMIT` | 409 | This workspace has reached its agent limit. Every agent you have keeps running. |
| `SAMPLES_NOT_OFFERED` | 409 | Sample targets are added only to a workspace with no policy and no connections of its own, and are not re-created while a policy depends on them. |
| `SAMPLES_BUSY` | 409 | A sample request is waiting for approval or provider evidence; settle it first. |
| `SAMPLES_UNAVAILABLE` | 409 | Sample targets are not available on this deployment. |
| `INVITATION_PENDING` | 409 | There is already a pending invitation for that address. |
| `ALREADY_MEMBER` | 409 | That address already belongs to someone in this workspace. |
| `RESEND_LIMIT` | 409 | This invitation cannot be resent again yet. |
| `PRINCIPAL_REPLACED` | 409 | This person rejoined through an invitation and now has a new entry in this workspace. Manage their access there. |
| `TOO_MANY_TOKENS` | 409 | You already have ten active tokens. Revoke one to create another. |
| `CONNECT_UNAVAILABLE` | 409 | Connecting from the console is not set up on this deployment. For Tines, its runtime configuration gives no collector key, so a provider key pasted in the console could not be sealed; for Microsoft Entra, it names no platform app for a directory administrator to consent to. Minting or rotating a reporting source is refused the same way wherever Tines cannot be connected from the console; reading and revoking a source are not. |
| `CONNECTION_EXISTS` | 409 | This Space already has an active connection for that platform. |
| `CONNECTION_CAPACITY` | 409 | This workspace has as many monitoring connections as it can hold: 20, revoked ones included. |
| `SOURCE_CAPACITY` | 409 | This workspace has as many reporting sources as it can hold: 100, revoked ones included. |
| `SOURCE_EXISTS` | 409 | This Space already has a reporting source for that story: rotate its token instead. A source that has kept its 10,000 events, which rotation does not reset, refuses no new one, so its story is added again before it is revoked. |
| `TOO_LARGE` | 413 | The body is too large. |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Send JSON. |
| `SPACE_REQUIRED` | 422 | Choose an active Space before creating this item. |
| `STOPPED` | 423 | The tenant is stopped. |
| `ATTEMPT_CAPACITY` | 429 | Too many connection attempts. Try again later. A workspace holds at most five Microsoft Entra consent attempts at once and twenty in any day. |
| `TOO_MANY_REQUESTS` | 429 | Too many requests; try again shortly. |
| `UNAVAILABLE` | 503 | ExecBound is unavailable; try again shortly. |

## Command codes

The owner commands act through the owner database connection, and the bundle, export and run commands as an administrator with a credential file. A command that refuses prints what refused it and the code to standard error, such as `Administration refused: INVALID_ACTOR.`, and exits 2. A code with the same name means the same kind of fault in every family below, but each family lists its own causes. Several codes are raised by the same functions the console calls; the console answers those with its own codes, and some codes below are reached only that way, as their rows say.

### Administration

The owner commands for tenants, principals and people, credentials, connector accounts, mappings, targets and resources, groups, approver assignments, executor keys and authentication failures print these as `Administration refused: CODE.`. The space commands print a space's own codes the same way; they are listed under [spaces](#spaces).

| Code | When |
| --- | --- |
| `ADMINISTRATION_UNAVAILABLE` | The database failed or refused the operation without a specific code: a lost connection, a statement or lock timeout, or a constraint such as a `--tenant` id on `tenant-create` or an `--account` id on `account-create` already in use. Details are withheld; check the database and retry. |
| `EMAIL_TAKEN` | `person-invite` would create a person with an address that a person in another tenant already holds. One address belongs to one person across the whole deployment. |
| `INVALID_ACCOUNT` | The `--account` of `mapping-create` or `resource-create` is not an active connector account of the tenant. |
| `INVALID_ACTION` | `mapping-create --action` is not an action the `--account`'s provider performs. The approver commands also refuse an action outside the catalog, which the command line's own choices normally catch first. |
| `INVALID_ACTOR` | The `--actor` is not an active administrator of the tenant, or is missing where one is required: only a tenant's first ADMIN may be created by `principal-create` or `person-invite` without one. Space commands also refuse an administrator who is a member of any space. |
| `INVALID_ALIAS` | `resource-create` refused an alias: `--alias-days` is outside 1 to 3660, `--hostname` was given for a resource that is not an endpoint, is not a valid hostname or looks like a secret, or the provider id or hostname is already an unexpired alias on that account. |
| `INVALID_CLOCK` | A caller supplied a time with no time zone. The owner commands always use the current UTC time, so an operator running them should not see it. |
| `INVALID_COMMAND` | An owner command reached no handler. The command line sends only owner commands this way, so it means a release added a command without one; report it. |
| `INVALID_CONNECTION` | The owner connection (`MIGRATION_DATABASE_URL`) does not connect as the role that owns ExecBound's tables, for example because it holds the runtime role's address. Use the owner role's connection. |
| `INVALID_CONTRACT` | `mapping-create --contract-version` names a context contract that does not serve the action and its resource type. Leave the option off to use the catalog's default contract. |
| `INVALID_CREDENTIAL` | `credential-revoke --credential` is not a credential of the tenant, or it is already revoked. |
| `INVALID_EMAIL` | `person-invite --email` is not a usable address (no spaces, one `@`, a dotted domain, at most 254 characters once normalised), or its domain looks like a secret. |
| `INVALID_FACT` | `resource-create` was given a fact (`--role`, `--privilege-class`, `--environment` or `--criticality`) that the resource type's contract does not store as inventory, or a value outside that fact's allowed values or range. |
| `INVALID_GROUP` | `group-assign --group` is not a group of the tenant. `group-list` shows the tenant's groups. |
| `INVALID_KEY` | An executor key command was refused: the key id is malformed, already used or looks like a secret, `--new-key-id` equals `--key-id`, the public key is malformed, weak, unreadable, already live or reported compromised, or the named key is unknown, already revoked or already reported compromised. |
| `INVALID_KIND` | `principal-create --kind` is not AGENT, HUMAN_APPROVER or ADMIN, or `person-invite --kind` is not ADMIN or HUMAN_APPROVER. The command line's own choices normally catch this first. |
| `INVALID_LABEL` | `person-invite --label` is blank or over 80 characters after trimming, or looks like a secret such as a token or key. |
| `INVALID_LIFETIME` | `--lifetime-hours` is out of bounds: `credential-issue` accepts 1 to 2160 hours (90 days) and `person-invite` accepts 1 to 336 hours (14 days). |
| `INVALID_MEMBERSHIP` | `group-assign`: the agent is already in that group, or already belongs to the maximum of 64 groups. `group-unassign`: the principal is not a member of that group. |
| `INVALID_NAME` | The name is refused: `tenant-create --name` is blank or over 120 characters, `group-create --name` is blank, over 80 characters, looks like a secret or is already another group's, or a `space-create` or `space-rename` name is blank or over 80 characters. |
| `INVALID_PRINCIPAL` | The principal does not fit the command: `credential-issue --principal` is not an active principal of the tenant, `approver-assign --approver` is not an active approver or administrator, `group-assign --principal` is not an active agent, or `person-invite --email` belongs to a deactivated person or one of another kind. |
| `INVALID_PROVIDER` | `account-create --provider` is not a provider in the action catalog. The command line's own choices normally catch this first. |
| `INVALID_PROVIDER_ID` | `resource-create --provider-id` is not 1 to 128 letters, digits, `.`, `_`, `:` or `-`, looks like a secret, or already names a resource of that type on the account. |
| `INVALID_REFERENCE` | The `mapping-create --ref` (the action name when omitted) must start with a lowercase letter and hold at most 80 lowercase letters, digits, `.`, `_` or `-`. It is also refused when it looks like a secret or another mapping of the tenant already uses it. |
| `INVALID_RESOURCE_TYPE` | `resource-create --resource-type` is not `endpoint` or `identity`. The command line's own choices normally catch this first. |
| `INVALID_SCOPE` | `approver-unassign` found no active assignment for that approver, target and action, so there is nothing to remove. |
| `INVALID_SOURCE` | `resource-create --source` is not an active inventory context source of the `--account`. An incident source, an inactive source or another account's source is refused. |
| `INVALID_SPACE` | The `--space` is not one of the tenant's spaces, or none was given to `principal-create`, `approver-assign` or `account-create` while the tenant has more than one. `person-invite` of a new approver is refused the same way in a tenant with several spaces. |
| `INVALID_STATE` | `executor-key-revoke` would retire the tenant's last live executor key while a space's selected policy bundle declares an external executor. Register or rotate in a replacement first; a stolen key is cut off with `executor-key-compromise` instead. |
| `INVALID_TARGET` | The `--target` of `approver-assign` or `resource-create` is not a canonical target of the tenant. Create one with `target-create`, or leave `--target` off `resource-create` to have one made. |
| `INVALID_TENANT` | The `--tenant` is not an existing, active tenant. `failures` also refuses when given neither `--tenant` nor `--unattributed`. |
| `INVALID_VERSION` | `mapping-create --mapping-version` or `resource-create --version` is empty, over 80 characters or looks like a secret. |
| `INVALID_WINDOW` | `failures --since-hours` must be more than 0 and at most 2160 (90 days). |
| `OUTPUT_UNAVAILABLE` | `credential-issue` or `person-invite` could not create `--output` as a new private file: it already exists, or its directory is missing or not writable. The command never overwrites a file, so choose a new path. |

### Spaces

`space-create`, `space-rename`, `space-archive`, `space-unarchive`, `space-assign` and `space-unassign` print these as `Administration refused: CODE.`.

| Code | When |
| --- | --- |
| `CONFLICT` | The space is not in a state the change allows: `space-archive` names a space that is already archived or is the tenant's last unarchived space, or `space-unarchive` names a space that is not archived. |
| `INVALID_ACTOR` | The acting principal is not a tenant administrator: it must be an active administrator with workspace-wide authority, not one seated as a member of a space. |
| `INVALID_NAME` | `space-create` or `space-rename`: the name is blank, over 80 characters or looks like a secret, or `--detail` is over 160 characters. `space-archive` or `space-unarchive`: the `--reason` is blank, over 500 characters or looks like a secret. |
| `INVALID_PRINCIPAL` | `space-assign --principal` is not an active administrator or approver of the tenant, or `space-unassign --principal` holds no membership in that space. |
| `INVALID_ROLE` | `space-assign --role` is not ADMIN or HUMAN_APPROVER, or is ADMIN for a principal who is not an administrator. A space role can narrow what a person is, never raise it. |
| `INVALID_SESSION` | Switching a console session's current space failed because the session is unknown, expired or revoked; sign in again. The owner commands do not produce it. |
| `INVALID_SPACE` | The `--space` is not one of the tenant's spaces. In the console and API it also refuses a space the person cannot see, or a write with no single space to land in, which needs a space chosen first. |
| `INVALID_TENANT` | The tenant is unknown, inactive or not set for the call. The owner commands check the tenant before the space rules, so they normally report it there under the same code. |
| `LAST_TENANT_ADMIN` | `space-assign` would seat the tenant's last tenant administrator in a space, narrowing them and leaving no workspace-wide administrator. Make another tenant administrator first. |
| `NAME_TAKEN` | `space-create` or `space-rename`: another space of the tenant already has that name, compared without regard to case. |
| `SPACE_ARCHIVED` | `space-assign` names an archived space, which takes no new members. Unarchive it with `space-unarchive` first. |
| `SPACE_UNAVAILABLE` | A space change failed without a recognised refusal, for example a database error or timeout. The diagnostic is withheld; check the database and retry. |

### Provisioning

The trusted context commands (`context-source-create`, `context-source-deactivate` and `context-import`) and the signal source commands (`signal-source-create`, `signal-source-rotate`, `signal-source-revoke` and `signal-source-list`) print these as `Provisioning refused: CODE.`. A manifest import adds the entry it refused, as ` at entry 3`. One message is not a refusal: when `context-import`'s import has committed and only its `--report` file could not be written, the command prints the manifest digest and counts as usual and exits 2 with `Provisioning imported the manifest, but the report was not written: REPORT_UNAVAILABLE.`.

| Code | When |
| --- | --- |
| `AMBIGUOUS_FACT` | `context-import` refused an entry naming a fact, in `facts` or `retract`, that the context contract catalog stores in different places for that resource type and manifest kind, or derives in one contract and stores in another. |
| `DERIVED_FACT` | `context-import` refused an entry naming, in `facts` or `retract`, a fact the context contract catalog derives rather than stores, so no manifest can write it. Remove that name from the entry. |
| `FUTURE_OBSERVATION` | `context-import` refused an entry whose `observed_at` is more than 60 seconds ahead of the importing host's clock. Check the clocks of the system that produced the manifest and of this host. |
| `INCIDENT_RELINKED` | `context-import` refused an incident entry whose `incident_id` is already stored against a different resource. An incident stays bound to its first resource; a ticket that moved to another asset needs a new incident identifier. |
| `INVALID_ACCOUNT` | The account is not an active connector account of the tenant: `--account` for `context-source-create`, or the manifest's `account_id` for `context-import`. |
| `INVALID_ACTOR` | `--actor` is not an active ADMIN principal of the tenant. Every provisioning change is audited under that actor, so name an active ADMIN. |
| `INVALID_CAPABILITY` | `signal-source-create` was given a `--capability` that is unknown or repeated. Only `resource_compromise.v1` exists, and it is the default when the option is left out. |
| `INVALID_CLOCK` | The time a command checked against has no timezone. The commands always read the system clock in UTC, so this reaches only a program that calls the provisioning code directly with its own time. |
| `INVALID_CONNECTION` | `MIGRATION_DATABASE_URL` connects as a role that does not own the ExecBound tables. Provisioning writes only over the owner connection; point the variable at the schema owner role. |
| `INVALID_GRACE` | `signal-source-rotate` was given a `--grace-seconds` outside 0 to 3,600. Zero stops the old token at once. |
| `INVALID_GROUP` | `signal-source-create` was given a `--group` that is not a principal group of the tenant. |
| `INVALID_INPUT` | A signal source command received a tenant or source that is not a UUID, or a flag that is not true or false. The command line checks these itself, so this reaches only a program calling the provisioning code directly. |
| `INVALID_INPUT_PATH` | `signal-source-create` was given an input path other than `independent` or `agent_forwarded`. The command line refuses such an `--input-path` as a usage error first, so this reaches only a program calling the provisioning code directly. |
| `INVALID_KIND` | `context-source-create` was given a kind other than `inventory` or `incident`. The command line refuses such a `--kind` as a usage error first, so this reaches only a program calling the provisioning code directly. |
| `INVALID_LABEL` | `signal-source-create` was given a `--label` that does not start with a letter or digit, runs past 96 characters, holds a character other than letters, digits, spaces, `.`, `_`, `:` or `-`, or looks like a password, key or token. |
| `INVALID_LIFETIME` | `signal-source-create` or `signal-source-rotate` was given `--hours` outside 1 to 720 (30 days). |
| `INVALID_MANIFEST` | The `context-import` manifest is not valid JSON in the context manifest format: an unknown, missing or malformed field, a bound exceeded, a duplicate entry, or an entry that states nothing or does not fit the kind. Also an entry holding text shaped like a secret. |
| `INVALID_PRINCIPAL` | `signal-source-create` was given a `--principal` that is not an active agent of the tenant. A source can vouch only for active agents. |
| `INVALID_PRODUCER` | `signal-source-create` was given a `--producer` that does not start with a lowercase letter, runs past 64 characters, holds a character other than lowercase letters, digits, `.`, `_` or `-`, or looks like a password, key or token. |
| `INVALID_SCOPE` | `signal-source-create` was given the same `--principal` twice, or more than 64 of them. Naming neither or both of `--principal` and `--group` is refused earlier as a usage error. |
| `INVALID_SOURCE` | For `context-import`, the manifest's `source_id` is not an active source of its account and kind. For `context-source-deactivate`, `--source` is unknown or already inactive. For `signal-source-rotate` or `signal-source-revoke`, `--source` is not a signal source of the tenant. |
| `INVALID_SPACE` | `signal-source-create` was given a `--space` that is not a space of the tenant, or left it out when the tenant has no space or more than one. Name the space with `--space`. |
| `INVALID_STATE` | `signal-source-rotate` or `signal-source-revoke` named a source that is already revoked. Revocation is final; register a new source instead. |
| `INVALID_TENANT` | `--tenant` does not name an active tenant. Nothing was changed. |
| `INVALID_VALUE` | `context-import` refused an entry with a fact value of the wrong exact type, or outside the domain a contract declares for that fact. |
| `INVALID_VERSION` | `signal-source-create` was given a `--version-min` or `--version-max` that is not three dot-separated numbers without leading zeros, such as `1.4.0`, or a minimum above the maximum. |
| `INVALID_WRITER` | `context-source-create` was given more than 16 `--writer` labels, a repeated one, or one that is not a lowercase letter followed by up to 63 lowercase letters, digits, `.`, `_` or `-`, or looks like a secret. For `context-import`, the manifest's `writer` is not one its source allows. |
| `MANIFEST_TOO_LARGE` | `context-import` refused a `--manifest` file larger than 16 MiB without loading it. Split the entries across several manifests. |
| `OBSERVATION_REGRESSION` | `context-import` refused an entry whose `observed_at` is earlier than the observation already stored for the resource, fact or incident it touches. Import manifests in observation order; an older export cannot overwrite a newer one. |
| `OUTPUT_UNAVAILABLE` | `signal-source-create` or `signal-source-rotate` could not create `--output` as a new private file, because the path already exists or its directory is missing or not writable. Nothing was registered or rotated; choose a new path. |
| `PROVISIONING_UNAVAILABLE` | The database could not be reached or refused a statement, including one running past 60 seconds or waiting past 5 seconds for a lock. The transaction rolled back and nothing changed; retry once the database is available. |
| `REPORT_UNAVAILABLE` | `context-import` could not create the `--report` file as a new private file: the path exists or its directory is missing or not writable. The file is created before the import, so nothing was imported. Name a new file and run the import again. Read after `Provisioning imported the manifest, but the report was not written:`, the file was created but writing it failed once the import had committed, for example on a full disk: the import stands and is audited, the digest and counts are printed, and the partial file is removed. Do not import the manifest again to get the report, because a second import changes nothing and reports every entry `unchanged`. |
| `TENANT_MISMATCH` | `context-import` refused a manifest whose `tenant_id` differs from `--tenant`. |
| `UNKNOWN_FACT` | `context-import` refused an entry naming, in `facts` or `retract`, a fact no context contract declares for that resource type and the manifest's kind. |
| `UNKNOWN_RESOURCE` | With `--strict`, `context-import` refused an entry naming a resource (`provider`, `resource_type`, `provider_id`) not registered under the manifest's account. Without `--strict` the entry is skipped and counted in `unknown_resources`. |
| `VERSION_REUSED` | `context-import` refused an entry that changes a stored fact value, an incident's status or severity, or the attesting source, while keeping the stored row's `version`. Give changed content a new version label. |

### Policy bundles

The bundle commands (`bundle-create`, `bundle-validate`, `bundle-activate`, `bundle-retire`, `bundle-list` and `bundle-preview`) print these as `Policy store refused: CODE.`, adding the field that failed validation when there is one, as ` at limits.0.group_id`.

| Code | When |
| --- | --- |
| `INVALID_BUNDLE` | No bundle with this id exists in the tenant, or the administrator may not manage policy in its space; a stored bundle failing its own consistency checks reads the same. Creating one is also refused when a mapping names another space's connector account. |
| `INVALID_CLOCK` | The deployment's clock gave a time with no time zone. A configuration fault, not a problem with the bundle. |
| `INVALID_COMPONENT` | A component does not hold against the tenant now: a mapping missing, inactive or changed since writing, a limit naming an unknown action, group, account, space or fact, a quorum rule naming no approval, context settings the contracts refuse, or an unusable checkpoint or signal mapping. Cedar refusing the bundle's own text reads the same, at `cedar_schema` when the schema does not validate on its own, and otherwise at the first of `authorization_policies` and `approval_policies` that does not validate against it, such as a `forbid` among the approval policies. Cedar's own diagnostics are never shown. |
| `INVALID_REASON` | `bundle-activate --reason` was given a reason that is blank once trimmed, longer than 500 characters, or shaped like a secret, such as a token or key. The value is never printed. Give a plain reason, or none. |
| `INVALID_IDENTITY` | The credential is not a current administrator of this tenant: it belongs to another tenant, is not an ADMIN's, has expired or been revoked, its holder or tenant is inactive, or its holder may not manage policy in the space concerned. |
| `INVALID_RULESET` | An edit to a draft's rules does not compile, for example a rule naming an undeclared fact or a value outside its domain. Only the console edits rules, and it reports this as an invalid body naming the rule's field. |
| `INVALID_STATE` | The bundle's state does not allow the step: validating anything but a draft, activating a bundle not validated or already selected in that space, or retiring one already retired or still selected by a space. Select another bundle there first. |
| `INVALID_TEXT` | The bundle holds text shaped like a secret, such as a token or key, in the field the location names. The value is never printed. Remove it and create the bundle again. |
| `INVALID_WINDOW` | The preview window is not more than zero and at most 30 days. Give `--window-hours` between 1 and 720. |
| `NO_ACTIVE_BUNDLE` | The space selects no policy bundle, so agents there are refused until one is activated, and the console cannot copy an active policy that does not exist. Activate a validated bundle. |
| `POLICY_UNAVAILABLE` | The policy store could not finish the step: the database failed or returned something unexpected, or the Cedar engine failed outright rather than refusing the bundle's text. Nothing changed. Check the database and try again. |
| `PREVIEW_UNAVAILABLE` | The preview could not replay the tenant's history against the bundle: the history export failed, for example because it exceeds the export's size limits, or the export did not verify or could not be simulated. Nothing was activated. |
| `RULESET_MISMATCH` | The bundle carries rules, and its compiled components differ from what those rules compile to against the current mappings, or the rules no longer compile. The location names the component or rule field. Compile the rules again and create the result as a new bundle. |
| `SPACE_ARCHIVED` | The space a new draft would belong to is archived and takes no new work. `bundle-create` writes in the tenant's first space, so it is refused while that space is archived. |

### Teammate invitations

`invitations-run`, which sends the invitation emails that are due, prints these as `Invitations run refused: CODE.`. Inviting someone and accepting an invitation happen in the console, which answers with its own codes, from [the console API's list](#console-api-codes).

| Code | When |
| --- | --- |
| `ACCOUNT_EXISTS` | Accepting with a new password is refused because an account, or an active person set up before accounts existed, already uses the invited address. Sign in with that account, then accept the invitation. |
| `ACCOUNT_MISMATCH` | Accepting while signed in is refused because the account sign-in could not be confirmed (missing, stale, or still waiting for its second factor), or the account is inactive or uses a different address from the invitation's. Sign in as the invited address and try again. |
| `ALREADY_MEMBER` | When inviting, an active person in this workspace already has the address, or an account with it is already an active member. When accepting, the signed-in account is already an active member. A removed member can be invited again. |
| `CONFLICT` | At acceptance, applying the invitation's roles collided with an existing record, such as the same role and Space named twice. Creating an invitation already refuses repeated pairs, so this is not expected in normal use. |
| `FORBIDDEN` | The person creating, resending, revoking or listing invitations is not an active member allowed to manage access, or the workspace is inactive. At acceptance, the inviter has since been deactivated or lost that permission; ask a current administrator for a new invitation. |
| `INVALID_CLOCK` | The application's clock and the database's clock differ by more than five minutes, so an administrator's change or an acceptance is refused. An operator corrects the server clock. |
| `INVALID_CONFIGURATION` | The invitations run has no mail settings in its runtime configuration, so it cannot send anything. Add the mail block and run it again. |
| `INVALID_DIGEST` | While minting a fresh link for a send, the database refused a malformed link hash. The send counts this as a temporary failure and retries later, so it does not reach a person. |
| `INVALID_EMAIL` | The address is not a valid email address once trimmed and lowercased, fails the database's own address check, or has a domain shaped like a secret such as a key or token. Check the address. |
| `INVALID_GROUP` | The reviewer group named for an Approver invitation is not a group of this workspace, carries the Administrator or Policy manager role, or carries a role the invitation does not give in that Space; or the invitation does not grant the Approver role. Choose another group, or none. The console names it as `INVALID_BODY` on `reviewer_group_id`. |
| `INVALID_LIMIT` | The invitations run was given a limit that is not a whole number from 1 to 50. Pass a value in that range, or leave the default of 50. |
| `INVALID_PASSWORD` | The new password chosen while accepting is not 12 to 200 characters long, or is the invited address itself. Choose a different password. |
| `INVALID_PRINCIPAL` | At acceptance, the invitation's roles could not be applied because the new person record is not an active person who can hold roles. This is not expected in normal use. |
| `INVALID_REQUEST` | An acceptance must carry exactly one proof of the person, a new password or a signed-in account, and this one carried both or neither. Also raised when a request lacks a workspace, invitation or link value the database needs. |
| `INVALID_ROLE` | A grant's role is missing or is not one of administrator, policy manager, approver or viewer. The same check runs again when the invitation is accepted. |
| `INVALID_ROLES` | The role grants are not a list, the list is empty or has more than 20 entries, an entry holds fields other than a role and a Space, or the same role and Space appear twice. |
| `INVALID_ROLE_SCOPE` | A grant limits the administrator role to one Space. Administrator always covers the whole workspace, so leave its Space empty. |
| `INVALID_SPACE` | A grant's Space is not a valid identifier or names no unarchived Space in this workspace. At acceptance, a Space archived since the invitation was sent is refused the same way; send a new invitation. |
| `INVALID_STATE` | Revoking an invitation that is no longer pending, or resending one that is no longer pending or has expired. Resending never extends an invitation, so an expired one needs a new invitation. Also raised when a reviewer group is named for an invitation that already names one. |
| `INVALID_TENANT` | At acceptance, the workspace the invitation belongs to is no longer active, so nobody can join it. |
| `INVALID_TOKEN` | The link is malformed or no longer matches (a later send replaced it, or repeated wrong attempts locked it), the invitation has expired, or a different account already accepted it. Ask an administrator to resend or send a new invitation. |
| `INVITATION_PENDING` | The address already has an unexpired pending invitation to this workspace. Resend or revoke that one instead; an expired pending invitation is replaced automatically. |
| `INVITATION_REVOKED` | An administrator revoked this invitation, so its link no longer joins the workspace. Ask for a new invitation. |
| `INVITATION_UNAVAILABLE` | The default: a database fault or an unrecognized refusal while creating, changing, listing, checking or accepting an invitation. Nothing more specific is shown, because a database message could quote an address; try again later. |
| `LAST_ADMINISTRATOR` | At acceptance, applying the invitation's roles would leave the workspace with no active person who can manage access. Acceptance only adds roles to a new person, so this is not expected in normal use. |
| `NOT_FOUND` | Resending or revoking names an invitation that does not exist in this workspace. |
| `RESEND_LIMIT` | The invitation has already been sent five times, a send is still waiting or under way, or one was delivered less than two minutes ago. Wait a few minutes, or revoke it and invite again. |
| `UNSAFE_DRAIN_POLICY` | The invitations run found the database rule that lets it see due invitations in every workspace missing or altered, and stops rather than silently send nothing. Check that the migrations ran under the role that owns the invitation functions. |

### The assistant

`tenant-assistant`, which switches the assistant on or off, prints these as `Emergency stop refused: CODE.`, the phrase every tenant command shares, and `recover` prints one as `Recovery refused: CODE.` when its sweep of old assistant text fails. Asking a question and drafting a rule happen in the console, which answers with its own codes. Drafting a rule from a sentence can also be refused with a [policy bundle](#policy-bundles) code.

| Code | When |
| --- | --- |
| `ASSISTANT_OFF` | The assistant is switched off for this workspace, so no question or rule draft starts. An administrator turns it on, giving a reason. |
| `ASSISTANT_UNAVAILABLE` | The default: a database function refused the assistant with a code outside the known list, or failed outright. Nothing more specific is shown; try again later. |
| `INVALID_ACTOR` | The database's own check found that the asking person is not an active approver or administrator of this workspace, or, for retiring old text, not an active administrator. |
| `INVALID_ANSWER` | Recording a finished turn was refused because a completed turn had no answer or carried a failure reason, or its cited records or tool list were malformed. This is an internal check, not expected in normal use. |
| `INVALID_BUNDLE` | Drafting a rule names a policy draft that does not exist in this workspace, that the person cannot manage policy for, or whose stored content fails its integrity check. |
| `INVALID_CONTEXT` | What the turn is about is not a question, execution, approval, finding, agent or policy change, a free question carried a record id or an explanation lacked one, or the record could not be read with the arguments given. |
| `INVALID_IDENTITY` | The credential or session is not a current person's: expired, revoked, deactivated, or an agent's. Switching the assistant needs a workspace administrator, retiring text an administrator, and drafting a rule needs policy management. A failed scheduled-sweep identity check reads the same. |
| `INVALID_MODEL` | The operator's configured model name is empty or longer than 80 characters, so no turn can be recorded. Correct the assistant's model setting. |
| `INVALID_PROPOSAL` | A rule drafted from a sentence could not be offered: the answer was not a valid rule, reused a rule id already in the draft, held a value shaped like a secret, or would not compile against the draft. The refusal names the field; try rewording. |
| `INVALID_QUESTION` | The question is empty or longer than 1,000 characters. Shorten it and ask again. |
| `INVALID_REASON` | Switching the assistant on or off needs a reason of 1 to 500 characters that does not look like a secret. The database also refuses a failed turn recorded without a reason from its fixed list, an internal check. |
| `INVALID_STATE` | The switch is already in the requested position; a turn being written to has already finished; or a rule draft was asked for on a policy that is not a draft written as rules, or whose own rules do not compile. |
| `INVALID_STEP` | A reading step the assistant tried to record is empty or longer than 200 characters. Steps are shortened before they are recorded, so this is not expected in normal use. |
| `INVALID_TENANT` | The request reached the database with no workspace, or the workspace is no longer active, so no turn can be recorded or retired. |
| `INVALID_TURN` | The turn named does not exist or is not one of this person's own, since turns are private to whoever asked; or the record a person asked to have explained was not found or is not readable by them. |
| `INVALID_USAGE` | Recording a finished turn was refused because its token counts were missing or negative. This is an internal check, not expected in normal use. |
| `MODEL_ERROR` | Drafting a rule from a sentence failed at the model: the request could not be made or the answer could not be read. The turn is recorded as failed, and the console answers `INVALID_PROPOSAL`. |
| `PERSON_LIMIT` | This person has started as many turns in the past hour as the operator's cap allows, 20 by default; rule drafts count too. Wait and ask again later. |
| `REFUSED_SECRET` | The record a person asked to have explained contains a value shaped like a secret, so nothing is sent to the model and no turn starts. A turn that meets such a value while reading ends failed with this reason. |
| `STEP_LIMIT` | A turn records at most 16 reading steps, and this one reached that bound. It happens only when the operator allows more reads per turn than that; the turn stops and later shows as abandoned. |
| `TENANT_LIMIT` | Turns started in this workspace in the past 24 hours have used the operator's daily token cap, 200,000 by default. New turns are refused until older ones age out of that window. |
| `TOKEN_LIMIT` | Drafting a rule from a sentence stopped because the model's answer reached its length limit before it was complete. The turn is recorded as failed, and the console answers `INVALID_PROPOSAL`. |

### Plugins

The gateway and every command load the first-party plugins the configuration names before anything else. A plugin that cannot be loaded stops the gateway from starting, and a command prints `Plugin refused: CODE.` or `Command refused: CODE.` and exits 2. A plugin can also refuse with a code of its own while its pages are built, which that plugin documents.

| Code | When |
| --- | --- |
| `COMMAND_CONFLICT` | A plugin's command has the name of a command the command line already has. Printed by the command line itself before any command runs. |
| `INVALID_APPROVAL_LINKS` | A plugin registered approval links that are not the expected object, or registered them twice. A defect in the plugin. |
| `INVALID_CLAIM` | A plugin claimed a database object outside the dormant catalog, a privilege outside the allowed set, nothing at all, both a whole-table and a column grant of one privilege, or the same object twice. A defect in the plugin. |
| `INVALID_COMMAND` | A plugin registered a command that is not the expected object, or whose name is not a lower-case letter followed by up to 39 lower-case letters, digits or hyphens. |
| `INVALID_FEATURE` | A plugin registered a session feature whose name is not a lower-case letter followed by up to 31 lower-case letters, digits or underscores, or whose check cannot be called. |
| `INVALID_PLUGIN_CONFIG` | A plugin's configuration section does not validate against that plugin's settings, or gives settings to a plugin that takes none. A plugin also raises it while the gateway starts when its section needs part of the core configuration that is missing. Correct the section. |
| `INVALID_PLUGIN_NAME` | A name in the plugins map or `EXECBOUND_PLUGINS` is not a lower-case letter followed by up to 31 lower-case letters, digits or underscores. |
| `INVALID_PROVIDER_SIGNUP` | A plugin registered its provider signup point wrongly: not the expected object, a completion step that is not asynchronous, or a refusal page that is not a plain callable. Or it registered one twice. A defect in the plugin. |
| `INVALID_ROUTE` | A plugin path is malformed, reserved for core, starts with a parameter, ends with a slash, can span segments, or lies outside the console API's prefix; or a plugin added a mount, a nested router or catch-all routes, or changed routes core had registered. |
| `INVALID_SERVICE_LINKS` | A plugin's service links are not the expected object, hold a link that is not https with a host, no user information and at most 200 characters, or a malformed support address, or were registered twice. |
| `INVALID_SIGN_IN_LINK` | A plugin's sign-in link is not the expected object, has a label that cannot be called or a path that is not a literal, unreserved path on this site outside `/assets`, or was registered twice. At run time, an unusable label is logged under it and its link hidden. |
| `INVALID_RECOVERY_LINK` | A plugin's recovery link is not the expected object, has a label that cannot be called or a path that is not a literal, unreserved path on this site outside `/assets`, or was registered twice. At run time, an unusable label is logged under it and its link hidden. |
| `INVALID_TOKEN_ROUTES` | A plugin's personal access token classification names a route core already classifies, puts one route in both its allowed and refused sets, names a path outside the console API or a method that is not an upper-case HTTP method, or was registered twice. |
| `NOT_A_PLUGIN` | The module named for a plugin exists but exposes no plugin object, or the object it exposes carries a different name. |
| `PLUGIN_API_MISMATCH` | The plugin was built for a different plugin API version than this release. Install the plugin release that matches; `execbound plugins` shows the API version. |
| `PLUGIN_CONFLICT` | Two plugins, or one named twice in `EXECBOUND_PLUGINS`, collide: the same console path, command, feature, token route or database claim, a second set of approval links, sign-in link, signup point or service links, or plugin service links beside the configuration's `service` block. |
| `PLUGIN_FAILED` | A plugin raised an error while being imported, configured or registered. Its message is withheld because it could carry configuration; the log names the plugin. A running gateway also logs it when a sign-in link's label fails, and hides the link. |
| `ROUTE_CONFLICT` | A plugin path is one that a core route or an earlier plugin route already answers for any method, or the two paths could match the same request. |
| `TOO_MANY_PLUGINS` | More than eight plugins are named. |
| `UNKNOWN_PLUGIN` | No plugin module of that name is installed. Check the spelling in the plugins map or `EXECBOUND_PLUGINS`, or install the plugin. |

### Restore verification

`scripts/verify_restore.py`, which checks a restored database against retained checkpoints ([retention, backup and recovery](RECOVERY.md)), prints these as `Recovery verification stopped: CODE.` and exits 2. With `--check-fence`, a plugin that `EXECBOUND_PLUGINS` names and that cannot load stops it first, printed as `Plugin refused: CODE.` with a code from [Plugins](#plugins).

| Code | When |
| --- | --- |
| `CONFLICTING_CHECKPOINTS` | Two `--checkpoint` files name the same tenant with different heads. Pass one retained checkpoint per tenant; two copies that disagree are worth investigating in their own right. |
| `DATABASE_UNAVAILABLE` | The restored database, or the live one with `--compare-live`, could not be read: the connection or a read failed, or a read ran past its 30-second limit. Check the connection, the owner role and that the restore finished. |
| `INVALID_CHECKPOINT` | A `--checkpoint` file is not a regular file, is empty or larger than 4 KiB, or is not a valid checkpoint head. Use the checkpoint file `audit-export --checkpoint` wrote. |
| `INVALID_DATABASE` | The `--restored-database` name is not a lower-case letter followed by up to 62 lower-case letters, digits or underscores, or `MIGRATION_DATABASE_URL`, read for `--restored-database` or `--compare-live`, or `DATABASE_URL`, read for `--check-fence`, is not a connection URL ExecBound accepts. The URL is never printed. |
| `INVALID_RESTORED_URL` | `--restored-url` is not a connection URL ExecBound accepts: it does not parse, does not use the `postgresql+psycopg` driver, lacks a host, database, user name or password, carries a query option other than the TLS ones, or names a server other than this machine without `sslmode=verify-full` and `sslrootcert`. Nothing was read, and the URL is never printed, because it can hold a password. |
| `NO_RESTORED_DATABASE` | Neither `--restored-url` nor `--restored-database` was given, or `--restored-database` was given without `MIGRATION_DATABASE_URL` set in the environment. |
| `NO_RUNTIME_DATABASE` | `--check-fence` reads the restored copy as the runtime role, through `DATABASE_URL` with the `--restored-database` name substituted, and `DATABASE_URL` is not set, names another instance than `MIGRATION_DATABASE_URL` (another host, or another port; `localhost` and `127.0.0.1` are one), or the restore was named with `--restored-url`, which can be on another instance. Nothing was read. Run the verifier where both URLs point at the instance holding the copy, and name it with `--restored-database`. |
| `OWNER_FENCED` | With `--check-fence`, the owner's reads of the restored copy are made with row-level security off, because each tenant's chain as the runtime role reads it is held to the owner's, and PostgreSQL refused one: the owner does not bypass row-level security and a table it read forces it, or it lacks a privilege on the copy. Nothing was compared, since two reads filtered by the same policies would agree. Run the fence check with an owner that bypasses row-level security, as a superuser does; without `--check-fence` the verifier reads the copy under each tenant's fence as before. |
| `REPORT_TOO_LARGE` | The report would exceed 1 MiB, so none was written. Verify fewer tenants per run, naming them with `--tenant` and `--checkpoint`. With `--check-fence` every tenant the copy holds is in the report whatever is named, and about 2,500 fit, so a copy holding more cannot have its fences checked in one run. |
| `RUNTIME_UNAVAILABLE` | With `--check-fence`, the runtime role could not connect to the restored copy, or a read it makes there failed or ran past its 30-second limit. Check `DATABASE_URL`, that the runtime role exists on the instance and may connect to the copy, and that the restore finished. A read of a tenant's own history that the copy's privileges refuse, or whose rows its policies hide, is not this code: it is reported as that tenant's `HIDES_OWN`. Nor is a read of the startup check that the copy's privileges refuse, as a copy without the schema's `USAGE` refuses its schema revision: that is the report's `RUNTIME_UNSAFE`. |

## The monitoring API

A monitored platform posts its activity to the monitoring intake with a source token, and an administrator registers sources and connections, runs collection, links discovered agents and acknowledges findings. How a code reaches a reader depends on where it was raised:

- **The intake** (`POST /v1/monitor/events`) is the only place that answers with a code and a status: `{"detail": "Monitoring unavailable", "code": "…"}` with the status below. Only `INVALID_EVENT`, `INVALID_SOURCE`, `SOURCE_RATE_LIMIT`, `SOURCE_CAPACITY`, `EVENT_CONFLICT`, `INVALID_CLOCK` and `MONITOR_UNAVAILABLE` answer a platform's post. A post refused before its event is parsed (a query string, a header the intake does not take, a content type other than JSON, a body too large or too slow, eight posts already in progress, or an `Authorization` header that is missing, repeated, not a `Bearer` token or longer than 170 characters) is answered 400, 401 or 429 with only `detail`.
- **A collection run** (`collect-tines` or `collect-entra`) prints its result as JSON. When a refusal met while reading the platform ends the run, it sets the result's `outcome`: `AUTH_LOST` and `RATE_LIMITED` are outcomes of their own, and every other code is the outcome `ERROR`. The connection keeps the code itself, which the console's monitoring page shows as the last collection refusal.
- **The monitoring commands** (`python -m execbound.monitoring.commands`), such as the ones that revoke sources, create and revoke connections, link agents, run collection and process and deliver findings, answer a monitoring refusal by printing only `Monitoring command unavailable. Check configuration, access and local services.` and exiting 2, with no code. That includes a collection run refused before it reads the platform, such as `KEY_MISMATCH`, and one refused while writing what it read, such as `AGENT_CAPACITY`. There are two exceptions, both exiting 2. `process --deliver-local` where the runtime configuration names a findings destination prints `--deliver-local refused: FINDINGS_DESTINATIONS_CONFIGURED.`, and `process --deliver` with no `EXECBOUND_RUNTIME_CONFIG` prints `--deliver needs EXECBOUND_RUNTIME_CONFIG.`. A `process --deliver` whose runtime configuration names a file that does not read still evaluates, without delivery, then logs `monitor.delivery_refused` at `ERROR` with the code `INVALID_CONFIGURATION`, prints `Monitoring command unavailable. Check configuration, access and local services.` and exits 2. A database that fails the runtime check is not a monitoring refusal: they print the sentence `execbound`'s own commands print for it, such as `Database refused: the runtime connection failed its safety check.`, and exit 2 (plugins). `create-source`, `rotate-source` and `init-demo`, which write new credentials to the file named by `--output`, instead print recovery guidance and exit 2, and leave a `.<output-name>.recovery-*` directory beside that file. When nothing was issued, `create-source` and `rotate-source` record the code in that directory, in `not-provisioned.json` for `INVALID_INPUT`, `INVALID_ADMIN`, `SOURCE_CAPACITY`, `SOURCE_EXISTS`, `INVALID_SPACE` or `SPACE_ARCHIVED` and in `not-rotated.json` for `INVALID_INPUT`, `INVALID_ADMIN`, `SOURCE_UNAVAILABLE` or `INVALID_STATE`.
- **The console** answers with its own codes ([console API codes](#console-api-codes)). For its monitoring reads and for acknowledging a finding: `AGENT_UNAVAILABLE` and `FINDING_UNAVAILABLE` become `NOT_FOUND`, `INVALID_ADMIN` becomes `FORBIDDEN` on the monitoring pages, `INVALID_NOTE` becomes `INVALID_BODY` naming `note`, `INVALID_INPUT` from acknowledging several findings at once becomes `INVALID_BODY` naming `finding_ids`, `ACKNOWLEDGED` becomes `CONFLICT`, and every other code, `INVALID_ADMIN` on an agent's page included, becomes `UNAVAILABLE`. For connecting from the console (`/monitor/connect` and `/monitor/connections/…`): a malformed label, team, address, key or schedule becomes `INVALID_BODY` naming its field and other malformed input `INVALID_BODY` naming none, `CONNECTION_UNAVAILABLE` becomes `NOT_FOUND`, `CONNECTION_REVOKED`, `CONNECTION_NOT_SEALED` and `CONNECTION_NOT_CONSENTED` become `CONFLICT`, `INVALID_ADMIN` becomes `FORBIDDEN`, `SPACE_REQUIRED`, `SPACE_ARCHIVED`, `CONNECTION_EXISTS`, `CONNECTION_CAPACITY` and `ATTEMPT_CAPACITY` keep their codes, and every other code becomes `UNAVAILABLE`. For reporting sources (`/monitor/sources`, read, minted, rotated or revoked): `SOURCE_UNAVAILABLE` becomes `NOT_FOUND`, so an unknown source and one outside the session's Spaces answer 404, `INVALID_STATE` becomes `CONFLICT`, so a revoked one answers 409, `INVALID_SPACE` becomes `SPACE_REQUIRED`, `INVALID_ADMIN` becomes `FORBIDDEN`, `INVALID_INPUT` becomes `INVALID_BODY`, `SPACE_REQUIRED`, `SPACE_ARCHIVED`, `SOURCE_CAPACITY` and `SOURCE_EXISTS` keep their codes, and every other code becomes `UNAVAILABLE`. The console's assistant, when it reads findings for a person and the read is refused, is given the monitoring code itself as its tool's answer.

The status beside each code is the one the intake's handler gives it, which is 400 for every code without a status of its own; only the intake's codes are ever sent with it.

| Code | Status | When |
| --- | --- | --- |
| `ACKNOWLEDGED` | 400 | Acknowledging a finding carried a note, but the finding was already acknowledged. An acknowledgement is final, so the note is not saved and nothing changes. |
| `AGENT_CAPACITY` | 400 | A directory collection run found more than 1,000 principals for one connection, in its agent identities, its service principals or the two together, or Graph served one of the two in pages too short for the run to reach its end within the twelve pages it reads. The run reads none of them in part: nothing from that agent snapshot is written, and the connection records the code as its outcome's. A Microsoft Entra delta pass whose changes would leave the connection holding more than 1,000 principals is refused the same way: nothing from its round is written and its delta link is dropped, it is counted in `collect-due`'s `delta_failed`, and the next full collection refuses the directory and records the code. |
| `AGENT_UNAVAILABLE` | 400 | No discovered agent matches: the agent identifier is malformed or unknown in the workspace, the platform reference is not one the connection discovered, or, when linking, the agent is no longer present in the directory. |
| `ATTEMPT_CAPACITY` | 400 | Starting a Microsoft Entra consent would make a sixth attempt live at once, or a twenty-first in a day, in the workspace. Nothing is recorded. The console answers `ATTEMPT_CAPACITY` with 429. |
| `CLIENT_MISMATCH` | 400 | A collection run for a consented Microsoft Entra connection was given the platform app of another client id than the one the directory consented to. Recorded on the connection; nothing is sent to Microsoft. |
| `COLLECTOR_KEY_UNAVAILABLE` | 400 | A collection run found nothing to open its connection with: for a sealed connection, no collector key that opens it (the collector was given none, the key it holds is not the one the connection was sealed to, or the ciphertext is damaged); for a consented Microsoft Entra connection, no platform app credential. Recorded on the connection; nothing is sent to the platform. |
| `CONNECTION_CAPACITY` | 400 | The workspace already holds 20 monitoring connections, revoked ones included, so another cannot be registered. |
| `CONNECTION_EXISTS` | 400 | The space already has an active connection to that kind of platform. Revoke it before registering another. |
| `CONNECTION_NOT_CONSENTED` | 400 | A consent update named a connection that is not a consented Microsoft Entra connection: an operator's connection is changed on the host that holds its key file. The console answers `CONFLICT`. |
| `CONNECTION_NOT_SEALED` | 400 | A key was pasted for a connection that is not sealed: an operator's key file is replaced on the host that holds it. The console answers `CONFLICT`. |
| `CONNECTION_REVOKED` | 400 | A collection run's connection was revoked while the run held it. Nothing more the run read is written, and it stops. |
| `CONNECTION_UNAVAILABLE` | 400 | The connection identifier is malformed or matches no connection in the workspace, or a revocation named a connection that is already revoked. |
| `DIRECTORY_UNAVAILABLE` | 400 | `create-connection` named a Microsoft Entra directory another connection in this deployment already reads, in this workspace or another: a directory is connected once. Nothing is registered, and the refusal names no workspace. |
| `EGRESS_CATALOGUED` | 400 | An address recorded as a Tines tenant's egress is in a range the reviewed egress catalog gives another platform, such as Anthropic's or Make's, so it cannot be this tenant's. Nothing is recorded. The console answers `INVALID_BODY` naming `addresses`. |
| `FINDINGS_DESTINATIONS_CONFIGURED` | 400 | `process --deliver-local` found a destination that lists findings in the runtime configuration `EXECBOUND_RUNTIME_CONFIG` names, so nothing was evaluated or sent. A finding is routed once, so a loopback run would take every pending finding from the configured destinations. Printed by the command, which exits 2. Run `process --deliver` instead. |
| `GRANT_CAPACITY` | 400 | A directory collection run reported more than 200 grants for one agent. None of that run's agent detail is written. |
| `INVALID_BASE_URL` | 400 | The Tines tenant address given in the console is not one, or reads as a secret. The console answers `INVALID_BODY` naming `base_url`. |
| `INVALID_CLOCK` | 400 | The deployment's clock gave a time with no time zone, so the operation stops. A configuration fault, not a fault in the request. |
| `INVALID_CONFIGURATION` | 400 | Delivering findings found an email destination that lists findings and no mail relay in the runtime configuration, so nothing was leased. Add the `mail` block, or take `findings` off the destination. |
| `INVALID_EGRESS` | 400 | The addresses recorded as a Tines tenant's egress are more than eight, repeat one another, or include one that is not a single public address (a network, an address with a zone, a private, shared, loopback, link-local, documentation, benchmarking, multicast or reserved address, one outside IPv6 global unicast, or not an address at all). Nothing is recorded. The store refuses each before the database is asked, and the database refuses more than eight, a repeat, a network and the same blocks again, from one list. The console answers `INVALID_BODY` naming `addresses`. |
| `INVALID_EVENT` | 400 | The body posted to the monitoring intake is not a valid event: not a JSON object, a repeated key, an unknown, missing or malformed field, or a kind whose fields do not match it. Fix the event before sending it again. |
| `INVALID_INPUT` | 400 | A value given to a monitoring operation is malformed or out of bounds, such as a label, a story or platform reference, an expiry not in the future, a heartbeat, grace period or batch size out of range, or a connection's address or key; or a set of findings to acknowledge that is empty, longer than 50 or names one twice. |
| `INVALID_KEY` | 400 | The API key pasted in the console is not printable ASCII without spaces, or is longer than 4,096 characters. The console answers `INVALID_BODY` naming `api_key`, and never repeats the key. |
| `INVALID_LABEL` | 400 | A connection's name given in the console is not 1 to 96 printable characters, or reads as a secret. The console answers `INVALID_BODY` naming `label`. |
| `INVALID_LIMIT` | 400 | The batch size for processing findings or delivering notifications is not a whole number from 1 to 50. |
| `INVALID_NOTE` | 400 | The note given with an acknowledgement is longer than 500 characters after trimming, is not printable text (line breaks aside), or is shaped like a password, key or token. It is never repeated, and nothing is acknowledged. |
| `INVALID_NOTIFICATION` | 400 | A finding's notification is larger than 4,096 bytes, or holds a value outside what a message may carry, so it is not sent and the delivery run stops. |
| `INVALID_RECEIVER` | 400 | The alert receiver configured for notifications is refused. It must be exactly `http://127.0.0.1:<port>/alerts` on the same machine, with a shared secret of 32 to 256 ASCII characters. |
| `INVALID_SCHEDULE` | 400 | A schedule is outside its kind's range: Entra collects every 3,600 to 86,400 seconds and has no activity interval; Tines reads its inventory daily, which is not adjustable, and its audit records every 300 to 3,600 seconds. The console answers `INVALID_BODY`. |
| `INVALID_SPACE` | 400 | The space named for a new connection is archived or does not exist, or the administrator belongs to spaces but is not an administrator of this one. For a reporting source, registered from the command line or the console, it means only that the space is not one of the workspace's: an archived space is `SPACE_ARCHIVED` and one the administrator does not administer `INVALID_ADMIN`. The console answers `SPACE_REQUIRED`. |
| `INVALID_STATE` | 400 | The source named is revoked, so it cannot be rotated or revoked again, or the connection named is revoked, so nothing can be collected, linked or recorded for it. A directory collection run also refuses a connection of another kind. For a source, the console answers `CONFLICT`. Listing finding deliveries refuses it, too, for a state no delivery can be in. Recording egress addresses named a connection that is not a Tines connection: only a Tines tenant has egress to record. |
| `INVALID_TEAM` | 400 | The Tines team id given in the console is not 1 to 64 letters, digits, dots, colons, underscores or hyphens, or reads as a secret. The console answers `INVALID_BODY` naming `team_id`. |
| `INVENTORY_CAPACITY` | 400 | A collection run reported more than 6,000 inventory items for one connection. Nothing from that inventory snapshot is written. |
| `LEASE_LOST` | 400 | A collection run no longer holds its connection: its lease ran out and another run took the connection, or it was revoked. Nothing more the run read is written; the next pass collects again. |
| `LINK_CONFLICT` | 400 | The discovered agent is already linked to a different principal, that principal is already linked to another agent, or another link change committed first. Withdraw the existing link before making a new one. |
| `PRINCIPAL_UNAVAILABLE` | 400 | Linking a discovered agent named a principal that is not an active agent principal in the workspace. |
| `SEALED_KEY_MISMATCH` | 400 | A sealed connection's key opened and names another workspace, connection or kind: a ciphertext copied from another row. Recorded on the connection; the key is never used and nothing is sent to the platform. |
| `SOURCE_EXISTS` | 400 | Registering a source for a story that already has an unrevoked source in that space that can still take its events, expired or not. Rotate the existing source to issue a new token. A source that has kept its 10,000 events, whose count rotation keeps, refuses no new one: register the story again while it stands, and revoke it once the story reports through the new token. Nothing is written. The console answers `SOURCE_EXISTS` with 409. |
| `SOURCE_UNAVAILABLE` | 400 | Reading, rotating or revoking a source named an identifier that is malformed or matches no source in the workspace, or, in the console, a source outside the session's Spaces. The console answers `NOT_FOUND`. |
| `SPACE_ARCHIVED` | 400 | Connecting from the console in an archived space, which takes no new work, or registering a reporting source in one, from the console or the command line. `create-source` places a source in the workspace's first space, so it is refused while that space is archived: unarchive it with `space-unarchive`. The console answers `SPACE_ARCHIVED`. |
| `SPACE_REQUIRED` | 400 | Connecting from the console with several spaces and none chosen, or in a space the administrator does not see. The console answers `SPACE_REQUIRED`. |
| `AUTH_LOST` | 400 | A collection run's credential was refused: signing in to the directory failed, a workflow platform answered 401 or 403, or the directory forbids reading agent identities. Check the credential the connection was registered with, and register the connection again with a new one if it was replaced. |
| `CAPACITY` | 400 | A Tines collection run would keep more than 200,000 observations for one connection, the most a Tines connection holds. The run keeps what fits and nothing past it, records the code as the connection's last refusal, and its audit cursor goes no further than the last record kept. A Microsoft Entra read of the directory's audit log never reports it: at the same bound the read moves on and keeps of each new entry only what the rules would miss without it, the first two entries each of ExecBound's executions could account for, whoever acted, a principal's first current observation of each action and its repeat more than fifteen days after its newest, and the first of each action by an actor the inventory does not hold yet only while the connection's principals and such actors number no more than 1,000, which its result counts as `bounded`, `kept_at_bound` and `dropped_at_bound`, and the scheduled `process` pass removes the audit observations no rule reads any more ([SCOUT.md](SCOUT.md#what-the-directorys-own-audit-log-shows)). |
| `DELTA_OVERFLOW` | 400 | A Microsoft Entra delta pass met more than 20 pages or 1,000 changes in one round. Nothing from the round is written and the connection's delta link is dropped; the next full collection reads the whole directory and takes a new one. Counted in `collect-due`'s `delta_failed`; the connection's health does not change. |
| `DIRECTORY_MISMATCH` | 400 | The directory the credential signs in to is not the one the connection was registered for. Nothing is collected. |
| `FORBIDDEN` | 400 | The directory accepted the credential but refused a read with 401 or 403, so the application lacks a permission the read needs. Grant it and collect again. |
| `KEY_MISMATCH` | 400 | The credential given to a collection run is not the one the connection was registered with. Nothing is sent to the platform. |
| `MALFORMED` | 400 | A platform's answer to a collection run is not the JSON object expected, or a sign-in answer carries no token. Nothing from it is written. A Microsoft Entra delta pass that meets a page it cannot read keeps the connection's delta link, and the next pass reads the same round again; one that meets a next link or delta link off the pinned Graph read, or a stored link that no longer validates, drops it for the next full collection to replace. Either is counted in `collect-due`'s `delta_failed`, and the connection's health does not change. A Microsoft Entra read of the directory's audit log that meets a page out of time order keeps nothing from that page; one that meets a next link off the pinned Graph read keeps the page that carried it and follows nothing. Either keeps what earlier pages read, leaves the audit cursor at the second of the last entry kept but never later than thirty minutes before the read's moment, or where it was if nothing was kept, is counted in `collect-due`'s `audit_failed` rather than `delta_failed`, and changes neither the run's outcome nor the connection's health. |
| `OVERSIZE` | 400 | A platform's answer to a collection run is larger than a run accepts. The run stops without writing it. |
| `PACED` | 400 | A directory's sign-in read would need more than the twelve seconds a run may wait for Microsoft Graph's reports budget, five requests in any ten seconds. The read stops without sending the request; after its first page it has read the newest sign-ins and the cursor moves on, and before it the cursor stays. It never changes the run's outcome. |
| `RATE_LIMITED` | 400 | The platform answered a collection run with 429. Collect again after the wait it gave. |
| `RESYNC_REQUIRED` | 400 | Microsoft Graph refused a Microsoft Entra delta pass's link with 400 or 410, as it does an expired one. The link is dropped and nothing from the round is written; the next full collection takes a new one. Counted in `collect-due`'s `delta_failed`; the connection's health does not change. |
| `UNAVAILABLE` | 400 | The platform could not be reached during a collection run, or answered with a status the run does not expect. Try again later. |
| `UNSUPPORTED` | 400 | The platform does not offer what a collection run reads: it answered 404 or 501, or 422 because the workspace's plan does not include the feature. |
| `INVALID_SOURCE` | 401 | The source token is malformed, unknown, wrong, revoked or expired, or the workspace is inactive. It is also the answer for an event whose story is not the one the source was registered for. |
| `INVALID_ADMIN` | 403 | The acting administrator is no longer current: the credential is expired or revoked, the principal is inactive or cannot manage the workspace, or the workspace is inactive. Monitoring checks this again inside every administrative operation. |
| `FINDING_UNAVAILABLE` | 404 | Acknowledging a finding named an identifier that is malformed or matches no finding in the workspace. |
| `EVENT_CONFLICT` | 409 | The source reported an event ID it had already reported, with different content. The first event is kept, marked as conflicting, and raises a finding. Send new content under a new event ID. |
| `SOURCE_CAPACITY` | 429 | The source already holds 10,000 accepted events, the most one source records, or registering a source found the workspace already holding 100 sources, revoked ones included. Waiting does not clear it. |
| `SOURCE_RATE_LIMIT` | 429 | The source has already sent 120 events in its current one-minute window. The refusal is recorded on the source; send again once the minute has passed. |
| `MONITOR_UNAVAILABLE` | 503 | Monitoring could not complete the operation because the database or a check it depends on failed, or linking an agent failed for an unexpected reason. Try again shortly. |
| `RULE_UNAVAILABLE` | 503 | Evaluating pending observations found one recorded under a detection rule version this deployment does not know. The pass is rolled back, and the observations stay pending until a deployment that knows the rule evaluates them. |

## The signal intake API

A registered security signal producer posts signed envelopes about the workspace's hosts with its source token ([security signals](SIGNALS.md)). A refusal is answered `{"detail": "Signal refused", "code": "…"}` with the status below, which is 400 for every code without a status of its own. A producer is told its own code, because it owns the source and must be able to fix what it sent; an authentication failure says nothing beyond `INVALID_SOURCE`.

| Code | Status | When |
| --- | --- | --- |
| `FUTURE_OBSERVATION` | 400 | The envelope's `observed_at` is more than 60 seconds later than the moment the gateway received it. The refusal is recorded on the source; check the producer's clock. |
| `INVALID_ENVELOPE` | 400 | The body is not a valid security signal envelope, contains text shaped like a secret, or carries a request reference, which the intake refuses. It is refused before the token is read and recorded against no source. |
| `INVALID_SIGNAL` | 400 | The source authenticated, but a field failed the stored record's own checks, such as a malformed event ID or record digest, an expiry not later than the observation, or a value out of range. The refusal is recorded on the source. |
| `STALE_ON_ARRIVAL` | 400 | The envelope's `observed_at` is 3,600 seconds or more before the moment the gateway received it. The refusal is recorded on the source; send observations as they are made and keep the producer's clock in time. |
| `INVALID_SOURCE` | 401 | The producer token is malformed, unknown, wrong, revoked or expired, or the workspace is inactive. It is counted as an authentication failure, never against the source's health. Rotate the source for a new token when it has expired. |
| `CAPABILITY_REFUSED` | 403 | The envelope's capability is not one the source is registered for. The refusal is recorded on the source. |
| `INCOMPATIBLE_PRODUCER` | 403 | The envelope names a producer other than the one the source is registered for, or a producer version outside the registered range. The refusal is recorded on the source. |
| `INVALID_SUBJECT` | 403 | The subject's account and provider do not name one of the workspace's connector accounts. The refusal is recorded on the source; identify the host by a connector account the workspace holds. |
| `SUBJECT_REFUSED` | 403 | The envelope's subject kind is not one the source is registered to vouch for. The refusal is recorded on the source. |
| `CONFLICTING_DUPLICATE` | 409 | The source already sent this event ID with different content. The first record is kept and the conflict is counted on the source; send new content under a new event ID. An identical resend is answered as a duplicate instead. |
| `SOURCE_CAPACITY` | 429 | The source already holds 500,000 records, the most one source may hold. Waiting does not clear it, because nothing removes old records yet. |
| `SOURCE_RATE_LIMIT` | 429 | The source has already sent 600 envelopes its token authenticated in the current minute, retries and refused ones included. The refusal is counted on the source; send again once the minute has passed. |
| `SIGNAL_UNAVAILABLE` | 503 | The database could not be reached, or the gateway's clock is more than 300 seconds from the database's. Try again shortly; if it persists, check both clocks. |
