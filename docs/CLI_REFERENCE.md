# Command-line reference

Every command the `execbound` command line and the monitoring commands take, and the arguments
each accepts. This page is generated from the commands' own argument parsers by
`scripts/cli_reference.py`, and a test fails when it no longer matches them. What each command
is for, in context, is in [operations](OPERATIONS.md), [install on one host](INSTALL.md) and
[deployment](DEPLOYMENT.md), and the codes a command refuses with are in
[error and refusal codes](ERROR_CODES.md).

A plugin may add commands of its own, which the plugin documents. They appear in `execbound --help`
once `EXECBOUND_PLUGINS` enables the plugin; `execbound plugins` lists only the enabled plugins'
names and the plugin API version.

## `execbound`

ExecBound installation and administration.

| Command | What it does |
| --- | --- |
| `init` | Write a one-host installation into a directory, secrets and all |
| `quickstart` | Take an empty database to a governed decision in one fenced sequence |
| `jobs` | Run the scheduled jobs on their intervals, one replica at a time |
| `seed-demo` | Create two synthetic tenants |
| `seed-validation` | Provision a private local demo |
| `replay` | Replay immutable files without live access |
| `replay-fixture` | Build a sanitized replay regression fixture from an export, or re-record one |
| `replay-fixture-check` | Replay a regression fixture and compare every decision with its recorded outcome |
| `mock-reprovision` | Reset one mock target; run inside the mock's own environment |
| `audit-export` | Export one tenant as a current ADMIN |
| `tenant-create` | Create a tenant with the owner connection |
| `principal-create` | Create a principal; a tenant's first ADMIN needs no --actor |
| `credential-issue` | Issue a credential; its token is written once to --output |
| `person-invite` | Find or create a person by email and write one set-password code to --output |
| `credential-list` | List a tenant's credentials |
| `credential-revoke` | Revoke a live credential |
| `approver-assign` | Assign an approver to one canonical target and action |
| `approver-unassign` | Deactivate one approver assignment |
| `group-create` | Create an empty principal group; names are unique per tenant |
| `group-assign` | Add an AGENT principal to a group |
| `group-unassign` | Remove an AGENT principal from a group |
| `group-list` | List a tenant's groups |
| `space-create` | Create a space; names are unique per tenant, case-insensitively |
| `space-rename` | Rename a space |
| `space-archive` | Stop new work in a space; nothing is deleted and history stays |
| `space-unarchive` | Let a space take work again |
| `space-assign` | Give a person a role in a space; the role narrows and never raises |
| `space-unassign` | Remove a membership; the rows it governed keep their space |
| `space-list` | List a tenant's spaces |
| `executor-key-register` | Register an executor's public key: Ed25519 as 64 hex characters, or ES256 as PEM, JWK or compressed hex |
| `executor-key-rotate` | Register a new executor key and revoke the previous one |
| `executor-key-revoke` | Revoke an executor key; proofs for earlier grants still verify |
| `executor-key-compromise` | Cut off a stolen executor key; it attests nothing, including earlier grants |
| `executor-key-list` | List a tenant's executor keys and their revocations |
| `account-create` | Create a connector account for one provider |
| `config-init` | Write a private gateway configuration and both mock accounts files |
| `account-list` | List a tenant's connector accounts |
| `mapping-list` | List a tenant's operation mappings |
| `resource-list` | List a tenant's resources with their targets and aliases |
| `mapping-create` | Bind a catalog action to an account's provider operation under an operation ref |
| `target-create` | Create a canonical target |
| `resource-create` | Register a provider resource with its canonical target and aliases |
| `ruleset-compile` | Compile a ruleset file into a bundle document over the tenant's active mappings |
| `context-source-create` | Create a trusted context source with its writer labels |
| `context-source-deactivate` | Deactivate a context source; its facts stop resolving |
| `context-import` | Import a context manifest of inventory facts or incidents |
| `signal-source-create` | Register a security signal producer; writes its token once |
| `signal-source-rotate` | Replace a producer token; the old one keeps a grace window |
| `signal-source-revoke` | Revoke a producer immediately and finally |
| `signal-source-list` | List producers with their registration and health |
| `invitations-run` | Drain due teammate invitations across every tenant; needs no identity |
| `weekly-summary-run` | Queue and send this week's opt-in summaries across every tenant; needs no identity |
| `failures` | List authentication failure windows for a tenant, or unattributed ones |
| `bundle-create` | Create DRAFT bundle content from a JSON file |
| `bundle-validate` | Validate a DRAFT bundle |
| `bundle-activate` | Activate a bundle for the tenant's first space; the one it replaces returns to VALIDATED once no space selects it |
| `bundle-retire` | Retire a bundle no space selects |
| `bundle-list` | List bundle lifecycle states |
| `bundle-preview` | Replay a candidate bundle over recent history without activating it |
| `tenant-stop` | Activate the tenant emergency stop with a required reason |
| `tenant-resume` | Release the tenant emergency stop with a required reason |
| `tenant-status` | Show the tenant emergency stop and enforcement mode |
| `tenant-mode` | Set the tenant enforcement mode (ENFORCE or OBSERVE) with a reason |
| `tenant-approval-deadline` | Set how long a new approval may wait: seconds from 120 to 3600, or off, with a reason |
| `tenant-assistant` | Turn the console assistant on or off for the tenant with a reason; prompts and answers are kept by the model provider for up to 30 days under its terms |
| `observe-report` | Summarize observed decisions from the audit chain |
| `rotation-readiness` | Show unsettled operations and outstanding expiries that still need current keys |
| `recover` | Settle committed but unsettled operations from provider evidence |
| `audit-verify` | Verify each workspace's audit chain to its head and each retained checkpoint on it |
| `reconcile` | Settle one committed or indeterminate operation from provider evidence |
| `notify` | Deliver pending approval notifications to the configured destinations |
| `notifications` | List approval notifications and their delivery state |
| `export-events` | Export new audit events and failure summaries to the destinations |
| `export-status` | Show export cursor state and lag per destination |
| `export-resume` | Resume a failed export cursor from where it stopped |
| `plugins` | List the plugins EXECBOUND_PLUGINS enables, and the plugin API |

### `execbound init`

Write a one-host installation into a directory, secrets and all.

| Argument | Required | Description |
| --- | --- | --- |
| `directory` | yes | An empty directory you own. |
| `--image IMAGE` | no | The image the compose file runs; a pull reference when a registry publishes one. Default `execbound:community`. |
| `--port PORT` | no | Where the gateway listens. Default `8080`. |
| `--project PROJECT` | no | Default `execbound`. |
| `--origin ORIGIN` | no | The origin people will use; the loopback port by default. |
| `--telemetry, --no-telemetry` | no | Answer the usage report question without being asked; the default is no, and nothing sends a report yet. |

### `execbound quickstart`

Take an empty database to a governed decision in one fenced sequence.

| Argument | Required | Description |
| --- | --- | --- |
| `--name NAME` | no | The tenant name. Default `ExecBound`. |
| `--private PRIVATE` | no | Default `/srv/private`. |
| `--state STATE` | no | Default `/srv/state`. |
| `--providers PROVIDERS` | no | Default `/srv/providers`. |
| `--gateway GATEWAY` | no | Default `http://127.0.0.1:8000`. |
| `--credential-days CREDENTIAL_DAYS` | no | Default `90`. |
| `--alembic-config ALEMBIC_CONFIG` | no | Default `alembic.ini`. |

### `execbound jobs`

Run the scheduled jobs on their intervals, one replica at a time.

| Argument | Required | Description |
| --- | --- | --- |
| `--state STATE` | no | Default `/srv/state`. |
| `--collector COLLECTOR` | no | The directory holding the collector's key and the platform app's credential. Default `/srv/collector`. |
| `--checkpoints CHECKPOINTS` | no | The directory of retained audit heads audit-verify places on each chain. Default `/srv/private/checkpoints`. |
| `--limit LIMIT` | no | Default `50`. |
| `--once` | no | One pass over every due job, then exit. |

### `execbound seed-demo`

Create two synthetic tenants.

| Argument | Required | Description |
| --- | --- | --- |
| `--output OUTPUT` | no | Default `local-data/demo.json`. |

### `execbound seed-validation`

Provision a private local demo.

| Argument | Required | Description |
| --- | --- | --- |
| `--output OUTPUT` | yes |  |
| `--seed SEED` | no | Default `execbound-validation-v1`. |
| `--gateway-port GATEWAY_PORT` | no | Default `8100`. |
| `--endpoint-port ENDPOINT_PORT` | no | Default `8101`. |
| `--identity-port IDENTITY_PORT` | no | Default `8102`. |

### `execbound replay`

Replay immutable files without live access.

| Argument | Required | Description |
| --- | --- | --- |
| `--input INPUT` | yes |  |
| `--trusted-head TRUSTED_HEAD` | yes |  |
| `--candidate CANDIDATE` | no |  |
| `--output OUTPUT` | yes |  |

### `execbound replay-fixture`

Build a sanitized replay regression fixture from an export, or re-record one.

| Argument | Required | Description |
| --- | --- | --- |
| `--input INPUT` | no | The audit export to build from; needed unless --from-fixture. |
| `--trusted-head TRUSTED_HEAD` | no | The export's independently retained checkpoint; needed with --input. |
| `--candidate CANDIDATE` | no | A candidate bundle to record outcomes for; repeat for up to eight, in order. |
| `--from-fixture FROM_FIXTURE` | no | Re-record this fixture's expected outcomes instead of building one. |
| `--output OUTPUT` | yes | A new file to write. |

### `execbound replay-fixture-check`

Replay a regression fixture and compare every decision with its recorded outcome.

| Argument | Required | Description |
| --- | --- | --- |
| `--fixture FIXTURE` | yes | The fixture file to replay and compare. |

### `execbound mock-reprovision`

Reset one mock target; run inside the mock's own environment.

| Argument | Required | Description |
| --- | --- | --- |
| `--provider {endpoint,identity}` | yes | One of `endpoint`, `identity`. |
| `--tenant TENANT` | yes | The tenant's id. |
| `--target TARGET` | yes |  |
| `--version VERSION` | no | Set this version and touch nothing else; omit to reset to the file's values. |
| `--reason REASON` | no |  |

### `execbound audit-export`

Export one tenant as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--output OUTPUT` | yes |  |
| `--checkpoint CHECKPOINT` | no |  |
| `--database DATABASE` | no | Read a restored copy on the same server, by name. |

### `execbound tenant-create`

Create a tenant with the owner connection.

| Argument | Required | Description |
| --- | --- | --- |
| `--name NAME` | yes | The tenant name; two tenants may share a name. |
| `--tenant TENANT` | no | Create it under this id; for a private configuration that already names one. |

### `execbound principal-create`

Create a principal; a tenant's first ADMIN needs no --actor.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--kind {AGENT,HUMAN_APPROVER,ADMIN}` | yes | One of `AGENT`, `HUMAN_APPROVER`, `ADMIN`. |
| `--actor ACTOR` | no | Auditing ADMIN principal. |
| `--space SPACE` | no | The space that owns an agent, or seats a person; the tenant's only one by default. |

### `execbound credential-issue`

Issue a credential; its token is written once to --output.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--principal PRINCIPAL` | yes | The principal the credential is issued to. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |
| `--lifetime-hours LIFETIME_HOURS` | no | The credential's lifetime in hours, bounded to 90 days: at most 2160. Default `8`. |
| `--output OUTPUT` | yes | A new file the token is written to once, created exclusively and owner-only where the platform carries POSIX modes; an existing path is refused. |

### `execbound person-invite`

Find or create a person by email and write one set-password code to --output.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--email EMAIL` | yes | The person's sign-in address; the person holding it is found, or one is created. |
| `--kind {ADMIN,HUMAN_APPROVER}` | no | One of `ADMIN`, `HUMAN_APPROVER`. Default `ADMIN`. |
| `--label LABEL` | no | A name for the person, up to 80 characters. |
| `--actor ACTOR` | no | Auditing ADMIN principal; a tenant's first ADMIN needs none. |
| `--lifetime-hours LIFETIME_HOURS` | no | Hours until the set-password code expires, between 1 and 336. Default `24`. |
| `--origin ORIGIN` | yes | This deployment's origin, for the address to open. |
| `--output OUTPUT` | yes | A new file the set-password code is written to once, exactly as credential-issue writes a token. |

### `execbound credential-list`

List a tenant's credentials.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |

### `execbound credential-revoke`

Revoke a live credential.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential CREDENTIAL` | yes | The live credential to revoke; the sessions and continuations it backs end at their next check. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound approver-assign`

Assign an approver to one canonical target and action.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--space SPACE` | no | The space the scope is held in; the tenant's only one by default. |
| `--approver APPROVER` | yes |  |
| `--target TARGET` | yes | A known canonical target. |
| `--action {endpoint.isolate,endpoint.lift_isolation,identity.disable,identity.enable,identity.reset_password,identity.revoke_sessions}` | yes | An action in the action catalog; a new action is assignable as soon as it is released. One of `endpoint.isolate`, `endpoint.lift_isolation`, `identity.disable`, `identity.enable`, `identity.reset_password`, `identity.revoke_sessions`. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound approver-unassign`

Deactivate one approver assignment.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--approver APPROVER` | yes | The approver of the assignment to deactivate; pending decisions under that scope then fail their server-side scope check. |
| `--target TARGET` | yes | The assignment's canonical target. |
| `--action {endpoint.isolate,endpoint.lift_isolation,identity.disable,identity.enable,identity.reset_password,identity.revoke_sessions}` | yes | The assignment's action. One of `endpoint.isolate`, `endpoint.lift_isolation`, `identity.disable`, `identity.enable`, `identity.reset_password`, `identity.revoke_sessions`. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound group-create`

Create an empty principal group; names are unique per tenant.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--name NAME` | yes | 1 to 80 characters after trimming, unique within the tenant; INVALID_NAME when shaped like a password, key or token. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound group-assign`

Add an AGENT principal to a group.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--group GROUP` | yes | The group, which must exist; INVALID_GROUP otherwise. |
| `--principal PRINCIPAL` | yes | An active AGENT principal (INVALID_PRINCIPAL otherwise), in at most 64 groups; a repeated or 65th membership is INVALID_MEMBERSHIP. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound group-unassign`

Remove an AGENT principal from a group.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--group GROUP` | yes | The group to remove the principal from. |
| `--principal PRINCIPAL` | yes | The principal to remove: its later requests stop charging the group while its earlier rows keep counting; a missing membership is INVALID_MEMBERSHIP. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound group-list`

List a tenant's groups.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |

### `execbound space-create`

Create a space; names are unique per tenant, case-insensitively.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--name NAME` | yes | 1 to 80 characters after trimming, unique within the tenant case-insensitively; INVALID_NAME when shaped like a password, key or token. |
| `--detail DETAIL` | no | A detail line for the space. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound space-rename`

Rename a space.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--space SPACE` | yes | The space to rename. |
| `--name NAME` | yes | Its new name: 1 to 80 characters after trimming, unique within the tenant case-insensitively; INVALID_NAME when shaped like a password, key or token. |
| `--detail DETAIL` | no |  |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound space-archive`

Stop new work in a space; nothing is deleted and history stays.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--space SPACE` | yes | The space to stop new work in; archiving the tenant's last unarchived one is refused. |
| `--reason REASON` | yes | Why the space is archived; a reason shaped like a password, key or token is refused as INVALID_NAME. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound space-unarchive`

Let a space take work again.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--space SPACE` | yes | The space to let take work again. |
| `--reason REASON` | yes | Why the space is unarchived; a reason shaped like a password, key or token is refused as INVALID_NAME. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound space-assign`

Give a person a role in a space; the role narrows and never raises.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--space SPACE` | yes | The space to seat the person in. |
| `--principal PRINCIPAL` | yes | The person to seat; an assignment that would leave the tenant with no tenant administrator is refused. |
| `--role {ADMIN,HUMAN_APPROVER}` | no | The person's role in the space, which narrows and never raises: ADMIN is refused for a HUMAN_APPROVER principal. One of `ADMIN`, `HUMAN_APPROVER`. Default `HUMAN_APPROVER`. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound space-unassign`

Remove a membership; the rows it governed keep their space.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--space SPACE` | yes | The space to remove the person from. |
| `--principal PRINCIPAL` | yes | The person to remove; the rows the membership governed keep their space. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound space-list`

List a tenant's spaces.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |

### `execbound executor-key-register`

Register an executor's public key: Ed25519 as 64 hex characters, or ES256 as PEM, JWK or compressed hex.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--key-id KEY_ID` | yes | A new id for the key; a taken id, or one shaped like a password, key or token, is INVALID_KEY. |
| `--public-key PUBLIC_KEY` | no | The executor's public key in --algorithm's form: Ed25519 as 64 hex characters (uppercase is normalized); ES256 as an SPKI PEM, a P-256 JSON Web Key or compressed SEC1 hex. Material already live for the tenant or recorded as compromised, or that nobody holds the private half of, is INVALID_KEY. |
| `--public-key-file PUBLIC_KEY_FILE` | no | A file holding that public key in the same forms, read instead of --public-key; trailing whitespace such as a final newline is stripped, and an unreadable file is INVALID_KEY. |
| `--algorithm {ED25519,ES256}` | no | The key's signature scheme; a key attests only reports in its own scheme. One of `ED25519`, `ES256`. Default `ED25519`. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

Exactly one of `--public-key`, `--public-key-file`.

### `execbound executor-key-rotate`

Register a new executor key and revoke the previous one.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--key-id KEY_ID` | yes | The live key to replace, retired as RETIRED in the same transaction so a proof for a grant issued while it was current still verifies; an unknown or already revoked id is INVALID_KEY. |
| `--new-key-id NEW_KEY_ID` | yes | A new id for the replacement key, other than --key-id; a taken id, or one shaped like a password, key or token, is INVALID_KEY. |
| `--public-key PUBLIC_KEY` | no | The replacement's public key in --algorithm's form: Ed25519 as 64 hex characters (uppercase is normalized); ES256 as an SPKI PEM, a P-256 JSON Web Key or compressed SEC1 hex. Material already live for the tenant or recorded as compromised, or that nobody holds the private half of, is INVALID_KEY. |
| `--public-key-file PUBLIC_KEY_FILE` | no | A file holding that public key in the same forms, read instead of --public-key; trailing whitespace such as a final newline is stripped, and an unreadable file is INVALID_KEY. |
| `--algorithm {ED25519,ES256}` | no | The key's signature scheme; a key attests only reports in its own scheme. One of `ED25519`, `ES256`. Default `ED25519`. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

Exactly one of `--public-key`, `--public-key-file`.

### `execbound executor-key-revoke`

Revoke an executor key; proofs for earlier grants still verify.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--key-id KEY_ID` | yes | The live key to retire as RETIRED; a proof for a grant issued while it was current still verifies. INVALID_STATE while it is the tenant's last live key and a bundle a space selects declares an external executor; an unknown or already revoked id is INVALID_KEY. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound executor-key-compromise`

Cut off a stolen executor key; it attests nothing, including earlier grants.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--key-id KEY_ID` | yes | The key whose private half is in someone else's hands, live or already retired: it and every other id of the tenant carrying the same public key are recorded COMPROMISED and attest nothing, earlier grants included, even when no live key is left; a key already cut off, or an unknown id, is INVALID_KEY. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound executor-key-list`

List a tenant's executor keys and their revocations.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |

### `execbound account-create`

Create a connector account for one provider.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--space SPACE` | no | The space that owns the account; the tenant's only one by default. |
| `--provider {graph,mock_crowdstrike,mock_entra}` | yes | A provider the action catalog binds; the gateway's private configuration names the account it creates by id. One of `graph`, `mock_crowdstrike`, `mock_entra`. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |
| `--account ACCOUNT` | no | Create it under this id; for a private configuration that already names one. |

### `execbound config-init`

Write a private gateway configuration and both mock accounts files.

| Argument | Required | Description |
| --- | --- | --- |
| `--output OUTPUT` | yes |  |
| `--origin ORIGIN` | yes | the public origin clients and approvers will use. |
| `--tenant TENANT` | yes | The tenant's id. |
| `--endpoint-account ENDPOINT_ACCOUNT` | yes |  |
| `--identity-account IDENTITY_ACCOUNT` | yes |  |
| `--endpoint-origin ENDPOINT_ORIGIN` | no | loopback only; a provider elsewhere must serve HTTPS. Default `http://127.0.0.1:8001`. |
| `--identity-origin IDENTITY_ORIGIN` | no | Default `http://127.0.0.1:8002`. |

### `execbound account-list`

List a tenant's connector accounts.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |

### `execbound mapping-list`

List a tenant's operation mappings.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |

### `execbound resource-list`

List a tenant's resources with their targets and aliases.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |

### `execbound mapping-create`

Bind a catalog action to an account's provider operation under an operation ref.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--account ACCOUNT` | yes | The active connector account the mapping binds to; INVALID_ACCOUNT otherwise. |
| `--action {endpoint.isolate,endpoint.lift_isolation,identity.disable,identity.enable,identity.reset_password,identity.revoke_sessions}` | yes | A catalog action bound for the account's provider (INVALID_ACTION otherwise); the provider operation and schema version come from the catalog, never the caller. One of `endpoint.isolate`, `endpoint.lift_isolation`, `identity.disable`, `identity.enable`, `identity.reset_password`, `identity.revoke_sessions`. |
| `--ref REF` | no | Operation ref agents use; defaults to the action. |
| `--mapping-version MAPPING_VERSION` | no | 1 to 80 characters, matching the version the bundle's mapping refs name; INVALID_VERSION otherwise, or when shaped like a password, key or token. Default `map-v1`. |
| `--contract-version {endpoint-isolation.v1,endpoint-isolation.v2,endpoint-recovery.v1,identity-control.v1,identity-credential.v1}` | no | A context contract version serving the action; defaults to the catalog's. One of `endpoint-isolation.v1`, `endpoint-isolation.v2`, `endpoint-recovery.v1`, `identity-control.v1`, `identity-credential.v1`. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound target-create`

Create a canonical target.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound resource-create`

Register a provider resource with its canonical target and aliases.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--account ACCOUNT` | yes | The active connector account the resource belongs to (INVALID_ACCOUNT otherwise); --source must be an inventory source of the same account. |
| `--resource-type {endpoint,identity}` | yes | The resource's type, whose contract domains check the optional facts, which can also arrive later through context-import; only an endpoint takes --hostname. One of `endpoint`, `identity`. |
| `--provider-id PROVIDER_ID` | yes | The provider's id for the resource, which becomes its provider_id alias for an agent's selector; INVALID_PROVIDER_ID when the account already holds it for this type, or when it is shaped like a password, key or token. |
| `--source SOURCE` | yes | The inventory context source that attests it. |
| `--target TARGET` | no | An existing canonical target; a new one is created otherwise. |
| `--hostname HOSTNAME` | no | Endpoint hostname alias. |
| `--version VERSION` | no | The resource's version, 1 to 80 characters; INVALID_VERSION otherwise, or when shaped like a password, key or token. Default `resource-v1`. |
| `--alias-days ALIAS_DAYS` | no | Days the provider_id and hostname aliases stay valid from creation, 1 to 3660; INVALID_ALIAS otherwise. Default `365`. |
| `--role ROLE` | no | An endpoint's role, one of domain_controller, server or workstation; INVALID_FACT otherwise, and for an identity. |
| `--privilege-class PRIVILEGE_CLASS` | no | An identity's privilege class, one of privileged, standard or tier0; INVALID_FACT otherwise, and for an endpoint. |
| `--environment ENVIRONMENT` | no | The resource's environment, one of development, production or staging; INVALID_FACT otherwise. |
| `--criticality CRITICALITY` | no | The resource's criticality, 0 to 4; INVALID_FACT otherwise. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound ruleset-compile`

Compile a ruleset file into a bundle document over the tenant's active mappings.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--input INPUT` | yes | The ruleset file. |
| `--output OUTPUT` | yes | Bundle document to write; refuses to overwrite. |
| `--ref REF` | no | Compile over this active mapping only; repeatable. Default: every active mapping. |
| `--signal-mappings SIGNAL_MAPPINGS` | no | A JSON array of signal mappings to carry into the bundle (docs/SIGNALS.md) |

### `execbound context-source-create`

Create a trusted context source with its writer labels.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--account ACCOUNT` | yes | The active connector account the source belongs to (INVALID_ACCOUNT otherwise); its manifests and the resources it attests are that account's. |
| `--kind {inventory,incident}` | yes | What it attests, inventory facts or incidents: a manifest of the other kind is INVALID_SOURCE, and resource-create takes only an inventory source. One of `inventory`, `incident`. |
| `--writer WRITER` | yes | A writer label; repeat for several. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound context-source-deactivate`

Deactivate a context source; its facts stop resolving.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--source SOURCE` | yes | The active source to deactivate; every fact it attests then fails resolution. An unknown or already inactive source is INVALID_SOURCE. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound context-import`

Import a context manifest of inventory facts or incidents.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--manifest MANIFEST` | yes | An execbound.context-manifest.v1 file an adapter wrote, at most 16 MiB; validated against the contract catalog and the tenant's sources and applied in one audited transaction, or refused with nothing written. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |
| `--strict` | no | Refuse the manifest when a resource is unknown. |
| `--report REPORT` | no | Write per-entry outcomes to a new file. |

### `execbound signal-source-create`

Register a security signal producer; writes its token once.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |
| `--label LABEL` | yes | A label for the producer, 1 to 96 characters of letters, digits, space and ._:- starting with a letter or digit; INVALID_LABEL otherwise, or when shaped like a password, key or token. |
| `--producer PRODUCER` | yes | Name its envelopes carry. |
| `--version-min VERSION_MIN` | yes | The lowest producer version accepted, as three integers separated by dots and compared as numbers; INVALID_VERSION otherwise, or when above --version-max. |
| `--version-max VERSION_MAX` | yes | The highest producer version accepted, in the same form; an envelope from a version outside the range is refused INCOMPATIBLE_PRODUCER. |
| `--capability CAPABILITY` | no | Repeat for several; default resource_compromise.v1. |
| `--principal PRINCIPAL` | no | An agent it may vouch for; repeatable. |
| `--group GROUP` | no | A principal group it may vouch for. |
| `--space SPACE` | no | The space that owns the source; the tenant's only one by default, and INVALID_SPACE when it has several. |
| `--offered` | no | Usable by every space. |
| `--input-path {agent_forwarded,independent}` | no | Whether the agent can feed the producer: independent if not, agent_forwarded if so; a required signal mapping admits only an independent source. One of `agent_forwarded`, `independent`. Default `independent`. |
| `--attests-liveness` | no | Only set when the producer proves it is still observing each subject. |
| `--hours HOURS` | no | The token's lifetime in hours, 1 to 720; INVALID_LIFETIME otherwise. Default `720`. |
| `--output OUTPUT` | yes | New file for the token; refuses to overwrite. |

Exactly one of `--principal`, `--group`.

### `execbound signal-source-rotate`

Replace a producer token; the old one keeps a grace window.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--source SOURCE` | yes | The source to give a new token; a revoked source is INVALID_STATE. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |
| `--hours HOURS` | no | The new token's lifetime in hours, 1 to 720; INVALID_LIFETIME otherwise. Default `720`. |
| `--grace-seconds GRACE_SECONDS` | no | How long the old token keeps working, 0 to 3600 seconds and never past its own expiry; INVALID_GRACE otherwise. Default `600`. |
| `--output OUTPUT` | yes | New file for the new token, written once and owner-only; refuses to overwrite. |

### `execbound signal-source-revoke`

Revoke a producer immediately and finally.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--source SOURCE` | yes | The source to revoke, immediately and finally: every token stops, a rotation's grace included. A source already revoked is INVALID_STATE. |
| `--actor ACTOR` | yes | The id of an active administrator of the tenant, whom the change is made and audited as. |

### `execbound signal-source-list`

List producers with their registration and health.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |

### `execbound invitations-run`

Drain due teammate invitations across every tenant; needs no identity.

| Argument | Required | Description |
| --- | --- | --- |
| `--limit LIMIT` | no | Default `50`. |

### `execbound weekly-summary-run`

Queue and send this week's opt-in summaries across every tenant; needs no identity.

| Argument | Required | Description |
| --- | --- | --- |
| `--limit LIMIT` | no | At most this many summaries a run, 1 to 50. Default `50`. |

### `execbound failures`

List authentication failure windows for a tenant, or unattributed ones.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | no | The tenant's id. |
| `--since-hours SINCE_HOURS` | no | Default `24`. |
| `--unattributed` | no | Rows without a verified tenant or subject. |

### `execbound bundle-create`

Create DRAFT bundle content from a JSON file.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--input INPUT` | yes | The JSON bundle file; tenant_id must match --tenant and bundle_id is generated when omitted. |

### `execbound bundle-validate`

Validate a DRAFT bundle.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--bundle BUNDLE` | yes | The DRAFT bundle to validate. |

### `execbound bundle-activate`

Activate a bundle for the tenant's first space; the one it replaces returns to VALIDATED once no space selects it.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--bundle BUNDLE` | yes | A VALIDATED bundle, or one another space selects, to select for the tenant's first space; the bundle it replaces returns to VALIDATED unless another space still selects it. |
| `--reason REASON` | no | Why this policy is being activated; recorded in the audit event. |

### `execbound bundle-retire`

Retire a bundle no space selects.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--bundle BUNDLE` | yes | The bundle to retire; a bundle any space still selects is refused as INVALID_STATE, so activate a replacement first. |

### `execbound bundle-list`

List bundle lifecycle states.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |

### `execbound bundle-preview`

Replay a candidate bundle over recent history without activating it.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--bundle BUNDLE` | yes | The candidate bundle to replay; it is never activated. |
| `--window-hours WINDOW_HOURS` | no | Hours of recent history to replay the candidate over, at most 720. Default `24`. |

### `execbound tenant-stop`

Activate the tenant emergency stop with a required reason.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current workspace administrator's API key, which is never passed on the command line. |
| `--reason REASON` | yes |  |

### `execbound tenant-resume`

Release the tenant emergency stop with a required reason.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current workspace administrator's API key, which is never passed on the command line. |
| `--reason REASON` | yes |  |

### `execbound tenant-status`

Show the tenant emergency stop and enforcement mode.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |

### `execbound tenant-mode`

Set the tenant enforcement mode (ENFORCE or OBSERVE) with a reason.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current workspace administrator's API key, which is never passed on the command line. |
| `--reason REASON` | yes |  |
| `--set {ENFORCE,OBSERVE}` | yes | One of `ENFORCE`, `OBSERVE`. |

### `execbound tenant-approval-deadline`

Set how long a new approval may wait: seconds from 120 to 3600, or off, with a reason.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current workspace administrator's API key, which is never passed on the command line. |
| `--reason REASON` | yes |  |
| `--set SET` | yes | seconds (120 to 3600) or off. |

### `execbound tenant-assistant`

Turn the console assistant on or off for the tenant with a reason; prompts and answers are kept by the model provider for up to 30 days under its terms.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current workspace administrator's API key, which is never passed on the command line. |
| `--reason REASON` | yes |  |
| `--set {on,off}` | yes | One of `on`, `off`. |

### `execbound observe-report`

Summarize observed decisions from the audit chain.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current workspace administrator's API key, which is never passed on the command line. |
| `--since-hours SINCE_HOURS` | no | Default `24`. |

### `execbound rotation-readiness`

Show unsettled operations and outstanding expiries that still need current keys.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current workspace administrator's API key, which is never passed on the command line. |

### `execbound recover`

Settle committed but unsettled operations from provider evidence.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | no | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | no | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--tenants-file TENANTS_FILE` | no | A tenant-to-token map; one run per tenant. |
| `--all-tenants` | no | Every active workspace, as its scheduler principal, with no credential. |
| `--budget-seconds BUDGET_SECONDS` | no | With --all-tenants: start no workspace after this many seconds (default 480) |
| `--limit LIMIT` | no | Default `50`. |
| `--grace-seconds GRACE_SECONDS` | no | Default `300`. |
| `--cancel-unattempted` | no |  |

### `execbound audit-verify`

Verify each workspace's audit chain to its head and each retained checkpoint on it.

| Argument | Required | Description |
| --- | --- | --- |
| `--all-tenants` | no | Every workspace in the directory, inactive ones too, with no credential. |
| `--tenant TENANT` | no | One workspace; may be given again. |
| `--checkpoint CHECKPOINT` | no | A retained head that audit-export wrote; may be given again. |
| `--checkpoints CHECKPOINTS` | no | A directory of retained heads, each *.head.json in it. |
| `--budget-seconds BUDGET_SECONDS` | no | Start no workspace after this many seconds (default 480) |

### `execbound reconcile`

Settle one committed or indeterminate operation from provider evidence.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--execution EXECUTION` | yes |  |
| `--reason REASON` | yes |  |
| `--cancel-if-missing` | no |  |

### `execbound notify`

Deliver pending approval notifications to the configured destinations.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | no | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | no | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--tenants-file TENANTS_FILE` | no | A tenant-to-token map; one drain per tenant. |
| `--all-tenants` | no | Every workspace a destination names, with no credential. |
| `--limit LIMIT` | no | Default `50`. |

### `execbound notifications`

List approval notifications and their delivery state.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--state {PENDING,IN_FLIGHT,DELIVERED,FAILED}` | no | One of `PENDING`, `IN_FLIGHT`, `DELIVERED`, `FAILED`. |

### `execbound export-events`

Export new audit events and failure summaries to the destinations.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--limit LIMIT` | no | Default `100`. |

### `execbound export-status`

Show export cursor state and lag per destination.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |

### `execbound export-resume`

Resume a failed export cursor from where it stopped.

| Argument | Required | Description |
| --- | --- | --- |
| `--tenant TENANT` | yes | The tenant's id. |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--destination DESTINATION` | yes |  |

### `execbound plugins`

List the plugins EXECBOUND_PLUGINS enables, and the plugin API.

## `python -m execbound.monitoring.commands`

Explicit Tines monitoring and local validation tools.

| Command | What it does |
| --- | --- |
| `check-tines` | Make one read-only Tines stories-list request |
| `init-demo` | Create a new local synthetic monitoring tenant/config |
| `create-source` | Register one story as a current ADMIN |
| `rotate-source` | Issue a replacement token as a current ADMIN |
| `revoke-source` | Disable a source for good as a current ADMIN |
| `create-connection` | Register the read-only collection connection as a current ADMIN |
| `revoke-connection` | Disable a collection connection as a current ADMIN |
| `collect-tines` | Run one bounded, read-only collection as a current ADMIN |
| `collect-entra` | Run one bounded, read-only Entra collection as a current ADMIN |
| `collect-due` | Collect every due connection this host can open (an operator key file, a sealed key with --collector-key, a consented directory with --platform-app), inside its lease |
| `collector-keygen` | Write a new collector key pair: the public half for the gateway, the private for the collector |
| `collector-reseal` | Re-seal every sealed connection from the old collector key to the new one |
| `link-agent` | Bind an external agent to an active agent principal, as a current ADMIN |
| `unlink-agent` | Withdraw that binding, as a current ADMIN |
| `record-egress` | Record the addresses a Tines tenant's HTTP requests leave from, as a current ADMIN |
| `accept-reach` | Record that an ADMIN accepts one ungoverned path |
| `set-profile` | Activate the next detection profile version as a current ADMIN |
| `show-profile` | Show the active detection profile |
| `deliveries` | List finding deliveries and their state as a current ADMIN |
| `serve` | Serve monitoring with no configured execution connectors |
| `receiver` | Run the authenticated loopback test receiver |
| `emit-demo` | Send synthetic heartbeat and tool result to the loopback gateway |
| `process` | Evaluate a bounded batch; optionally deliver findings |

### `python -m execbound.monitoring.commands check-tines`

Make one read-only Tines stories-list request.

| Argument | Required | Description |
| --- | --- | --- |
| `--env-file ENV_FILE` | yes |  |

### `python -m execbound.monitoring.commands init-demo`

Create a new local synthetic monitoring tenant/config.

| Argument | Required | Description |
| --- | --- | --- |
| `--output OUTPUT` | yes |  |
| `--gateway-port GATEWAY_PORT` | no | Default `8120`. |
| `--receiver-port RECEIVER_PORT` | no | Default `8121`. |

### `python -m execbound.monitoring.commands create-source`

Register one story as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--label LABEL` | yes |  |
| `--story-id STORY_ID` | yes |  |
| `--hours HOURS` | no | Default `8`. |
| `--output OUTPUT` | yes |  |

### `python -m execbound.monitoring.commands rotate-source`

Issue a replacement token as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--source SOURCE` | yes |  |
| `--hours HOURS` | no | Default `8`. |
| `--grace-minutes GRACE_MINUTES` | no | Default `10`. |
| `--output OUTPUT` | yes |  |

### `python -m execbound.monitoring.commands revoke-source`

Disable a source for good as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--source SOURCE` | yes |  |

### `python -m execbound.monitoring.commands create-connection`

Register the read-only collection connection as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--label LABEL` | yes |  |
| `--key-file KEY_FILE` | yes |  |
| `--kind {tines,entra_agent_id}` | no | One of `tines`, `entra_agent_id`. Default `tines`. |
| `--team-id TEAM_ID` | no |  |
| `--space SPACE` | no | Register in this authorised, active Space. |

### `python -m execbound.monitoring.commands revoke-connection`

Disable a collection connection as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--connection CONNECTION` | yes |  |

### `python -m execbound.monitoring.commands collect-tines`

Run one bounded, read-only collection as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--connection CONNECTION` | yes |  |
| `--key-file KEY_FILE` | yes |  |
| `--audit-pages AUDIT_PAGES` | no | Default `20`. |
| `--inventory` | no |  |

### `python -m execbound.monitoring.commands collect-entra`

Run one bounded, read-only Entra collection as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--connection CONNECTION` | yes |  |
| `--key-file KEY_FILE` | yes |  |

### `python -m execbound.monitoring.commands collect-due`

Collect every due connection this host can open (an operator key file, a sealed key with --collector-key, a consented directory with --platform-app), inside its lease.

| Argument | Required | Description |
| --- | --- | --- |
| `--all-tenants` | no | Every active workspace, as its scheduled actor with no credential. |
| `--tenant TENANT` | no | One workspace, as its current ADMIN. |
| `--credential-file CREDENTIAL_FILE` | no | With --tenant: that workspace's ADMIN credential. |
| `--key-files KEY_FILES` | no | A directory of <connection id>.env key files; a connection without one is skipped. |
| `--collector-key COLLECTOR_KEY` | no | The collector's private key file, which opens sealed connections; give it again for the key a rotation is retiring. A path that names no file is no key yet. |
| `--platform-app PLATFORM_APP` | no | The platform app's credential file, which reads every consented directory. A path that names no file is no credential yet. |
| `--budget-seconds BUDGET_SECONDS` | no | Start no collection after this many seconds (1 to 3600, default 240) Default `240`. |
| `--per-tenant PER_TENANT` | no | Start at most this many collections a workspace (1 to 20, default 4) Default `4`. |

### `python -m execbound.monitoring.commands collector-keygen`

Write a new collector key pair: the public half for the gateway, the private for the collector.

| Argument | Required | Description |
| --- | --- | --- |
| `--output OUTPUT` | yes | A directory for collector-public.json and collector-private.json; neither may exist. |

### `python -m execbound.monitoring.commands collector-reseal`

Re-seal every sealed connection from the old collector key to the new one.

| Argument | Required | Description |
| --- | --- | --- |
| `--old-key OLD_KEY` | yes | The current collector's private key file. |
| `--new-key NEW_KEY` | yes | The new collector's public key file. |
| `--all-tenants` | no | Every active workspace, as its scheduled actor with no credential. |

### `python -m execbound.monitoring.commands link-agent`

Bind an external agent to an active agent principal, as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--connection CONNECTION` | yes |  |
| `--agent AGENT` | yes | The directory object identifier. |
| `--principal PRINCIPAL` | yes |  |

### `python -m execbound.monitoring.commands unlink-agent`

Withdraw that binding, as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--connection CONNECTION` | yes |  |
| `--agent AGENT` | yes | The directory object identifier. |

### `python -m execbound.monitoring.commands record-egress`

Record the addresses a Tines tenant's HTTP requests leave from, as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--connection CONNECTION` | yes | The Tines connection. |
| `--address ADDRESS` | no | One egress address as Tines shows it at /info; give it again for each, at most 8. |
| `--clear` | no | Clear the recorded addresses. |

### `python -m execbound.monitoring.commands accept-reach`

Record that an ADMIN accepts one ungoverned path.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--connection CONNECTION` | yes |  |
| `--agent AGENT` | yes | The directory object identifier. |
| `--action ACTION` | yes |  |
| `--path-kind {grant,role,inherited,observation}` | yes | One of `grant`, `role`, `inherited`, `observation`. |
| `--path PATH` | yes |  |
| `--reason REASON` | yes | A stable reason code, A to Z and _. |
| `--days DAYS` | no | 0 leaves the acceptance open. Default `0`. |

### `python -m execbound.monitoring.commands set-profile`

Activate the next detection profile version as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--input INPUT` | yes |  |

### `python -m execbound.monitoring.commands show-profile`

Show the active detection profile.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |

### `python -m execbound.monitoring.commands deliveries`

List finding deliveries and their state as a current ADMIN.

| Argument | Required | Description |
| --- | --- | --- |
| `--credential-file CREDENTIAL_FILE` | yes | A private file holding a current administrator's API key, which is never passed on the command line. |
| `--state {PENDING,ROUTED,IN_FLIGHT,DELIVERED,FAILED}` | no | List only the deliveries in this state. One of `PENDING`, `ROUTED`, `IN_FLIGHT`, `DELIVERED`, `FAILED`. |

### `python -m execbound.monitoring.commands serve`

Serve monitoring with no configured execution connectors.

| Argument | Required | Description |
| --- | --- | --- |
| `--config CONFIG` | yes |  |

### `python -m execbound.monitoring.commands receiver`

Run the authenticated loopback test receiver.

| Argument | Required | Description |
| --- | --- | --- |
| `--config CONFIG` | yes |  |
| `--output OUTPUT` | yes |  |

### `python -m execbound.monitoring.commands emit-demo`

Send synthetic heartbeat and tool result to the loopback gateway.

| Argument | Required | Description |
| --- | --- | --- |
| `--config CONFIG` | yes |  |

### `python -m execbound.monitoring.commands process`

Evaluate a bounded batch; optionally deliver findings.

| Argument | Required | Description |
| --- | --- | --- |
| `--config CONFIG` | no |  |
| `--all-tenants` | no | Evaluate every active workspace as its scheduled actor; with --deliver, send its findings. |
| `--deliver-local` | no | Send findings to the monitoring file's loopback test receiver; refused (FINDINGS_DESTINATIONS_CONFIGURED) where EXECBOUND_RUNTIME_CONFIG names a findings destination. |
| `--deliver` | no | Send findings to the destinations EXECBOUND_RUNTIME_CONFIG names. |
| `--limit LIMIT` | no | Default `50`. |
