# Retention, backup and recovery

This guide states what ExecBound retains and for how long, what a backup must contain, how to restore and how to prove that a restore is trustworthy. The procedure is tested locally and in CI against synthetic data; it is a runbook for the operator, not a managed backup service. Objectives are stated as adjustable defaults.

## What is retained, and what is purged

| Data | Where | Retention | Reason |
| --- | --- | --- | --- |
| Audit events and heads | `audit_events`, `audit_heads` | Indefinite | Every event is hash-chained to the previous one; removing any event breaks verification of everything after it. |
| Executions, transitions, impact facts, target claims, approvals | execution tables | Indefinite | Rolling-window limits read retained impact; an unsettled `DISPATCH_COMMITTED` or `INDETERMINATE` operation holds its reservation until exact evidence settles it. Purging would refund impact or erase uncertainty without evidence. |
| Executor public keys | `executor_keys` | Indefinite | A rotated or retired key still verifies the proofs for grants issued while it was current, and a key recorded `COMPROMISED` is what refuses one retroactively; deleting either row changes what a retained record proves. |
| Policy bundle contents and lifecycle | policy tables | Indefinite | Frozen plans and replays reference bundle content by digest. |
| Credentials and sessions | `credentials`, `human_sessions` | Rows stay; tokens expire and can be revoked | Only digests are stored; expiry and revocation are recorded, never deleted, so history keeps its actors. |
| Provider journals and tombstones | each provider's SQLite store | Indefinite | They are the only evidence that settles retained uncertainty. |
| Monitoring observations and findings | monitoring tables | Bounded per source (10,000 observations per source) and per collecting connection (200,000 observations per Tines connection; a Microsoft Entra connection's reads go on past its 200,000 and keep only what the rules would miss, at most about 8,000 more plus two for each recent ExecBound execution, [Scout](SCOUT.md#what-the-directorys-own-audit-log-shows)). Findings are never purged, and neither are observations, except a Microsoft Entra connection's directory audit observations, which the scheduled `monitor-process` removes once they are thirty days old, evaluated and cited by no finding, unless a rule still reads them or may yet read them ([Scout](SCOUT.md#what-the-directorys-own-audit-log-shows)) | Detective evidence; bounds prevent unbounded growth, and the audit purge keeps a directory's bound to a month of evidence rather than a lifetime. |
| Assistant questions, steps and answers | `assistant_turns` | Cleared thirty days after the turn completes, by the scheduled `recover` pass; the row and its token counts stay ([Operations](OPERATIONS.md#turn-the-consoles-assistant-on-for-a-tenant)) | A turn's text is never in the audit chain, so clearing it leaves every verification intact. |
| Authentication failure counters | `authentication_failures` | Operator's choice; may be purged with the owner connection | Bounded per-minute telemetry that nothing references; the runtime cannot delete it and no automated purge exists. |
| Replay exports and reports | operator files | Operator's choice | Sanitized derivatives; never a substitute for the database backup. |

Apart from those directory audit observations and the assistant's text, no automated purge exists and none is planned for the tables above; a backup that must keep either for longer than thirty days has to be taken before they age out. If storage growth becomes a concern, the safe options are archiving whole tenants after their retention obligation ends, or partitioning by tenant, both outside this repository today.

## The backup set

A recoverable backup contains all of the following, taken close together:

1. **The gateway database**, as a logical dump made with the owner role. Dump with `pg_dump -Fc -U <owner> <database>` so the `execbound` schema, its forced row-level security policies and the runtime role's grants restore exactly. Roles themselves are cluster objects; recreate `execbound_owner` and `execbound_app` on the target instance before restoring (see [Deployment](DEPLOYMENT.md#order-of-operations)).
2. **Every provider store**: each mock provider's SQLite file. Copy it with SQLite's online backup (`sqlite3 <store> ".backup '<copy>'"`), not a plain file copy of a live database.
3. **Configuration and keys**: the gateway JSON with its continuation keys, each provider's accounts file with its signing keys, and the database URLs. Losing provider evidence keys can prevent settlement of retained uncertainty, and losing continuation keys invalidates outstanding pending-status tokens. Store these in the secret store's own backup, not next to the dump.
4. **Independently retained checkpoints**: the `*.head.json` files that `execbound audit-export` publishes, kept somewhere the database administrator cannot silently replace. They are what turns "the restored chain verifies" into "the restored chain is the one we had". On a Community installation, a copy in `private/checkpoints/` is also placed on the live chain every hour by the jobs service's `audit-verify` ([Operations](OPERATIONS.md#verify-the-audit-chain-on-a-schedule)).

Take the database dump and the store copies while the gateway is stopped or quiescent when you can; the verifier reports a restore that is older than the live database rather than hiding it.

## Restore

1. Provision the target instance with the owner and restricted runtime roles.
2. Restore the dump into an empty database: `pg_restore -U <owner> -d <database> <dump>`.
3. Run the verifier against the restored database (below) with every checkpoint you retained, and with `--compare-live` when the original database is still reachable.
4. Restore the provider stores to the paths their accounts files expect and verify them with `--provider-store`.
5. Mount configuration and keys and apply any migrations newer than the dump with the owner role. Then run the verifier again with `--check-fence` (below), which reads the restored database as the runtime role and needs it at the gateway's schema revision; a dump of the current revision can be checked in step 3's run instead. Start the providers, then the gateway, and wait for `GET /health/ready`. On the one-host Compose installation, read [what stopping its database needs](INSTALL.md#when-the-database-stops-or-restarts) first: in an older compose file, the other processes have to be restarted after it.
6. As the final proof, export a tenant's history from the restored gateway as a current ADMIN and replay it offline against the checkpoint you retained before the incident:

   ```sh
   uv run execbound audit-export --database <restored-database> --tenant <tenant> --credential-file <admin.token> --output restored.json --checkpoint restored.head.json
   uv run execbound replay --input restored.json --trusted-head <retained.head.json> --output restored-replay
   ```

   The replay verifies the exported chain against the retained head and reconstructs every decision; `report.json` must be complete.

   `--database` names a restored copy on the server `DATABASE_URL` already points at, so only the database name changes and nobody renders a connection string with its password to read the copy. Leave it out to export from the database the environment selects.

## The verifier

`scripts/verify_restore.py` (module `execbound.recovery`) reads the restored database with the owner role and, per tenant, verifies the audit chain from genesis to the stored head, places each retained checkpoint on that chain, counts unsettled operations and, optionally, compares the head with the live database. It never writes to either database, never prints a connection string, and writes its JSON report to a new file only.

```sh
uv run python scripts/verify_restore.py --restored-database execbound_restore --compare-live \
    --checkpoint evidence/tenant-0.head.json --checkpoint evidence/tenant-1.head.json \
    --provider-store restored/endpoint.sqlite3 --provider-store restored/identity.sqlite3 \
    --output restore-report.json
```

`--restored-database` substitutes a database name into `MIGRATION_DATABASE_URL` for a restore on the same instance; `--restored-url` names another instance. Tenants come from `--tenant` and from the checkpoints; without either, the verifier enumerates tenants only when the role bypasses row-level security (a local superuser owner), and otherwise reports `NO_TENANTS_SELECTED`. With `--check-fence` it checks every tenant the copy holds, named or not (below).

A restore is of the whole database: the dump carries every tenant, and there is no way to bring one tenant back without the others. What matters after one is that every tenant is still behind its own fence in the copy, which the owner's reads above do not show: each names its tenant in the statement itself, and a local owner bypasses row-level security altogether. `--check-fence` reads the restored copy as the runtime role as well, through `DATABASE_URL` with the `--restored-database` name substituted, so it needs both URLs pointing at the instance that holds the copy, and stops as `NO_RUNTIME_DATABASE` before reading anything when they name different hosts or ports (`localhost` and `127.0.0.1` are one). It also reads the copy as the owner with row-level security off, because each tenant's chain as the runtime role reads it is held to the owner's, and an owner that row security filters would read through the very policies under test: two reads filtered alike agree whatever the policies hide. PostgreSQL refuses a read with row security off to a role a policy applies to, rather than filtering it, so an owner that does not bypass row-level security stops the check as `OWNER_FENCED`. Run it with an owner that bypasses row-level security, as a superuser does; without `--check-fence` the owner's reads stay under each tenant's fence. The fence check reads every tenant the copy holds, every workspace and every tenant with an audit chain, not only the tenants `--tenant` and the checkpoints name, which come first in the report: a workspace nobody retained a checkpoint for, one with no history among them, may be the one a policy lets see the others, and that shows only under its own fence. Each tenant it adds is checked in full, chain included, and appears in the report like a named one.

```sh
uv run python scripts/verify_restore.py --restored-database execbound_restore --check-fence \
    --checkpoint evidence/tenant-0.head.json --checkpoint evidence/tenant-1.head.json \
    --output restore-fence-report.json
```

It first runs the gateway's own startup check of the runtime role on the copy (the role is no superuser, does not bypass row-level security and owns no table, every table forces row-level security, and its privileges stay within the gateway's catalog), loading the plugins `EXECBOUND_PLUGINS` names first so their grants are expected, as every command does. A refusal is the report's problem `RUNTIME_UNSAFE`, and so is a read of that check the copy's privileges refuse, as a copy without the schema's `USAGE` refuses its schema revision; that check reads flags and grants, never a policy's body. Then, for every tenant of the copy, it sets that tenant's fence and, as the runtime role and in one read-only snapshot, counts every row of every table with a tenant column the role may read that belongs to another tenant, and reads the tenant's own audit chain. Each tenant's `fence` in the report is one of:

| `fence` | Meaning | Outcome |
| --- | --- | --- |
| `NOT_CHECKED` | `--check-fence` was not given. | Passes |
| `HOLDS` | No row of another tenant was visible, the tenant's own chain reads exactly as the owner reads it, and another tenant of the copy holds rows the runtime role reads under its own fence. | Passes |
| `ALONE` | As `HOLDS`, but no other tenant of the copy holds a row the runtime role reads under that tenant's own fence, as in a copy of a single workspace. Every other tenant's row in the copy was still counted, so a fence that showed this tenant one would have read `CROSSES`; what the run cannot show is that the copy held any row for the fence to keep out. | Passes, and is not `HOLDS` |
| `CROSSES` | A row of another tenant was visible under this tenant's fence: a policy that admits too much, or a role that bypasses row security. | Fails |
| `HIDES_OWN` | The tenant's own chain does not read as the owner, with row security off, reads it: the copy's policies hide rows of the runtime role's own history, or its privileges refuse the read. A fence that admits nothing also keeps everyone else out, so it must not pass. A read that fails any other way, at its 30-second limit for one, stops the check as `RUNTIME_UNAVAILABLE` instead. | Fails |

A restore that lost the forced row-level security of one table fails as `RUNTIME_UNSAFE`, and one that lost the runtime role's grants (`pg_restore --no-acl`), or only the schema's `USAGE`, fails as `RUNTIME_UNSAFE` and every tenant's `HIDES_OWN`: without `USAGE` the role may read no table, so there is no row to count, and its chain read is refused.

A policy that admits too much passes the startup check, which reads no policy's body, and the fence check sees it only through the rows the copy holds. A tenant is `CROSSES` when, under its fence, the runtime role reads a row another tenant holds. A policy on one table that admits every row therefore fails as the `CROSSES` of each tenant that can see another tenant's row in that table: every tenant, when two or more tenants of the copy hold rows there, but when only one does, the others are `CROSSES` and the one whose rows they see can still read `HOLDS`. Such a policy is not seen at all on a table that holds no row a tenant could see as another's: an empty one, or any table of a copy that holds a single tenant. Nor is a policy lost from a table whose row-level security is still forced: it hides that table's rows from every tenant rather than exposing them, and shows only on the audit chain's tables, as `HIDES_OWN`, where the owner's read, made with row security off, still holds the chain. `HOLDS` counts the other tenants' rows over every table the runtime role may read together, so it is a statement about the rows in the copy, not about each table's policy.

| Result | Meaning | Outcome |
| --- | --- | --- |
| `chain_ok: false` | An event was altered, removed or reordered relative to the stored head. | Fails |
| `MATCHES_CHECKPOINT` | The retained head is the restored head. | Passes |
| `AHEAD_OF_CHECKPOINT` | The retained head sits on the restored chain; later events exist. | Passes |
| `BEHIND_CHECKPOINT` | The restore lacks events the retained head proves existed. | Fails: data loss |
| `DIVERGES_FROM_CHECKPOINT` | The restored chain carries a different hash at the retained sequence. | Fails: history replaced |
| `BEHIND_LIVE` / `AHEAD_OF_LIVE` | The restore is older or newer than the live database. | Passes; the gap is the recovery point |
| `DIVERGES_FROM_LIVE` | Live and restored chains disagree. | Fails |
| `unresolved_executions` | Operations still holding reservations after the restore. | Informational; reconcile them from provider evidence |
| `STORE_CORRUPT` / `STORE_UNREADABLE` / `STORE_WITHOUT_JOURNAL` | A provider store failed its integrity check or has no journal table. | Fails |
| `CROSSES` / `HIDES_OWN` / `RUNTIME_UNSAFE` | With `--check-fence`, a tenant's fence failed in the restored copy, or the runtime role there failed the startup check (above). | Fails |

To hold a report to what you expect rather than read it by eye, in a rehearsal's script for example, `python -m execbound.reports` checks it one named expectation at a time and reads only:

```sh
uv run python -m execbound.reports restore --report restore-report.json \
    --tenant t0=evidence/tenant-0.head.json --tenant t1=evidence/tenant-1.head.json \
    --ok --tenants-exactly t0,t1 --stores-ok --checkpoint t0=MATCHES_CHECKPOINT --live t1=MATCHES_LIVE \
    --fence t0=HOLDS --fence t1=HOLDS
uv run python -m execbound.reports replay --report restored-replay/report.json --complete --min-decisions 1
```

`--tenant NAME=HEAD_FILE` gives the tenant of a retained checkpoint a short name, and every other flag names tenants that way, problems included (`--problem tenant:t0:CHAIN_BROKEN`). The restore checks are `--ok` or `--not-ok`, `--no-problems`, `--problems-exactly`, `--problem`, `--forbid-problem`, `--tenants-exactly`, `--stores-ok`, `--stores-exactly` and, for one tenant, `--checkpoint`, `--live`, `--fence`, `--chain-ok`, `--unresolved` and `--events-min`; the replay checks are `--complete` or `--incomplete`, `--issues-exactly`, `--decisions` and `--min-decisions`; and `tenant-id --file HEAD_FILE` prints a checkpoint's tenant id. Each check prints `PASS <check>` or `FAIL <check>: expected <x>, found <y>`, and a failed check exits 1. A check that could pass by mistake exits 2 before anything is compared: an unknown flag, an unbound name, a status or problem the verifier never reports, or a report that is unreadable, larger than 1 MiB, carries a duplicate key, is not version 1 or lacks the fields its writer gives it. A report written before the verifier read the fence has no `fence` field and is refused that way.

CI performs the round trip after the demonstration: it dumps the demonstration database with `pg_dump`, restores it into a second database on the same instance, verifies both tenants against the checkpoints the demonstration published while comparing with the live database and with `--check-fence`, holds each tenant's fence to `HOLDS` and, since the fence check reads every tenant the copy holds, the report to those two tenants and no other, and exports each tenant from the restored database to replay it offline against its own original checkpoint.

## Uncertain checkpoint grants

An [externally executed operation](CHECKPOINT.md) reaches uncertainty by its own route and has fewer ways out of it. This is what the scheduled run does and what it deliberately does not.

The same is true of a grant an [Arcade logic extension](ARCADE.md) opened: the correlation row is the extension's own bookkeeping and this run does not read it, so what the run sees is an ordinary grant. A control point that states a result settles the row terminally and drains it out of this run's uncertain counters; one that says nothing leaves exactly what a silent Gate executor leaves.

**The sweep settles nothing.** A grant whose report window closes unreported moves `DISPATCH_COMMITTED` to `INDETERMINATE` with the reason `UNREPORTED_GRANT`; the impact stays `UNRESOLVED` and the canonical claim stays held, so the grant keeps charging every scope and keeps its target unavailable to that tenant. The run takes the checkpoint branch on the row's report window before any connector is looked up, because a grant has no connector by construction, and re-reads every condition under the fence so a report that landed between the selection and the sweep decides instead of the run. `reconcile_operation`, the connector path both `execbound reconcile` and the run's cancellation mode use, **refuses a checkpoint in every mode**: settling one `FAILED_NOT_EXECUTED` on cancellation evidence would be the refund on absent evidence the contract forbids, and asking a provider about an operation ExecBound never dispatched is not a question worth asking.

**The administrator exit is the Activity page, not the CLI.** `execbound reconcile` looks the account up in the live connector inventory and refuses. The console's settlement control takes the executor's own signed record and goes to the connector-free reconciliation with the verifier that checks the tenant's registered keys. It is offered for a grant nothing has settled — `DISPATCH_COMMITTED` or `INDETERMINATE` — and for the one settled row `reconcile` admits a second settlement of: a grant a control point closed at `FAILED_EFFECT_UNKNOWN`, tier `ASSERTED`, retained reason `REPORTED_FAILURE`, where the same form takes an ADMIN-signed non-execution, rewrites the impact to a non-execution and releases the claim. Another settled row is offered none, and an attempt against one is refused `INVALID_STATE` and audited under an event that names no execution.

Two consequences belong here rather than being discovered:

- **Settling a live grant closes ExecBound's route on its executor and does not stop it acting.** The act grant is still live and nothing revokes it, ExecBound dispatched nothing, and it cannot undo what the executor does at the vendor; the executor's later report is then refused unless it restates the settled outcome. Like the emergency stop, it cannot recall an issued grant.
- **A grant only a compromised key could have attested has no *attested* exit.** Every report carrying a signed record, the administrator's settlement and a replacement key are refused at the same verifier. What is no longer true is that such a grant has no exit at all: the verifier is loaded only for a report that presents a record, so an executor still holding its report secret settles the row on its **bare word** — `EXECUTED`, or `FAILED_EFFECT_UNKNOWN` with reason `REPORTED_FAILURE` — which confirms the impact and puts the row in front of this run, which frees the target once the act window has passed. What that tenant loses is the ability to answer the statement, because the correction needs a key usable at the grant instant and no later registration can be one. A grant nobody reports at all still has no exit: the sweep leaves it `INDETERMINATE` with impact charged and the claim held, and nothing releases either afterwards. That is the direction the contract requires — retained uncertainty over a refund on evidence nobody trusts.

**The claim an assertion left held has two exits, and this run is the one that fits every settled assertion.** Attested evidence against a settled row is refused by the outcome route as a contradiction, and promotion from `ASSERTED` to `ATTESTED` is not built. An administrator's settlement of a settled checkpoint is refused `INVALID_STATE` except for the correctable row above, whose correction releases the claim itself and is the other exit. For every settled assertion this run is what frees the target: it selects settled checkpoints at tier `ASSERTED` whose claim is unreleased and whose act window has passed, re-reads all of it under the fence, releases the claim and appends `execution.claim_released` with the reason `ACT_WINDOW_CLOSED`. The execution is untouched and stays `EXECUTED` at tier `ASSERTED` with its impact confirmed, because what the act window's closing ends is the executor's authority to act rather than the charge for what it says it did.

**The run also ends an approval nobody answered.** An approval reaches `EXPIRED` only when something touches it — the agent's next identical request, or a human's late decision — so one the agent never retried and no human ever opened stayed `PENDING` for as long as the tenant kept its rows, and its execution stayed `PENDING_APPROVAL`. The run selects executions still `PENDING_APPROVAL` whose approval is `PENDING` or `APPROVED` and whose `expires_at` passed more than the grace period ago, re-reads every condition under the fence, and ends the row through the same helper a late touch uses: the approval to `EXPIRED` and the execution to `STALE_AUTHORIZATION`, reason `APPROVAL_EXPIRED`, with the `approval.transition` and `execution.transition` events in the chain and the run's ADMIN as the actor. It counts one `expired`.

**It releases nothing there, because a pending approval holds nothing.** Measured on a local reproduction thirty-six hours past a ten-minute deadline: no `execution_impact` row, no `resource_claims` row, and both demo rules projecting zero. Admission writes the impact row and the canonical claim on the path that reserves, after an approval has been verified and consumed, so a tenant loses no capacity and holds no target while a human ignores an approval. What the sweep repairs is a lifecycle that otherwise never terminates and the count of executions held for a person that the console's Home reads.

A decision arriving in the same instant is not a race either way: both writers take the same tenant fence, and `decide_approval` independently refuses a decision at or past `expires_at` and records the lapse itself, so the window between an expiry and the next run can never be decided in. The console compares `expires_at` to the server's clock rather than trusting the state alone, and a lapsed approval stays readable under Approvals' Lapsed view on both sides of the sweep.

**Read the run's counters, and alert on the right one.** `unresolved` means a row was due and would not move; that is the alerting signal. A grant inside its report window is counted `open_grants` and one already in retained uncertainty `uncertain_grants`, and **neither is an alert** — both used to land in `unresolved`, which alerted an operator five minutes after every grant was issued and, for a swept one, forever. `swept`, `settled_grants`, `released` and `expired` count what the run did and what something else did before it got there. The per-run counts are listed in [Operations](OPERATIONS.md#recover-an-uncertain-execution).

## Objectives

| Objective | Default | How to change |
| --- | --- | --- |
| Recovery point (RPO) | The interval between dumps; the verifier shows the exact gap as `BEHIND_LIVE`. | Schedule dumps and store copies more often; use PostgreSQL continuous archiving or the hosted provider's point-in-time recovery for the gateway database. |
| Recovery time (RTO) | Manual: provision, restore, verify, restore stores, start, readiness. | Automate steps 1 to 5 with the container image and rehearse them. |
| Checkpoint retention | One `head.json` per tenant per export, kept off the database host. | Export and retain after every administrative change and on a schedule. |
| Rehearsal | CI on every change with synthetic data. | Rehearse on the real deployment on a fixed cadence and record the report. |

## What this proves and what it does not

A passing verification proves the restored history is internally consistent and identical to the retained checkpoints up to their sequences, that no unsettled operation vanished, and that provider stores are readable; with `--check-fence`, it also proves that the runtime role passes the gateway's startup check on the copy and that, for every tenant the copy holds as a workspace or an audit chain, no tenant's fence shows it a row another tenant holds in the copy or hides its own history. A tenant id that holds rows in other tables but has neither is counted under every other tenant's fence, never read under its own. The fence check counts rows of tables with a tenant column; it reads no table the runtime role may not read and none fenced to a signed-in account rather than a tenant, and it reads no policy's body, so a policy that would admit rows no other tenant holds in the copy goes unseen. It does not prove that the provider stores and the database are from the same instant, that keys were backed up correctly, or that anything outside these files exists. Keep the four parts of the backup set together and test the whole sequence, not the dump alone. Hosted PostgreSQL backups taken by the platform cover the database only; the stores, keys and checkpoints still need their own copies.
