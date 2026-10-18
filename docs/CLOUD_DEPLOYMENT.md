# Deploy it in your cloud

[Install](INSTALL.md) puts ExecBound on one host with Docker and nothing else. This page is the next question: can it run in our AWS, Azure or Google Cloud account, on the managed services we already pay for?

It can, and the mapping is short, because ExecBound needs four things:

1. **One container for the gateway.** It is a long-lived HTTP service holding a connection pool, not a request handler.
2. **PostgreSQL 17.** A managed instance is fine, with the two conditions under [caveats every recipe repeats](#caveats-every-recipe-repeats).
3. **The private configuration mounted read-only.** One JSON file, holding the connector credentials and the continuation keys, at the path `EXECBOUND_RUNTIME_CONFIG` names.
4. **Somewhere to run the scheduled jobs, with TLS in front.** Short-lived commands on a timer (two always, more where monitoring or mail is configured), and a proxy or load balancer terminating TLS ahead of the gateway.

Every recipe below is a mapping of those four onto one cloud's services. [The image and its processes](DEPLOYMENT.md) is the contract each recipe expresses; nothing here replaces it.

## What is tested and what is not

**The one-host install is exercised on every change** by CI's `fresh-machine` stage, which builds the image from the commit, runs the three install commands from an empty directory and governs a first action ([Install on one host](INSTALL.md)).

**The three recipes below are described and not yet proven.** No one has run ExecBound on ECS, Container Apps or Cloud Run. They are written from the process contract rather than from a deployment, and this sentence stays here in these words until someone runs one and records it. Treat them as a starting point you will verify, not as a supported configuration.

## What every recipe states

Each recipe below says the same five things, in the same order, because these are where a cloud deployment goes wrong:

1. **The process table mapping.** Which cloud object runs the gateway, which runs each job, and where the providers live.
2. **The configuration mounted as a secret.** One file, read-only, never an environment variable holding the whole document in plain text on a service definition.
3. **Migrations run from a one-off task with the owner connection, before the new gateway starts.** A gateway older than the schema fails readiness and refuses to serve, which is the intended behaviour and not a reason to start it anyway.
4. **`GET /health/ready` as the probe.** It checks that PostgreSQL is reachable at the expected schema revision with a correctly restricted runtime role. `GET /health/live` answers that the process is up and checks nothing.
5. **The job schedule.** `execbound recover --all-tenants --limit 50` every fifteen minutes and `execbound notify --all-tenants --limit 50` every minute, or as often as the scheduler allows: an approval's default deadline is two minutes, and the drain stops sending fifteen seconds before it. Where external monitoring is in use, add `python -m execbound.monitoring.commands process --config <monitor.json> --limit 50` every five; `monitor.json` holds `{"admin_token": "<an administrator's token>"}`. Where monitoring connections are collected on a schedule, add `python -m execbound.monitoring.commands collect-due --all-tenants --key-files <dir> [--collector-key <file>] [--platform-app <file>]` every five, on a host that holds those files: the collector's private key and the platform app's credential belong to the collecting task alone, never to the gateway ([scheduled collection](TINES_MONITORING.md#scheduled-collection-and-evaluation)). Where a mail relay is configured, add `execbound invitations-run --limit 50` every two, and where its `mail` block also sets `weekly_summary: true`, `execbound weekly-summary-run --limit 50` every hour. Alternatively, run `execbound jobs` as one long-lived process with a state directory: it runs the same jobs on the schedule [Install on one host](INSTALL.md#the-jobs-service) gives, `notify` every fifteen seconds where an approval destination is configured, and takes a lock so that a second replica never runs one twice.

## AWS

**Process table.** The gateway on **ECS Fargate** behind an Application Load Balancer, or on **App Runner** where you would rather not manage a load balancer. PostgreSQL on **RDS for PostgreSQL 17**. The jobs as **scheduled ECS tasks** on EventBridge Scheduler, one rule per command, each running the same image with a different command. A team already running **EKS** should run the gateway as a Deployment and the jobs as CronJobs instead; nothing in the image prefers one over the other.

**Configuration.** Put the gateway JSON in **Secrets Manager**. ECS's `secrets` block delivers a secret as an environment variable, and the gateway reads a file, so either start each process with `python -m execbound.boot <command>` and deliver the document as `EXECBOUND_RUNTIME_CONFIG_JSON`, or fetch it in a read-only init step and write it to a tmpfs path. The boot module writes what it is handed to an owner-only file and removes it from the environment before the process starts ([Deployment](DEPLOYMENT.md#not-covered)). Do not bake it into the image: `.dockerignore` is an allowlist precisely so it cannot be copied in by mistake.

**Migrations.** A one-off `RunTask` of the same image with `MIGRATION_DATABASE_URL` set to the owner connection and the command `alembic upgrade head`, run to completion before the new service revision starts. Wire it as a deployment step, not as a container that races the gateway.

**Probe.** Target group health check on `GET /health/ready`, and the ECS container health check on `GET /health/live`.

**Jobs.** An EventBridge Scheduler rule for each command, at the cadences above, each targeting an ECS task definition that shares the gateway's image and configuration.

## Azure

**Process table.** The gateway as an **Azure Container Apps** app. PostgreSQL on **Azure Database for PostgreSQL Flexible Server**. The jobs as **Container Apps Jobs** on a cron trigger. **AKS** otherwise, with the same Deployment and CronJob shape as EKS.

**Configuration.** A Container Apps **secret**, referenced as a secret volume mount so the file lands read-only at the configured path. Key Vault references work where the app has a managed identity.

**Migrations.** A **manual-trigger Container Apps Job** running the same image with the owner connection, started and awaited before the new revision is activated. Container Apps revisions are the natural place to gate this: activate the new revision only after the job succeeds.

**Probe.** A readiness probe on `GET /health/ready` and a liveness probe on `GET /health/live`. Container Apps ingress needs the target port set to the container's 8000.

**Jobs.** A cron-triggered job for each command, at the cadences above.

## Google Cloud

**Process table.** The gateway on **Cloud Run with a minimum instance count of 1**, which is what keeps the connection pool alive; a service that scales to zero pays the pool's cost on every cold request and drops in-flight work. PostgreSQL on **Cloud SQL for PostgreSQL 17**. The jobs as **Cloud Run Jobs** invoked by **Cloud Scheduler**.

**Configuration.** A **Secret Manager** secret mounted as a volume, so the process reads a file rather than an environment variable.

**Migrations.** A **Cloud Run Job execution** of the same image with the owner connection, awaited before the new revision takes traffic. Cloud Run's revision traffic split is the gate.

**Probe.** A startup probe and a liveness probe; point the startup probe at `GET /health/ready` and the liveness probe at `GET /health/live`.

**Jobs.** A Cloud Scheduler job for each command, at the cadences above, each executing one Cloud Run Job.

## What not to use

**Plain serverless functions.** Lambda, Azure Functions in the consumption plan, Cloud Functions. The gateway is a long-lived service holding a connection pool and in-flight execution state, not a request handler. A function per request opens and abandons pools, cannot hold the advisory locks the jobs rely on, and turns every cold start into a readiness failure.

**Databricks Apps with Lakebase.** This one is worth stating for its reasons rather than as taste, because the combination looks plausible:

- **Databricks Apps run on serverless compute**, which suits an interactive application rather than a service that must be up between requests.
- **Lakebase scales to zero and closes idle connections, and advisory locks are lost when it does.** That is precisely the mechanism the jobs service uses so a scheduled job never runs twice. Losing it does not produce an error; it produces two concurrent runs of a job written on the assumption that there is one.
- **Lakebase allows no superuser connection**, and the install creates its own database roles: a schema owner and a restricted runtime role that owns no tables and cannot bypass row-level security.

## Caveats every recipe repeats

**More than one gateway is possible, within stated limits.** [Run more than one gateway](DEPLOYMENT.md#run-more-than-one-gateway) says what the replica-safety test proves, what it does not, and what every replica must share. One replica is the simpler starting point.

**Providers must be reachable over HTTPS** unless they share the gateway's host. The connector refuses cleartext to anything but a loopback address, and there is no opt-in for cleartext on a private network. A provider on another host, even inside your VPC, serves HTTPS with a certificate the gateway can verify.

**Mock providers ship by default.** A fresh deployment governs the two protected mocks. Real actions need connector credentials for a real vendor, or an external executor reporting through the [checkpoint](CHECKPOINT.md), before anything outside ExecBound changes.

**What your managed PostgreSQL must allow.** Creating the schema owner and the restricted runtime role, and enforcing forced row-level security on tenant tables. A managed service that refuses either cannot run ExecBound. Readiness refuses a runtime role that can bypass row-level security, so a deployment that gets this wrong fails loudly at startup rather than quietly at query time.

**Back up the provider stores with the database.** Each provider keeps a store holding the journals that settle retained uncertainty. Losing one loses the evidence that an uncertain operation is resolvable. [Retention, backup and recovery](RECOVERY.md) describes the backup set and the verifier.

**Nothing here is a validated public deployment.** The [threat model](THREAT_MODEL.md) states what is evidenced and what is not, and it is the document to read before putting a gateway on the public internet.

## AGPL and your legal team

ExecBound's server is licensed under the **AGPL-3.0-only**; the Python client, the provider protocol and the connectors are Apache-2.0. Two sentences cover what a managed security service provider usually asks:

- **The AGPL places no restriction on whom you run ExecBound for.**
- **Unmodified use as a service carries no source obligation; a modified version offered to those clients does.** The AGPL's network clause attaches to the modifications you serve, not to the act of serving.

This is a description of the licence, not legal advice, and your counsel should read the licence text rather than this paragraph.
