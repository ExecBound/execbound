# Deployment

This guide covers the container image and the order of operations for running the gateway and the two protected mock providers outside the local demonstration harness. It describes what the image contains and how to place configuration, secrets, the database, TLS termination and health probes around it. The hosted service is one deployment of this image; this guide describes the image and the order of operations, not that deployment's own configuration. Before connecting a real vendor, work through [Before a production deployment](OPERATIONS.md#before-a-production-deployment) and the [threat model](THREAT_MODEL.md).

## The Community install

One host, Docker and nothing else, in three commands:

```sh
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/execbound:/install" execbound:community execbound init /install
cd execbound && docker compose up -d
docker compose run --rm gateway execbound quickstart
```

`execbound init` writes the compose file, the role script, the starter ruleset, a `.env` with two generated database passwords, and the private configuration with fresh continuation keys, per-provider dispatch and control tokens and evidence keys. `docker compose up -d` starts PostgreSQL, the gateway, both mock providers and the jobs service. `execbound quickstart` applies the schema and builds the deployment the private configuration describes, ending with two governed requests, one executed and one refused. [Install](INSTALL.md) is the runbook, including the same work one command at a time for a deployment that wants its own tenant rather than the demonstration one.

The target is **under ten minutes from nothing to a first governed decision**, and it is measured rather than asserted: every change is installed from nothing with the three commands before it is published, by a `fresh-machine` check that runs them from an empty directory, times them and fails over ten minutes. A runner whose Docker already holds the database image skips that pull, and [Install](INSTALL.md) gives what a clean runner measured. The development repository also tests each change's upgrade: its own `fresh-machine` job populates an installation on the revision the change was made on, upgrades it by the runbook's two upgrade commands, and verifies its backup before and after.

**One substitution.** `execbound:community` is built locally (`docker build --tag execbound:community .`). No release has been published to a registry yet, so there is no pull reference to give; when there is, `EXECBOUND_IMAGE` in the written `.env` becomes it and nothing else changes ([Releases](RELEASE.md)).

The installation runs the two mock providers. It is complete for one organisation, which is what Community is, and it is not a production deployment: the rest of this document is the process table and the contract a real one must express.

## The image


`Dockerfile` builds one image for every ExecBound process; the command selects the role. The build argument `EXECBOUND_COMMIT` records the source commit in the image, and `/health/ready` reports it as `commit` beside the package `version`; a build that omits it reports the platform's own `RENDER_GIT_COMMIT` where one is injected, and null otherwise. CI passes the checked-out commit. When the gateway has loaded a plugin, `/health/ready` also carries `plugins`, the loaded plugin names, and `plugin_api`, the plugin API version, and never a plugin's configuration. The build argument `CONSOLE_EDITION` chooses the console edition the image carries: `core`, the self-hosted console, unless the build names another, for which the console's `build:<edition>` script runs, so an edition with no build script fails the build ([Surfaces](SURFACES.md#how-the-console-is-served)). A process that serves the console reports the edition its build names as `console` in `/health/ready`.

- **Built from the locked environment only.** A builder stage installs the runtime dependency group from `uv.lock` with `uv sync --locked --no-dev --no-editable` and installs the package itself as a wheel. Development tools, test fixtures and browsers are not present. The wheel contains only `execbound`; the synthetic packs and validation harness in `src/execbound_harness` are never packaged.
- **The console is built in a stage that ends before the image.** A Node stage (`node:24.21.0-bookworm-slim`, pinned by digest) enables corepack, installs the console's locked tree with pnpm at the exact version and hash `console/package.json` names, under a seven-day minimum release age and with no dependency install scripts, and runs the Vite build inside its size budget. The builder copies only the built files into `src/execbound/surfaces/console_dist` before it installs the package, so the wheel and the image carry them; the runtime stage never holds Node, pnpm or `node_modules`, which the smoke test's `test ! -e /build` and uid checks keep true. The console is the surface a person opens and is not optional: every console route answers 503 with a plain sentence where the package carries no build, so an image built without the Node stage is a deployment nobody can sign in to ([surfaces](SURFACES.md#how-the-console-is-served)).
- **Pinned bases.** The Python base and the uv binary are pinned by digest. Treat a digest update like any other dependency change and let CI rebuild the image.
- **Non-root.** The runtime stage creates user `execbound` (uid 10001) and runs as it. Nothing under `/opt/execbound` or `/srv/execbound` is writable by that user, and no process writes there. The user has `/bin/sh` as its login shell and an empty `~/.ssh` (mode 0700), which a hosting platform's SSH or dashboard shell may need to open an operator session as a non-root user. The image runs no SSH server.
- **No configuration or secrets in layers.** `.dockerignore` is an allowlist: only `pyproject.toml`, `uv.lock`, `src/`, `alembic.ini`, `migrations/`, the client package's sources and `console/` (its sources, never its `node_modules` or a local build) enter the build context. `.env` files, `local-data/`, private fixtures and caches cannot be copied in by mistake.
- **Migrations travel with the image** under `/srv/execbound/migrations` so the owner connection can apply them from a one-off container of the same build.
- **Health check.** Every process listens on port 8000 inside its own container, so the image's `HEALTHCHECK` is a TCP connection to that port and fits the gateway and both providers. Orchestrator readiness for the gateway should use `GET /health/ready` (below).

Build and inspect:

```sh
docker build --build-arg EXECBOUND_COMMIT=$(git rev-parse HEAD) --tag execbound:local .
docker run --rm execbound:local id -u
docker run --rm execbound:local execbound --help
```

CI builds the image on every push and pull request, in the same job as the tests, and smoke-tests it without a database: uid 10001, the login shell and private `~/.ssh` with no SSH server, the CLI help, `alembic history`, `GET /health/live` answering `ok`, `GET /health/ready` answering 503 while no database is reachable, and no private files inside the image. It then reads `core` from the console build the image carries.

## Processes and their inputs

| Process | Command | Inputs |
| --- | --- | --- |
| Gateway | the image default (`uvicorn execbound.app:create_app --factory --host 0.0.0.0 --port 8000`) | `DATABASE_URL` for the restricted runtime role; `EXECBOUND_RUNTIME_CONFIG` pointing at the private gateway JSON mounted read-only |
| Endpoint mock provider | `uvicorn execbound_connectors.mock_app:create_mock_app --factory --host 0.0.0.0 --port 8000` | `EXECBOUND_MOCK_PROVIDER=mock_crowdstrike`, `EXECBOUND_MOCK_ACCOUNTS_PATH` (private accounts file, read-only), `EXECBOUND_MOCK_DATABASE_PATH` (SQLite store on a persistent volume) |
| Identity mock provider | same command | `EXECBOUND_MOCK_PROVIDER=mock_entra` and its own accounts file and store |
| Arcade hook surface | `uvicorn execbound.arcade.boundary:create_arcade --factory --host 0.0.0.0 --port 8000` | The same `DATABASE_URL` and the **same** `EXECBOUND_RUNTIME_CONFIG` file the gateway reads. Run it only where the private configuration carries an `arcade` block |
| Jobs service | `execbound jobs` | `DATABASE_URL`, `EXECBOUND_RUNTIME_CONFIG`, and a state directory holding `jobs.json` and `monitor.json`. Runs `recover --all-tenants`, `notify --all-tenants` and `audit-verify --all-tenants`, which hold no credential, only once `jobs.json`, quickstart's mark, exists (`audit-verify` with `--checkpoints` where `/srv/private/checkpoints` exists), and `monitor-process`, which runs as the jobs administrator in `monitor.json`; and, only where the state directory holds a `key-files` directory of operator key files (`<connection id>.env`) or the collector directory (`--collector`, `/srv/collector` by default) holds the collector's `collector-private.json`, during a rotation the retiring `collector-previous.json`, or the platform app's `scout-app.json`, `collect-due --all-tenants`, which holds no workspace credential and collects each due monitoring connection whose key file is there, given `--collector-key`, each Tines key pasted in the console and sealed for the collector, and given `--platform-app`, each Microsoft Entra directory that consented to the deployment's app; each on its interval, behind an advisory lock held for the interval; see [Operations](OPERATIONS.md#the-jobs-service) |
| Migration (one-off) | `alembic upgrade head` | `MIGRATION_DATABASE_URL` for the schema owner |
| Collector key pair (one-off) | `python -m execbound.monitoring.commands collector-keygen --output <directory>` | Nothing but the output directory. `collector-public.json` goes into the gateway's private configuration as `scout.collector` and makes **Connect Tines** available in the console; `collector-private.json` is the collector's alone (the jobs service's own `/srv/collector` mount in a Compose install, never a directory the gateway mounts), and opens every key the console sealed. A new pair is moved to with `collector-reseal`, while the collector holds both keys; see [Tines monitoring](TINES_MONITORING.md#connect-tines-from-the-console) |
| Platform app (one-off, for Microsoft Entra consent) | An app registration in your own directory, multi-tenant or single-tenant, with the redirect URIs `<origin>/connect/entra/signed-in` and `<origin>/connect/entra/consented`, ID token issuance, the directory-role claim (`groupMembershipClaims` `DirectoryRole`), the application permissions `AgentIdentity.Read.All`, `Application.Read.All`, `AuditLog.Read.All` and `Directory.Read.All`, and a certificate credential | Its public values go into the gateway's private configuration as `scout.entra`, beside `scout.collector`: `client_id`, `authority` (`organizations`, or your directory's id for a single-tenant registration) and `display_name`, the name a directory administrator sees under Enterprise applications; that makes **Connect Microsoft Entra** available in the console and serves the two consent routes, which answer 404 without it. The certificate and its private key, with the client id, are the collector's alone as `scout-app.json` (`{"client_id", "certificate_pem", "private_key_pem"}`, owner-only, in the jobs service's own `/srv/collector` mount in a Compose install); rotate the certificate every 90 days. See [Scout](SCOUT.md#connect-microsoft-entra-from-the-console) |
| Administration (one-off) | `execbound <command>` per [Operations](OPERATIONS.md#administer-tenants-credentials-approvers-and-bundles) | `MIGRATION_DATABASE_URL` for owner commands, `DATABASE_URL` plus a mounted ADMIN credential file for bundle commands |

The gateway JSON has the shape documented in [Surfaces](SURFACES.md#private-configuration-and-startup). Each connector's `origin` must name the provider as the gateway resolves it. The connector refuses cleartext to anything but a loopback IP address (`ConnectionConfig` in `provider/connector.py`), so a provider on another host, even on a private network, must serve HTTPS with a certificate the gateway can verify; an `http://` origin works only for a provider on the same host as the gateway. This is a decision rather than a gap: there is no opt-in for cleartext on a private network, and the deployment validated below serves its mocks over HTTPS with bearer authentication for that reason. Dispatch and control tokens and evidence keys must differ between provider families; startup refuses reuse.

**The Arcade hook surface is a second public process, and it costs two things worth writing down.** It holds a **runtime**, not a loopback intake, so it opens its own connection pool against the same database: the pooler has to have room for the gateway's pool and this one. And the two processes must be given the **same** private configuration file, or they will disagree about which tools are governed — a disagreement nothing downstream would notice, because each process answers correctly for the map it holds. It serves `POST /pre`, `POST /post` and `GET /health` and answers 404 to every other method and raw path it holds; `GET /health` is not a second readiness implementation but the application's own `/health/ready` under a shorter path, which is what Arcade's configuration and a platform's health check ask for.

Provider stores must persist: a provider that loses its SQLite store loses the journals that settle retained uncertainty. Mount `EXECBOUND_MOCK_DATABASE_PATH` on a volume and back it up with the gateway database as [Retention, backup and recovery](RECOVERY.md) describes.

## Order of operations

1. **Provision the database roles.** Locally, `scripts/local_setup.py` creates the owner and restricted runtime roles and both databases; on a managed database, create the same two roles with its own tools. The runtime role must own no tables and must not be able to bypass row-level security; `GET /health/ready` refuses a role that can.
2. **Apply migrations with the owner connection** from a one-off container of the exact image you will run:

   ```sh
   docker run --rm -e MIGRATION_DATABASE_URL=<owner URL> execbound:local alembic upgrade head
   ```

   Apply migrations before starting a gateway of that build. Downgrades that would drop history are refused by design.
3. **Start the providers** with their accounts files and persistent stores. A provider on the gateway's own host may use a cleartext loopback origin; any other provider, on a private network or not, serves HTTPS with a certificate the gateway verifies. Every provider endpoint authenticates its caller, so where a provider is reachable from is a matter of exposure, not of authority.
4. **Generate the gateway configuration** with independent continuation keys and per-provider credentials, and mount it read-only at the path `EXECBOUND_RUNTIME_CONFIG` names. The `origin` field is the public HTTPS origin clients and approvers will use (see TLS below).
5. **Start the gateway** and wait for `GET /health/ready` to answer `ready`. Readiness checks the schema revision and the runtime role's restricted privileges; it does not check provider health, an active bundle or inventory freshness, so a ready gateway can still refuse a particular action.
6. **Administer tenants, credentials, approvers and bundles** with one-off containers running the `execbound` commands; issued tokens are written to files you mount, never printed.

Rolling a new image: build, apply its migrations with the owner connection, then replace the processes. A gateway older than the schema fails readiness rather than serving.

## Run more than one gateway

Community may run several gateways behind a load balancer, and the supported tooling for it — a Helm chart, reference architectures, an air-gapped bundle — is Enterprise. This section is published because the replica-safety test passes; it would say pending and name the test if it did not.

**What is proved.** `tests/test_replica_safety.py` checks two guarantees against one PostgreSQL and one tenant, each twice: once with two gateways in one process, each with its own engine and connection pool, and once with two gateway operating system processes, each the image's application under uvicorn reading the same private configuration file, reached over HTTP with an agent's credential and an approver's console session. Six concurrent admissions at a ceiling of three admit exactly three, and the other three are refused rather than lost; one approved execution retried six times across both gateways issues exactly one dispatch ticket and charges exactly one unit of impact. Across the two processes the approval is decided on the second process's console, and the protected mock provider, a process of its own, receives exactly as many dispatches as were admitted. The shared state is in the database and both replicas reach it through the same fences, so a gateway process that counted its own admissions rather than the tenant's would fail the two-process check, which the in-process one cannot catch.

Three more paths are checked across processes. Six MCP `execute` calls at once, three on each gateway process, at the same ceiling of three, execute three and refuse three for the limit, and each call of the older protocol revision arrives on the process that did not see its handshake and is answered as though it had. A person's console session signed in on one process reads on the other, and once ended on either process it is refused on the other at its next request. Two `execbound recover` processes that have both read one uncertain operation as unsettled settle it once, and each reports it executed. A gateway process that counted its own admissions, kept MCP sessions in its own memory or remembered a console session it had already read, or a recovery run that kept its own record of the operations it had settled, would fail these checks.

**What is not.** Nothing else is checked across processes: not the Arcade hooks, and no path the paragraphs above do not name, so a defect that kept state in a module global on one of those paths would not be caught by this test. Every process shares one host, with no load balancer between them and the test. No multi-replica deployment has been operated. No recovery time has been measured for a tested high-availability arrangement either.

The arrangement:

| Piece | How many | Notes |
| --- | --- | --- |
| Gateway | Several | Stateless. Every replica reads the **same** private configuration file; two files that disagree would disagree about what is governed, and each would answer correctly for the map it holds. |
| Jobs service | Any number of replicas | Each job's interval is taken by one replica and held for that interval; see [Operations](OPERATIONS.md#the-jobs-service). |
| PostgreSQL | One | Every fence, budget, claim and approval lives here. |
| Load balancer | One | Terminates TLS and passes `Host` through unchanged; the configuration's `origin` is the public HTTPS origin, and the gateway refuses a request whose `Host` is not its netloc. |
| Providers | As the process table above | A provider on another host serves HTTPS with a certificate the gateway verifies. |

Three things to get right:

- **Migrations run once, before the new gateways start.** A gateway older than the schema fails readiness rather than serving; roll the schema first, then the replicas.
- **The request limits key their window by the direct peer address.** Behind a proxy every request shares that key on each replica, and the windows are per replica rather than per deployment, so set `limits.client_requests` for the proxy's aggregate and rely on the per-credential and per-sign-in windows for individual callers.
- **The jobs service wants a direct connection, not a transaction-mode pooler.** Its advisory locks are session-scoped; a pooler that hands the session to somebody else between statements loses them.

**Managed PostgreSQL** works and is the usual choice: Amazon RDS, Azure Database for PostgreSQL Flexible Server, Cloud SQL, or Supabase. Remote URLs must carry `sslmode=verify-full` with a mounted CA path, which the gateway enforces rather than recommends.

## TLS termination and origin

The gateway serves cleartext on its container port. Terminate TLS at a reverse proxy or load balancer in front of it and pass the `Host` header through unchanged. The configuration's `origin` must be exactly the public HTTPS origin: the human surface compares the `Host` and `Origin` headers against it, sets `__Host-` prefixed secure cookies and HSTS only when the origin is HTTPS, and MCP clients are told that origin for approvals.

The request limits key the per-client window by the direct peer address and trust no forwarding headers. Behind a proxy every request shares that key, so set `limits.client_requests` in the gateway configuration for the proxy's aggregate rate rather than for one caller, and rely on the per-credential and per-sign-in windows for individual callers; see [Operations](OPERATIONS.md#health-and-capacity).

## Health probes

| Probe | Route | Meaning |
| --- | --- | --- |
| Liveness | `GET /health/live` | The process answers; no dependency is checked. |
| Readiness | `GET /health/ready` | PostgreSQL is reachable at the expected schema revision with a correctly restricted runtime role. Returns 503 otherwise. The body also carries `plugins` and `plugin_api` when a plugin is loaded, and `console`, the console edition the packaged build names (`core` or `hosted`), in a process that serves the console. |
| Arcade readiness | `GET /health` on the hook process | The same answer as `GET /health/ready`, under the path the hook contract declares: 200 with the database up, 503 with it down, unauthenticated and naming no tenant. |
| Container `HEALTHCHECK` | TCP connect to port 8000 | Generic for gateway and providers; use the routes above for the gateway. |

Providers expose no health route beyond the TCP check; the gateway reports provider failures per execution as retained uncertainty, not as readiness.

## Secrets

- `DATABASE_URL` and `MIGRATION_DATABASE_URL` carry passwords. Supply them through the orchestrator's secret mechanism or a mounted file the process reads at start, never through image layers, build arguments or shell history. Remote URLs must use `sslmode=verify-full` with a mounted CA path.
- The gateway JSON and the provider accounts files contain dispatch and control tokens and evidence keys. Mount them read-only from a secret store, owned by root and readable by uid 10001 only.
- Issued agent and human tokens are written once by `credential-issue` to a file you choose; hand that file to the agent or approver through your own channel and delete it.
- Nothing in this repository rotates keys automatically; [Rotate signing and evidence keys](OPERATIONS.md#rotate-signing-and-evidence-keys) is the manual procedure.

## Release record, provenance and rollback

The `provenance` stage of `scripts/ci.py` writes three files into `local-data/release/` on every CI run, from the image the `image` stage built just before it. The release workflow publishes the same three with each release, beside the image ([Releases](RELEASE.md)):

- `sbom.cdx.json` — a CycloneDX 1.6 SBOM of the **application virtual environment** the image runs from, generated with `cyclonedx-bom==7.1.0` against a `uv sync --locked --no-dev --group showcase --no-editable` environment built beside the image, with the flags the `Dockerfile` installs it with. This is the set the application imports; it is deliberately **not** every Python distribution present in the image. The Rust crates compiled into `cedarpy` are listed inside its component, from the CycloneDX SBOM its wheel bundles, read by that environment's own interpreter (`scripts/release_provenance.py --nest-crates`); each keeps its licence, package URL and hash, and its reference becomes its own reference inside cedarpy's, so no two components share one. The base layer also carries pip and its vendored packages under `/usr/local/lib/python3.13`, which the application never executes and which this SBOM does not list. The scheduled image scan covers the whole filesystem and is the place those appear.
- `provenance.json` — the source repository, revision and ref; the workflow, run and kind of runner; SHA-256 digests of `uv.lock`, `pyproject.toml`, the `Dockerfile` and the console's lockfile and manifest; the digest-pinned base images read out of the `Dockerfile`; the built image's id and the SBOM's digest; and a licence disposition derived from the SBOM. For a release, the workflow then adds the registry digest it pushed and the identity that signed it.
- `image-distributions.json` — the distributions the built image actually carries, read out of the image itself.

The job **compares the last two and fails on any difference**, so an SBOM that does not describe what shipped cannot be retained as if it did; `provenance.json` records the comparison as `sbom_matches_image` with the drift in both directions. A comparison that could not be made is recorded as unknown, never as a match. The comparison is of Python distributions alone: the crates inside `cedarpy` are compiled into it, not installed beside it, so they are neither counted against the image nor able to hide a difference in it.

The licence disposition names every component whose licence is **undeclared** or **copyleft**, so neither can enter a release unnoticed. It reads the crates inside `cedarpy` too, and names one that needs a decision with `within`, the component it is compiled into. None does today: every crate cedarpy bundles is permissive, as `DEPENDENCIES.md` records. Current dispositions:

| Component | Licence | Disposition |
| --- | --- | --- |
| `execbound` | AGPL-3.0-only | **Ours.** The server, whose source is this repository. Distributing the image, or offering a modified copy as a network service, carries the AGPL's obligations. |
| `psycopg`, `psycopg-binary` | LGPL-3.0-only | Used unmodified, through its public API. `THIRD_PARTY_NOTICES.md` says where their source is and that the image can be rebuilt with a relinked copy. |
| `certifi` | MPL-2.0 | File-level copyleft on unmodified files only; no obligation while the files are unmodified. |
| `cedarpy` | Undeclared in metadata | Apache-2.0 in the `LICENSE` file the wheel ships; the package declares `License-File` without an SPDX identifier, so tooling cannot read it. |

The client, the provider protocol and the connectors are ours too, under Apache-2.0, and their metadata declares it, so the disposition does not list them.

### What a release and a rollback would have to record

A CI build is never pushed; a release is, and its record is the release record [Releases](RELEASE.md) describes: the tag, the commit and the CI run it passed, the digest, the signing identity and the approval it was published on. A deployment of it is a separate record, the operator's. Nothing links a deployment record to a CI artifact yet, so `provenance.json` records the deploy approval, the environment record and the rollback reference as explicit gaps rather than omitting them. When a deployment exists, the chain it must record is: the change record and its pull request and reviewer; the CI run whose checks passed; the artifact digest and its SBOM; the approver, scope and approval time; the environment, operator, time and result; and the rollback version, trigger, authorization and verification. An approved rollback restores a prior image but cannot undo consequential actions already dispatched — reconciling those is a separate governed step, not part of the rollback.

### Signing

A CI build is **not** signed: it is identified by the local image id its build produced, and it has no registry digest because it is never pushed. Its `provenance.json` says so under `signing`.

A release is signed. The release workflow pushes the image, then signs the digest the registry holds with cosign keyless (Sigstore, under the workflow's own GitHub identity). It verifies that signature before it publishes anything else, and writes the digest and the identity into the release's `provenance.json`. [Releases](RELEASE.md#verify-an-image-before-you-run-it) gives the command that checks it. **No release has been published yet**, so no signed image exists yet either.

### What the repository enforces

In the development repository ExecBound is built in, `main` is protected: a pull request cannot merge until its required checks pass, the rule applies to administrators too, a direct push is refused, and so are force-pushes and deletions. This repository's `main` changes only through export pull requests that a maintainer reviews. The provenance document records which checks ran on the build it describes.

## Validated deployments

| Date | Where | What was validated | Record |
| --- | --- | --- | --- |
| September 16 to 18, 2026 | A managed platform: the gateway and the two mock providers as web services, the mocks with persistent disks, three scheduled jobs, and managed PostgreSQL reached through its session pooler | Readiness through the pooler with the pinned CA bundle; both mocks refusing unauthenticated calls and accepting their dispatch tokens with resources provisioned at start; every scheduled job completing; the six runbook scenarios in OBSERVE mode (29 decisions) and in ENFORCE mode with real mock mutations, two approvals from the console consumed within their deadlines, and the provider refusing a second action on a mutated target until the inventory carried the new version | Kept with the hosted service |

A deployment with synthetic data against mock providers is not a production deployment: no real vendor and no real tenant data. The threat model's R11 records what remains.

## Not covered

- A host that cannot mount secret files can hand the private configuration, a mock's accounts and resources files, the ADMIN token and the database CA bundle over as environment variables and start every process with `python -m execbound.boot <command>`: the module writes them to owner-only files under `/tmp/execbound` (or `EXECBOUND_BOOT_DIR`), provisions the mock store, scrubs the values from the environment and execs the command without a shell, expanding `$NAME` arguments itself. It refuses malformed material before starting anything. A plugin that needs files of its own at start adds them through the module's `files` hook, written after core's, and the hosted service's plugin starts its processes that way.
- A plugin's own settings live in that same private configuration file, under the plugin's name in its `plugins` map, and the plugin validates them with its own strict model when it loads; the same keys at the top level are refused as unknown, because core's own schema does not declare them. [Surfaces](SURFACES.md#without-a-plugin) says what a deployment serves without a plugin.
- The one-host Compose file `execbound init` writes is one expression of the process table; Kubernetes manifests and a Helm chart are not provided and are Enterprise, and the process table above is the contract they must express.
- Scheduling `recover`, `notify` and `monitor-process`, and `invitations-run` where a mail relay is configured, is the jobs service's job in a Compose install. Anywhere else it is an operator's cron entry, systemd timer or container job with the same image and private configuration: `recover --all-tenants` and `notify --all-tenants` need no credential file, and `monitor-process` still needs an ADMIN credential in its configuration file; see [Operations](OPERATIONS.md#the-jobs-service) and [Recover an uncertain execution](OPERATIONS.md#recover-an-uncertain-execution).
- Backups, retention and the restore verifier are described in [Retention, backup and recovery](RECOVERY.md); scheduling them is the operator's job. Key rotation is a reload of the private configuration: with `key_reload_seconds` set, the gateway rereads the file on that interval and rotates its key rings to what the file now names. Audit events and failure summaries are exported to the configured destinations with `export-events`, `export-status` and `export-resume` ([API reference](API_REFERENCE.md)).
- The providers are controlled mocks. A real vendor integration needs evidence of its own.
- The only validated deployment is the one above, with synthetic data and mock providers; building and running this image locally does not add to that.
