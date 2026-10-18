# Install ExecBound on one host

For somebody with the image and no checkout. You need **Docker with Compose, and nothing else** — no Python, no uv, no Node, no browser. Until a release is published there is no image to pull: build one once from a clone, as [the one substitution](#the-one-substitution) below says.

This runs the two mock providers, which is what the first governed action is demonstrated against. It is not a production deployment: read [Deployment](DEPLOYMENT.md) for the process table, TLS and secret handling before anything real depends on it. No production deployment of the self-hosted edition has been validated yet.

Every command below runs in a container. Nothing writes outside the directory you choose.

## Three commands

```sh
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/execbound:/install" execbound:community execbound init /install
cd execbound && docker compose up -d
docker compose run --rm gateway execbound quickstart
```

The third one ends like this:

```
[9/9] Two requests governed.

The installation has governed its first actions.

  ws01.example     EXECUTED  INC-1001  execution 5f7c…
  ws02.example     DENIED    INC-1002  execution 9a41…
```

**Under ten minutes from nothing, measured rather than claimed.** Every change is installed from nothing with these three commands before it is published. The `fresh-machine` check in [CI](../.github/workflows/ci.yml) runs exactly them from an empty directory, times the wall clock from the first to the end of the third, and fails over ten minutes. The number in the build log is the claim; on a clean GitHub-hosted runner it has measured 24 seconds, and a runner whose Docker already holds `postgres:17.11` skips that pull and measures less.

### What each one does

**`execbound init /install`** writes the whole installation into a directory you own: `compose.yaml`, `initdb/`, `starter-rules.json`, a `.env` with two freshly generated database passwords and the uid and gid it ran as, and `private/` holding the gateway's configuration and both providers' account files with fresh continuation keys, dispatch and control tokens and evidence keys. It refuses a directory that already holds an installation, because overwriting would replace tokens the providers and the database already agree on and the failure would appear later as a provider refusing a dispatch. It prints the path and never the contents.

It also asks one question — whether this deployment should send ExecBound a weekly usage report — and takes **no** for an answer, including the answer a `docker run` with no terminal gives. `--telemetry` or `--no-telemetry` answers it without being asked. Nothing sends anything today: the setting is recorded in `private/gateway.json` and nothing reads it yet.

**`-u "$(id -u):$(id -g)"` is not optional.** The container writes into a directory on your host. Without it the process runs as the image's own user, which cannot write into a directory you own — and a directory Docker creates for a missing mount is owned by root, which it cannot write into either. Running as you is also what lets you read the credential files the third command writes, and it is where the `EXECBOUND_UID` and `EXECBOUND_GID` in the `.env` come from.

**`docker compose up -d`** starts five processes: PostgreSQL, the gateway, the endpoint mock, the identity mock and the jobs service. A sixth container, `netns`, runs nothing: it holds the network namespace the five share, which is what makes the database and both mocks genuinely `127.0.0.1` to the gateway, and it publishes the gateway's port. The database creates two roles on its first start: the schema owner (`execbound_owner`, which migrations and administration use) and the restricted runtime role (`execbound_app`, which the gateway uses and which cannot bypass row-level security — readiness refuses a role that can). The jobs service waits, saying so, until the third command has run.

**`execbound quickstart`** applies the schema, then builds the deployment the private configuration already describes: the tenant, its first administrator and a separate administrator for the scheduled jobs, both mock providers as connector accounts, the mapping from `endpoint.isolate` to the endpoint account's `contain` operation, an inventory source and an incident source, two endpoints that differ in one fact, an open critical incident for each, both targets provisioned in the provider's own store, the starter rules compiled and activated, an agent with its own credential, and then two requests.

It refuses to run twice against the same database and says what it found rather than changing it.

### The one substitution

`execbound:community` is an image you built or loaded locally. No release has been published yet, so there is no `docker pull` to give you. Once one is, `EXECBOUND_IMAGE` in the `.env` becomes the release's reference, by digest once you have verified its signature ([Releases](RELEASE.md#verify-an-image-before-you-run-it)), and nothing else in the installation changes. To build it from a checkout: `docker build --tag execbound:community .`

## Sign in

```sh
curl -fsS http://127.0.0.1:8080/health/live
curl -fsS http://127.0.0.1:8080/health/ready
```

`live` answers as soon as the process is up. `ready` checks the schema revision and that the runtime role really is restricted; it does **not** check provider health, an active bundle or inventory freshness, so a ready gateway can still refuse a particular action for good reasons.

For initial installation setup, open `http://127.0.0.1:8080/login?setup=1` and use the contents of `state/admin.token`. **Activity** shows the two decisions, the agent's page shows its budget meters moving, and **Policies** lists the active policy: open it and choose its rules to read the starter rules back as sentences and edit them there.

All three credentials — the administrator's, the agent's, and the jobs service's in `state/jobs.json` and `state/monitor.json` — expire after ninety days. The jobs credential's expiry matters only to `monitor-process`: `recover` and `notify` hold no credential, and the jobs service runs them only once `state/jobs.json`, quickstart's mark, exists. Issue another with `credential-issue --lifetime-hours 2160`, as the long way below does (without `--lifetime-hours` a credential lasts eight hours, and ninety days is the most any can); the agent's can also be issued from the console's **API keys** page ([Get an API key](https://docs.execbound.ai/api/agent#description/authentication)).

## Why the second request was refused

`ws02.example` satisfies every condition of the allow rule: it is a workstation, its incident is open, its severity is critical. It is refused anyway, because it is criticality 4 and **a denial wins over a permit**. A target that simply matched no allow rule would also be refused — that is the default — so a refusal like that would have demonstrated nothing about precedence. This one can only be explained by the deny rule.

A refusal by a deny rule and a refusal by the default report the same reason, `NOT_AUTHORIZED`. Cedar's denial is a denial, and the event does not name the rule that produced it. What tells you which rule applied is the frozen plan the chain carries beside the decision, read against the rules on the policy page.

The starter rules are four rules and two budgets over `endpoint.isolate`:

| | |
| --- | --- |
| Allow | when `role` is workstation, `incident_status` is OPEN and `incident_severity` is CRITICAL |
| Deny | when `role` is domain_controller |
| Deny | when `criticality` is 4 |
| Review | when `is_production` is true |

They are demonstration rules over mock providers. Replace them: the [action catalog](ACTION_CATALOG.md#soc-policy-pack) describes a fuller pack, and [Policy](POLICY.md) states what rules can and cannot express. `starter-rules.json` beside your `compose.yaml` is the copy to edit; [the long way](#the-long-way-one-command-at-a-time) shows how to compile and activate an edited one.

Both decisions, and everything that led to them, are in the audit chain:

```sh
docker compose run --rm -v "$PWD:/work" -w /work gateway execbound audit-export \
  --tenant <tenant> --credential-file /srv/state/admin.token --output /work/audit.json
```

The export holds every event of the tenant from genesis: the principals and credentials, the two sources, the mapping, the resources, the import with its manifest digest, the bundle created, compiled, validated and activated, and for each request the frozen plan, the decision and its reasons. The allowed one also carries `execution.dispatch_attempt` with `precondition_class: ENFORCED_BY_PROVIDER`, which is the mock stating that it checked the frozen version in the same write that isolated the machine.

## The jobs service

The `jobs` container runs the scheduled work that a deployment needs and that nothing else does: `recover` every fifteen minutes, `monitor-process` every five and `audit-verify` every hour, which reads every workspace's audit chain again and logs `audit.chain_failed` if one does not verify; where the runtime configuration names an approval notification destination, `notify` every fifteen seconds, which delivers approval notifications; and, where it has a `mail` block, `invitations-run` every two minutes, which retries teammate invitations the console's first send could not deliver. Without a mail relay the console does not offer to invite by email; use **Add user** on the Users page instead. The service decides whether to run `notify` and `invitations-run` when it starts, so after adding the first notification destination or the `mail` block, restart the jobs service as well as the gateway (`docker compose restart gateway jobs`). Jobs run side by side, so a long recovery pass never holds a notification back.

```sh
docker compose logs jobs
```

Each run takes a PostgreSQL advisory lock named for the job and the interval it belongs to, and holds it for the rest of that interval, so a second replica of this service never runs the same interval twice:

```sh
docker compose up -d --scale jobs=2
```

The lock reaches two jobs services. It does not reach a job you run by hand, which takes no lock.

A lock lives in the database session that took it, so a database restart ends every lock at once. The service carries on: at the end of an interval whose session the restart ended it logs `dependency.unavailable` with the job and the code `SESSION_LOST`, and for an interval that begins while the database is not answering, the same event with `DATABASE_UNAVAILABLE`, and it asks again a second later. It does not run an interval it already ran, but a second replica may, because the lock that kept it out went with the restart.

### Connect Tines from the console

To let an administrator connect Tines from the console, give the installation a monitoring collector key pair. `execbound init` made an empty `collector/` directory, which only the `jobs` container mounts, read-only; the gateway never sees it, because the private key in it opens every Tines key the console seals. Write the pair there, then put the public half in the gateway's private configuration and restart:

```sh
docker compose run --rm -v "$PWD/collector:/srv/collector" gateway \
  python -m execbound.monitoring.commands collector-keygen --output /srv/collector/keys
mv collector/keys/collector-private.json collector/ && cat collector/keys/collector-public.json
```

Add what that prints to `private/gateway.json` as `"scout": {"collector": {...}}`, keep `collector/keys/collector-public.json` for a later re-seal, and run `docker compose restart gateway jobs`. **Monitoring → Connect Tines** is then offered, and the jobs service collects each sealed connection on its schedule with `collect-due --collector-key`.

**An installation made before this release** has no `collector/` directory, and its `compose.yaml` mounts none, because an upgrade keeps the `compose.yaml` `init` wrote. Before the steps above, create the directory yourself, so that Docker does not create it owned by root the first time it is mounted, name it in `.env`, and add the mount to the `jobs` service alone:

```sh
mkdir -m 700 collector
printf '\nEXECBOUND_COLLECTOR=./collector\n' >> .env
```

Under `jobs:` → `volumes:` in `compose.yaml`, after the state directory's line, add:

```yaml
      - ${EXECBOUND_COLLECTOR:-./collector}:/srv/collector:ro
```

Then run `docker compose up -d`. Never add the mount to the gateway.

**To move to a new key pair**, follow the order in [Tines monitoring](TINES_MONITORING.md#connect-tines-from-the-console). Here, the key being retired goes to `collector/collector-previous.json`, which the jobs service gives `collect-due` beside the new key, so a connection sealed to either is collected throughout:

```sh
mv collector/collector-private.json collector/collector-previous.json
docker compose run --rm -v "$PWD/collector:/srv/collector" gateway \
  python -m execbound.monitoring.commands collector-keygen --output /srv/collector/next
mv collector/next/collector-private.json collector/ && cat collector/next/collector-public.json
```

Replace `scout.collector` in `private/gateway.json` with what that prints, and run `docker compose restart gateway`. Then re-seal, and repeat until it reports no `resealed` and no `failed` connection:

```sh
docker compose run --rm jobs python -m execbound.monitoring.commands collector-reseal \
  --old-key /srv/collector/collector-previous.json \
  --new-key /srv/collector/next/collector-public.json --all-tenants
```

Only then remove `collector/collector-previous.json`.

### Connect Microsoft Entra from the console

To let an administrator connect a Microsoft Entra directory by its administrator's consent, register an app of your own as [Deployment](DEPLOYMENT.md#processes-and-their-inputs) describes (the platform app), with the redirect URIs `<your origin>/connect/entra/signed-in` and `<your origin>/connect/entra/consented` and a certificate credential. Connect Tines from the console first: Microsoft Entra is accepted only beside `scout.collector`. Write the certificate, its private key and the app's client id to `collector/scout-app.json` as `{"client_id", "certificate_pem", "private_key_pem"}`, owner-only, add `"entra": {"client_id": "...", "authority": "organizations", "display_name": "..."}` beside `collector` under `scout` in `private/gateway.json`, and run `docker compose restart gateway jobs`. **Monitoring → Connect Microsoft Entra** is then offered, and the jobs service gives `collect-due` the file as `--platform-app`. The certificate reads every directory that consented to your app; it lives in the `collector/` directory the gateway never mounts, and is rotated every 90 days ([Scout](SCOUT.md#connect-microsoft-entra-from-the-console)).

## Support and versions

Community is complete for one organisation and is supported by the community, with no guarantee:

- Questions and bugs: GitHub Discussions and issues.
- Vulnerability reports: `SECURITY.md`. Do not open an issue for one.
- Security fixes go into the **latest release**. There is no long-term support branch; a supported one is part of the Enterprise kit.
- Upgrades are supported **from the previous minor version**. Going further means stepping through each minor version's migrations in order.
- Running more than one gateway is possible and documented in [Deployment](DEPLOYMENT.md#run-more-than-one-gateway). The supported tooling for it — a Helm chart, reference architectures, an air-gapped bundle — is Enterprise.

## The long way, one command at a time

Quickstart is a demonstration tenant with mock providers. A deployment that is going to hold your own tenant, your own targets and your own rules does the same work by hand, and these are the commands. They run against an installation `execbound init` wrote, in the directory it wrote it into, with the database started and nothing else done:

```sh
docker compose up -d db
docker compose run --rm gateway alembic upgrade head
run() { docker compose run --rm gateway execbound "$@"; }
```

Migrations run as the owner, never as the runtime role, and the compose file gives this container that connection. Apply them before starting a gateway of that build: a gateway older than the schema fails readiness rather than serving. The long-running gateway does **not** hold the owner connection — it starts through `execbound.boot`, which removes that variable from the environment before the server process is exec'd.

### 1. A tenant, an administrator and two accounts

The tenant and both connector accounts already have identifiers: `execbound init` generated them and the private configuration names them, so the rows have to carry exactly those. Read them out of `private/gateway.json` (`connectors[].tenant_id` and `connectors[].account_id`; the file holds tokens, so read the two fields rather than printing it).

```sh
run tenant-create --name "Acme" --tenant <tenant>
run principal-create --tenant <tenant> --kind ADMIN
run account-create --tenant <tenant> --provider mock_crowdstrike --actor <admin> --account <endpoint account>
run account-create --tenant <tenant> --provider mock_entra --actor <admin> --account <identity account>
```

The first ADMIN needs no `--actor`; every later principal does, because a principal is created *by* somebody and the audit chain records who.

Then issue that administrator a credential. It is written to a file and never printed:

```sh
run credential-issue --tenant <tenant> --principal <admin> --actor <admin> --lifetime-hours 2160 --output /srv/state/admin.token
```

`state/` is mounted into this container, so the file appears beside your `compose.yaml` and you own it.

### 2. Register what the agent may act on

A request resolves against the registry, so the registry has to hold the target before an agent can name it. Facts are attested by a source, never by the caller, so the sources come first.

```sh
run context-source-create --tenant <tenant> --account <endpoint account> \
  --kind inventory --writer inventory_sync --actor <admin>
run context-source-create --tenant <tenant> --account <endpoint account> \
  --kind incident --writer soc_analyst --actor <admin>
run mapping-create --tenant <tenant> --account <endpoint account> \
  --action endpoint.isolate --actor <admin>
```

The mapping is what binds the catalog's `endpoint.isolate` to this account's `contain` operation. The provider operation, schema version and context contract come from the catalog and never from you, so a mapping can only name something the catalog already binds.

Then your endpoints:

```sh
run resource-create --tenant <tenant> --account <endpoint account> --resource-type endpoint \
  --provider-id device-ws-01 --source <inventory source> --hostname ws01.example \
  --role workstation --environment development --criticality 2 --actor <admin>
```

Each prints a `canonical_target_id`. Keep them.

Isolation's contract requires an incident, so each endpoint needs one. Facts and incidents arrive as a manifest, which a source attests and the importer applies in one audited transaction. Write the manifest into the installation directory and mount it:

```sh
docker compose run --rm gateway python -c "import uuid; print(uuid.uuid4())"

cat > incidents.json <<EOF
{
  "manifest": "execbound.context-manifest.v1",
  "tenant_id": "<tenant>",
  "account_id": "<endpoint account>",
  "source_id": "<incident source>",
  "kind": "incident",
  "writer": "soc_analyst",
  "entries": [
    {"provider": "mock_crowdstrike", "resource_type": "endpoint", "provider_id": "device-ws-01",
     "incident_id": "<uuid>", "version": "ticket-1001",
     "observed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
     "facts": {"incident_status": "OPEN", "incident_severity": "CRITICAL"}}
  ]
}
EOF

docker compose run --rm -v "$PWD:/work" -w /work gateway execbound context-import \
  --tenant <tenant> --manifest /work/incidents.json --actor <admin> --strict
```

`--strict` refuses the whole manifest if it names a resource the registry does not hold, which is what you want here: the importer never creates resources, so a typo would otherwise be reported and skipped rather than stopping you.

Last, the provider has to hold the same targets the registry does. The mocks keep their own store — that is the point of a provider, and a dispatch whose target the provider has never heard of has nothing to act on. Put the canonical target ids in `EXECBOUND_ENDPOINT_RESOURCES` in `.env` as one JSON list, with no spaces inside the JSON, and recreate the provider:

```ini
EXECBOUND_ENDPOINT_RESOURCES=[{"tenant_id":"<tenant>","account_id":"<endpoint account>","provider_id":"device-ws-01","canonical_target_id":"<target>","version":"resource-v1"}]
```

```sh
docker compose up -d endpoint
```

`version` must be the resource's registry version, `resource-v1` unless you passed `--version`. It is the precondition the provider checks atomically at dispatch: a value the registry does not agree with makes every dispatch for that target fail closed as `STALE_AUTHORIZATION`, which is the safe direction and an annoying one to debug.

Provisioning at start **creates and never overwrites**, so restarting a provider later leaves everything the mock has since done to a target alone. Adding a target to the list and restarting provisions only the new one.

> **A variable you exported wins over `.env`, silently.** Compose reads the environment of the process before it reads the file, so if you ran something like `set -a; . ./.env` you will find `docker compose up -d endpoint` printing `Running` instead of recreating anything. `unset EXECBOUND_ENDPOINT_RESOURCES` before bringing the provider up, and use `docker compose config` to see what Compose actually resolved.

### 3. Write the policy

Nothing is permitted until a bundle is active: the default is refusal, and an installation with no bundle refuses every request. The bundle the kernel reads is compiled Cedar, which you should not have to write. Write rules instead and let the image compile them. `starter-rules.json` beside `compose.yaml` is a first draft to edit.

```sh
docker compose run --rm -v "$PWD:/work" -w /work gateway execbound ruleset-compile \
  --tenant <tenant> --input /work/starter-rules.json --output /work/bundle.json
```

That reads the tenant's own active mappings, compiles the rules against the contracts those mappings name, and writes a complete bundle document. It writes a file and changes nothing else: no bundle row, no activation. It refuses to overwrite, because the document you activated is the record of what you activated. It prints the `bundle_id` the next two commands need.

Then the ordinary lifecycle, as an administrator over the runtime connection:

```sh
bundle() { docker compose run --rm -v "$PWD:/work" -w /work gateway execbound "$@" \
  --tenant <tenant> --credential-file /srv/state/admin.token; }

bundle bundle-create --input /work/bundle.json     # DRAFT
bundle bundle-validate --bundle <bundle>           # VALIDATED
bundle bundle-activate --bundle <bundle>           # ACTIVE
```

Validation recompiles the rules the document carries and refuses content that disagrees with them, so a hand-edited bundle is refused whichever way it was written. That check is why the compiler is allowed to sit outside the enforcement boundary at all.

### 4. Govern one action

An agent is a principal with its own credential, never yours:

```sh
run principal-create --tenant <tenant> --kind AGENT --actor <admin>
run credential-issue --tenant <tenant> --principal <agent> --actor <admin> --lifetime-hours 2160 --output /srv/state/agent.token
```

Now act as that agent:

```sh
TOKEN=$(cat state/agent.token)

curl -sS -X POST http://127.0.0.1:8080/v1/execute \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"operation_ref":"endpoint.isolate","target":{"kind":"hostname","value":"ws01.example"},
       "arguments":{},"reference":"INC-1001","claimed_context":{"incident_id":"<uuid>"}}'
```

```json
{"execution_id":"...","state":"EXECUTED","plan_hash":"...","approval_id":null,"approval_state":null}
```

A target that a deny rule covers answers the same shape with `"state":"DENIED"` and leaves the provider's row untouched.

### 5. Let the jobs service run

The [jobs service](#the-jobs-service) waits until `state/jobs.json` exists, and `monitor-process` signs in with the administrator credential in `state/monitor.json`. Quickstart writes both; by hand, give the jobs an administrator of their own, so the credential that runs unattended is not the one a person signs in with:

```sh
run principal-create --tenant <tenant> --kind ADMIN --actor <admin>
run credential-issue --tenant <tenant> --principal <jobs admin> --actor <admin> --lifetime-hours 2160 --output /srv/state/jobs.token
(
  umask 077
  token=$(cat state/jobs.token)
  printf '{"%s": "%s"}\n' "<tenant>" "$token" > state/jobs.json
  printf '{"admin_token": "%s"}\n' "$token" > state/monitor.json
)
rm state/jobs.token
docker compose up -d
```

Both files are readable by you alone, and the token is in them and nowhere else. Then `docker compose logs jobs` shows each job completing on its interval.

## Upgrade to a newer image

Load or pull the new image, point `EXECBOUND_IMAGE` in `.env` at it, apply its migrations with the owner connection, then replace the processes:

```sh
docker compose run --rm gateway alembic upgrade head
docker compose up -d
```

Migrations first, always. A gateway older than the schema fails readiness rather than serving, which is the safe direction; a gateway newer than the schema is the one that would misread rows, and applying first is what prevents it. Downgrades that would drop history are refused by design. Upgrades are supported from the previous minor version; going further means stepping through each minor version's migrations in order.

Keep the `compose.yaml` your `init` wrote; these two commands are the whole upgrade. `scripts/community_upgrade.py` tests exactly that, and the development repository's CI runs it on every change: it installs the revision the change was made on, lets quickstart govern with it, and upgrades that install by these two commands. The test then requires:

- The gateway reports ready.
- The history from before the upgrade is unchanged at the head of the chain after it.
- The agent credential issued before the upgrade governs again, with the same answers the policy and the provider's state call for.
- Every scheduled job completes.
- The backup below verifies both before and after.

Until releases carry versions, the revision a change is based on stands in for the previous one. [The upgrade trial](trials/2026-09-26-community-upgrade.md) records the first run, across six migrations.

## Back up, and prove the backup restores

Two things have to be kept together: the database, and the provider stores. A provider that loses its store loses the journals that settle retained uncertainty, so an uncertain operation would have nothing to be reconciled from.

```sh
POSTGRES_PASSWORD=$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2-)
mkdir -p backups
docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" \
  db pg_dump -Fc -U execbound_owner execbound > backups/execbound.dump
tar -czf backups/providers.tar.gz providers
```

A backup nobody has restored is a hope. Restore it into a second database on the same instance and verify it:

```sh
docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" \
  db createdb -U execbound_owner execbound_restore
docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" \
  db pg_restore -U execbound_owner -d execbound_restore < backups/execbound.dump

mkdir -p reports
docker compose run --rm -v "$PWD/reports:/out" gateway python -m execbound.recovery \
  --restored-database execbound_restore --compare-live --output /out/restore-report.json
```

It prints one line per tenant and writes a JSON report:

```
Restore verification passed: 8af26def events=3 chain=ok checkpoint=NO_CHECKPOINT live=MATCHES_LIVE fence=NOT_CHECKED unresolved=0
```

`chain=ok` means the audit chain verifies from genesis to the stored head in the restored copy. `live=MATCHES_LIVE` means that head is the one the live database holds, so the backup is current rather than merely readable. `fence=NOT_CHECKED` means the copy was read as the owner only; `--check-fence` reads it as the runtime role too and checks there that no workspace sees another workspace's rows and that each still reads its own history. The verifier writes to a new file only and never touches either database. [Retention, backup and recovery](RECOVERY.md) explains what it checks and what it does not.

Drop the copy when you are done:

```sh
docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" \
  db dropdb -U execbound_owner execbound_restore
```

## When the database stops or restarts

Nothing else needs restarting. The namespace every process shares belongs to `netns`, not to the database, so stopping and starting `db`, `docker compose restart db`, or PostgreSQL exiting and Docker restarting it leaves every process where it was. While PostgreSQL is away, readiness answers 503 and the gateway refuses consequential requests without sending anything; once it is healthy, readiness answers 200 again.

Two cases do strand the other processes in a namespace nobody can reach. Docker still reports them healthy, because each health check connects to `127.0.0.1` inside the namespace it was left in, so check readiness through the published port instead: `curl -fsS http://127.0.0.1:8080/health/ready`.

- **`netns` stopped on its own.** `docker compose stop netns` takes the namespace with it. Stop it only with everything else (`docker compose stop`); if it was stopped alone, `docker compose restart` repairs it.
- **A `compose.yaml` with `network_mode: "service:db"`.** In a compose file written before `netns` existed, the database owns the namespace, so every stop, restart or crash of the database strands the rest. Once the database is healthy again, run `docker compose restart gateway endpoint identity jobs`. `docker compose up -d` is not enough: it leaves running containers alone.

## Reinstalling, and running two of them

`docker compose down` keeps the database volume, so a second attempt with a new `.env` authenticates against the roles the first attempt created and fails with `password authentication failed` several steps later. To start genuinely fresh, take the volume with it: `docker compose down -v`, and run `execbound init` into a new directory.

To run a second ExecBound on this host, give it a different `EXECBOUND_PROJECT`: the project names the volume, so two installations sharing a name share a database.

## What this run established

The three commands were run end to end on one machine against a freshly built image and an empty database, and the wall clock from the first command to the end of the third was recorded. The gateway reported ready, the administrator token signed in, and the two requests answered `EXECUTED` and `DENIED`, with the mock's store holding `ws01.example` contained and `ws02.example` untouched. The jobs service ran each of its three jobs once, and a second replica of it ran none of them a second time in the same interval.

The long way and the restore verification were exercised separately against a populated install in the runs recorded in [the installation trial](trials/2026-09-19-community-install.md) and [the first-action trial](trials/2026-09-19-community-first-action.md). That installation trial also ran the upgrade commands, but its database was already at head, so the migrations had nothing to do. An upgrade across a real schema change was first exercised in [the upgrade trial](trials/2026-09-26-community-upgrade.md), and the development repository's CI now upgrades from the revision each change was made on. The defects those trials found are fixed above: the database was addressed by container hostname, which the gateway refuses as remote without TLS; the containers ran as the image's own user, which could not read material the operator owns; the provider stores were a named volume, which Docker creates root-owned so a non-root process could never write to them; and a variable exported into the shell silently overrode `.env`.

The largest gap is the same in all of these: Docker was the host's, and the host is a machine this project is developed on. What a genuinely fresh machine does is the `fresh-machine` stage's answer, and the first record of these three commands is [the quickstart trial](trials/2026-09-20-community-quickstart.md). No run so far has used a published or signed image, a real provider, the identity path, or an approval.
