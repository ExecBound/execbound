# Community installation: three commands, timed

A run of [the runbook](../INSTALL.md)'s three commands on 20 September 2026, from an empty
directory to a governed decision, with the wall clock measured. The earlier
[installation trial](2026-09-19-community-install.md) and
[first-action trial](2026-09-19-community-first-action.md) cover the same ground in fourteen
steps; this is what replaced them, and it is the run
the runbook's target of under ten minutes is claimed against.

## What was run

An empty directory, a locally built image, and no database volume:

```sh
docker run --rm -u "$(id -u):$(id -g)" -v "$install:/install" execbound:quickstart-claude \
  execbound init /install --image execbound:quickstart-claude --port 8601 \
  --project execbound-quickstart-claude
cd "$install" && docker compose up -d
docker compose run --rm gateway execbound quickstart
```

The image tag, the port and the project name were chosen to stay clear of other services on
this workstation; the runbook's defaults are `execbound:community`, 8080 and `execbound`.

## What it established

**Twelve seconds**, measured from the start of the first command to the end of the third,
with the two images already present on the host. That number is this machine with a warm
Docker cache and is not the claim: the `fresh-machine` job measures a runner that has just
pulled PostgreSQL and built nothing else, which is the case a stranger is in. *Note,
2 October 2026: on a clean GitHub-hosted runner the job has measured 24 seconds; a runner
whose Docker already holds the PostgreSQL image skips that pull and measures less
([the runbook](../INSTALL.md#three-commands)).*

`execbound init` wrote the compose file, `initdb/`, `starter-rules.json`, a `.env` with two
generated passwords and the installer's own uid and gid, and `private/` with the gateway
configuration and both accounts files at 0600. Telemetry was asked for and left off: the run
had no terminal, and the answer to a question nobody heard is no.

`docker compose up -d` started five containers. The jobs service came up before there was
anything for it to run as and said so once a second, in the words the design chose:
`{"command":"recover","event":"job.waiting","reason":"CREDENTIAL_UNAVAILABLE"}`.

`execbound quickstart` printed nine steps and two decisions:

```
  ws01.example     EXECUTED  INC-1001  execution 04bbf2ef-47d9-4629-971d-f0edf399df13
  ws02.example     DENIED    INC-1002  execution 9adc6b87-a625-4053-b0f3-23da1b4afe4f
```

Afterwards, on the same installation:

- `GET /health/live` answered `{"status":"ok"}`, `/health/ready` answered 200, and `/login`
  served the console.
- `audit-export` as the runbook gives it exported **27 events** from genesis: three
  principals, three credentials, two accounts, two context sources, one mapping, two
  resources, the import, the bundle's four lifecycle events, and six execution transitions
  over two evaluations.
- The jobs service ran **each of its three jobs once**, each exiting 0. A second replica,
  started inside the intervals the first had taken, found every one of them held:
  `{"command":"recover","event":"job.held_elsewhere","tick":1988847}`. No `(job, tick)` pair
  ran twice, which is the check the `fresh-machine` job performs, run here against the real
  log.
- The backup section worked as written: `pg_dump`, `createdb`, `pg_restore`, and the
  verifier reporting `events=27 chain=ok checkpoint=NO_CHECKPOINT live=MATCHES_LIVE
  unresolved=0`.
- A second `execbound quickstart` refused and changed nothing: *This database already holds
  the tenant this installation names (ExecBound, 3 principals).*

## What running it found that reading it would not

**The database container was simply unhealthy.** `execbound init` created every directory it
writes at 0700, including `initdb/`, which PostgreSQL's own entrypoint reads as the database
image's user. It cannot open a directory nobody but the installer may read, and the only
symptom is `ls: cannot open directory '/docker-entrypoint-initdb.d/': Permission denied` in a
container log nobody reads, five layers under `dependency failed to start`. The two
directories that hold credentials stay 0700; `initdb/` is 0755, and
`tests/test_quickstart.py` now asserts the mode of each.

**The console was unreachable on a port that was published.** The gateway was started with
`--host 127.0.0.1`, copied from the mock providers, which is right for them and wrong for it:
a published port forwards to the namespace's own address and not to its loopback, so
`docker compose ps` showed `127.0.0.1:8601->8000/tcp` and the browser got a connection reset.
The gateway binds `0.0.0.0` and the mocks stay on loopback, where their cleartext origins are
only accepted because they are loopback. `tests/test_community_bundle.py` reads both.

**The command needed the CLI's name.** `docker run <image> init /install` looks for an
executable called `init`, because the image has no entrypoint and deliberately keeps none —
the same image runs `alembic`, `uvicorn` and `python -m`. The command is
`docker run <image> execbound init /install`, which is the runbook's, this record's and the
fresh-machine job's.

**The paths quickstart printed were the container's.** An installer told to sign in with
`/srv/state/admin.token`, with no container open, cannot find the file. It now names
`state/admin.token` in the directory they installed into.

## What this does not establish

- **The machine is not fresh.** Docker was this workstation's, both base images were cached,
  and the host is one this project is developed on. The cold case belongs to the
  `fresh-machine` job.
- **The image was built locally and is unsigned.** Nothing is pushed to a registry until a
  release is published ([Releases](../RELEASE.md)), so no run has yet used a published or
  signed artifact.
- **Both providers are mocks.** No real vendor, no real tenant data, and the identity path
  untouched.
- **No approval was exercised.** The starter ruleset's production review rule compiled and
  never fired; every decision here was reached without a person.
- **One gateway.** The replica-safety test covers two runtimes against one database; no
  multi-replica deployment has been run.
