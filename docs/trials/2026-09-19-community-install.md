# Community installation trial, 19 September 2026

`docs/INSTALL.md` followed from the artifact alone, with no repository present. Records what the run established, what it corrected, and what it does not establish.

> Note, 2 October 2026: since 20 September 2026 [the runbook](../INSTALL.md#three-commands) is three commands instead of the numbered steps below, and `execbound init` writes the installation files and creates the directories that this run was given or created by hand. The [quickstart trial](2026-09-20-community-quickstart.md) records that run.

## What was used

A directory containing only what an installer receives: `execbound-community.tar`, `compose.yaml`, `.env.example`, `initdb/`, `README.md` and `INSTALL.md`. No checkout, no `uv`, no Python on the path, no browser. Docker is the host's.

## Result

Steps 1 to 11 succeeded as written.

| Step | What it produced |
| --- | --- |
| 1 load | `Loaded image: execbound:community` |
| 2 directories | `private` and `providers` owned by the installing user |
| 4 database | `Up 14 seconds (healthy)` |
| 5 schema | `0037_agent_bindings` |
| 6 tenant | tenant, ADMIN, two connector accounts, one credential file |
| 7 configuration | three files at mode 0600 |
| 8 start | all four processes healthy |
| 9 ready | `{"status":"ready","version":"0.1.0","commit":"41cd0b8"}`; sign-in `303`; dashboard `200` |
| 10 upgrade | already at head against a populated database |
| 11 restore | `chain=ok checkpoint=NO_CHECKPOINT live=MATCHES_LIVE unresolved=0` |

## What earlier runs corrected

Four defects were found by following the runbook rather than reading it. Each looked reasonable on the page and each failed several steps after its cause.

**The database was addressed by container hostname.** `connection.py` refuses a PostgreSQL URL whose host is not loopback unless it carries `sslmode=verify-full` and a CA bundle, so `db:5432` was refused at the migration step. Every process now shares one network namespace, so the database and both providers are genuinely at `127.0.0.1` — the condition that rule is about. The same rule had already forced the provider arrangement; it had been applied to one and not the other.

**The containers ran as the image's own user.** The private material is mode 0600 in a directory the operator owns, so the gateway could not read its own configuration and the operator could not read the administrator token written for them. They now run as the installing user; both are unprivileged.

**The provider stores were a named volume.** Docker creates those root-owned and these processes are not root, so the store could never be written. They are a directory the installer owns, which also makes the backup easier to keep beside the database.

**The compose project name was fixed.** A second installation on the same host silently adopted the first one's database volume, which survives `docker compose down`, and failed with `password authentication failed` against passwords that were correct. The project name is now a variable and the runbook says how to start genuinely fresh. This one was found by the clean-room run itself, because it was the second installation on this machine.

A fifth trap is in the runbook rather than the code: Docker creates a missing bind-mount source as root, so both directories must exist before the first `compose` command.

## What this does not establish

**Docker is the host's, and the host is the machine this was developed on.** The artifact and the runbook were isolated; the kernel, the Docker installation and the image cache were not. A different machine, and particularly one where `docker compose` is a different version, remains untried.

**The image was built locally, not pulled.** There is no registry and nothing is signed, which `docs/DEPLOYMENT.md` records. Step 1 loads a tar; it becomes a pull when a registry exists.

**No demonstration was run.** The six scenarios need a seeded sandbox, and both seeding commands live in the development harness, which the wheel deliberately does not package. The runbook's scope was amended accordingly: the sandbox is the hosted service's trial path, and a self-hosted installer governs their own first action instead. That section of the runbook is not written yet. *Note, 2 October 2026: written the same day; the [first-action trial](2026-09-19-community-first-action.md) records its run.*

**The providers were never exercised.** They start, report healthy and are reachable at loopback, but nothing dispatched through them, so this establishes that the installation stands up, not that it governs an action.
