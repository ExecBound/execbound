<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/execbound-mark-dark.svg">
    <img src=".github/assets/execbound-mark-light.svg" alt="" width="96" height="96">
  </picture>
</p>

<h1 align="center">ExecBound</h1>

<p align="center">
  <strong>Security for AI agents that act.</strong><br>
  The agent proposes. ExecBound decides.
</p>

<p align="center">
  <a href="https://docs.execbound.ai">Documentation</a> ·
  <a href="docs/INSTALL.md">Install</a> ·
  <a href="https://trust.execbound.ai">Trust center</a> ·
  <a href="https://github.com/ExecBound/execbound/discussions">Discussions</a> ·
  <a href="SECURITY.md">Security</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0--only-0A7486" alt="License: AGPL-3.0-only"></a>
  <a href="https://github.com/ExecBound/execbound/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ExecBound/execbound/ci.yml?branch=main&amp;label=CI" alt="CI status"></a>
  <a href="https://docs.execbound.ai"><img src="https://img.shields.io/badge/docs-read-0A7486" alt="Documentation"></a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/console-home-dark.png">
    <img src=".github/assets/console-home-light.png" width="900" alt="The ExecBound console's Home page with synthetic data: the week's decisions by outcome, three requests held for a person, and the decisions chart.">
  </picture>
</p>

AI agents now take actions with real consequences: they isolate a workstation, disable an account, revoke a session. A prompt asking an agent to be careful does not narrow what its credential can do. ExecBound sits between the agent and the systems it acts on, and decides outside the model whether each action may run.

The agent asks ExecBound over MCP or HTTP. ExecBound resolves the request to one canonical action and one target against trusted inventory, applies deterministic Cedar policy and shared impact limits, asks a named person when a rule says to, and only then lets the action run. The agent holds an ExecBound credential; the provider credentials and the control stores stay inside the trusted service boundary.

## Highlights

- **Decisions outside the model.** Policy, trusted context and limits decide, not the agent's own account of itself. An unknown action, a mismatched target or missing context fails closed.
- **A person when it matters.** A rule can hold a request for a named approver. Approvals are scoped to the exact request, expire, and are consumed once.
- **Shared impact limits.** Limits count the targets affected across agents, runs and protocols within the scope you configure, and reservations are atomic, so simultaneous requests cannot spend the same remaining capacity.
- **Credentials out of the agent's reach.** On the Execute path ExecBound holds the provider credential and dispatches the action itself.
- **A record you can replay.** Every decision is appended to the workspace's audit chain with its evidence, and an exported history replays offline without acting on anything.

ExecBound has three placements: **Execute** holds the connector and dispatches a governed action; **Gate** issues a plan-bound grant to an external executor; **Monitor** receives activity without granting execution authority. Tines instrumentation and collection, the external checkpoint and Arcade hooks, and Scout's Entra inventory source are implemented to different evidence levels. Read [Integrations](docs/INTEGRATIONS.md) for the tested path and its limits, and [Scout](docs/SCOUT.md) for what directory evidence can establish.

This repository is self-hosted Community: the gateway and its console, the Python client, the examples and the integrations, with the tests that prove them. ExecBound is also offered as a hosted service; [Community and hosting](docs/EDITIONS.md) sets out how the two differ.

## Install it

First get the `execbound:community` image. Either verify the [latest release](https://github.com/ExecBound/execbound/releases)'s signature as [Releases](docs/RELEASE.md#verify-an-image-before-you-run-it) describes, pull it by the digest you verified and tag it: `docker pull ghcr.io/execbound/execbound@sha256:<digest>`, then `docker tag ghcr.io/execbound/execbound@sha256:<digest> execbound:community`. Or build it in a clone of this repository with `docker build --tag execbound:community .`. Then run three commands in an empty directory (outside the clone, if you built the image), on a host with Docker and nothing else:

```sh
mkdir execbound && docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/execbound:/install" execbound:community execbound init /install
cd execbound && docker compose up -d
docker compose run --rm gateway execbound quickstart
```

The first creates `execbound/` there. The third ends with two governed requests, one executed and one refused, and prints where to sign in. [Install on one host](docs/INSTALL.md) explains each command, why the second request is refused, and how to do the same work one command at a time. The installation runs against two mock providers: read [Deployment](docs/DEPLOYMENT.md) before anything real depends on it.

## Run the demo from a clone

The demonstration seeds a synthetic deployment, starts the gateway and both mock providers, drives a browser through governed requests and approvals, and writes a sanitized evidence report. It needs Python 3.13, uv, Docker Compose with a working engine, and the Node and pnpm versions [console/package.json](console/package.json) pins.

```sh
uv sync --locked
uv run playwright install chromium
corepack enable
cd console
pnpm install --frozen-lockfile
pnpm build
cd ..
uv run python scripts/local_setup.py
uv run alembic upgrade head
uv run execbound seed-validation --seed demo-1 --output local-data/demo-1
uv run python scripts/validation_demo.py run --private local-data/demo-1 --output local-data/demo-1-evidence
```

On Linux, install Chromium with `uv run playwright install --with-deps chromium`. `local_setup.py` starts PostgreSQL in Docker Compose on a loopback port and writes the git-ignored `.env` holding its credentials. Use a new seed and new output directories for every run, and run the demonstration straight after seeding: the fixture's trusted context expires after 300 seconds. The evidence directory holds sanitized reports and screenshots; credentials and provider stores stay in the private fixture directory.

To look around yourself, seed a fresh directory and run `serve` in place of `run`, then open `http://127.0.0.1:8100/login` while it runs. The [integration examples](examples/README.md) call that running demonstration over HTTP and MCP.

## What it protects, and what it does not

V1 supports one canonical target per action, fixed provider operations, shared impact across runs and adapters, and fail-closed authorization. There is no generic HTTP passthrough, batch mutation, automatic resend of an uncertain operation, or approval flag supplied by the agent. Gate and Monitor do not stop a caller that uses a separate credential outside ExecBound, and tenant row-level security does not contain an attacker who obtains arbitrary SQL access with the runtime credential.

The [threat model](docs/THREAT_MODEL.md) names who can act on ExecBound and what each trust boundary must hold, lists the security invariants every path keeps, and records for each threat its mitigation, the code that enforces it, the test that exercises it and its status. [Where credentials live](docs/CREDENTIALS.md) says where every credential is kept and who can read it, and [Architecture](docs/ARCHITECTURE.md) describes the components and the trust boundaries between them.

## Documentation

The documents under [docs](docs/) are also published at [docs.execbound.ai](https://docs.execbound.ai). Start with:

| Need | Read |
| --- | --- |
| Use the console: setup, agent connections, reviewers, policies and monitoring | [Use the console](docs/CONSOLE_GUIDE.md) |
| Connect an agent host and handle each answer | [Connect an agent host](docs/AGENT_HOSTS.md) |
| Write a policy | [Write a policy](docs/POLICY_GUIDE.md) |
| Run the image and its processes | [Deployment](docs/DEPLOYMENT.md), then [Deploy it in your cloud](docs/CLOUD_DEPLOYMENT.md) |
| Back up, restore and verify history | [Retention, backup and recovery](docs/RECOVERY.md) |
| Verify a release's image before you run it | [Releases](docs/RELEASE.md) |
| Call the HTTP and MCP interfaces, or use the CLI | [Interfaces in depth](docs/API_REFERENCE.md) |

## Support

Community is supported by the community, with no guarantee. Ask questions in Discussions and report bugs in issues. Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes, and never in a public issue. Security fixes are made in the latest release only.

## Contributing

Pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) says how a change is reviewed and reaches this repository, what it must pass, and the sign-off every commit carries. Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## License

ExecBound is licensed under AGPL-3.0-only ([LICENSE](LICENSE)). The [Python client](clients/python/), the [provider protocol](protocol/), the [connectors](connectors/), the [examples](examples/), the [integrations](integrations/), the [deployment files](deploy/) and the server's install bundle, starter policy packs and MCP recipes are Apache-2.0, the documentation in [docs](docs/) is CC BY 4.0 and the console's fonts are OFL-1.1, each directory with its own license file and each source file with an `SPDX-License-Identifier` line naming its license.

An organization whose policies do not allow AGPL software can ask ExecBound LLC for the server and console under a free [internal-use license](INTERNAL_USE_LICENSE.md). "ExecBound" and its mark are trademarks of ExecBound LLC; [TRADEMARK.md](TRADEMARK.md) says how you may use them. Contributions are made under the [contributor agreement](CONTRIBUTOR_AGREEMENT.md).
