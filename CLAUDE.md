# Instructions for coding agents

`CLAUDE.md` and `AGENTS.md` hold the same text: Claude Code reads the first, and other coding agents read the second. A change to one is made to both.

ExecBound decides whether an AI agent's action may run, and holds the credentials that carry it out, so a mistake here can matter more than in most software. Read [README.md](README.md) for what it is and how to run it, and [CONTRIBUTING.md](CONTRIBUTING.md) for how a change is reviewed and what it must pass. Before changing a subsystem, read its guide under `docs/`: [Architecture](docs/ARCHITECTURE.md), [Policy](docs/POLICY.md), [Approvals, impact limits and execution](docs/EXECUTION.md), [The data model](docs/DATA_MODEL.md) and the [threat model](docs/THREAT_MODEL.md) among them. The [acceptance inventory](docs/ACCEPTANCE_TESTS.md) lists the scenarios every change must keep, each with its required result.

## Security invariants

Every change keeps these. The threat model states the threats against each one.

- An agent's identity and tenant come from authentication, and every object and connector account is scoped to a tenant.
- Unknown or mismatched action or target input is rejected.
- A failure of required context, policy, state or audit intent prevents consequential dispatch.
- A hard denial always wins over permits and approvals.
- Approvals are scoped, expiring and held server-side, and each is consumed by one execution claim.
- Target impact is shared across agents, runs and adapters within the configured principal or tenant scope.
- The provider checks the frozen precondition atomically where the vendor offers a conditional write, and a binding that declares `ENFORCED_BY_PROVIDER` makes that claim. A vendor that offers none is declared `CHECKED_BY_CONNECTOR`, which proves ExecBound's own read and comparison immediately before the write, with the window between them measured and retained: not atomicity, and not a third party's report. Never describe a dispatch as atomically precondition-checked unless its binding declares `ENFORCED_BY_PROVIDER`.
- An uncertain operation cannot be retried or refunded without sufficient evidence.
- Replay never executes a provider or changes live budgets, approvals or execution state.
- Human pages treat agent and provider strings as untrusted data.
- Raw provider credentials, runtime configuration, signing material and control stores stay outside the protected agent's read and write authority, and there are no generic passthrough tools or agent-controlled connector destinations.

## How to change the code

- **Security behaviour starts with a failing test.** Write a meaningful regression at the boundary the change protects, see it fail, implement the change, then run the relevant suite.
- **Transactions and concurrency are tested on real PostgreSQL.** Never offer sequential mocks as evidence of atomicity.
- **Frozen history stays byte-compatible.** The contract fixtures `tests/fixtures/endpoint-contract-v1.json` and `tests/fixtures/identity-contract-v1.json` stay unchanged, and their tests, `tests/test_endpoint_upgrade_compatibility.py` and `tests/test_identity_compatibility.py`, keep passing. Never change the serialized form of an existing frozen plan, bundle, provider command or journal.
- **Migrations are added, never edited.** A new migration keeps old frozen bytes, operation proof and retained uncertainty, and updates forced row-level security, grants and the `check_runtime` catalog in `src/execbound/db.py` together.
- **No test is skipped.** The CI validation stage refuses a test report that holds a skipped or expected-failure case. A test that cannot run everywhere is not collected, rather than skipped.
- **Secrets in tests are minted by fixtures,** never typed into a test file, and every rendered output a test inspects passes through `assert_secret_free` before anything else is asserted about it.
- **One complete protected action path comes before another connector.** A protocol adapter never authorizes or dispatches on its own; it goes through the kernel.
- **The hosted service's plugin is not in this repository.** Core code reaches plugin behaviour only through the registry in `src/execbound/plugins.py`, and `tests/test_boundary.py` refuses any file that imports or names the plugin's module.
- **Every source file names its license** in an `SPDX-License-Identifier` line at its top. Stage a new file and run `python3 scripts/licence_headers.py --write`, or name the file after `--write`.
- **Documents change with the code.** A change to behaviour updates the guide under `docs/` that describes it.

## Commits and pull requests

- Work on a branch, and send the change as a pull request against `main`.
- A `Signed-off-by:` line certifies the Developer Certificate of Origin for a person. Add one (`git commit -s`) only under the identity of the person you work for, and only when they have asked you to; never sign off for anyone else.
- Commit messages and pull request descriptions say what the change does, in plain sentences, and carry no assistant attribution.

## Commands

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest -q
uv build
python3 scripts/licence_headers.py --check
```

`ruff format --check .` also checks the fenced `python` blocks inside Markdown files, so a document's Python example is formatted like code. The console's checks run from `console/`: `pnpm install --frozen-lockfile`, then `pnpm check`.

The suite needs PostgreSQL, two MCP client environments, the agent SDK examples, Chromium and a console build; [CONTRIBUTING.md](CONTRIBUTING.md) gives the commands. It destructively rebuilds its own test databases, so never point it at data anyone wants to keep, and run one suite at a time against one database. `python3 scripts/ci.py all`, in a fresh clone, runs every stage CI runs.
