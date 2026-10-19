# Contributing to ExecBound

Thank you for helping. This guide says how a change reaches ExecBound, what it has to pass, and what you certify when you send one. Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Report a vulnerability privately

Never in an issue, a pull request or a discussion. [SECURITY.md](SECURITY.md) says how to report one and what is in scope.

## How a pull request reaches `main`

This repository is exported from ExecBound's development repository, which also holds the hosted service. `main` here changes only through export pull requests: each carries one export of the development repository, and a maintainer reviews and merges it. Nothing reaches `main` any other way, and that includes your pull request.

Your pull request is still where your change is reviewed, in public. Once it is ready:

1. A maintainer applies your commits to the development repository, with you kept as their author.
2. Your pull request is closed rather than merged, and the maintainer says so on it.
3. The next export brings your change back here. Its commit carries a `Co-authored-by:` line with the name and address of your commits, so GitHub credits you.

A change made to `main` any other way would be overwritten by the next export, so none is made. The name and address in the credit are the ones your commits already show; if you would rather not publish an address, commit with your GitHub `noreply` address.

For anything larger than a small fix, open an issue first, so the approach can be agreed before you write it.

## Sign off every commit

Every commit carries a `Signed-off-by:` line, which certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change, or otherwise have the right to submit it under the license of the files it touches. `git commit -s` adds the line from your git name and address:

```sh
git commit -s -m "Refuse an approval that has already expired"
```

To sign off commits already on your branch, `git rebase --signoff main`, then push the branch again. A pull request with a commit that is not signed off is not applied.

## The contributor agreement

Every contribution is made under the [contributor agreement](https://github.com/ExecBound/execbound/blob/main/CONTRIBUTOR_AGREEMENT.md). You keep your copyright and give ExecBound LLC a license to use your contribution, including under other licenses than this repository's, and a license to any of your patents it needs. That is what lets ExecBound offer the code under its [internal-use license](INTERNAL_USE_LICENSE.md), in its hosted service and in its paid editions, as well as under AGPL-3.0 and Apache-2.0. ExecBound publishes every contribution it accepts under the license of the files it was submitted to.

Accept it by ticking its box in the pull request template, or by saying so on the pull request. An organization that wants to accept it for the people who contribute on its behalf writes to justin.pitt@execbound.ai, as the agreement's section 8 describes, and the people it lists tick the template's other box. A pull request is applied only after the author of every commit in it has accepted the agreement, in one of those ways.

A third party's work, such as code copied from another project, goes in a commit of its own, with its source and license in the commit message and the file's header, as the agreement's section 5 describes.

## What a change has to pass

[CI](.github/workflows/ci.yml) runs every stage of `scripts/ci.py` on each pull request. The same stages run on your machine, with Docker, uv, Node and pnpm, in a fresh clone rather than the checkout you work in:

```sh
python3 scripts/ci.py --print all
python3 scripts/ci.py all
```

The first prints what would run. While you work, the focused checks are quicker:

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run mypy
python3 scripts/licence_headers.py --check
cd console
pnpm install --frozen-lockfile
pnpm check
cd ..
```

The Python suite needs its database and tools first: `uv run python scripts/local_setup.py --test-workers 4` starts PostgreSQL in Docker Compose and creates a test database for each of four workers, and the suite also drives two MCP client environments, the agent SDK examples and Chromium:

```sh
uv pip install --target .tools/mcp-legacy --require-hashes -r tests/mcp-legacy.txt
uv pip install --target .tools/sdk-examples --require-hashes --no-binary claude-agent-sdk -r tests/sdk-examples.txt
uv run playwright install chromium
uv run pytest -q -n 4 --dist loadfile
```

Build the console (`pnpm build` in `console/`) before the suite, because its browser tests serve the build. The suite destructively rebuilds its own test databases, so never point it at data you want to keep, and run one suite at a time against one database.

## How tests are written here

- **A change to security behaviour starts with a test that fails without it.** Write the regression at the boundary it protects, watch it fail, then implement the change.
- **Transactions and concurrency are tested on real PostgreSQL.** A sequential mock is never evidence of atomicity.
- **Frozen history stays byte-compatible.** The contract fixtures `tests/fixtures/endpoint-contract-v1.json` and `tests/fixtures/identity-contract-v1.json` stay unchanged, and their tests, `tests/test_endpoint_upgrade_compatibility.py` and `tests/test_identity_compatibility.py`, keep passing. Never change the serialized form of an existing frozen plan, bundle, provider command or journal, and never edit an applied migration.
- **No test is skipped.** The validation stage refuses a test report that holds a skipped or expected-failure case, so a test either runs and passes or is not collected.
- **Secrets are minted by fixtures,** never typed into a test, and every rendered output a test inspects passes through `assert_secret_free` first.

## Conventions

- **Every source file names its license** in an `SPDX-License-Identifier` line at its top, the license of its directory. Stage a new file and run `python3 scripts/licence_headers.py --write`, which writes the line into every tracked file that needs it, or name the file after `--write`; `--check` names any file whose line is missing or wrong.
- **A new migration** keeps old frozen bytes, operation proof and retained uncertainty, and updates forced row-level security, grants and the `check_runtime` catalog in `src/execbound/db.py` together.
- **One complete protected action path comes before another connector.** A protocol adapter never authorizes or dispatches on its own; it goes through the kernel.
- **Pages treat agent and provider strings as untrusted data.**
- **Documents change with the code.** A change to behaviour updates the guide under `docs/` that describes it.
- **A number such as `#418` in a code comment** refers to an issue in ExecBound's development tracker, where this code is written before it is published here, not to an issue in this repository. It records why the code is as it is, and it is kept so the code reads the same in both places. Published documents carry no such numbers; an issue or pull request here is the place to ask about one.
