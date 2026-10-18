# Community installation: governing the first action

A clean-room run of [the runbook](../INSTALL.md) steps 10 to 12, on 19 September 2026,
against a freshly created installation. The earlier
[installation trial](2026-09-19-community-install.md) covers steps 1 to 9 and the upgrade
and restore sections; this one covers the part that was missing, and the reason the
runbook's scope was amended: an installation that runs is not the same as an installation
that has governed anything.

> Note, 2 October 2026: the runbook's numbered steps were replaced on 20 September 2026 by
> [three commands](../INSTALL.md#three-commands), whose third, `execbound quickstart`, does
> what this run did by hand. The commands below are now the runbook's
> [long way](../INSTALL.md#the-long-way-one-command-at-a-time).

## What was run

A new directory holding only `deploy/community/`, an empty database volume, and the image.
Steps 1 to 9 first, so nothing carried over from an earlier attempt, then 10 to 12 exactly
as written, with the identifiers each step prints.

- Two context sources, one inventory and one incident, both on the endpoint account.
- One operation mapping: `endpoint.isolate` on `mock_crowdstrike`.
- Two endpoints, identical but for one fact: `ws01.example` at criticality 2 and
  `ws02.example` at criticality 4. Both workstations, both in `development`.
- One incident manifest, two entries, both `OPEN` and `CRITICAL`, imported `--strict`:
  `applied 2, facts_written 4, incidents_created 2, unknown_resources 0`.
- Both canonical target ids into `EXECBOUND_ENDPOINT_RESOURCES`, and the endpoint provider
  recreated. Its store then held two resources and two representations.
- `ruleset-compile` on the shipped `starter-rules.json`: four rules, two budgets, one
  mapping, one bundle document.
- `bundle-create`, `bundle-validate`, `bundle-activate`: `DRAFT`, `VALIDATED`, `ACTIVE`.
- One AGENT principal and its own credential.
- Two requests, same action, same empty arguments, different target.

## What it established

**An installation holding only the image and the bundle directory can author its first
policy.** It could not before. The bundle document the lifecycle and the policy pages accept
carries a Cedar schema and two policy sets, and nothing in the image would write them; the
console's rules editor refuses to work until a bundle is already active, because the active
bundle's mappings are what tells it which actions a rule may speak about. The compiler
existed and was reachable only from the development harness, so every deployment's first
bundle came from a checkout. `ruleset-compile` is that compiler as a command.

**One allowed action, dispatched.** `ws01.example` answered `EXECUTED`. The mock's own store
then held that target `contained`, with its `mutation_count` at 1, its version advanced from
`resource-v1` to a new one, and one journal row. The audit chain carries
`execution.dispatch_attempt` with `precondition_class: ENFORCED_BY_PROVIDER`.

**One refused action, and refused by the rule rather than by default.** `ws02.example`
answered `DENIED`, and its store row was untouched. It satisfies every condition of the
allow rule — workstation, incident open, severity critical — so the only thing that explains
the refusal is the deny rule on criticality 4. A target that matched no allow rule would
have been refused too, by the default, and would have demonstrated nothing about precedence.

**Both visible in the audit chain**, along with everything that led to them: 25 events from
genesis, covering the principals and credentials, both sources, the mapping, both resources,
the import with its manifest digest, the bundle created, compiled, validated and activated,
and for each request the frozen plan, the decision and its reasons.

**The console reads it back.** `/policy/rules` shows the four rules as sentences beside the
Cedar they compile to; Activity shows both requests with their states; the agent's page
shows its autonomous budget at `1 of 10`.

## What running it corrected

Five things, none of which reading would have found:

1. **The image could not author a first policy.** This is the gap the whole section exists
   to close, and it was invisible from inside a checkout, where the harness packs are always
   importable.
2. **A variable exported into the shell silently beats `.env`.** Compose reads the process
   environment before the file, so after a `set -a; . ./.env` — the obvious way to get
   `$POSTGRES_PASSWORD` for step 5 — editing `.env` changes nothing, `docker compose up -d
   endpoint` prints `Running`, and the provider starts with the old empty list. Nothing
   fails; the dispatch just finds no target much later. The runbook now says to set the
   password without exporting it, and names `docker compose config` as the way to see what
   Compose actually resolved.
3. **The first refusal demonstrated nothing.** It used a domain controller, which no allow
   rule matches, so default deny and the deny rule are indistinguishable and the audit chain
   reports `NOT_AUTHORIZED` either way. Replaced with the criticality-4 workstation above.
4. **The bundle's own README contradicted its compose file**, describing the provider store
   as a named volume after it became a bind mount.
5. **The runbook still said upgrade and restore were unwritten**, two sections after they
   were written.

## What this does not establish

- **Not a different machine.** Docker was the host's own, and the host is the machine this
  was developed on. The same gap the installation trial recorded; it is the one thing a
  clean directory cannot fake.
- **Not a published artifact.** The image was built locally. Nothing is pushed to a
  registry and nothing is signed, so the runbook's step 1 was a local tag rather than a
  `docker load` of a released archive, and the licence decision still
  gates distribution itself. *Note, 2 October 2026: settled on 25 September 2026; the server
  is licensed AGPL-3.0-only.*
- **Not a real provider.** Both providers are mocks. `ENFORCED_BY_PROVIDER` is true of them
  because they offer a conditional write; it says nothing about any vendor, and no claim
  here transfers to one.
- **Not the identity path.** The identity mock started and stayed healthy. Nothing was
  dispatched to it, and no identity mapping, resource or rule was created.
- **Not approval.** The starter's review rule for production targets compiled into the
  approval policy set and was never triggered: both demonstration endpoints are in
  `development`. No approver was assigned and no approval was requested, granted or
  consumed.
- **Not a recommended policy.** `starter-rules.json` is four demonstration rules over two
  mock endpoints. It is a starting point to be replaced, not a pack.
- **Not upgrade or restore.** Those sections were exercised in the earlier trial and were
  not re-run here.
