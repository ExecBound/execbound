# Community installation: an upgrade across six migrations

A run of [the runbook](../INSTALL.md)'s upgrade and backup sections on 26 September 2026. The
installation had already governed something, and the upgrade crossed a real schema change. The
[installation trial](2026-09-19-community-install.md) ran the same two upgrade commands, but its
database was already at head (its step 10), so the migrations had nothing to do. This run
exercises that section for the first time, and is the record behind the runbook's commitment
that its upgrade and restore steps are exercised and recorded. From 26 September 2026 the
development repository's `fresh-machine` job repeats it for every change, from that change's
base revision.

## What was run

Two images, both built on this workstation from the development repository:

| Image | Revision | Schema |
| --- | --- | --- |
| Old | `bfc37a64ba78` on `main`, 24 September 2026 | `0056_gate_evidence` |
| New | `ccfc96ce` on `main`, 26 September 2026 | `0062_people_numbers` |

Between the two lie six migrations:

- `0057_api_key_never`
- `0058_api_key_numbers`
- `0059_workspace_invitations`
- `0060_sample_targets`
- `0061_replaced_principals`
- `0062_people_numbers`

Five of them carry `UPDATE`, `INSERT` or `DELETE` statements, directly or in the functions
they install, over tables quickstart populates: principals, credentials, context sources,
resources and connector accounts. They are not only new columns.

`scripts/community_upgrade.py` ran the steps, and only the runbook's own commands:

```sh
python3 scripts/community_upgrade.py \
  --old-image execbound:upgrade-old-local --new-image execbound:upgrade-new-local \
  --project execbound-upgrade-local --port 18991 --directory "$scratch/run1"
```

In order, it:

1. Ran `execbound init` and `execbound quickstart` on the old image.
2. Took the runbook's backup, restored it into `execbound_restore` and ran
   `python -m execbound.recovery --compare-live`.
3. Pointed `EXECBOUND_IMAGE` at the new image and ran
   `docker compose run --rm gateway alembic upgrade head`, then `docker compose up -d`. The
   `compose.yaml` the old `init` wrote stayed in place, because the runbook does not tell an
   installer to replace it.
4. Exported the history with `execbound audit-export`, using the administrator token.
5. Sent two requests with the agent credential issued before the upgrade.
6. Waited for the scheduled jobs.
7. Took the backup and verified it again.

The whole job's steps, replayed from the development repository's CI workflow, ran the same
upgrade after the fresh three-command install.

## What it established

| Check | Before the upgrade | After the upgrade |
| --- | --- | --- |
| Schema | `0056_gate_evidence` | `0062_people_numbers`, the new image's own head |
| Quickstart's decisions | `ws01.example` EXECUTED, `ws02.example` DENIED | not re-run; quickstart refuses a second run |
| Gateway readiness | ready | ready |
| Backup restored and verified | 27 events, `chain=ok`, `live=MATCHES_LIVE`, 0 unresolved | 36 events, `chain=ok`, `live=MATCHES_LIVE`, 0 unresolved |
| Pre-upgrade head in the new chain | n/a | unchanged at sequence 27 |
| Agent credential issued before | n/a | `ws02.example` DENIED; `ws01.example` STALE_AUTHORIZATION |
| Scheduled jobs on the new image | n/a | `recover`, `notify` and `monitor-process` each completed; none failed |

- **The two answers after the upgrade are the right ones.** The deny rule still wins for
  `ws02.example`. The provider still holds `ws01.example` contained from quickstart's run, so
  the frozen precondition no longer matches and nothing is dispatched twice. That second answer
  shows the provider stores survived the containers being replaced.
- **Timing:** 37 seconds for the upgrade check alone, and 1 minute 25 seconds for the whole
  `fresh-machine` job replayed with a warm Docker cache.

**The check catches an upgrade that breaks meaning, not only one that crashes.** In a scratch
copy of the tree, which was never committed, a seventh migration deactivated every context
source. That is valid SQL, and it leaves a database the gateway accepts. After the upgrade:
- the gateway reported **ready**, which was the most the earlier trial could check;
- the same credential's request for `ws02.example` answered 503 `EXECUTION_UNAVAILABLE`, because
  its incident no longer resolved;
- the check failed and named that request.

## What it did not establish

- **Base revisions, not versioned releases.** There are no releases yet, so the "previous
  minor version" the runbook supports is stood in for by the previous state of `main`.
- **Only images built locally from source.** No published or signed image was used, and no
  image was pulled from a registry.
- **One installation of the project's own design.** One tenant, two mock providers and the
  starter policy. No real provider, identity path, approval or console session crossed the
  upgrade.
- **An upgrade that changes `compose.yaml` is not covered.** Only the image changed between the
  two revisions. A release that also needs a compose change would fail this check, which is
  the intent, and the runbook would then have to say what to change.
- **Not a clean host.** Docker was this workstation's, with both images and `postgres:17.11`
  already present.
