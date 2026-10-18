# Trial records

What was actually run, on a date, against a real product or a fresh installation. A trial
record is the only thing that promotes an integration row to **platform-validated** on the
[integrations page](../INTEGRATIONS.md); a test that runs in CI promotes it only as far as
fixture-tested, and a design or a recipe with nothing run behind it leaves the row
research-only with mode Unknown.

Each record reads as it was written on its date. Identifiers that would locate a lab tenant,
an account or a machine are replaced with neutral descriptions, and where something has
changed since, a dated note says so rather than the record being rewritten. A commit a record
names is in the development repository, from which the public repository is exported. A few
records about the hosted service's own operations are kept with the hosted service rather
than published here.

## The two kinds of record here

- **Integration trials**, named by `evidence.trial` in
  [`integrations/manifest.json`](../../integrations/manifest.json). Each ran against a real
  product in a lab tenant or test account holding no organization's own data. Each carries
  `Host:`, `Version:`, `Date:`, `Transport:`, `Gateway commit:` and `Fixture seed:` on their
  own lines, and a `## Scenarios` section with the exact result of each scenario, which
  `tests/test_integrations_manifest.py` checks.
- **Installation and first-action trials.** These follow
  [the installation runbook](../INSTALL.md) rather than a product integration, so no manifest
  row names them and the field check does not apply. They are here because they are the same
  kind of evidence: one dated run, recorded as it happened.

## Writing one

Name the file `YYYY-MM-DD-<slug>.md` and record what was run, what it established, and what
it did **not** establish: a scenario not exercised, a branch that did not fire, a permission
nobody had. A row is promoted only as far as the trial went, a newer host version is not
claimed until it is re-trialled, and a failure keeps the row where it was. "Supported",
"certified" and "verified" are refused on the integrations page and in its manifest: those
are commercial words, and these records are evidence.
