// SPDX-License-Identifier: AGPL-3.0-only
// One value report, as the console API answers `/report`, for the tests of Home's card, the
// report page and the Live board's neighbours (#678).

import type { ReportView } from "../api/types.gen";

export const REPORT: ReportView = {
  range: "7d",
  since: "2026-09-12T14:00:00Z",
  until: "2026-09-19T14:02:11Z",
  mode: "ENFORCE",
  space: "All spaces",
  requests: 40,
  refused: {
    policy: 6,
    limit: 4,
    busy: 1,
    top_actions: [
      { action: "endpoint.isolate", action_label: "Isolate endpoint", count: 4 },
      { action: "identity.disable", action_label: "Disable identity", count: 2 },
    ],
  },
  held: {
    total: 9,
    approved: 5,
    approved_unused: 1,
    refused: 1,
    lapsed: 2,
    closed: 0,
    waiting: 1,
    median_seconds_to_decide: 180,
  },
  uncertain: { settled: 2, unsettled_now: 1, effect_unknown: 1 },
  observed: { total: 0, would_refuse: 0, would_refuse_by_limit: 0, would_hold: 0, would_run: 0 },
  refused_before_decision: 3,
  monitoring: { quiet_sources: 1, open_findings: 0 },
};
