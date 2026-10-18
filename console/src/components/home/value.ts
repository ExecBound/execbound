// SPDX-License-Identifier: AGPL-3.0-only
// What ExecBound did (#678): the rows Home's card and the report page show, their
// words and the Activity search each number opens. Every word is fixed here, so a test can read
// all of it; nothing an agent, a provider or a target names reaches a heading or a link.

import type { ReportView } from "../../api/types.gen";
import type { ActivitySearch, Outcome } from "../../lib/activity-search";

/** Each outcome's words, as a pinned chip names it. */
export const OUTCOME_WORDS: Readonly<Record<Outcome, string>> = {
  refused_policy: "Refused by policy or a failed check",
  refused_limit: "Refused by an impact limit",
  refused_busy: "Refused because another request held the target",
  approved: "Approved",
  refused_by_person: "Refused by a person",
  lapsed: "Lapsed before a decision",
  approved_unused: "Approved, but not used before the deadline",
  closed: "Closed without a decision",
  waiting: "Still waiting",
  settled: "Uncertain dispatch, settled",
  unsettled_now: "Still unsettled",
  effect_unknown: "Effect unknown",
  would_refuse: "Would have been refused",
  would_refuse_by_limit: "Would have been refused by a limit",
  would_hold: "Would have been held",
  would_run: "Would have run",
};

export const COPY = {
  title: "What ExecBound did",
  since: "Requests made since",
  full: "Full report",
  observeTitle: "Observe mode: nothing was enforced",
  footer: "Counts of what ExecBound recorded. A refusal is not proof that harm was prevented.",
  noActivity: "(no Activity record)",
  medianLead: "Median time to decide:",
  open: "open in Activity",
} as const;

/** The one sentence that must name harm prevented, to say a refusal is no proof of it. */
export const DISCLAIMER = COPY.footer;

/** A count's sentence for its link's accessible name: "4 refused by an impact limit". */
export const SENTENCES: Readonly<Record<Outcome, string>> = {
  refused_policy: "refused by policy or a failed check",
  refused_limit: "refused by an impact limit",
  refused_busy: "refused because another request held the target",
  approved: "approved",
  approved_unused: "approved, not used before the deadline",
  refused_by_person: "refused by a person",
  lapsed: "lapsed before a decision",
  closed: "closed without a decision",
  waiting: "still waiting",
  settled: "uncertain dispatches settled",
  unsettled_now: "still unsettled",
  effect_unknown: "with an unknown effect",
  would_refuse: "would have been refused",
  would_refuse_by_limit: "would have been refused by a limit",
  would_hold: "would have been held",
  would_run: "would have run",
};

/** One number of the list: its label, the count, and the outcome its link opens, if any. */
export interface ValueRow {
  key: string;
  label: string;
  count: number;
  outcome?: Outcome;
  /** Lines under the row, each a count of its own. */
  parts?: ValueRow[];
  /** Top actions, each linking to its outcome narrowed by action. */
  actions?: { action: string; label: string; count: number }[];
  note?: string;
}

/** The Activity search a count opens: the outcome, from the report's start, and an action. */
export function activityFor(outcome: Outcome, since: string, action?: string): ActivitySearch {
  return action === undefined ? { outcome, from: since } : { outcome, from: since, action };
}

export function minutes(seconds: number): string {
  if (seconds < 60) return `${String(seconds)} s`;
  if (seconds < 3600) return `${String(Math.round(seconds / 60))} min`;
  return `${String(Math.round(seconds / 360) / 10)} h`;
}

/** The enforced rows, in reading order. A row the report has nothing for is left out where the
 * copy says so; a count of zero that means something is kept. */
export function rows(report: ReportView): ValueRow[] {
  const held = report.held;
  const found: ValueRow[] = [
    {
      key: "policy",
      label: "Refused by policy or a failed check",
      count: report.refused.policy,
      outcome: "refused_policy",
      actions: report.refused.top_actions.map((top) => ({ action: top.action, label: top.action_label, count: top.count })),
    },
    { key: "limit", label: "Refused by an impact limit", count: report.refused.limit, outcome: "refused_limit" },
  ];
  if (report.refused.busy > 0) {
    found.push({
      key: "busy",
      label: "Refused because another request held the target",
      count: report.refused.busy,
      outcome: "refused_busy",
    });
  }
  const parts: ValueRow[] = [{ key: "approved", label: "approved", count: held.approved, outcome: "approved" }];
  if (held.approved_unused > 0) {
    parts.push({
      key: "unused",
      label: "of which not used before the deadline",
      count: held.approved_unused,
      outcome: "approved_unused",
    });
  }
  parts.push(
    { key: "refused", label: "refused", count: held.refused, outcome: "refused_by_person" },
    { key: "lapsed", label: "lapsed before a decision", count: held.lapsed, outcome: "lapsed" },
  );
  if (held.closed > 0) {
    parts.push({ key: "closed", label: "closed without a decision", count: held.closed, outcome: "closed" });
  }
  parts.push({ key: "waiting", label: "still waiting", count: held.waiting, outcome: "waiting" });
  found.push({
    key: "held",
    label: "Held for a person",
    count: held.total,
    parts,
    note:
      held.median_seconds_to_decide !== null
        ? `${COPY.medianLead} ${minutes(held.median_seconds_to_decide)}`
        : undefined,
  });
  found.push({
    key: "settled",
    label: "Uncertain dispatches settled",
    count: report.uncertain.settled,
    outcome: "settled",
    parts: [
      { key: "unsettled", label: "still unsettled", count: report.uncertain.unsettled_now, outcome: "unsettled_now" },
      { key: "unknown", label: "effect unknown", count: report.uncertain.effect_unknown, outcome: "effect_unknown" },
    ],
  });
  if (report.refused_before_decision !== null) {
    found.push({
      key: "before",
      label: `Refused before a decision ${COPY.noActivity}`,
      count: report.refused_before_decision,
    });
  }
  return found;
}

/** Observe mode's would-have counts, kept apart from every enforced count. */
export function observed(report: ReportView): ValueRow[] {
  const seen = report.observed;
  return [
    {
      key: "would_refuse",
      label: "would have refused",
      count: seen.would_refuse,
      outcome: "would_refuse",
      parts: [{ key: "by_limit", label: "by a limit", count: seen.would_refuse_by_limit, outcome: "would_refuse_by_limit" }],
    },
    { key: "would_hold", label: "held", count: seen.would_hold, outcome: "would_hold" },
    { key: "would_run", label: "run", count: seen.would_run, outcome: "would_run" },
  ];
}
