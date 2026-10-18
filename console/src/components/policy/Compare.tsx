// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";

import { comparePolicyBundleOptions } from "../../api/@tanstack/react-query.gen";
import type { BundleDetail, PolicyComparison } from "../../api/types.gen";
import { Problem } from "../directory/forms";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { DIRECTION, policyName, ruleSentence, type Direction } from "./format";
import "./policy.css";

/** Whether this policy is one a comparison with the policy in use is worth asking for. */
export function comparable(detail: BundleDetail): boolean {
  return detail.state === "DRAFT" || detail.state === "VALIDATED" || (detail.state === "ACTIVE" && !detail.active);
}

/** How this policy differs from the one active in this Space, read once per detail. */
export function useComparison(detail: BundleDetail) {
  return useQuery({
    ...comparePolicyBundleOptions({ path: { bundle_id: detail.bundle_id } }),
    enabled: comparable(detail),
  });
}

const WHY_NOT: Record<string, string> = {
  "no-active": "No policy is active in this Space, so every rule here is new.",
  "no-space": "Choose a Space to compare this policy with the one it would replace.",
  "is-active": "This is the policy active in this Space.",
  cedar:
    "This policy, or the one in use, is written in Cedar rather than as rules, so it cannot be compared rule by rule. The preview shows what would decide differently.",
};

function plural(count: number, one: string, many: string): string {
  return `${String(count)} ${count === 1 ? one : many}`;
}

/** The activation dialog's line: what the comparison counted, by direction. */
export function compareSummary(comparison: PolicyComparison | undefined): string | null {
  if (comparison === undefined || !comparison.comparable || comparison.against === null) return null;
  const parts: string[] = [];
  if (comparison.wider > 0) parts.push(plural(comparison.wider, "change allows more", "changes allow more"));
  if (comparison.narrower > 0) {
    parts.push(
      parts.length === 0
        ? plural(comparison.narrower, "change allows less", "changes allow less")
        : plural(comparison.narrower, "allows less", "allow less"),
    );
  }
  if (comparison.unclear > 0) {
    parts.push(parts.length === 0 ? plural(comparison.unclear, "change to check", "changes to check") : `${String(comparison.unclear)} to check`);
  }
  const counted = parts.length === 0 ? "nothing allows more or less" : parts.join(", ");
  return `Compared with ${policyName(comparison.against)} as the rules read: ${counted}.`;
}

interface Entry {
  key: string;
  direction: Direction;
  label: string;
  lines: { text: string; mono?: boolean }[];
}

const RANK: Record<Direction, number> = { wider: 0, narrower: 1, unclear: 2, none: 3 };

function fieldWords(fields: readonly string[]): string {
  return fields.map((field) => field.replaceAll("_", " ")).join(", ");
}

function mappingSentence(change: PolicyComparison["mappings"][number]): string {
  if (change.change === "added") return `${change.action} is also served through another connector account`;
  if (change.change === "removed") return `${change.action} is no longer served through this connector account`;
  const fields = change.fields;
  if (fields.length === 1 && fields[0] === "external_executor") {
    return change.direction === "wider"
      ? `${change.action} now lets an external executor act after approval`
      : `${change.action} no longer lets an external executor act`;
  }
  if (fields.length === 1 && fields[0] === "observe_only") {
    return change.direction === "wider"
      ? `${change.action} is now carried out rather than only observed`
      : `${change.action} is now only observed`;
  }
  return `${change.action} changes its mapping's ${fieldWords(fields)}`;
}

/** Every change as one list, most permissive first; every value is the answer's own text. */
function entries(comparison: PolicyComparison): Entry[] {
  const list: Entry[] = [];
  for (const rule of comparison.rules) {
    const lines: Entry["lines"] = [];
    if (rule.before !== null) lines.push({ text: `Before: ${ruleSentence(rule.before)}` });
    if (rule.after !== null) lines.push({ text: `After: ${ruleSentence(rule.after)}` });
    if (rule.change === "changed" && rule.direction === "none") lines.push({ text: "Only its note changes." });
    list.push({ key: `rule:${rule.rule_id}`, direction: rule.direction, label: rule.rule_id, lines });
  }
  for (const budget of comparison.budgets) {
    const lines: Entry["lines"] = [];
    if (budget.before !== null) lines.push({ text: `Before: ${budget.before}` });
    if (budget.after !== null) lines.push({ text: `After: ${budget.after}` });
    list.push({ key: `budget:${budget.rule_id}`, direction: budget.direction, label: budget.rule_id, lines });
  }
  for (const action of comparison.actions) {
    list.push({
      key: `action:${action.change}:${action.action}`,
      direction: action.direction,
      label: action.action,
      lines: [
        {
          text:
            action.change === "added"
              ? `${action.action} is newly mapped in this policy.`
              : `${action.action} is no longer mapped in this policy.`,
        },
      ],
    });
  }
  for (const mapping of comparison.mappings) {
    list.push({
      key: `mapping:${mapping.operation_ref}:${mapping.account_id}`,
      direction: mapping.direction,
      label: mapping.operation_ref,
      lines: [{ text: mappingSentence(mapping) }, { text: mapping.account_id, mono: true }],
    });
  }
  for (const setting of comparison.context) {
    list.push({
      key: `context:${setting.contract}:${setting.source_kind}`,
      direction: setting.direction,
      label: setting.contract,
      lines: [
        {
          text:
            setting.change === "changed"
              ? `The ${setting.source_kind} setting changes its ${fieldWords(setting.fields)}.`
              : `The ${setting.source_kind} setting is ${setting.change}.`,
        },
      ],
    });
  }
  for (const signal of comparison.signals) {
    list.push({
      key: `signal:${signal.contract}:${signal.capability}`,
      direction: signal.direction,
      label: signal.contract,
      lines: [{ text: `The ${signal.capability} signal mapping is ${signal.change}.` }],
    });
  }
  return list.sort((left, right) => RANK[left.direction] - RANK[right.direction]);
}

/**
 * Changes from the active policy (#678): what this policy changes from the one in use
 * in this Space, as the rules read. It is never a decision; the preview is what shows what
 * would actually have decided differently. Each change leads with its word, and the colour
 * repeats it.
 */
export function Changes({
  detail,
  comparison,
  error,
}: {
  detail: BundleDetail;
  comparison: PolicyComparison | undefined;
  error: unknown;
}) {
  if (!comparable(detail)) return null;
  return (
    <Card title="Changes from the active policy">
      <Problem error={error} />
      {comparison === undefined ? null : !comparison.comparable ? (
        <p className="muted">{WHY_NOT[comparison.why_not ?? ""] ?? WHY_NOT["no-active"]}</p>
      ) : (
        <ChangeList comparison={comparison} />
      )}
    </Card>
  );
}

function ChangeList({ comparison }: { comparison: PolicyComparison }) {
  const list = entries(comparison);
  return (
    <>
      <p className="muted">
        As the rules read, compared with {policyName(comparison.against ?? "")}, the policy
        active in this Space. The preview shows what would actually have decided differently.
      </p>
      {list.length === 0 ? (
        <p>The rules, budgets and mappings are the same as the policy in use.</p>
      ) : (
        <ul className="policy-changes">
          {list.map((entry) => {
            const shown = DIRECTION[entry.direction];
            return (
              <li key={entry.key} className="policy-change">
                <span className="badges">
                  {shown === null ? null : <Badge tone={shown.tone}>{shown.word}</Badge>}
                  <span className="mono">{entry.label}</span>
                </span>
                {entry.lines.map((line, index) => (
                  <p key={String(index)} className={line.mono === true ? "mono faint" : undefined}>
                    {line.text}
                  </p>
                ))}
              </li>
            );
          })}
        </ul>
      )}
    </>
  );
}
