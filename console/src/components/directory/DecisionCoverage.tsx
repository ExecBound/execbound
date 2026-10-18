// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { useRouterState } from "@tanstack/react-router";
import { useEffect } from "react";

import { readApprovalCoverageOptions } from "../../api/@tanstack/react-query.gen";
import type {
  ApprovalCoverage,
  ApprovalRule,
  CoverageAction,
  CoverageSpace,
  CoverageTarget,
} from "../../api/types.gen";
import { Card } from "../ui/Card";
import { Time } from "../ui/Time";
import { Button } from "../ui/Button";
import { explain } from "./errors";
import { COVERAGE_ID } from "./coverage-id";
import { prefix } from "./format";

/** A gap the administrator chose to fix: the target with its labels, the action and the Space. */
export interface Gap {
  space_id: string;
  action: string;
  target: { id: string; labels: string | null };
}

export { COVERAGE_ID };

function people(count: number): string {
  return `${String(count)} ${count === 1 ? "person" : "people"}`;
}

/** What holds an action, in words: `rule:prod-review` reads as rule `prod-review`. */
function heldBy(held: string[]) {
  return held.map((name, index) => {
    const [kind, ...rest] = name.split(":");
    const id = rest.join(":");
    return (
      <span key={name}>
        {index > 0 ? (index === held.length - 1 ? " and " : ", ") : null}
        {kind === "rule" ? <>rule <code>{id}</code></> : kind === "limit" ? <>limit <code>{id}</code></> : "the custom policy"}
      </span>
    );
  });
}

function shortfall(row: CoverageTarget, required: number): string {
  if (row.reviewers === 0) return "Nobody can decide this";
  return `Needs ${String(required)} people; ${String(row.reviewers)} can decide`;
}

/**
 * Decision coverage on Approval rules (#678): for each Space and each action its active policy
 * can hold, how many people can decide it, and which resources held, requested or thinly
 * covered in the last 30 days too few people can decide. Every fix opens an existing dialog,
 * prefilled, and changes nothing until the administrator completes it.
 *
 * Read when the page mounts and when the window regains focus, and refetched after every rule,
 * assignment and group change made here; never on a timer.
 */
export function DecisionCoverage({
  rules,
  writeSpace,
  onAddToRule,
  onAssign,
}: {
  rules: ApprovalRule[];
  /** The Space an individual assignment would land in, or null when that is ambiguous. */
  writeSpace: string | null;
  onAddToRule: (gap: Gap, rule: ApprovalRule | null) => void;
  onAssign: (gap: Gap) => void;
}) {
  const coverage = useQuery(readApprovalCoverageOptions());
  const hash = useRouterState({ select: (state) => state.location.hash });
  const loaded = coverage.data !== undefined;
  useEffect(() => {
    // Home's link lands here; the card arrives after the page, so bring it into view once.
    if (loaded && hash === COVERAGE_ID) document.getElementById(COVERAGE_ID)?.scrollIntoView({ block: "start" });
  }, [loaded, hash]);
  return (
    <Card title="Decision coverage" id={COVERAGE_ID} className="coverage">
      {coverage.data === undefined ? (
        coverage.isError ? (
          <p role="alert">Decision coverage could not be loaded. {explain(coverage.error)}</p>
        ) : (
          <p role="status" className="muted">Loading decision coverage</p>
        )
      ) : (
        <Coverage data={coverage.data} rules={rules} writeSpace={writeSpace} onAddToRule={onAddToRule} onAssign={onAssign} />
      )}
      <p className="note">
        Based on current rules, groups, roles and assignments. Eligibility is checked again when a request is reviewed
        and before execution.
      </p>
    </Card>
  );
}

function short(action: CoverageAction): boolean {
  return (
    action.reviewers < action.required ||
    action.held_uncovered.total > 0 ||
    action.thin.total > 0 ||
    action.requested_uncovered.total > 0
  );
}

function Coverage({
  data,
  rules,
  writeSpace,
  onAddToRule,
  onAssign,
}: {
  data: ApprovalCoverage;
  rules: ApprovalRule[];
  writeSpace: string | null;
  onAddToRule: (gap: Gap, rule: ApprovalRule | null) => void;
  onAssign: (gap: Gap) => void;
}) {
  const settled = data.spaces.every((space) => space.actions.every((action) => !short(action)));
  return (
    <>
      {data.mode === "OBSERVE" ? (
        <p className="note">
          Observe only: nothing is held while the workspace observes. This shows who would decide once it enforces.
        </p>
      ) : null}
      {settled ? (
        <p>
          Every action the active policies can hold has enough people to decide it, for every resource held or
          requested in the last 30 days.
        </p>
      ) : null}
      {data.truncated ? (
        <p className="note">
          Not everything is shown: this reads at most 50 Spaces and the newest 5,000 resources per Space and action.
        </p>
      ) : null}
      {data.spaces.map((space) => (
        <SpaceCoverage
          key={space.space_id}
          space={space}
          rules={rules}
          writable={writeSpace === space.space_id}
          onAddToRule={onAddToRule}
          onAssign={onAssign}
        />
      ))}
    </>
  );
}

function SpaceCoverage({
  space,
  rules,
  writable,
  onAddToRule,
  onAssign,
}: {
  space: CoverageSpace;
  rules: ApprovalRule[];
  writable: boolean;
  onAddToRule: (gap: Gap, rule: ApprovalRule | null) => void;
  onAssign: (gap: Gap) => void;
}) {
  const heading = `coverage-${space.space_id}`;
  return (
    <section className="coverage-space" aria-labelledby={heading}>
      <h3 id={heading}>{space.name}</h3>
      {space.policy === "none" ? (
        <p className="muted">No active policy: nothing is held.</p>
      ) : space.actions.length === 0 ? (
        <p className="muted">The active policy holds nothing for a person to decide.</p>
      ) : (
        <ul className="coverage-actions">
          {space.actions.map((action) => (
            <ActionCoverage
              key={action.action}
              space={space}
              action={action}
              rules={rules}
              writable={writable}
              onAddToRule={onAddToRule}
              onAssign={onAssign}
            />
          ))}
        </ul>
      )}
    </section>
  );
}

function ActionCoverage({
  space,
  action,
  rules,
  writable,
  onAddToRule,
  onAssign,
}: {
  space: CoverageSpace;
  action: CoverageAction;
  rules: ApprovalRule[];
  writable: boolean;
  onAddToRule: (gap: Gap, rule: ApprovalRule | null) => void;
  onAssign: (gap: Gap) => void;
}) {
  const fixes = { space, action, rules, writable, onAddToRule, onAssign };
  return (
    <li className="coverage-action">
      <p>
        <strong>{action.action_label}</strong> · held by {heldBy(action.held_by)} · {people(action.reviewers)}{" "}
        can decide
      </p>
      {action.reviewers === 0 ? (
        <p className="tone-deny">Nobody can decide this action in {space.name}.</p>
      ) : action.reviewers < action.required ? (
        <p className="tone-deny">
          Needs {String(action.required)} people; {String(action.reviewers)} can decide this action in {space.name}.
        </p>
      ) : null}
      {!action.known ? (
        <p className="note">
          Custom policy: it may hold this action; which requests it holds cannot be read from the policy.
          {action.upto !== null ? ` It may need up to ${String(action.upto)} people.` : null}
        </p>
      ) : null}
      {action.held_uncovered.total > 0 ? (
        <>
          <p>
            {action.held_uncovered.total} {action.held_uncovered.total === 1 ? "resource" : "resources"} requested in
            the last 30 days cannot be decided.
          </p>
          <ul className="coverage-gaps">
            {action.held_uncovered.rows.map((row) => (
              <GapRow key={row.canonical_target_id} row={row} verb="held" note={shortfall(row, action.required)} {...fixes} />
            ))}
          </ul>
        </>
      ) : null}
      {action.thin.total > 0 ? (
        <ul className="coverage-gaps">
          {action.thin.rows.map((row) => (
            <GapRow
              key={row.canonical_target_id}
              row={row}
              verb="held"
              note={`Only ${people(row.reviewers)} can decide ${row.labels ?? "this resource"}, exactly the quorum; if one is away, its requests lapse.`}
              {...fixes}
            />
          ))}
        </ul>
      ) : null}
      {action.requested_uncovered.total > 0 ? (
        <details>
          <summary>
            {action.requested_uncovered.total} other {action.requested_uncovered.total === 1 ? "resource" : "resources"}{" "}
            this action reached could not be decided if they were held.
          </summary>
          <ul className="coverage-gaps">
            {action.requested_uncovered.rows.map((row) => (
              <GapRow key={row.canonical_target_id} row={row} verb="requested" note={shortfall(row, action.required)} {...fixes} />
            ))}
          </ul>
        </details>
      ) : null}
    </li>
  );
}

function GapRow({
  row,
  verb,
  note,
  space,
  action,
  rules,
  writable,
  onAddToRule,
  onAssign,
}: {
  row: CoverageTarget;
  verb: "held" | "requested";
  note: string;
  space: CoverageSpace;
  action: CoverageAction;
  rules: ApprovalRule[];
  writable: boolean;
  onAddToRule: (gap: Gap, rule: ApprovalRule | null) => void;
  onAssign: (gap: Gap) => void;
}) {
  const gap: Gap = {
    space_id: space.space_id,
    action: action.action,
    target: { id: row.canonical_target_id, labels: row.labels ?? null },
  };
  // Rules in this Space that already route this action and have room for one more resource.
  const room = rules.filter(
    (rule) =>
      rule.active && rule.space_id === space.space_id && rule.actions.includes(action.action) && rule.targets.length < 100,
  );
  const times = row.requests === 1 ? "once" : `${String(row.requests)} times`;
  return (
    <li className="coverage-gap">
      <span className="coverage-gap-what">
        {row.labels ?? "Unnamed resource"} <span className="mono faint">{prefix(row.canonical_target_id)}</span>
      </span>
      <small>
        {verb} {times}, last <Time at={row.last_requested_at} /> · {note}
      </small>
      <span className="coverage-gap-fixes">
        <details className="coverage-menu">
          <summary>Add to a rule</summary>
          <ul>
            {room.map((rule) => (
              <li key={rule.rule_id}>
                <Button size="small" onClick={() => { onAddToRule(gap, rule); }}>
                  {rule.name}
                </Button>
              </li>
            ))}
            <li>
              <Button size="small" onClick={() => { onAddToRule(gap, null); }}>
                New rule
              </Button>
            </li>
          </ul>
        </details>
        {writable ? (
          <Button size="small" onClick={() => { onAssign(gap); }}>
            Assign a person
          </Button>
        ) : (
          <small className="muted">To assign one person, switch to {space.name} first.</small>
        )}
      </span>
    </li>
  );
}
