// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import type { BundlePreviewView, ChangedDecisionRow } from "../../api/types.gen";
import { Explain } from "../assistant/Explain";
import { when } from "../directory/format";
import { Badge } from "../ui/Badge";
import { Table, Td, Th } from "../ui/Table";
import { DECISION, decisionWord } from "./format";
import "./policy.css";

const PREFIX = 8;
// Above this many changed decisions the table starts folded, so the activation step stays near.
const FOLDED_ABOVE = 10;

/**
 * What a candidate would have decided over the tenant's own recorded history, as the
 * stepper's preview step shows it (#678).
 *
 * It is a replay: no provider runs, and no live budget, approval or execution state moves.
 * It is not run on arrival or on validation, because it replays the window the person
 * chooses and a page render is not that choice; the person starts it.
 */
export function PreviewResult({ result, bundleId }: { result: BundlePreviewView; bundleId: string }) {
  if (!result.available) {
    return (
      <p className="note" role="status">
        The preview could not be computed from this tenant&rsquo;s recent history. Nothing is
        shown rather than figures that would not be its own.
      </p>
    );
  }
  const decisions = result.considered === 1 ? "1 decision" : `${String(result.considered)} decisions`;
  return (
    <>
      <p className="note" role="status">
        {decisions} considered, {result.changed.length === 1 ? "1 would change" : `${String(result.changed.length)} would change`}.{" "}
        {result.complete ? "The history is complete." : `The history is incomplete: ${result.issues.join(", ")}.`}
      </p>
      <div className="effect-counts">
        <EffectCounts label="As recorded" counts={result.baseline_effects} />
        <EffectCounts label="Under this bundle" counts={result.candidate_effects} />
      </div>
      {result.changed.length === 0 ? (
        <p className="muted">No recorded decision would change.</p>
      ) : result.changed.length > FOLDED_ABOVE ? (
        <details className="policy-changed">
          <summary>Show the {String(result.changed.length)} decisions that would change</summary>
          <ChangedTable changed={result.changed} />
        </details>
      ) : (
        <ChangedTable changed={result.changed} />
      )}
      {/* The changed decisions are the record of what this candidate would do; the
          explanation sits below them, collapsed (#330). Each row opens in Activity's drawer,
          which carries its own Explain for that one decision. */}
      {result.changed.length > 0 ? (
        <Explain kind="policy_change" id={bundleId} what="this policy change" />
      ) : null}
    </>
  );
}

function ChangedTable({ changed }: { changed: readonly ChangedDecisionRow[] }) {
  return (
    <Table caption="The decisions this bundle would have made differently.">
      <thead>
        <tr>
          <Th>Request</Th>
          <Th>Action</Th>
          <Th>Today</Th>
          <Th>This bundle</Th>
          <Th>Because</Th>
        </tr>
      </thead>
      <tbody>
        {changed.map((change, index) => (
          // One request can be replayed more than once (at admission and at its decision).
          <tr key={`${change.execution_id}:${String(index)}`}>
            <th scope="row" className="mono">
              {/* The record itself, in Activity's drawer, which keeps its state in the
                  address so this link restores it (#333). */}
              <Link to="/activity" search={{ open: change.execution_id }}>
                {change.execution_id.slice(0, PREFIX)}
              </Link>
              <span className="faint"> {when(change.semantic_time)}</span>
            </th>
            <Td mono>{change.action}</Td>
            <Td>
              <Effect effect={change.baseline_effect} />
            </Td>
            <Td>
              <Effect effect={change.candidate_effect} />
              {change.required_approvers > 1 ? (
                <span className="faint"> {String(change.required_approvers)} approvers</span>
              ) : null}
            </Td>
            <Td>
              {change.rule_ids.length > 0 ? (
                <span className="mono">{change.rule_ids.join(", ")}</span>
              ) : change.candidate_reasons.length > 0 ? (
                <span className="mono">{change.candidate_reasons.join(", ")}</span>
              ) : (
                <span className="faint">{change.differences.join(", ")}</span>
              )}
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export function Effect({ effect }: { effect: string }) {
  const shown = DECISION[effect];
  return shown === undefined ? (
    <span>{decisionWord(effect)}</span>
  ) : (
    <Badge tone={shown.tone}>{shown.word}</Badge>
  );
}

export function EffectCounts({ label, counts }: { label: string; counts: Record<string, number> }) {
  const entries = Object.entries(counts);
  return (
    <div>
      <p className="eyebrow">{label}</p>
      {entries.length === 0 ? (
        <p className="muted">Nothing in the window.</p>
      ) : (
        <ul className="plain">
          {entries.map(([effect, count]) => (
            <li key={effect}>
              <span className="mono">{String(count)}</span> {decisionWord(effect)}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
