// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

import type { MonitorFinding } from "../../api/types.gen";
import { prefix } from "../../lib/when";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Definition, Definitions } from "../ui/Definitions";
import { Time } from "../ui/Time";
import { accountable } from "./Agents";

export type Subject = "agent" | "observation" | "connection" | "source";

// `new-agent.v1` is raised no more (#355), and the findings it raised are still read here.
const AGENT_RULES = new Set([
  "ungoverned-reach.v1",
  "sponsorless-agent.v1",
  "new-agent.v1",
  "new-actor.v1",
  "first-consequential-action.v1",
  "new-ai-consent.v1",
]);
// `initial-inventory.v1` names its connection and no agent or observation, so it is filed under
// the connection without an entry here; its row says what it is through `RULE_SENTENCES`.
const CONNECTION_RULES = new Set(["collection-health.v1", "instrumentation-gap.v1"]);
export const GAP_RULE = "instrumentation-gap.v1";

/** What a finding is about, by its rule: a directory agent, an observation, a connection or a source. */
export function subjectOf(finding: MonitorFinding): Subject {
  if (finding.agent !== null || AGENT_RULES.has(finding.rule_version)) return "agent";
  if (finding.observation_id !== null) return "observation";
  if (CONNECTION_RULES.has(finding.rule_version)) return "connection";
  if (finding.rule_version === "source-health.v1") return "source";
  return finding.connection_id !== null ? "connection" : "source";
}

const SENTENCES: Record<Subject, string> = {
  observation:
    "This is a finding about source-reported activity. ExecBound did not block or independently confirm the external action. This rule does not evaluate external approvals.",
  agent:
    "This is a finding about what the directory says this agent can reach. ExecBound did not block anything, and governing the agent adds a governed path beside this one rather than removing it.",
  connection: "This is a finding about collection or reporting health, not about an action.",
  source: "This is a finding about collection or reporting health, not about an action.",
};

/** Where a rule's own sentence says more truly what it is about than its subject's does. */
const RULE_SENTENCES: Record<string, string> = {
  "first-consequential-action.v1":
    "This is a finding about activity the directory recorded for this agent. ExecBound did not block it, and governing the agent adds a governed path beside the one it used rather than removing it.",
  "new-ai-consent.v1":
    "This is a finding about an application the directory says an AI publisher provides. ExecBound did not block anything; whether the consent stays is decided in the directory.",
  "initial-inventory.v1":
    "This is a summary of what the first collection found. It is not about one action or agent, and later findings report what changes.",
};

/** The one line under a row's title that says what the finding is about, as text. */
function summary(finding: MonitorFinding, subject: Subject): string {
  switch (subject) {
    case "agent":
      return `Agent: ${finding.agent?.display_name ?? "not listed any more"}`;
    case "connection":
      return `Connection: ${finding.connection_label ?? "not shown"}`;
    case "source":
      return `Source: ${finding.source_label ?? "not shown"}`;
    case "observation":
      return `Story ${finding.story_id ?? "not reported"} / ${finding.action ?? "Heartbeat"}`;
  }
}

function Subjects({ finding, subject }: { finding: MonitorFinding; subject: Subject }): ReactNode {
  switch (subject) {
    case "agent":
      return (
        <>
          <Definition term="Agent">
            {finding.agent !== null ? (
              <Link to="/monitor/agents/$agentId" params={{ agentId: finding.agent.agent_id }}>
                {finding.agent.display_name}
              </Link>
            ) : (
              "Not listed by the directory any more"
            )}
          </Definition>
          <Definition term="Owner">{finding.agent !== null ? accountable(finding.agent) : "Not read"}</Definition>
        </>
      );
    case "connection":
      return (
        <>
          <Definition term="Connection">{finding.connection_label ?? "Not shown"}</Definition>
          {finding.rule_version === GAP_RULE ? (
            <Definition term="Stories with a gap">
              <Link to="/monitor" search={{ view: "inventory" }}>
                Inventory
              </Link>
            </Definition>
          ) : null}
        </>
      );
    case "source":
      return <Definition term="Source">{finding.source_label ?? "Not shown"}</Definition>;
    case "observation":
      return (
        <>
          <Definition term="Story / reported action">
            <span className="mono">{finding.story_id ?? "Not reported"}</span> / {finding.action ?? "Heartbeat"}
          </Definition>
          <Definition term="Target reference" mono>
            {finding.target_ref ?? "Unavailable"}
          </Definition>
          <Definition term="Reported outcome">{finding.outcome ?? "Not applicable"}</Definition>
        </>
      );
  }
}

/**
 * One finding as a compact row: its title, what it is about, when it was recorded and its state,
 * with a disclosure that reveals the rest in place, so the expanded finding stays in the list's
 * reading order. Every label, name and reference renders as text.
 */
export function FindingRow({
  finding,
  expanded,
  onToggle,
  selected = false,
  onSelect,
  children,
}: {
  finding: MonitorFinding;
  expanded: boolean;
  onToggle: () => void;
  /** Whether an open row is in the bulk selection, and how to change that; a row without `onSelect` offers no checkbox. */
  selected?: boolean;
  onSelect?: (checked: boolean) => void;
  /** What the open row offers below its facts: the acknowledgement, or who made it. */
  children?: ReactNode;
}) {
  const subject = subjectOf(finding);
  const open = finding.acknowledged_at === null;
  const body = `finding-${finding.finding_id}`;
  return (
    <li className="finding-row" data-finding={expanded ? "open" : undefined}>
      <div className={onSelect !== undefined && open ? "finding-head finding-head-select" : "finding-head"}>
        {onSelect !== undefined && open ? (
          <label className="finding-select">
            <input
              type="checkbox"
              checked={selected}
              onChange={(event) => {
                onSelect(event.target.checked);
              }}
            />
            <span className="sr-only">Select {finding.title}</span>
          </label>
        ) : null}
        <div className="finding-title">
          <strong>{finding.title}</strong>
          <small>{summary(finding, subject)}</small>
        </div>
        <div className="finding-meta">
          <Time at={finding.created_at} />
          <Badge tone={open ? "hold" : "stale"}>{open ? "Open" : "Acknowledged"}</Badge>
          {finding.synthetic ? <Badge tone="accent">Synthetic directory</Badge> : null}
        </div>
        <Button className="finding-toggle" aria-expanded={expanded} aria-controls={body} onClick={onToggle}>
          {expanded ? "Hide details" : "Show details"}
        </Button>
      </div>
      {expanded ? (
        <div id={body} className="finding-body">
          <Definitions aria-label={`Finding ${finding.title}`}>
            <Definition term="Rule" mono>
              {finding.rule_version}
              {finding.profile_version !== null ? ` (profile version ${String(finding.profile_version)})` : ""}
            </Definition>
            <Subjects finding={finding} subject={subject} />
            {finding.observation_id !== null ? (
              <Definition term="Observation" mono>
                {prefix(finding.observation_id)}
              </Definition>
            ) : null}
          </Definitions>
          <p className="muted">{RULE_SENTENCES[finding.rule_version] ?? SENTENCES[subject]}</p>
          {children}
        </div>
      ) : (
        <div id={body} hidden />
      )}
    </li>
  );
}
