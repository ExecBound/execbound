// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import { prefix } from "../../lib/when";

/**
 * One identifier an answer rests on (#330).
 *
 * The server keeps a paragraph's ids only where a tool returned that id in the same turn, so
 * an identifier the model invented never reaches this component: it stays in the paragraph's
 * text as text. What the server does not say is what **kind** of record an id names, and a
 * UUID's shape says nothing, so a chip is a link in exactly one case — the turn's own context,
 * whose kind the turn states — and inert text otherwise. Guessing would be worse than a chip
 * that does not link: a citation that opens the wrong record is a lie with a href on it.
 */
export function Citation({
  id,
  kind,
}: {
  id: string;
  /** The turn's context kind, when this id is the turn's own context id. */
  kind?: string;
}) {
  const inner = (
    <>
      <span className="cite-kind">{WORDS[kind ?? ""] ?? "Reference"}</span>
      <span className="mono">{prefix(id)}</span>
    </>
  );
  switch (kind) {
    case "execution":
      return (
        <Link to="/activity" search={{ open: id }} className="cite">
          {inner}
        </Link>
      );
    case "approval":
      return (
        <Link to="/approvals/$approvalId" params={{ approvalId: id }} className="cite">
          {inner}
        </Link>
      );
    case "agent":
      return (
        <Link to="/agents/$agentId" params={{ agentId: id }} className="cite">
          {inner}
        </Link>
      );
    case "finding":
      return (
        <Link to="/monitor" search={{ view: "findings", state: "all", open: id }} className="cite">
          {inner}
        </Link>
      );
    default:
      return <span className="cite cite-inert">{inner}</span>;
  }
}

const WORDS: Record<string, string> = {
  execution: "Decision",
  approval: "Approval",
  agent: "Agent",
  finding: "Finding",
  policy_change: "Policy",
};
