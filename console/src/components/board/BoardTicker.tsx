// SPDX-License-Identifier: AGPL-3.0-only
// The last twenty events as sentences, beneath the board (#280). Identifiers,
// labels and state words only: no name, no email, no secret, and no reason text from a request.

import { Badge, type Tone } from "../ui/Badge";
import { Link } from "@tanstack/react-router";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import type { BoardShot, BoardView } from "../../api/types.gen";
import { periodLabel } from "./search";
import { reasonSentence } from "../../lib/decision-presentation";
import { useServerNow } from "../../lib/clock";
import { Deadline, Time } from "../ui/Time";

const ACTIONS: Record<string, string> = {
  "endpoint.isolate": "Isolate endpoint", "endpoint.lift_isolation": "Lift isolation",
  "identity.disable": "Disable identity", "identity.enable": "Enable identity",
  "identity.revoke_sessions": "Revoke sessions", "identity.reset_password": "Reset password",
};
const OUTCOMES: Record<string, string> = {
  "shot-in": "Decision in progress.", "shot-out": "Allowed; awaiting dispatch.",
  land: "Execution confirmed.", deny: "Blocked before execution.",
  hold: "Waiting for a reviewer's decision.", unsettled: "Outcome is not yet confirmed. Inspect the request before retrying.",
  hollow: "Inspect the request for the recorded outcome.", observe: "Observed only; ExecBound did not dispatch this request.",
  short: "Rejected before a plan could be prepared.",
};

/**
 * Why a request was refused before any plan was frozen, from the code the audit recorded for
 * it (#545). The decision record's sentences describe a frozen plan, which a refusal never had,
 * so these are its own; a code with no sentence here reads as the phase's generic outcome.
 */
const REFUSALS: Record<string, string> = {
  INVALID_OPERATION: "The action named is not one this space offers.",
  // Never answered to the agent, which is told only that execution is unavailable (T1.17).
  // Admission records it for another space's account, and for an agent in more groups than a
  // decision reads.
  INVALID_CONFIGURATION: "The action's provider account belongs to another space, or the agent belongs to too many groups.",
  // A stale policy reference (answered as unavailable), a checkpoint mapping on a connected
  // account, a key ring that cannot attest a grant, or a selected policy that is not active
  // (each answered 409): the sentence is true of every one.
  INVALID_BUNDLE: "The policy the agent's space selects cannot authorize this action as the workspace is configured.",
  INVALID_TARGET: "The target named could not be found.",
  INVALID_CONTEXT: "The target's trusted context was missing, did not match the claimed incident, or was no longer fresh.",
  INVALID_ARGUMENTS: "The arguments are not ones the action accepts.",
  INVALID_RUN: "The run the request named was unknown or had ended.",
  STALE_AUTHORIZATION: "The target's trusted context changed while the request was being admitted.",
  DEPENDENCY_UNAVAILABLE: "Something the request needed could not be reached.",
  DEPENDENCY_OR_CONTEXT_UNAVAILABLE: "A dependency or the trusted context was unavailable; the record does not say which.",
};

/** What an approval that ran out did, keyed by the server's word for it (#678). */
const RAN_OUT: Record<string, string> = {
  lapsed: "Lapsed before a decision; nothing ran.",
  unused: "Approved, not used before the deadline; nothing ran.",
};

function outcome(shot: BoardShot): string {
  const ranOut = RAN_OUT[shot.word];
  if (shot.phase === "hollow" && ranOut !== undefined) return ranOut;
  if (shot.phase === "short") return REFUSALS[shot.detail] ?? "Rejected before a plan could be prepared.";
  // The server's word, read by the rule a denied agent's category is read by: a policy denial
  // records its codes as a list, so no single recorded reason names the limit.
  if (shot.word === "limit") return "An impact limit blocked this request.";
  if (/^[A-Z][A-Z_]+$/.test(shot.detail)) return reasonSentence({ code: shot.detail, sentence: "", rule_id: null });
  return shot.detail !== "" ? shot.detail : OUTCOMES[shot.phase] ?? "Open the request for its recorded outcome.";
}

/** Colour is reserved for decisions, so a phase maps to the decision it represents and no more. */
const TONES: Record<string, Tone> = {
  "shot-in": "stale",
  short: "deny",
  deny: "deny",
  hold: "hold",
  "shot-out": "allow",
  land: "allow",
  unsettled: "hold",
  hollow: "stale",
  observe: "obs",
};

export function tone(phase: string): Tone {
  return TONES[phase] ?? "stale";
}

/** A shot with no word yet is a request in flight, which is a state and deserves its own word. */
export function word(shot: BoardShot): string {
  if (shot.lapsed === true) return "lapsed";
  if (shot.unused === true) return "not used";
  if (shot.phase === "hollow") return "closed";
  return shot.word === "" ? "in flight" : shot.word;
}

/** A shot's agent as its lane names it: the name, and the handle beside a label (#678). */
export function agentName(shot: BoardShot, view: BoardView): { name: string; handle: string | null } {
  const lane = view.agents.find((entry) => entry.index === shot.agent);
  return lane === undefined ? { name: "—", handle: null } : { name: lane.label, handle: lane.handle };
}

function AgentCell({ shot, view }: { shot: BoardShot; view: BoardView }) {
  const agent = agentName(shot, view);
  return (
    <>
      {agent.name}
      {agent.handle !== null ? (
        <>
          {" "}
          <span className="faint">{agent.handle}</span>
        </>
      ) : null}
    </>
  );
}

/** A held request's deadline, against the server's clock, ticking while the ticker is shown. */
function ShotDeadline({ at }: { at: string }) {
  return <Deadline at={at} now={useServerNow()} />;
}

export function BoardTicker({ view }: { view: BoardView }) {
  if (view.ticker.length === 0) {
    return <EmptyState title={`No requests in the ${periodLabel(view.window_seconds).toLowerCase()}.`} />;
  }
  return (
    <Table caption="The most recent requests in the window, newest first, as sentences." density="compact">
      <thead>
        <tr>
          <Th>Agent</Th>
          <Th>Action / target</Th>
          <Th>Requested</Th>
          <Th>State</Th>
          <Th>Outcome</Th>
          <Th>Request</Th>
        </tr>
      </thead>
      <tbody>
        {view.ticker.map((shot, index) => (
          <tr key={shot.execution_id ?? `s${String(index)}`}>
            <Td>
              <AgentCell shot={shot} view={view} />
            </Td>
            <Td>{shot.action ? ACTIONS[shot.action] ?? shot.action : shot.phase === "short" ? "Request rejected" : "Action unavailable"}<br /><span className="faint">{shot.target_label ?? "Target not resolved"}</span></Td>
            <Td>{shot.requested_at ? <Time at={shot.requested_at} /> : "Time unavailable"}</Td>
            <Td>
              <Badge tone={tone(shot.phase)}>{word(shot)}</Badge>
            </Td>
            <Td>
              {shot.expires_at && (shot.lapsed === true || shot.unused === true) ? (
                // An approval that ran out, at the instant the server says it did.
                <>
                  {outcome(shot)}
                  <br />
                  {shot.lapsed === true ? "Lapsed at " : "Not used by "}
                  <Time at={shot.expires_at} precision="second" />
                </>
              ) : shot.expires_at ? (
                // A held shot's deadline, in the viewer's zone; the server's "answer by … UTC"
                // detail is for the server-rendered page and is not repeated here.
                <>
                  {OUTCOMES.hold}
                  <br />
                  <ShotDeadline at={shot.expires_at} />
                </>
              ) : (
                <>
                  {outcome(shot)}
                  {shot.detail && <details><summary>Recorded detail</summary><code>{shot.detail}</code></details>}
                </>
              )}
            </Td>
            <Td>
              {shot.execution_id !== null ? (
                <Link to="/activity" search={{ open: shot.execution_id }} aria-label={`Open request ${shot.execution_id}`}>
                  Open request
                </Link>
              ) : "—"}
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
