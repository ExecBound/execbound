// SPDX-License-Identifier: AGPL-3.0-only
import type { TurnView } from "../../api/types.gen";
import { REFUSALS } from "../../lib/assistant";
import { Citation } from "./Citation";
import { useTurnStream } from "./useTurnStream";

/**
 * One turn as it happens and as it ended (#330). The same component serves the Ask page's
 * turn view and the Explain panel on a record's page, because they show the same thing.
 *
 * Everything here is text. The server stores an answer as paragraphs of plain text with the
 * identifiers each rests on, and React renders text as text, so there is no Markdown, no link
 * and no markup the model could have written. The only thing that becomes a link is a citation
 * chip, and only for the turn's own context, whose kind the turn states.
 */
export function Turn({ turn, labelled = true }: { turn: TurnView; labelled?: boolean }) {
  useTurnStream(turn.turn_id, turn.state);
  const running = turn.state === "RUNNING";
  const refusal = turn.state === "FAILED" ? (REFUSALS[turn.reason ?? ""] ?? REFUSALS.MODEL_ERROR) : undefined;
  const context = turn.context_id;
  return (
    <div className="turn">
      {labelled ? (
        <p className="turn-label">Generated explanation. The facts above are the record.</p>
      ) : null}
      {turn.steps.length > 0 ? (
        <ol className="turn-steps" aria-label="What the assistant read">
          {turn.steps.map((step, index) => (
            <li key={`${String(index)}:${step}`}>{step}</li>
          ))}
        </ol>
      ) : null}
      {running ? (
        <p className="muted turn-running" role="status">
          Reading this tenant&apos;s records…
        </p>
      ) : null}
      {refusal !== undefined ? (
        <p className="fault" role="status">
          {refusal}
        </p>
      ) : null}
      {turn.cannot_answer && turn.paragraphs.length === 0 ? (
        <p className="muted" role="status">
          The assistant could not answer that from this tenant&apos;s records.
        </p>
      ) : null}
      {turn.paragraphs.map((paragraph, index) => (
        <div className="turn-paragraph" key={`${String(index)}:${paragraph.text.slice(0, 24)}`}>
          <p>{paragraph.text}</p>
          {paragraph.ids.length > 0 ? (
            <ul className="cites" aria-label="What this paragraph rests on">
              {paragraph.ids.map((id) => (
                <li key={id}>
                  <Citation id={id} kind={id === context ? turn.context_kind : undefined} />
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ))}
      {turn.state === "COMPLETED" ? (
        <p className="turn-foot muted">
          It reads what you can read, changes nothing, and never says what to decide.
        </p>
      ) : null}
    </div>
  );
}
