// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { readAssistantTurnOptions } from "../../api/@tanstack/react-query.gen";
import { useAssistant } from "../../lib/assistant";
import { copyFor } from "../../lib/refusal";
import { ASSISTANT_FIELDS, useAsk, useOpened } from "./ask";
import type { ExplainProps } from "./Explain";
import { Turn } from "./Turn";

/** The panel `Explain` loads only where the deployment has an assistant (see Explain.tsx). */
export default function Panel({ kind, id, what, question }: ExplainProps) {
  const assistant = useAssistant();
  const [open, setOpen] = useState(false);
  const [turnId, setTurnId] = useState<string | undefined>(undefined);
  const ask = useAsk((turn) => {
    setTurnId(turn.turn_id);
  });
  const opened = useOpened();
  const recorded = useRef<string | undefined>(undefined);
  const query = useQuery({
    ...readAssistantTurnOptions({ path: { turn_id: turnId ?? "" } }),
    enabled: turnId !== undefined,
  });

  useEffect(() => {
    if (turnId === undefined || recorded.current === turnId) return;
    recorded.current = turnId;
    opened.mutate({ path: { turn_id: turnId }, body: {} });
    // `opened` is a stable mutation object from the query client; the turn id is what changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [turnId]);

  if (!assistant.enabled) return null;

  return (
    <section className="assistant-explain" aria-label={`Explanation of ${what}`}>
      <button
        type="button"
        className="assistant-explain-toggle"
        aria-expanded={open}
        disabled={ask.isPending}
        onClick={() => {
          const next = !open;
          setOpen(next);
          if (next && turnId === undefined && !ask.isPending) {
            ask.mutate({
              body:
                question === undefined
                  ? { context_kind: kind, context_id: id }
                  : { context_kind: kind, context_id: id, question },
            });
          }
        }}
      >
        {ask.isPending ? "Explaining…" : open ? `Hide the explanation of ${what}` : `Explain ${what}`}
      </button>
      {open ? (
        <div className="assistant-explain-body">
          {ask.isError ? (
            <p className="fault" role="alert">
              {copyFor(ask.error, ASSISTANT_FIELDS)}
            </p>
          ) : query.data !== undefined ? (
            <Turn turn={query.data} />
          ) : (
            <p className="muted" role="status">
              Reading this tenant&apos;s records…
            </p>
          )}
        </div>
      ) : null}
    </section>
  );
}
