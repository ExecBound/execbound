// SPDX-License-Identifier: AGPL-3.0-only
// A running turn, watched over server-sent events (#330). The server holds no channel: it
// reads the turn row and sends a `step` event per step the row gained and a `done` event
// carrying what the client needs to render the end of the turn without a second request. This
// hook writes both into the query cache, so the page has one source of truth and a reader who
// arrives late, reloads, or comes back to the tab sees the same thing.
//
// Two deliberate choices. The stream is opened only while the turn is RUNNING, so a finished
// turn costs nothing and a reader on a phone is not holding a connection open for a page that
// will never change. And nothing here trusts the frames: a payload that is not the shape
// expected is dropped, because it would otherwise be a string from the network deciding what
// the page renders.

import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";

import { readAssistantTurnQueryKey } from "../../api/@tanstack/react-query.gen";
import type { TurnView } from "../../api/types.gen";

/** What `done` carries: enough of the turn to render its end, not the whole row. */
interface Done {
  state: string;
  reason: string | null;
  paragraphs: TurnView["paragraphs"];
  cannot_answer: boolean;
  cited_ids: string[];
}

function parsed(data: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(data);
    return typeof value === "object" && value !== null
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function stepOf(data: string): { index: number; text: string } | undefined {
  const body = parsed(data);
  if (body === undefined) return undefined;
  const { index, text } = body;
  return typeof index === "number" && typeof text === "string" ? { index, text } : undefined;
}

function doneOf(data: string): Done | undefined {
  const body = parsed(data);
  if (body === undefined || typeof body.state !== "string") return undefined;
  return {
    state: body.state,
    reason: typeof body.reason === "string" ? body.reason : null,
    paragraphs: Array.isArray(body.paragraphs) ? (body.paragraphs as TurnView["paragraphs"]) : [],
    cannot_answer: body.cannot_answer === true,
    cited_ids: Array.isArray(body.cited_ids) ? (body.cited_ids as string[]) : [],
  };
}

/** Watch one turn while it runs, writing what the row gains into the query cache. */
export function useTurnStream(turnId: string, state: string | undefined): void {
  const queryClient = useQueryClient();
  const running = state === "RUNNING";

  useEffect(() => {
    if (!running) return;
    const key = readAssistantTurnQueryKey({ path: { turn_id: turnId } });
    const source = new EventSource(`/api/console/v1/assistant/turns/${turnId}/events`);
    let ended = false;

    const write = (change: (turn: TurnView) => TurnView) => {
      queryClient.setQueryData<TurnView>(key, (current) =>
        current === undefined ? current : change(current),
      );
    };
    // `MessageEvent.data` is typed `any`; it is a string from the network and is treated as
    // one, parsed defensively, and never used for anything but text the page renders.
    const dataOf = (event: Event): string =>
      event instanceof MessageEvent && typeof event.data === "string" ? event.data : "";

    source.addEventListener("step", (event) => {
      const step = stepOf(dataOf(event));
      if (step === undefined) return;
      write((turn) =>
        turn.steps.length > step.index ? turn : { ...turn, steps: [...turn.steps, step.text] },
      );
    });
    source.addEventListener("done", (event) => {
      ended = true;
      const end = doneOf(dataOf(event));
      if (end === undefined) void queryClient.invalidateQueries({ queryKey: key });
      else write((turn) => ({ ...turn, ...end }));
      source.close();
    });
    source.onerror = () => {
      // The connection dropped rather than ended. EventSource reconnects on its own, and the
      // server tells a reconnecting reader every step again, so the only thing to do here is
      // stop reconnecting once the turn is over.
      if (ended) source.close();
    };

    return () => {
      source.close();
    };
  }, [queryClient, running, turnId]);
}
