// SPDX-License-Identifier: AGPL-3.0-only
// The board's live connection: one EventSource, opened while the board is live and the tab is
// looked at, and closed otherwise (#333, #280). The stream replaced the five-second poll the
// board started with.
//
// Three things decide whether it is open, and they are all the viewer's: the board is not paused,
// the document is visible, and the session is still there. A hidden tab holds no connection and
// makes no request, which is the wall-display case the size budget cares about; a paused board
// holds none either, because Pause means "stop", not "stop drawing".
//
// EventSource rather than the generated client's own SSE helper: the browser reconnects on its
// own, honouring the `retry` the server sends, which is exactly what a display left on a wall for
// a week needs and what a hand-written reader would have to reimplement. The address is a
// constant in this file and never built from anything a request carried.

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { readBoardOptions } from "../../api/@tanstack/react-query.gen";
import type { BoardView } from "../../api/types.gen";
import { signInAgain } from "../../lib/client-config";
import { useTimeZone, utcOffsetMinutes } from "../../lib/time";
import { subscribeWorkspace, workspaceGeneration, workspaceStale } from "../../lib/workspace-context";

export const STREAM = "/api/console/v1/board/stream";

/**
 * The live board's read, keyed by the viewer's offset so "today" starts at their midnight. The
 * page reads it and the stream writes every frame to the same entry: one helper builds both, so
 * the two cannot drift into different keys and leave the page on its first fetch.
 */
export function liveBoardOptions(offset: number) {
  return readBoardOptions({ query: { utc_offset: String(offset) } });
}

/** The stream's address: a constant path with the workspace generation and the viewer's offset. */
export function streamUrl(generation: string, offset: number): string {
  const query = new URLSearchParams();
  if (generation !== "") query.set("generation", generation);
  query.set("utc_offset", String(offset));
  return `${STREAM}?${query.toString()}`;
}

type Connection = "connecting" | "live" | "closed";
export type StreamState = Connection | "paused" | "hidden";

/** Whether the tab is being looked at; `document.hidden` and nothing cleverer. */
function useVisible(): boolean {
  const [visible, setVisible] = useState(() => !document.hidden);
  useEffect(() => {
    const onChange = () => {
      setVisible(!document.hidden);
    };
    document.addEventListener("visibilitychange", onChange);
    return () => {
      document.removeEventListener("visibilitychange", onChange);
    };
  }, []);
  return visible;
}

/**
 * Keep the board query's data current from the stream, and say what the connection is doing.
 *
 * Every frame replaces the whole snapshot, so there is nothing to merge and a client that missed
 * a frame is correct at the next one. The data lands in the query cache rather than in state of
 * its own, so the page reads one value whether it came from the first fetch or from the stream.
 */
export function useBoardStream(live: boolean): StreamState {
  const client = useQueryClient();
  const visible = useVisible();
  // Only what the connection itself reports lives in state; paused and hidden are facts about
  // the page and the tab, so they are derived rather than stored, and no effect sets state
  // synchronously to say something its own inputs already say.
  const [connection, setConnection] = useState<Connection>("connecting");
  const [choice] = useTimeZone();
  const offset = utcOffsetMinutes(choice);

  useEffect(() => {
    if (!live || !visible || workspaceStale()) return undefined;
    const source = new EventSource(streamUrl(workspaceGeneration(), offset));
    const unsubscribe = subscribeWorkspace(() => { if (workspaceStale()) source.close(); });
    const key = liveBoardOptions(offset).queryKey;
    source.addEventListener("board", (event: MessageEvent<string>) => {
      if (workspaceStale()) return;
      setConnection("live");
      client.setQueryData<BoardView>(key, JSON.parse(event.data) as BoardView);
    });
    source.addEventListener("closed", () => {
      // The session ended, the credential was revoked or the role changed. Reconnecting would
      // only be refused, so the connection is closed here and the person is sent to sign in,
      // which is what a 401 on any other route already does.
      source.close();
      setConnection("closed");
      signInAgain();
    });
    source.addEventListener("error", () => {
      // A dropped connection, not a refusal: the browser reopens it after the retry the server
      // named, and the next frame is a whole snapshot, so nothing needs catching up.
      setConnection("connecting");
    });
    return () => {
      unsubscribe();
      source.close();
      setConnection("connecting");
    };
  }, [client, live, visible, offset]);

  if (!live) return "paused";
  if (!visible) return "hidden";
  return connection;
}

/** What the connection is doing, in the words the page says it in. */
export function streamWords(state: StreamState): string {
  switch (state) {
    case "live":
      return "Live. The board updates itself as requests arrive.";
    case "connecting":
      return "Connecting to the live stream.";
    case "paused":
      return "Paused; nothing moves and nothing is requested.";
    case "hidden":
      return "Not in view; nothing is requested until you come back.";
    case "closed":
      return "The session ended.";
  }
}
