// SPDX-License-Identifier: AGPL-3.0-only
// The live board (#280) in the shell: the full-ink display page, lanes through the checkpoint,
// words for every state, motion keyframed from the server's event times, Pause, and a phone
// layout. The page reads; it changes nothing and decides nothing.
//
// The page reload the server-rendered board uses is replaced by a server-sent events stream on
// the same origin, which `connect-src 'self'` already admits. Pause is still in the URL, so a
// link or the back button restores a stilled board exactly as it did before.

import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { readBoardOptions } from "../api/@tanstack/react-query.gen";
import type { BoardView } from "../api/types.gen";
import { BoardCounters } from "../components/board/BoardCounters";
import { BoardFigure } from "../components/board/BoardFigure";
import { BoardIdle } from "../components/board/BoardIdle";
import { BoardTicker } from "../components/board/BoardTicker";
import { boardSearch, periodLabel } from "../components/board/search";
import { liveBoardOptions, streamWords, useBoardStream } from "../components/board/useBoardStream";
import { count } from "../components/board/geometry";
import { Card } from "../components/ui/Card";
import { PageHeading } from "../components/ui/PageHeading";
import { Chips } from "../components/ui/Chips";
import { Time } from "../components/ui/Time";
import { can, useSession } from "../lib/session";
import { useTimeZone, utcOffsetMinutes } from "../lib/time";

export const Route = createFileRoute("/board")({
  validateSearch: boardSearch,
  component: BoardPage,
});

function Band({ view }: { view: BoardView }) {
  const flagged = view.observations.filter((seen) => seen.flagged).length;
  return (
    <p className="board-note">
      Monitoring reported {count(view.observations.length, "observation")} in the
      {" "}{periodLabel(view.window_seconds).toLowerCase()}
      {flagged > 0 ? `, ${String(flagged)} of them flagged by a rule` : ""}.
      {" "}Source-reported observations do not establish enforced or confirmed execution.
    </p>
  );
}

function BoardPage() {
  const { live, window: windowSize } = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const session = useSession();
  const canReview = can(session, "approvals.decide");
  const historical = windowSize !== undefined;
  const running = !historical && live !== false;
  // No interval of its own: the stream is what keeps this current, and a paused or hidden board
  // holds the last snapshot rather than asking for another one.
  const [choice] = useTimeZone();
  const query = useQuery({
    ...(windowSize === undefined ? liveBoardOptions(utcOffsetMinutes(choice)) : readBoardOptions({ query: { window: windowSize } })),
    refetchInterval: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    staleTime: running ? 5_000 : Infinity,
  });
  const state = useBoardStream(running);
  const view = query.data;

  return (
    <div className={running ? "board-page ink" : "board-page ink board-still"}>
      <PageHeading
        title={historical ? "Historical board" : "Live board"}
        lead="Requests from agents, decisions at the checkpoint, and named targets. Open a request to inspect its evidence."
        actions={
          historical ? (
            <button
              className="btn"
              type="button"
              disabled={query.isFetching}
              onClick={() => { void query.refetch(); }}
            >
              Refresh snapshot
            </button>
          ) : running ? (
            <Link className="btn" to="/board" search={{ live: false }}>
              Pause
            </Link>
          ) : (
            <Link className="btn" to="/board" search={{}}>
              Resume
            </Link>
          )
        }
      />
      <div className="board-window-controls">
        <Chips
          label="Board window"
          chips={[
            { value: "15m", label: "15 minutes · Live" },
            { value: "1h", label: "1 hour · Historical" },
            { value: "24h", label: "24 hours · Historical" },
          ] as const}
          value={windowSize ?? "15m"}
          onChange={(next) => {
            void navigate({ search: next === "15m" ? {} : { window: next, live: false } });
          }}
        />
        <Link to="/activity">Open Activity</Link>
        {canReview ? <Link to="/approvals">Open approvals</Link> : null}
      </div>
      <p className="board-state" role="status">
        {historical ? "Historical snapshot. Motion and live updates are off." : streamWords(state)}
      </p>
      {view === undefined ? (
        <p className="board-note">
          {query.isError
            ? "The board could not be read. Open Activity or refresh to try again."
            : "Reading this window."}
        </p>
      ) : (
        <>
          {!running ? (
            <p className="board-snapshot">
              Snapshot as of <Time at={view.observed_at} precision="second" />.
              {" "}Counts and states are held at that moment.
            </p>
          ) : null}
          <BoardCounters view={view} live={running} />
          {view.shots.length === 0 ? (
            <BoardIdle view={view} canManage={can(session, "access.manage")} canReview={canReview} />
          ) : null}
          {view.shots.length > 0 || view.observations.length > 0 ? (
            <div
              className="board"
              tabIndex={0}
              role="group"
              aria-label="The board, which pans sideways on a narrow screen"
            >
              <BoardFigure view={view} />
            </div>
          ) : null}
          {view.requests_truncated || view.rejections_truncated || view.observations_truncated ? (
            <p className="board-note">
              This window is capped. Window totals cover a sample of {view.window.requests} requests,
              {" "}{view.window.refused ?? 0} pre-decision refusals and {view.observations.length} monitoring observations.
              {" "}Use Activity for the full request history.
            </p>
          ) : null}
          {view.watching ? <Band view={view} /> : null}
          {view.ticker.length > 0 ? (
            <Card
              title={`Recent requests (${String(view.ticker.length)})`}
              aside={<Link className="btn btn-small" to="/activity">Open Activity</Link>}
            >
              <BoardTicker view={view} />
            </Card>
          ) : null}
        </>
      )}
    </div>
  );
}
