// SPDX-License-Identifier: AGPL-3.0-only
// The board itself: agents on the left, the checkpoint in the middle, targets on the right, and
// every shot a row the tenant already holds (#280). Lanes are horizontal, so every
// motion is a horizontal translation with fixed keyframes and a lane's position is a `transform`
// attribute, never a rule that has to know where a lane sits.
//
// Nothing an agent or a provider supplied becomes a class, an id or a URL: a lane's identity on
// this picture is the integer the server assigned it, and its label is text.

import type { BoardShot, BoardView } from "../../api/types.gen";
import {
  AGENT_X,
  CHECKPOINT_X,
  TARGET_X,
  WIDTH,
  delay,
  figureLabel,
  height,
  laneY,
  rows,
  shotRow,
  targetRow,
} from "./geometry";
// The board's rules load with the board, not with every page: a top-level stylesheet import in a
// route file stays with the route tree in the first chunk, which an approval link loads too.
import "./board.css";

export function BoardFigure({ view }: { view: BoardView }) {
  const tall = height(view);
  const rowCount = rows(view);
  return (
    <svg viewBox={`0 0 ${String(WIDTH)} ${String(tall)}`} role="img" aria-label={figureLabel(view)}>
      <g className="lanes">
        {view.agents.map((lane) => (
          <g key={`a${String(lane.index)}`} transform={`translate(0 ${String(laneY(lane.index))})`}>
            {lane.handle !== null ? (
              // A label an administrator wrote, with the handle beneath it, so two agents
              // labelled alike stay apart (#678).
              <>
                <title>{`${lane.label} · ${lane.handle}`}</title>
                <text className="lane-label" x={8} y={-4}>
                  {lane.label}
                </text>
                <text className="lane-group" x={8} y={10}>
                  {lane.handle}
                </text>
              </>
            ) : (
              <text className="lane-label" x={8} y={4}>
                {lane.label}
              </text>
            )}
            <line className="lane-rule" x1={AGENT_X} x2={CHECKPOINT_X - 2} y1={0} y2={0} />
          </g>
        ))}
        {view.more_agents > 0 ? (
          <g transform={`translate(0 ${String(laneY(view.agents.length))})`}>
            <text className="lane-label" x={8} y={4}>
              {view.more_agents} more {view.more_agents === 1 ? "agent" : "agents"}
            </text>
          </g>
        ) : null}
        {view.targets.map((lane, position) => (
          <g key={`t${String(lane.index)}`} transform={`translate(0 ${String(laneY(position))})`}>
            <line className="lane-rule" x1={CHECKPOINT_X + 122} x2={WIDTH - 10} y1={0} y2={0} />
            <text className="lane-label" x={TARGET_X} y={-4}>
              {lane.label}
            </text>
            <text className="lane-group" x={TARGET_X} y={10}>
              {lane.group}
            </text>
          </g>
        ))}
        {view.more_targets > 0 ? (
          <g transform={`translate(0 ${String(laneY(view.targets.length))})`}>
            <text className="lane-label" x={TARGET_X} y={4}>
              {view.more_targets} more {view.more_targets === 1 ? "target" : "targets"}
            </text>
          </g>
        ) : null}
      </g>
      <g className="checkpoint">
        <line
          className="checkpoint-rule"
          x1={CHECKPOINT_X}
          x2={CHECKPOINT_X}
          y1={TOP_RULE}
          y2={tall - 16}
        />
        <text className="checkpoint-word" x={CHECKPOINT_X} y={TOP_WORD}>
          checkpoint
        </text>
      </g>
      <g className="shots">
        {view.shots.map((shot, index) => (
          <Shot key={shot.execution_id ?? `s${String(index)}`} shot={shot} view={view} />
        ))}
      </g>
      {view.watching ? (
        // Seen by monitoring, not governed: these pass *under* the checkpoint, because that is
        // exactly what they did. A finding marks its shot.
        <g className="band" transform={`translate(0 ${String(laneY(rowCount) + 8)})`}>
          <line className="band-rule" x1={8} x2={WIDTH - 10} y1={0} y2={0} />
          <text className="band-label" x={8} y={16}>
            Seen by monitoring, not governed
          </text>
          {view.observations.map((seen, index) => (
            <g key={`o${String(index)}`} transform={`translate(${String(AGENT_X)} 0)`}>
              <circle
                className={seen.flagged ? "seen flagged" : "seen"}
                style={{ animationDelay: delay(seen.age) }}
                r={4}
                cx={0}
                cy={0}
              />
            </g>
          ))}
        </g>
      ) : null}
    </svg>
  );
}

const TOP_RULE = 16;
const TOP_WORD = 8;

function Shot({ shot, view }: { shot: BoardShot; view: BoardView }) {
  const style = { animationDelay: delay(shot.age) };
  const landed = targetRow(shot, view);
  return (
    <>
      <g transform={`translate(${String(AGENT_X)} ${String(laneY(shotRow(shot, view)))})`}>
        <circle
          className={`shot ${shot.phase}`}
          style={style}
          r={shot.agent >= 0 ? 5 : 4}
          cx={0}
          cy={0}
        />
      </g>
      {landed >= 0 ? (
        <g transform={`translate(${String(CHECKPOINT_X)} ${String(laneY(landed))})`}>
          <circle className={`shot ${shot.phase}`} style={style} r={5} cx={0} cy={0} />
        </g>
      ) : null}
    </>
  );
}
