// SPDX-License-Identifier: AGPL-3.0-only
// Where every mark on the board sits, and nothing else. Pure arithmetic over the snapshot the
// server sent, so the caps, the row count and the overflow rows are testable without a browser
// and the figure component is left drawing what it is handed (#280).
//
// The numbers are the server-rendered board's, unchanged: lanes are horizontal, so every motion
// is a horizontal translation, an agent lane starts at 160 and the checkpoint stands at 500.
// Keeping them means the two boards are the same picture rather than two drawings of one idea.

import type { BoardShot, BoardView } from "../../api/types.gen";
import { periodLabel } from "./search";

export const PITCH = 26;
export const TOP = 40;
export const WIDTH = 1000;
export const AGENT_X = 160;
export const CHECKPOINT_X = 500;
export const TARGET_X = 640;
export const BAND_HEIGHT = 28;

/** How many lane rows the picture needs, counting the overflow rows and the rejection lane. */
export function rows(view: BoardView): number {
  const agents = view.agents.length + (view.more_agents > 0 ? 1 : 0) + 1;
  const targets = view.targets.length + (view.more_targets > 0 ? 1 : 0);
  return Math.max(agents, targets);
}

export function height(view: BoardView): number {
  return TOP + rows(view) * PITCH + 24 + (view.watching ? BAND_HEIGHT : 0);
}

/** The y of one lane row, by its position in its own column. */
export function laneY(index: number): number {
  return TOP + index * PITCH;
}

/**
 * The delay that anchors a shot on its own event time.
 *
 * The server-rendered board spends 151 generated CSS classes on this, because a policy that
 * forbids inline style leaves a template no other way to say "this one started 4.2 seconds ago".
 * React applies a style prop through the CSSOM, which `style-src 'self'` does not govern
 * (#333), so here the delay is simply the number, exact rather than quantised, and the
 * generated class block is not needed at all. `tests/test_browser_console.py` collects
 * `securitypolicyviolation` events on every route, so this claim is checked by a browser.
 */
export function delay(ageTenths: number): string {
  return `-${(ageTenths / 10).toFixed(1)}s`;
}

/** A shot's row in the agent column; a request refused before a decision has a lane of its own. */
export function shotRow(shot: BoardShot, view: BoardView): number {
  return shot.agent >= 0 ? shot.agent : view.agents.length;
}

/**
 * The row a shot lands on, or -1 when it never crossed the checkpoint.
 *
 * A target lane's `index` is the order the server first saw it; the column is drawn sorted by
 * group and label, so the row a lane occupies is its position in that sorted list and not its
 * index. The server-rendered board draws its labels at the sorted position and its shots at the
 * index, which puts a shot on the wrong line whenever the two orders differ; this resolves the
 * shot the same way the label is resolved, so the mark and the name are always on one row.
 */
export function targetRow(shot: BoardShot, view: BoardView): number {
  if (shot.target === null) return -1;
  return view.targets.findIndex((lane) => lane.index === shot.target);
}

/**
 * The sentence the picture is labelled with, so the board is not only drawn.
 *
 * An `img` needs one accessible name, and "a diagram" is not one. This says what the board
 * currently shows, in the words the board itself uses, which is also what a reader with reduced
 * motion or a screen reader gets instead of the movement.
 */
export function figureLabel(view: BoardView): string {
  const agents = count(view.agents.length + view.more_agents, "agent");
  const targets = count(view.targets.length + view.more_targets, "target");
  const shots = count(view.shots.length, "request");
  return (
    `Requests from agents through the checkpoint toward targets. ` +
    `${shots} in the ${periodLabel(view.window_seconds).toLowerCase()}, from ${agents}, naming ${targets}.`
  );
}

export function count(value: number, noun: string): string {
  return `${String(value)} ${noun}${value === 1 ? "" : "s"}`;
}
