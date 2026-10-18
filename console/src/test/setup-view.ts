// SPDX-License-Identifier: AGPL-3.0-only
// A Space's setup read (`GET /setup`, #678) as a test names it: every step to do unless the test
// says otherwise, with the record each done step carries.

import type { SetupMilestone, SetupView } from "../api/types.gen";

export const SETUP = "/api/console/v1/setup";
export const SPACE = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const AGENT = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
export const EXECUTION = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
export const DECIDED = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
export const POLICY = "ffffffff-ffff-4fff-8fff-ffffffffffff";
export const AT = "2026-10-08T09:30:00+00:00";

type Key = SetupMilestone["key"];
type State = SetupMilestone["state"];

const KEYS: readonly Key[] = ["policy", "agent_key", "first_request", "reviewer", "first_decision"];

const RECORDS: Record<Key, SetupMilestone["record"]> = {
  policy: { kind: "bundle", id: POLICY, request_ref: null },
  agent_key: { kind: "agent", id: AGENT, request_ref: null },
  first_request: { kind: "execution", id: EXECUTION, request_ref: "EB-12" },
  reviewer: { kind: "approver", id: AGENT, request_ref: null },
  first_decision: { kind: "execution", id: DECIDED, request_ref: "EB-14" },
};

/** A ready read; each named key takes its state, a done one its record and time. */
export function setupView(states: Partial<Record<Key, State>> = {}, changes: Partial<SetupView> = {}): SetupView {
  const milestones = KEYS.map((key): SetupMilestone => {
    const state = states[key] ?? "todo";
    const done = state === "done";
    return { key, state, at: done && key !== "reviewer" ? AT : null, record: done ? RECORDS[key] : null };
  });
  return {
    state: "ready",
    space_id: SPACE,
    connected: true,
    samples_here: true,
    default_space_id: SPACE,
    milestones,
    done: milestones.filter((item) => item.state === "done").length,
    required: milestones.filter((item) => item.state !== "not_applicable").length,
    next: milestones.find((item) => item.state === "todo")?.key ?? null,
    observed: null,
    ...changes,
  };
}

export const CHOOSE_SPACE: SetupView = {
  state: "choose_space",
  space_id: null,
  connected: false,
  samples_here: false,
  default_space_id: SPACE,
  milestones: [],
  done: 0,
  required: 0,
  next: null,
  observed: null,
};
