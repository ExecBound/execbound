// SPDX-License-Identifier: AGPL-3.0-only
// The External activity view (#355): a directory's audit-log observation names its actor and its
// target by object id alone, and a collected record that names no target says nothing about one.

import { cleanup, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import type { MonitorSnapshot } from "../../api/types.gen";
import { snapshot } from "../../test/monitor-data";
import { renderPage } from "../../test/page";
import { Activity } from "./Activity";

const ACTOR = "aaaaaaaa-0000-4000-8000-000000000009";
const TARGET = "d0d0d0d0-0000-4000-8000-000000000001";

type Observation = MonitorSnapshot["observations"][number];

function observation(changes: Partial<Observation>): Observation {
  return {
    observation_id: "0b0b0b0b-0000-4000-8000-000000000009",
    occurred_at: "2026-10-16T05:00:00+00:00",
    received_at: "2026-10-16T05:05:00+00:00",
    kind: "entra_audit",
    story_id: null,
    action: "identity.disable",
    evidence: "collected",
    operation_name: "entra-audit.v1:disable_account",
    actor_ref: ACTOR,
    target_ref: TARGET,
    outcome: "success",
    evaluation_state: "COMPLETED",
    evaluation_result: "MATCH",
    integrity_conflict_at: null,
    finding_ids: [],
    ...changes,
  };
}

afterEach(cleanup);

describe("the External activity view", () => {
  it("names a directory audit observation's actor and target by object id", async () => {
    renderPage(<Activity data={snapshot({ observations: [observation({})] })} />);
    const table = await screen.findByRole("table", { name: /Recent observations/ });
    expect(within(table).getByText(/entra-audit\.v1:disable_account by actor/)).toHaveTextContent(
      `entra-audit.v1:disable_account by actor ${ACTOR} on ${TARGET}`,
    );
  });

  it("says nothing about a target a collected record does not name", async () => {
    renderPage(
      <Activity
        data={snapshot({
          observations: [observation({ kind: "ai_tool_run", operation_name: "AiToolRun", target_ref: null })],
        })}
      />,
    );
    const table = await screen.findByRole("table", { name: /Recent observations/ });
    expect(within(table).getByText(/AiToolRun by actor/)).toHaveTextContent(`AiToolRun by actor ${ACTOR}`);
    expect(within(table).queryByText(/ on /)).toBeNull();
  });
});
