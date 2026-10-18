// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { MonitorFinding } from "../../api/types.gen";
import { HEALTH, REACH } from "../../test/monitor-data";
import { FindingRow, subjectOf } from "./FindingRow";

const NEW_ACTOR: MonitorFinding = {
  ...REACH,
  finding_id: "f1f1f1f1-0000-4000-8000-000000000010",
  title: "New service principal reaches a consequential action through a path nothing governs",
  rule_version: "new-actor.v1",
};
const FIRST_ACTION: MonitorFinding = {
  ...REACH,
  finding_id: "f1f1f1f1-0000-4000-8000-000000000011",
  title: "First consequential action outside ExecBound: identity.disable",
  rule_version: "first-consequential-action.v1",
  observation_id: "0b0b0b0b-0000-4000-8000-000000000011",
  action: "identity.disable",
};
const AI_CONSENT: MonitorFinding = {
  ...REACH,
  finding_id: "f1f1f1f1-0000-4000-8000-000000000012",
  title: "New consent to an application from Anthropic",
  rule_version: "new-ai-consent.v1",
};
const NEW_AGENT: MonitorFinding = {
  ...REACH,
  finding_id: "f1f1f1f1-0000-4000-8000-000000000014",
  title: "New agent identity first seen since the last collection",
  rule_version: "new-agent.v1",
};
const INVENTORY: MonitorFinding = {
  ...HEALTH,
  finding_id: "f1f1f1f1-0000-4000-8000-000000000013",
  title: "Initial inventory: 27 actors, 2 with consequential reach",
  rule_version: "initial-inventory.v1",
  connection_label: "Synthetic directory",
};

describe("what a Scout finding is about (#355)", () => {
  it("files the three new actor rules under their agent, listed or not", () => {
    for (const finding of [NEW_ACTOR, FIRST_ACTION, AI_CONSENT]) {
      expect(subjectOf(finding)).toBe("agent");
      // A finding whose agent the directory no longer lists is still about that agent.
      expect(subjectOf({ ...finding, agent: null })).toBe("agent");
    }
  });

  it("files a retained new-agent finding under its agent, listed or not", () => {
    // Raised no more, and read still: without its rule, an agent no longer listed would be filed
    // under its connection.
    expect(subjectOf(NEW_AGENT)).toBe("agent");
    expect(subjectOf({ ...NEW_AGENT, agent: null })).toBe("agent");
    const { getByText } = render(
      <ul>
        <FindingRow finding={{ ...NEW_AGENT, agent: null }} expanded onToggle={() => undefined} />
      </ul>,
    );
    expect(getByText("Agent: not listed any more")).toBeInTheDocument();
  });

  it("files the inventory summary under the connection it names", () => {
    // It carries a connection and nothing else, which is what files a finding there.
    expect(subjectOf(INVENTORY)).toBe("connection");
  });

  it("says what each rule is about, as text", () => {
    const { rerender } = render(
      <ul>
        <FindingRow finding={INVENTORY} expanded onToggle={() => undefined} />
      </ul>,
    );
    expect(screen.getByText("Connection: Synthetic directory")).toBeInTheDocument();
    expect(screen.getByText(/summary of what the first collection found/)).toBeInTheDocument();
    expect(screen.queryByText(/collection or reporting health/)).not.toBeInTheDocument();

    rerender(
      <ul>
        <FindingRow finding={{ ...AI_CONSENT, agent: null }} expanded onToggle={() => undefined} />
      </ul>,
    );
    expect(screen.getByText(/an AI publisher provides/)).toBeInTheDocument();

    rerender(
      <ul>
        <FindingRow finding={{ ...FIRST_ACTION, agent: null }} expanded onToggle={() => undefined} />
      </ul>,
    );
    expect(screen.getByText(/activity the directory recorded/)).toBeInTheDocument();
    expect(screen.getByText("Agent: not listed any more")).toBeInTheDocument();
  });
});
