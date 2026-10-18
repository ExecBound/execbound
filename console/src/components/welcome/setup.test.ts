// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SampleStatusView } from "../../api/types.gen";
import { CHOOSE_SPACE, setupView } from "../../test/setup-view";
import { hideSetupCard, openingStep, parseStep, setupCardHidden, showSetupCard, stepDone, STEPS } from "./setup";

const OFFERED: SampleStatusView = {
  state: "absent",
  offered: true,
  available: true,
  demo_available: false,
  demo_needs_refresh: false,
  bundle_id: null,
  hosts: [],
  observed_at: null,
  stale_at: null,
  first_request: null,
};
const NOT_OFFERED: SampleStatusView = { ...OFFERED, offered: false };
const TENANT = "11111111-1111-4111-8111-111111111111";

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

describe("Getting started's steps (UX10, #678)", () => {
  it("names the four steps in order", () => {
    expect(STEPS).toEqual(["example", "connect", "verify", "controls"]);
  });

  it("admits exactly the four steps from the address", () => {
    for (const step of STEPS) expect(parseStep(step)).toBe(step);
    for (const value of ["Connect", "../x", "", " connect", 1, null, undefined, ["connect"], { step: "connect" }]) {
      expect(parseStep(value)).toBeUndefined();
    }
  });

  it("opens on the example only where it can reach a decision in this Space", () => {
    expect(openingStep(setupView({}, { connected: false }), OFFERED)).toBe("example");
    // Samples go to the default Space, not this one: on to the first step left here.
    expect(openingStep(setupView({}, { connected: false, samples_here: false }), OFFERED)).toBe("connect");
    expect(openingStep(setupView({}, { connected: false }), NOT_OFFERED)).toBe("connect");
    expect(openingStep(setupView({ policy: "done" }), OFFERED)).toBe("connect");
    expect(openingStep(setupView({ agent_key: "done" }), NOT_OFFERED)).toBe("verify");
    expect(openingStep(setupView({ agent_key: "done", first_request: "done" }), NOT_OFFERED)).toBe("controls");
  });

  it("opens on the example as before where either read is missing or names no Space", () => {
    expect(openingStep(undefined, OFFERED)).toBe("example");
    expect(openingStep(setupView({ agent_key: "done" }), undefined)).toBe("example");
    expect(openingStep(CHOOSE_SPACE, NOT_OFFERED)).toBe("example");
  });

  it("marks a step done only from its milestones", () => {
    expect(stepDone("example", setupView({ policy: "done", agent_key: "done" }))).toBe(false);
    expect(stepDone("connect", setupView({ agent_key: "done" }))).toBe(true);
    expect(stepDone("verify", setupView({ agent_key: "done" }))).toBe(false);
    expect(stepDone("verify", setupView({ first_request: "done" }))).toBe(true);
    expect(stepDone("controls", setupView({ policy: "done", reviewer: "done", first_decision: "done" }))).toBe(true);
    expect(stepDone("controls", setupView({ policy: "done", reviewer: "not_applicable", first_decision: "not_applicable" }))).toBe(true);
    expect(stepDone("controls", setupView({ policy: "done", reviewer: "done", first_decision: "needs_enforcing" }))).toBe(false);
    expect(stepDone("controls", setupView({ reviewer: "done", first_decision: "done" }))).toBe(false);
    expect(stepDone("connect", undefined)).toBe(false);
    expect(stepDone("connect", CHOOSE_SPACE)).toBe(false);
  });
});

describe("the sidebar card's hidden preference (UX11)", () => {
  it("round-trips per workspace under its own key", () => {
    expect(setupCardHidden(TENANT)).toBe(false);
    hideSetupCard(TENANT);
    expect(localStorage.getItem(`execbound.setup-card.hidden.${TENANT}`)).toBe("1");
    expect(setupCardHidden(TENANT)).toBe(true);
    expect(setupCardHidden("another")).toBe(false);
    showSetupCard(TENANT);
    expect(setupCardHidden(TENANT)).toBe(false);
  });

  it("reads storage that throws as not hidden, and swallows a failed write", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(setupCardHidden(TENANT)).toBe(false);
    expect(() => { hideSetupCard(TENANT); }).not.toThrow();
  });
});
