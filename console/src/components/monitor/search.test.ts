// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { parseMonitorSearch } from "./search";

const ID = "3f2b8c1e-5d4a-4b6c-8e9f-0a1b2c3d4e5f";

describe("Monitoring's search values (MQ10, #678)", () => {
  it("keeps every value the page knows", () => {
    expect(parseMonitorSearch({ view: "findings", state: "acknowledged", open: ID, story: "4001", focus: "quiet" })).toEqual({
      view: "findings",
      state: "acknowledged",
      open: ID,
      story: "4001",
      focus: "quiet",
    });
  });

  it("drops a value it does not know", () => {
    expect(
      parseMonitorSearch({
        view: "x",
        state: "closed",
        open: ID.toUpperCase(),
        story: "a b",
        focus: "sources",
      }),
    ).toEqual({});
    expect(parseMonitorSearch({ story: "x".repeat(97) })).toEqual({});
    expect(parseMonitorSearch({ story: "<img>" })).toEqual({});
    expect(parseMonitorSearch({ open: "not-an-id" })).toEqual({});
  });

  it("keeps a setup provider it offers, beside every other value (UX18)", () => {
    expect(parseMonitorSearch({ setup: "tines" })).toEqual({ setup: "tines" });
    expect(parseMonitorSearch({ setup: "entra_agent_id" })).toEqual({ setup: "entra_agent_id" });
    expect(
      parseMonitorSearch({ view: "findings", state: "open", open: ID, story: "4001", focus: "quiet", setup: "tines" }),
    ).toEqual({ view: "findings", state: "open", open: ID, story: "4001", focus: "quiet", setup: "tines" });
  });

  it("keeps the return from Microsoft as done or refused, and nothing else (MC11)", () => {
    expect(parseMonitorSearch({ connect: "done" })).toEqual({ connect: "done" });
    expect(parseMonitorSearch({ connect: "refused", setup: "tines" })).toEqual({ connect: "refused", setup: "tines" });
    for (const connect of ["Done", "connected", "", "done ", 1, true, null, undefined, ["done"], { done: true }]) {
      expect(parseMonitorSearch({ connect })).toEqual({});
    }
  });

  it("drops a setup provider it does not offer (UX18)", () => {
    for (const setup of ["other", "Tines", "", "tines ", "entra", 1, true, null, undefined, ["tines"], { tines: true }]) {
      expect(parseMonitorSearch({ setup })).toEqual({});
    }
  });

  it("drops anything that is not a string", () => {
    for (const value of [1, 4001, true, null, undefined, ["findings"], { view: "findings" }]) {
      expect(parseMonitorSearch({ view: value, state: value, open: value, story: value, focus: value })).toEqual({});
    }
  });
});
