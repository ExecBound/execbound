// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, describe, expect, it } from "vitest";

import { clockOffset, forgetServerTime, noteServerTime, serverNow } from "./clock";

describe("the server clock", () => {
  afterEach(() => {
    forgetServerTime();
  });

  it("knows nothing until a response carries a date", () => {
    expect(clockOffset()).toBeNull();
    noteServerTime(new Headers({}), 1_000);
    noteServerTime(new Headers({ date: "not a date" }), 1_000);
    expect(clockOffset()).toBeNull();
    expect(serverNow()).toBeGreaterThan(0);
  });

  it("corrects a phone that runs an hour fast, to the middle of the server's second", () => {
    const server = Date.parse("Sat, 19 Sep 2026 14:07:31 GMT");
    const phone = server + 3_600_000;
    noteServerTime(new Headers({ date: "Sat, 19 Sep 2026 14:07:31 GMT" }), phone);
    expect(clockOffset()).toBe(-3_600_000 + 500);
    expect(serverNow() - Date.now()).toBeCloseTo(-3_600_000 + 500, -2);
  });
});
