// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { monitoringBadge } from "./badge";

describe("the count beside Monitoring (MQ3, #678)", () => {
  it("counts open findings first and lands on them", () => {
    expect(monitoringBadge(3, 2)).toEqual({
      count: 3,
      search: { view: "findings" },
      label: "3 open findings; 2 sources or collections quiet",
    });
    expect(monitoringBadge(1, 0).label).toBe("1 open finding");
  });

  it("counts quiet items when nothing is open and lands on them", () => {
    expect(monitoringBadge(0, 2)).toEqual({
      count: 2,
      search: { focus: "quiet" },
      label: "2 monitoring sources or collections quiet",
    });
    expect(monitoringBadge(0, 1).label).toBe("1 monitoring source or collection quiet");
  });

  it("shows nothing when nothing is waiting", () => {
    expect(monitoringBadge(0, 0)).toEqual({ count: 0, search: {}, label: "" });
  });
});
