// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { VIEWS } from "./RoutedApprovals";
import { APPROVALS_VIEWS, parseApprovalsSearch } from "./search";

describe("the approvals view in the address (#678)", () => {
  it("keeps the four views and drops anything else", () => {
    for (const view of ["pending", "decided", "lapsed", "others"]) {
      expect(parseApprovalsSearch({ view })).toEqual({ view });
    }
    expect(parseApprovalsSearch({ view: "later" })).toEqual({});
    expect(parseApprovalsSearch({ view: 3 })).toEqual({});
    expect(parseApprovalsSearch({})).toEqual({});
    // The routed page reads the same four, without importing the routes' parser.
    expect([...VIEWS]).toEqual([...APPROVALS_VIEWS]);
  });
});
