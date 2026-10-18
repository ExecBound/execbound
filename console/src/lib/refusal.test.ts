// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { copyFor, refusal } from "./refusal";

describe("a refusal", () => {
  it("reads the code and the fields the API named", () => {
    expect(refusal({ code: "INVALID_BODY", detail: "x", fields: ["deadline", 3] })).toEqual({
      code: "INVALID_BODY",
      fields: ["deadline"],
    });
    expect(refusal({ code: "CONFLICT" })).toEqual({ code: "CONFLICT", fields: [] });
  });

  it("reads anything else as unavailable, never as a sentence from the server", () => {
    expect(refusal(new TypeError("Failed to fetch"))).toEqual({ code: "UNAVAILABLE", fields: [] });
    expect(refusal("<html>gateway timeout</html>")).toEqual({ code: "UNAVAILABLE", fields: [] });
    expect(refusal({ code: 500 })).toEqual({ code: "UNAVAILABLE", fields: [] });
    expect(copyFor("<b>server text</b>")).not.toContain("server text");
  });

  it("maps a code to copy, and a named field to the form's own line", () => {
    expect(copyFor({ code: "CONFLICT" })).toBe("That is already the current state; nothing was changed.");
    expect(copyFor({ code: "STOPPED" })).toContain("emergency stop");
    expect(copyFor({ code: "SOMETHING_NEW" })).toContain("unavailable");
    expect(
      copyFor({ code: "INVALID_BODY", fields: ["deadline"] }, { deadline: "The deadline is 120 to 3600 seconds, or off." }),
    ).toBe("The deadline is 120 to 3600 seconds, or off.");
    expect(copyFor({ code: "INVALID_BODY", fields: ["other"] }, { deadline: "x" })).toBe(
      "A field is missing, unknown or out of bounds.",
    );
  });
});
