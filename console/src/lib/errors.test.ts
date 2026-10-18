// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { codeOf, copyFor } from "./errors";

// The map the reconcile dialog and the workspace switcher read (#333): a refusal
// becomes the client's own sentence for its code, never the server's words.
describe("the refusal copy for the reconcile dialog and the workspace switcher", () => {
  it("maps a known code to the client's own sentence", () => {
    expect(copyFor({ code: "INVALID_CONTINUATION", detail: "stale" })).toBe(
      "The record changed since it was read. Close it and open it again.",
    );
    expect(copyFor({ code: "WORKSPACE_CHANGED" })).toBe("The workspace changed. Reload before continuing.");
    expect(copyFor({ code: "FORBIDDEN" })).toBe("This is not yours to do.");
  });

  it("never shows the server's detail, even for a code it does not know", () => {
    const shown = copyFor({ code: "SOMETHING_NEW", detail: "<b>server words</b>" });
    expect(shown).toBe("The request was refused.");
    expect(shown).not.toContain("server words");
  });

  it("reads anything without a string code as a failure to reach the server", () => {
    for (const error of [undefined, null, "boom", new Error("network"), { code: 503 }, { detail: "x" }]) {
      expect(copyFor(error)).toBe("ExecBound could not be reached; try again.");
    }
  });

  it("returns the code only when it is a string", () => {
    expect(codeOf({ code: "CONFLICT" })).toBe("CONFLICT");
    expect(codeOf({ code: 409 })).toBeUndefined();
    expect(codeOf("CONFLICT")).toBeUndefined();
  });
});
