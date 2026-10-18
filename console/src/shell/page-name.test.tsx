// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { titleNoun, titleNumber, titleRef, titleShort, type TitleWord } from "./page-name";

describe("title words (NV1, #678)", () => {
  it("accept a request reference and nothing shaped otherwise", () => {
    expect(titleRef("EB-1042")).toBe("EB-1042");
    expect(titleRef("ws-01.corp.example")).toBeUndefined();
    expect(titleRef("EB-1042 <b>")).toBeUndefined();
    expect(titleRef("")).toBeUndefined();
    expect(titleRef("EB-1234567890123")).toBeUndefined();
  });

  it("number a principal only with a positive whole number", () => {
    expect(titleNumber("Agent", 3)).toBe("Agent 3");
    expect(titleNumber("User", 12)).toBe("User 12");
    expect(titleNumber("Agent", 0)).toBeUndefined();
    expect(titleNumber("Agent", -3)).toBeUndefined();
    expect(titleNumber("Agent", 1.5)).toBeUndefined();
    expect(titleNumber("Agent", null)).toBeUndefined();
    expect(titleNumber("Agent", "3")).toBeUndefined();
  });

  it("shorten only a hexadecimal id", () => {
    expect(titleShort("Policy version", "acddee11-2222-4333-8444-555566667777")).toBe("Policy version acddee11");
    expect(titleShort("Policy version", "zzzz")).toBeUndefined();
    expect(titleShort("Turn", "<script>alert(1)</script>")).toBeUndefined();
  });

  it("never throw, whatever they are given", () => {
    const hostile: unknown[] = [undefined, null, 1n, {}, [], Symbol("x"), () => "EB-1", Number.NaN, Infinity];
    for (const value of hostile) {
      expect(() => titleRef(value)).not.toThrow();
      expect(() => titleNumber("Agent", value)).not.toThrow();
      expect(() => titleShort("Turn", value)).not.toThrow();
    }
    expect(titleNoun("Not found")).toBe("Not found");
  });

  it("refuse a plain string or a lower-case noun at compile time", () => {
    // @ts-expect-error a server's string is not a title word.
    const raw: TitleWord = "ws-01.corp.example";
    // @ts-expect-error the noun is the directory's capitalised "Agent" or "User".
    titleNumber("agent", 1);
    // @ts-expect-error only the console's fixed nouns.
    titleNoun("ws-01.corp.example");
    expect(raw).toBe("ws-01.corp.example");
  });
});
