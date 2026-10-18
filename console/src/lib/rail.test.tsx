// SPDX-License-Identifier: AGPL-3.0-only
import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { readRail, useRail } from "./rail";

describe("the sidebar rail", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("starts open, toggles, and is remembered per browser", () => {
    expect(readRail()).toBe(false);
    const { result } = renderHook(() => useRail());
    expect(result.current[0]).toBe(false);
    act(() => {
      result.current[1]();
    });
    expect(result.current[0]).toBe(true);
    expect(window.localStorage.getItem("eb.sidebar")).toBe("rail");
    expect(readRail()).toBe(true);
  });

  it("starts open when storage refuses", () => {
    expect(
      readRail({
        getItem: () => {
          throw new Error("refused");
        },
      }),
    ).toBe(false);
  });
});
