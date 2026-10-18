// SPDX-License-Identifier: AGPL-3.0-only
import { act, render, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { KEPT_FIELD, noteStorage, useKeptFieldMounted } from "./kept";

describe("whether this page keeps what is typed (#678)", () => {
  it("is true only while a keeping field is on the page and storage works", async () => {
    noteStorage(true);
    const mounted = renderHook(() => useKeptFieldMounted());
    expect(mounted.result.current).toBe(false);
    const field = render(<textarea aria-label="Bundle JSON" {...{ [KEPT_FIELD]: "" }} />);
    await act(async () => {
      await Promise.resolve();
    });
    expect(mounted.result.current).toBe(true);
    act(() => {
      noteStorage(false);
    });
    expect(mounted.result.current).toBe(false);
    act(() => {
      noteStorage(true);
    });
    field.unmount();
    await act(async () => {
      await Promise.resolve();
    });
    expect(mounted.result.current).toBe(false);
  });

  it("names the attribute each keeping field writes as a literal", () => {
    expect(KEPT_FIELD).toBe("data-eb-kept");
  });
});
