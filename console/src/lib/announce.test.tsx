// SPDX-License-Identifier: AGPL-3.0-only
import { act, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { announce, Announcer } from "./announce";

const nextFrame = () =>
  act(async () => {
    await new Promise((resolve) => requestAnimationFrame(resolve));
  });

describe("the live region", () => {
  it("speaks politely in the one status region, and again when repeated", async () => {
    render(<Announcer />);
    const regions = screen.getAllByRole("status");
    expect(regions).toHaveLength(1);
    const region = regions[0];
    expect(region).toHaveAttribute("aria-live", "polite");
    act(() => {
      announce("3 actions match");
    });
    await nextFrame();
    expect(region).toHaveTextContent("3 actions match");
    act(() => {
      announce("3 actions match");
    });
    // Cleared at once, so the same words are a change a screen reader speaks again.
    expect(region).toHaveTextContent("");
    await nextFrame();
    expect(region).toHaveTextContent("3 actions match");
  });
});
