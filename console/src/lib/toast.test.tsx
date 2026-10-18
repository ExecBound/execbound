// SPDX-License-Identifier: AGPL-3.0-only
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { Toaster } from "../components/ui/Toast";
import { clearToasts, toast } from "./toast";

describe("toasts", () => {
  afterEach(() => {
    clearToasts();
  });

  it("land in a polite live region and can be dismissed", async () => {
    render(<Toaster />);
    const region = screen.getByRole("status");
    expect(region).toHaveAttribute("aria-live", "polite");
    act(() => {
      toast("Saved.", 0);
    });
    expect(region).toHaveTextContent("Saved.");
    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(region).not.toHaveTextContent("Saved.");
  });
});
