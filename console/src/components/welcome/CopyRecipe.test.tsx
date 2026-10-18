// SPDX-License-Identifier: AGPL-3.0-only
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { CopyRecipe } from "./CopyRecipe";

const originalClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");

afterEach(() => {
  if (originalClipboard === undefined) Reflect.deleteProperty(navigator, "clipboard");
  else Object.defineProperty(navigator, "clipboard", originalClipboard);
});

it("keeps the recipe available for manual copying when the clipboard API is absent", async () => {
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
  render(<CopyRecipe label="Public connection configuration" text="public configuration" />);
  fireEvent.click(screen.getByRole("button", { name: "Copy configuration" }));
  await waitFor(() => { expect(screen.getByRole("status")).toHaveTextContent("Select the configuration above and copy it manually."); });
  expect(screen.getByRole("region", { name: "Public connection configuration" })).toHaveTextContent("public configuration");
});

it("offers manual copying when the browser rejects clipboard access", async () => {
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn().mockRejectedValue(new Error("Permission denied")) } });
  render(<CopyRecipe label="Connection" text="public configuration" />);
  fireEvent.click(screen.getByRole("button", { name: "Copy configuration" }));
  await waitFor(() => { expect(screen.getByRole("status")).toHaveTextContent("copy it manually"); });
});

it("confirms a completed copy of the displayed configuration", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
  render(<CopyRecipe label="Connection" text="public configuration" />);
  fireEvent.click(screen.getByRole("button", { name: "Copy configuration" }));
  await waitFor(() => { expect(screen.getByRole("status")).toHaveTextContent("Configuration copied."); });
  expect(writeText).toHaveBeenCalledWith("public configuration");
});
