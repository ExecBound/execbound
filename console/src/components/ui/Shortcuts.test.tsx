// SPDX-License-Identifier: AGPL-3.0-only
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { resetSingleKeysForTest, setSingleKeys, singleKeysEnabled } from "../../lib/keys";
import { PLACEHOLDER } from "../../lib/session";
import { renderPage } from "../../test/page";
import Shortcuts from "./Shortcuts";

afterEach(() => {
  setSingleKeys(true);
  resetSingleKeysForTest();
});

const ADMIN = { ...PLACEHOLDER, role: "ADMIN" as const, permissions: ["console.read", "access.manage", "policy.manage", "approvals.decide", "workspace.manage"] };

describe("the keyboard list (NV5, NV6, #678)", () => {
  it("lists the keys of each page this person can open, and no promise it cannot keep", async () => {
    renderPage(<Shortcuts open onClose={() => undefined} />, ADMIN);
    const list = await screen.findByRole("dialog", { name: "Keyboard" });
    expect(list).not.toHaveTextContent("g then a letter");
    for (const [keys, page] of [["g h", "Home"], ["g a", "Approvals"], ["g p", "Policies"], ["g ?", "Help & support"]] as const) {
      const term = within(list).getByText(keys);
      expect(term.closest("div")).toHaveTextContent(page);
    }
    expect(within(list).getByText("Ctrl K or Cmd K").closest("div")).toHaveTextContent("Search");
  });

  it("leaves out a page the role cannot open", async () => {
    renderPage(<Shortcuts open onClose={() => undefined} />, { ...PLACEHOLDER, role: "APPROVER" });
    const list = await screen.findByRole("dialog", { name: "Keyboard" });
    expect(within(list).queryByText("g p")).toBeNull();
    expect(within(list).getByText("g a")).toBeInTheDocument();
  });

  it("turns the single-key shortcuts off and marks them off", async () => {
    renderPage(<Shortcuts open onClose={() => undefined} />, ADMIN);
    const list = await screen.findByRole("dialog", { name: "Keyboard" });
    const box = within(list).getByRole("checkbox", { name: "Use single-key shortcuts (?, g, j and k)" });
    expect(box).toBeChecked();
    await userEvent.click(box);
    expect(singleKeysEnabled()).toBe(false);
    expect(within(list).getByText("j and k").closest("div")).toHaveTextContent("(off)");
    expect(within(list).getByText("?").closest("div")).toHaveTextContent("(off)");
    expect(within(list).getByText(/Go to a page/)).toHaveTextContent("(off)");
  });
});
