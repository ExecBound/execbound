// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useEdition } from "./context";
import { edition } from "./core";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the core edition (#496)", () => {
  it("fills every slot with nothing", () => {
    expect(edition.navigation).toEqual([]);
    for (const Slot of [edition.TopBarItems, edition.WorkspacePanels, edition.TenantDefinitions, edition.AccountPanels, edition.Welcome, edition.FixtureHint]) {
      const { container, unmount } = render(<Slot />);
      expect(container).toBeEmptyDOMElement();
      unmount();
    }
  });

  it("counts nothing and asks the server nothing", () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    for (const name of ["account_opened", "approval_completed"] as const) {
      edition.event(name);
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it("offers operator commands, since a self-hosted reader can run them (#678)", () => {
    expect(edition.operatorCommands).toBe(true);
  });

  it("offers watching first, since a self-hosted administrator can finish monitoring setup (#678)", () => {
    expect(edition.watchFirst).toBe(true);
  });

  it("keeps core's own approval remedy, pointing at the operator's configuration (#678)", () => {
    expect(edition.ApprovalRemedy).toBeNull();
  });

  it("is what a component reads where no edition was provided", () => {
    function Probe() {
      return <p>{useEdition() === edition ? "core" : "another"}</p>;
    }
    render(<Probe />);
    expect(screen.getByText("core")).toBeInTheDocument();
  });
});
