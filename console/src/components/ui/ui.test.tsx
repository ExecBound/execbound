// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { Badge } from "./Badge";
import { Button } from "./Button";
import { Card } from "./Card";
import { Drawer } from "./Drawer";
import { EmptyState } from "./EmptyState";
import { PageHeading } from "./PageHeading";
import { Table, Td, Th } from "./Table";

describe("the shared components", () => {
  it("put the word first on a badge and the colour second", () => {
    render(<Badge tone="deny">Denied</Badge>);
    const badge = screen.getByText("Denied");
    expect(badge).toHaveClass("badge", "badge-deny");
    expect(badge.querySelector(".badge-dot")).toHaveAttribute("aria-hidden", "true");
  });

  it("make every button a button unless told otherwise", () => {
    render(
      <>
        <Button variant="primary" size="decision">
          Approve
        </Button>
        <Button type="submit">Send</Button>
      </>,
    );
    expect(screen.getByRole("button", { name: "Approve" })).toHaveAttribute("type", "button");
    expect(screen.getByRole("button", { name: "Approve" })).toHaveClass("btn-primary", "btn-decision");
    expect(screen.getByRole("button", { name: "Send" })).toHaveAttribute("type", "submit");
  });

  it("render a card with its heading, a page heading that can take focus, and an empty state", () => {
    render(
      <>
        <PageHeading title="Approvals" lead="Waiting for a person." />
        <Card title="Needs you">body</Card>
        <EmptyState title="Nothing waiting">Come back later.</EmptyState>
      </>,
    );
    expect(screen.getByRole("heading", { level: 1, name: "Approvals" })).toHaveAttribute("tabindex", "-1");
    expect(screen.getByRole("heading", { level: 2, name: "Needs you" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Nothing waiting");
  });

  it("give a table a caption and scoped column headers", () => {
    render(
      <Table caption="Recent decisions" density="compact">
        <thead>
          <tr>
            <Th>Time</Th>
            <Th>Target</Th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <Td mono>14:07:31</Td>
            <Td>ws25</Td>
          </tr>
        </tbody>
      </Table>,
    );
    const table = screen.getByRole("table", { name: "Recent decisions" });
    expect(table).toHaveClass("table-compact");
    for (const header of screen.getAllByRole("columnheader")) expect(header).toHaveAttribute("scope", "col");
    expect(screen.getByText("14:07:31")).toHaveClass("mono");
  });

  it("open a drawer as a dialog named by its title and close it on Escape", async () => {
    const onClose = vi.fn();
    const drawer = (open: boolean) => (
      <Drawer open={open} onClose={onClose} title="Isolate endpoint dc01" eyebrow={<Badge tone="deny">Denied</Badge>}>
        <p>Why</p>
      </Drawer>
    );
    const { rerender } = render(drawer(false));
    // Closed, a drawer renders nothing, so Base UI's dialog is never fetched (#333). The
    // budget script refuses a static import of it.
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByText("Why")).toBeNull();
    rerender(drawer(true));
    const dialog = await screen.findByRole("dialog", { name: "Isolate endpoint dc01" });
    expect(dialog).toHaveClass("drawer");
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });
});
