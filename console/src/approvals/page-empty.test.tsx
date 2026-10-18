// SPDX-License-Identifier: AGPL-3.0-only
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";

import { PLACEHOLDER } from "../lib/session";
import { answerWith, renderPage } from "../test/page";
import { ApprovalsPage } from "./ApprovalsPage";
import type { ApprovalsView } from "./search";

/** The page with its view held as a route would hold it. */
function Viewed() {
  const [view, setView] = useState<ApprovalsView | undefined>();
  return (
    <ApprovalsPage
      view={view}
      onView={(next) => {
        setView(next);
      }}
    />
  );
}

afterEach(() => { vi.unstubAllGlobals(); });

it("renders one empty state for the selected queue without a duplicate detail pane", async () => {
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
  answerWith({ "GET /api/console/v1/approvals": { body: { items: [], server_time: "2026-09-22T12:00:00Z" } } });
  renderPage(<Viewed />);
  await waitFor(() => { expect(screen.getByRole("button", { name: "Pending 0" })).toBeInTheDocument(); });
  expect(screen.getAllByText("Nothing is waiting for you.")).toHaveLength(1);
  expect(screen.queryByRole("region", { name: "Detail" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Decided today" }));
  expect(await screen.findByText("Nothing assigned to you was decided today.")).toBeInTheDocument();
  expect(screen.queryByText("Nothing is waiting for you.")).toBeNull();
});

it.each([
  ["an administrator", "ADMIN" as const, "Decided today lists only the approvals you are assigned to review; Activity lists the others."],
  ["an approver", "APPROVER" as const, "Decided today lists the approvals you are assigned to review, whoever decided them."],
])("says what Decided today counts when it is empty, to %s (#678)", async (_who, role, body) => {
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
  answerWith({ "GET /api/console/v1/approvals": { body: { items: [], server_time: "2026-09-22T12:00:00Z" } } });
  renderPage(<ApprovalsPage view="decided" />, { ...PLACEHOLDER, role });
  expect(await screen.findByText("Nothing assigned to you was decided today.")).toBeInTheDocument();
  expect(screen.getByText(body)).toBeInTheDocument();
  expect(screen.queryByText(/When an agent asks for something a person must decide/)).toBeNull();
});

it("links the basic page at the approval's own address when the record cannot be read (#496)", async () => {
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
  const id = "4b1e90c2-0000-4000-8000-000000000001";
  answerWith({ "GET /api/console/v1/approvals": { body: { items: [], server_time: "2026-09-22T12:00:00Z" } } });
  renderPage(<ApprovalsPage selected={id} />, {
    ...PLACEHOLDER,
    tenant: { id: "7f8e9d0c-0000-4000-8000-000000000003", name: "Synthetic SOC", detail: "" },
  });
  expect(await screen.findByRole("link", { name: "use the basic page" })).toHaveAttribute("href", `/approvals/${id}/classic`);
});
