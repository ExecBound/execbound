// SPDX-License-Identifier: AGPL-3.0-only
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { PersonalSettingsView } from "../../api/types.gen";
import { answerWith, heldReply, renderPage, settle } from "../../test/page";
import { SUMMARY_COPY, WeeklySummary } from "./WeeklySummary";

function view(summary: PersonalSettingsView["weekly_summary"]): PersonalSettingsView {
  return {
    identity: { principal_id: "p-1", kind: "ADMIN", credential_id: "c-1" },
    tenant_name: "Synthetic SOC",
    email: "dana@example.com",
    has_password: true,
    credential: { issued_at: "2026-09-19T04:00:00+00:00", expires_at: "2026-09-19T12:00:00+00:00" },
    sessions: [],
    others: 0,
    directory: { provider: null, link: null },
    weekly_summary: summary,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the weekly summary card", () => {
  it("offers nothing where the deployment does not send it", async () => {
    answerWith({});
    const { container } = renderPage(<WeeklySummary view={view({ available: false, subscribed: false, address: null })} />);
    await settle();
    expect(container.textContent).not.toContain(SUMMARY_COPY.title);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("shows the address as text and says nothing changes until the server answers", async () => {
    const held = heldReply();
    const seen = answerWith({ "POST /api/console/v1/settings/weekly-summary": () => held.reply });
    const user = userEvent.setup();
    renderPage(<WeeklySummary view={view({ available: true, subscribed: false, address: "<b>dana</b>@example.com" })} />);
    expect(await screen.findByText("<b>dana</b>@example.com")).toBeInTheDocument();
    expect(screen.getByText(SUMMARY_COPY.lead)).toBeInTheDocument();
    expect(screen.getByText("Off")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Turn on the weekly summary" }));
    // Waiting for the server: still off, and the switch is not offered twice.
    expect(screen.getByText("Off")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Turn on the weekly summary" })).toBeDisabled();
    expect(seen.map((item) => [item.method, item.path, item.body])).toEqual([
      ["POST", "/api/console/v1/settings/weekly-summary", { subscribed: true }],
    ]);
    held.send({ body: view({ available: true, subscribed: true, address: "dana@example.com" }) });
    await settle();
    expect(await screen.findByText("On")).toBeInTheDocument();
  });

  it("is not offered without an address, and says who can add one", async () => {
    answerWith({});
    renderPage(<WeeklySummary view={view({ available: true, subscribed: false, address: null })} />);
    expect(await screen.findByText(SUMMARY_COPY.noAddress)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Turn on the weekly summary" })).toBeDisabled();
  });

  it("says what a refusal means in its own words", async () => {
    answerWith({
      "POST /api/console/v1/settings/weekly-summary": {
        status: 409,
        body: { code: "CONFLICT", detail: "Something changed first." },
      },
    });
    const user = userEvent.setup();
    renderPage(<WeeklySummary view={view({ available: true, subscribed: true, address: "dana@example.com" })} />);
    await user.click(await screen.findByRole("button", { name: "Turn off the weekly summary" }));
    expect(await screen.findByRole("alert")).not.toHaveTextContent("");
    expect(screen.getByText("On")).toBeInTheDocument();
  });
});
