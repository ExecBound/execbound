// SPDX-License-Identifier: AGPL-3.0-only
// Home's account notices (#678): the API keys expiring soon, at most five agents with the rest
// counted and linked to API keys, read for an administrator only and absent when empty (AK5).

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ExpiringKey } from "../../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { answerWith, renderPage, settle } from "../../test/page";
import { AccountNotices } from "./AccountNotices";

const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN" };
const APPROVER: SessionSummary = { ...PLACEHOLDER, role: "APPROVER" };

function notice(index: number): ExpiringKey {
  const id = `00000000-0000-4000-8000-00000000000${String(index)}`;
  return {
    credential_id: id,
    number: index,
    principal_id: `10000000-0000-4000-8000-00000000000${String(index)}`,
    principal_number: index,
    principal_label: index === 1 ? "<b>Tines</b> stories" : null,
    expires_at: "2026-10-09T08:00:00Z",
    last_used_at: "2026-10-08T11:55:00Z",
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  localStorage.clear();
});

const ME = "44444444-4444-4444-4444-444444444444";

function settings(security: { authenticator: boolean; available: boolean }) {
  return {
    body: {
      identity: { principal_id: ME, kind: "ADMIN", credential_id: ME },
      security: { passkeys: 0, recovery_remaining: 0, requirement: "optional", ...security },
    },
  };
}

describe("Home's account notices", () => {
  it("lists five agents' keys and links the rest to API keys", async () => {
    answerWith({
      "GET /api/console/v1/credentials/expiring": { body: { keys: [1, 2, 3, 4, 5].map(notice), more: 2 } },
    });
    renderPage(<AccountNotices />, ADMIN);
    expect(await screen.findByRole("heading", { level: 2, name: "API keys expiring soon" })).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(5);
    expect(screen.getByRole("link", { name: "Key 1 for <b>Tines</b> stories" })).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    expect(screen.getByRole("link", { name: "Key 2 for Agent 2" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "and 2 more" })).toHaveAttribute("href", "/credentials");
  });

  it("shows nothing when no key needs a notice", async () => {
    const seen = answerWith({ "GET /api/console/v1/credentials/expiring": { body: { keys: [], more: 0 } } });
    renderPage(<AccountNotices />, ADMIN);
    await waitFor(() => {
      expect(seen.some((call) => call.path === "/api/console/v1/credentials/expiring")).toBe(true);
    });
    await settle();
    expect(screen.queryByRole("heading", { name: "API keys expiring soon" })).toBeNull();
  });

  it("reads nothing and shows nothing for an approver", async () => {
    const seen = answerWith({ "GET /api/console/v1/credentials/expiring": { body: { keys: [notice(1)], more: 0 } } });
    renderPage(<AccountNotices />, APPROVER);
    await settle();
    expect(seen).toHaveLength(0);
    expect(screen.queryByRole("heading", { name: "API keys expiring soon" })).toBeNull();
  });
});

describe("Home's second-factor card (AK11)", () => {
  const TITLE = "Your account has no second factor";

  it("shows once to an administrator without a factor, and stays dismissed in this browser", async () => {
    answerWith({ "GET /api/console/v1/settings": settings({ authenticator: false, available: true }) });
    const first = renderPage(<AccountNotices />, ADMIN);
    expect(await screen.findByRole("heading", { level: 2, name: TITLE })).toBeInTheDocument();
    expect(screen.getByText("Changes to people, keys and approval rules are not protected by a second factor for your account.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Add a second factor" })).toHaveAttribute("href", "/account/security");
    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByRole("heading", { name: TITLE })).toBeNull();
    expect(localStorage.getItem(`eb.notice.second-factor.${ME}`)).toBe("dismissed");
    first.unmount();
    renderPage(<AccountNotices />, ADMIN);
    await settle();
    expect(screen.queryByRole("heading", { name: TITLE })).toBeNull();
  });

  it("shows nothing with a factor, without account security, or to an approver", async () => {
    answerWith({ "GET /api/console/v1/settings": settings({ authenticator: true, available: true }) });
    const one = renderPage(<AccountNotices />, ADMIN);
    await settle();
    expect(screen.queryByRole("heading", { name: TITLE })).toBeNull();
    one.unmount();
    answerWith({ "GET /api/console/v1/settings": settings({ authenticator: false, available: false }) });
    const two = renderPage(<AccountNotices />, ADMIN);
    await settle();
    expect(screen.queryByRole("heading", { name: TITLE })).toBeNull();
    two.unmount();
    answerWith({ "GET /api/console/v1/settings": settings({ authenticator: false, available: true }) });
    renderPage(<AccountNotices />, APPROVER);
    await settle();
    expect(screen.queryByRole("heading", { name: TITLE })).toBeNull();
  });

  it("shows and dismisses for the page's lifetime where storage throws, logging nothing", async () => {
    answerWith({ "GET /api/console/v1/settings": settings({ authenticator: false, available: true }) });
    const error = vi.spyOn(console, "error");
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    renderPage(<AccountNotices />, ADMIN);
    expect(await screen.findByRole("heading", { level: 2, name: TITLE })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByRole("heading", { name: TITLE })).toBeNull();
    expect(error).not.toHaveBeenCalled();
  });
});
