// SPDX-License-Identifier: AGPL-3.0-only
import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { NO_SERVICE, PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { withEdition } from "../../test/edition";
import { renderPage } from "../../test/page";
import { OperatorSteps } from "./OperatorSteps";

const TENANT = "11111111-1111-4111-8111-111111111111";
const SPACE = "22222222-2222-4222-8222-222222222222";
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", tenant: { id: TENANT, name: "Acme", detail: "" }, space: { id: SPACE, name: "Default", archived: false } };

afterEach(() => {
  vi.unstubAllGlobals();
});

function instructions(): string {
  return screen.getByRole("region", { name: "Copy instructions for your operator" }).textContent;
}

describe("the operator's steps (UX12, #678)", () => {
  it("names this workspace and this Space in the commands, and who may run them", async () => {
    renderPage(<OperatorSteps />, ADMIN);
    await screen.findByRole("region", { name: "Copy instructions for your operator" });
    const text = instructions();
    expect(text).toContain(`account-create --tenant ${TENANT} --space ${SPACE}`);
    expect(text).toContain('Install, "The long way, one command at a time"');
    expect(text).toContain('Operations, "Provision trusted context"');
    expect(text).toContain("a Space administrator's principal is refused as the actor");
    // No address at all, the service's included: no scheme and no domain.
    expect(text).not.toMatch(/https?:/);
    expect(text).not.toMatch(/\.ai\b|\.com\b/);
    expect(screen.getByText(/Your deployment's operator registers a provider account/)).toBeInTheDocument();
  });

  it("keeps the Space's placeholder where none is selected", async () => {
    renderPage(<OperatorSteps />, { ...ADMIN, space: null });
    await screen.findByRole("region", { name: "Copy instructions for your operator" });
    expect(instructions()).toContain(`--tenant ${TENANT} --space <space id>`);
  });

  it("links the documentation only where the deployment names it", async () => {
    renderPage(<OperatorSteps />, ADMIN);
    await screen.findByRole("region", { name: "Copy instructions for your operator" });
    expect(screen.queryByRole("link", { name: "Open the documentation" })).toBeNull();
  });

  it("links the deployment's documentation where it names one", async () => {
    renderPage(<OperatorSteps />, { ...ADMIN, service: { ...NO_SERVICE, help_url: "https://docs.example.com/" } });
    expect(await screen.findByRole("link", { name: "Open the documentation" })).toHaveAttribute("href", "https://docs.example.com/");
  });

  it("names the service operator in an edition whose readers run no commands", async () => {
    renderPage(withEdition(<OperatorSteps />, { operatorCommands: false }), { ...ADMIN, service: { ...NO_SERVICE, support_email: "help@example.com" } });
    expect(await screen.findByText(/Your service operator connects providers for this workspace/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "help@example.com" })).toHaveAttribute("href", "mailto:help@example.com");
    expect(screen.queryByRole("region", { name: "Copy instructions for your operator" })).toBeNull();
  });

  it("names no address where the service configured none", async () => {
    renderPage(withEdition(<OperatorSteps />, { operatorCommands: false }), ADMIN);
    expect(await screen.findByText("Your service operator connects providers for this workspace.")).toBeInTheDocument();
    expect(screen.queryByRole("link")).toBeNull();
  });
});
