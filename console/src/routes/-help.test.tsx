// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ServiceLinksView, SessionView } from "../api/types.gen";
import { NO_SERVICE } from "../lib/session";
import { TERMS } from "../lib/words";
import { routeTree } from "../routeTree.gen";
import { serve } from "../test/api";

const LINKS: ServiceLinksView = {
  support_email: "support@example.com",
  help_url: "https://example.com/help",
  status_url: "https://example.com/status",
  privacy_url: "https://example.com/privacy",
  terms_url: "https://example.com/terms",
  plans_url: "https://example.com/plans",
  security_url: "https://example.com/security",
  privacy_requests_url: "https://example.com/help#requests",
  source_url: "https://example.com/source",
  operator: "Example Operations Ltd",
};

function session(service: ServiceLinksView): SessionView {
  return {
    generation: "test-generation", can_switch_workspaces: false,
    access: { managed: false, roles: ["administrator"], permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"], workspace_permissions: [], space_permissions: {} },
    identity: { principal_id: "p-admin", kind: "ADMIN", label: "A. Rivera" },
    tenant: { tenant_id: "t-1", name: "Acme SOC", mode: "ENFORCE", approval_deadline_seconds: 900 },
    csrf_token: "token", release: null, expires_at: "2026-09-19T20:00:00Z", ends_at: "2026-09-20T04:00:00Z", end_reason: "sign_in", stop: null,
    space: null, spaces: 1, all_spaces: false, assistant: false, invitations: false, mail: true, features: [],
    service,
  };
}

/** Help, in the shell, for a session whose deployment names these links. */
function mount(service: ServiceLinksView) {
  serve({ "/api/console/v1/session": session(service) });
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/help"] }) });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

function card(title: string) {
  const heading = screen.getByRole("heading", { name: title });
  const found = heading.closest("section");
  if (found === null) throw new Error(`No card is headed ${title}`);
  return within(found);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Help's contact and plans cards (#496)", () => {
  it("link the deployment's support address and pages where it names them", async () => {
    mount(LINKS);
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    expect(card("Contact support").getByRole("link", { name: "Email support" })).toHaveAttribute(
      "href",
      "mailto:support@example.com?subject=ExecBound%20support",
    );
    expect(card("Contact support").getByRole("link", { name: "Service status and incident updates" })).toHaveAttribute("href", LINKS.status_url);
    const plans = card("Plans and privacy");
    expect(plans.getByRole("link", { name: "Plans and contact sales" })).toHaveAttribute("href", LINKS.plans_url);
    expect(plans.getByRole("link", { name: "Privacy notice" })).toHaveAttribute("href", LINKS.privacy_url);
    expect(plans.getByRole("link", { name: "Report a security issue" })).toHaveAttribute("href", LINKS.security_url);
  });

  it("are not shown at all where the deployment names nothing", async () => {
    mount(NO_SERVICE);
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    expect(screen.getByRole("heading", { name: "Sign-in and account help" })).toBeInTheDocument();
    for (const title of ["Contact support", "Plans and privacy", "Privacy and security"]) {
      expect(screen.queryByRole("heading", { name: title })).toBeNull();
    }
    expect(document.querySelector('a[href^="mailto:"], a[href^="https:"]')).toBeNull();
  });

  it("say how a setup credential's holder keeps signing in, where the session notice points (#678)", async () => {
    mount(NO_SERVICE);
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    expect(
      card("Sign-in and account help").getByText(
        "Signed in with a setup credential? It expires, and cannot be used after that. Before it does, have the installation owner set up your own sign-in, a password or your organization's directory, or issue another setup credential.",
      ),
    ).toBeInTheDocument();
  });

  it("keep what the deployment names and leave out what it does not", async () => {
    mount({ ...NO_SERVICE, status_url: LINKS.status_url, security_url: LINKS.security_url });
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    const contact = card("Contact support");
    expect(contact.queryByRole("link", { name: "Email support" })).toBeNull();
    expect(contact.queryByText(/Include the page name/)).toBeNull();
    expect(contact.getByRole("link", { name: "Service status and incident updates" })).toHaveAttribute("href", LINKS.status_url);
    const privacy = card("Privacy and security");
    expect(privacy.getAllByRole("link").map((link) => link.textContent)).toEqual(["Report a security issue"]);
    // No separator is left beside the one link.
    expect(privacy.getByRole("link", { name: "Report a security issue" }).closest("p")?.textContent).toBe("Report a security issue");
    expect(privacy.queryByText(/Need capacity/)).toBeNull();
    expect(screen.queryByRole("heading", { name: "Plans and privacy" })).toBeNull();
  });

  it("offer only the support address where the deployment names no status page", async () => {
    mount({ ...NO_SERVICE, support_email: LINKS.support_email });
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    const contact = card("Contact support");
    expect(contact.getByRole("link", { name: "Email support" })).toHaveAttribute(
      "href",
      "mailto:support@example.com?subject=ExecBound%20support",
    );
    expect(contact.queryByText("Service status and incident updates")).toBeNull();
    expect(contact.getAllByRole("link").map((link) => link.textContent)).toEqual(["Email support"]);
  });
});

describe("reopening the sidebar's setup progress (UX11, #678)", () => {
  afterEach(() => {
    localStorage.clear();
  });

  it("offers an administrator the control while the card is hidden in this browser, and it clears the preference", async () => {
    localStorage.setItem("execbound.setup-card.hidden.t-1", "1");
    mount(NO_SERVICE);
    const control = await screen.findByRole("button", { name: "Show setup progress in the sidebar" });
    control.click();
    expect(localStorage.getItem("execbound.setup-card.hidden.t-1")).toBeNull();
    expect(await screen.findByRole("link", { name: "Open getting started" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show setup progress in the sidebar" })).toBeNull();
  });

  it("offers no control to anyone but an administrator", async () => {
    localStorage.setItem("execbound.setup-card.hidden.t-1", "1");
    const base = session(NO_SERVICE);
    serve({
      "/api/console/v1/session": {
        ...base,
        identity: { principal_id: "p-approver", kind: "HUMAN_APPROVER", label: "B. Chen" },
        access: { ...base.access, roles: ["approver"], permissions: ["console.read", "approvals.decide"] },
      },
    });
    const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/help"] }) });
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("link", { name: "Open Activity" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show setup progress in the sidebar" })).toBeNull();
  });

  it("offers no control while the card shows", async () => {
    mount(NO_SERVICE);
    expect(await screen.findByRole("link", { name: "Open getting started" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show setup progress in the sidebar" })).toBeNull();
  });
});

describe("Help's own cards (NV15, #678)", () => {
  let meta: HTMLMetaElement | null = null;

  afterEach(() => {
    meta?.remove();
    meta = null;
  });

  function release(content: string) {
    meta = document.createElement("meta");
    meta.setAttribute("name", "execbound-release");
    meta.setAttribute("content", content);
    document.head.append(meta);
  }

  it("links the deployment's documentation where it names it, and only there", async () => {
    mount(LINKS);
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    expect(card("Documentation").getByRole("link", { name: "Open the documentation" })).toHaveAttribute("href", LINKS.help_url);
    expect(card("Contact support").getByText(/the version shown below, any request ID or error reference/)).toBeInTheDocument();
  });

  it("has no documentation card where the deployment names none", async () => {
    mount(NO_SERVICE);
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    expect(screen.queryByRole("heading", { name: "Documentation" })).toBeNull();
  });

  it("opens the keyboard list", async () => {
    mount(NO_SERVICE);
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    await userEvent.click(card("Keyboard").getByRole("button", { name: "Keyboard shortcuts" }));
    expect(await screen.findByRole("dialog", { name: "Keyboard" })).toBeInTheDocument();
  });

  it("shows the version's first twelve characters and copies all forty", async () => {
    const full = "0123456789abcdef0123456789abcdef01234567";
    release(full);
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    mount(NO_SERVICE);
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    const about = card("About this console");
    expect(about.getByText("0123456789ab")).toBeInTheDocument();
    await userEvent.click(about.getByRole("button", { name: "Copy version" }));
    expect(writeText).toHaveBeenCalledWith(full);
    expect(await screen.findByText("Version copied.")).toBeInTheDocument();
  });

  it("says when the build records no version, and offers no copy", async () => {
    release("");
    mount(NO_SERVICE);
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    const about = card("About this console");
    expect(about.getByText("This build does not record its version.")).toBeInTheDocument();
    expect(about.queryByRole("button", { name: "Copy version" })).toBeNull();
  });

  it("lists the console's words exactly as the term list holds them, with one Uncertain entry", async () => {
    mount(NO_SERVICE);
    await screen.findByRole("heading", { level: 1, name: "Help & support" });
    const words = card("Words this console uses");
    expect(words.getAllByRole("term").map((term) => term.textContent)).toEqual(TERMS.map((entry) => entry.term));
    expect(words.getAllByRole("definition").map((meaning) => meaning.textContent)).toEqual(TERMS.map((entry) => entry.meaning));
    expect(TERMS.filter((entry) => entry.term.startsWith("Uncertain"))).toHaveLength(1);
  });
});
