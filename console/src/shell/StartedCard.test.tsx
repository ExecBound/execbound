// SPDX-License-Identifier: AGPL-3.0-only
import { useMutation } from "@tanstack/react-query";
import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { hideSetupCard, showSetupCard } from "../components/welcome/setup";
import { PLACEHOLDER, type SessionSummary } from "../lib/session";
import { answerWith, heldReply, renderPage, settle } from "../test/page";
import { CHOOSE_SPACE, SETUP, setupView } from "../test/setup-view";
import { FOOTER } from "./navigation";
import StartedFoot, { StartedCard, useSetupProgress } from "./StartedCard";

const TENANT = "11111111-1111-4111-8111-111111111111";
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", tenant: { id: TENANT, name: "Acme", detail: "" } };

/** The card where it is a card, else the plain row's stand-in, as the sidebar chooses. */
function Probe({ rail = false }: { rail?: boolean }) {
  const progress = useSetupProgress(true);
  return progress.line !== null ? <StartedCard progress={progress} rail={rail} /> : <p>Getting started row</p>;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe("the sidebar's Getting started card (UX11, #678)", () => {
  it("says how many required steps are done and which is next, with a bar", async () => {
    answerWith({ [`GET ${SETUP}`]: { body: setupView({ policy: "done", agent_key: "done", first_request: "done" }) } });
    const { container } = renderPage(<Probe />, ADMIN);
    expect(await screen.findByText("3 of 5 · Next: Choose a reviewer")).toBeInTheDocument();
    const fill = container.querySelector<HTMLElement>(".started-fill");
    expect(fill?.style.width).toBe("60%");
    expect(container.querySelector(".started-track")).toHaveAttribute("aria-hidden", "true");
    expect(screen.getByRole("link")).toHaveAttribute("href", "/welcome");
  });

  it("asks for a provider first while the Space has no connection", async () => {
    answerWith({ [`GET ${SETUP}`]: { body: setupView({}, { connected: false }) } });
    renderPage(<Probe />, ADMIN);
    expect(await screen.findByText("0 of 5 · Next: Connect a provider")).toBeInTheDocument();
  });

  it("says approvals need Enforcing, and stays a card, where that is all that is left", async () => {
    answerWith({
      [`GET ${SETUP}`]: { body: setupView({ policy: "done", agent_key: "done", first_request: "done", reviewer: "done", first_decision: "needs_enforcing" }) },
    });
    renderPage(<Probe />, ADMIN);
    expect(await screen.findByText("4 of 5 · Approvals need Enforcing")).toBeInTheDocument();
  });

  it("is titled with its count in the collapsed rail", async () => {
    answerWith({ [`GET ${SETUP}`]: { body: setupView({ policy: "done", agent_key: "done", first_request: "done" }) } });
    renderPage(<Probe rail />, ADMIN);
    expect(await screen.findByRole("link")).toHaveAttribute("title", "Getting started: 3 of 5");
  });

  it("is the plain row once every required step is done", async () => {
    answerWith({
      [`GET ${SETUP}`]: { body: setupView({ policy: "done", agent_key: "done", first_request: "done", reviewer: "not_applicable", first_decision: "not_applicable" }) },
    });
    renderPage(<Probe />, ADMIN);
    await settle();
    expect(await screen.findByText("Getting started row")).toBeInTheDocument();
  });

  it("is the plain row while loading, on a failed read and where no Space is chosen", async () => {
    const held = heldReply();
    answerWith({ [`GET ${SETUP}`]: () => held.reply });
    const loading = renderPage(<Probe />, ADMIN);
    expect(await screen.findByText("Getting started row")).toBeInTheDocument();
    loading.unmount();
    answerWith({});
    const failed = renderPage(<Probe />, ADMIN);
    await settle();
    expect(await screen.findByText("Getting started row")).toBeInTheDocument();
    failed.unmount();
    answerWith({ [`GET ${SETUP}`]: { body: CHOOSE_SPACE } });
    renderPage(<Probe />, ADMIN);
    await settle();
    expect(await screen.findByText("Getting started row")).toBeInTheDocument();
  });

  it("is the plain row where this person hid it in this browser, and follows a change", async () => {
    localStorage.setItem(`execbound.setup-card.hidden.${TENANT}`, "1");
    answerWith({ [`GET ${SETUP}`]: { body: setupView() } });
    renderPage(<Probe />, ADMIN);
    await settle();
    expect(await screen.findByText("Getting started row")).toBeInTheDocument();
    act(() => {
      showSetupCard(TENANT);
    });
    expect(await screen.findByText("0 of 5 · Next: Activate a policy")).toBeInTheDocument();
    act(() => {
      hideSetupCard(TENANT);
    });
    expect(await screen.findByText("Getting started row")).toBeInTheDocument();
  });

  it("shows where browser storage throws", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    answerWith({ [`GET ${SETUP}`]: { body: setupView() } });
    renderPage(<Probe />, ADMIN);
    expect(await screen.findByText("0 of 5 · Next: Activate a policy")).toBeInTheDocument();
  });

  it("asks nothing where the footer offers no Getting started", async () => {
    const seen = answerWith({ [`GET ${SETUP}`]: { body: setupView() } });
    function Off() {
      useSetupProgress(false);
      return null;
    }
    renderPage(<Off />, ADMIN);
    await settle();
    expect(seen).toEqual([]);
  });
});

describe("reading the setup again after a change (UX11, #678)", () => {
  const ENTRIES = FOOTER.filter((entry) => entry.to === "/welcome");

  /** A change the console makes, standing for any of them: a key issued, a decision, the mode. */
  function Change({ fails = false }: { fails?: boolean }) {
    const change = useMutation({
      mutationFn: () => (fails ? Promise.reject(new Error("refused")) : Promise.resolve({ token: "shown-once" })),
      retry: 0,
    });
    return <button type="button" onClick={() => { change.mutate(); }}>Change</button>;
  }

  function setupReads(seen: { method: string; path: string }[]): number {
    return seen.filter((request) => request.method === "GET" && request.path === SETUP).length;
  }

  it("reads the setup again once any change succeeds, and not after one that fails", async () => {
    const seen = answerWith({ [`GET ${SETUP}`]: { body: setupView() } });
    renderPage(<><StartedFoot rail={false} entries={ENTRIES} item={(entry) => <li key={entry.to}>{entry.label}</li>} /><Change /><Change fails /></>, ADMIN);
    expect(await screen.findByText("0 of 5 · Next: Activate a policy")).toBeInTheDocument();
    const before = setupReads(seen);
    const [succeeds, fails] = screen.getAllByRole("button", { name: "Change" });
    if (succeeds === undefined || fails === undefined) throw new Error("No changes");
    await userEvent.click(fails);
    await settle();
    expect(setupReads(seen)).toBe(before);
    await userEvent.click(succeeds);
    await waitFor(() => {
      expect(setupReads(seen)).toBe(before + 1);
    });
  });
});
