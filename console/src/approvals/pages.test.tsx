// SPDX-License-Identifier: AGPL-3.0-only
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { SessionSummary } from "../lib/session";
import { deadline } from "../lib/time";
import { renderPage } from "../test/page";

/** A page under test, once the router has rendered the detail's title. */
async function page(ui: ReactNode, session: SessionSummary) {
  const rendered = renderPage(ui, session);
  await screen.findAllByRole("heading", { level: 2 });
  return rendered;
}
import { DetailView } from "./DetailView";
import {
  ADMIN,
  APPROVAL,
  APPROVER,
  detail,
  gateway,
  HOSTILE,
  item,
  list,
  OTHER,
  SPACE_X,
  SPACE_Y,
  routed,
  TARGET,
} from "./fixtures";
import { Queue } from "./Queue";

const NOW = Date.parse("2026-09-19T14:10:00Z");

function desktop() {
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
}

function views(seen: { method: string; path: string; query: URLSearchParams }[]): string[] {
  return seen.filter((r) => r.method === "GET" && r.path === "/api/console/v1/approvals").map((r) => r.query.get("view") ?? "");
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("the view lives in the address (#678)", () => {
  beforeEach(desktop);

  it("opens the view a link names, pushes a chip's view and returns to it on Back", async () => {
    const seen = gateway({ "GET /api/console/v1/approvals": list([]) });
    const { router, history } = routed("/approvals?view=lapsed", APPROVER);
    const lapsed = await screen.findByRole("button", { name: /^Lapsed/ });
    expect(lapsed).toHaveAttribute("aria-pressed", "true");
    await waitFor(() => {
      expect(views(seen)).toContain("lapsed");
    });
    const decided = screen.getByRole("button", { name: /^Decided today/ });
    await userEvent.click(decided);
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ view: "decided" });
    });
    expect(screen.getByRole("button", { name: /^Decided today/ })).toHaveAttribute("aria-pressed", "true");
    // A view is not a change of page: the keyboard stays on the chip.
    expect(document.activeElement).toBe(screen.getByRole("button", { name: /^Decided today/ }));
    history.back();
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ view: "lapsed" });
    });
    expect(screen.getByRole("button", { name: /^Lapsed/ })).toHaveAttribute("aria-pressed", "true");
  });

  it("never shows the default in the address", async () => {
    gateway({ "GET /api/console/v1/approvals": list([]) });
    const { router } = routed("/approvals?view=lapsed", APPROVER);
    await userEvent.click(await screen.findByRole("button", { name: /^Pending/ }));
    await waitFor(() => {
      expect(router.state.location.href).toBe("/approvals");
    });
  });

  it("reads Pending for a view this session cannot use, and drops it without a new entry", async () => {
    const seen = gateway({ "GET /api/console/v1/approvals": list([]) });
    const { router, history } = routed("/approvals?view=others", APPROVER);
    const before = history.length;
    expect(await screen.findByRole("button", { name: /^Pending/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.queryByRole("button", { name: /^Waiting on others/ })).toBeNull();
    await waitFor(() => {
      expect(router.state.location.search).toEqual({});
    });
    expect(history.length).toBe(before);
    expect(views(seen)).not.toContain("others");
  });

  it("opens a row with the view in its link", async () => {
    gateway({
      "GET /api/console/v1/approvals": list([]),
      "GET /api/console/v1/approvals?view=others": list([item({ reviewers: 1, reviewers_left: 1, assigned_to_you: false })]),
    });
    routed("/approvals?view=others", ADMIN);
    const row = await screen.findByRole("link", { name: /Isolate endpoint/ });
    expect(row).toHaveAttribute("href", `/approvals/${APPROVAL}?view=others`);
  });
});

describe("Waiting on others (#678)", () => {
  beforeEach(desktop);

  it("says why an administrator's queue is empty and offers both ways on", async () => {
    gateway({
      "GET /api/console/v1/approvals": list([]),
      "GET /api/console/v1/approvals?view=others": list([
        item({ reviewers: 1, reviewers_left: 1, assigned_to_you: false }),
        item({ approval_id: OTHER, reviewers: 0, reviewers_left: 0, assigned_to_you: false }),
      ]),
    });
    const { router } = routed("/approvals", ADMIN);
    expect(await screen.findByRole("button", { name: "Waiting on others 2" })).toBeInTheDocument();
    expect(await screen.findByText("You are not assigned to review any of the 2 requests waiting here.")).toBeInTheDocument();
    expect(screen.getByText(/Administrators review only what they are assigned to/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "See who reviews" })).toHaveAttribute("href", "/approvers");
    await userEvent.click(screen.getByRole("button", { name: "Show waiting on others" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ view: "others" });
    });
    const rows = await screen.findAllByRole("link", { name: /Isolate endpoint/ });
    expect(rows).toHaveLength(2);
  });

  it("says nothing is waiting when nothing is waiting on anyone", async () => {
    gateway({ "GET /api/console/v1/approvals": list([]) });
    routed("/approvals", ADMIN);
    expect(await screen.findByRole("button", { name: "Waiting on others 0" })).toBeInTheDocument();
    expect(screen.getByText("Nothing is waiting for you.")).toBeInTheDocument();
  });

  it("never asks an approver's gateway for others", async () => {
    const seen = gateway({ "GET /api/console/v1/approvals": list([]) });
    routed("/approvals", APPROVER);
    expect(await screen.findByText("Nothing is waiting for you.")).toBeInTheDocument();
    expect(views(seen)).not.toContain("others");
  });

  it("gives each row its quorum so far and who can decide it", async () => {
    const { container } = render(
      <RoutedRows
        items={[
          item({ reviewers: 1, reviewers_left: 1, assigned_to_you: false }),
          item({ approval_id: OTHER, reviewers: 0, reviewers_left: 0, assigned_to_you: false }),
          item({ approval_id: "4b1e90c2-0000-4000-8000-00000000000c", required: 2, recorded: 0, reviewers: 1, reviewers_left: 1 }),
        ]}
      />,
    );
    const rows = await screen.findAllByRole("link");
    const [first, second] = rows;
    if (first === undefined || second === undefined) throw new Error("Rows missing");
    expect(first).toHaveTextContent("0 of 1 approvals · 1 assigned");
    expect(within(second).getByText("No one can approve this")).toHaveClass("tone-deny");
    expect(rows[2]).toHaveTextContent("0 of 2 approvals · Cannot reach the quorum");
    // Counting down, as Pending does.
    expect(container.querySelectorAll(".queue-left")).toHaveLength(3);
  });
});

function RoutedRows({ items }: { items: ReturnType<typeof item>[] }) {
  const root = createRootRoute({ component: () => <Outlet /> });
  const index = createRoute({ getParentRoute: () => root, path: "/", component: () => <Queue items={items} view="others" now={NOW} emptyTitle="Nothing" /> });
  const one = createRoute({ getParentRoute: () => root, path: "/approvals/$approvalId", component: () => <p>opened</p> });
  const router = createRouter({ routeTree: root.addChildren([index, one]), history: createMemoryHistory({ initialEntries: ["/"] }) });
  return <RouterProvider router={router} />;
}

describe("the Waiting panel (#678)", () => {
  const waiting = (changes: Parameters<typeof detail>[0] = {}) =>
    detail({
      reviewing: false,
      continuation: null,
      item: item({ reviewers: 1, reviewers_left: 1, assigned_to_you: false }),
      ...changes,
    });

  it("replaces the decision bar for an administrator who is not assigned", async () => {
    await page(<DetailView detail={waiting()} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, ADMIN);
    expect(await screen.findByRole("heading", { name: "You are not assigned to decide this request." })).toBeInTheDocument();
    expect(screen.getByText("1 person is assigned. 0 of 1 approvals recorded.")).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Your decision" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Approve\b/ })).toBeNull();
  });

  it("says why nobody can decide, and why the quorum cannot be reached", async () => {
    const { unmount } = await page(
      <DetailView detail={waiting({ item: item({ reviewers: 0, reviewers_left: 0 }), space: { space_id: SPACE_X, name: "Customer X" } })} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />,
      ADMIN,
    );
    expect(
      await screen.findByText("No one can approve this: nobody who can open this request holds a review assignment for this action and target in Customer X."),
    ).toBeInTheDocument();
    unmount();
    await page(
      <DetailView detail={waiting({ item: item({ required: 2, recorded: 0, reviewers: 1, reviewers_left: 1 }) })} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />,
      ADMIN,
    );
    expect(
      await screen.findByText("This request cannot reach its quorum: 0 of 2 approvals recorded and 1 assigned person has not decided."),
    ).toBeInTheDocument();
  });

  it("says Waiting for you only to someone who can decide", async () => {
    const { unmount } = await page(<DetailView detail={waiting()} now={NOW} phone deciding={false} onDecide={vi.fn()} />, ADMIN);
    expect(screen.getByText("Waiting for a person")).toBeInTheDocument();
    expect(screen.queryByText("Waiting for you")).toBeNull();
    unmount();
    await page(<DetailView detail={detail()} now={NOW} phone deciding={false} onDecide={vi.fn()} />, APPROVER);
    expect(screen.getByText("Waiting for you")).toBeInTheDocument();
  });

  it("says Waiting for you at every width, as it does on a phone (#678)", async () => {
    await page(<DetailView detail={detail()} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, APPROVER);
    expect(screen.getByText("Waiting for you")).toBeInTheDocument();
    expect(screen.queryByText("Waiting for a person")).toBeNull();
  });

  it.each([
    ["the server read it as lapsed", { status: "expired" as const, continuation: null }],
    ["its deadline passed after the last read", {}],
  ])("reads a lapsed approval as lapsed and never as waiting, where %s (#678)", async (_case, changes) => {
    const past = "2026-09-19T14:09:00Z";
    await page(
      <DetailView
        detail={detail({ ...changes, item: item({ expires_at: past }), deadline: { ...detail().deadline, expires_at: past } })}
        now={NOW}
        phone={false}
        deciding={false}
        onDecide={vi.fn()}
      />,
      APPROVER,
    );
    expect(screen.getByText("Lapsed")).toHaveClass("badge-stale");
    expect(document.body.textContent).not.toMatch(/waiting for/i);
    expect(screen.getByText(/^Execution:/).closest("p")).toHaveTextContent(
      "Execution: The approval lapsed, so this request cannot run. No provider execution is recorded.",
    );
  });

  it("renders a hostile target and label as text in the panel and the dialog", async () => {
    gateway({});
    await page(
      <DetailView detail={waiting({ item: item({ target: HOSTILE, action_label: HOSTILE, reviewers: 1, reviewers_left: 1 }) })} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />,
      ADMIN,
    );
    await userEvent.click((await screen.findByRole("button", { name: "Assign yourself to review this" })));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getAllByText(HOSTILE).length).toBeGreaterThan(0);
    expect(document.querySelector("img")).toBeNull();
  });

  it("asks to switch to the approval's space first, and says when the role cannot assign", async () => {
    const twoSpaces: SessionSummary = { ...ADMIN, spaces: 2, space: { id: SPACE_Y, name: "Customer Y", archived: false } };
    const { unmount } = await page(
      <DetailView detail={waiting({ space: { space_id: SPACE_X, name: "Customer X" } })} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />,
      twoSpaces,
    );
    expect((await screen.findByRole("button", { name: "Switch to Customer X to assign yourself" }))).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Assign yourself to review this" })).toBeNull();
    unmount();
    const narrow: SessionSummary = { ...ADMIN, spaces: 2, space: { id: SPACE_X, name: "Customer X", archived: false }, permissions: ["console.read"] };
    await page(
      <DetailView detail={waiting({ space: { space_id: SPACE_X, name: "Customer X" } })} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />,
      narrow,
    );
    expect((await screen.findByRole("button", { name: "Assign yourself to review this" }))).toBeDisabled();
    expect(await screen.findByText(/cannot assign reviewers\./)).toHaveTextContent("Your role in Customer X cannot assign reviewers.");
  });

  it("says what assigning does, and that it moves a review held in another space", async () => {
    gateway({});
    const { unmount } = await page(<DetailView detail={waiting()} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, ADMIN);
    await userEvent.click((await screen.findByRole("button", { name: "Assign yourself to review this" })));
    let dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("Assign yourself to review Isolate endpoint on ws25 in Synthetic SOC?");
    expect(dialog).toHaveTextContent("If you use a second factor and last verified it more than 30 minutes ago, you will be asked for it.");
    expect(within(dialog).getByRole("button", { name: "Assign me" })).toBeInTheDocument();
    unmount();
    await page(
      <DetailView
        detail={waiting({ space: { space_id: SPACE_X, name: "Customer X" }, your_review_elsewhere: { space_id: SPACE_Y, name: "Customer Y" } })}
        now={NOW}
        phone={false}
        deciding={false}
        onDecide={vi.fn()}
      />,
      ADMIN,
    );
    await userEvent.click((await screen.findByRole("button", { name: "Assign yourself to review this" })));
    dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(
      "This moves your review of Isolate endpoint on ws25 from Customer Y to Customer X. You will no longer review it in Customer Y.",
    );
    expect(within(dialog).getByRole("button", { name: "Move my review to Customer X" })).toBeInTheDocument();
  });

  it.each([
    [true, "You can now decide this request."],
    [false, "Your assignment is recorded, but your access does not let you decide here."],
  ])("assigns the reader to this one request and says whether they can now decide (%s)", async (decidable, said) => {
    const seen = gateway({
      [`POST /api/console/v1/people/${ADMIN.person.id ?? ""}/scopes/assign`]: { body: {} },
      [`GET /api/console/v1/approvals/${APPROVAL}`]: { body: decidable ? detail() : waiting() },
    });
    await page(<DetailView detail={waiting()} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, ADMIN);
    await userEvent.click((await screen.findByRole("button", { name: "Assign yourself to review this" })));
    await userEvent.click(await screen.findByRole("button", { name: "Assign me" }));
    expect(await screen.findByText(said)).toBeInTheDocument();
    const posts = seen.filter((r) => r.method === "POST");
    expect(posts).toHaveLength(1);
    expect(posts[0]?.path).toBe(`/api/console/v1/people/${ADMIN.person.id ?? ""}/scopes/assign`);
    expect(posts[0]?.body).toEqual({ target: TARGET, action: "endpoint.isolate" });
  });

  it.each([
    ["INVALID_SPACE", "Choose Synthetic SOC before assigning yourself."],
    ["INVALID_ACTION", "This action cannot be assigned for review."],
    ["FORBIDDEN", "Your role in Synthetic SOC cannot assign reviewers."],
    ["SOMETHING_NEW", "Your assignment was not recorded. Try again."],
  ])("answers %s in fixed copy, never the server's text", async (code, copy) => {
    gateway({
      [`POST /api/console/v1/people/${ADMIN.person.id ?? ""}/scopes/assign`]: { status: 400, body: { code, detail: "server words" } },
    });
    await page(<DetailView detail={waiting()} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, ADMIN);
    await userEvent.click((await screen.findByRole("button", { name: "Assign yourself to review this" })));
    await userEvent.click(await screen.findByRole("button", { name: "Assign me" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(copy);
    expect(screen.queryByText(/server words/)).toBeNull();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });
});

describe("the approval link in the Waiting panel (#678)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function copied(linkPath: string, writeText: (text: string) => Promise<void>) {
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const waiting = detail({ link_path: linkPath, reviewing: false, continuation: null, item: item({ reviewers: 1, reviewers_left: 1 }) });
    await page(<DetailView detail={waiting} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, ADMIN);
    await userEvent.click((await screen.findByRole("button", { name: "Copy approval link" })));
  }

  it("copies the server's path on this page's own origin", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    const workspace = `/workspaces/7f8e9d0c-0000-4000-8000-000000000003/approvals/${APPROVAL}`;
    await copied(workspace, writeText);
    expect(writeText).toHaveBeenCalledWith(window.location.origin + workspace);
    expect(await screen.findByText(/Link copied\./)).toBeInTheDocument();
  });

  it.each([`//evil.example/approvals/${APPROVAL}`, `/approvals/${OTHER}`, "javascript:alert(1)"])(
    "replaces a path outside the grammar or for another approval: %s",
    async (linkPath) => {
      const writeText = vi.fn(() => Promise.resolve());
      await copied(linkPath, writeText);
      expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/approvals/${APPROVAL}`);
    },
  );

  it("shows the link as text where the clipboard refuses", async () => {
    await copied(`/approvals/${APPROVAL}`, () => Promise.reject(new Error("denied")));
    const shown = await screen.findByText(`${window.location.origin}/approvals/${APPROVAL}`);
    expect(shown.parentElement).toHaveTextContent(`Copy this link: ${window.location.origin}/approvals/${APPROVAL}`);
    expect(document.body.textContent).not.toMatch(/address bar/i);
  });
});

describe("the decision bar (#678)", () => {
  const session: SessionSummary = APPROVER;

  it("names both choices from their visible word, the target and the workspace", async () => {
    await page(<DetailView detail={detail()} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, session);
    const approve = screen.getByRole("button", { name: "Approve Isolate endpoint · ws25 in Synthetic SOC" });
    const refuse = screen.getByRole("button", { name: "Refuse. Nothing is sent to ws25 in Synthetic SOC" });
    expect(approve).toHaveClass("btn-allow");
    expect(refuse).toHaveClass("btn-danger");
    for (const button of [approve, refuse]) {
      expect(button).not.toHaveClass("btn-primary");
      expect(button).not.toHaveAttribute("aria-label");
    }
  });

  it("restates the effect, the deadline in its one form and the quorum", async () => {
    const { container } = await page(<DetailView detail={detail()} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, session);
    const facts = container.querySelector(".decision-facts");
    expect(facts).toHaveTextContent(
      `Reversible by Lift endpoint isolation · ${deadline("2099-01-01T00:00:00Z", NOW)} · 0 of 1 approvals recorded`,
    );
    const irreversible = detail({ effect: { ...detail().effect, reversible: false, reversed_by: null } });
    const again = await page(<DetailView detail={irreversible} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, session);
    expect(again.container.querySelector(".decision-facts")).toHaveTextContent(/^No catalog action reverses this · /);
  });

  it("names the workspace where it can be ambiguous, and always on a phone", async () => {
    const one = await page(<DetailView detail={detail()} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, session);
    expect(one.container.querySelector(".decision-scope")).toBeNull();
    one.unmount();
    const switching = await page(<DetailView detail={detail()} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, { ...session, canSwitchWorkspaces: true });
    expect(switching.container.querySelector(".decision-scope")).toHaveTextContent("Deciding in Synthetic SOC");
    switching.unmount();
    const spaced = await page(
      <DetailView detail={detail({ space: { space_id: SPACE_X, name: "Customer X" } })} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />,
      { ...session, spaces: 2 },
    );
    expect(spaced.container.querySelector(".decision-scope")).toHaveTextContent("Deciding in Synthetic SOC · Customer X");
    expect(spaced.container.querySelector(".decision-space")).toHaveTextContent("· Customer X");
    spaced.unmount();
    const onPhone = await page(<DetailView detail={detail()} now={NOW} phone deciding={false} onDecide={vi.fn()} />, session);
    expect(onPhone.container.querySelector(".decision-scope")).toHaveTextContent("Deciding in Synthetic SOC");
    expect(onPhone.container.querySelector(".decision-space")).toBeNull();
  });

  it("names the workspace on the eyebrow for every reader", async () => {
    const { container } = await page(<DetailView detail={detail({ status: "settled", continuation: null })} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, session);
    expect(container.querySelector(".detail-eyebrow .detail-workspace")).toHaveTextContent("Synthetic SOC");
  });

  it("disables both while a decision is on its way", async () => {
    await page(<DetailView detail={detail()} now={NOW} phone={false} deciding onDecide={vi.fn()} />, session);
    expect(screen.getByRole("button", { name: /^Approve\b/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /^Refuse\b/ })).toBeDisabled();
  });
});
