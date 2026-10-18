// SPDX-License-Identifier: AGPL-3.0-only
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clearDrafts, restoreApprovalDraft, saveApprovalDraft, sweepDrafts } from "../lib/drafts";
import { KEPT_FIELD } from "../lib/kept";
import { SessionContext, type SessionSummary } from "../lib/session";
import { SignOut } from "../shell/SignOut";
import { renderPage } from "../test/page";
import { DetailView } from "./DetailView";
import { APPROVAL, APPROVER, detail, gateway, item, list, OTHER, routed } from "./fixtures";

const NOW = Date.parse("2026-09-19T14:10:00Z");
const KEY = `eb:draft:approval:${APPROVAL}`;
const LATER = "2026-09-19T14:19:31Z";
// The routed page counts from the gateway's clock, which this stand-in does not set.
const FAR = "2099-01-01T00:00:00Z";

function stored(key = KEY): unknown {
  const raw = window.sessionStorage.getItem(key);
  return raw === null ? null : (JSON.parse(raw) as unknown);
}

async function open(onDecide = vi.fn(), session: SessionSummary = APPROVER, now = NOW) {
  const page = renderPage(
    <DetailView detail={detail({ item: item({ expires_at: LATER }) })} now={now} phone={false} deciding={false} onDecide={onDecide} />,
    session,
  );
  await screen.findAllByRole("heading", { level: 2 });
  return page;
}

/** A refusal as the generated client throws it: the body's code, and its fields. */
function refusal(code: string, fields?: string[]): Error {
  return Object.assign(new Error(code), { code, detail: "x", ...(fields === undefined ? {} : { fields }) });
}

function field(): HTMLInputElement {
  return screen.getByLabelText("Comment for the audit record (optional)");
}

beforeEach(() => {
  window.sessionStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("the approval comment survives signing in again (#678)", () => {
  it("marks the page as one that keeps what is typed while the comment field is on it", async () => {
    await open();
    expect(field().closest(`[${KEPT_FIELD}]`)).not.toBeNull();
  });

  it("keeps what is typed, bound to the person and the deadline, and forgets an empty field", async () => {
    await open();
    await userEvent.type(field(), "Checked with on-call");
    expect(stored()).toEqual({ p: APPROVER.person.id, x: LATER, t: "Checked with on-call" });
    await userEvent.clear(field());
    expect(stored()).toBeNull();
  });

  it("restores the comment for the same person before the deadline, and says so", async () => {
    saveApprovalDraft(APPROVAL, APPROVER.person.id, LATER, "Kept text");
    await open();
    expect(field()).toHaveValue("Kept text");
    expect(await screen.findByText("Your comment was kept.")).toBeInTheDocument();
  });

  it.each([
    ["another person", { ...APPROVER, person: { ...APPROVER.person, id: "someone-else" } }, NOW],
    ["a time after the deadline", APPROVER, Date.parse(LATER) + 1000],
  ])("restores nothing for %s, and forgets it", (_case, session, now) => {
    saveApprovalDraft(APPROVAL, APPROVER.person.id, LATER, "Kept text");
    expect(restoreApprovalDraft(APPROVAL, session.person.id, now)).toBeNull();
    expect(stored()).toBeNull();
  });

  it("forgets the comment and empties the field once the server accepts the decision", async () => {
    const onDecide = vi.fn(() => Promise.resolve({}));
    await open(onDecide);
    await userEvent.type(field(), "Approve it");
    await userEvent.click(screen.getByRole("button", { name: /^Approve\b/ }));
    expect(onDecide).toHaveBeenCalledWith("APPROVE", "Approve it");
    await waitFor(() => {
      expect(field()).toHaveValue("");
    });
    expect(stored()).toBeNull();
  });

  it.each(["APPROVAL_EXPIRED", "ALREADY_DECIDED", "NOT_FOUND", "CONFLICT"])(
    "forgets the comment when %s ends the approval",
    async (code) => {
      await open(vi.fn(() => Promise.reject(refusal(code))));
      await userEvent.type(field(), "Too late");
      await userEvent.click(screen.getByRole("button", { name: /^Approve\b/ }));
      await waitFor(() => {
        expect(stored()).toBeNull();
      });
    },
  );

  it("keeps the comment when the gateway is only unavailable", async () => {
    await open(vi.fn(() => Promise.reject(refusal("UNAVAILABLE"))));
    await userEvent.type(field(), "Try again");
    await userEvent.click(screen.getByRole("button", { name: /^Approve\b/ }));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(stored()).toEqual({ p: APPROVER.person.id, x: LATER, t: "Try again" });
  });

  it("forgets secret-shaped text the kernel refused, keeps it on screen and stops keeping it", async () => {
    await open(vi.fn(() => Promise.reject(refusal("INVALID_BODY", ["comment"]))));
    await userEvent.type(field(), "Words the kernel refused");
    await userEvent.click(screen.getByRole("button", { name: /^Refuse\b/ }));
    await waitFor(() => {
      expect(stored()).toBeNull();
    });
    expect(field()).toHaveValue("Words the kernel refused");
    await userEvent.type(field(), "b");
    expect(stored()).toBeNull();
    await userEvent.clear(field());
    await userEvent.type(field(), "Plain words");
    expect(stored()).toEqual({ p: APPROVER.person.id, x: LATER, t: "Plain words" });
  });

  it("keeps nothing without the person's id, and breaks nothing when storage throws", async () => {
    const { unmount } = await open(vi.fn(), { ...APPROVER, person: { label: "B. Chen", detail: "", initials: "" } });
    await userEvent.type(field(), "Unbound");
    expect(stored()).toBeNull();
    unmount();
    const throwing = {
      getItem: () => { throw new Error("denied"); },
      setItem: () => { throw new Error("denied"); },
      removeItem: () => { throw new Error("denied"); },
      key: () => { throw new Error("denied"); },
      clear: () => undefined,
      get length(): number { throw new Error("denied"); },
    };
    vi.stubGlobal("sessionStorage", throwing);
    await open();
    await userEvent.type(field(), "Still typed");
    expect(field()).toHaveValue("Still typed");
    expect(() => {
      clearDrafts();
      sweepDrafts();
    }).not.toThrow();
  });

  it("sweeps drafts whose approval has ended", () => {
    saveApprovalDraft(APPROVAL, APPROVER.person.id, LATER, "Old");
    saveApprovalDraft(OTHER, APPROVER.person.id, "2099-01-01T00:00:00Z", "Current");
    sweepDrafts(Date.parse(LATER) + 1);
    expect(stored()).toBeNull();
    expect(stored(`eb:draft:approval:${OTHER}`)).not.toBeNull();
  });

  it("forgets every draft when the person signs out, then posts the form", async () => {
    saveApprovalDraft(APPROVAL, APPROVER.person.id, LATER, "One");
    saveApprovalDraft(OTHER, APPROVER.person.id, LATER, "Two");
    const posted = vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => undefined);
    render(
      <SessionContext.Provider value={APPROVER}>
        <SignOut />
      </SessionContext.Provider>,
    );
    const form = screen.getByRole("button", { name: "Sign out" }).closest("form");
    if (form === null) throw new Error("No form");
    fireEvent.submit(form);
    await waitFor(() => {
      expect(posted).toHaveBeenCalledTimes(1);
    });
    expect(stored()).toBeNull();
    expect(stored(`eb:draft:approval:${OTHER}`)).toBeNull();
  });
});

describe("one comment field per approval (#678)", () => {
  it("never carries text typed on one approval to another's field or decision", async () => {
    vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
    vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
    const first = item({ expires_at: FAR });
    const second = item({ approval_id: OTHER, target: "ws26", expires_at: FAR });
    const seen = gateway({
      "GET /api/console/v1/approvals": list([first, second]),
      [`GET /api/console/v1/approvals/${APPROVAL}`]: { body: detail({ item: first }) },
      [`GET /api/console/v1/approvals/${OTHER}`]: { body: detail({ item: second, link_path: `/approvals/${OTHER}` }) },
      [`POST /api/console/v1/approvals/${OTHER}/decision`]: {
        body: { approval_id: OTHER, approval_state: "APPROVED", decision: "APPROVE", execution_state: "EXECUTING", recorded: 1, required: 1 },
      },
    });
    routed(`/approvals/${APPROVAL}`, APPROVER);
    expect(await screen.findByRole("heading", { level: 2, name: "ws25" })).toBeInTheDocument();
    await userEvent.type(field(), "About ws25");
    await userEvent.click(screen.getByRole("link", { name: /ws26/ }));
    expect(await screen.findByRole("heading", { level: 2, name: "ws26" })).toBeInTheDocument();
    expect(field()).toHaveValue("");
    expect(stored()).toEqual({ p: APPROVER.person.id, x: FAR, t: "About ws25" });
    expect(stored(`eb:draft:approval:${OTHER}`)).toBeNull();
    await userEvent.type(field(), "About ws26");
    await userEvent.click(screen.getByRole("button", { name: /^Approve\b/ }));
    await waitFor(() => {
      expect(seen.some((request) => request.method === "POST")).toBe(true);
    });
    const post = seen.find((request) => request.method === "POST");
    expect(post?.body).toEqual({ decision: "APPROVE", comment: "About ws26", continuation: "token" });
  });
});
