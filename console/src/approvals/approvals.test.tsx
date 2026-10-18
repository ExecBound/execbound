// SPDX-License-Identifier: AGPL-3.0-only
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, onTestFinished, vi } from "vitest";

import type { ApprovalDetail, ApprovalItem } from "../api/types.gen";
import { withEdition } from "../test/edition";
import { answerWith, renderPage } from "../test/page";
import { ApprovalsPage } from "./ApprovalsPage";
import { refusalCode, refusalText, stateBadge, statusNotice } from "./copy";
import { DetailView, requester } from "./DetailView";
import { focusDetailNext, takeDetailFocus } from "./focus";
import { Queue } from "./Queue";
import {
  ADMIN as ADMIN_SESSION,
  APPROVAL as FIXTURE_APPROVAL,
  APPROVER as APPROVER_SESSION,
  detail as fixtureDetail,
  gateway,
  item as fixtureItem,
  list,
  routed,
} from "./fixtures";
import { createSequence } from "../shell/Keyboard";
import { age, secondsSince, secondsUntil, timeOfDay } from "./time";
import { setDeviceZoneForTests } from "../lib/time";

const NOW = Date.parse("2026-09-19T14:10:00Z");
const HOSTILE = "<img src=x onerror=alert(1)>";

function item(changes: Partial<ApprovalItem> = {}): ApprovalItem {
  return {
    request_ref: "EB-1042",
    external_case: null,
    approval_id: "4b1e90c2-0000-4000-8000-000000000001",
    execution_id: "5c2f91d3-0000-4000-8000-000000000002",
    action: "endpoint.isolate",
    action_label: "Isolate endpoint",
    target: "ws25",
    resource_class: "workstation",
    environment: "production",
    agent: { principal_id: "aaaaaaaa-0000-4000-8000-000000000003", label: "triage-agent-a", number: 3 },
    notified: null,
    created_at: "2026-09-19T14:07:31Z",
    expires_at: "2026-09-19T14:19:31Z",
    total_seconds: 720,
    deadline_clock: "approval deadline",
    approval_state: "PENDING",
    execution_state: "PENDING_APPROVAL",
    execution_state_label: "Held",
    required: 1,
    recorded: 0,
    mine: null,
    decided_at: null,
    ...changes,
  };
}

function detail(changes: Partial<ApprovalDetail> = {}): ApprovalDetail {
  return {
    item: item(),
    deliveries: [],
    related_requests: [],
    timeline: [],
    status: "pending",
    sentence: "Isolate endpoint on ws25, a production workstation, requested by triage-agent-a at 14:07:31 UTC.",
    plan_hash: "ab".repeat(32),
    canonical_target_id: "cccccccc-0000-4000-8000-000000000004",
    arguments: [],
    facts: [
      {
        name: "environment",
        value: "production",
        origin: "RESOLVED",
        source_kind: "inventory",
        source_object_id: "ws25",
        source_version: "r-7",
        permitted_writers: ["inventory"],
        observed_at: "2026-09-19T14:04:00Z",
        valid_until: "2026-09-19T14:34:00Z",
        age_seconds: 360,
      },
    ],
    obligations: [
      { id: "policy:policy0", kind: "policy", rule_id: "review-production", sentence: "Review endpoint.isolate when environment is production." },
    ],
    quorum: { required: 1, recorded: 0, decisions: [], mine: null },
    deadline: { created_at: "2026-09-19T14:07:31Z", expires_at: "2026-09-19T14:19:31Z", total_seconds: 720, clock: "approval deadline" },
    effect: {
      sentence: "If approved, ExecBound sends contain to mock_crowdstrike for ws25 once. Reversible by Lift endpoint isolation.",
      provider: "mock_crowdstrike",
      provider_operation: "contain",
      resource_version: "r-7",
      mapping_version: "map-v1",
      precondition: null,
      reversible: true,
      reversed_by: "Lift endpoint isolation",
    },
    limits: [],
    notices: [],
    mode: "ENFORCE",
    stop: null,
    space: null,
    reviewing: true,
    your_review_elsewhere: null,
    link_path: "/approvals/4b1e90c2-0000-4000-8000-000000000001",
    continuation: "token",
    server_time: "2026-09-19T14:10:00Z",
    ...changes,
  };
}

/** The nth element of a query's answer, or a failure that names it. */
function nth(elements: HTMLElement[], index: number): HTMLElement {
  const element = elements[index];
  if (element === undefined) throw new Error(`no element ${String(index)}`);
  return element;
}

function withRouter(element: React.ReactNode, initial = "/approvals") {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const list = createRoute({ getParentRoute: () => rootRoute, path: "/approvals", component: () => element });
  const one = createRoute({
    getParentRoute: () => rootRoute,
    path: "/approvals/$approvalId",
    component: () => <p>opened</p>,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([list, one]),
    history: createMemoryHistory({ initialEntries: [initial] }),
  });
  return <RouterProvider router={router} />;
}

const ZONE = "EDT";

/** Whether a printed time names its zone, or sits under a heading or caption that does. */
function namesItsZone(time: Element, zone: string): boolean {
  if (time.textContent.trim().endsWith(zone)) return true;
  for (let node = time.parentElement; node !== null; node = node.parentElement) {
    const label = node.querySelector(":scope > h2, :scope > h3, :scope > caption, :scope > .queue-caption");
    if (label?.textContent.includes(zone)) return true;
  }
  return false;
}


/** The shell's keyboard, which moves along a list's rows; removed after the test. */
function listKeys(): void {
  const handle = createSequence({ entries: [], navigate: vi.fn(), openShortcuts: vi.fn() });
  window.addEventListener("keydown", handle);
  onTestFinished(() => {
    window.removeEventListener("keydown", handle);
  });
}

describe("times in the viewer's zone", () => {
  afterEach(() => {
    setDeviceZoneForTests(undefined);
  });

  it("prints the request time in the viewer's zone and never labels a local time UTC", () => {
    setDeviceZoneForTests("America/New_York");
    const { container } = render(
      <DetailView
        detail={detail({
          item: item({ created_at: "2026-10-08T17:34:24Z", expires_at: "2099-01-01T00:00:00Z" }),
          status: "paused",
          continuation: null,
          stop: { stopped_at: "2026-10-08T17:36:00Z", reason: "Contain agent 7" },
          timeline: [{ at: "2026-10-08T17:34:24Z", kind: "transition", state: "PENDING_APPROVAL", sentence: "Held for a person.", actor: null }],
          quorum: {
            required: 2,
            recorded: 1,
            mine: null,
            decisions: [{ principal_id: "dddddddd-0000-4000-8000-000000000005", label: "B. Chen", kind: "HUMAN_APPROVER", number: 2, decision: "APPROVE", decided_at: "2026-10-08T17:35:02Z" }],
          },
        })}
        now={Date.parse("2026-10-08T17:40:00Z")}
        phone={false}
        deciding={false}
        onDecide={vi.fn()}
      />,
    );
    const sentence = container.querySelector(".detail-sentence");
    expect(sentence).toHaveTextContent("requested by triage-agent-a (Agent 3) at 2026-10-08 13:34:24 EDT");
    expect(screen.getByText("2026-10-08 13:34:24 EDT")).toHaveAttribute("title", "2026-10-08 17:34:24 UTC");
    expect(screen.getByRole("status")).toHaveTextContent("Stopped at 2026-10-08 13:36:00 EDT");
    expect(screen.getByText("2026-10-08 13:35:02 EDT")).toBeInTheDocument();
    expect(container.querySelector(".quorum")).toHaveTextContent("B. Chen: approved at 2026-10-08 13:35:02 EDT");
    // "UTC" may appear in a title, never as text beside a local time.
    expect(container.textContent).not.toContain("UTC");
    const times = [...container.querySelectorAll("time")];
    expect(times.length).toBeGreaterThanOrEqual(4);
    for (const time of times) expect(namesItsZone(time, ZONE), time.outerHTML).toBe(true);
    expect(screen.getByRole("heading", { name: "Timeline · EDT" })).toBeInTheDocument();
  });

  it("captions the queue with the zone its clock times are in", async () => {
    setDeviceZoneForTests("America/New_York");
    const { container } = render(
      withRouter(
        <Queue
          items={[item({ created_at: "2026-10-08T17:34:24Z", expires_at: "2026-10-08T17:44:24Z" })]}
          view="lapsed"
          now={NOW}
          emptyTitle="Nothing"
        />,
      ),
    );
    await screen.findAllByRole("link");
    expect(screen.getByText("Times in EDT")).toBeInTheDocument();
    expect(screen.getByText("13:34:24")).toHaveAttribute("title", "2026-10-08 17:34:24 UTC");
    const times = [...container.querySelectorAll("time")];
    expect(times).toHaveLength(2);
    for (const time of times) expect(namesItsZone(time, ZONE), time.outerHTML).toBe(true);
  });
});

describe("names on the approval (#678)", () => {
  it("names an unlabelled decider by number and the agent with its handle", () => {
    const { container } = render(
      <DetailView
        detail={detail({
          item: item({ agent: { principal_id: "aaaaaaaa-0000-4000-8000-000000000003", label: "triage-bot", number: 3 } }),
          quorum: {
            required: 2,
            recorded: 1,
            mine: null,
            decisions: [{ principal_id: "dddddddd-0000-4000-8000-000000000005", label: null, kind: "HUMAN_APPROVER", number: 2, decision: "APPROVE", decided_at: "2026-09-19T14:08:00Z" }],
          },
        })}
        now={NOW}
        phone={false}
        deciding={false}
        onDecide={vi.fn()}
      />,
    );
    expect(container.querySelector(".detail-sentence")).toHaveTextContent("requested by triage-bot (Agent 3) at 2026-09-19 14:07:31 UTC");
    expect(container.querySelector(".quorum")).toHaveTextContent("User 2: approved at 2026-09-19 14:08:00 UTC");
    expect(container.textContent).not.toContain("dddddddd");
    expect(container.textContent).not.toContain("aaaaaaaa");
  });
});

describe("the words", () => {
  it("map a refusal code to copy and fall back for anything else", () => {
    expect(refusalCode({ code: "STOPPED", detail: "x" })).toBe("STOPPED");
    expect(refusalCode(new Error("boom"))).toBeNull();
    expect(refusalCode("text")).toBeNull();
    expect(refusalText({ code: "APPROVAL_EXPIRED" })).toContain("This approval lapsed");
    expect(refusalText({ code: "SOMETHING_NEW" })).toContain("result could not be confirmed");
    expect(refusalText(undefined)).toContain("check whether your decision was recorded");
  });

  it("say why nothing can be decided, by status", () => {
    expect(statusNotice(detail())).toBeNull();
    expect(statusNotice(detail({ status: "paused" }))?.text).toContain("emergency stop");
    expect(statusNotice(detail({ status: "expired" }))?.tone).toBe("stale");
    const decided = detail({ status: "decided", quorum: { required: 2, recorded: 1, decisions: [], mine: "APPROVE" } });
    expect(statusNotice(decided)?.text).toBe(
      "Your decision (approve) is recorded. 1 of 2 approvals recorded; the approval waits for the remaining approvers.",
    );
    const settled = detail({ status: "settled", item: item({ approval_state: "DENIED", execution_state: "DENIED" }) });
    expect(statusNotice(settled)?.tone).toBe("deny");
    expect(statusNotice(settled)?.text).toContain("ExecBound refused this request before dispatch");
    expect(stateBadge(item())).toEqual({ text: "Waiting for a person", tone: "hold" });
    expect(stateBadge(item(), true).text).toBe("Waiting for you");
    expect(stateBadge(item({ approval_state: "CONSUMED" }))).toEqual({ text: "Approved", tone: "allow" });
    // One word for each answer and for a lapsed approval (#678).
    expect(stateBadge(item({ approval_state: "DENIED" }))).toEqual({ text: "Refused", tone: "deny" });
    expect(stateBadge(item({ approval_state: "EXPIRED" }))).toEqual({ text: "Lapsed", tone: "stale" });
    expect(statusNotice(detail({ status: "expired" }))?.text).toContain("This approval lapsed");
    const refused = detail({ status: "decided", quorum: { required: 2, recorded: 0, decisions: [], mine: "DENY" } });
    expect(statusNotice(refused)?.text).toContain("Your decision (refuse) is recorded.");
    const words = statusNotice({ ...settled, item: { ...settled.item, execution_state_label: "Denied" } })?.text ?? "";
    expect(words).toContain("Approval: Refused. Request: Denied. Nothing more can be decided here.");
    // No recorded code is lower-cased into a sentence.
    expect(words).not.toMatch(/human denied|denied and the request/);
    expect(requester({ principal_id: "aaaaaaaa-1111-4000-8000-000000000003", label: null, number: 3 })).toBe("Agent 3");
    expect(requester({ principal_id: "aaaaaaaa-1111-4000-8000-000000000003", label: "triage-bot", number: 3 })).toBe("triage-bot (Agent 3)");
  });

  it("count seconds from the server's clock and say an age in round words", () => {
    expect(secondsUntil("2026-09-19T14:19:31Z", NOW)).toBe(571);
    expect(secondsUntil("2026-09-19T14:00:00Z", NOW)).toBe(0);
    expect(secondsSince("2026-09-19T14:04:00Z", NOW)).toBe(360);
    expect(age(40)).toBe("40 s");
    expect(age(360)).toBe("6 min");
    expect(age(7200)).toBe("2 h");
    expect(age(200_000)).toBe("2 d");
    expect(timeOfDay("2026-09-19T14:07:31Z")).toBe("14:07:31");
    expect(timeOfDay("nonsense")).toBe("nonsense");
  });
});

describe("the queue", () => {
  it("lists each approval as a link with its ring, its target as text and the time left", async () => {
    render(
      withRouter(
        <Queue
          items={[item(), item({ approval_id: "4b1e90c2-0000-4000-8000-000000000009", target: HOSTILE, mine: "APPROVE" })]}
          view="pending"
          now={NOW}
          emptyTitle="Nothing"
        />,
      ),
    );
    const rows = await screen.findAllByRole("link");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveAttribute("href", "/approvals/4b1e90c2-0000-4000-8000-000000000001");
    expect(within(nth(rows, 0)).getByText("9:31", { selector: ".queue-left" })).toBeInTheDocument();
    // The ring is decorative in a row: the text beside it says the time, so it is hidden.
    expect(within(nth(rows, 0)).getByRole("img", { name: "9:31 left", hidden: true })).toBeInTheDocument();
    expect(within(nth(rows, 0)).getByText("Isolate endpoint")).toBeInTheDocument();
    expect(within(nth(rows, 1)).getByText(HOSTILE)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(rows[1]).toHaveTextContent("your decision is recorded");
  });

  it("shows the decision beside a decided approval and moves with j and k", async () => {
    listKeys();
    render(
      withRouter(
        <Queue
          items={[
            item({ approval_state: "DENIED", execution_state: "DENIED" }),
            item({ approval_id: "4b1e90c2-0000-4000-8000-000000000009", approval_state: "CONSUMED", execution_state: "EXECUTED" }),
          ]}
          view="decided"
          now={NOW}
          emptyTitle="Nothing"
        />,
      ),
    );
    expect(await screen.findByText("Refused")).toHaveClass("badge-deny");
    expect(screen.getByText("Approved")).toHaveClass("badge-allow");
    const rows = screen.getAllByRole("link");
    const [first, second] = [nth(rows, 0), nth(rows, 1)];
    first.focus();
    await userEvent.keyboard("j");
    expect(second).toHaveFocus();
    await userEvent.keyboard("k");
    expect(first).toHaveFocus();
  });

  it("focuses the first row on j from no focused row, as Activity does (NV7, #678)", async () => {
    listKeys();
    render(
      withRouter(
        <Queue
          items={[item(), item({ approval_id: "4b1e90c2-0000-4000-8000-000000000009" })]}
          view="pending"
          now={NOW}
          emptyTitle="Nothing"
        />,
      ),
    );
    const rows = await screen.findAllByRole("link");
    expect(document.activeElement).toBe(document.body);
    await userEvent.keyboard("j");
    expect(nth(rows, 0)).toHaveFocus();
    expect(nth(rows, 0)).toHaveClass("queue-row");
  });

  it("reads a lapsed approval as lapsed, with the moment it lapsed and no countdown", async () => {
    // #426: an approval past its deadline showed a ring reading 0:00, which reads as
    // urgency rather than as the absence of anything to do.
    render(
      withRouter(
        <Queue
          items={[item({ created_at: "2026-09-18T17:44:59Z", expires_at: "2026-09-18T17:54:59Z" })]}
          view="lapsed"
          now={NOW}
          emptyTitle="Nothing has lapsed undecided."
        />,
      ),
    );
    const row = nth(await screen.findAllByRole("link"), 0);
    expect(within(row).getByText("Lapsed")).toHaveClass("badge-stale");
    expect(row).toHaveTextContent("lapsed 2026-09-18 17:54:59 UTC");
    expect(screen.queryByText("0:00")).toBeNull();
    expect(screen.queryByRole("img", { hidden: true })).toBeNull();
  });

  it("says when nothing waits", async () => {
    render(withRouter(<Queue items={[]} view="pending" now={NOW} emptyTitle="Nothing is waiting for you." />));
    expect(await screen.findByRole("status")).toHaveTextContent("Nothing is waiting for you.");
  });
});

describe("the detail", () => {
  it("removes decision controls as soon as the deadline passes between polls", () => {
    render(<DetailView detail={detail()} now={NOW + 720_000} phone deciding={false} onDecide={vi.fn()} />);
    expect(screen.queryByRole("button", { name: /^Approve\b/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Refuse\b/ })).toBeNull();
    expect(screen.getByRole("status")).toHaveTextContent("deadline has passed");
    // A deadline that passed on screen reads Lapsed, the word every page uses (#678).
    expect(screen.getByText("Lapsed")).toHaveClass("badge-stale");
    expect(screen.queryByText("0:00 left")).toBeNull();
  });

  it("makes an indeterminate result clear without inviting another execution", () => {
    render(<DetailView detail={detail({ status: "settled", continuation: null, item: item({ approval_state: "CONSUMED", execution_state: "INDETERMINATE" }) })}
      now={NOW} phone deciding={false} onDecide={vi.fn()} />);
    expect(screen.getByRole("status")).toHaveTextContent("Do not retry");
    expect(screen.getByText(/The effect is unknown/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Approve\b/ })).toBeNull();
  });

  it("shows the shared reference and treats a case as unverified external context", async () => {
    render(<DetailView detail={detail({ item: item({ external_case: {
      source: "tines", case_id: HOSTILE, url: "https://lab.tines.com/cases/4821",
    } }) })} now={NOW} phone deciding={false} onDecide={vi.fn()} />);
    expect(screen.getByText("EB-1042")).toBeInTheDocument();
    // The request context sits below the decision and arrives with its own chunk.
    expect(await screen.findByText(HOSTILE)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("Reported by the caller; not verified incident context.")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "Open case at lab.tines.com ↗" });
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveAttribute("target", "_blank");
    expect(screen.getByText("Technical details").closest("details")).not.toHaveAttribute("open");
  });

  it("says the plan in words, lists the rule, the facts with their age and the two buttons", async () => {
    const onDecide = vi.fn();
    render(<DetailView detail={detail()} now={NOW} phone={false} deciding={false} onDecide={onDecide} />);
    expect(screen.getByRole("heading", { level: 2, name: "ws25" })).toBeInTheDocument();
    // The reader can decide it, so at any width it is waiting for them (#678).
    expect(screen.getByText("Waiting for you")).toHaveClass("badge-hold");
    expect(screen.getByText("review-production")).toHaveClass("rule-id");
    expect(screen.getByText("Review endpoint.isolate when environment is production.")).toBeInTheDocument();
    expect(screen.getByText("Quorum: 1 approval needed, none recorded yet.")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "9:31 left" })).toBeInTheDocument();
    const facts = screen.getByRole("table");
    expect(within(facts).getByRole("rowheader", { name: "environment" })).toBeInTheDocument();
    expect(within(facts).getByText("production")).toHaveClass("mono");
    expect(within(facts).getByText("6 min")).toBeInTheDocument();
    expect(screen.getByText(/Reversible: yes, by Lift endpoint isolation/)).toBeInTheDocument();
    // The explanation is the assistant's, and this deployment has none, so there is no
    // disclosure at all rather than one that could never open (#330).
    expect(screen.queryByText("Explain this request")).toBeNull();
    await userEvent.type(screen.getByLabelText("Comment for the audit record (optional)"), "Confirmed");
    await userEvent.click(screen.getByRole("button", { name: /^Approve\b/ }));
    expect(onDecide).toHaveBeenCalledWith("APPROVE", "Confirmed");
    await userEvent.click(screen.getByRole("button", { name: /^Refuse\b/ }));
    expect(onDecide).toHaveBeenLastCalledWith("DENY", "Confirmed");
  });

  it("disables both buttons while the server decides, and renders a hostile target as text", () => {
    render(
      <DetailView
        detail={detail({ item: item({ target: HOSTILE }) })}
        now={NOW}
        phone
        deciding
        onDecide={vi.fn()}
      />,
    );
    expect(screen.getByRole("button", { name: /^Approve\b/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /^Refuse\b/ })).toBeDisabled();
    expect(screen.getByRole("heading", { level: 2, name: HOSTILE })).toHaveTextContent(HOSTILE);
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("Waiting for you")).toBeInTheDocument();
    expect(screen.getByText("9:31 left")).toBeInTheDocument();
  });

  it("shows the reason instead of the buttons when nothing can be decided", () => {
    render(
      <DetailView
        detail={detail({
          status: "paused",
          continuation: null,
          stop: { stopped_at: "2026-09-19T14:09:00Z", reason: "Contain agent 7" },
        })}
        now={NOW}
        phone={false}
        deciding={false}
        onDecide={vi.fn()}
      />,
    );
    expect(screen.queryByRole("button", { name: /^Approve\b/ })).toBeNull();
    expect(screen.getByRole("status")).toHaveTextContent("Decisions are paused while the emergency stop is active.");
    expect(screen.getByRole("status")).toHaveTextContent("Contain agent 7");
  });

  it("names a signal fact's producer and capability, never the incident register", () => {
    render(<DetailView detail={detail({ facts: [{
      name: "compromise", value: "no_detection", origin: "RESOLVED", source_kind: "signal",
      source_object_id: "device-01", source_version: "1", permitted_writers: ["signal_mappings"],
      observed_at: "2026-09-19T14:09:00Z", valid_until: "2026-09-19T14:14:00Z", age_seconds: 60,
      capability: "resource_compromise.v1", source_label: HOSTILE,
    }] })} now={NOW} phone deciding={false} onDecide={vi.fn()} />);
    // The label is registered text and renders as text, isolated in its own element so its
    // direction cannot reach the capability beside it.
    const label = screen.getByText(HOSTILE);
    expect(label.tagName).toBe("BDI");
    expect(label.parentElement).toHaveTextContent(`${HOSTILE} (resource_compromise.v1)`);
    expect(screen.getByText("device-01").tagName).toBe("BDI");
    expect(screen.queryByText("Incident register")).toBeNull();
    expect(document.querySelector("img")).toBeNull();
  });

  it("names a signal fact by its kind and capability where its source carries no label", () => {
    render(<DetailView detail={detail({ facts: [{
      name: "compromise", value: "no_detection", origin: "RESOLVED", source_kind: "signal",
      source_object_id: "device-01", source_version: "1", permitted_writers: ["signal_mappings"],
      observed_at: "2026-09-19T14:09:00Z", valid_until: "2026-09-19T14:14:00Z", age_seconds: 60,
      capability: "resource_compromise.v1", source_label: null,
    }] })} now={NOW} phone deciding={false} onDecide={vi.fn()} />);
    expect(screen.getByText("Security signal (resource_compromise.v1)")).toBeInTheDocument();
    expect(screen.queryByText("Incident register")).toBeNull();
  });

  it("names every other fact's source by its kind", () => {
    render(<DetailView detail={detail({ facts: [{
      name: "incident_status", value: "OPEN", origin: "RESOLVED", source_kind: "incident",
      source_object_id: "inc-7", source_version: "3", permitted_writers: ["incident"],
      observed_at: "2026-09-19T14:09:00Z", valid_until: "2026-09-19T14:14:00Z", age_seconds: 60,
      capability: null, source_label: null,
    }] })} now={NOW} phone deciding={false} onDecide={vi.fn()} />);
    expect(screen.getByText("Incident register")).toBeInTheDocument();
  });

  it("takes the focus on its title when a row asked for it", () => {
    focusDetailNext();
    render(<DetailView detail={detail()} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />);
    expect(screen.getByRole("heading", { level: 2, name: "ws25" })).toHaveFocus();
    expect(takeDetailFocus()).toBe(false);
  });
});

describe("the page's report to the edition (#496)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("tells the edition when a decision completes the approval", async () => {
    vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
    vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
    // Far in the future, so the decision controls are there whatever the test's clock reads.
    const open = item({ expires_at: "2099-01-01T00:00:00Z" });
    const id = open.approval_id;
    answerWith({
      "GET /api/console/v1/approvals": { body: { items: [open], server_time: "2026-09-19T14:10:00Z" } },
      [`GET /api/console/v1/approvals/${id}`]: { body: detail({ item: open }) },
      [`POST /api/console/v1/approvals/${id}/decision`]: {
        body: { approval_id: id, approval_state: "APPROVED", decision: "APPROVE", execution_state: "EXECUTING", recorded: 1, required: 1 },
      },
    });
    const event = vi.fn();
    renderPage(withEdition(<ApprovalsPage selected={id} />, { event }));
    await userEvent.click(await screen.findByRole("button", { name: /^Approve\b/ }));
    await waitFor(() => {
      expect(event).toHaveBeenCalledWith("approval_completed");
    });
    expect(event).toHaveBeenCalledTimes(1);
  });
});

describe("held requests too few people can decide (#678)", () => {
  const UNROUTED = "/api/console/v1/approval-coverage/unrouted";
  const answer = {
    body: {
      server_time: "2026-09-19T14:10:00Z",
      pending: 1,
      pending_nobody: 1,
      pending_truncated: false,
      pending_latest: {
        approval_id: FIXTURE_APPROVAL,
        execution_id: "5c2f91d3-0000-4000-8000-000000000002",
        request_ref: "EB-1042",
        space_id: "5a5a5a5a-0000-4000-8000-00000000000a",
        at: "2026-09-19T14:19:31Z",
        state: "PENDING",
      },
      recent: 1,
      recent_latest: null,
    },
  };

  function desktop() {
    vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
    vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
  }

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("puts the line above the chips on the queue for an administrator", async () => {
    desktop();
    gateway({
      "GET /api/console/v1/approvals": list([]),
      [`GET ${UNROUTED}`]: answer,
    });
    routed("/approvals", ADMIN_SESSION);
    const line = await screen.findByText(/No one can approve 1 held request\./);
    const chips = screen.getByRole("group", { name: "Which approvals" });
    expect(line.compareDocumentPosition(chips) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("leaves it off an open approval, so the cold link never asks for it", async () => {
    desktop();
    const seen = gateway({
      "GET /api/console/v1/approvals": list([fixtureItem()]),
      [`GET /api/console/v1/approvals/${FIXTURE_APPROVAL}`]: { body: fixtureDetail() },
      [`GET ${UNROUTED}`]: answer,
    });
    routed(`/approvals/${FIXTURE_APPROVAL}`, ADMIN_SESSION);
    await screen.findAllByRole("heading", { level: 2 });
    await waitFor(() => { expect(seen.some((call) => call.path === `/api/console/v1/approvals/${FIXTURE_APPROVAL}`)).toBe(true); });
    expect(seen.some((call) => call.path === UNROUTED)).toBe(false);
    expect(screen.queryByText(/No one can approve/)).toBeNull();
  });

  it("asks nothing for an approver", async () => {
    desktop();
    const seen = gateway({ "GET /api/console/v1/approvals": list([]), [`GET ${UNROUTED}`]: answer });
    routed("/approvals", APPROVER_SESSION);
    await screen.findByRole("group", { name: "Which approvals" });
    await waitFor(() => { expect(seen.some((call) => call.path === "/api/console/v1/approvals")).toBe(true); });
    expect(seen.some((call) => call.path === UNROUTED)).toBe(false);
  });

  const lapsedItems = [
    fixtureItem({ approval_id: "4b1e90c2-0000-4000-8000-0000000000a1", request_ref: "EB-1", approval_state: "EXPIRED", reviewers_at_hold: 0, required: 1 }),
    fixtureItem({ approval_id: "4b1e90c2-0000-4000-8000-0000000000a2", request_ref: "EB-2", approval_state: "EXPIRED", reviewers_at_hold: 1, required: 2 }),
    fixtureItem({ approval_id: "4b1e90c2-0000-4000-8000-0000000000a3", request_ref: "EB-3", approval_state: "EXPIRED", reviewers_at_hold: 2, required: 1 }),
  ];

  it("badges a lapsed row too few people could decide when it was held", async () => {
    desktop();
    gateway({ "GET /api/console/v1/approvals?view=lapsed": list(lapsedItems), "GET /api/console/v1/approvals": list([]) });
    routed("/approvals?view=lapsed", ADMIN_SESSION);
    const rows = await screen.findAllByRole("link", { name: /EB-\d/ });
    const byRef = (ref: string): HTMLElement => {
      const found = rows.find((row) => row.textContent.includes(ref));
      if (found === undefined) throw new Error(`No row ${ref}`);
      return found;
    };
    expect(await within(byRef("EB-1")).findByText("No one could approve this when it was held")).toBeInTheDocument();
    expect(await within(byRef("EB-2")).findByText("Too few people could approve this when it was held")).toBeInTheDocument();
    expect(within(byRef("EB-3")).queryByText(/could approve this when it was held/)).toBeNull();
  });

  it("shows no hold badge to an approver, whose rows carry no count", async () => {
    desktop();
    const hidden = lapsedItems.map((row) => ({ ...row, reviewers_at_hold: null }));
    gateway({ "GET /api/console/v1/approvals?view=lapsed": list(hidden), "GET /api/console/v1/approvals": list([]) });
    routed("/approvals?view=lapsed", APPROVER_SESSION);
    await screen.findAllByRole("link", { name: /EB-\d/ });
    expect(screen.queryByText(/could approve this when it was held/)).toBeNull();
  });

  it("leaves a row waiting on others to its own words", async () => {
    desktop();
    gateway({
      "GET /api/console/v1/approvals?view=others": list([fixtureItem({ reviewers: 0, reviewers_left: 0, assigned_to_you: false, reviewers_at_hold: 0 })]),
      "GET /api/console/v1/approvals": list([]),
    });
    routed("/approvals?view=others", ADMIN_SESSION);
    expect(await screen.findByText("No one can approve this")).toBeInTheDocument();
    expect(screen.queryByText(/could approve this when it was held/)).toBeNull();
  });
});
