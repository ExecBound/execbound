// SPDX-License-Identifier: AGPL-3.0-only
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Proposed, Settings, TurnView } from "../../api/types.gen";
import { PLACEHOLDER } from "../../lib/session";
import { answerWith, renderPage, type Seen } from "../../test/page";
import { AskPage } from "./AskPage";
import { Citation } from "./Citation";
import { DescribeRule } from "./DescribeRule";
import { Explain } from "./Explain";
import { Turn } from "./Turn";

const TURN = "11111111-1111-4111-8111-111111111111";
const EXECUTION = "22222222-2222-4222-8222-222222222222";
const AGENT = "33333333-3333-4333-8333-333333333333";
const BUNDLE = "44444444-4444-4444-8444-444444444444";
/** A deployment whose operator configured a model; the flag travels with the session. */
const CONFIGURED = { ...PLACEHOLDER, assistant: true, role: "ADMIN" as const };

const ON: Settings = {
  enabled: true,
  model: "claude-sonnet-5",
  provider_retention: "Prompts and answers are kept by the model provider for up to 30 days.",
  person_hourly_turns: 20,
  tenant_daily_tokens: 200000,
};
const SETTINGS = "GET /api/console/v1/assistant/settings";

function turn(overrides: Partial<TurnView> = {}): TurnView {
  return {
    turn_id: TURN,
    context_kind: "question",
    context_id: null,
    question: "What happened today?",
    state: "COMPLETED",
    reason: null,
    steps: ["Read the overview"],
    paragraphs: [{ text: "Nine requests, one denied.", ids: [EXECUTION] }],
    cannot_answer: false,
    cited_ids: [EXECUTION],
    created_at: "2026-09-19T10:00:00Z",
    completed_at: "2026-09-19T10:00:04Z",
    ...overrides,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("a turn", () => {
  it("renders the answer as text with a chip for every id a tool returned", async () => {
    answerWith({});
    renderPage(<Turn turn={turn()} />, CONFIGURED);
    expect(await screen.findByText("Nine requests, one denied.")).toBeInTheDocument();
    expect(screen.getByText("Read the overview")).toBeInTheDocument();
    // The server says which ids a tool returned and not what kind of record each names, so a
    // chip is a link only for the turn's own context and inert text otherwise (#330).
    expect(screen.queryByRole("link")).toBeNull();
    expect(screen.getByText(EXECUTION.slice(0, 8))).toBeInTheDocument();
    expect(screen.getByText("Generated explanation. The facts above are the record.")).toBeInTheDocument();
  });

  it("renders markup the model wrote as the text it is, and links nothing else", async () => {
    answerWith({});
    const injected = '![x](https://elsewhere.test/a.png) <script>alert(1)</script> [link](https://elsewhere.test)';
    renderPage(
      <Turn
        turn={turn({
          paragraphs: [{ text: `The agent label says: ${injected}`, ids: [] }],
          cited_ids: [],
        })}
      />,
      CONFIGURED,
    );
    expect(await screen.findByText(`The agent label says: ${injected}`)).toBeInTheDocument();
    expect(document.querySelectorAll("a")).toHaveLength(0);
    expect(document.querySelectorAll("img")).toHaveLength(0);
    expect(document.querySelector("script")).toBeNull();
  });

  it("shows the server's sentence for a refused explanation and no answer at all", async () => {
    answerWith({});
    renderPage(
      <Turn
        turn={turn({
          context_kind: "approval",
          state: "FAILED",
          reason: "RECOMMENDATION",
          paragraphs: [],
          cited_ids: [],
        })}
      />,
      CONFIGURED,
    );
    expect(await screen.findByText("The explanation could not be shown.")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("approve");
  });
});

describe("the Ask page", () => {
  it("asks, and says nothing about the assistant where the tenant switched it off", async () => {
    answerWith({
      [SETTINGS]: { body: { ...ON, enabled: false } },
    });
    renderPage(<AskPage />, { ...CONFIGURED, role: "ADMIN" });
    expect(
      await screen.findByText("The assistant is not turned on for this tenant"),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("What would you like to know?")).toBeNull();
  });

  it("sends the question and goes to its turn", async () => {
    const seen: Seen[] = answerWith({
      [SETTINGS]: { body: ON },
      "GET /api/console/v1/assistant/turns": { body: { turns: [] } },
      "POST /api/console/v1/assistant/turns": { body: turn({ state: "RUNNING", steps: [] }) },
      [`GET /api/console/v1/assistant/turns/${TURN}`]: { body: turn() },
    });
    renderPage(<AskPage />, CONFIGURED);
    const box = await screen.findByLabelText("What would you like to know?");
    await userEvent.type(box, "What happened today?");
    await userEvent.click(screen.getByRole("button", { name: "Ask" }));
    await waitFor(() => {
      expect(seen.some((request) => request.method === "POST")).toBe(true);
    });
    const asked = seen.find((request) => request.method === "POST");
    expect(asked?.body).toEqual({ question: "What happened today?" });
    expect(asked?.headers.get("x-csrf-token")).toBe("token-under-test");
  });
});

describe("Explain", () => {
  it("is absent where the deployment has no assistant", async () => {
    answerWith({});
    // The session says there is none, so the component asks nothing and renders nothing.
    renderPage(<Explain kind="agent" id={AGENT} what="this agent" />, PLACEHOLDER);
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: /Explain/ })).toBeNull();
    });
  });

  it("is collapsed, asks only when opened, and records the opening", async () => {
    const seen: Seen[] = answerWith({
      [SETTINGS]: { body: ON },
      "POST /api/console/v1/assistant/turns": {
        body: turn({ context_kind: "agent", context_id: AGENT, question: null }),
      },
      [`GET /api/console/v1/assistant/turns/${TURN}`]: {
        body: turn({ context_kind: "agent", context_id: AGENT, question: null }),
      },
      [`POST /api/console/v1/assistant/turns/${TURN}/opened`]: {
        body: turn({ context_kind: "agent", context_id: AGENT, question: null }),
      },
    });
    renderPage(<Explain kind="agent" id={AGENT} what="this agent" />, CONFIGURED);
    const toggle = await screen.findByRole("button", { name: "Explain this agent" });
    // Collapsed: nothing has been asked, so nothing has been sent to a model.
    expect(seen.some((request) => request.path === "/api/console/v1/assistant/turns")).toBe(false);
    await userEvent.click(toggle);
    expect(await screen.findByText("Nine requests, one denied.")).toBeInTheDocument();
    const asked = seen.find((request) => request.path === "/api/console/v1/assistant/turns");
    expect(asked?.body).toEqual({ context_kind: "agent", context_id: AGENT });
    await waitFor(() => {
      expect(seen.some((request) => request.path.endsWith("/opened"))).toBe(true);
    });
  });
});

describe("Describe a rule", () => {
  it("fills the add-a-rule form and adds nothing until the form is submitted", async () => {
    const proposed: Proposed = {
      words: "never isolate a domain controller",
      sentence: "Deny endpoint.isolate when role is domain_controller",
      lines: ["role is domain_controller"],
      rule: {
        id: "isolate-never-tier-zero",
        action: "endpoint.isolate",
        effect: "DENY",
        note: null,
        quorum: null,
        when: [{ kind: "fact", name: "role", operator: "is", values: ["domain_controller"] }],
      },
    };
    const seen: Seen[] = answerWith({
      [SETTINGS]: { body: ON },
      "POST /api/console/v1/assistant/rules": { body: proposed },
    });
    const filled: string[] = [];
    renderPage(
      <DescribeRule
        bundleId={BUNDLE}
        editable
        onProposed={(rule) => {
          filled.push(rule.sentence);
        }}
      />,
      CONFIGURED,
    );
    const box = await screen.findByLabelText("What should the rule do?");
    await userEvent.type(box, "never isolate a domain controller");
    await userEvent.click(screen.getByRole("button", { name: "Describe a rule" }));
    expect(await screen.findByText(proposed.sentence)).toBeInTheDocument();
    expect(filled).toEqual([proposed.sentence]);
    expect(screen.getByText("role is domain_controller")).toBeInTheDocument();
    const asked = seen.find((request) => request.path.endsWith("/assistant/rules"));
    expect(asked?.body).toEqual({ bundle_id: BUNDLE, words: "never isolate a domain controller" });
    // One request, and it is the proposal: nothing was written to the draft.
    expect(seen.some((request) => request.path.includes("/policy/"))).toBe(false);
  });

  it("is absent where the deployment has no assistant, and where the bundle is read-only", async () => {
    answerWith({});
    renderPage(
      <DescribeRule bundleId={BUNDLE} editable onProposed={() => undefined} />,
      PLACEHOLDER,
    );
    await waitFor(() => {
      expect(screen.queryByLabelText("What should the rule do?")).toBeNull();
    });
    answerWith({ [SETTINGS]: { body: ON } });
    renderPage(
      <DescribeRule bundleId={BUNDLE} editable={false} onProposed={() => undefined} />,
      CONFIGURED,
    );
    await waitFor(() => {
      expect(screen.queryByLabelText("What should the rule do?")).toBeNull();
    });
  });

  it("says where a description the compiler will not take failed", async () => {
    answerWith({
      [SETTINGS]: { body: ON },
      "POST /api/console/v1/assistant/rules": {
        status: 409,
        body: { code: "INVALID_PROPOSAL", detail: "x", fields: ["when.0.name"] },
      },
    });
    renderPage(
      <DescribeRule bundleId={BUNDLE} editable onProposed={() => undefined} />,
      CONFIGURED,
    );
    const box = await screen.findByLabelText("What should the rule do?");
    await userEvent.type(box, "deny when the mood is bad");
    await userEvent.click(screen.getByRole("button", { name: "Describe a rule" }));
    expect(await screen.findByText(/could not be written as a rule/)).toBeInTheDocument();
  });
});

describe("a finding's citation (MQ10, #678)", () => {
  it("opens that finding in the Findings queue", async () => {
    const id = "f1f1f1f1-0000-4000-8000-000000000001";
    renderPage(<Citation id={id} kind="finding" />);
    expect(await screen.findByRole("link", { name: /f1f1f1f1/ })).toHaveAttribute("href", `/monitor?view=findings&state=all&open=${id}`);
  });
});
