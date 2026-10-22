// SPDX-License-Identifier: AGPL-3.0-only
import { useSearch } from "@tanstack/react-router";
import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { BundlePreviewView, ChangedDecisionRow, MappingRow, PolicyPage } from "../../api/types.gen";
import {
  ACCOUNT,
  ACTIVE,
  detail,
  DRAFT,
  EXECUTION,
  json,
  mount,
  PAGE,
  PREVIEW,
  expectNoRequests,
  resetClient,
  stub,
} from "../../test/policy";
import { clearDrafts } from "../../lib/drafts";
import { KEPT_FIELD } from "../../lib/kept";
import { clearToasts } from "../../lib/toast";
import { PLACEHOLDER, SessionContext } from "../../lib/session";
import { Toaster } from "../ui/Toast";
import { BundleDetailView } from "./BundleDetail";
import { BundleList, currentFirst, NewDraft } from "./BundleList";
import { changeSummary, decisionWord, duration, EFFECT, isWindow, policyName, retiredToggle, STATE } from "./format";

beforeEach(expectNoRequests);
afterEach(resetClient);

describe("the policy words", () => {
  it("give every lifecycle state and every effect a word before a colour", () => {
    expect(STATE.ACTIVE.word).toBe("Active");
    expect(STATE.RETIRED.tone).toBe("stale");
    expect(EFFECT.DENY).toEqual({ word: "Deny", tone: "deny" });
    expect(decisionWord("REQUIRE_APPROVAL")).toBe("Held for a person");
    // An effect the catalog gains later still reads as words rather than a code.
    expect(decisionWord("SOMETHING_NEW")).toBe("something new");
    expect(isWindow("24h")).toBe(true);
    expect(isWindow("90d")).toBe(false);
  });

  const change = (baseline: string, candidate: string, differences: string[] = []): ChangedDecisionRow => ({
    execution_id: EXECUTION,
    action: "endpoint.isolate",
    semantic_time: "2026-09-19T07:40:00Z",
    baseline_effect: baseline,
    baseline_reasons: [],
    candidate_effect: candidate,
    candidate_reasons: [],
    rule_ids: [],
    differences,
    required_approvers: 1,
  });
  const previewed = (changed: ChangedDecisionRow[], considered: number): BundlePreviewView => ({
    ...PREVIEW,
    window: "7d",
    window_seconds: 604800,
    considered,
    changed,
  });

  it("sum up a preview's changes by what they moved from and to", () => {
    const changed = [
      change("ALLOW", "REQUIRE_APPROVAL"),
      change("REQUIRE_APPROVAL", "DENY"),
      change("ALLOW", "REQUIRE_APPROVAL"),
    ];
    expect(changeSummary(previewed(changed, 41))).toBe(
      "Previewed over the last 7 days: 3 of 41 recorded decisions would change (2 allowed to held, 1 held to denied).",
    );
  });

  it("count a change that keeps the effect but not the approval requirement", () => {
    const changed = [change("ALLOW", "REQUIRE_APPROVAL"), change("REQUIRE_APPROVAL", "REQUIRE_APPROVAL", ["required_approvers"])];
    expect(changeSummary(previewed(changed, 5))).toBe(
      "Previewed over the last 7 days: 2 of 5 recorded decisions would change (1 allowed to held, 1 with a different approval requirement).",
    );
  });

  it("say when the window held nothing, nothing changed, or the preview was unavailable", () => {
    expect(changeSummary(previewed([], 0))).toBe(
      "Previewed over the last 7 days: no recorded decision in that window, so nothing here shows what would change.",
    );
    expect(changeSummary(previewed([], 12))).toBe(
      "Previewed over the last 7 days: none of 12 recorded decisions would change.",
    );
    expect(changeSummary({ ...previewed([], 0), available: false })).toBe(
      "The preview could not be computed, so what would change is not known here.",
    );
    expect(changeSummary({ ...previewed([change("OBSERVE", "SOMETHING_NEW")], 1), window: "1h" })).toBe(
      "Previewed over the last hour: 1 of 1 recorded decision would change (1 observed to something new).",
    );
  });
});

describe("the bundle list", () => {
  it("marks the active selection and links every bundle by its identity", async () => {
    const router = mount(<BundleList page={PAGE} />);
    const table = await screen.findByRole("table", { name: /Policy versions available in this Space/ });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    // The active selection leads, then the draft.
    const [active, draft] = [rows[0] ?? table, rows[1] ?? table];
    expect(within(draft).getByText("Draft")).toBeInTheDocument();
    expect(within(active).getByText("Active")).toBeInTheDocument();
    expect(within(active).getByText("the active selection")).toBeInTheDocument();
    await userEvent.click(within(draft).getByRole("link", { name: "Policy version 22222222" }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`/policy/${DRAFT}`);
    });
  });

  it("marks the starter policy sample targets installed", async () => {
    const page: PolicyPage = {
      ...PAGE,
      bundles: PAGE.bundles.map((row) => (row.bundle_id === ACTIVE ? { ...row, sample: true } : row)),
    };
    mount(<BundleList page={page} />);
    const table = await screen.findByRole("table", { name: /Policy versions available in this Space/ });
    const [active, draft] = within(table).getAllByRole("row").slice(1);
    if (draft === undefined || active === undefined) throw new Error("two rows expected");
    expect(within(active).getByText("Sample")).toHaveClass("badge-accent");
    expect(draft).not.toHaveTextContent("Sample");
  });
});

describe("a calmer list", () => {
  const row = (id: number, state: PolicyPage["bundles"][number]["state"], changed: string, active = false) => ({
    bundle_id: `${String(id).padStart(8, "0")}-0000-4000-8000-000000000000`,
    content_hash: "e".repeat(64),
    state,
    changed_at: changed,
    active,
  });
  const LONG: PolicyPage = {
    active: "00000001-0000-4000-8000-000000000000",
    bundles: [
      row(2, "DRAFT", "2026-10-01T10:00:00Z"),
      row(1, "ACTIVE", "2026-09-01T10:00:00Z", true),
      row(3, "VALIDATED", "2026-10-03T10:00:00Z"),
      row(4, "ACTIVE", "2026-10-04T10:00:00Z"),
      row(5, "DRAFT", "2026-10-05T10:00:00Z"),
      ...Array.from({ length: 12 }, (_, index) =>
        row(100 + index, "RETIRED", `2026-08-${String(index + 1).padStart(2, "0")}T10:00:00Z`),
      ),
    ],
  };

  it("counts retired versions in words", () => {
    expect(retiredToggle(1)).toBe("Show 1 retired version");
    expect(retiredToggle(12)).toBe("Show 12 retired versions");
  });

  it("puts the selection first, then drafts newest first, then versions active elsewhere", () => {
    const { current, retired } = currentFirst(LONG.bundles);
    expect(current.map((item) => item.bundle_id.slice(0, 8))).toEqual([
      "00000001", "00000005", "00000003", "00000002", "00000004",
    ]);
    expect(retired).toHaveLength(12);
    expect(retired[0]?.bundle_id.slice(0, 8)).toBe("00000111");
  });

  it("folds retired versions behind a count, in the address, and Back folds them again", async () => {
    function Page() {
      const search: { retired?: unknown } = useSearch({ strict: false });
      return <BundleList page={LONG} showRetired={search.retired === 1} />;
    }
    const router = mount(<Page />);
    const table = await screen.findByRole("table", { name: /Policy versions available in this Space/ });
    expect(within(table).getAllByRole("row").slice(1)).toHaveLength(5);
    expect(screen.queryByRole("table", { name: /Retired policy versions/ })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Show 12 retired versions" }));
    const retired = await screen.findByRole("table", { name: "Retired policy versions, newest change first." });
    expect(within(retired).getAllByRole("row").slice(1)).toHaveLength(12);
    expect(router.state.location.searchStr).toBe("?retired=1");
    expect(screen.getByRole("button", { name: "Hide retired versions" })).toBeInTheDocument();
    router.history.back();
    await waitFor(() => {
      expect(screen.queryByRole("table", { name: /Retired policy versions/ })).toBeNull();
    });
  });

  it("shows the latest activation's reason under the time, as text", async () => {
    const page: PolicyPage = {
      ...PAGE,
      bundles: PAGE.bundles.map((item) =>
        item.bundle_id === ACTIVE ? { ...item, note: "<img src=x> Tighten tier 0" } : item,
      ),
    };
    mount(<BundleList page={page} />);
    const note = await screen.findByText("<img src=x> Tighten tier 0");
    expect(note).toHaveClass("policy-note");
    expect(note.querySelector("img")).toBeNull();
  });
});

describe("an active version under All spaces (#678)", () => {
  const ALL_SPACES = { ...PLACEHOLDER, space: null, spaces: 2, allSpaces: true };
  const ONE_SPACE = { ...PLACEHOLDER, space: { id: "5a5a5a5a-0000-4000-8000-00000000000a", name: "Identity response", archived: false }, spaces: 2, allSpaces: true };
  // With no Space selected the server marks no version as the selection.
  const unselected: PolicyPage = { ...PAGE, active: null, bundles: PAGE.bundles.map((row) => ({ ...row, active: false })) };

  it("asks for a Space instead of offering a first policy it could not create", async () => {
    mount(<SessionContext.Provider value={ALL_SPACES}><NewDraft hasActive={false} starterHint="Choose a Space before starting or copying a policy." /></SessionContext.Provider>);
    expect(await screen.findByText(/Choose a Space in the switcher at the top of the page/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create first policy" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Create from JSON" })).toBeNull();
  });

  it("reads Active in the list, and Active in another Space only where a Space is selected", async () => {
    mount(<SessionContext.Provider value={ALL_SPACES}><BundleList page={unselected} /></SessionContext.Provider>);
    const table = await screen.findByRole("table", { name: /Policy versions/ });
    const active = within(table).getAllByRole("row").find((row) => row.textContent.includes("Policy version 11111111"));
    if (active === undefined) throw new Error("no active row");
    expect(within(active).getByText("Active")).toHaveClass("badge-allow");
    expect(table).not.toHaveTextContent("another Space");
    expect(table).not.toHaveTextContent("this Space");
    expect(active).toHaveTextContent("Copy it, or choose a Space to activate it there");
    cleanup();
    mount(<SessionContext.Provider value={ONE_SPACE}><BundleList page={unselected} /></SessionContext.Provider>);
    expect(await screen.findByText("Active in another Space")).toBeInTheDocument();
  });

  it("says in the detail that no Space is selected rather than that it is another Space's", async () => {
    mount(
      <SessionContext.Provider value={ALL_SPACES}>
        <BundleDetailView detail={detail({ active: false })} active={null} />
      </SessionContext.Provider>,
      `/policy/${ACTIVE}`,
    );
    expect(await screen.findByText("Choose a Space to see whether this policy decides its requests.")).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("Active in another Space");
    expect(document.body).not.toHaveTextContent("not the active selection in this Space");
    expect(screen.getByText(/^Next: choose a Space to activate this policy there/)).toBeInTheDocument();
  });
});

describe("the bundle detail", () => {
  it("reads the rules as sentences with the effect first and a note as text", async () => {
    mount(<BundleDetailView detail={detail()} active={{ bundle_id: ACTIVE }} />, `/policy/${ACTIVE}`);
    expect(
      await screen.findByText("Allow isolating an endpoint when the target is a workstation."),
    ).toBeInTheDocument();
    expect(screen.getByText("Deny")).toBeInTheDocument();
    // A note carrying markup is text and reaches no HTML sink.
    const note = screen.getByText(/Note: <img src=x onerror=alert\(1\)>/);
    expect(note.querySelector("img")).toBeNull();
    expect(
      screen.getByText(/As the rules read\. The decision is the kernel/),
    ).toBeInTheDocument();
  });

  it("names the action a mapping's ref serves, once, when the ref is another name for it", async () => {
    const mapping: MappingRow = {
      operation_ref: "endpoint.isolate",
      account_id: ACCOUNT,
      mapping_version: "map-v1",
      schema_version: "action.v1",
      context_contract_version: "endpoint-isolation.v1",
      observe_only: false,
      external_executor: false,
    };
    const mappings = [
      mapping,
      { ...mapping, operation_ref: "isolate.corroborated", action: "endpoint.isolate", context_contract_version: "endpoint-isolation.v2" },
    ];
    mount(<BundleDetailView detail={detail({ mappings })} active={{ bundle_id: ACTIVE }} />, `/policy/${ACTIVE}`);
    expect(await screen.findByText(/^Controls endpoint isolate\. An action needs an allow rule/)).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "The operation mappings this bundle binds." });
    const operations = within(table).getAllByRole("rowheader").map((cell) => cell.textContent);
    expect(operations).toEqual(["endpoint.isolate", "isolate.corroborated (endpoint.isolate)"]);
  });

  it("marks the starter policy and says what removing the samples does to it", async () => {
    mount(<BundleDetailView detail={detail({ sample: true })} active={{ bundle_id: ACTIVE }} />, `/policy/${ACTIVE}`);
    expect(await screen.findByText("Sample")).toHaveClass("badge-accent");
    expect(screen.getByText(/Removing them retires this policy while it is still active and unchanged/)).toBeInTheDocument();
  });

  it("meters a limit the tenant counts as one and says how the others are counted", async () => {
    mount(<BundleDetailView detail={detail()} active={{ bundle_id: ACTIVE }} />, `/policy/${ACTIVE}`);
    const meter = await screen.findByRole("meter");
    expect(meter).toHaveAttribute("aria-valuenow", "8");
    expect(meter).toHaveAttribute("aria-valuemax", "20");
    expect(screen.getByText(/Counted each agent on its own, so there is no one figure here\./)).toBeInTheDocument();
    expect(screen.getByText(/10 autonomous targets per 1 hour/)).toBeInTheDocument();
  });

  it("shows the compiled policy read-only and names the rule behind a quorum", async () => {
    mount(<BundleDetailView detail={detail()} active={{ bundle_id: ACTIVE }} />, `/policy/${ACTIVE}`);
    expect(await screen.findByText(/permit\(principal, action ==/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "As policy language" })).toBeInTheDocument();
    expect(screen.getByText("review-production")).toBeInTheDocument();
    // An empty policy set says so rather than leaving a blank block.
    expect(screen.getAllByText("None.").length).toBeGreaterThan(0);
    // An active bundle is not a candidate, so nothing offers to replay history for it.
    expect(screen.queryByRole("button", { name: /^Preview the last/ })).toBeNull();
  });

  it("previews a candidate on the window asked for, linking each change to its record", async () => {
    stub(async (request) => {
      expect(request.url).toContain(`/api/console/v1/policy/${DRAFT}/preview`);
      expect(await request.clone().json()).toEqual({ window: "7d" });
      return json({ ...PREVIEW, window: "7d" });
    });
    const router = mount(
      <BundleDetailView detail={detail({ bundle_id: DRAFT, content_hash: "d".repeat(64), state: "DRAFT", active: false })} active={{ bundle_id: ACTIVE }} />,
      `/policy/${DRAFT}`,
    );
    await userEvent.selectOptions(await screen.findByLabelText("Replay over"), "7d");
    await userEvent.click(screen.getByRole("button", { name: "Preview the last 7 days" }));
    await waitFor(() => {
      expect(screen.getByText(/3 decisions considered, 1 would change\./)).toBeInTheDocument();
    });
    const changes = screen.getByRole("table", { name: /would have made differently/ });
    const rows = within(changes).getAllByRole("row");
    expect(rows).toHaveLength(2);
    const change = rows[1] ?? changes;
    expect(within(change).getByText("Allowed")).toHaveClass("badge-allow");
    expect(within(change).getByText("Held for a person")).toHaveClass("badge-hold");
    // The rule behind the change, never the engine's positional identifier.
    expect(within(change).getByText("review-production")).toBeInTheDocument();
    expect(within(change).getByText("2 approvers")).toBeInTheDocument();
    // Both counts are shown, so the person sees what changes and not only that it changed.
    expect(screen.getByText("As recorded").parentElement).toHaveTextContent("3 Allowed");
    expect(screen.getByText("Under this bundle").parentElement).toHaveTextContent(
      "2 Held for a person",
    );
    // The record opens in Activity's drawer, whose state is in the address (#333).
    await userEvent.click(within(change).getByRole("link", { name: /33333333/ }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/activity");
    });
    expect(router.state.location.searchStr).toContain(`open=${EXECUTION}`);
  });

  it("says the preview is unavailable rather than showing zeroes", async () => {
    stub(() => Promise.resolve(json({ ...PREVIEW, available: false, considered: 0, changed: [] })));
    mount(
      <BundleDetailView detail={detail({ bundle_id: DRAFT, content_hash: "d".repeat(64), state: "DRAFT", active: false })} active={null} />,
      `/policy/${DRAFT}`,
    );
    await userEvent.click(await screen.findByRole("button", { name: "Preview the last 7 days" }));
    await waitFor(() => {
      expect(screen.getByText(/could not be computed from this tenant/)).toBeInTheDocument();
    });
    expect(screen.queryByText(/decisions considered/)).toBeNull();
  });

  it("names what activation changes, and waits for the server before saying it happened", async () => {
    const answered = vi.fn();
    stub(async (request) => {
      if (request.url.includes("/preview")) return json(PREVIEW);
      answered();
      expect(await request.clone().json()).toEqual({ confirm: true, reason: "Tighten tier 0" });
      return json(detail({ bundle_id: DRAFT, state: "ACTIVE", active: true }));
    });
    mount(
      <BundleDetailView detail={detail({ bundle_id: DRAFT, content_hash: "d".repeat(64), state: "VALIDATED", active: false })} active={{ bundle_id: ACTIVE }} />,
      `/policy/${DRAFT}`,
    );
    await userEvent.click(await screen.findByRole("button", { name: "Preview the last 7 days" }));
    await waitFor(() => {
      expect(screen.getByText(/3 decisions considered/)).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole("button", { name: "Activate" }));
    const dialog = await screen.findByRole("dialog");
    // The confirmation names the bundle that stops being the selection and quotes the preview.
    expect(within(dialog).getByText(/11111111/)).toBeInTheDocument();
    expect(within(dialog).getByText(/stops being/)).toBeInTheDocument();
    expect(
      within(dialog).getByText(
        "Previewed over the last 24 hours: 1 of 3 recorded decisions would change (1 allowed to held).",
      ),
    ).toBeInTheDocument();
    expect(answered).not.toHaveBeenCalled();
    // Activation asks what changed and why, and waits for it.
    expect(within(dialog).getByRole("button", { name: "Activate" })).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/What changed and why/), "Tighten tier 0");
    await userEvent.click(within(dialog).getByRole("button", { name: "Activate" }));
    await waitFor(() => {
      expect(answered).toHaveBeenCalledTimes(1);
    });
  });

  it("requires a replacement before retiring a policy selected by a space", async () => {
    mount(<BundleDetailView detail={detail()} active={{ bundle_id: ACTIVE }} />, `/policy/${ACTIVE}`);
    expect(await screen.findByText(/Activate a replacement before retiring/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retire" })).toBeNull();
  });

  it("can explicitly select a shared policy already active in another Space", async () => {
    const sent = vi.fn();
    stub(async (request) => { sent(await request.clone().json()); return json(detail({ active: true })); });
    mount(<BundleDetailView detail={detail({ active: false })} active={null} />, `/policy/${ACTIVE}`);
    await userEvent.click(await screen.findByRole("button", { name: "Activate" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/new request in the selected Space/)).toBeInTheDocument();
    expect(sent).not.toHaveBeenCalled();
    await userEvent.type(within(dialog).getByLabelText(/What changed and why/), "Share the baseline");
    await userEvent.click(within(dialog).getByRole("button", { name: "Activate" }));
    await waitFor(() => { expect(sent).toHaveBeenCalledWith({ confirm: true, reason: "Share the baseline" }); });
    expect(screen.queryByRole("button", { name: "Retire" })).toBeNull();
  });

  it("offers no lifecycle step on a retired bundle", async () => {
    mount(
      <BundleDetailView detail={detail({ state: "RETIRED", active: false })} active={null} />,
      `/policy/${ACTIVE}`,
    );
    expect(await screen.findByRole("heading", { name: "As policy language" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retire" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Validate" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Activate" })).toBeNull();
  });
});

describe("guided policy starts", () => {
  it("creates a first policy from configured mappings without JSON or an active version", async () => {
    let sent: unknown;
    stub(async (request) => { sent = await request.clone().json(); return json(detail({ bundle_id: DRAFT, state: "DRAFT", active: false })); });
    mount(<NewDraft hasActive={false} starterAvailable />);
    await userEvent.click(await screen.findByRole("button", { name: "Create first policy" }));
    await waitFor(() => { expect(sent).toEqual({ source: "template", template: "security-response" }); });
  });

  it("creates a real review-every-action draft while JSON stays under Advanced", async () => {
    let sent: unknown;
    stub(async (request) => {
      sent = await request.clone().json();
      return json(detail({ bundle_id: DRAFT, state: "DRAFT", active: false }));
    });
    const router = mount(<NewDraft hasActive formAvailable />);
    expect(await screen.findByRole("heading", { name: "Current protections" })).toBeInTheDocument();
    const advanced = screen.getByText("Advanced: import or copy complete configuration").closest("details");
    expect(advanced).not.toHaveAttribute("open");
    expect(screen.getByLabelText(/Bundle JSON/).closest("details")).toBe(advanced);
    await userEvent.click(screen.getByRole("button", { name: "Start with approval for every action" }));
    await waitFor(() => { expect(sent).toEqual({ source: "template", template: "review-all" }); });
    await waitFor(() => { expect(router.state.location.pathname).toBe(`/policy/${DRAFT}`); });
  });

  it("explains why custom Cedar cannot be offered as an editable template", async () => {
    mount(<NewDraft hasActive formAvailable={false} />);
    expect(await screen.findByText(/cannot safely convert/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Customize current protections" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Copy the active bundle" })).toBeEnabled();
  });

  it("keeps policy text and identity behind closed Advanced disclosures", async () => {
    mount(<BundleDetailView detail={detail({ written_as_rules: false, rules: [], form_available: false })} active={null} />);
    expect(await screen.findByText(/cannot be safely translated/)).toBeInTheDocument();
    expect(screen.getByText(/permit\(principal/).closest("details")).not.toHaveAttribute("open");
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(policyName(ACTIVE));
    expect(duration(60)).toBe("1 minute");
    expect(duration(3600)).toBe("1 hour");
    expect(duration(5400)).toBe("90 minutes");
  });
});

describe("a new policy document kept across signing in again (#678)", () => {
  const KEY = "eb:draft:policy:new";
  const DOCUMENT = '{"rules": []}';
  const person = { ...PLACEHOLDER, person: { ...PLACEHOLDER.person, id: "p-1" } };
  const keep = (principal: string) => {
    window.sessionStorage.setItem(KEY, JSON.stringify({ p: principal, x: "2999-01-01T00:00:00Z", t: DOCUMENT }));
  };
  const form = () => (
    <SessionContext.Provider value={person}>
      <NewDraft hasActive formAvailable />
      <Toaster />
    </SessionContext.Provider>
  );

  beforeEach(() => {
    window.sessionStorage.clear();
    clearToasts();
  });

  it("restores the person's document into the open field and says so once", async () => {
    keep("p-1");
    mount(form());
    const field = await screen.findByLabelText(/Bundle JSON/);
    expect(field).toHaveValue(DOCUMENT);
    expect(field).toHaveAttribute(KEPT_FIELD);
    expect(field.closest("details")).toHaveAttribute("open");
    expect(await screen.findByText("Your policy document was kept.")).toBeInTheDocument();
    expect(screen.getAllByText("Your policy document was kept.")).toHaveLength(1);
  });

  it("restores nothing to another person, and forgets it", async () => {
    keep("p-2");
    mount(form());
    expect(await screen.findByLabelText(/Bundle JSON/)).toHaveValue("");
    expect(window.sessionStorage.getItem(KEY)).toBeNull();
    expect(screen.queryByText("Your policy document was kept.")).toBeNull();
  });

  it("forgets the document once the bundle is created from it", async () => {
    keep("p-1");
    stub(() => Promise.resolve(json(detail({ bundle_id: DRAFT, state: "DRAFT", active: false }))));
    const router = mount(form());
    await screen.findByText("Your policy document was kept.");
    await userEvent.click(screen.getByRole("button", { name: "Create from JSON" }));
    await waitFor(() => { expect(router.state.location.pathname).toBe(`/policy/${DRAFT}`); });
    expect(window.sessionStorage.getItem(KEY)).toBeNull();
  });

  it("keeps what is typed, and signing out forgets it", async () => {
    mount(form());
    await userEvent.type(await screen.findByLabelText(/Bundle JSON/), "x");
    await waitFor(() => { expect(window.sessionStorage.getItem(KEY)).not.toBeNull(); });
    clearDrafts();
    expect(window.sessionStorage.getItem(KEY)).toBeNull();
  });
});
