// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, renderHook, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { BoardShot, BoardView } from "../../api/types.gen";
import { readBoardQueryKey } from "../../api/@tanstack/react-query.gen";
import { BoardCounters, figures } from "./BoardCounters";
import { BoardFigure } from "./BoardFigure";
import { BoardIdle } from "./BoardIdle";
import { BoardTicker, tone, word } from "./BoardTicker";
import { delay, figureLabel, height, rows, shotRow, targetRow } from "./geometry";
import { boardSearch } from "./search";
import { liveBoardOptions, streamUrl, streamWords, useBoardStream } from "./useBoardStream";
import { setDeviceZoneForTests, setTimeZone, useTimeZone, utcOffsetMinutes } from "../../lib/time";

function shot(changes: Partial<BoardShot> = {}): BoardShot {
  return {
    agent: 0,
    target: null,
    phase: "land",
    word: "executed",
    detail: "",
    age: 12,
    execution_id: null,
    expires_at: null,
    ...changes,
  };
}

afterEach(() => {
  setDeviceZoneForTests(undefined);
  setTimeZone("local");
  window.localStorage.clear();
});

it("words a held request's deadline from its instant, in the viewer's zone (CF5)", () => {
  setDeviceZoneForTests("America/New_York");
  const expires = new Date(Date.now() + 5 * 60_000 + 30_000).toISOString();
  render(<BoardTicker view={view({ ticker: [shot({ phase: "hold", word: "held for a person", detail: "answer by 17:39:00 UTC", expires_at: expires })] })} />);
  expect(screen.getByText(/^5 min left, by \d\d:\d\d E[DS]T$/)).toBeInTheDocument();
  // The server's "answer by … UTC" belongs to the server-rendered page, not to this one.
  expect(screen.queryByText(/answer by/)).toBeNull();
});

it("prints a lane's handle beside its label, and tells two agents labelled alike apart (#678)", () => {
  const twins = view({
    agents: [
      { index: 0, label: "triage-bot", group: "", handle: "Agent 1" },
      { index: 1, label: "triage-bot", group: "", handle: "Agent 2" },
      { index: 2, label: "Agent 3", group: "", handle: null },
    ],
    ticker: [shot({ agent: 0 }), shot({ agent: 1 }), shot({ agent: 2 })],
  });
  const { container } = render(<BoardFigure view={twins} />);
  expect([...container.querySelectorAll(".lanes title")].map((title) => title.textContent)).toEqual([
    "triage-bot · Agent 1",
    "triage-bot · Agent 2",
  ]);
  render(<BoardTicker view={twins} />);
  const rows = screen.getAllByRole("row").slice(1);
  expect(rows.map((row) => row.querySelector("td")?.textContent)).toEqual(["triage-bot Agent 1", "triage-bot Agent 2", "Agent 3"]);
});

it("names the day UTC's when the viewer chose UTC", () => {
  setTimeZone("utc");
  render(<BoardCounters view={view()} live={false} />);
  expect(screen.getByText("Today (UTC)")).toBeInTheDocument();
});

it("explains a historical request without opening its details", () => {
  render(<BoardTicker view={view({ ticker: [shot({ action: "endpoint.isolate", target_label: "workstation-01", requested_at: "2026-09-22T10:30:00Z" })] })} />);
  expect(screen.getByText("Isolate endpoint")).toBeInTheDocument();
  expect(screen.getByText("workstation-01")).toBeInTheDocument();
  expect(screen.getByText("2026-09-22 10:30 UTC")).toBeInTheDocument();
  expect(screen.getByText("Execution confirmed.")).toBeInTheDocument();
});

describe("a request refused before a plan was frozen", () => {
  it.each([
    ["INVALID_OPERATION", "The action named is not one this space offers."],
    ["INVALID_CONFIGURATION", "The action's provider account belongs to another space, or the agent belongs to too many groups."],
    ["INVALID_BUNDLE", "The policy the agent's space selects cannot authorize this action as the workspace is configured."],
    ["INVALID_TARGET", "The target named could not be found."],
    ["INVALID_CONTEXT", "The target's trusted context was missing, did not match the claimed incident, or was no longer fresh."],
    ["INVALID_ARGUMENTS", "The arguments are not ones the action accepts."],
    ["DEPENDENCY_OR_CONTEXT_UNAVAILABLE", "A dependency or the trusted context was unavailable; the record does not say which."],
  ])("reads %s as a refusal, not as a decision on a frozen plan", (code, sentence) => {
    render(<BoardTicker view={view({ ticker: [shot({ agent: -1, phase: "short", word: "refused before a decision", detail: code })] })} />);
    expect(screen.getByText(sentence)).toBeInTheDocument();
    expect(screen.queryByText(/frozen arguments/)).toBeNull();
    // The recorded code stays one click away, for the person who wants the exact record.
    expect(screen.getByText(code)).toBeInTheDocument();
  });

  it("falls back to the phase's own sentence for a code it has no words for", () => {
    render(<BoardTicker view={view({ ticker: [shot({ agent: -1, phase: "short", word: "refused before a decision", detail: "TENANT_STOPPED" })] })} />);
    expect(screen.getByText("Rejected before a plan could be prepared.")).toBeInTheDocument();
  });

  it("still explains a denial's recorded reason with the decision's words", () => {
    render(<BoardTicker view={view({ ticker: [shot({ phase: "deny", word: "denied", detail: "HUMAN_DENIED" })] })} />);
    expect(screen.getByText("A reviewer refused this request.")).toBeInTheDocument();
  });
});

function view(changes: Partial<BoardView> = {}): BoardView {
  return {
    observed_at: "2026-09-19T12:00:00Z",
    window_seconds: 900,
    max_age_tenths: 150,
    agents: [{ index: 0, label: "isolation-bot", group: "", handle: "Agent 1" }],
    targets: [{ index: 0, label: "host-01", group: "Endpoints, production", handle: null }],
    shots: [],
    ticker: [],
    more_agents: 0,
    more_targets: 0,
    today: { requests: 9, allowed: 6, denied: 2, held: 1, executed: 5, unsettled: 1, observed: 0 },
    window: {
      requests: 3,
      allowed: 2,
      denied: 1,
      held: 0,
      executed: 2,
      unsettled: 0,
      observed: 0,
      limited: 1,
      refused: 1,
    },
    last_request_seconds: 4,
    observations: [],
    watching: false,
    ...changes,
  };
}

describe("the board's geometry", () => {
  it("anchors a shot on its own event time, as a delay rather than a generated class", () => {
    expect(delay(0)).toBe("-0.0s");
    expect(delay(42)).toBe("-4.2s");
    expect(delay(150)).toBe("-15.0s");
  });

  it("gives a request refused before a decision a lane of its own beneath the agents", () => {
    const current = view();
    expect(shotRow(shot(), current)).toBe(0);
    expect(shotRow(shot({ agent: -1, phase: "short" }), current)).toBe(1);
  });

  it("lands a shot on the row its target's name is drawn on, not on the lane's index", () => {
    // The column is drawn sorted by group and label, so a lane assigned second can be the first
    // row. Resolving the shot by index would put the mark one line away from the name.
    const current = view({
      targets: [
        { index: 1, label: "host-02", group: "Endpoints, development", handle: null },
        { index: 0, label: "host-01", group: "Endpoints, production", handle: null },
      ],
    });
    expect(targetRow(shot({ target: 0 }), current)).toBe(1);
    expect(targetRow(shot({ target: 1 }), current)).toBe(0);
    expect(targetRow(shot({ target: null }), current)).toBe(-1);
  });

  it("counts the rows the overflow lines need and makes room for the band", () => {
    const plain = view();
    expect(rows(plain)).toBe(2);
    expect(rows(view({ more_agents: 3 }))).toBe(3);
    expect(height(view({ watching: true }))).toBe(height(plain) + 28);
  });

  it("names the picture with what it currently shows", () => {
    expect(figureLabel(view({ shots: [shot()], more_targets: 5 }))).toBe(
      "Requests from agents through the checkpoint toward targets. 1 request in the last " +
        "fifteen minutes, from 1 agent, naming 6 targets.",
    );
  });
});

describe("the board's search parameters", () => {
  it("reads live as the default and takes both spellings of a paused board", () => {
    expect(boardSearch({})).toEqual({});
    expect(boardSearch({ live: true })).toEqual({});
    expect(boardSearch({ live: false })).toEqual({ live: false });
    // The server-rendered board's own spelling, so its address still pauses here.
    expect(boardSearch({ live: "0" })).toEqual({ live: false });
    expect(boardSearch({ live: "false" })).toEqual({ live: false });
  });

  it("accepts only bounded historical windows and forces a historical view to stay still", () => {
    expect(boardSearch({ window: "1h", live: true })).toEqual({ window: "1h", live: false });
    expect(boardSearch({ window: "24h" })).toEqual({ window: "24h", live: false });
    expect(boardSearch({ window: "7d" })).toEqual({});
  });
});

describe("the board's figure", () => {
  it("draws the checkpoint, both legs of a landed shot and only one of a held one", () => {
    const { container } = render(
      <BoardFigure
        view={view({ shots: [shot({ target: 0 }), shot({ phase: "hold", word: "held" })] })}
      />,
    );
    expect(container.querySelectorAll(".checkpoint-rule")).toHaveLength(1);
    expect(container.querySelectorAll(".shot")).toHaveLength(3);
    expect(container.querySelectorAll(".shot.hold")).toHaveLength(1);
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain("through the checkpoint");
  });

  it("puts a hostile label in text and never in a class, an id or a URL", () => {
    const hostile = '<img src=x onerror=alert(1)>" class="shot land';
    const { container } = render(
      <BoardFigure view={view({ agents: [{ index: 0, label: hostile, group: "", handle: "Agent 1" }] })} />,
    );
    const label = container.querySelector(".lane-label");
    expect(label?.textContent).toBe(hostile);
    expect(container.innerHTML).not.toContain("onerror=alert(1)>");
    expect(container.querySelectorAll("img")).toHaveLength(0);
  });

  it("draws the monitoring band only when something is watching", () => {
    const seen = { target: 0, label: "host-01", action: "tool.call", flagged: true, age: 3 };
    expect(render(<BoardFigure view={view()} />).container.querySelectorAll(".seen")).toHaveLength(0);
    const { container } = render(
      <BoardFigure view={view({ watching: true, observations: [seen] })} />,
    );
    expect(container.querySelectorAll(".seen.flagged")).toHaveLength(1);
    expect(container.querySelector(".band-label")?.textContent).toBe(
      "Seen by monitoring, not governed",
    );
  });

  it("gives every shot the delay its age asks for, through the style property", () => {
    const { container } = render(<BoardFigure view={view({ shots: [shot({ age: 37 })] })} />);
    expect(container.querySelector<SVGElement>(".shot")?.style.animationDelay).toBe("-3.7s");
  });
});

describe("the board's counters", () => {
  it("leaves out a figure the period does not count rather than drawing it as zero", () => {
    const labels = figures(view().today).map((figure) => figure.label);
    expect(labels).not.toContain("by a limit");
    expect(labels).not.toContain("refused before a decision");
    expect(figures(view().window).map((figure) => figure.label)).toContain(
      "refused before a decision",
    );
  });

  it("says which period each row is, and says where the two window figures come from", () => {
    setDeviceZoneForTests("America/New_York");
    render(<BoardCounters view={view()} live={false} />);
    // The viewer's own day, named by the zone that applied at its midnight.
    expect(screen.getByText(/^Today, since 00:00 E[DS]T$/)).toBeInTheDocument();
    expect(screen.queryByText("Today, UTC")).toBeNull();
    expect(screen.getByText("Last fifteen minutes")).toBeInTheDocument();
    expect(screen.getByText(/counted for the window only/)).toBeInTheDocument();
  });
});

describe("a lapsed approval on the board (#678)", () => {
  it("counts lapses after the held figure, and leaves the figure out at zero", () => {
    const counters = { requests: 3, allowed: 0, denied: 0, held: 1, executed: 0, unsettled: 0, observed: 0 };
    const labels = (lapsed: number) => figures({ ...counters, lapsed }).map((figure) => figure.label);
    expect(labels(2)).toEqual([
      "requests",
      "allowed",
      "denied",
      "held for a person",
      "lapsed before a decision",
      "executed",
      "observed only",
      "unsettled",
    ]);
    expect(labels(0)).not.toContain("lapsed before a decision");
  });

  it("says a lapse and an unused approval ran nothing, and never that they are held", () => {
    const at = "2026-09-19T13:50:00Z";
    render(
      <BoardTicker
        view={view({
          ticker: [
            shot({ phase: "hollow", word: "lapsed", detail: "lapsed at 13:50:00 UTC", expires_at: at, lapsed: true }),
            shot({ phase: "hollow", word: "unused", detail: "approved, not used by 13:50:00 UTC", expires_at: at, unused: true }),
          ],
        })}
      />,
    );
    expect(screen.getByText(/^Lapsed before a decision; nothing ran\.Lapsed at/)).toBeInTheDocument();
    expect(screen.getByText(/^Approved, not used before the deadline; nothing ran\.Not used by/)).toBeInTheDocument();
    expect(screen.getByText("lapsed")).toBeInTheDocument();
    expect(screen.getByText("not used")).toBeInTheDocument();
    expect(screen.queryByText(/held/i)).toBeNull();
    expect(screen.queryByText(/Waiting for a reviewer/)).toBeNull();
  });
});

describe("the last request figure", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("ages the server's number by local elapsed time while the board is live", () => {
    render(<BoardCounters view={view()} live />);
    expect(screen.getByText(/Last request 4 seconds ago\./)).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(3000);
    });
    expect(screen.getByText(/Last request 7 seconds ago\./)).toBeInTheDocument();
  });

  it("does not age a paused board, because a paused board is a picture of one moment", () => {
    render(<BoardCounters view={view()} live={false} />);
    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(screen.getByText(/Last request 4 seconds ago\./)).toBeInTheDocument();
  });

  it("says so when there is no recorded request in the viewer's scope", () => {
    render(<BoardCounters view={view({ last_request_seconds: null })} live />);
    expect(screen.getByText(/No recorded request in your current view\./)).toBeInTheDocument();
  });

  it("shows an older last known request even when the live window is empty", () => {
    render(<BoardCounters view={view({ last_request_seconds: 7200 })} live={false} />);
    expect(screen.getByText(/Last request 2 hours ago\./)).toBeInTheDocument();
  });

  it("names the selected historical period", () => {
    render(<BoardCounters view={view({ window_seconds: 86400 })} live={false} />);
    expect(screen.getByText("Last 24 hours")).toBeInTheDocument();
    expect(screen.queryByText("Last fifteen minutes")).not.toBeInTheDocument();
  });
});

describe("the ticker", () => {
  it("gives every phase a decision tone and every shot a word", () => {
    expect(tone("deny")).toBe("deny");
    expect(tone("land")).toBe("allow");
    expect(tone("observe")).toBe("obs");
    expect(tone("nonsense")).toBe("stale");
    expect(word(shot({ word: "" }))).toBe("in flight");
  });

  it("names the agent and states the word beside it", () => {
    render(<BoardTicker view={view({ ticker: [shot()] })} />);
    expect(screen.getByText("isolation-bot")).toBeInTheDocument();
    expect(screen.getByText("executed")).toBeInTheDocument();
  });

  it("says a limit blocked a denial the server words as a limit, which records no single reason", () => {
    // The server words a denial `limit` by the rule the agent's category is read by. A policy
    // denial records its codes as a list, so the shot's detail is empty and the word is the signal.
    render(<BoardTicker view={view({ ticker: [shot({ phase: "deny", word: "limit", detail: "" })] })} />);
    expect(screen.getByText("limit")).toBeInTheDocument();
    expect(screen.getByText("An impact limit blocked this request.")).toBeInTheDocument();
    expect(screen.queryByText("Blocked before execution.")).toBeNull();
  });

  it("does not read an approval obligation's prefix as a denial by a limit", () => {
    render(<BoardTicker view={view({ ticker: [shot({ phase: "deny", word: "denied", detail: "limit:soc-1" })] })} />);
    expect(screen.queryByText("An impact limit blocked this request.")).toBeNull();
  });

  it("says nothing happened rather than leaving a blank region", () => {
    render(<BoardTicker view={view()} />);
    expect(screen.getByText("No requests in the last fifteen minutes.")).toBeInTheDocument();
  });

  it("links each known request to its exact Activity evidence", async () => {
    const id = "10000000-0000-4000-8000-000000000001";
    renderWithRouter(<BoardTicker view={view({ ticker: [shot({ execution_id: id })] })} />);
    expect(await screen.findByRole("link", { name: `Open request ${id}` })).toHaveAttribute(
      "href", `/activity?open=${id}`,
    );
  });
});

function renderWithRouter(children: React.ReactNode) {
  vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
  const routeTree = createRootRoute({ component: () => children });
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/"] }) });
  render(<RouterProvider router={router} />);
}

describe("a quiet board", () => {
  it("offers history and explains that quietness does not establish coverage", async () => {
    renderWithRouter(<BoardIdle view={view()} canManage canReview />);
    expect(await screen.findByRole("link", { name: "Browse requests" })).toHaveAttribute("href", "/activity");
    expect(screen.getByText(/Earlier requests are still available/)).toBeInTheDocument();
    expect(screen.getByText(/does not establish.*every action is governed/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Connect an agent" })).not.toBeInTheDocument();
  });

  it("offers setup only to an administrator with no recorded request", async () => {
    renderWithRouter(<BoardIdle view={view({ last_request_seconds: null })} canManage canReview />);
    expect(await screen.findByRole("link", { name: "Connect an agent" })).toHaveAttribute("href", "/agents");
  });

  it("keeps setup out of a reviewer's empty view", async () => {
    renderWithRouter(<BoardIdle view={view({ last_request_seconds: null })} canManage={false} canReview={false} />);
    await screen.findByRole("link", { name: "Browse requests" });
    expect(screen.queryByRole("link", { name: "Connect an agent" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Open approvals" })).not.toBeInTheDocument();
  });
});

describe("the stream", () => {
  class FakeSource {
    static opened: FakeSource[] = [];
    listeners = new Map<string, (event: MessageEvent<string>) => void>();
    closed = false;
    constructor(readonly url: string) {
      FakeSource.opened.push(this);
    }
    addEventListener(name: string, handler: (event: MessageEvent<string>) => void) {
      this.listeners.set(name, handler);
    }
    close() {
      this.closed = true;
    }
    send(name: string, data: string) {
      this.listeners.get(name)?.(new MessageEvent(name, { data }));
    }
  }

  beforeEach(() => {
    FakeSource.opened = [];
    vi.stubGlobal("EventSource", FakeSource);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function wrapper(client: QueryClient) {
    return function Wrapper({ children }: { children: React.ReactNode }) {
      return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
    };
  }

  it("opens one connection while live and puts every frame into the board's query", () => {
    const client = new QueryClient();
    const { result } = renderHook(() => useBoardStream(true), { wrapper: wrapper(client) });
    expect(FakeSource.opened).toHaveLength(1);
    // The viewer's offset rides on the stream, so its frames count today from their midnight.
    expect(FakeSource.opened[0]?.url).toBe(`/api/console/v1/board/stream?utc_offset=${String(utcOffsetMinutes())}`);
    expect(result.current).toBe("connecting");
    act(() => {
      FakeSource.opened[0]?.send("board", JSON.stringify(view({ more_agents: 2 })));
    });
    expect(result.current).toBe("live");
    const held = client.getQueriesData<BoardView>({ queryKey: [{ _id: "readBoard" }] });
    expect(held[0]?.[1]?.more_agents).toBe(2);
  });

  it("opens nothing at all while the board is paused", () => {
    const client = new QueryClient();
    const { result } = renderHook(() => useBoardStream(false), { wrapper: wrapper(client) });
    expect(FakeSource.opened).toHaveLength(0);
    expect(result.current).toBe("paused");
  });

  it("never replaces a historical snapshot with a live frame", () => {
    const client = new QueryClient();
    const historical = readBoardQueryKey({ query: { window: "1h" } });
    client.setQueryData(historical, view({ window_seconds: 3600 }));
    renderHook(() => useBoardStream(true), { wrapper: wrapper(client) });
    act(() => { FakeSource.opened[0]?.send("board", JSON.stringify(view())); });
    expect(client.getQueryData<BoardView>(historical)?.window_seconds).toBe(3600);
    expect(client.getQueryData<BoardView>(liveBoardOptions(utcOffsetMinutes()).queryKey)?.window_seconds).toBe(900);
  });

  it("follows a change of zone: it reopens with the new offset and still lands where the page reads", () => {
    setDeviceZoneForTests("America/New_York");
    const client = new QueryClient();
    const { result } = renderHook(
      () => {
        const [choice] = useTimeZone();
        useBoardStream(true);
        // What the live page reads, built by the same helper.
        return useQuery({ ...liveBoardOptions(utcOffsetMinutes(choice)), enabled: false });
      },
      { wrapper: wrapper(client) },
    );
    expect(FakeSource.opened[0]?.url).toMatch(/utc_offset=-(240|300)$/);
    act(() => {
      setTimeZone("utc");
    });
    expect(FakeSource.opened[0]?.closed).toBe(true);
    expect(FakeSource.opened).toHaveLength(2);
    expect(FakeSource.opened[1]?.url).toBe("/api/console/v1/board/stream?utc_offset=0");
    act(() => {
      FakeSource.opened[1]?.send("board", JSON.stringify(view({ more_agents: 5 })));
    });
    // A frame written anywhere but the page's own entry would leave the page on its first fetch.
    expect(result.current.data?.more_agents).toBe(5);
  });

  it("carries the workspace generation beside the offset", () => {
    expect(streamUrl("abc", -240)).toBe("/api/console/v1/board/stream?generation=abc&utc_offset=-240");
    expect(streamUrl("", 0)).toBe("/api/console/v1/board/stream?utc_offset=0");
  });

  it("closes the connection when the board is paused and does not reopen it", () => {
    const client = new QueryClient();
    const { rerender } = renderHook((live: boolean) => useBoardStream(live), {
      wrapper: wrapper(client),
      initialProps: true,
    });
    expect(FakeSource.opened).toHaveLength(1);
    rerender(false);
    expect(FakeSource.opened[0]?.closed).toBe(true);
    expect(FakeSource.opened).toHaveLength(1);
  });

  it("says what the connection is doing in words, for every state it can be in", () => {
    for (const state of ["connecting", "live", "paused", "hidden", "closed"] as const) {
      expect(streamWords(state).length).toBeGreaterThan(0);
    }
    expect(streamWords("hidden")).toContain("nothing is requested");
  });
});
