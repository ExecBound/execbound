// SPDX-License-Identifier: AGPL-3.0-only
// Waiting for a new source's first heartbeat (MC16, #678): it reads the source every ten
// seconds while the page is visible and never while it is hidden, stops after ten minutes and
// says so plainly, and flips to reporting on the first heartbeat, linking to Activity.

import { act, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { answerWith, renderPage, type Seen } from "../../test/page";
import { SOURCE, source } from "../../test/source-data";
import { SourceWaiting } from "./SourceWaiting";

const READ = `/api/console/v1/monitor/sources/${SOURCE}`;

afterEach(() => {
  Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
  document.dispatchEvent(new Event("visibilitychange", { bubbles: true }));
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function reads(calls: Seen[]): number {
  return calls.filter((call) => call.method === "GET" && call.path === READ).length;
}

/** The waiting line itself, not the toast region beside it. */
function line(): HTMLElement {
  const found = document.querySelector<HTMLElement>("p.monitor-note[role=status]");
  if (found === null) throw new Error("no waiting line");
  return found;
}

function hide(hidden: boolean) {
  Object.defineProperty(document, "visibilityState", { value: hidden ? "hidden" : "visible", configurable: true });
  // As a browser fires it: at the document, bubbling to the window the query client listens on.
  document.dispatchEvent(new Event("visibilitychange", { bubbles: true }));
}

describe("waiting for the first heartbeat (MC16)", () => {
  it("reads the source every ten seconds while visible, and not at all while hidden", async () => {
    vi.useFakeTimers();
    const calls = answerWith({ [`GET ${READ}`]: { body: source() } });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(1);
    });
    expect(line()).toHaveTextContent("Waiting for the first heartbeat from story 4001…");
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(2);
    });
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(3);
    });
    hide(true);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(reads(calls)).toBe(3);
    hide(false);
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(reads(calls)).toBeGreaterThan(3);
    });
  });

  it("stops after ten minutes and says what to check", async () => {
    vi.useFakeTimers();
    const calls = answerWith({ [`GET ${READ}`]: { body: source() } });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(1);
    });
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await act(async () => {
      await Promise.resolve();
    });
    expect(line()).toHaveTextContent(
      "No heartbeat yet. Check the story's HTTP Request action and its credential, then reload.",
    );
    // Ten minutes of reads every ten seconds, and one more once they are up.
    const stopped = reads(calls);
    expect(stopped).toBeLessThanOrEqual(62);
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    expect(reads(calls)).toBe(stopped);
  });

  it.each([
    [900, "every 15 minutes", "30 minutes"],
    [3600, "every hour", "2 hours"],
  ])(
    "never calls a %i-second source's story faulty when its ten minutes end before its first heartbeat is due",
    async (seconds, every, allowed) => {
      vi.useFakeTimers();
      const calls = answerWith({ [`GET ${READ}`]: { body: source({ heartbeat_seconds: seconds }) } });
      renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
      await vi.waitFor(() => {
        expect(reads(calls)).toBe(1);
      });
      await vi.advanceTimersByTimeAsync(10 * 60_000);
      await act(async () => {
        await Promise.resolve();
      });
      // A correctly built story may not have sent its first heartbeat yet, and the health pass
      // allows it twice its interval: the card says when to look again, not that it is broken.
      expect(line()).toHaveTextContent(
        `No heartbeat yet. This source expects one ${every}, so the story's first can take that long, and this has stopped checking on its own. Reload later; if the source is marked stale, ${allowed} after it was added, check the story's HTTP Request action and its credential.`,
      );
      const stopped = reads(calls);
      await vi.advanceTimersByTimeAsync(5 * 60_000);
      expect(reads(calls)).toBe(stopped);
    },
  );

  it("says what to check once the health pass has called a 15-minute source silent before its ten minutes end", async () => {
    vi.useFakeTimers();
    answerWith({ [`GET ${READ}`]: { body: source({ heartbeat_seconds: 900, health_state: "STALE", coverage: "No heartbeat" }) } });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await act(async () => {
      await Promise.resolve();
    });
    expect(line()).toHaveTextContent("No heartbeat yet. Check the story's HTTP Request action and its credential, then reload.");
  });

  it("reads once more before saying no heartbeat came, when the ten minutes ended while hidden", async () => {
    vi.useFakeTimers();
    let heard = false;
    const calls = answerWith({
      [`GET ${READ}`]: () => ({
        body: heard ? source({ coverage: "Reporting", last_heartbeat_at: "2026-10-12T12:08:00+00:00" }) : source(),
      }),
    });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(1);
    });
    // The administrator is in Tines; the story's first heartbeat arrives while this tab is hidden.
    hide(true);
    heard = true;
    await vi.advanceTimersByTimeAsync(12 * 60_000);
    await act(async () => {
      await Promise.resolve();
    });
    expect(line()).not.toHaveTextContent(/No heartbeat yet/);
    hide(false);
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent("Reporting. First heartbeat at");
    });
  });

  it("says the source is reporting when the page's own read of it already has", async () => {
    vi.useFakeTimers();
    answerWith({ [`GET ${READ}`]: { body: source() } });
    renderPage(
      <SourceWaiting
        sourceId={SOURCE}
        storyId="4001"
        known={source({ coverage: "Reporting", last_heartbeat_at: "2026-10-12T12:03:00+00:00" })}
      />,
    );
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent("Reporting. First heartbeat at");
    });
    expect(line().querySelector("time")).toHaveAttribute("dateTime", "2026-10-12T12:03:00+00:00");
  });

  it("agrees with the health pass once it has called the source silent, and keeps checking for its first heartbeat", async () => {
    vi.useFakeTimers();
    let heard = false;
    const calls = answerWith({
      [`GET ${READ}`]: () => ({
        body: heard
          ? source({ health_state: "STALE", coverage: "Reporting", last_heartbeat_at: "2026-10-12T12:04:00+00:00" })
          : source({ health_state: "STALE", coverage: "No heartbeat" }),
      }),
    });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    // The health pass calls a new source silent twice its interval after its mint, ten minutes for
    // the default, while the card's ten minutes start only when the token dialog closes: the card
    // says so beside the badge and goes on reading.
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent("No heartbeat yet. Check the story's HTTP Request action and its credential; this keeps checking.");
    });
    const after = reads(calls);
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(after + 1);
    });
    heard = true;
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent("Reporting. First heartbeat at");
    });
  });

  it("says to reload once its ten minutes are up with the source still silent", async () => {
    vi.useFakeTimers();
    const calls = answerWith({ [`GET ${READ}`]: { body: source({ health_state: "STALE", coverage: "No heartbeat" }) } });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(1);
    });
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await act(async () => {
      await Promise.resolve();
    });
    expect(line()).toHaveTextContent("No heartbeat yet. Check the story's HTTP Request action and its credential, then reload.");
    const stopped = reads(calls);
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    expect(reads(calls)).toBe(stopped);
  });

  it("stops waiting for a source revoked meanwhile, and says so", async () => {
    vi.useFakeTimers();
    let revoked = false;
    const calls = answerWith({
      [`GET ${READ}`]: () => ({
        body: revoked ? source({ coverage: "Disabled", revoked_at: "2026-10-12T12:02:00+00:00" }) : source(),
      }),
    });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(1);
    });
    revoked = true;
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent("This source was revoked, so story 4001 can no longer report through it.");
    });
    const after = reads(calls);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(reads(calls)).toBe(after);
    expect(line()).not.toHaveTextContent(/Check the story's HTTP Request action/);
  });

  it("says so when the source cannot be read, and stops for one no longer in a Space the reader sees", async () => {
    vi.useFakeTimers();
    let answer = { status: 503, body: { code: "UNAVAILABLE", detail: "x" } };
    const calls = answerWith({ [`GET ${READ}`]: () => answer });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent("The source could not be read just now; this keeps trying.");
    });
    answer = { status: 404, body: { code: "NOT_FOUND", detail: "x" } };
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent("This source is not in a Space you see. Reload to see what is.");
    });
    const after = reads(calls);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(reads(calls)).toBe(after);
  });

  it("never says it keeps trying once its ten minutes are up and the last read failed", async () => {
    vi.useFakeTimers();
    let failing = false;
    const calls = answerWith({
      [`GET ${READ}`]: () => (failing ? { status: 503, body: { code: "UNAVAILABLE", detail: "x" } } : { body: source() }),
    });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(1);
    });
    await vi.advanceTimersByTimeAsync(9 * 60_000 + 55_000);
    failing = true;
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent(
        "The source could not be read when the ten minutes were up, so this has stopped checking on its own and reads it again only when you come back to this tab. Reload to see whether the story is reporting.",
      );
    });
    expect(line()).not.toHaveTextContent(/keeps trying/);
    const after = reads(calls);
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    expect(reads(calls)).toBe(after);
    expect(line()).not.toHaveTextContent(/keeps trying/);
  });

  it("reads the source again each time the reader comes back once it has stopped", async () => {
    vi.useFakeTimers();
    let failing = false;
    let heard = false;
    const calls = answerWith({
      [`GET ${READ}`]: () =>
        failing
          ? { status: 503, body: { code: "UNAVAILABLE", detail: "x" } }
          : { body: heard ? source({ coverage: "Reporting", last_heartbeat_at: "2026-10-12T12:12:00+00:00" }) : source() },
    });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(1);
    });
    await vi.advanceTimersByTimeAsync(9 * 60_000 + 55_000);
    failing = true;
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent(/stopped checking on its own/);
    });
    const stopped = reads(calls);
    // Away in Tines and back: the return reads the source once more, whatever it answered last.
    failing = false;
    heard = true;
    hide(true);
    hide(false);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(stopped + 1);
    });
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent("Reporting. First heartbeat at");
    });
  });

  it("says the source is reporting from its first heartbeat, and links to Activity", async () => {
    vi.useFakeTimers();
    let heard = false;
    const calls = answerWith({
      [`GET ${READ}`]: () => ({
        body: heard ? source({ coverage: "Reporting", last_heartbeat_at: "2026-10-12T12:01:00+00:00" }) : source(),
      }),
    });
    renderPage(<SourceWaiting sourceId={SOURCE} storyId="4001" />);
    await vi.waitFor(() => {
      expect(reads(calls)).toBe(1);
    });
    heard = true;
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(line()).toHaveTextContent("Reporting. First heartbeat at");
    });
    expect(line().querySelector("time")).toHaveAttribute("dateTime", "2026-10-12T12:01:00+00:00");
    expect(screen.getByRole("link", { name: /Activity/ })).toHaveAttribute("href", "/monitor?view=activity");
    const after = reads(calls);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(reads(calls)).toBe(after);
  });
});
