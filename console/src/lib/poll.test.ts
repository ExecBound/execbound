// SPDX-License-Identifier: AGPL-3.0-only
// The one polling timer (#427): a tick asks each endpoint once however many components
// watch it, every endpoint lands on the same tick, and nothing ticks while the tab is hidden.

import { afterEach, describe, expect, it, vi } from "vitest";

import { POLL_MS, polling, subscribe } from "./poll";

let off: (() => void)[] = [];

function watch(key: string): ReturnType<typeof vi.fn> {
  const poll = vi.fn();
  off.push(subscribe(key, poll));
  return poll;
}

function show(state: "visible" | "hidden"): void {
  Object.defineProperty(document, "visibilityState", { value: state, configurable: true });
  document.dispatchEvent(new Event("visibilitychange"));
}

afterEach(() => {
  for (const stop of off) stop();
  off = [];
  show("visible");
  vi.useRealTimers();
});

describe("the polling timer", () => {
  it("asks each endpoint once a tick, whoever is watching it", () => {
    vi.useFakeTimers();
    const overview = watch("overview");
    const executions = watch("executions");
    const approvals = watch("approvals");
    // A second component watching the approvals count: one request serves both.
    const sidebar = watch("approvals");
    vi.advanceTimersByTime(POLL_MS);
    expect(overview).toHaveBeenCalledTimes(1);
    expect(executions).toHaveBeenCalledTimes(1);
    expect(approvals).toHaveBeenCalledTimes(1);
    expect(sidebar).not.toHaveBeenCalled();
    vi.advanceTimersByTime(POLL_MS);
    expect(overview).toHaveBeenCalledTimes(2);
    expect(executions).toHaveBeenCalledTimes(2);
    expect(approvals).toHaveBeenCalledTimes(2);
  });

  it("does not start a second timer when a later endpoint joins", () => {
    vi.useFakeTimers();
    const first = watch("overview");
    vi.advanceTimersByTime(POLL_MS / 2);
    const late = watch("executions");
    // Half a period later both are still on the one timer, so both land together.
    vi.advanceTimersByTime(POLL_MS / 2);
    expect(first).toHaveBeenCalledTimes(1);
    expect(late).toHaveBeenCalledTimes(1);
  });

  it("stops while the tab is hidden and starts again when it shows", () => {
    vi.useFakeTimers();
    const overview = watch("overview");
    show("hidden");
    expect(polling()).toBe(false);
    vi.advanceTimersByTime(POLL_MS * 5);
    expect(overview).not.toHaveBeenCalled();
    show("visible");
    expect(polling()).toBe(true);
    vi.advanceTimersByTime(POLL_MS);
    expect(overview).toHaveBeenCalledTimes(1);
  });

  it("stops entirely when the last watcher goes", () => {
    vi.useFakeTimers();
    watch("overview");
    expect(polling()).toBe(true);
    for (const stop of off) stop();
    off = [];
    expect(polling()).toBe(false);
  });
});
