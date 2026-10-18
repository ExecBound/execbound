// SPDX-License-Identifier: AGPL-3.0-only
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useListening } from "./listening";

let state: DocumentVisibilityState = "visible";

function hide(next: DocumentVisibilityState) {
  state = next;
  act(() => {
    document.dispatchEvent(new Event("visibilitychange"));
  });
}

beforeEach(() => {
  state = "visible";
  vi.useFakeTimers();
  vi.spyOn(document, "visibilityState", "get").mockImplementation(() => state);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function listen(props: { active: boolean; pending: boolean }) {
  const check = vi.fn();
  const hook = renderHook((current: { active: boolean; pending: boolean }) => useListening(check, current), {
    initialProps: props,
  });
  act(() => {
    hook.result.current.start();
  });
  return { check, hook };
}

describe("the Verify listener (MQ8, #678)", () => {
  it("checks again every ten seconds while active", () => {
    const { check, hook } = listen({ active: true, pending: false });
    expect(hook.result.current.listening).toBe(true);
    act(() => {
      vi.advanceTimersByTime(9_999);
    });
    expect(check).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(check).toHaveBeenCalledTimes(1);
    // The caller's check goes out and settles; the next is armed after it.
    hook.rerender({ active: true, pending: true });
    hook.rerender({ active: true, pending: false });
    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    expect(check).toHaveBeenCalledTimes(2);
  });

  it("makes no call while the tab is hidden, and resumes when it is visible", () => {
    const { check } = listen({ active: true, pending: false });
    hide("hidden");
    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(check).not.toHaveBeenCalled();
    hide("visible");
    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    expect(check).toHaveBeenCalledTimes(1);
  });

  it("stops after ten minutes of wall time", () => {
    const { check, hook } = listen({ active: true, pending: false });
    for (let index = 0; index < 70; index += 1) {
      act(() => {
        vi.advanceTimersByTime(10_000);
      });
      hook.rerender({ active: true, pending: true });
      hook.rerender({ active: true, pending: false });
    }
    expect(check.mock.calls.length).toBeLessThanOrEqual(60);
    expect(hook.result.current.listening).toBe(false);
    expect(hook.result.current.stoppedAtCap).toBe(true);
  });

  it("stops when it is no longer active, when stopped, and on unmount", () => {
    const { check, hook } = listen({ active: true, pending: false });
    hook.rerender({ active: false, pending: false });
    act(() => {
      vi.advanceTimersByTime(30_000);
    });
    expect(check).not.toHaveBeenCalled();
    hook.rerender({ active: true, pending: false });
    act(() => {
      hook.result.current.stop();
    });
    act(() => {
      vi.advanceTimersByTime(30_000);
    });
    expect(check).not.toHaveBeenCalled();
    act(() => {
      hook.result.current.start();
    });
    hook.unmount();
    act(() => {
      vi.advanceTimersByTime(30_000);
    });
    expect(check).not.toHaveBeenCalled();
  });

  it("never starts a check while one is out", () => {
    const { check } = listen({ active: true, pending: true });
    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(check).not.toHaveBeenCalled();
  });
});
