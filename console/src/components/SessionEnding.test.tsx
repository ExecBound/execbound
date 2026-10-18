// SPDX-License-Identifier: AGPL-3.0-only
import { act, screen } from "@testing-library/react";
import { useEffect, useState, type ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { forgetServerTime, noteServerTime } from "../lib/clock";
import { noteStorage } from "../lib/kept";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../lib/session";
import { renderPage } from "../test/page";
import SessionEnding from "./SessionEnding";

const signInAgain = vi.fn();

const NOW = Date.parse("2026-10-11T12:00:00Z");
const ENDS = new Date(NOW + 3 * 60 * 1000).toISOString();

const control: { setSession: (session: SessionSummary) => void } = { setSession: () => undefined };

function Live({ initial, children }: { initial: SessionSummary; children: ReactNode }) {
  const [session, set] = useState(initial);
  useEffect(() => {
    control.setSession = set;
  }, []);
  return <SessionContext.Provider value={session}>{children}</SessionContext.Provider>;
}

function KeptField() {
  return <textarea aria-label="Bundle JSON" data-eb-kept="" />;
}

function show(session: Partial<SessionSummary>, extra: ReactNode = null) {
  return renderPage(
    <Live initial={{ ...PLACEHOLDER, endsAt: ENDS, endReason: "sign_in", ...session }}>
      <SessionEnding signInAgain={signInAgain} />
      {extra}
    </Live>,
  );
}

async function pass(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

const notice = () => document.querySelector<HTMLElement>(".banner-ending[role=\"status\"]");

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  vi.setSystemTime(NOW);
  forgetServerTime();
  noteStorage(true);
  signInAgain.mockClear();
});

afterEach(() => {
  vi.useRealTimers();
  forgetServerTime();
  noteStorage(false);
});

describe("the notice before a session's hard end (#678)", () => {
  it("shows nothing three minutes before the end, then the sign-in notice at two", async () => {
    show({});
    await pass(0);
    expect(notice()).toBeNull();
    await pass(59_000);
    expect(notice()).toBeNull();
    await pass(1_000);
    expect(notice()).toHaveTextContent(
      "You will be signed out at" ,
    );
    expect(notice()).toHaveTextContent(
      "eight hours after you signed in. Save what you are doing, then sign in again to keep working.",
    );
    expect(notice()?.querySelector("time")?.getAttribute("dateTime")).toBe(ENDS);
    screen.getByRole("button", { name: "Sign in again" }).click();
    expect(signInAgain).toHaveBeenCalledTimes(1);
    // It never takes focus.
    expect(document.activeElement).toBe(document.body);
  });

  it("says typing is kept only where a keeping field is mounted and storage works", async () => {
    show({}, <KeptField />);
    await pass(60_000);
    expect(notice()).toHaveTextContent("Sign in again to keep working. What you have typed on this page is kept.");
    act(() => {
      noteStorage(false);
    });
    expect(notice()).toHaveTextContent("Save what you are doing, then sign in again to keep working.");
    expect(notice()).not.toHaveTextContent("is kept");
  });

  it("tells a setup credential's holder how to keep signing in, and offers no sign-in", async () => {
    show({ endReason: "setup_credential" }, <KeptField />);
    await pass(60_000);
    expect(notice()).toHaveTextContent(
      "The setup credential you signed in with expires at",
    );
    expect(notice()).toHaveTextContent(
      "and you will be signed out then. It cannot be used after that: set up your own sign-in before then. Save what you are doing.",
    );
    expect(screen.queryByRole("button", { name: "Sign in again" })).toBeNull();
    expect(screen.getByRole("link", { name: "How to sign in after setup" })).toHaveAttribute("href", "/help");
  });

  it("measures the two minutes on the server's clock, not the device's", async () => {
    // The device runs five minutes fast: the server's time is five minutes behind it.
    const server = NOW - 5 * 60 * 1000;
    noteServerTime(new Headers({ date: "Sun, 11 Oct 2026 11:55:00 GMT" }), NOW);
    // Three minutes before the end by the server's clock, two minutes past it by the device's.
    show({ endsAt: new Date(server + 3 * 60 * 1000).toISOString() });
    await pass(0);
    expect(notice()).toBeNull();
    await pass(59_000);
    expect(notice()).toBeNull();
    await pass(1_000);
    expect(notice()).not.toBeNull();
  });

  it("goes away when the session view names a later end, as a sign-in in another tab does", async () => {
    show({});
    await pass(60_000);
    expect(notice()).not.toBeNull();
    act(() => {
      control.setSession({ ...PLACEHOLDER, endsAt: new Date(NOW + 8 * 3600 * 1000).toISOString(), endReason: "sign_in" });
    });
    await pass(0);
    expect(notice()).toBeNull();
  });

  it("shows nothing for a session view that names no end", async () => {
    show({ endsAt: undefined });
    await pass(10 * 60_000);
    expect(notice()).toBeNull();
  });
});
