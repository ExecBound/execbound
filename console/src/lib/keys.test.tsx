// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createSequence, typing } from "../shell/Keyboard";
import { allEntries, visible, type NavigationEntry } from "../shell/navigation";
import { resetSingleKeysForTest, setSingleKeys, singleKeysEnabled } from "./keys";

beforeEach(() => {
  window.localStorage.clear();
  resetSingleKeysForTest();
});

afterEach(() => {
  vi.restoreAllMocks();
  resetSingleKeysForTest();
});

describe("typing", () => {
  it("is true for a field and false for a button", () => {
    const input = document.createElement("input");
    const area = document.createElement("textarea");
    const select = document.createElement("select");
    const editable = document.createElement("div");
    // jsdom does not compute isContentEditable from the attribute.
    Object.defineProperty(editable, "isContentEditable", { value: true });
    expect(typing(input)).toBe(true);
    expect(typing(area)).toBe(true);
    expect(typing(select)).toBe(true);
    expect(typing(editable)).toBe(true);
    expect(typing(document.createElement("button"))).toBe(false);
    expect(typing(null)).toBe(false);
  });
});

describe("the single-key preference", () => {
  it("is on by default and is kept as off when turned off", () => {
    expect(singleKeysEnabled()).toBe(true);
    setSingleKeys(false);
    expect(singleKeysEnabled()).toBe(false);
    expect(window.localStorage.getItem("eb.single-keys")).toBe("off");
    resetSingleKeysForTest();
    expect(singleKeysEnabled()).toBe(false);
    setSingleKeys(true);
    expect(window.localStorage.getItem("eb.single-keys")).toBeNull();
  });

  it("stays on and never throws when storage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(singleKeysEnabled()).toBe(true);
    expect(() => {
      setSingleKeys(false);
    }).not.toThrow();
  });
});

function press(key: string, init: KeyboardEventInit = {}, target: EventTarget = document.body): KeyboardEvent {
  const event = new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true, ...init });
  Object.defineProperty(event, "target", { value: target });
  return event;
}

const ENTRIES: NavigationEntry[] = visible(allEntries(), "ADMIN", { permissions: ["access.manage", "policy.manage", "approvals.decide", "workspace.manage"] });
const APPROVER_ENTRIES: NavigationEntry[] = visible(allEntries(), "APPROVER", {});

function sequence(entries: readonly NavigationEntry[] = ENTRIES) {
  let clock = 0;
  const navigate = vi.fn();
  const openShortcuts = vi.fn();
  const handle = createSequence({ entries, navigate, openShortcuts, now: () => clock });
  return {
    handle,
    navigate,
    openShortcuts,
    wait: (ms: number) => {
      clock += ms;
    },
  };
}

describe("g then a letter (NV5, #678)", () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it("goes to the page within a second, and nowhere after it", () => {
    const keys = sequence();
    keys.handle(press("g"));
    keys.wait(999);
    keys.handle(press("a"));
    expect(keys.navigate).toHaveBeenCalledWith("/approvals");
    keys.navigate.mockClear();
    keys.handle(press("g"));
    keys.wait(1001);
    keys.handle(press("a"));
    expect(keys.navigate).not.toHaveBeenCalled();
  });

  it("does nothing for a letter no page has", () => {
    const keys = sequence();
    keys.handle(press("g"));
    keys.handle(press("x"));
    expect(keys.navigate).not.toHaveBeenCalled();
  });

  it("sends g then ? to Help, and ? alone to the keyboard list", () => {
    const keys = sequence();
    keys.handle(press("g"));
    keys.handle(press("?", { shiftKey: true }));
    expect(keys.navigate).toHaveBeenCalledWith("/help");
    expect(keys.openShortcuts).not.toHaveBeenCalled();
    keys.navigate.mockClear();
    keys.handle(press("?", { shiftKey: true }));
    expect(keys.openShortcuts).toHaveBeenCalledTimes(1);
    expect(keys.navigate).not.toHaveBeenCalled();
    keys.handle(press("?", { altKey: true }));
    keys.handle(press("?", { metaKey: true }));
    expect(keys.openShortcuts).toHaveBeenCalledTimes(1);
  });

  it("never opens a page the role cannot see", () => {
    const keys = sequence(APPROVER_ENTRIES);
    keys.handle(press("g"));
    keys.handle(press("p"));
    expect(keys.navigate).not.toHaveBeenCalled();
  });

  it("does nothing in a field, over a dialog, with a modifier, on a repeat, or with single keys off", () => {
    const keys = sequence();
    const input = document.createElement("input");
    keys.handle(press("g", {}, input));
    keys.handle(press("a", {}, input));
    const dialog = document.createElement("div");
    dialog.setAttribute("role", "dialog");
    document.body.append(dialog);
    keys.handle(press("g"));
    keys.handle(press("a"));
    dialog.remove();
    keys.handle(press("g", { ctrlKey: true }));
    keys.handle(press("a"));
    keys.handle(press("g", { repeat: true }));
    keys.handle(press("a"));
    setSingleKeys(false);
    keys.handle(press("g"));
    keys.handle(press("a"));
    keys.handle(press("?", { shiftKey: true }));
    expect(keys.navigate).not.toHaveBeenCalled();
    expect(keys.openShortcuts).not.toHaveBeenCalled();
  });
});

describe("j and k along a list (NV7, #678)", () => {
  function List() {
    return (
      <ul data-rows="button">
        {["one", "two", "three"].map((name) => (
          <li key={name}>
            <button type="button">{name}</button>
          </li>
        ))}
      </ul>
    );
  }

  it("focuses the first row from no row, moves between rows, and stays at either end", async () => {
    const user = userEvent.setup();
    const handle = createSequence({ entries: [], navigate: vi.fn(), openShortcuts: vi.fn() });
    window.addEventListener("keydown", handle);
    try {
      render(<List />);
      await user.keyboard("k");
      expect(screen.getByRole("button", { name: "one" })).toHaveFocus();
      (document.activeElement as HTMLElement).blur();
      await user.keyboard("j");
      expect(screen.getByRole("button", { name: "one" })).toHaveFocus();
      await user.keyboard("jj");
      expect(screen.getByRole("button", { name: "three" })).toHaveFocus();
      await user.keyboard("j");
      expect(screen.getByRole("button", { name: "three" })).toHaveFocus();
      // In a field, j is a letter.
      const input = document.createElement("input");
      document.body.append(input);
      input.focus();
      await user.keyboard("j");
      expect(input).toHaveFocus();
      expect(input).toHaveValue("j");
      screen.getByRole("button", { name: "two" }).focus();
      setSingleKeys(false);
      await user.keyboard("k");
      expect(screen.getByRole("button", { name: "two" })).toHaveFocus();
    } finally {
      window.removeEventListener("keydown", handle);
    }
  });
});
