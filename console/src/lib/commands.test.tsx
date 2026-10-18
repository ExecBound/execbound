// SPDX-License-Identifier: AGPL-3.0-only
// The palette's command bus (NV12, #678): one pending command, taken once, by its own name,
// within five seconds.

import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { COMMAND_MS, forgetCommands, requestCommand, useCommand, type CommandName } from "./commands";

function Target({ name, open }: { name: CommandName; open: () => void }) {
  useCommand(name, open);
  return null;
}

afterEach(() => {
  forgetCommands();
  vi.useRealTimers();
});

describe("the command bus", () => {
  it("opens the dialog its command names once", () => {
    const open = vi.fn();
    requestCommand("add-agent");
    const first = render(<Target name="add-agent" open={open} />);
    expect(open).toHaveBeenCalledTimes(1);
    first.unmount();
    render(<Target name="add-agent" open={open} />);
    expect(open).toHaveBeenCalledTimes(1);
  });

  it("reaches a page that is already open", () => {
    const open = vi.fn();
    render(<Target name="issue-key" open={open} />);
    expect(open).not.toHaveBeenCalled();
    requestCommand("issue-key");
    expect(open).toHaveBeenCalledTimes(1);
  });

  it("ignores a command older than five seconds", () => {
    vi.useFakeTimers();
    const open = vi.fn();
    requestCommand("new-space");
    vi.advanceTimersByTime(COMMAND_MS + 1);
    render(<Target name="new-space" open={open} />);
    expect(open).not.toHaveBeenCalled();
  });

  it("leaves another name's command alone", () => {
    const open = vi.fn();
    requestCommand("add-agent");
    render(<Target name="add-user" open={open} />);
    expect(open).not.toHaveBeenCalled();
  });
});
