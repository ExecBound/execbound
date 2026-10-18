// SPDX-License-Identifier: AGPL-3.0-only
// The source token shown once (MC14, MC20, #678): titled for what it is, the token only in its
// read-only field with a Copy button, the recipe below never carrying it, the intake-only
// sentence and nothing that says the holder can act as anyone; it closes on its own button
// only, and afterwards the token is nowhere the console keeps anything.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { MintedSource } from "../../api/types.gen";
import { clearToasts } from "../../lib/toast";
import { answerWith, keptNowhere, renderPage } from "../../test/page";
import { minted, TOKEN } from "../../test/source-data";
import { SourceTokenDialog } from "./SourceTokenDialog";

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

function Holder({ initial, onClosed }: { initial: MintedSource; onClosed: () => void }) {
  const [shown, setShown] = useState<MintedSource | null>(initial);
  return (
    <SourceTokenDialog
      minted={shown}
      onClose={() => {
        setShown(null);
        onClosed();
      }}
    />
  );
}

function open(initial = minted()) {
  answerWith({});
  const onClosed = vi.fn();
  const rendered = renderPage(<Holder initial={initial} onClosed={onClosed} />);
  return { ...rendered, onClosed };
}

function occurrences(text: string, part: string): number {
  return text.split(part).length - 1;
}

describe("the source token dialog (MC14)", () => {
  it("shows the token once, in its field, with the recipe and the intake-only sentence", async () => {
    open();
    const dialog = await screen.findByRole("dialog", { name: "Copy the source token now" });
    const field = within(dialog).getByLabelText(/Source token/);
    expect(field).toHaveValue(TOKEN);
    expect(field).toHaveAttribute("readonly");
    // The token is in the field and nowhere in the dialog's text: not in the recipe below it.
    expect(occurrences(dialog.textContent, TOKEN)).toBe(0);
    expect(occurrences(dialog.innerHTML, TOKEN)).toBeLessThanOrEqual(1);
    expect(within(dialog).getByRole("button", { name: "Copy" })).toBeInTheDocument();
    expect(dialog).toHaveTextContent(
      "This token authorizes intake only. It lets one Tines story send events about itself to ExecBound. It cannot run actions, approve requests or read anything from ExecBound.",
    );
    expect(dialog).not.toHaveTextContent(/act as|console API/i);
    expect(dialog).toHaveTextContent("https://console.example/v1/monitor/events");
    expect(dialog).toHaveTextContent("restrict its domain to console.example");
    expect(dialog).toHaveTextContent("Bearer <<CREDENTIAL.your_credential_name>>");
    const body = within(dialog).getByLabelText("Heartbeat body");
    expect(body).toHaveTextContent('"story_id": "4001"');
    expect(body).toHaveTextContent('"kind": "heartbeat"');
  });

  it("copies the token exactly", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    open();
    const dialog = await screen.findByRole("dialog", { name: "Copy the source token now" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Copy" }));
    expect(writeText).toHaveBeenCalledWith(TOKEN);
  });

  it("says rotating again ends any earlier token's grace, so a lost token is replaced knowingly", async () => {
    open();
    const dialog = await screen.findByRole("dialog", { name: "Copy the source token now" });
    expect(dialog).toHaveTextContent(
      "if it is lost, rotate the source to issue another. Rotating again stops at once any earlier token still within its grace.",
    );
  });

  it("names when a rotated source's previous token stops reporting", async () => {
    open(minted({ previous_valid_until: "2026-10-12T12:10:00+00:00" }));
    const dialog = await screen.findByRole("dialog", { name: "Copy the source token now" });
    expect(dialog).toHaveTextContent(/The previous token keeps reporting until/);
    expect(dialog).toHaveTextContent(/update the story's credential before then\. Rotating again before then stops it at once\./);
    expect(within(dialog).getByText(/The previous token keeps reporting until/).querySelector("time")).toHaveAttribute(
      "dateTime",
      "2026-10-12T12:10:00+00:00",
    );
  });

  it("closes on its own button only, and then the token is nowhere", async () => {
    const { queryClient, onClosed } = open();
    const dialog = await screen.findByRole("dialog", { name: "Copy the source token now" });
    await userEvent.keyboard("{Escape}");
    expect(screen.getByRole("dialog", { name: "Copy the source token now" })).toBeInTheDocument();
    expect(onClosed).not.toHaveBeenCalled();
    // A stray press outside it, on the scrim or the page behind, keeps it open too.
    const outside = userEvent.setup({ pointerEventsCheck: 0 });
    const scrim = document.querySelector<HTMLElement>(".scrim");
    expect(scrim).not.toBeNull();
    for (const target of [scrim, document.body]) {
      if (target === null) continue;
      await outside.pointer({ keys: "[MouseLeft]", target });
    }
    expect(screen.getByRole("dialog", { name: "Copy the source token now" })).toBeInTheDocument();
    expect(onClosed).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: "I have copied it" }));
    await waitFor(() => {
      expect(onClosed).toHaveBeenCalledTimes(1);
    });
    await keptNowhere(queryClient, TOKEN);
  });
});
