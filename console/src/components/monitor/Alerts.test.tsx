// SPDX-License-Identifier: AGPL-3.0-only
import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { MonitorDelivery, MonitorDestination } from "../../api/types.gen";
import { edition as core } from "../../edition/core";
import { NO_SERVICE } from "../../lib/session";
import { ADMIN, renderMonitor } from "../../test/monitor";
import { FINDING, snapshot } from "../../test/monitor-data";
import { answerWith } from "../../test/page";
import { NOT_SENT, receivesNothing, rulesWords, SENT, spacesWords } from "./Alerts";

const SNAPSHOT = "GET /api/console/v1/monitor";

const DELIVERED: MonitorDelivery = {
  delivery_id: "d0d0d0d0-0000-4000-8000-000000000001",
  finding_id: FINDING,
  destination_id: "soc-slack",
  created_at: "2026-10-17T12:00:00+00:00",
  state: "DELIVERED",
  attempts: 1,
  last_error: null,
};

const SLACK: MonitorDestination = {
  destination_id: "soc-slack",
  kind: "slack",
  host: "hooks.slack.com",
  rules: ["sensitive-action.v2"],
  spaces: [{ space_id: "5ace0000-0000-4000-8000-000000000001", name: "Customer A" }],
  other_spaces: 1,
  unknown_spaces: 0,
};

const EMAIL: MonitorDestination = { destination_id: "jane", kind: "email", host: "", rules: null, spaces: null, other_spaces: 0, unknown_spaces: 0 };

/** A destination of the workspace whose configured Spaces are none of it, so nothing reaches it. */
const MISTAKEN: MonitorDestination = { ...SLACK, destination_id: "mistaken", spaces: [], other_spaces: 0, unknown_spaces: 1 };

/** Each cell of a row: its stacked label, its text, and whether it is set in mono. */
function cells(row: HTMLElement | undefined) {
  return Array.from(row?.querySelectorAll("td") ?? [], (cell) => [cell.getAttribute("data-label"), cell.textContent, cell.classList.contains("mono")]);
}

/** A table's column headers, in order. */
function headers(table: HTMLElement) {
  return within(table)
    .getAllByRole("columnheader")
    .map((header) => header.textContent);
}

/** The separate parts a row's Spaces cell lists. */
function spaceParts(row: HTMLElement | undefined) {
  const cell = row?.querySelector<HTMLElement>('td[data-label="Spaces"]');
  if (cell === null || cell === undefined) throw new Error("no Spaces cell");
  return within(cell)
    .getAllByRole("listitem")
    .map((item) => item.textContent);
}

/** Who sets findings destinations, as the line under the destinations names them. */
function operatorLine(operator: string | null) {
  return `${operator ?? "This deployment's operator"} sets findings destinations in its private configuration.`;
}

describe("Alert settings (#31)", () => {
  it("says findings are not sent where no destination is configured, and lists every delivery unfolded", async () => {
    const unrouted = { ...DELIVERED, destination_id: null, state: "FAILED", attempts: 0, last_error: "TOO_OLD_TO_SEND" };
    answerWith({ [SNAPSHOT]: { body: snapshot({ deliveries: [unrouted] }) } });
    renderMonitor("/monitor?view=alerts");
    // A status, as the console's other empty states are.
    expect(await screen.findByText(NOT_SENT)).toHaveAttribute("role", "status");
    expect(NOT_SENT).toBe(
      "No findings destination is configured for this workspace, so findings are not sent outside the console. They appear under Findings, in the count beside Monitoring in the sidebar, and on Home.",
    );
    expect(screen.queryByText(SENT)).toBeNull();
    expect(screen.getByRole("heading", { name: "Where findings appear" })).toBeInTheDocument();
    expect(screen.getByText(operatorLine(null))).toBeInTheDocument();
    const table = screen.getByRole("table", { name: /Finding deliveries/ });
    expect(table.closest("details")).toBeNull();
    expect(within(table).getByRole("link", { name: "f1f1f1f1" })).toHaveAttribute("href", `/monitor?view=findings&state=all&open=${FINDING}`);
    const [, row] = within(table).getAllByRole("row");
    // "Not routed" is prose, so it is not set in mono as a destination's id is.
    expect(cells(row)).toEqual([
      [null, "d0d0d0d0", true],
      ["Finding", "f1f1f1f1", true],
      ["Destination", "Not routed", false],
      ["State", "FAILED", false],
      ["Attempts", "0", false],
      ["Last error", "TOO_OLD_TO_SEND", false],
    ]);
    expect(
      screen.getByText(
        "A pending delivery is not a lost finding. One that failed with DELIVERY_UNCERTAIN may still have arrived, so check the destination for its delivery ID.",
      ),
    ).toBeInTheDocument();
  });

  it("lists each findings destination by id, kind, host, rules and Spaces, and no other field the server sends", async () => {
    // Fields the type does not carry, as a server that sent too much would: none is rendered.
    // The URL is split so the export's credential scrub does not read this fake as a webhook.
    const slack = { ...SLACK, url: "https://hooks.slack.com/" + "services/T0/B0/s3cr3t", secret: "s3cr3t-hook" };
    const jane = { ...EMAIL, to: "jane@example.com" };
    answerWith({ [SNAPSHOT]: { body: snapshot({ destinations: [slack, jane], deliveries: [DELIVERED] }) } });
    renderMonitor("/monitor?view=alerts");
    const destinations = await screen.findByRole("table", {
      name: "Findings destinations, as this deployment's private configuration names them. Addresses and secrets are never shown.",
    });
    expect(screen.getByText(SENT)).toBeInTheDocument();
    expect(SENT).toBe(
      "Each finding is sent once, within about five minutes, to every destination below that accepts its rule and its Space. A finding acknowledged before it is sent is not sent. Findings report what was seen. They never block or allow an action.",
    );
    expect(screen.queryByText(NOT_SENT)).toBeNull();
    expect(headers(destinations)).toEqual(["Destination", "Kind", "Host", "Rules", "Spaces"]);
    const [, slackRow, janeRow] = within(destinations).getAllByRole("row");
    // Rule versions are identifiers, set in mono as they are elsewhere; "Every rule" is prose.
    expect(cells(slackRow).slice(0, 4)).toEqual([
      [null, "soc-slack", true],
      ["Kind", "slack", false],
      ["Host", "hooks.slack.com", true],
      ["Rules", "sensitive-action.v2", true],
    ]);
    expect(spaceParts(slackRow)).toEqual(["Customer A", "1 Space you cannot see"]);
    // An email destination has no host, said in prose rather than in mono.
    expect(cells(janeRow).slice(0, 4)).toEqual([
      [null, "jane", true],
      ["Kind", "email", false],
      ["Host", "None", false],
      ["Rules", "Every rule", false],
    ]);
    expect(spaceParts(janeRow)).toEqual(["Every Space"]);
    expect(slackRow).not.toHaveTextContent(/unknown|Receives no findings/);
    expect(document.body.textContent).not.toMatch(/services\/|s3cr3t|@example\.com/);
    const deliveries = screen.getByRole("table", { name: /Finding deliveries/ });
    expect(headers(deliveries)).toEqual(["Delivery", "Finding", "Destination", "State", "Attempts", "Last error"]);
    const [, delivery] = within(deliveries).getAllByRole("row");
    expect(cells(delivery)).toEqual([
      [null, "d0d0d0d0", true],
      ["Finding", "f1f1f1f1", true],
      ["Destination", "soc-slack", true],
      ["State", "DELIVERED", false],
      ["Attempts", "1", false],
      ["Last error", "None", false],
    ]);
    expect(screen.getByText(operatorLine(null))).toBeInTheDocument();
  });

  it("names the deployment's operator as who sets findings destinations, where it names one", async () => {
    answerWith({ [SNAPSHOT]: { body: snapshot({ destinations: [EMAIL] }) } });
    renderMonitor("/monitor?view=alerts", { session: { ...ADMIN, service: { ...NO_SERVICE, operator: "Example Operator" } } });
    expect(await screen.findByText(operatorLine("Example Operator"))).toHaveClass("muted");
    expect(screen.queryByText(/private configuration file/)).toBeNull();
  });

  it("folds the local test receiver for an operator and offers none without operator commands", async () => {
    answerWith({ [SNAPSHOT]: { body: snapshot() } });
    const first = renderMonitor("/monitor?view=alerts");
    const receiver = (await screen.findByText("Local test receiver")).closest("details");
    if (receiver === null) throw new Error("no receiver");
    expect(receiver).not.toHaveAttribute("open");
    expect(receiver).toHaveTextContent(
      "Where no findings destination is configured, process --deliver-local sends findings to an authenticated loopback test receiver. Its deliveries are listed above as local-receiver.",
    );
    expect(within(receiver).getByText("process --deliver-local", { selector: "code" })).toBeInTheDocument();
    expect(within(receiver).getByText("The receiver the monitoring file names, listed as local-receiver")).toBeInTheDocument();
    expect(within(receiver).queryByRole("table")).toBeNull();
    first.unmount();
    renderMonitor("/monitor?view=alerts", { edition: { ...core, operatorCommands: false } });
    const table = await screen.findByRole("table", { name: /Finding deliveries/ });
    // An empty table says so in a row of its own, as the console's other tables do.
    expect(within(table).getByText("No deliveries recorded.")).toBeInTheDocument();
    expect(screen.queryByText("Local test receiver")).toBeNull();
  });

  it("words rules and Spaces from the server's values alone", () => {
    expect(rulesWords(EMAIL)).toBe("Every rule");
    expect(rulesWords({ ...SLACK, rules: ["a.v1", "b.v1"] })).toBe("a.v1, b.v1");
    expect(spacesWords(EMAIL)).toEqual(["Every Space"]);
    expect(spacesWords({ ...SLACK, other_spaces: 2 })).toEqual(["Customer A", "2 Spaces you cannot see"]);
    expect(spacesWords({ ...SLACK, other_spaces: 0 })).toEqual(["Customer A"]);
    expect(spacesWords({ ...SLACK, other_spaces: 0, unknown_spaces: 1 })).toEqual(["Customer A", "1 unknown Space ID"]);
    expect(spacesWords({ ...MISTAKEN, unknown_spaces: 2 })).toEqual(["2 unknown Space IDs"]);
  });

  it("orders the Spaces it names by name, not by identifier", () => {
    const spaces = [
      { space_id: "00000000-0000-4000-8000-000000000001", name: "Zulu" },
      { space_id: "ffffffff-0000-4000-8000-000000000001", name: "Alpha" },
    ];
    expect(spacesWords({ ...SLACK, spaces, other_spaces: 0 })).toEqual(["Alpha", "Zulu"]);
    expect(spacesWords({ ...SLACK, spaces: [...spaces].reverse(), other_spaces: 0 })).toEqual(["Alpha", "Zulu"]);
  });

  it("says a destination receives no findings only where every Space it names is unknown", () => {
    expect(receivesNothing(MISTAKEN)).toBe(true);
    expect(receivesNothing({ ...MISTAKEN, unknown_spaces: 3 })).toBe(true);
    // A Space the reader cannot see may still receive findings, and so may a named one.
    expect(receivesNothing({ ...MISTAKEN, other_spaces: 1 })).toBe(false);
    expect(receivesNothing({ ...SLACK, other_spaces: 0, unknown_spaces: 1 })).toBe(false);
    expect(receivesNothing(EMAIL)).toBe(false);
    expect(receivesNothing({ ...MISTAKEN, unknown_spaces: 0 })).toBe(false);
  });

  it("says an unknown Space ID is a configuration problem, never a Space the reader cannot see, and that it receives nothing", async () => {
    answerWith({ [SNAPSHOT]: { body: snapshot({ destinations: [MISTAKEN, SLACK] }) } });
    renderMonitor("/monitor?view=alerts");
    const destinations = await screen.findByRole("table", { name: /Findings destinations/ });
    const [, mistaken, slack] = within(destinations).getAllByRole("row");
    expect(spaceParts(mistaken)).toEqual(["1 unknown Space ID"]);
    expect(mistaken).toHaveTextContent("Receives no findings");
    expect(mistaken).not.toHaveTextContent("cannot see");
    expect(slack).not.toHaveTextContent("Receives no findings");
  });

  it("keeps each Space it names apart from the next and from the counts, so a comma in a name merges nothing", async () => {
    const spaces = [
      { space_id: "5ace0000-0000-4000-8000-000000000002", name: "Customer B" },
      { space_id: "5ace0000-0000-4000-8000-000000000001", name: "Acme, Inc." },
    ];
    answerWith({ [SNAPSHOT]: { body: snapshot({ destinations: [{ ...SLACK, spaces, other_spaces: 2, unknown_spaces: 0 }] }) } });
    renderMonitor("/monitor?view=alerts");
    const destinations = await screen.findByRole("table", { name: /Findings destinations/ });
    const [, row] = within(destinations).getAllByRole("row");
    expect(spaceParts(row)).toEqual(["Acme, Inc.", "Customer B", "2 Spaces you cannot see"]);
  });

  it("shows every destination and delivery field as text, never as markup", async () => {
    const markup = "<img src=x onerror=alert(1)>";
    // Eight characters, so the identifier's shown prefix is a whole element if parsed as markup.
    const bold = "<b>x</b>";
    answerWith({
      [SNAPSHOT]: {
        body: snapshot({
          destinations: [
            {
              ...SLACK,
              destination_id: `${markup}id`,
              kind: `${markup}kind`,
              host: `${markup}host`,
              rules: [`${markup}rule`],
              spaces: [{ space_id: "5ace0000-0000-4000-8000-000000000001", name: `${markup}space` }],
            },
          ],
          deliveries: [
            {
              ...DELIVERED,
              delivery_id: `${bold}-0000-4000-8000-000000000001`,
              destination_id: `${markup}id`,
              state: `${markup}state`,
              last_error: `${markup}error`,
            },
          ],
        }),
      },
    });
    renderMonitor("/monitor?view=alerts");
    const destinations = await screen.findByRole("table", { name: /Findings destinations/ });
    const deliveries = screen.getByRole("table", { name: /Finding deliveries/ });
    for (const field of ["id", "kind", "host", "rule", "space"]) expect(destinations).toHaveTextContent(`${markup}${field}`);
    for (const field of ["id", "state", "error"]) expect(deliveries).toHaveTextContent(`${markup}${field}`);
    expect(deliveries).toHaveTextContent(bold);
    for (const table of [destinations, deliveries]) {
      expect(table.querySelector("img")).toBeNull();
      expect(table.querySelector("b")).toBeNull();
    }
  });
});
