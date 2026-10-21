// SPDX-License-Identifier: AGPL-3.0-only
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { SampleHostView, SampleStatusView } from "../../api/types.gen";
import { answerWith, renderPage } from "../../test/page";
import { TinesTestEvent } from "./TinesTestEvent";

const OPERATION = "op.from-the-server";
function host(hostname: string, effect: string, incident: string | null): SampleHostView {
  return { hostname, effect, incident_id: incident, criticality: 1, environment: "dev", provider_id: `${hostname}-id`, role: "workstation", rules: [] };
}

const HOSTS = [
  host("ws-dev-01.sample.invalid", "allow", "22222222-0000-4000-8000-000000000001"),
  host("dc-01.sample.invalid", "deny", "22222222-0000-4000-8000-000000000002"),
  host("ws-prod-01.sample.invalid", "require approval", "22222222-0000-4000-8000-000000000003"),
  host("no-incident.sample.invalid", "allow", null),
];

function samples(state: SampleStatusView["state"], hosts = HOSTS): SampleStatusView {
  return {
    state,
    offered: true,
    available: true,
    bundle_id: null,
    demo_available: false,
    demo_needs_refresh: false,
    first_request: null,
    hosts,
    observed_at: null,
    stale_at: null,
  };
}

function serve(status: SampleStatusView, operationRef: string | null = OPERATION) {
  answerWith({
    "GET /api/console/v1/connection": { body: { origin: "https://gateway.example.test", recipes: {}, workstation: null, operation_ref: operationRef, samples_state: status.state } },
    "GET /api/console/v1/samples": { body: status },
  });
}

/** Long enough for both stubbed queries to answer. */
async function settled(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 50));
}

async function shownEvent(): Promise<Record<string, unknown>> {
  const region = await screen.findByRole("region", { name: "Test event" });
  return JSON.parse(region.textContent) as Record<string, unknown>;
}

describe("a test event for the Execute story on a sample target (#178)", () => {
  it("fills the story's entry fields from the server's answers, with a new reference", async () => {
    serve(samples("present"));
    renderPage(<TinesTestEvent />);
    const { reference, ...event } = await shownEvent();
    expect(event).toEqual({
      operation_ref: OPERATION,
      target_kind: "hostname",
      target_value: "ws-dev-01.sample.invalid",
      incident_id: "22222222-0000-4000-8000-000000000001",
    });
    expect(reference).toMatch(/^tines-test-[0-9a-f]{8}$/);
  });

  it("follows the target the person picks, with a new reference, and offers only samples with an open incident", async () => {
    serve(samples("present"));
    renderPage(<TinesTestEvent />);
    const before = await shownEvent();
    const picker = screen.getByRole("combobox", { name: "Sample target" });
    expect([...picker.querySelectorAll("option")].map((option) => option.textContent)).toEqual([
      "ws-dev-01.sample.invalid (executes)",
      "dc-01.sample.invalid (is denied)",
      "ws-prod-01.sample.invalid (waits for approval)",
    ]);
    await userEvent.selectOptions(picker, "ws-prod-01.sample.invalid");
    const after = await shownEvent();
    expect(after.target_value).toBe("ws-prod-01.sample.invalid");
    expect(after.incident_id).toBe("22222222-0000-4000-8000-000000000003");
    expect(after.reference).not.toBe(before.reference);
    await userEvent.click(screen.getByRole("button", { name: "New reference" }));
    expect((await shownEvent()).reference).not.toBe(after.reference);
  });

  it("shows no event while the workspace has no samples", async () => {
    serve(samples("absent", []));
    renderPage(<TinesTestEvent />);
    await settled();
    expect(screen.queryByRole("region", { name: "Test event" })).toBeNull();
  });

  it("shows no event when the server names no operation for the samples", async () => {
    serve(samples("present"), null);
    renderPage(<TinesTestEvent />);
    await settled();
    expect(screen.queryByRole("region", { name: "Test event" })).toBeNull();
  });
});
