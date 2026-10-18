// SPDX-License-Identifier: AGPL-3.0-only
import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SampleStatusView } from "../../api/types.gen";
import { PLACEHOLDER } from "../../lib/session";
import { answerWith, renderPage, settle } from "../../test/page";
import { SETUP, setupView } from "../../test/setup-view";
import { NoConnectionHint } from "./NoConnectionHint";

const SAMPLES = "/api/console/v1/samples";
const ADMIN = { ...PLACEHOLDER, role: "ADMIN" as const };
const OFFERED: SampleStatusView = { state: "absent", offered: true, available: true, demo_available: false, demo_needs_refresh: false, bundle_id: null, hosts: [], observed_at: null, stale_at: null, first_request: null };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the Policies page's connection hint (UX12, #678)", () => {
  it("offers the example where samples can tick something in this Space", async () => {
    answerWith({ [`GET ${SETUP}`]: { body: setupView({}, { connected: false }) }, [`GET ${SAMPLES}`]: { body: OFFERED } });
    renderPage(<NoConnectionHint />, ADMIN);
    expect(await screen.findByText(/refused until this Space has a registered connection/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Try an example" })).toHaveAttribute("href", "/welcome?step=example");
  });

  it("says samples go to the default Space, then gives the operator's steps, elsewhere", async () => {
    answerWith({ [`GET ${SETUP}`]: { body: setupView({}, { connected: false, samples_here: false }) }, [`GET ${SAMPLES}`]: { body: OFFERED } });
    renderPage(<NoConnectionHint />, ADMIN);
    expect(await screen.findByText(/added to the workspace's default Space, not this one/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Try an example" })).toBeNull();
    expect(screen.getByRole("region", { name: "Copy instructions for your operator" })).toBeInTheDocument();
  });

  it("gives the operator's steps where no samples are offered", async () => {
    answerWith({ [`GET ${SETUP}`]: { body: setupView({}, { connected: false }) }, [`GET ${SAMPLES}`]: { body: { ...OFFERED, offered: false } } });
    renderPage(<NoConnectionHint />, ADMIN);
    expect(await screen.findByRole("region", { name: "Copy instructions for your operator" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Try an example" })).toBeNull();
  });

  it("asks nothing and says nothing for anyone but an administrator", async () => {
    const seen = answerWith({ [`GET ${SETUP}`]: { body: setupView({}, { connected: false }) }, [`GET ${SAMPLES}`]: { body: OFFERED } });
    const { container } = renderPage(<NoConnectionHint />, { ...PLACEHOLDER, role: "APPROVER" });
    await settle();
    expect(container.querySelector(".no-connection")).toBeNull();
    expect(seen).toEqual([]);
  });

  it("says nothing once the Space has a connection, or where the read fails", async () => {
    answerWith({ [`GET ${SETUP}`]: { body: setupView() }, [`GET ${SAMPLES}`]: { body: OFFERED } });
    const { container, unmount } = renderPage(<NoConnectionHint />, ADMIN);
    await settle();
    expect(container.querySelector(".no-connection")).toBeNull();
    unmount();
    answerWith({ [`GET ${SAMPLES}`]: { body: OFFERED } });
    const failed = renderPage(<NoConnectionHint />, ADMIN);
    await settle();
    expect(failed.container.querySelector(".no-connection")).toBeNull();
  });
});
