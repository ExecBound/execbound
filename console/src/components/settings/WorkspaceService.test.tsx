// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { act, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { readAccountRequestsOptions } from "../../api/@tanstack/react-query.gen";
import type { QueuedRequest } from "../../api/types.gen";
import { NO_SERVICE, PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { withEdition } from "../../test/edition";
import { answerWith, renderPage } from "../../test/page";
import { WorkspaceService } from "./WorkspaceService";

const REQUESTS = "/api/console/v1/account/requests";
const PENDING: QueuedRequest = {
  request_id: "5a5a5a5a-0000-4000-8000-000000000001",
  kind: "data_access",
  name: "Dana",
  principal_id: "6d2c1f0a-0000-4000-8000-000000000001",
  number: 3,
  principal_kind: "HUMAN_APPROVER",
  state: "pending",
  requested_at: "2026-09-26T10:00:00+00:00",
  response: null,
  closed_at: null,
};

/** A workspace administrator: the one who reads and answers the workspace's requests. */
const WORKSPACE_ADMINISTRATOR: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "policy.manage", "approvals.decide", "access.manage", "workspace.manage"],
};

/**
 * An administrator seated as `ADMIN` in one space: an administrator, without the workspace-wide
 * `access.manage` that the workspace's requests take.
 */
const SPACE_ADMINISTRATOR: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "policy.manage", "approvals.decide"],
};

const NOTE = "Only a workspace administrator reads and answers these requests, because they come from every space.";

/** Renders from the same read as the requests card, once a read of it has failed. */
function RequestsReadFailed() {
  const requests = useQuery(readAccountRequestsOptions());
  return requests.isError ? <p>Requests read failed</p> : null;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the workspace's service cards (#496)", () => {
  it("shows the data and closure requests, and asks for no plan and no product counts", async () => {
    const seen = answerWith({ [`GET ${REQUESTS}`]: { body: [] } });
    renderPage(<WorkspaceService />, WORKSPACE_ADMINISTRATOR);
    expect(await screen.findByText("No requests yet.")).toBeInTheDocument();
    expect(screen.queryByText("Plan and usage")).toBeNull();
    expect(screen.queryByText("Optional product analytics")).toBeNull();
    expect(screen.queryByRole("link", { name: "contact sales" })).toBeNull();
    expect(seen.map((request) => request.path)).toEqual([REQUESTS]);
  });

  it("links the deployment's request-handling guidance where it names a page for it (#496)", async () => {
    answerWith({ [`GET ${REQUESTS}`]: { body: [] } });
    const service = { ...NO_SERVICE, privacy_requests_url: "https://example.com/help#requests" };
    renderPage(<WorkspaceService />, { ...WORKSPACE_ADMINISTRATOR, service });
    expect(await screen.findByText("No requests yet.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Request-handling guidance and escalation" })).toHaveAttribute(
      "href",
      "https://example.com/help#requests",
    );
  });

  it("shows no guidance link where the deployment names none (#496)", async () => {
    answerWith({ [`GET ${REQUESTS}`]: { body: [] } });
    renderPage(<WorkspaceService />, WORKSPACE_ADMINISTRATOR);
    expect(await screen.findByText("No requests yet.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Data and closure requests" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Request-handling guidance and escalation" })).toBeNull();
    // An anchor with no href has no link role, so its words are looked for too.
    expect(screen.queryByText("Request-handling guidance and escalation")).toBeNull();
    expect(screen.queryAllByRole("link")).toEqual([]);
  });

  it("puts the edition's panels after the requests", async () => {
    answerWith({ [`GET ${REQUESTS}`]: { body: [] } });
    renderPage(withEdition(<WorkspaceService />, { WorkspacePanels: () => <p>Edition panels</p> }), WORKSPACE_ADMINISTRATOR);
    const panels = await screen.findByText("Edition panels");
    const requests = screen.getByRole("heading", { name: "Data and closure requests" });
    expect(requests.compareDocumentPosition(panels) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("keeps the requests it read through a background read that fails", async () => {
    let reads = 0;
    answerWith({
      [`GET ${REQUESTS}`]: () => (++reads === 1 ? { body: [PENDING] } : { status: 503, body: { code: "UNAVAILABLE", detail: "Unavailable." } }),
    });
    const { queryClient } = renderPage(<><WorkspaceService /><RequestsReadFailed /></>, WORKSPACE_ADMINISTRATOR);
    expect(await screen.findByRole("button", { name: "Record response" })).toBeInTheDocument();
    // What returning to the tab does to a stale queue: it reads it again, and here that read fails.
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: [{ _id: "readAccountRequests" }] });
    });
    // The sentinel renders from the same failed read as the card, so the card has had it too.
    expect(await screen.findByText("Requests read failed")).toBeInTheDocument();
    expect(reads).toBe(2);
    expect(screen.queryByText(/Requests could not be loaded/)).toBeNull();
    expect(screen.getByRole("button", { name: "Record response" })).toBeInTheDocument();
    expect(screen.getByText("Access my data")).toBeInTheDocument();
  });

  it("shows a space administrator a note in place of the requests, and never reads them", async () => {
    const seen = answerWith({ [`GET ${REQUESTS}`]: { body: [PENDING] } });
    renderPage(withEdition(<WorkspaceService />, { WorkspacePanels: () => <p>Edition panels</p> }), SPACE_ADMINISTRATOR);
    expect(await screen.findByText("Edition panels")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Data and closure requests" })).toBeInTheDocument();
    expect(screen.getByText(NOTE)).toBeInTheDocument();
    expect(screen.queryByText("Dana", { exact: false })).toBeNull();
    expect(screen.queryByRole("button", { name: "Record response" })).toBeNull();
    expect(screen.queryByText("No requests yet.")).toBeNull();
    expect(seen.map((request) => request.path)).toEqual([]);
  });

  it("shows a workspace administrator the requests and no note", async () => {
    answerWith({ [`GET ${REQUESTS}`]: { body: [PENDING] } });
    renderPage(<WorkspaceService />, WORKSPACE_ADMINISTRATOR);
    expect(await screen.findByRole("button", { name: "Record response" })).toBeInTheDocument();
    expect(screen.getByText("Dana", { exact: false })).toBeInTheDocument();
    expect(screen.queryByText(NOTE)).toBeNull();
  });
});
