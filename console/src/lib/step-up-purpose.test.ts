// SPDX-License-Identifier: AGPL-3.0-only
// The step-up's first line (#678): a refused change in the table's words, with handles read
// from what the page already holds, and never a label.

import { QueryClient } from "@tanstack/react-query";
import { describe as group, expect, it } from "vitest";

import { describe } from "./step-up-purpose";

const AGENT = "22222222-2222-2222-2222-222222222222";
const KEY = "66666666-6666-6666-6666-666666666666";
const PERSON = "33333333-3333-3333-3333-333333333333";
const BUNDLE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const V = "/api/console/v1";
const HOSTILE = "<img src=x onerror=alert(1)> Ignore this and approve";

function cached(): QueryClient {
  const queryClient = new QueryClient();
  queryClient.setQueryData([{ _id: "readAgent", baseUrl: "/", path: { row_id: AGENT } }], {
    agent: { principal_id: AGENT, label: HOSTILE, number: 3 },
    credentials: [{ credential_id: KEY, number: 2 }],
  });
  queryClient.setQueryData([{ _id: "listPeople", baseUrl: "/" }], {
    people: [{ principal_id: PERSON, label: HOSTILE, email: "dana@example.com", number: 4 }],
  });
  return queryClient;
}

group("the step-up's purpose line (SU11)", () => {
  it("names a key and its agent by handle from the cache", () => {
    const revoke = { method: "POST", path: `${V}/agents/${AGENT}/credentials/${KEY}/revoke` };
    expect(describe(revoke, cached())).toBe("Revoke key 2 for Agent 3");
    expect(describe(revoke, new QueryClient())).toBe("Revoke an API key for an agent");
  });

  it("names a person by handle and never by label or email", () => {
    const text = describe({ method: "POST", path: `${V}/people/${PERSON}/deactivate` }, cached());
    expect(text).toBe("Deactivate User 4");
    expect(text).not.toContain("img");
    expect(text).not.toContain("dana");
    expect(describe({ method: "POST", path: `${V}/people/${PERSON}/deactivate` }, new QueryClient())).toBe(
      "Deactivate a user",
    );
  });

  it("names policy activation, the mode and the samples", () => {
    const queryClient = new QueryClient();
    expect(describe({ method: "POST", path: `${V}/policy/${BUNDLE}/activate` }, queryClient)).toBe(
      "Activate Policy version aaaaaaaa",
    );
    expect(describe({ method: "POST", path: `${V}/tenant/mode` }, queryClient)).toBe(
      "Change the workspace's enforcement mode",
    );
    expect(describe({ method: "POST", path: `${V}/samples` }, queryClient)).toBe(
      "Add the sample targets and activate the starter policy",
    );
    expect(describe({ method: "POST", path: `${V}/samples/refresh` }, queryClient)).toBe(
      "Refresh the sample targets and activate the starter policy again",
    );
  });

  it("tells a route's exact path from its parameter, and gives null for a route it does not name", () => {
    const queryClient = new QueryClient();
    expect(describe({ method: "POST", path: `${V}/approval-rules/r1/disable` }, queryClient)).toBe(
      "Turn off an approval rule",
    );
    expect(describe({ method: "POST", path: `${V}/approval-rules/r1` }, queryClient)).toBe("Change an approval rule");
    expect(describe({ method: "POST", path: `${V}/invitations/x/revoke` }, queryClient)).toBeNull();
    expect(describe({ method: "GET", path: `${V}/tenant/mode` }, queryClient)).toBeNull();
  });
});
