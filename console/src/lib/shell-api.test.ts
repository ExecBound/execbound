// SPDX-License-Identifier: AGPL-3.0-only
// Each call in `shell-api.ts` against the generated one it stands for: the same query key, so the
// two share a cache, and the same request, so the two reach the same route the same way.
import type { QueryFunctionContext, QueryKey } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as generated from "../api/@tanstack/react-query.gen";
import { client } from "../api/client.gen";
import * as sdk from "../api/sdk.gen";
import * as shell from "./shell-api";

afterEach(() => {
  vi.restoreAllMocks();
});

const APPROVAL = "11111111-0000-4000-8000-000000000001";

/** What the query function hands the client, with the abort signal set aside. */
async function requested(
  method: "get" | "post",
  options: { queryKey: QueryKey; queryFn?: unknown },
): Promise<unknown> {
  const call = vi.spyOn(client, method).mockResolvedValue({ data: {} });
  const run = options.queryFn as (context: QueryFunctionContext) => Promise<unknown>;
  await run({ queryKey: options.queryKey, signal: new AbortController().signal } as QueryFunctionContext);
  const request = { ...(call.mock.calls[0]?.[0] as Record<string, unknown>) };
  delete request.signal;
  call.mockRestore();
  return request;
}

/** The two options' keys are equal, and so are the requests their query functions make. */
async function same(ours: { queryKey: QueryKey; queryFn?: unknown }, theirs: { queryKey: QueryKey; queryFn?: unknown }) {
  expect(ours.queryKey).toEqual(theirs.queryKey);
  expect(await requested("get", ours)).toEqual(await requested("get", theirs));
}

describe("the shell's queries have the generated key and make the generated request", () => {
  it("reads the session", async () => {
    await same(shell.readSessionOptions(), generated.readSessionOptions());
  });

  it("reads the workspaces", async () => {
    await same(shell.readWorkspacesOptions(), generated.readWorkspacesOptions());
  });

  it("lists the spaces", async () => {
    const options = { query: { state: "all" as const, cursor: "next" } };
    await same(shell.listSpacesOptions(options), generated.listSpacesOptions(options));
  });

  it("lists the approvals", async () => {
    const options = { query: { view: "pending" as const } };
    await same(shell.listApprovalsOptions(options), generated.listApprovalsOptions(options));
  });

  it("reads the tenant", async () => {
    await same(shell.readTenantOptions(), generated.readTenantOptions());
  });

  it("reads an approval", async () => {
    const options = { path: { approval_id: APPROVAL } };
    await same(shell.readApprovalOptions(options), generated.readApprovalOptions(options));
  });

  it("names the keys the rest of the console invalidates by", () => {
    expect(shell.readSessionQueryKey()).toEqual(generated.readSessionQueryKey());
    expect(shell.readWorkspacesQueryKey()).toEqual(generated.readWorkspacesQueryKey());
  });
});

describe("the shell's mutations", () => {
  it("sets the session's space as the generated call does", async () => {
    const call = vi.spyOn(client, "post").mockResolvedValue({ data: {} });
    await shell.setSessionSpace({ body: { space_id: null }, throwOnError: true });
    await sdk.setSessionSpace({ body: { space_id: null }, throwOnError: true });
    expect(call.mock.calls[0]?.[0]).toEqual(call.mock.calls[1]?.[0]);
  });

  it("decides an approval as the generated call does", async () => {
    const call = vi.spyOn(client, "post").mockResolvedValue({ data: {} });
    const body = { decision: "APPROVE" } as Parameters<typeof sdk.decideApproval>[0]["body"];
    await shell.decideApproval({ path: { approval_id: APPROVAL }, body, throwOnError: true });
    await sdk.decideApproval({ path: { approval_id: APPROVAL }, body, throwOnError: true });
    expect(call.mock.calls[0]?.[0]).toEqual(call.mock.calls[1]?.[0]);
  });
});
