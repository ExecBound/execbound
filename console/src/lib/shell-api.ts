// SPDX-License-Identifier: AGPL-3.0-only
// The calls the shell and an approval link opened cold make (#678), written against the
// generated client instead of imported from the generated SDK and Query options.
//
// Each of those two generated modules holds every operation in the console API, and the bundler
// keeps a module whole: importing one option from them put all of the API's operations in the
// shell's chunk, so every endpoint any page added made an approval link opened cold heavier.
// These are the same calls with the generated types, the same addresses and the same query
// keys, so a page that reads or invalidates through the generated options shares their cache.
// `shell-api.test.ts` holds each one to the generated call and key it stands for.

import { type DefaultError, queryOptions } from "@tanstack/react-query";

import type { QueryKey } from "../api/@tanstack/react-query.gen";
import { client } from "../api/client.gen";
import type { Options } from "../api/sdk.gen";
import type {
  DecideApprovalData,
  DecideApprovalResponses,
  ListApprovalsData,
  ListApprovalsResponse,
  ListApprovalsResponses,
  ListSpacesData,
  ListSpacesResponse,
  ListSpacesResponses,
  ReadApprovalData,
  ReadApprovalResponse,
  ReadApprovalResponses,
  ReadSessionData,
  ReadSessionResponse,
  ReadSessionResponses,
  ReadTenantData,
  ReadTenantResponse,
  ReadTenantResponses,
  ReadWorkspacesData,
  ReadWorkspacesResponse,
  ReadWorkspacesResponses,
  SetSessionSpaceData,
  SetSessionSpaceResponses,
} from "../api/types.gen";

/** The generated key: the operation's id and base address, with whatever the call names. */
function createQueryKey<TOptions extends Options>(id: string, options?: TOptions): [QueryKey<TOptions>[0]] {
  // An empty base address falls back to the client's, as the generated key's `||` does.
  const own = options?.baseUrl;
  const params = {
    _id: id,
    baseUrl: own !== undefined && own !== "" ? own : (options?.client ?? client).getConfig().baseUrl,
  } as QueryKey<TOptions>[0];
  if (options?.body) params.body = options.body;
  if (options?.headers) params.headers = options.headers;
  if (options?.path) params.path = options.path;
  if (options?.query) params.query = options.query;
  return [params];
}

export const readSessionQueryKey = (options?: Options<ReadSessionData>) => createQueryKey("readSession", options);

export const readSessionOptions = (options?: Options<ReadSessionData>) =>
  queryOptions<ReadSessionResponse, DefaultError, ReadSessionResponse, ReturnType<typeof readSessionQueryKey>>({
    queryFn: async ({ queryKey, signal }) => {
      const { data } = await (options?.client ?? client).get<ReadSessionResponses, unknown, true>({
        url: "/api/console/v1/session",
        ...options,
        ...queryKey[0],
        signal,
        throwOnError: true,
      });
      return data;
    },
    queryKey: readSessionQueryKey(options),
  });

export const readWorkspacesQueryKey = (options?: Options<ReadWorkspacesData>) =>
  createQueryKey("readWorkspaces", options);

export const readWorkspacesOptions = (options?: Options<ReadWorkspacesData>) =>
  queryOptions<ReadWorkspacesResponse, DefaultError, ReadWorkspacesResponse, ReturnType<typeof readWorkspacesQueryKey>>({
    queryFn: async ({ queryKey, signal }) => {
      const { data } = await (options?.client ?? client).get<ReadWorkspacesResponses, unknown, true>({
        url: "/api/console/v1/session/workspaces",
        ...options,
        ...queryKey[0],
        signal,
        throwOnError: true,
      });
      return data;
    },
    queryKey: readWorkspacesQueryKey(options),
  });

export const listSpacesQueryKey = (options?: Options<ListSpacesData>) => createQueryKey("listSpaces", options);

export const listSpacesOptions = (options?: Options<ListSpacesData>) =>
  queryOptions<ListSpacesResponse, DefaultError, ListSpacesResponse, ReturnType<typeof listSpacesQueryKey>>({
    queryFn: async ({ queryKey, signal }) => {
      const { data } = await (options?.client ?? client).get<ListSpacesResponses, unknown, true>({
        url: "/api/console/v1/spaces",
        ...options,
        ...queryKey[0],
        signal,
        throwOnError: true,
      });
      return data;
    },
    queryKey: listSpacesQueryKey(options),
  });

export const listApprovalsQueryKey = (options?: Options<ListApprovalsData>) =>
  createQueryKey("listApprovals", options);

export const listApprovalsOptions = (options?: Options<ListApprovalsData>) =>
  queryOptions<ListApprovalsResponse, DefaultError, ListApprovalsResponse, ReturnType<typeof listApprovalsQueryKey>>({
    queryFn: async ({ queryKey, signal }) => {
      const { data } = await (options?.client ?? client).get<ListApprovalsResponses, unknown, true>({
        url: "/api/console/v1/approvals",
        ...options,
        ...queryKey[0],
        signal,
        throwOnError: true,
      });
      return data;
    },
    queryKey: listApprovalsQueryKey(options),
  });

export const readTenantQueryKey = (options?: Options<ReadTenantData>) => createQueryKey("readTenant", options);

export const readTenantOptions = (options?: Options<ReadTenantData>) =>
  queryOptions<ReadTenantResponse, DefaultError, ReadTenantResponse, ReturnType<typeof readTenantQueryKey>>({
    queryFn: async ({ queryKey, signal }) => {
      const { data } = await (options?.client ?? client).get<ReadTenantResponses, unknown, true>({
        url: "/api/console/v1/tenant",
        ...options,
        ...queryKey[0],
        signal,
        throwOnError: true,
      });
      return data;
    },
    queryKey: readTenantQueryKey(options),
  });

export const readApprovalQueryKey = (options: Options<ReadApprovalData>) => createQueryKey("readApproval", options);

export const readApprovalOptions = (options: Options<ReadApprovalData>) =>
  queryOptions<ReadApprovalResponse, DefaultError, ReadApprovalResponse, ReturnType<typeof readApprovalQueryKey>>({
    queryFn: async ({ queryKey, signal }) => {
      const { data } = await (options.client ?? client).get<ReadApprovalResponses, unknown, true>({
        url: "/api/console/v1/approvals/{approval_id}",
        ...options,
        ...queryKey[0],
        signal,
        throwOnError: true,
      });
      return data;
    },
    queryKey: readApprovalQueryKey(options),
  });

export const setSessionSpace = <ThrowOnError extends boolean = false>(
  options: Options<SetSessionSpaceData, ThrowOnError>,
) =>
  (options.client ?? client).post<SetSessionSpaceResponses, unknown, ThrowOnError>({
    url: "/api/console/v1/session/space",
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers as Record<string, string> | undefined) },
  });

export const decideApproval = <ThrowOnError extends boolean = false>(options: Options<DecideApprovalData, ThrowOnError>) =>
  (options.client ?? client).post<DecideApprovalResponses, unknown, ThrowOnError>({
    url: "/api/console/v1/approvals/{approval_id}/decision",
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers as Record<string, string> | undefined) },
  });
