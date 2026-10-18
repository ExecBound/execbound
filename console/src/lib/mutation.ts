// SPDX-License-Identifier: AGPL-3.0-only
// A decision, or any change that cannot be undone, is never optimistic (#333):
// the button waits for the server's answer. This helper is `useMutation` with the optimistic
// hook removed from its type, so a page cannot write one by accident; `isPending` is what a
// button reads to disable itself.

import { useMutation, type UseMutationOptions, type UseMutationResult } from "@tanstack/react-query";

export type ServerMutationOptions<TData, TVariables> = Omit<
  UseMutationOptions<TData, Error, TVariables>,
  "onMutate" | "retry"
>;

export function useServerMutation<TData, TVariables = void>(
  options: ServerMutationOptions<TData, TVariables>,
): UseMutationResult<TData, Error, TVariables> {
  return useMutation<TData, Error, TVariables>({ ...options, retry: 0 });
}
