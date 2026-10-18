// SPDX-License-Identifier: AGPL-3.0-only
// One change to one person: the server's answer replaces the page's copy, and the list is
// invalidated so a label, a state or a directory account shown there follows. Nothing is
// assumed before the server answers, because the button waited for it.

import { useQueryClient } from "@tanstack/react-query";

import { readPersonQueryKey } from "../../api/@tanstack/react-query.gen";
import type { PersonDetail } from "../../api/types.gen";
import { useServerMutation, type ServerMutationOptions } from "../../lib/mutation";
import { toast } from "../../lib/toast";

export function usePersonChange<TVariables>(
  principalId: string,
  options: ServerMutationOptions<PersonDetail, TVariables>,
  done: string,
) {
  const queryClient = useQueryClient();
  return useServerMutation<PersonDetail, TVariables>({
    ...options,
    onSuccess: (data, variables, context, mutation) => {
      toast(done);
      queryClient.setQueryData(readPersonQueryKey({ path: { principal_id: principalId } }), data);
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listPeople" }] });
      void options.onSuccess?.(data, variables, context, mutation);
    },
  });
}

/**
 * A scope change's options as the person page uses them. The route answers no content where
 * the reader may not administer the person (a scope is a write on its space, #678); the person
 * page is only open to a reader who may, so there it always answers the detail, and an answer
 * without one would leave the page's copy as it was (`setQueryData` ignores `undefined`).
 */
export function scopeChange<TData, TVariables>(
  options: ServerMutationOptions<TData, TVariables>,
): ServerMutationOptions<PersonDetail, TVariables> {
  return options as unknown as ServerMutationOptions<PersonDetail, TVariables>;
}
