// SPDX-License-Identifier: AGPL-3.0-only
// A credential is issued by one mutation and shown once (#333, the show-once rule). The answer
// is copied into component state for the dialog and the mutation is reset at once, with a
// garbage-collection time of zero, so the secret is in no query, no mutation record, no URL
// and no storage the moment the dialog closes: only the person's clipboard has it.

import { useCallback, useState } from "react";

import { useServerMutation, type ServerMutationOptions } from "../../lib/mutation";

export function useShowOnce<TData, TVariables>(
  options: ServerMutationOptions<TData, TVariables>,
) {
  const [secret, setSecret] = useState<TData | null>(null);
  const [error, setError] = useState<unknown>(null);
  const mutation = useServerMutation<TData, TVariables>({ ...options, gcTime: 0 });
  const { mutateAsync, reset, isPending } = mutation;
  const issue = useCallback(
    async (variables: TVariables): Promise<boolean> => {
      setError(null);
      let answer: TData;
      try {
        answer = await mutateAsync(variables);
      } catch (failure) {
        setError(failure);
        return false;
      }
      setSecret(answer);
      reset();
      return true;
    },
    [mutateAsync, reset],
  );
  // Closing the shown secret, or opening the form for another, starts clean: a refusal from an
  // earlier attempt must not greet the next one.
  const close = useCallback(() => {
    setSecret(null);
    setError(null);
  }, []);
  const clear = useCallback(() => {
    setError(null);
  }, []);
  return { secret, error, issue, close, clear, pending: isPending };
}
