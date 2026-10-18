// SPDX-License-Identifier: AGPL-3.0-only
// One tenant change: a store function the command line also calls, answered with the fresh
// tenant view, which replaces the page's data; the session is re-read so the top bar's mode
// pill and the stop state follow at once. The button waited for the server, so nothing here
// is undone on failure: there was nothing to undo.

import { useQueryClient, type UseMutationOptions } from "@tanstack/react-query";

import { readSessionQueryKey, readTenantQueryKey } from "../../api/@tanstack/react-query.gen";
import type { TenantSettingsView } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";

// The reason every one of these dialogs sends is screened for text shaped like a password,
// key or token where it is written (`execution/modes.py`, `execution/stops.py`,
// `assistant/turns.py`), so this sentence states that rule beside the one it always did; the
// same line answers a reason left blank and one refused for looking like a secret.
export const REASON_REQUIRED =
  "A reason of 1 to 500 characters is required, with nothing in it that looks like a password, key or token.";
export const DEADLINE_BOUNDS = "The deadline is 120 to 3600 seconds, or off.";

/** The lines a tenant form shows for the fields the API can name. */
export const TENANT_FIELDS: Record<string, string> = {
  reason: REASON_REQUIRED,
  deadline: DEADLINE_BOUNDS,
  mode: "Choose Enforcing or Observe only.",
};

export function useTenantChange<TVariables>(
  options: UseMutationOptions<TenantSettingsView, Error, TVariables>,
  onDone: (view: TenantSettingsView) => void,
) {
  const queryClient = useQueryClient();
  return useServerMutation<TenantSettingsView, TVariables>({
    ...options,
    onSuccess: (view) => {
      queryClient.setQueryData(readTenantQueryKey(), view);
      void queryClient.invalidateQueries({ queryKey: readSessionQueryKey() });
      onDone(view);
    },
  });
}

/** A reason as the store functions read it: trimmed, 1 to 500 characters, or nothing. */
export function reasonOf(raw: string): string | undefined {
  const reason = raw.trim();
  return reason.length >= 1 && reason.length <= 500 ? reason : undefined;
}
