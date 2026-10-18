// SPDX-License-Identifier: AGPL-3.0-only
// Asking is one mutation, and the answer to it is a turn id: the server writes the row,
// answers at once, and runs the model loop behind the response (#330). Nothing
// here is optimistic, because there is nothing to guess: the row either exists or the request
// was refused, and the refusal is the one the tenant's switch or the operator's caps made.

import { useQueryClient } from "@tanstack/react-query";

import {
  askAssistantMutation,
  listAssistantTurnsQueryKey,
  recordAssistantTurnOpenedMutation,
  readAssistantTurnQueryKey,
} from "../../api/@tanstack/react-query.gen";
import type { TurnView } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";

/** The lines an assistant refusal reads as, over the shared copy. */
export const ASSISTANT_FIELDS: Record<string, string> = {
  question: "Type a question of 1 to 1,000 characters.",
  context_id: "That record could not be read.",
};

export function useAsk(onDone: (turn: TurnView) => void) {
  const queryClient = useQueryClient();
  return useServerMutation({
    ...askAssistantMutation(),
    onSuccess: (turn: TurnView) => {
      queryClient.setQueryData(readAssistantTurnQueryKey({ path: { turn_id: turn.turn_id } }), turn);
      void queryClient.invalidateQueries({ queryKey: listAssistantTurnsQueryKey() });
      onDone(turn);
    },
  });
}

/**
 * Opening an explanation is recorded (#330), so a later review can see which
 * decisions were made after one was read. It is sent once, when a person opens the panel.
 */
export function useOpened() {
  return useServerMutation({ ...recordAssistantTurnOpenedMutation() });
}
