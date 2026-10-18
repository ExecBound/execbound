// SPDX-License-Identifier: AGPL-3.0-only
// A failed read's Try again that stays where it is while the read is asked again.
//
// A query with nothing loaded forgets its failure the moment it is asked again: it goes back
// to pending, so a card that shows its failure only while `isError` holds swaps Try again for
// its loading line, and the focus a keyboard user gave the button falls to the page's body. The
// failure this returns holds until the read Try again asked for settles, so the button keeps
// its place, and its focus, marked unavailable while that read is out, and is there to press
// again if the read fails again.

import { useState } from "react";

/** The two parts of a query result Try again needs. */
interface Retryable<TError> {
  error: TError | null;
  refetch: () => Promise<unknown>;
}

export interface Retry<TError = unknown> {
  /** The failure to show: the read's own, or while Try again's read is out, the one it answered. */
  failure: TError | null;
  /** Whether the read Try again asked for is still out. */
  retrying: boolean;
  /** Ask for the read again, one read at a time. */
  retry: () => void;
}

export function useRetry<TError>(query: Retryable<TError>): Retry<TError> {
  const [held, setHeld] = useState<{ error: TError } | null>(null);
  return {
    failure: query.error ?? held?.error ?? null,
    retrying: held !== null,
    retry: () => {
      if (held !== null || query.error === null) return;
      setHeld({ error: query.error });
      // The query's own state is settled before its refetch resolves, so the render that lets
      // the held failure go already reads the answer: the failure again, or the data.
      void query.refetch().finally(() => {
        setHeld(null);
      });
    },
  };
}
