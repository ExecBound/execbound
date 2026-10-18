// SPDX-License-Identifier: AGPL-3.0-only
import type { Retry } from "../../lib/retry";
import { Button } from "./Button";

/**
 * A failed read's Try again. While the read it asked for is out it says it is unavailable
 * rather than being disabled, which would drop the focus the person gave it.
 */
export function TryAgain({ retry }: { retry: Retry }) {
  return (
    <Button aria-disabled={retry.retrying ? "true" : undefined} onClick={retry.retry}>
      Try again
    </Button>
  );
}
