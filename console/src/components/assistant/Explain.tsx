// SPDX-License-Identifier: AGPL-3.0-only
import { lazy, Suspense } from "react";

import { useSession } from "../../lib/session";

export type ExplainKind = "execution" | "approval" | "finding" | "agent" | "policy_change";

/**
 * Explain, on a record's own page (#330).
 *
 * Three rules this component exists to keep. It is **absent**, not disabled, where the
 * operator configured no model, and it is not shown where the tenant's switch is off, so a
 * page that has never had an assistant looks exactly as it did. The explanation is
 * **collapsed** until a person asks for it and sits **below** the record, because the frozen
 * facts above are the record and the explanation is not. And opening it is **recorded**, so a
 * later review can see which decisions were made after one was read.
 *
 * The server re-reads the record with the asking person's own authority before the model sees
 * anything, so an identifier they could not read is refused here the way the page refuses it.
 */
export interface ExplainProps {
  kind: ExplainKind;
  id: string;
  /** What the button names, e.g. "this decision"; the panel's heading uses it too. */
  what: string;
  question?: string;
}

// The panel, and the assistant's turn view behind it, are their own chunk. A page that never
// had an assistant downloads none of it, which is most of what keeps a cold approval link
// inside its budget (tests/test_browser_approval_speed.py).
const Panel = lazy(() => import("./ExplainPanel"));

export function Explain(props: ExplainProps) {
  // One context read and nothing else where the deployment has no assistant. The panel
  // holds every hook the feature needs, so a page that never had an assistant runs no query,
  // mounts no state, loads no code and is exactly the page it was.
  if (!useSession().assistant) return null;
  return (
    <Suspense fallback={null}>
      <Panel {...props} />
    </Suspense>
  );
}
