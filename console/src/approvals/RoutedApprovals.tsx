// SPDX-License-Identifier: AGPL-3.0-only
import { useNavigate, useRouter } from "@tanstack/react-router";
import { useCallback, useSyncExternalStore } from "react";

import { holdFocus } from "../lib/focus";
import { ApprovalsPage } from "./ApprovalsPage";
import type { ApprovalsView } from "./search";

// The four views `search.ts` validates the routes with, kept here too so this chunk does not
// import the routes' parser: `search.test.ts` holds the two lists equal.
export const VIEWS: readonly ApprovalsView[] = ["pending", "decided", "lapsed", "others"];

/**
 * The Approvals page with its view in the address (#678), as both core approval routes render
 * it. Changing the chip pushes a history entry and keeps the keyboard on the chip, since a view
 * is not a change of page; dropping a view this session cannot use replaces the entry instead.
 */
export function RoutedApprovals({ selected }: { selected?: string }) {
  // The location's search, read defensively against the same four views the routes accept. Read
  // from the router's own store rather than through a match, which a cold link would pay for.
  const router = useRouter();
  const search = useSyncExternalStore(
    (changed) => router.subscribe("onResolved", changed),
    () => router.state.location.search,
  );
  const navigate = useNavigate();
  const view = VIEWS.find((option) => option === (search as { view?: unknown }).view);
  const onView = useCallback(
    (next: ApprovalsView | undefined, replace = false) => {
      if (!replace) holdFocus();
      void navigate({ to: ".", search: (previous) => ({ ...previous, view: next }), replace });
    },
    [navigate],
  );
  return <ApprovalsPage selected={selected} view={view} onView={onView} />;
}
