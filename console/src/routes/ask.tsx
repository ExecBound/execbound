// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute } from "@tanstack/react-router";

import { AskPage } from "../components/assistant/AskPage";

/**
 * `?q=` carries words typed in the command palette, which never asks anything itself: the
 * question lands in the box on this page, where the person reads it back and presses Ask
 * (#330). Validated here, in the route file, from nothing but the search itself.
 */
export const Route = createFileRoute("/ask")({
  validateSearch: (search: Record<string, unknown>): { q?: string } =>
    typeof search.q === "string" && search.q.trim() !== "" ? { q: search.q.slice(0, 1000) } : {},
  component: AskRoute,
});

function AskRoute() {
  const { q } = Route.useSearch();
  return <AskPage initial={q ?? ""} />;
}
