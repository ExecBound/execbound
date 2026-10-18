// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute, useNavigate } from "@tanstack/react-router";

import type { Step } from "../components/welcome/steps";
import { parseStep } from "../components/welcome/steps";
import { WelcomePage } from "../components/welcome/WelcomePage";

/**
 * `?step=` names the Getting started step (#678), so a reload and the browser's Back keep it.
 * The route's component admits it only as one of the four steps (`parseStep`); anything else
 * reaches the page as no step, and the page opens on its opening step. As on Monitoring, the
 * check is not in `validateSearch`: the route tree is in every page's first load, an approval
 * link opened cold included, and the check belongs to Getting started's own chunk. The search
 * type is therefore unchecked, and nothing reads `Route.useSearch()` except through `parseStep`.
 */
export const Route = createFileRoute("/welcome")({
  validateSearch: (search: Record<string, unknown>) => search as { step?: Step },
  component: WelcomeRoute,
});

function WelcomeRoute() {
  const step = parseStep(Route.useSearch().step);
  const navigate = useNavigate({ from: "/welcome" });
  return (
    <WelcomePage
      step={step}
      onStep={(next, options) => {
        void navigate({ search: { step: next }, replace: options?.replace });
      }}
    />
  );
}
