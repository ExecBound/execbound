// SPDX-License-Identifier: AGPL-3.0-only
import { createRootRoute, Outlet } from "@tanstack/react-router";

import { StepUpHost } from "../components/StepUpHost";
import { SessionProvider } from "../lib/SessionProvider";
import { Shell } from "../shell/Shell";

export const Route = createRootRoute({
  component: () => (
    <SessionProvider>
      <Shell>
        <Outlet />
      </Shell>
      {/* The step-up asked in place, over whatever page is open (decided 28 September 2026). */}
      <StepUpHost />
    </SessionProvider>
  ),
});
