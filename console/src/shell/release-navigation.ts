// SPDX-License-Identifier: AGPL-3.0-only
// A newer release, once noted, loads on the next change of page (#678): the person is leaving the
// page anyway, so nothing they typed is lost, and a tab left open for days does not keep an old
// build. A change of the query alone (a filter, a drawer) stays in the page. Nothing is reloaded
// while a change is being sent, a decision or a stop among them: the navigation happens in the
// page and the next one tries again. A Live board on a wall, with nobody pressing anything for a
// minute, no dialog open and nothing being sent, reloads itself.

import { useQueryClient } from "@tanstack/react-query";
import { useBlocker, useRouter } from "@tanstack/react-router";
import { useEffect } from "react";

import { useNewerRelease } from "../lib/release";
import { dialogOpen } from "./Keyboard";

/** How long the Live board waits without input before it loads a newer release. */
export const BOARD_IDLE_MS = 60_000;

export function useReleaseNavigation(pathname: string): void {
  const newer = useNewerRelease();
  const router = useRouter();
  const queryClient = useQueryClient();
  useBlocker({
    disabled: !newer,
    enableBeforeUnload: false,
    withResolver: false,
    shouldBlockFn: ({ current, next }) => {
      if (next.pathname === current.pathname || queryClient.isMutating() > 0) return false;
      // The router builds the destination from the location it parsed; the browser loads it.
      const destination = router.buildLocation({ to: next.pathname, search: next.search } as never);
      window.location.assign(destination.href);
      return true;
    },
  });
  useEffect(() => {
    if (!newer || pathname !== "/board") return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const restart = () => {
      clearTimeout(timer);
      timer = setTimeout(idle, BOARD_IDLE_MS);
    };
    const idle = () => {
      if (document.visibilityState === "visible" && queryClient.isMutating() === 0 && !dialogOpen()) {
        window.location.reload();
      } else {
        restart();
      }
    };
    const events = ["keydown", "pointerdown", "pointermove"] as const;
    for (const name of events) window.addEventListener(name, restart);
    restart();
    return () => {
      clearTimeout(timer);
      for (const name of events) window.removeEventListener(name, restart);
    };
  }, [newer, pathname, queryClient]);
}
