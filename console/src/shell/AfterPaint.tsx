// SPDX-License-Identifier: AGPL-3.0-only
// What the shell does once the page has settled (#678): the one polite live region and
// what it says, the tab's title and the waiting count, the single-key shortcuts, what Recent keeps,
// a newer release's loading on the next change of page, and whichever of the shell's dialogs is
// open. None of it is part of a page's first frame, so it loads as one chunk once the page has
// what it needs (or at once when a dialog is asked for), and the first load of every page, an
// approval link opened cold among them, carries none of it. Each dialog, the phone's navigation
// sheet among them, is a chunk of its own again, loaded when it first opens.

import { lazy, Suspense, useMemo } from "react";

import { useEdition } from "../edition/context";
import { Announcer } from "../lib/announce";
import { useRecordRecents } from "../lib/recents";
import { useSession } from "../lib/session";
import { Keyboard } from "./Keyboard";
import { allEntries, visible } from "./navigation";
import type { PageName } from "./page-name";
import { useReleaseNavigation } from "./release-navigation";
import { useDocumentTitle } from "./title";

/** The shell's dialogs; one is open at a time. */
export type Overlay = "palette" | "shortcuts" | "stop" | "notifications" | "sheet";

// The palette is loaded the first time it opens (#333); the budget script refuses a static
// import of it.
const CommandPalette = lazy(() => import("../components/ui/CommandPalette"));
const Notifications = lazy(() => import("./Notifications"));
const Shortcuts = lazy(() => import("../components/ui/Shortcuts"));
// The phone's navigation sheet loads the first time Menu is pressed.
const NavigationSheet = lazy(() => import("./NavigationSheet"));
// The stop dialog is the tenant page's, loaded here only when an administrator opens it.
const StopDialog = lazy(() =>
  import("../components/tenant/StopDialog").then((module) => ({ default: module.StopDialog })),
);

/** The shell passes in the path, its navigate function and what it holds for the page. */
export default function AfterPaint({
  pathname,
  navigate,
  overlay,
  close,
  name,
  open,
  href,
  findings,
}: {
  pathname: string;
  navigate: (to: string) => void;
  overlay: Overlay | null;
  close: () => void;
  /** The name the current page declared, which the shell holds. */
  name: PageName | null;
  /** The record open over the page, `?open=`, which Recent keeps. */
  open: string | undefined;
  /** The page's address as the router built it, which Copy link copies. */
  href: string;
  /** Open monitoring findings, from the shell's counts. */
  findings: number;
}) {
  const session = useSession();
  const { navigation } = useEdition();
  useDocumentTitle(pathname, name);
  useRecordRecents(pathname, open);
  useReleaseNavigation(pathname);
  const entries = useMemo(
    () =>
      visible(allEntries(navigation), session.role, {
        assistant: session.assistant,
        invitations: session.invitations,
        permissions: session.permissions,
      }),
    [navigation, session.role, session.assistant, session.invitations, session.permissions],
  );
  return (
    <>
      <Announcer />
      <Keyboard entries={entries} navigate={navigate} />
      <Suspense fallback={null}>
        {overlay === "palette" ? <CommandPalette open onClose={close} href={href} /> : null}
        {overlay === "shortcuts" ? <Shortcuts open onClose={close} /> : null}
        {overlay === "notifications" ? <Notifications onClose={close} findings={findings} /> : null}
        {overlay === "sheet" ? <NavigationSheet onClose={close} /> : null}
        {overlay === "stop" ? <StopDialog open active={session.stop !== null} onClose={close} /> : null}
      </Suspense>
    </>
  );
}
