// SPDX-License-Identifier: AGPL-3.0-only
import { useIsFetching } from "@tanstack/react-query";
import { useNavigate, useRouterState } from "@tanstack/react-router";
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type Dispatch,
  type ReactNode,
  type SetStateAction,
} from "react";

import { Toaster } from "../components/ui/Toast";
import { useEdition } from "../edition/context";
import { signInAgain } from "../lib/client-config";
import { useFocusOnNavigation } from "../lib/focus";
import { useNewerRelease } from "../lib/release";
import { useRail } from "../lib/rail";
import { useSession } from "../lib/session";
import { ShellActionsContext, type ShellActions } from "./actions";
import type { Overlay } from "./AfterPaint";
import { PageNameSetterContext, PageNameValueContext, type PageName } from "./page-name";
import { useCounts } from "./counts";
import { ServiceFooter } from "./ServiceFooter";
import { heldPaletteQuery } from "./reopen";
import { Sidebar } from "./Sidebar";
import { StopBanner } from "./StopBanner";
import { TabBar } from "./TabBar";
import { TopBar } from "./TopBar";

// The banner for a newer release loads only once one is noted.
const ReleaseBanner = lazy(() => import("./ReleaseBanner"));
// The notice before a session's hard end loads once the page has settled; it shows two minutes
// before that end, so a cold approval link never waits for it (#678).
const SessionEnding = lazy(() => import("../components/SessionEnding"));
// The title, the single-key shortcuts and the shell's dialogs load once the page has what it
// needs, or as soon as a dialog is asked for; a page's first load carries none of them.
const AfterPaint = lazy(() => import("./AfterPaint"));

/** How long the shell waits for a page to settle before loading its extras regardless. */
const SETTLE_LIMIT_MS = 4000;
/** How long the page must have been quiet, no read outstanding and the router idle. */
const QUIET_MS = 1000;

/**
 * True once the page has settled: the router idle and no read outstanding for a whole second,
 * which bridges the moments between a page's chunk arriving and its reads starting. A cold
 * approval link is decidable before the shell's extras are asked for, so they never compete with
 * what the person is waiting for. It stays true once it is.
 */
function usePageSettled(): [boolean, () => void] {
  const fetching = useIsFetching();
  const routing = useRouterState({ select: (state) => state.status !== "idle" });
  const [settled, setSettled] = useState(false);
  // However busy the page stays, the extras arrive within a few seconds of the shell.
  useEffect(() => {
    const limit = setTimeout(() => {
      setSettled(true);
    }, SETTLE_LIMIT_MS);
    return () => {
      clearTimeout(limit);
    };
  }, []);
  useEffect(() => {
    if (settled || fetching > 0 || routing) return;
    const quiet = setTimeout(() => {
      setSettled(true);
    }, QUIET_MS);
    return () => {
      clearTimeout(quiet);
    };
  }, [settled, fetching, routing]);
  const settle = useCallback(() => {
    setSettled(true);
  }, []);
  return [settled, settle];
}

export function Shell({ children }: { children: ReactNode }) {
  const [rail, toggleRail] = useRail();
  // A palette that switched the session to All spaces opens again in the shell that comes back.
  const [overlay, setOverlay] = useState<Overlay | null>(() => (heldPaletteQuery() !== null ? "palette" : null));
  const [pageName, setPageName] = useState<PageName | null>(null);
  const session = useSession();
  const newer = useNewerRelease();
  // Asking for a dialog loads the extras at once, and they stay.
  const [settled, settle] = usePageSettled();
  const counts = useCounts();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const open = useRouterState({ select: (state) => openRecord(state.location.search) });
  const href = useRouterState({ select: (state) => state.location.href });
  const go = useCallback(
    (to: string) => {
      void navigate({ to });
    },
    [navigate],
  );
  // Ask is in the top bar only where the operator configured a model (#330).
  const assistant = session.assistant;
  useFocusOnNavigation();
  // What an edition counts; core counts nothing and asks nothing (#496).
  const { event } = useEdition();
  useEffect(() => {
    event("account_opened");
  }, [event]);

  // Ctrl K or Cmd K carries a modifier, so it is never a single-key shortcut and is always on.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === "k") {
        event.preventDefault();
        settle();
        setOverlay("palette");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [settle]);

  const close = useCallback(() => {
    setOverlay(null);
  }, []);
  const actions = useMemo<ShellActions>(
    () => ({
      openPalette: () => {
        settle();
        setOverlay("palette");
      },
      openShortcuts: () => {
        settle();
        setOverlay("shortcuts");
      },
      openStop: () => {
        settle();
        setOverlay("stop");
      },
      openNotifications: () => {
        settle();
        setOverlay("notifications");
      },
      openSheet: () => {
        settle();
        setOverlay("sheet");
      },
    }),
    [settle],
  );

  return (
    <ShellContexts actions={actions} name={pageName} setName={setPageName}>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <div className={rail ? "shell shell-rail" : "shell"}>
        <Sidebar
          rail={rail}
          onToggle={toggleRail}
          onSearch={actions.openPalette}
        />
        <TopBar
          onNavigate={actions.openSheet}
          sheetOpen={overlay === "sheet"}
          waiting={(counts.approvals ?? 0) + (session.role === "ADMIN" ? (counts.monitoring ?? 0) : 0)}
          onAsk={
            assistant
              ? () => {
                  void navigate({ to: "/ask" });
                }
              : undefined
          }
          onStop={actions.openStop}
          onNotifications={actions.openNotifications}
        />
        <div className="banners">
          {newer ? (
            <Suspense fallback={null}>
              <ReleaseBanner />
            </Suspense>
          ) : null}
          <StopBanner onResume={actions.openStop} />
          {settled ? <Suspense fallback={null}><SessionEnding signInAgain={signInAgain} /></Suspense> : null}
        </div>
        <main id="main" className="content">
          {children}
          <ServiceFooter />
        </main>
        <TabBar counts={counts} />
      </div>
      <Toaster />
      {settled ? (
        <Suspense fallback={null}>
          <AfterPaint
            pathname={pathname}
            navigate={go}
            overlay={overlay}
            close={close}
            name={pageName}
            open={open}
            href={href}
            findings={session.role === "ADMIN" ? (counts.monitoring ?? 0) : 0}
          />
        </Suspense>
      ) : null}
    </ShellContexts>
  );
}

/** What the shell gives every page: its open functions, and the page's name both ways. */
function ShellContexts({
  actions,
  name,
  setName,
  children,
}: {
  actions: ShellActions;
  name: PageName | null;
  setName: Dispatch<SetStateAction<PageName | null>>;
  children: ReactNode;
}) {
  return (
    <ShellActionsContext.Provider value={actions}>
      <PageNameSetterContext.Provider value={setName}>
        <PageNameValueContext.Provider value={name}>{children}</PageNameValueContext.Provider>
      </PageNameSetterContext.Provider>
    </ShellActionsContext.Provider>
  );
}

/** The record a page has open over it, `?open=<id>`, as text, for Recent. */
function openRecord(search: unknown): string | undefined {
  const value = typeof search === "object" && search !== null ? (search as Record<string, unknown>).open : undefined;
  return typeof value === "string" ? value : undefined;
}
