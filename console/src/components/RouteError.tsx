// SPDX-License-Identifier: AGPL-3.0-only
import { useRouter, useRouterState, type ErrorComponentProps } from "@tanstack/react-router";
import { lazy, Suspense, useLayoutEffect, useState } from "react";

import { recoverChunk } from "../lib/chunk";
import { codeOf } from "../lib/errors";
import { removeFrame } from "../lib/frame";
import { titleNoun, usePageName, type PageName } from "../shell/page-name";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";

const FAILED: PageName = { crumbs: [], current: "Could not load", title: [titleNoun("Could not load")] };

const APPROVAL = /^\/approvals\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/|$)/i;

/** A typed refusal's own words: the console API's code, never a page's data. */
const REFUSED: Record<string, [string, string]> = {
  FORBIDDEN: ["You don't have access to this", "Your role or your spaces do not include it. Ask a workspace administrator if you need it."],
  NOT_FOUND: ["There is nothing here you can open", "It may have been removed, or it is not in your scope or current space."],
  UNAVAILABLE: ["ExecBound is unavailable", "It refuses requests it cannot check rather than letting them through. Try again shortly."],
};

// The report and the reference people can quote load only when a page has failed; where that
// chunk cannot load either, the card stands without them.
const Reference = lazy(() => import("./ErrorReference").catch(() => ({ default: () => null })));

/**
 * A failure stays in its page (#333): the shell stays, the page says it could not
 * load, Retry re-runs the route, and on an approval route the classic page is one link away. A
 * chunk that failed to load reloads the page once before any of this is shown. A typed refusal
 * says what it is, and any other failure is reported to the server once, with a reference the
 * person can quote (#678).
 */
export function RouteError({ error, reset, info }: ErrorComponentProps) {
  const router = useRouter();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const routeId = useRouterState({
    select: (state) => (state.matches.find((match) => match.status === "error") ?? state.matches.at(-1))?.routeId,
  });
  // A chunk that failed to load reloads the page once; the boundary decides that as it first
  // renders, and a failure it is reloading for is not reported.
  const [recovering] = useState(() => recoverChunk(error));
  usePageName(FAILED);
  // Where the failure came before the session was known, the plain frame would cover the card.
  useLayoutEffect(removeFrame, []);
  const approval = APPROVAL.exec(pathname);
  const code = codeOf(error);
  const [heading, line] = (code !== undefined ? REFUSED[code] : undefined) ?? [
    "This page could not load",
    "The rest of the console is still working. Try again, or go somewhere else.",
  ];
  return (
    <Card className="route-error">
      <h1 tabIndex={-1}>{heading}</h1>
      <p className="lead">{line}</p>
      {code === undefined && !recovering ? (
        <Suspense fallback={null}>
          <Reference error={error} routeId={routeId} componentStack={info?.componentStack} />
        </Suspense>
      ) : null}
      <div className="row">
        <Button
          variant="primary"
          onClick={() => {
            reset();
            void router.invalidate();
          }}
        >
          Retry
        </Button>
        {approval?.[1] !== undefined ? (
          <a className="btn" href={`/approvals/${approval[1]}/classic`}>
            Use the basic approval page
          </a>
        ) : null}
      </div>
    </Card>
  );
}
