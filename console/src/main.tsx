// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRouter, lazyRouteComponent, RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

// The edition this build is (#496). This is the only module that names `@edition` or
// `@route-tree`; every page reads the edition's slots through `useEdition()`.
import { edition } from "@edition";
import { routeTree } from "@route-tree";

import { RouteError } from "./components/RouteError";
import { EditionContext } from "./edition/context";
import { readSessionOptions } from "./lib/shell-api";
import "./styles/app.css";

// Polling pauses while the tab is hidden (#333): nothing refetches on an
// interval unless the document is visible, and the page's own queries inherit this.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchIntervalInBackground: false,
      refetchOnWindowFocus: true,
      retry: 1,
    },
  },
});

// Start the session read while the route chunk loads. Controls still wait for the
// SessionProvider, but a cold phone link need not pay these round trips in sequence.
void queryClient.query({ ...readSessionOptions(), staleTime: 30_000 }).catch(() => undefined);

const router = createRouter({
  routeTree,
  defaultPreload: "intent",
  defaultErrorComponent: RouteError,
  // A missing page is rare, so its card loads when one is asked for rather than with every page.
  defaultNotFoundComponent: lazyRouteComponent(() => import("./components/NotFound"), "NotFound"),
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const root = document.getElementById("root");
if (root === null) {
  throw new Error("The document has no root element");
}
// The plain frame painted the first frame and stays until the session is known: the session
// provider removes it then, or the route boundary or the not-found page if one renders first.
createRoot(root).render(
  <StrictMode>
    <EditionContext.Provider value={edition}>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </EditionContext.Provider>
  </StrictMode>,
);
