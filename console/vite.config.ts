// SPDX-License-Identifier: AGPL-3.0-only
import { realpathSync } from "node:fs";
import path from "node:path";

import { tanstackRouter } from "@tanstack/router-plugin/vite";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, normalizePath } from "vite";

import { coreOnly, editionFor, editionMeta, hostedDirOf, hostedStyles, outDir, routeTreeFileHeader } from "./scripts/editions.ts";
import { tinesStories } from "./scripts/stories.ts";

// The console serves every console route at its final path (#333). The application's
// own files keep one address of their own, `/console/`, because the routes it answers are the
// product's paths (`/`, `/approvals/...`) and `/assets/` already belongs to the pages that stay
// server-rendered. The core build is written straight into the Python package so `uv build` and
// the image carry it; the directory is ignored by git and admitted to the wheel by hatch's
// `artifacts` line.
//
// The edition this build is (#496): `vite build` is core's and `vite build --mode hosted`
// the hosted service's, which adds src/hosted/'s routes under core's root route through a
// virtual route config. `@edition` names the edition's slots and `@route-tree` its routes, and
// only src/main.tsx imports either. The core build refuses to reach any file under src/hosted/,
// in its own bundle and in every worker's; the hosted build gives Tailwind the hosted sources
// back, which core's stylesheet leaves out of its scan. The paths are the real ones, because the
// build's module ids are.
const ROOT = realpathSync.native(import.meta.dirname);
const HOSTED = hostedDirOf(ROOT);
const from = (file: string) => path.join(ROOT, file);

export default defineConfig(({ mode }) => {
  const edition = editionFor(mode);
  const hosted = edition === "hosted";
  return {
    base: "/console/",
    plugins: [
      tanstackRouter(
        hosted
          ? {
              target: "react",
              autoCodeSplitting: true,
              routesDirectory: "./src",
              generatedRouteTree: "./src/hosted/routeTree.gen.ts",
              routeTreeFileHeader: routeTreeFileHeader(edition),
              // Core's route files, then the hosted edition's, under core's own root route.
              virtualRouteConfig: {
                type: "root",
                file: "routes/__root.tsx",
                children: [
                  { type: "physical", directory: "routes", pathPrefix: "" },
                  { type: "physical", directory: "hosted/routes", pathPrefix: "" },
                ],
              },
            }
          : { target: "react", autoCodeSplitting: true, routeTreeFileHeader: routeTreeFileHeader(edition) },
      ),
      react(),
      // Before Tailwind, which is `enforce: "pre"` too, so the list's order is the hooks' order.
      ...(hosted ? [hostedStyles(normalizePath(from("src/styles/app.css")))] : []),
      tailwindcss(),
      editionMeta(edition),
      // The committed Tines stories and their license, unchanged, for Getting started (#678).
      tinesStories(ROOT),
      ...(hosted ? [] : [coreOnly(HOSTED)]),
    ],
    worker: {
      plugins: () => (hosted ? [] : [coreOnly(HOSTED)]),
    },
    resolve: {
      alias: [
        { find: /^@edition$/, replacement: from(hosted ? "src/hosted/edition.tsx" : "src/edition/core.ts") },
        { find: /^@route-tree$/, replacement: from(hosted ? "src/hosted/routeTree.gen.ts" : "src/routeTree.gen.ts") },
      ],
    },
    build: {
      outDir: outDir(edition, process.env),
      emptyOutDir: true,
      manifest: true,
      // No inline script or style may leave this build: the policy is `script-src 'self'` and
      // `style-src 'self'` with no nonce, so a polyfill script or an inlined asset would be
      // refused by the browser and, worse, would be the one thing an audit could not see.
      modulePreload: { polyfill: false },
      assetsInlineLimit: 0,
      sourcemap: false,
      rolldownOptions: {
        output: {
          codeSplitting: {
            includeDependenciesRecursively: false,
            groups: [
              // React and TanStack's libraries in one chunk (#678). Every page loads them with the
              // shell; split by which later chunk shares which part, they had become a dozen small
              // files, each paying its own compression and request overhead on a cold approval link.
              {
                name: "vendor",
                test: /node_modules[\\/]\.pnpm[\\/](react|react-dom|scheduler|@tanstack\+[a-z-]+)@/,
              },
              {
                name: "setup",
                test: /src[\\/](components[\\/]welcome[\\/](setup|steps|OperatorSteps|ConnectionNeeded|WatchFirstLine|SetupCardToggle|NoConnectionHint|CopyRecipe)\.tsx?|components[\\/]welcome[\\/]welcome\.css|shell[\\/](StartedCard\.tsx|started\.css))$/,
              },
            ],
          },
        },
      },
    },
  };
});
