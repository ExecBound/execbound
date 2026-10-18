// SPDX-License-Identifier: AGPL-3.0-only
import { defineConfig } from "@hey-api/openapi-ts";

// The client and its Query hooks are generated from the console API's document only (#333).
// `pnpm generate` writes src/api, and dev, build, typecheck and test all run it first, so the
// client is derived from the document on every use and is not committed: it cannot drift, and
// two changes adding a route never conflict over ten thousand lines of output neither of them
// wrote. `scripts/console_openapi.py --check` holds the document itself to the router; it is
// core's own, and a plugin's console edition generates its own client from its own document
// (#496).
export default defineConfig({
  input: { path: "./openapi/console-v1.json" },
  output: { path: "src/api", clean: true, postProcess: [] },
  plugins: [
    { name: "@hey-api/client-fetch", runtimeConfigPath: "./src/lib/client-config.ts" },
    "@hey-api/typescript",
    { name: "@hey-api/sdk", validator: false },
    "@tanstack/react-query",
  ],
});
