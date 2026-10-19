# Console dependencies

Every package the console installs, why it is there and what it costs. [`DEPENDENCIES.md`](../DEPENDENCIES.md) at the root is the same document for the Python tree. `tests/test_console_dependencies.py` compares this file to `package.json` and `pnpm-workspace.yaml`, so a new package, a changed version, an install script or a license exception is a reviewed change here and never a side effect of an install.

Every version is exact and was published at least seven days before it was pinned; `minimumReleaseAge` in `pnpm-workspace.yaml` then refuses anything younger at every later install. Compressed sizes are gzip, measured from the production build at the pinned version, because gzip is what a reverse proxy in front of the gateway typically serves; a development package ships nothing.

## Runtime

| Package | Version | Reason | Compressed |
| --- | --- | --- | --- |
| `react` | 19.3.0 | The component model. | about 45 KB with `react-dom` |
| `react-dom` | 19.3.0 | Renders it in the browser. | counted with `react` |
| `@tanstack/react-router` | 1.170.41 | Typed file-based routes and search parameters; the drawer's state lives in the URL. | about 40 KB |
| `@tanstack/react-query` | 5.104.1 | Server state and polling; the mutation helper with no optimistic mode is built on it. | about 13 KB |
| `@base-ui/react` | 1.8.0 | Unstyled, accessible primitives; the drawer and the palette's dialog are built on its Dialog, which locks scroll through the CSSOM and injects no `<style>` element. | about 12 KB for the parts used |
| `cmdk` | 1.1.1 | The command palette's list, input and keyboard model, loaded the first time the palette opens; brings four `@radix-ui/*` packages, of which only the id, primitive and ref helpers are reached because the palette's dialog is Base UI's. | about 8 KB, in the palette chunk only |

## Development

| Package | Version | Reason |
| --- | --- | --- |
| `typescript` | 6.0.3 | Strict typing. 6.0 rather than 7 because typescript-eslint 8.71 accepts `>=4.8.4 <6.1.0`, so the lint toolchain cannot run 7. |
| `vite` | 8.3.2 | The build: hashed assets, the manifest the budget reads, no inline script or style. |
| `@vitejs/plugin-react` | 6.1.1 | React fast refresh and the JSX transform. |
| `tailwindcss` | 4.3.3 | Utilities over the tokens as CSS variables. |
| `@tailwindcss/vite` | 4.3.3 | Runs Tailwind inside the Vite build. |
| `@tanstack/router-plugin` | 1.168.42 | Generates the route tree from the route files and splits each route into its own chunk. |
| `vitest` | 5.0.3 | Unit tests, run in CI and before every pull request. |
| `jsdom` | 30.1.1 | The document Vitest renders into. |
| `@testing-library/react` | 16.3.3 | Renders components the way a person reaches them. |
| `@testing-library/dom` | 10.4.2 | The queries `@testing-library/react` builds on (its peer). |
| `@testing-library/jest-dom` | 7.0.1 | Matchers over the rendered document. |
| `@testing-library/user-event` | 14.6.7 | Keyboard and pointer interaction in tests. |
| `eslint` | 10.12.0 | Lint, with the untrusted-string bans in `eslint.config.js`. |
| `typescript-eslint` | 8.71.0 | The type-checked rule sets and the TypeScript parser. |
| `eslint-plugin-react-hooks` | 7.1.1 | The rules of hooks. |
| `@types/react` | 19.3.0 | Types for React. |
| `@types/react-dom` | 19.3.0 | Types for React DOM. |
| `@types/node` | 24.19.1 | Types for the Vite and Vitest configuration files and the budget script. |
| `axe-core` | 4.13.0 | The accessibility engine `tests/test_browser_console.py` injects into every console route in Chromium; ships nothing. |
| `@hey-api/openapi-ts` | 0.99.0 | Generates the API client and its Query hooks from `openapi/console-v1.json`; the fetch client it writes is bundled into `src/api`, so no runtime package. |

## Install scripts

No package runs an install script: `strictDepBuilds` is on and `allowBuilds` is empty, so a package that wants one fails the install rather than being skipped quietly. `@tailwindcss/oxide` ships its native binary as an optional platform package and needs none.

## Overrides

`pnpm-workspace.yaml` may hold a transitive dependency above the version its dependent pins, when that version is vulnerable and the dependent has not moved. Each is listed here and removed when the dependent catches up.

- `js-yaml` to 4.3.2: `@hey-api/json-schema-ref-parser` (through `@hey-api/openapi-ts`, development only) pins 4.2.0, which carries three high advisories (quadratic CPU in merge keys and `!!omap`); 4.3.2 is the patched release and is older than the minimum release age.

## License exceptions

`scripts/console_sbom.py` holds every package to the allowlist: MIT, Apache-2.0, the BSD family, ISC, and the dedications that oblige less than MIT does (MIT-0, 0BSD, Unlicense, CC0-1.0). A package the browser receives has no exception. A development package may be named here instead, with its license and the reason it is acceptable: none of these ships a byte to a browser, and each is a tool the build runs.

- `lightningcss` and `lightningcss-*`: MPL-2.0. The CSS engine Tailwind and Vite use; file-level copyleft on its own files, which the build neither modifies nor distributes.
- `caniuse-lite`: CC-BY-4.0. Browser support data behind `browserslist`, read at build time.
- `lru-cache` and `minimatch`: BlueOak-1.0.0. Permissive; pulled in by the TypeScript and ESLint toolchain.
- `axe-core`: MPL-2.0. The accessibility engine the Python browser suite injects; a test tool that never ships.
- `argparse`: Python-2.0 (the PSF license). Pulled in by `@hey-api/openapi-ts` through `js-yaml`; a generator that runs at development time and ships nothing.

After any `pnpm add`, run the license check CI runs, so a license the allowlist refuses is found here and not on the pull request:

```sh
pnpm licenses list --json > ../local-data/console-licenses.json
pnpm licenses list --prod --json > ../local-data/console-licenses-prod.json
uv run --project .. python ../scripts/console_sbom.py --lockfile pnpm-lock.yaml --licenses ../local-data/console-licenses.json --production-licenses ../local-data/console-licenses-prod.json --dependencies DEPENDENCIES.md --output ../local-data/release/sbom-console.cdx.json
```
