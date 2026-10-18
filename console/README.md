# The ExecBound console

The console is a single-page application served by the gateway at the console's own paths — `/`, `/approvals`, `/activity` and the rest.

## Build and test

Node 24.21.0 and pnpm 11.26.0, both exact: `engines` refuses anything else (`engineStrict` in `pnpm-workspace.yaml`), and pnpm comes from corepack at the hash `packageManager` names. Run `corepack enable` once.

```sh
cd console
pnpm install --frozen-lockfile
pnpm check          # typecheck, lint, test, build
pnpm build          # writes ../src/execbound/surfaces/console_dist and runs the size budget
pnpm dev            # a development server; the gateway still serves the API
```

The build lands inside the Python package so `uv build` and the image carry it; the directory is ignored by git and admitted to the wheel by hatch's `artifacts` line in `pyproject.toml`. The Python suite's console tests read that build when it is present, and the CI job `verify` builds it before the suite. The gateway serves it at every console route, and answers 503 on each of them where the package carries no build ([surfaces](../docs/SURFACES.md#how-the-console-is-served)).

**Two editions**. `pnpm build` makes the core edition, which the package, the wheel and the self-hosted image carry. The hosted service's edition (not part of the public repository) is core's sources with its own pages and cards added through the edition's slots and a virtual route config. Where its sources are present, under `src/hosted/`, `pnpm check:hosted` checks it and `pnpm build:hosted` (`vite build --mode hosted`) builds it into a directory under `dist/`, which git ignores, so building it never replaces the build the package carries; where they are absent, as in the public repository, the `:hosted` scripts need the hosted sources and stop before building anything without them. `CONSOLE_OUT_DIR` moves either build, and may name only the package's build directory or a directory inside `dist/`; a blank value counts as unset, and anything else is refused while Vite loads its configuration, before the build empties anything. Only the Dockerfile sets it, so that an image built with `--build-arg CONSOLE_EDITION=hosted`, from a tree that holds the hosted edition, carries that edition where the package reads it. Each build writes its edition into the document's `execbound-edition` meta tag, which the gateway's `/health/ready` reports as `console`. `pnpm test` runs core's tests and leaves the hosted edition's out. Where that edition is present, `pnpm test:hosted` (`vitest run --mode hosted`) runs every test, core's included, with the hosted client pointed at the test origin; a core test passes the same in both, because a component rendered without an edition's provider is core. To run one file, name it straight after the script, as in `pnpm test src/shell`: with `--` in between, Vitest runs every file.

## What holds the line

- `pnpm-workspace.yaml`: a seven-day `minimumReleaseAge`, `strictDepBuilds` with an empty `allowBuilds`, so no dependency runs an install script. `DEPENDENCIES.md` records every package with its reason; `tests/test_console_dependencies.py` compares it to `package.json`.
- `vite.config.ts`: `base: "/console/"` (the application answers the product's own paths, so its own files keep one address of their own), the manifest on, no module-preload polyfill, no inlined asset, so the build emits no inline script or style under `script-src 'self'` and `style-src 'self'`.
- `eslint.config.js`: typescript-eslint's strict type-checked sets, the hooks rules, and the bans that keep an untrusted string out of the page and out of code (`dangerouslySetInnerHTML`, `innerHTML` and its relatives, `eval`, `new Function`, string timers), each held by a fixture in `scripts/bans.test.ts`. Core's files carry two more bans, held there too: no import of a module under `src/hosted/`, static or lazy, and no `@edition` or `@route-tree` outside `src/main.tsx`.
- `scripts/editions.ts`: which edition a Vite mode builds and where it is written, the edition tag it writes into the document, and the core build's refusal of any module or emitted asset under `src/hosted/`, in its own bundle and in every worker's; `scripts/editions.test.ts` holds it, the build configuration of both editions included.
- `scripts/budget.mjs`: the size budget over the build manifest, run by `pnpm build`; `scripts/budget.test.ts` holds it.
- `index.html`: the plain frame (HTML and CSS only, from `public/frame.css` over `public/tokens.css`) that paints before any script, the `execbound-release` meta tag the gateway fills, and the `execbound-edition` meta tag the build fills.
- `scripts/console_sbom.py` (repository root): the npm tree's CycloneDX SBOM from the lockfile and the licence allowlist, run in CI.

## Layout

```text
console/
  index.html               the document and the plain frame
  public/tokens.css        the design tokens, both schemes and the two forced ones; the only file with a colour literal
  public/frame.css         the plain frame, painted before any script
  public/fonts/            IBM Plex Sans and Mono, Latin1 subsets, with the OFL
  public/favicon.svg       the project's mark
  public/favicon.ico       the same mark at 16, 32 and 48; the gateway also serves it at /favicon.ico
  src/main.tsx             the router, the query client, the error and not-found components, and the edition, the one module that names @edition and @route-tree
  src/routes/              one file per core route (TanStack Router, file based); routeTree.gen.ts is generated and committed
  src/edition/             the seam: the Edition type, EditionContext and useEdition (context.ts), and the core edition, every slot empty (core.ts)
  src/hosted/              the hosted service's edition, where it is present (not part of the public repository): its fill of the slots, its routes, its API document and client, and its tests
  src/api/                 the API client and Query hooks, generated from openapi/console-v1.json; not committed
  src/approvals/           the Approvals page's components, words and time helpers; a page with more than one file keeps them in a directory named for it
  src/shell/               the shell: Sidebar, TopBar, TabBar, ReleaseBanner, Mark, icons and the navigation list
  src/components/ui/       Badge, Button, Card, PageHeading, EmptyState, Table, Drawer, Toast, CommandPalette, Shortcuts
  src/components/charts/   StackedBars, Sparkline, Meter, CountdownRing; SVG, token colours, a caption each
  src/components/board/    the live board's own figure, counters, ticker and stream hook
  src/components/          RouteError (the per-route boundary), NotFound
  src/lib/                 session, release, chunk, focus, mutation, toast, rail, appearance (the chosen scheme), clock (the server's time from the Date header), poll (the one polling timer every polled query shares), counts (the navigation pills), step-up and verify-identity (the step-up asked in place)
  src/styles/app.css       the fonts, Tailwind over the tokens, and every component's rules
  src/test/setup.ts        Testing Library matchers and cleanup
  src/test/edition.tsx     withEdition, a core test's stand-in edition: core's slots with some replaced
  scripts/                 the budget, the editions' build parts and the lint-ban fixtures
```

## The kit

- **Tokens.** `public/tokens.css` holds the light block and the dark block as `--eb-*` properties; `tests/test_console_tokens.py` holds every documented pairing to WCAG 2.2 AA in both schemes and refuses a colour literal anywhere else under `src/`. Tailwind reads them through `@theme inline` in `app.css` (`bg-surface`, `text-muted`, `border-line`, and so on).
- **Appearance.** System, Light or Dark, in Personal settings. `src/lib/appearance.ts` writes one word into a cookie, and the gateway renders `data-eb-scheme` on the root element of the document it serves, where two blocks of `tokens.css` take that attribute over `prefers-color-scheme`. A cookie rather than the `localStorage` the rail and the density use, and the server rather than the bundle, because the document may carry no inline script and paints the plain frame before any script runs: a choice applied in the browser would be one frame of the other scheme on every visit. The word is a preference and never a credential — it is read by one function, it decides only which palette paints, and no row records it. The live board stays `.ink` in every appearance.
- **The shell.** `src/shell/navigation.ts` is the one list a core page is added to: label, path, icon, group and roles; an edition's entries follow core's through its `navigation` slot. The sidebar (248 px, a 68 px rail remembered per browser), the phone tab bar, the breadcrumbs and the palette all read it. `SessionContext` (`src/lib/session.ts`) tells the shell the role, the mode, the tenant and the person; the API base fills it.
- **Pages.** `PageHeading` renders the one `h1`, which takes focus when a navigation resolves. `RouteError` is the error boundary of every route: the shell stays, Retry re-runs the route, an approval route links the classic page, and a chunk that failed to load reloads the page once.
- **Changes.** `useServerMutation` is `useMutation` without an optimistic hook in its type; a button disables on `isPending` and the answer is the server's. `toast()` lands in the polite live region.
- **Polling.** `usePolledQuery` (`src/lib/poll.ts`) is `useQuery` on the application's one timer instead of a timer of its own. Every polled endpoint lands on the same tick, a tick asks each endpoint once however many components watch it, and the timer is cleared while the document is hidden, so a tab left open behind another one asks for nothing.
- **Detail.** `Drawer` is controlled; a page keeps `open` in its search parameters so a link or the back button restores it.
- **Charts.** SVG components that draw only with token colours and carry a caption stating their figures.

## The API

`/api/console/v1/` is served by `src/execbound/surfaces/console_api/`, one module per area registered by one line in `AREAS`. Its guards are the pages' own boundary plus what JSON needs (`guards.py`); its refusals are typed codes (`errors.py`); its document is `openapi/console-v1.json`, written by `scripts/console_openapi.py`, and the client with its Query hooks is generated from it into `src/api` by `pnpm generate`. The document is committed; the client is not, and `dev`, `build`, `typecheck` and `test` each run `pnpm generate` first, so it is always the one the committed document describes. The shell reads the session through that client (`src/lib/SessionProvider.tsx`), and `src/lib/client-config.ts` is the client's runtime configuration: same origin, the CSRF token from the session route held in memory, the release header compared on every response, a 401 sending the person to sign in. The one 401 it answers in place is a change refused `MFA_REQUIRED` by the step-up: `src/lib/step-up.ts` is where `StepUpHost` (mounted once in `__root.tsx`) registers the question, loading `StepUpDialog` the first time it is asked, `src/lib/verify-identity.ts` sends the code to `POST /session/verify` and holds the new CSRF token, and the wrapper sends the refused change again exactly once. Requests wait while a code is checked, because the answer replaces the session cookie.

## Adding a page

A page is added in seven places, each its own file or one line in a shared one. In this order:

1. **The API module.** `src/execbound/surfaces/console_api/<area>.py` defines Pydantic models for its responses and a `<area>_routes(routes, runtime, config, guards)` function that registers its routes on the shared router. A read is `session, _ = await guards.session(request, query=frozenset({...}))` and names the query keys it accepts; a change is `session, body = await guards.mutation(request, <Model>)`, always a `POST`, with a model whose `model_config` forbids extra fields. Every route wraps the store function its page calls today, under the same authority (a route that is one role's passes `kind="ADMIN"` to the guard, which refuses anyone else before the body is read, as the pages' `admin(session)` does), the same fence and the same bounds; cursor pagination at 50. A mutation passes `openapi_extra=body(<Model>)` from `bodies.py`, so the document carries its body model and the generated client's `body` is typed. A refusal is `raise ApiError("<CODE>")` from `errors.py`; add a code there only when none fits. Register the module by one line in `AREAS` in `console_api/__init__.py`.
2. **The authority entries.** Add each route to `CONSOLE` in `tests/test_route_authority.py` as `SESSION`; a route reachable without a session does not exist on this API.
3. **The document.** `uv run python scripts/console_openapi.py` rewrites `console/openapi/console-v1.json`, the published document of core's areas; commit it, and `--check` holds it to the router. A plugin's areas go into that plugin's own document instead, which `--plugin <name>` writes to `console/src/<name>/openapi/console-<name>-v1.json` for the plugin's console edition; commit it too, while that edition's client, under `src/<name>/api`, is generated from it like core's and not committed. The client under `src/api` regenerates from the core document on every `pnpm` command that reads it and is not committed, so there is nothing to commit and nothing for two branches to conflict over.
4. **The tests.** `tests/test_console_api_<area>.py` uses `console_client`, `refusals` and `assert_no_secrets` from `tests/console_api_fixtures.py` for every route (an ADMIN, an approver in and out of scope, a bearer credential refused and audited, no session, a cross-tenant object answering 404, the secret check over every response) and adds the route's own cases. Vitest covers the page's components; `tests/test_browser_console.py` gains the route in its entry list, so axe and the policy check cover it, and `CONSOLE_ROUTES` in `src/execbound/surfaces/console.py` gains its path, which `tests/test_console_serving.py` holds equal to the generated route tree.
5. **The route file.** A core page's is `console/src/routes/<path>.tsx`, and a page of the hosted service's edition goes under that edition's own `routes/`. Each exports `Route = createFileRoute("/<path>")({ component })`, renders one `PageHeading`, and reads its data from its edition's generated hooks (`readXOptions()` from `src/api/@tanstack/react-query.gen` for core, and from the edition's own generated client for its plugin's routes; such a page may still read core's). Drawer state lives in `validateSearch` (`?open=<id>`), never in component state alone. A change goes through `useServerMutation` and a button that disables on `isPending`. Untrusted strings render as text; a link is a `Link` with `to` and `params`, never a string built from data.
6. **The navigation line.** One line in `console/src/shell/navigation.ts` (label, path, icon, group, roles, count) if the page is a top-level entry; a detail page under an existing entry needs none. A page of the hosted service's edition has its entry in that edition's own list instead, which the edition passes in its `navigation` slot.
7. **The server's route list.** One line in `CONSOLE_ROUTES` in `src/execbound/surfaces/console.py`, and one row in `CONSOLE` in `tests/test_route_authority.py`. The server enumerates the console's addresses rather than serving the document from a catch-all, so a page with no line here is unreachable; `tests/test_console_serving.py` holds the two lists equal to the generated route tree, so this step cannot be forgotten quietly. A page of the hosted service's edition is registered by its plugin instead, with `registry.console_path`, and that plugin's own tests pin it and hold `console_routes` with the plugin loaded equal to the edition's route tree.

Then `DEPENDENCIES.md` if the page brought a package (it should not need one), `docs/SURFACES.md` for the routes, a description of the change in the pull request, and the budget: `pnpm build` prints every route chunk beside its 60 KB, and `pnpm build:hosted` the hosted edition's where it is present.
