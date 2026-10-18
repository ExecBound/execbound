// SPDX-License-Identifier: AGPL-3.0-only
import { Dialog } from "@base-ui/react/dialog";
import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Command } from "cmdk";
import { useEffect, useMemo, useRef, useState } from "react";

import { listSpacesOptions, readApprovalQueryKey, searchOptions } from "../../api/@tanstack/react-query.gen";
import type { ApprovalDetail } from "../../api/types.gen";
import { approvalLink } from "../../approvals/link";
import type { SearchResult } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import type { ActivitySearch } from "../../lib/activity-search";
import { requestCommand, type CommandName } from "../../lib/commands";
import { moveFocusNext } from "../../lib/focus";
import { useSingleKeys } from "../../lib/keys";
import { approvalIn, clearRecents, readRecents, type Recent } from "../../lib/recents";
import { can, useSession, type SessionSummary } from "../../lib/session";
import { useSpaceSwitch } from "../../lib/spaces";
import { toast } from "../../lib/toast";
import { toneFor } from "../../lib/words";
import { clearRecentWorkspaces } from "../../lib/workspaces";
import { WorkspacePaletteGroup } from "../../shell/WorkspacePaletteGroup";
import { useManyWorkspaces } from "../RequestRef";
import { Icon, type IconName } from "../../shell/icons";
import { useShellActions } from "../../shell/actions";
import { heldPaletteQuery, holdPaletteQuery, releasePaletteQuery } from "../../shell/reopen";
import { allEntries, visible, type NavigationEntry } from "../../shell/navigation";
import { aliasesOf } from "./aliases";
import { Badge } from "./Badge";
import "../../shell/surfaces.css";

const QUERY_MAX = 80;
const SETTLE_MS = 150;
const ICONS: Record<SearchResult["kind"], IconName> = {
  approval: "approvals",
  execution: "activity",
  target: "activity",
  agent: "agents",
  person: "people",
};

/** Where a record opens: an execution or an approval in the drawer, a target or an agent as a
 * filter. A person opens their own page instead (`isPerson`), never Activity. */
export function destination(result: SearchResult): ActivitySearch {
  switch (result.kind) {
    case "approval":
    case "execution":
      return { open: result.execution_id ?? result.id };
    case "target":
      return { target: result.id };
    case "agent":
      return { agent: result.id };
    case "person":
      return {};
  }
}

/** A person result opens `/people/<id>`; the server offers one only to who manages access. */
export function isPerson(result: SearchResult): boolean {
  return result.kind === "person";
}

/** The "Go to" entry a target, an agent or a person adds. */
export function goTo(result: SearchResult): string | undefined {
  if (result.kind === "target") return `Activity where the target is ${result.label}`;
  if (result.kind === "agent") return `Activity where the agent is ${result.label}`;
  if (result.kind === "person") return `Open ${result.label}`;
  return undefined;
}

type Matchable = Pick<NavigationEntry, "label" | "aliases"> & { to?: string };

/** The words a page answers to: its label, its aliases and its address's own segment. */
function names(entry: Matchable): string[] {
  const segment = entry.to?.slice(1) ?? "";
  return [entry.label, ...aliasesOf(entry), ...(segment === "" ? [] : [segment])];
}

export function matches(entry: Matchable, query: string): boolean {
  return names(entry).some((name) => matchesName(name, query));
}

/** The alias or segment that matched where the label did not, to show beside the label. */
export function matchedAlias(entry: Matchable, query: string): string | undefined {
  const typed = query.trim();
  if (typed === "" || matchesName(entry.label, typed)) return undefined;
  return names(entry).slice(1).find((name) => matchesName(name, typed));
}

/** Whether a name matches what has been typed; an empty query matches everything. */
export function matchesName(name: string, query: string): boolean {
  const typed = query.trim();
  return typed === "" || name.toLowerCase().includes(typed.toLowerCase());
}

/** Writes `text` to the clipboard and says whether it could. */
async function copy(text: string, done: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast(done);
  } catch {
    toast("Copy is not available in this browser.");
  }
}

/** What the server's search accepts from this person, as the empty palette says it. */
export function searchHint(session: Pick<SessionSummary, "role" | "permissions">): string {
  if (session.role !== "ADMIN") return "Type EB-1042, a case ID, a hostname or a provider id.";
  if (can(session, "access.manage")) {
    return "Type EB-1042, a case ID, a hostname, a provider id, an agent's name or number, or User 3.";
  }
  return "Type EB-1042, a case ID, a hostname, a provider id, or an agent's name or number.";
}

/** The commands that go to a page and open its dialog, each with the page it needs to see. */
const OPENERS: readonly { name: CommandName; label: string; to: string }[] = [
  { name: "add-agent", label: "Add agent", to: "/agents" },
  { name: "add-user", label: "Add user", to: "/people" },
  { name: "new-space", label: "New space", to: "/spaces" },
  { name: "issue-key", label: "Issue API key", to: "/credentials" },
];

/**
 * The command palette (#333): records from the search endpoint, an edition's
 * actions (#496), "Go to" over the pages and the filters a record suggests, and Ask,
 * which carries the typed words to the Ask page rather than asking anything from here (#330).
 * cmdk supplies the list, the input and the keyboard model; the dialog is Base UI's, which locks
 * scroll through the CSSOM and injects no style element. The list is not filtered by cmdk,
 * because the records are the server's answer to the query and the pages are matched here.
 */
export default function CommandPalette({
  open,
  onClose,
  href = "/",
}: {
  open: boolean;
  onClose: () => void;
  /** The current page's address as the router built it, path and search, for Copy link. */
  href?: string;
}) {
  const navigate = useNavigate();
  const session = useSession();
  const many = useManyWorkspaces();
  const { navigation, paletteLinks } = useEdition();
  const { openStop, openShortcuts } = useShellActions();
  const queryClient = useQueryClient();
  const pathname = new URL(href, "http://console.invalid").pathname;
  // The palette's name follows the deployment: where there is no assistant it only searches.
  const name = session.assistant ? "Search or ask" : "Search";
  const [single] = useSingleKeys();
  // The words a switch to All spaces carried over, else nothing.
  const [query, setQuery] = useState(() => heldPaletteQuery() ?? "");
  useEffect(releasePaletteQuery, []);
  const [settled, setSettled] = useState("");
  // The search waits for the typing to settle, so a person's keystrokes are not each a request.
  useEffect(() => {
    const timer = setTimeout(() => {
      setSettled(query.trim().slice(0, QUERY_MAX));
    }, SETTLE_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [query]);
  const records = useQuery({
    ...searchOptions({ query: { q: settled } }),
    enabled: settled !== "",
    staleTime: 10_000,
  });
  // The fourth group: the person's own spaces, each one a switch. The list is asked for only
  // while the palette is open, and the search endpoint already names each record's space when
  // the reader can see more than one, because two of an MSSP's customers may both have a host
  // called WS-001.
  const spaces = useQuery({
    ...listSpacesOptions({ query: { state: "active" } }),
    enabled: session.spaces > 1 || session.allSpaces,
    staleTime: 30_000,
  });
  const switcher = useSpaceSwitch();
  const current = session.space?.id ?? null;
  const switchable = (spaces.data?.items ?? []).filter((space) => matchesName(space.name, query));
  const seen = visible(allEntries(navigation), session.role, {
    assistant: session.assistant,
    invitations: session.invitations,
    permissions: session.permissions,
  });
  const pages = seen.filter((entry) => matches(entry, query.trim()));
  const shown = new Set(seen.map((entry) => entry.to));
  // Recent: kinds and ids from this browser, for this person in this workspace.
  const owner = useMemo(() => ({ tenant: session.tenant.id, principal: session.person.id }), [session.tenant.id, session.person.id]);
  const paths = useMemo(() => new Set(allEntries(navigation).map((entry) => entry.to)), [navigation]);
  const [recents, setRecents] = useState<Recent[]>(() => readRecents(owner, paths));
  const empty = query.trim() === "";
  const recentIds = recents.flatMap((item) => (item.k === "execution" ? [item.id] : []));
  // Each recorded record is asked for again through the scoped search, only while nothing is
  // typed; one the search does not find, revoked or in another space, is not shown.
  const found = useQueries({
    queries: recentIds.map((id) => ({ ...searchOptions({ query: { q: id } }), staleTime: 30_000, enabled: empty })),
  });
  const recentRecords = new Map(
    recentIds.flatMap((id, index) => {
      const hit = found[index]?.data?.results.find((result) => result.kind === "execution" && result.id === id);
      return hit === undefined ? [] : [[id, hit] as const];
    }),
  );
  type RecentRow =
    | { key: string; entry: NavigationEntry; record?: undefined }
    | { key: string; entry?: undefined; record: SearchResult };
  const recentRows = recents.flatMap((item): RecentRow[] => {
    if (item.k === "page") {
      const entry = seen.find((candidate) => candidate.to === item.to);
      return entry === undefined ? [] : [{ key: `recent:page:${entry.to}`, entry }];
    }
    const record = recentRecords.get(item.id);
    return record === undefined ? [] : [{ key: `recent:execution:${item.id}`, record }];
  });
  // The page's own address, built by the router; an approval's is the deployment's validated
  // link for it, which needs the approval read first.
  const approvalId = approvalIn(pathname);
  const approval =
    approvalId === undefined
      ? undefined
      : queryClient.getQueryData<ApprovalDetail>(readApprovalQueryKey({ path: { approval_id: approvalId } }));
  // Built only when chosen, against this page's own origin.
  const pageLink = (): string =>
    approvalId === undefined
      ? new URL(href, window.location.origin).href
      : approvalLink(approval?.link_path, approvalId, `/approvals/${encodeURIComponent(approvalId)}`, window.location.origin);
  // An edition's actions, each a server page, where the session's feature holds (#496):
  // what a narrow phone's top bar has no room for is reached here, as Ask is.
  const links = paletteLinks.filter(
    (link) => session.features.includes(link.feature) && matches(link, query.trim()),
  );
  const results = settled === "" ? [] : (records.data?.results ?? []);
  // Commands only open what a button would open; Enter never performs an action. Each one that
  // goes to a page is offered only where that page is one this person can see.
  const commands: { key: string; label: string; run: () => void }[] = [];
  if (can(session, "workspace.manage")) {
    commands.push({
      key: "stop",
      label: session.stop === null ? "Emergency stop…" : "Resume from the emergency stop…",
      run: openStop,
    });
  }
  for (const opener of OPENERS) {
    if (!shown.has(opener.to) || (opener.name === "new-space" && session.role !== "ADMIN")) continue;
    commands.push({
      key: opener.name,
      label: opener.label,
      run: () => {
        requestCommand(opener.name);
        moveFocusNext();
        void navigate({ to: opener.to });
      },
    });
  }
  commands.push({ key: "shortcuts", label: "Keyboard shortcuts", run: openShortcuts });
  // On an approval its address is the deployment's validated link, which needs the read first.
  if (approvalId === undefined || approval !== undefined) {
    commands.push({
      key: "copy-link",
      label: "Copy link to this page",
      run: () => {
        void copy(pageLink(), "Link copied.");
      },
    });
  }
  if (recents.length > 0) {
    commands.push({
      key: "clear-recent",
      label: "Clear recent",
      run: () => {
        clearRecents(owner);
        clearRecentWorkspaces();
        setRecents([]);
      },
    });
  }
  const offered = commands.filter((command) => matchesName(command.label, query));
  const suggestions = results.filter((result) => goTo(result) !== undefined);
  // After "Go to", the page heading takes focus when the navigation resolves; the dialog must
  // not hand focus back to where it was. After Escape it does, as any dialog would.
  const leaving = useRef(false);
  const go = (to: string, search?: ActivitySearch) => {
    leaving.current = true;
    moveFocusNext();
    onClose();
    void (search === undefined ? navigate({ to }) : navigate({ to: "/activity", search }));
  };
  const select = (result: SearchResult) => {
    if (isPerson(result)) {
      leaving.current = true;
      moveFocusNext();
      onClose();
      // Built by the router from the id: no link is ever made from a label.
      void navigate({ to: "/people/$personId", params: { personId: result.id } });
      return;
    }
    go("/activity", destination(result));
  };
  return (
    <Dialog.Root
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Backdrop className="scrim" />
        <Dialog.Popup className="palette" finalFocus={() => !leaving.current}>
          <Dialog.Title className="sr-only">{name}</Dialog.Title>
          <Command label={name} shouldFilter={false}>
            <div className="palette-input">
              <Icon name="search" />
              <Command.Input
                autoFocus
                placeholder={name}
                maxLength={QUERY_MAX}
                value={query}
                onValueChange={setQuery}
              />
              <kbd>Esc</kbd>
            </div>
            <Command.List className="palette-list">
              <Command.Empty className="palette-empty">Nothing matches.</Command.Empty>
              {empty && recentRows.length > 0 ? (
                <Command.Group heading="Recent">
                  {recentRows.map((row) =>
                    row.entry !== undefined ? (
                      <Command.Item
                        key={row.key}
                        value={row.key}
                        onSelect={() => {
                          go(row.entry.to);
                        }}
                      >
                        <Icon name={row.entry.icon} />
                        {row.entry.label}
                      </Command.Item>
                    ) : (
                      <Command.Item
                        key={row.key}
                        value={row.key}
                        onSelect={() => {
                          go("/activity", { open: row.record.id });
                        }}
                      >
                        <Icon name="activity" />
                        <span className="palette-record">
                          <span>{row.record.label}</span>
                          <small>{row.record.detail}</small>
                        </span>
                      </Command.Item>
                    ),
                  )}
                </Command.Group>
              ) : null}
              <Command.Group heading={many ? `Records in ${session.tenant.name}` : "Records"}>
                {settled === "" ? (
                  <Command.Item value="records-hint" disabled>
                    {searchHint(session)}
                  </Command.Item>
                ) : null}
                {settled !== "" && records.isPending ? (
                  <Command.Item value="records-searching" disabled>
                    Searching records
                  </Command.Item>
                ) : null}
                {settled !== "" && records.isError ? (
                  <Command.Item value="records-failed" disabled>
                    Records could not be searched.
                  </Command.Item>
                ) : null}
                {settled !== "" && records.data !== undefined && results.length === 0 ? (
                  <Command.Item value="records-none" disabled>
                    {session.space !== null && session.allSpaces
                      ? `No record matches in ${session.space.name}.`
                      : "No record matches in your scope."}
                  </Command.Item>
                ) : null}
                {settled !== "" && records.data !== undefined && results.length === 0 && session.space !== null && session.allSpaces ? (
                  // The session's own switch to All spaces: the established visibility path,
                  // with no scope flag on the search. The palette stays open and asks again.
                  <Command.Item
                    value="records-everywhere"
                    onSelect={() => {
                      // The switch draws the shell again; the palette comes back with these words.
                      holdPaletteQuery(query);
                      switcher.mutate({ space: null, name: null }, { onError: releasePaletteQuery });
                    }}
                  >
                    <Icon name="spaces" />
                    Search all your spaces
                  </Command.Item>
                ) : null}
                {results.map((result) => (
                  <Command.Item
                    key={`${result.kind}:${result.id}`}
                    value={`${result.kind}:${result.id}`}
                    onSelect={() => {
                      select(result);
                    }}
                  >
                    <Icon name={ICONS[result.kind]} />
                    <span className="palette-record">
                      <span>{result.label}</span>
                      <small>
                        {result.space_name !== null && result.space_name !== undefined
                          ? `${result.space_name} · ${result.detail}`
                          : result.detail}
                      </small>
                    </span>
                    {result.state !== null && result.state_label !== null ? (
                      <Badge tone={toneFor(result.state)}>{result.state_label}</Badge>
                    ) : null}
                  </Command.Item>
                ))}
              </Command.Group>
              {links.length > 0 ? (
                // Before "Go to", so a phone's Menu shows them without scrolling past every page.
                <Command.Group heading="Actions">
                  {links.map((link) => (
                    <Command.Item
                      key={`link:${link.href}`}
                      value={`link:${link.href}`}
                      onSelect={() => {
                        // A server page, not one of the console's: the browser leaves for it.
                        leaving.current = true;
                        onClose();
                        window.location.assign(link.href);
                      }}
                    >
                      <Icon name={link.icon} />
                      {link.label}
                    </Command.Item>
                  ))}
                </Command.Group>
              ) : null}
              {offered.length > 0 ? (
                <Command.Group heading="Commands">
                  {offered.map((command) => (
                    <Command.Item
                      key={`command:${command.key}`}
                      value={`command:${command.key}`}
                      onSelect={() => {
                        leaving.current = command.key !== "copy-link" && command.key !== "clear-recent";
                        if (command.key !== "clear-recent") onClose();
                        command.run();
                      }}
                    >
                      <Icon name="arrow" />
                      {command.label}
                    </Command.Item>
                  ))}
                </Command.Group>
              ) : null}
              <Command.Group heading="Go to">
                {suggestions.map((result) => (
                  <Command.Item
                    key={`go:${result.kind}:${result.id}`}
                    value={`go:${result.kind}:${result.id}`}
                    onSelect={() => {
                      select(result);
                    }}
                  >
                    <Icon name={isPerson(result) ? "people" : "activity"} />
                    {goTo(result)}
                  </Command.Item>
                ))}
                {pages.map((entry) => (
                  <Command.Item
                    key={`page:${entry.to}`}
                    value={`page:${entry.to}`}
                    aria-keyshortcuts={single && entry.key !== undefined ? `g ${entry.key}` : undefined}
                    onSelect={() => {
                      go(entry.to);
                    }}
                  >
                    <Icon name={entry.icon} />
                    {entry.label}
                    {matchedAlias(entry, query) !== undefined ? (
                      <small className="palette-alias">{matchedAlias(entry, query)}</small>
                    ) : null}
                    {single && entry.key !== undefined ? (
                      <kbd className="palette-key" aria-hidden="true">
                        g {entry.key}
                      </kbd>
                    ) : null}
                  </Command.Item>
                ))}
              </Command.Group>
              {session.allSpaces || switchable.length > 0 ? (
                <Command.Group heading="Spaces">
                  {session.allSpaces && current !== null ? (
                    <Command.Item
                      value="space:all"
                      onSelect={() => {
                        leaving.current = false;
                        onClose();
                        switcher.mutate({ space: null, name: null });
                      }}
                    >
                      <Icon name="tenant" />
                      All spaces
                    </Command.Item>
                  ) : null}
                  {switchable.map((space) => (
                    <Command.Item
                      key={`space:${space.space_id}`}
                      value={`space:${space.space_id}`}
                      disabled={space.space_id === current}
                      onSelect={() => {
                        if (space.space_id === current) return;
                        leaving.current = false;
                        onClose();
                        switcher.mutate({ space: space.space_id, name: space.name });
                      }}
                    >
                      <Icon name="tenant" />
                      {space.space_id === current ? `${space.name} (current)` : space.name}
                    </Command.Item>
                  ))}
                </Command.Group>
              ) : null}
              <WorkspacePaletteGroup query={query} />
              {session.assistant ? (
                <Command.Group heading="Ask">
                  {/* The palette never asks: it carries the words to the Ask page, which is
                      where a question is read back before anything is sent (#330). */}
                  <Command.Item
                    value="ask"
                    onSelect={() => {
                      const asked = query.trim();
                      leaving.current = true;
                      onClose();
                      void navigate({ to: "/ask", search: asked === "" ? {} : { q: asked } });
                    }}
                  >
                    <Icon name="ask" />
                    {query.trim() === "" ? "Ask the assistant" : `Ask: ${query.trim()}`}
                  </Command.Item>
                </Command.Group>
              ) : null}
            </Command.List>
            <footer className="palette-foot">
              <span>
                <kbd>Up</kbd> <kbd>Down</kbd> to move
              </span>
              <span>
                <kbd>Enter</kbd> to open
              </span>
              <span>
                <kbd>Esc</kbd> to close
              </span>
            </footer>
          </Command>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
