// SPDX-License-Identifier: AGPL-3.0-only
import { useCallback, useEffect, useRef, useState } from "react";

import type { WorkspaceItem } from "../api/types.gen";
import { Deadline } from "../components/ui/Time";
import { serverNow } from "../lib/clock";
import { copyFor } from "../lib/errors";
import { ordered, readRecent } from "../lib/workspace-recents";
import { useWorkspaceSwitch } from "../lib/workspace-switch";
import { useWorkspaces } from "../lib/workspaces";
import { moveOption, trapPopoverKeys, useOutsidePress } from "./listbox";
import "./workspace-menu.css";

const ROLE_WORDS: Record<string, string> = {
  administrator: "Administrator",
  policy_manager: "Policy manager",
  approver: "Approver",
  viewer: "Viewer",
};
const FILTER_FROM = 6;

/** The roles a workspace gives this account, in the shell's words. */
export function rolesIn(item: WorkspaceItem): string {
  if (item.roles.length === 0) return item.kind === "ADMIN" ? "Administrator" : "Member";
  return item.roles.map((role) => ROLE_WORDS[role] ?? role).join(", ");
}

/** What waits there for this account, or what entering it asks; nothing for a quiet one. */
export function WaitingLine({ item }: { item: WorkspaceItem }) {
  if (item.current) return <small>Current</small>;
  if (item.entry === "factor") return <small>Opens after you confirm your second factor</small>;
  if (item.entry === "enrol") return <small>Opens after you set up a second factor</small>;
  if (item.entry === "directory") return <small>Opens only through your organization's sign-in</small>;
  const waiting = item.waiting ?? 0;
  if (item.waiting_state !== "counted" || waiting === 0 || item.next_lapse === null) return null;
  // The deadline is floored to the minute, so once that minute has passed less than one is left.
  const now = serverNow();
  return (
    <small className="workspace-waiting">
      {waiting} waiting for you · the first has{" "}
      {Date.parse(item.next_lapse) <= now ? "under a minute left" : <Deadline at={item.next_lapse} now={now} />}
    </small>
  );
}

/**
 * The menu of the account's workspaces: a listbox, the current one first and selected, then
 * those the account entered, most recent first by the server's record, then this browser's
 * recent ones, then the rest, as `ordered()` sorts them. Arrow keys move, Enter and Space choose,
 * Escape closes and gives the trigger its focus back, and a press outside closes. Choosing is
 * never optimistic: every option waits while the switch is answered.
 */
export default function WorkspaceMenu({ onClose }: { onClose: (focus: boolean) => void }) {
  const list = useWorkspaces();
  const switcher = useWorkspaceSwitch();
  const panel = useRef<HTMLDivElement | null>(null);
  const [query, setQuery] = useState("");
  const [recent] = useState(readRecent);
  const dismiss = useCallback(() => { onClose(false); }, [onClose]);
  useOutsidePress(panel, dismiss);
  const items = ordered(list.data?.workspaces ?? [], recent);
  const typed = query.trim().toLowerCase();
  const shown = items.filter((item) => item.name.toLowerCase().includes(typed));
  const loaded = items.length > 0;
  useEffect(() => {
    if (loaded) panel.current?.querySelector<HTMLElement>('input, [role="option"]')?.focus();
  }, [loaded]);
  const pending = switcher.isPending;
  const choose = (item: WorkspaceItem) => {
    if (pending || item.entry === "directory") return;
    if (item.current) {
      onClose(true);
      return;
    }
    switcher.mutate({ id: item.tenant_id, name: item.name });
  };
  return (
    <div
      ref={panel}
      className="workspace-menu"
      onKeyDown={(event) => {
        trapPopoverKeys(event, panel, () => { onClose(true); });
      }}
    >
      <h2>Your workspaces</h2>
      {items.length >= FILTER_FROM ? (
        <input
          type="text"
          className="workspace-filter"
          value={query}
          aria-label="Filter workspaces"
          placeholder="Filter workspaces"
          onChange={(event) => {
            setQuery(event.target.value);
          }}
          onKeyDown={(event) => {
            if (event.key !== "ArrowDown") return;
            event.preventDefault();
            panel.current?.querySelector<HTMLElement>('[role="option"]')?.focus();
          }}
        />
      ) : null}
      {list.isPending ? <p role="status">Loading workspaces…</p> : null}
      <ul role="listbox" aria-label="Workspaces" className="workspace-options">
        {shown.map((item, index) => (
          <li
            key={item.tenant_id}
            id={item.tenant_id}
            role="option"
            aria-selected={item.current}
            aria-disabled={pending || item.entry === "directory" ? "true" : undefined}
            tabIndex={index === 0 ? 0 : -1}
            className="workspace-option"
            onClick={() => {
              choose(item);
            }}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                event.preventDefault();
                moveOption(event.currentTarget, event.key === "ArrowDown" ? 1 : -1);
                return;
              }
              if (event.key !== "Enter" && event.key !== " ") return;
              event.preventDefault();
              choose(item);
            }}
          >
            <strong>{item.name}</strong>
            <small>{rolesIn(item)}</small>
            <WaitingLine item={item} />
          </li>
        ))}
      </ul>
      {pending ? <p role="status">Opening {switcher.variables.name}.</p> : null}
      {switcher.isError || list.isError ? <p role="alert">{copyFor(switcher.error ?? list.error)}</p> : null}
    </div>
  );
}
