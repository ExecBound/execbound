// SPDX-License-Identifier: AGPL-3.0-only
import { Command } from "cmdk";

import { copyFor } from "../lib/errors";
import { useWorkspaceSwitch } from "../lib/workspace-switch";
import { useWorkspaces } from "../lib/workspaces";
import { Icon } from "./icons";

/**
 * The palette's "Workspaces" group (#678): every other workspace of the account, to switch to,
 * and the current one, which cannot be chosen. Choosing keeps the palette open and holds every
 * item until the server answers; the navigation is the switch's own, so it still happens if the
 * palette is closed first.
 */
export function WorkspacePaletteGroup({ query }: { query: string }) {
  const list = useWorkspaces();
  const switcher = useWorkspaceSwitch();
  const items = list.data?.workspaces ?? [];
  if (items.length < 2) return null;
  const typed = query.trim().toLowerCase();
  const shown = items.filter((item) => typed === "" || item.name.toLowerCase().includes(typed));
  if (shown.length === 0) return null;
  const pending = switcher.isPending;
  return (
    <Command.Group heading="Workspaces">
      {shown.map((item) => (
        <Command.Item
          key={`workspace:${item.tenant_id}`}
          value={`workspace:${item.tenant_id}`}
          disabled={item.current || pending || item.entry === "directory"}
          onSelect={() => {
            if (item.current || pending || item.entry === "directory") return;
            switcher.mutate({ id: item.tenant_id, name: item.name });
          }}
        >
          <Icon name="tenant" />
          {item.current ? `${item.name} (current)` : `Switch to ${item.name}`}
        </Command.Item>
      ))}
      {pending ? <p role="status" className="palette-empty">Opening {switcher.variables.name}.</p> : null}
      {switcher.isError ? <p role="alert" className="palette-empty">{copyFor(switcher.error)}</p> : null}
    </Command.Group>
  );
}
