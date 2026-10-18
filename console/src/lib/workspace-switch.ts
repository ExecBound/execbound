// SPDX-License-Identifier: AGPL-3.0-only
// Moving this browser to another of the account's workspaces (#678). Never optimistic: the
// browser leaves when the server answers. The answer is handled by the hook's own `onSuccess`,
// which TanStack Query keeps with the mutation, never by callbacks passed to `mutate()`, which
// are dropped when the caller unmounts: closing the palette mid-switch still lands the person.

import { useQueryClient } from "@tanstack/react-query";

import { selectWorkspace } from "../api/sdk.gen";
import { useServerMutation } from "./mutation";
import { isSection, sectionRoot } from "./sections";
import { useSession } from "./session";
import { rememberRecent } from "./workspace-recents";
import { announceSwitch, type WorkspaceRef } from "./workspace-context";

export function useWorkspaceSwitch() {
  const client = useQueryClient();
  const source = useSession().tenant.id;
  return useServerMutation({
    mutationFn: async (workspace: WorkspaceRef) => {
      // The section the person is on, so the switch lands on the same page there.
      const root = sectionRoot(window.location.pathname).to;
      const { data } = await selectWorkspace({
        body: { tenant_id: workspace.id, ...(isSection(root) ? { section: root } : {}) },
        throwOnError: true,
      });
      return data;
    },
    onSuccess: async (result, workspace) => {
      announceSwitch(workspace);
      // The workspace left behind, then the one entered: the menu there offers both first.
      rememberRecent(source);
      rememberRecent(workspace.id);
      await client.cancelQueries();
      client.clear();
      window.location.assign(result.location);
    },
  });
}
