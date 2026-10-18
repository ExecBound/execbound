// SPDX-License-Identifier: AGPL-3.0-only
import { useSession } from "../lib/session";
import { useWorkspaces } from "../lib/workspaces";

/** Whether this account belongs to more than one workspace, as far as this tab knows. */
export function useManyWorkspaces(): boolean {
  return (useWorkspaces().data?.workspaces.length ?? 0) > 1;
}

/**
 * A request reference. Every workspace numbers its own requests, so for a person with several,
 * the reference names the workspace it belongs to: "EB-12 · Contoso SOC" (#678). Display only;
 * the reference itself, and every address, is unchanged.
 */
export function RequestRef({ value, prefix = "" }: { value: string; prefix?: string }) {
  const session = useSession();
  const many = useManyWorkspaces();
  return (
    <span className="mono">
      {prefix}
      {value}
      {many ? ` · ${session.tenant.name}` : null}
    </span>
  );
}
