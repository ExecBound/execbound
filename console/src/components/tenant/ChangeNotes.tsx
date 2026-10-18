// SPDX-License-Identifier: AGPL-3.0-only
import type { TenantSettingsView } from "../../api/types.gen";
import { when } from "../../lib/when";
import { PrincipalName } from "../PrincipalName";

/** When a workspace setting last changed and who changed it, or what it has been since. */
export function Changed({ change, never }: { change: TenantSettingsView["mode"]["changed"]; never: string }) {
  return (
    <p className="muted">
      {change === null ? (
        never
      ) : (
        <>
          Changed <span className="mono">{when(change.at)}</span> by{" "}
          {change.by_ref !== null ? <PrincipalName principal={change.by_ref} /> : "an administrator"}.
        </>
      )}
    </p>
  );
}

/** What a narrowed administrator is told in place of a control they do not hold. */
export function WorkspaceOnly({ what }: { what: string }) {
  return <p className="note">Only a workspace administrator {what}, because it applies to every space.</p>;
}
