// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";

import { readSamplesOptions, readSetupOptions } from "../../api/@tanstack/react-query.gen";
import { useSession } from "../../lib/session";
import { ConnectionNeeded } from "./ConnectionNeeded";

/**
 * Under Policies' new draft, for an administrator, where no policy is active and the starter is
 * unavailable (#678): only while the Space has no registered connection, what would give it one. Nothing renders
 * while either read is out or where the setup read fails.
 */
export function NoConnectionHint() {
  const admin = useSession().role === "ADMIN";
  const setup = useQuery({ ...readSetupOptions(), staleTime: 30_000, enabled: admin }).data;
  const samples = useQuery({ ...readSamplesOptions(), staleTime: 30_000, enabled: admin });
  if (setup?.state !== "ready" || setup.connected || samples.isPending) return null;
  return <div className="notice no-connection">
    <p>Requests from agents are refused until this Space has a registered connection and an active policy.</p>
    <ConnectionNeeded setup={setup} samples={samples.data} />
  </div>;
}
