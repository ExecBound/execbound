// SPDX-License-Identifier: AGPL-3.0-only
// Monitoring's one meaning of quiet (#678): an active, unrevoked reporting source whose health
// is STALE, or an active, unrevoked connection whose collection is overdue. The count beside
// Monitoring, the Connections tab, Home, the order of Connections and the `focus=quiet` mark
// all use these two predicates and nothing else.

import type { MonitorConnection, MonitorSource } from "../../api/types.gen";

/** A connection whose collection evidence went stale; one that is only not reporting is not quiet. */
export function isQuietConnection(connection: Pick<MonitorConnection, "revoked_at" | "overdue_since">): boolean {
  return connection.revoked_at === null && connection.overdue_since !== null;
}

/** A source whose heartbeat went stale; a disabled, expired or never-heard source is not quiet. */
export function isQuietSource(source: Pick<MonitorSource, "revoked_at" | "health_state" | "coverage">): boolean {
  return source.revoked_at === null && source.coverage !== "Disabled" && source.health_state === "STALE";
}
