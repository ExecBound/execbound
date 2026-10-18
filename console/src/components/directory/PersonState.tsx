// SPDX-License-Identifier: AGPL-3.0-only
import type { PersonRow } from "../../api/types.gen";
import { Badge } from "../ui/Badge";

/** A person's state as the list and the person page both show it. An entry a re-invitation
 * replaced (migration 0061) is not merely deactivated: it is retired for good, and the person
 * is managed through the entry that replaced it. */
export function PersonStateBadge({ person }: { person: Pick<PersonRow, "active" | "replaced_by"> }) {
  if (person.replaced_by !== null) return <Badge tone="stale">Rejoined as a new entry</Badge>;
  return person.active ? <Badge tone="allow">Active</Badge> : <Badge tone="stale">Deactivated</Badge>;
}
