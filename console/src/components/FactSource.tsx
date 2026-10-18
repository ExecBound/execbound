// SPDX-License-Identifier: AGPL-3.0-only
import { sourceWord } from "../lib/words";

/**
 * Where a trusted fact came from, in words. A signal fact names its producer by the label its
 * registration carries, or by its kind where the server sent none, and the capability it
 * answers; every other fact names its source's kind. The label is data from
 * outside ExecBound: text in its own isolate, so its direction cannot reorder the capability
 * beside it, and never a link.
 */
export function FactSource({
  fact,
}: {
  fact: { source_kind: string; source_label?: string | null; capability?: string | null };
}) {
  return (
    <>
      {fact.source_label ? <bdi>{fact.source_label}</bdi> : sourceWord(fact.source_kind)}
      {fact.capability ? ` (${fact.capability})` : null}
    </>
  );
}
