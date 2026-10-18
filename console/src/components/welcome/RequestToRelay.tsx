// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The request a person relays to their agent (#545): the operation, the target by the selector
 * it is named with, and the incident by the field it goes in, so the agent guesses none of them.
 * The incident is named as `claimed_context.incident_id`, the path `list_actions` gives it,
 * because `execute` also asks for a `reference` (a ticket, case or run id), and an incident sent
 * there instead leaves the request without its context, which the agent is answered as 503
 * `EXECUTION_UNAVAILABLE`, with no cause.
 * `operationRef` is the server's (`readConnection`'s `operation_ref`, read from the samples' own
 * mapping) and never a name the console holds; until it arrives, or where the server names none,
 * the sentence names the target and its incident alone, as it did before. Every name the agent
 * spells is code, and the target a person picked is emphasised in both sentences. One target a
 * person chose, never a list of them: no agent is given a target listing.
 */
export function RequestToRelay({ operationRef, kind, value, incident }: { operationRef: string | null; kind: string; value: string; incident: string | null }) {
  if (operationRef === null) {
    return <>isolate <strong>{value}</strong>{incident === null ? null : <> for incident <code>{incident}</code></>}</>;
  }
  return <>call <code>execute</code> with <code>operation_ref</code> <code>{operationRef}</code>, target <code>{kind}</code> <strong>{value}</strong>{incident === null ? null : <> and <code>claimed_context.incident_id</code> <code>{incident}</code></>}</>;
}
