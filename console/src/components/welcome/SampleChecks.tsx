// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";

import { listApprovalsOptions, readConnectionOptions, readTenantOptions } from "../../api/@tanstack/react-query.gen";
import type { SampleHostView, SampleStatusView } from "../../api/types.gen";
import { usePolledQuery } from "../../lib/poll";
import { dateTime, toneFor } from "../../lib/words";
import { announces, deliveryWords } from "../tenant/delivery";
import { Badge } from "../ui/Badge";
import { blockingApproval, deadlineWords, RETIRE_TO_REFRESH, sampleApproval, useStaleSince } from "./held";
import { RequestToRelay } from "./RequestToRelay";

/**
 * What guided setup tells the person about a denial (#545), in the terms the agent's
 * own answer uses (`runtime.denial_notice`): the agent gets the state and the request's reference,
 * never the cause, and is told a person can find it by searching the console for the reference;
 * a busy target and a spent shared limit are the only causes named to it (#551), and every notice
 * says that re-sending the same request returns the same answer.
 */
export const BARE_DENIAL =
  "Your agent is told that the request was denied and given its reference, such as EB-12, but not why: the reason is recorded for you, and searching the console for that reference finds it. The only causes an agent is ever told are that another request holds the target or that a shared limit is spent. Re-sending the same request returns the same answer.";

/**
 * Why each new request needs a new `reference` (#545): the idempotency key is derived from the
 * operation, the target's selector and the reference (`requests.derive_key`), and the request's
 * hash leaves the incident out (`wire_hash` excludes `claimed_context`), so a reference already
 * recorded on a target finds the request recorded under it (`admission`), whatever incident it
 * names: a settled one answers as it did, and a held one is progressed, which is how sending it
 * again runs it once approved. After a refresh that would bring back an old answer and record
 * nothing new. `reference` is code, being the field the agent sends, and is glossed with what the
 * agent guide says it is, since the denial sentence calls the request's EB number its reference.
 */
function References() {
  return <details className="setup-details"><summary>Why each new request needs a new reference</summary><p className="muted">Each new request needs a new <code>reference</code> from your agent, the ticket, case or run id it sends: on the same target, a <code>reference</code> already recorded brings back the request recorded under it, even with a new incident. Your agent should reuse one only to send the same request again, as after you approve it.</p></details>;
}

/**
 * What guided setup says after the deadline when nothing announces a held request (#678):
 * with an approval destination, the step states how fast its notifications have arrived instead.
 * A findings destination or the audit export announces none (#31).
 */
export const NO_DESTINATION = "No approval destination is configured, so a held request is announced only in this console.";

/** The sample loop (#420): the first request an agent made on a sample, and the two left to try. */
export function SampleChecks({ samples }: { samples: SampleStatusView }) {
  // The operation the samples answer to is the server's, read as the connection card reads it.
  const connection = useQuery({ ...readConnectionOptions(), staleTime: 30_000 });
  const operationRef = connection.data?.operation_ref ?? null;
  const first = samples.first_request;
  const target = (effect: string) => samples.hosts.find((host) => host.effect === effect);
  const allowed = target("allow");
  const denied = target("deny");
  const held = target("require approval");
  // By the server's clock, read again every half minute: Verify protection's poll of the status
  // re-renders nothing while its answer is unchanged, so the poll alone would never bring the note.
  const staleSince = useStaleSince(samples.stale_at);
  const ask = (host: SampleHostView) => <RequestToRelay operationRef={operationRef} kind="hostname" value={host.hostname} incident={host.incident_id} />;
  return <section aria-labelledby="sample-checks">
    <h3 id="sample-checks">Your sample targets</h3>
    {/* Every request on the samples is refused, so the note is the page's warning, in the amber
        a notice uses for what waits on a person, and it is announced when the clock brings it. */}
    {staleSince !== null ? <p className="notice notice-hold" role="status">The sample facts went stale at {dateTime(staleSince)}: every request on them is refused, and your agent is told only that execution is unavailable, until you refresh them in Try an example. {RETIRE_TO_REFRESH}</p> : null}
    {first === null
      ? <p>No request on a sample target yet.{allowed !== undefined ? <> Ask your agent to {ask(allowed)}.</> : null}</p>
      : <p>First request: <Link to="/activity" search={{ open: first.execution_id }}>{first.provider_id}</Link>{" "}<Badge tone={toneFor(first.state)}>{first.state_label}</Badge></p>}
    <ul className="setup-links">
      {denied !== undefined ? <li>Ask it to {ask(denied)}. The starter policy denies a domain controller, so the request stops before the endpoint.<details className="setup-details"><summary>What your agent is told when it is denied</summary><p className="muted">{BARE_DENIAL}</p></details></li> : null}
      {held !== undefined ? <li>Ask it to {ask(held)}. A production target waits for approval in <Link to="/approvals">Approvals</Link>; approve it there, and it executes when your agent sends the same request again.<HeldApproval samples={samples} host={held} stale={staleSince !== null} /></li> : null}
    </ul>
    <References />
  </section>;
}

/**
 * How long the production workstation's request can wait, and where it is now (#545).
 * The deadline is the workspace's own (`held.ts`). The approval comes from the two lists the
 * Approvals page reads for an administrator: the newest pending approval on this target since
 * the facts were recorded, else the newest lapsed one that still holds the samples, which the
 * Approvals page lists only under Lapsed. Either is linked at its own address.
 * A lapsed one is ended by the recovery run, every fifteen minutes (`schedule.JOBS`), once it is
 * the run's grace, 300 seconds by default, past its deadline (`select_lapsed_approvals`), so
 * within about twenty minutes of the lapse, or sooner by the agent that made it. Admission matches
 * that agent's next request on the target to the lapsed row, by its key when it is the same
 * request sent again and by its intent otherwise, and ends the row as `STALE_AUTHORIZATION`, which
 * is that request's answer; only a request after it, under a new reference, gets a new approval. A
 * request under a new reference is resolved before that match, so on stale facts it is refused
 * without reaching the row, and the same request sent again never is: the line asks for the same
 * request. (An observing workspace answers a held row as it stands, so there only the run ends
 * it.) A newer pending approval beside a lapse nothing has ended is therefore another agent's: its
 * request is an intent of its own, and a held request takes no claim on the target, so it is
 * admitted and waits, and the line names it.
 * Once the facts are stale their stale time bounds nothing, so the deadline is worded without it.
 */
function HeldApproval({ samples, host, stale }: { samples: SampleStatusView; host: SampleHostView; stale: boolean }) {
  const tenant = useQuery({ ...readTenantOptions(), staleTime: 60_000 });
  const pending = usePolledQuery({ ...listApprovalsOptions({ query: { view: "pending" } }) });
  const waiting = sampleApproval(pending.data?.items, samples, host);
  const lapsed = usePolledQuery({ ...listApprovalsOptions({ query: { view: "lapsed" } }), enabled: pending.data !== undefined && waiting === undefined });
  // A switched-off query keeps its last answer, so once a newer request is pending the lapsed
  // list may still hold a lapse the recovery run has since ended: it is read only while none is.
  const blocking = waiting === undefined ? blockingApproval(lapsed.data?.items, samples, host) : undefined;
  return <>
    <p className="muted">{deadlineWords(tenant.data?.deadline.seconds, stale ? null : samples.stale_at)}</p>
    {tenant.data !== undefined ? <p className="muted">{announces(tenant.data.destinations) ? deliveryWords(tenant.data.delivery, true) : NO_DESTINATION}</p> : null}
    {waiting !== undefined ? <p>Waiting now: <Link to="/approvals/$approvalId" params={{ approvalId: waiting.approval_id }}>{waiting.request_ref}</Link>, open until {dateTime(waiting.expires_at)}{waiting.deadline_clock === "context validity" ? ", when its facts go stale or your agent's API key expires, whichever is first" : ""}.</p> : null}
    {blocking !== undefined ? <p><Link to="/approvals/$approvalId" params={{ approvalId: blocking.approval_id }}>{blocking.request_ref}</Link> lapsed at {dateTime(blocking.expires_at)} before it executed. Ask the agent that made it to send the same request again: that ends it, and a new request after that, with a new <code>reference</code>, waits for a new approval while the sample facts are current. Otherwise ExecBound ends it at a scheduled recovery run, within about twenty minutes of the lapse; until it ends, the sample targets cannot be refreshed or removed.</p> : null}
  </>;
}
