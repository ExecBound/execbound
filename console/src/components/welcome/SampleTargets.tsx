// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { installSamplesMutation, refreshSamplesMutation, removeSamplesMutation } from "../../api/@tanstack/react-query.gen";
import type { SampleHostView, SampleStatusView } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { useService } from "../../lib/session";
import { toast } from "../../lib/toast";
import { dateTime } from "../../lib/words";
import { workspaceGeneration } from "../../lib/workspace-context";
import { explain, refusalOf } from "../directory/errors";
import { Problem } from "../directory/forms";
import { Badge, type Tone } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Table, Td, Th } from "../ui/Table";
import { RETIRE_TO_REFRESH, useStaleSince } from "./held";

/** What the starter rules read on a sample target's facts: a word first, then a decision tone. */
const EFFECTS: Record<string, { word: string; tone: Tone }> = {
  allow: { word: "Allowed", tone: "allow" },
  "require approval": { word: "Needs approval", tone: "hold" },
  deny: { word: "Denied", tone: "deny" },
};

const ROLES: Record<string, string> = { workstation: "Workstation", domain_controller: "Domain controller" };

/** What one click adds, said before the click. */
const ADDS = [
  "A sample connection to the protected endpoint mock, used by nothing else.",
  "A development workstation the starter policy lets your agent isolate.",
  "A production workstation whose isolation waits for your approval.",
  "A domain controller the starter policy never lets anyone isolate.",
  "The starter policy, active in this workspace, and an open critical incident on each target.",
] as const;

export const SAMPLE_CAPTION = "Sample targets and what the starter policy does to an isolation request";

const DEMO_CONFIGURATION = "/api/console/v1/samples/demo-configuration";

/**
 * The demo configuration's address (#247): the fixed path and the session generation, built as
 * the report's CSV is, since a download link carries no workspace header and a tab left on a
 * workspace the person has since switched away from is refused rather than handed the new one's.
 */
export function demoConfigurationUrl(generation: string): string {
  return generation === "" ? DEMO_CONFIGURATION : `${DEMO_CONFIGURATION}?${new URLSearchParams({ generation }).toString()}`;
}

/**
 * What a refresh does, said beside its button: it re-creates the targets, so the agent needs the
 * new request, and review of them returns to the administrator who refreshed, exactly as an
 * install gives it to the administrator who installed (`samples_install` grants its actor a scope
 * on each new target; `samples_remove` switches every scope on the old ones off). The new request
 * needs a new reference: the key is derived from the operation, the target's selector and the
 * reference (`requests.derive_key`), and the incident is no part of the request's hash
 * (`wire_hash` leaves `claimed_context` out), so a reference already recorded on a sample target
 * finds that request, which the refresh left settled, and is answered with it (`admission`).
 */
export const REFRESHES =
  "Refreshing re-creates the sample targets with new incidents, so your agent needs the new request from Verify protection, with a new reference: one already recorded on the same target brings back that request's answer. Review of the samples returns to you alone, as when they were added, and the starter policy is activated again. Requests already made stay in Activity.";

/**
 * Why the server refused a refresh, in the refresh's own words: the shared sentences for these
 * codes speak of adding and removing the samples, which would be wrong here. A refused refresh
 * is rolled back whole, so each says nothing changed.
 * - `SAMPLES_BUSY`: a request on the samples is unresolved, which includes a held request whose
 *   approval lapsed, until a scheduled recovery run ends it, within about twenty minutes of the
 *   lapse (`samples.refresh`; the run's cadence and grace are in `SampleChecks`' `HeldApproval`).
 * - `SAMPLES_NOT_OFFERED`: `POLICY_PRESENT` before anything is removed, while a policy a person
 *   made names the samples or a space other than the default one selects the starter, either of
 *   which the refresh would break (`_PERSONS_POLICY`); or the install step's own refusal once the
 *   workspace has a policy or a connection of its own (`POLICY_PRESENT`, `ACCOUNT_PRESENT`,
 *   `MAPPING_PRESENT`). Retiring the policy that names the samples is the way out
 *   (`held.RETIRE_TO_REFRESH`); removing the samples is not offered, because a removal still
 *   breaks the first two (SM6c).
 */
export function refreshRefusal(error: unknown): string {
  const { code } = refusalOf(error);
  if (code === "SAMPLES_BUSY") return "A sample request is waiting for approval or provider evidence, so the sample facts were not refreshed and nothing changed. Settle it in Approvals or Activity; if its approval lapsed, ExecBound ends it at a scheduled recovery run, within about twenty minutes of the lapse, and the samples can be refreshed after that.";
  if (code === "SAMPLES_NOT_OFFERED") return `The sample facts were not refreshed, and nothing changed. Re-creating the samples would break a policy someone made that names them, or take the starter policy away from another space that uses it. A refresh is also refused once this workspace has a policy or connection of its own. ${RETIRE_TO_REFRESH}`;
  return explain(error);
}

/**
 * What a refresh that went through did. A refresh that found no samples answers their status and
 * writes nothing (`samples.refresh`), which happens only where they were removed after this card
 * read them, so it is never called a refresh.
 */
function refreshedWords(view: SampleStatusView): string {
  if (view.state === "absent") {
    const gone = "There were no sample targets to refresh: they were removed since this page last read them.";
    return view.offered ? `${gone} Add them again to try an example.` : gone;
  }
  return view.stale_at === null ? "Sample facts refreshed. Each target has a new incident." : `Sample facts refreshed. Each target has a new incident, and the facts stay current until ${dateTime(view.stale_at)}.`;
}

/**
 * When the facts were recorded, and what their going stale does to a request, in the terms the
 * agent is answered in: a request on stale facts is refused before any decision with a 503
 * `EXECUTION_UNAVAILABLE`, and no execution is recorded (#545).
 */
function factsWords(samples: SampleStatusView, stale: boolean): string {
  if (samples.observed_at === null || samples.stale_at === null) return "";
  const recorded = dateTime(samples.observed_at);
  const until = dateTime(samples.stale_at);
  return stale
    ? ` Facts recorded ${recorded} went stale at ${until}: a request on them is refused before any decision, and your agent is told only that execution is unavailable. Refresh the sample facts to record them again.`
    : ` Facts recorded ${recorded}. From ${until} a request on them is refused before any decision, and your agent is told only that execution is unavailable; refresh the sample facts to record them again.`;
}

/**
 * Sample targets (#420): one click gives an empty workspace a real first governed action, one more
 * re-creates them when their facts go stale (#545), and one more takes them back out. While
 * the server says the demo can run on the samples (`demo_available`: this deployment serves them,
 * the starter is the policy in force and enforced, no emergency stop is active, its isolation
 * mapping is live, each target has an open incident, the facts are current, no request on them is
 * unresolved and none since their facts were recorded has changed one at the provider) and the
 * facts are still current by the card's own clock, the card also offers the optional command-line
 * demo's configuration for them (#247), after the governed path rather than as a step of its own,
 * and never a link the server would answer with a 404: from the instant the facts go stale the
 * route answers 404, and the card takes the link back then even with nothing new read. Where a
 * refresh is all the demo waits for (`demo_needs_refresh`: the facts have gone stale, or guided
 * setup's own requests isolated the sample workstation and, approved, the production one), or the
 * facts went stale since the server offered it, it says so in the link's place. Adding is offered
 * only while the workspace has no policy and no connection, which the server decides; refreshing
 * and removing wait for the server, removing asks first, and both are held back while a sample
 * request waits for approval or provider evidence, and while either is on its way. After a change the card reads the samples and the connection
 * again rather than showing the change's own answer, which a later change may already have
 * overtaken, and the change stays on its way until they have come, so the buttons and the toast
 * never run ahead of the table. A refused change reads the samples again too, since a refusal means
 * the card's read is out of date, and starting a change clears what the others last said. The
 * effect column is what the starter rules read on each target's facts, never the kernel's
 * decision. Staleness is judged by the server's clock, read again every half minute
 * (`held.useStaleSince`).
 */
export function SampleTargets({ samples }: { samples: SampleStatusView }) {
  const [confirming, setConfirming] = useState(false);
  const cache = useQueryClient();
  const staleSince = useStaleSince(samples.stale_at);
  // Where the client's guide can be read: the deployment's source, linked where it names one.
  const source = useService().source_url;
  const guide = <>the Python client&apos;s guide (<code>clients/python/README.md</code> in {source !== null ? <a href={source}>the source repository</a> : "the source repository"})</>;
  // Each returns the reads it waits for, so its mutation stays pending, and its button held,
  // until the card shows what the server now holds.
  async function changed(message: string) {
    void cache.invalidateQueries({ queryKey: [{ _id: "listPolicy" }] });
    await Promise.all([
      cache.invalidateQueries({ queryKey: [{ _id: "readSamples" }] }),
      cache.invalidateQueries({ queryKey: [{ _id: "readConnection" }] }),
    ]);
    setConfirming(false);
    toast(message);
  }
  async function refused() {
    await cache.invalidateQueries({ queryKey: [{ _id: "readSamples" }] });
    setConfirming(false);
  }
  const install = useServerMutation({
    ...installSamplesMutation(),
    onSuccess: () => changed("Sample targets added. The starter policy is active."),
  });
  const refresh = useServerMutation({
    ...refreshSamplesMutation(),
    // The toast says what this refresh recorded; the table and the facts line come from the
    // samples read again, never from this answer.
    onSuccess: (view) => changed(refreshedWords(view)),
    onError: refused,
  });
  const remove = useServerMutation({
    ...removeSamplesMutation(),
    onSuccess: () => changed("Sample targets removed. Their requests stay in Activity."),
    onError: refused,
  });
  /** A change about to start: what the others last said is about a card that has moved on. */
  function clear() {
    install.reset();
    refresh.reset();
    remove.reset();
  }
  if (samples.state === "absent" && !samples.offered) return null;
  const mark = <Badge tone="accent">Sample</Badge>;
  if (samples.state === "absent") {
    return <Card title="Sample targets" aside={mark}>
      <p>Give your agent something real to act on. Adding sample targets creates:</p>
      <ul>{ADDS.map((line) => <li key={line}>{line}</li>)}</ul>
      <p className="muted">Synthetic data only: nothing here reaches a real system, and you can remove it at any time.</p>
      <Button variant="primary" disabled={install.isPending} onClick={() => { clear(); install.mutate({ body: {} }); }}>
        {install.isPending ? "Adding sample targets…" : "Add sample targets"}
      </Button>
      <Problem error={install.error} />
    </Card>;
  }
  const busy = samples.state === "present";
  const held = busy || refresh.isPending || remove.isPending;
  const stale = staleSince !== null;
  return <Card title="Sample targets" aside={stale ? <span className="badges">{mark}<Badge tone="stale">Stale</Badge></span> : mark}>
    <p>This workspace has sample targets and the starter policy. Ask your agent to isolate one: each request passes the whole policy, and an allowed one really changes the protected endpoint mock.</p>
    <Table caption={SAMPLE_CAPTION} density="compact">
      <thead><tr><Th>Target</Th><Th>Kind</Th><Th>Open incident</Th><Th>Starter policy</Th></tr></thead>
      <tbody>{samples.hosts.map((host) => <SampleRow key={host.provider_id} host={host} />)}</tbody>
    </Table>
    <p className="muted">As the starter rules read these facts; each live decision is the policy's own.{factsWords(samples, stale)}</p>
    {busy ? <p className="note">A sample request is waiting for approval or provider evidence. Settle it in Approvals or Activity before refreshing or removing the samples.</p> : null}
    {confirming ? <div className="form-row" role="group" aria-label="Confirm removal">
      <p>Remove the sample targets? Their connection and targets stop working, and their history stays.</p>
      <Button variant="danger" disabled={remove.isPending} onClick={() => { clear(); remove.mutate({ body: {} }); }}>Remove</Button>
      <Button disabled={remove.isPending} onClick={() => { setConfirming(false); }}>Cancel</Button>
    </div> : <>
      <div className="form-row">
        <Button disabled={held} onClick={() => { clear(); refresh.mutate({ body: {} }); }}>{refresh.isPending ? "Refreshing sample facts…" : "Refresh sample facts"}</Button>
        <Button disabled={held} onClick={() => { setConfirming(true); }}>Remove sample targets</Button>
      </div>
      <details className="setup-details"><summary>What a refresh changes</summary><p className="muted">{REFRESHES}</p></details>
    </>}
    <Problem error={refresh.error} explain={refreshRefusal} />
    <Problem error={remove.error} />
    {samples.demo_available && !stale ? <p className="muted">Optional: the <code>execbound-demo</code> command from the Python client runs the boundary and approval beats on these targets from your own machine with an agent&apos;s API key, as {guide} describes. It needs them as their facts record them, and an isolation of one that executes, by a run or by your own agent, changes it, so refresh the sample facts and download the configuration again before the next run. <a href={demoConfigurationUrl(workspaceGeneration())} download="sandbox.json">Download demo configuration</a></p> : null}
    {samples.demo_needs_refresh || (samples.demo_available && stale) ? <p className="muted">Optional: the <code>execbound-demo</code> command from the Python client runs the boundary and approval beats on these targets from your own machine, as {guide} describes. Its configuration is offered while the sample facts are current and record the targets as they are, which they stop doing when the facts go stale or a request, your own agent&apos;s or a run&apos;s, isolates a target; refresh the sample facts to download it.</p> : null}
  </Card>;
}

function SampleRow({ host }: { host: SampleHostView }) {
  const effect: { word: string; tone: Tone } = EFFECTS[host.effect] ?? { word: host.effect, tone: "obs" };
  return <tr>
    <Td><span className="badges"><span className="mono">{host.hostname}</span><Badge tone="accent">Sample</Badge></span></Td>
    <Td>{`${ROLES[host.role] ?? host.role.replaceAll("_", " ")}, ${host.environment}`}</Td>
    <Td mono>{host.incident_id ?? "None"}</Td>
    <Td><Badge tone={effect.tone}>{effect.word}</Badge></Td>
  </tr>;
}
