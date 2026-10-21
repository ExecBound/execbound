// SPDX-License-Identifier: AGPL-3.0-only
// A Tines story as an agent's host (#678): the two committed stories as downloads, unchanged, and
// the steps the integration's README gives for each, in its order. The files carry no origin,
// token or tenant id; the person adds the agent's key as a Tines credential and the origin as a
// resource, here shown from the gateway's own answer. Both are Advisory for Tines. With sample
// targets added, the Execute story's last step carries a test event for one of them (#178).

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { readConnectionOptions, readTenantOptions } from "../../api/@tanstack/react-query.gen";
import { useEdition } from "../../edition/context";
import { CopyRecipe } from "./CopyRecipe";
import { ServiceOperatorWords } from "./OperatorSteps";
import { TinesTestEvent } from "./TinesTestEvent";

type Story = "execute" | "gate";

const BASE = `${import.meta.env.BASE_URL}stories/tines/`;
/** The approval wait for a workspace whose deadline is off, the README's value for one that never set it. */
const DEFAULT_WAIT = 120;

export const STORY_FILES: Record<Story, string> = {
  execute: `${BASE}execbound-governed-action.json`,
  gate: `${BASE}execbound-gate.json`,
};

export function TinesStory() {
  const [story, setStory] = useState<Story>("execute");
  const origin = useQuery({ ...readConnectionOptions(), staleTime: 30_000 }).data?.origin;
  const deadline = useQuery({ ...readTenantOptions(), staleTime: 30_000 }).data?.deadline;
  const { operatorCommands } = useEdition();
  const off = deadline?.seconds === null;
  const wait = String(deadline?.seconds ?? DEFAULT_WAIT);
  const resources = (names: string) => <>
    <p>Create Text resources: {names}.</p>
    {origin !== undefined ? <CopyRecipe label="execbound_origin" text={origin} /> : <p role="status">Loading the gateway&apos;s origin…</p>}
    <p><code>execbound_poll_seconds</code>: <code>30</code>. <code>execbound_wait_seconds</code>: <code>{wait}</code>{deadline === undefined ? " (the workspace's approval deadline, in seconds)" : null}.</p>
    {off ? <p className="muted">The approval deadline is off in this workspace. The story reports pending after this wait, and a later call with the same reference picks up the decision.</p> : null}
  </>;
  const reach = (exits: string) => <li>
    Choose how the story is reached, and do one of these:
    <ul>
      <li><strong>Posted to directly:</strong> open the <code>Entry</code> action once in the Tines editor, which assigns its webhook path and secret. They are empty in the file on purpose: a committed secret would let anyone post into the tenant that exported it.</li>
      <li><strong>Called from another story or an AI Agent:</strong> enable Send to Story with <code>Entry</code> as the entry action and {exits} as exits, in the story&apos;s settings or with <code>{"PUT /api/v1/stories/{id}"}</code>. It cannot be set in the imported file.</li>
    </ul>
  </li>;
  return <div className="tines-story stack">
    <ul className="tines-choices">
      <li>
        <label><input type="radio" name="tines-story" checked={story === "execute"} onChange={() => { setStory("execute"); }} /> <strong>Execute: ExecBound dispatches.</strong></label>
        <p>ExecBound decides, then calls the provider with its own connector. Tested in live Tines against ExecBound&apos;s protected endpoint mock.</p>
        <p><a href={STORY_FILES.execute} download className="btn">Download the Execute story</a></p>
      </li>
      <li>
        <label><input type="radio" name="tines-story" checked={story === "gate"} onChange={() => { setStory("gate"); }} /> <strong>Gate: your vendor connectors stay in Tines.</strong></label>
        <p>ExecBound decides, then the story calls your vendor once with the credential kept in Tines and reports what happened. Tested in live Tines against the same mock acting as the vendor; no real vendor yet.</p>
        <p><a href={STORY_FILES.gate} download className="btn">Download the Gate story</a></p>
      </li>
    </ul>
    <p>Both are Advisory for Tines: nothing forces a story to call ExecBound.</p>
    <h4>{story === "execute" ? "Installing the Execute story" : "Installing the Gate story"}</h4>
    {story === "execute" ? <ol className="steps tines-steps">
        <li>In Tines, create a Text credential named exactly <code>execbound</code> holding this agent&apos;s API key, with its allowed hosts set to this gateway&apos;s host and <code>/v1/execute</code>. Never paste the key into the story.</li>
        <li>{resources("execbound_origin, execbound_poll_seconds and execbound_wait_seconds")}</li>
        <li>Import the story into a real team, not a personal one.</li>
        {reach("both Outcome and Refused: no reference")}
        <li>Run it with a test event naming a target you control, a <code>reference</code> and an <code>incident_id</code>.<TinesTestEvent /></li>
      </ol> : <ol className="steps tines-steps">
        <li>Create three Text credentials: <code>execbound_gate</code>, this agent&apos;s key, allowed only the gateway&apos;s <code>/v1/execute</code> and <code>/v1/executions/</code> paths; <code>execbound_gate_vendor</code>, the vendor&apos;s dispatch token, allowed only the vendor&apos;s host; and <code>execbound_gate_signing</code>, the ES256 private key, which Tines requires to have no host restriction.</li>
        <li>{resources("execbound_origin, execbound_vendor_origin, execbound_gate_key_id, execbound_poll_seconds and execbound_wait_seconds")}</li>
        <li>
          Import the story into a dedicated team, not one that holds unrelated credentials.
          <p className="notice notice-hold">The signing credential cannot be host-restricted, so any story in the team that can read it can sign with it.</p>
        </li>
        <li>{operatorCommands
          ? <>An administrator of this deployment registers the story&apos;s public key and a Gate account: see the Tines integration README in the source, &quot;The Gate story&quot;.</>
          : <ServiceOperatorWords>Your service operator registers the story&apos;s public key: send them the public key and the actions to gate</ServiceOperatorWords>}</li>
        {reach("Outcome, Needs administrator and Refused: no reference")}
        <li>Run it with a test event.</li>
      </ol>}
  </div>;
}
