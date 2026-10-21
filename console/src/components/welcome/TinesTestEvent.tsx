// SPDX-License-Identifier: AGPL-3.0-only
// A test event for the Execute story on a sample target (#178). The story's entry fields, from the
// integration's README, filled from the server's own answers: the sample the person picks, its open
// incident, and the operation the samples answer to (`operation_ref`, read as the connection card
// reads it, never written here). The reference is new for every event, because a reference already
// recorded on a target brings back the request recorded under it. Nothing here lists targets to an
// agent (decision 2T0): these are the workspace's own samples, shown to the person who added them.

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { readConnectionOptions, readSamplesOptions } from "../../api/@tanstack/react-query.gen";
import type { SampleHostView } from "../../api/types.gen";
import { CopyRecipe } from "./CopyRecipe";

/** A reference no earlier run has used: the story refuses to run without one. */
export function freshReference(): string {
  return `tines-test-${crypto.randomUUID().slice(0, 8)}`;
}

/** The event the Execute story's `Entry` reads, for one sample target. */
export function testEvent(host: SampleHostView, incident: string, operationRef: string, reference: string): string {
  return JSON.stringify(
    {
      operation_ref: operationRef,
      target_kind: "hostname",
      target_value: host.hostname,
      incident_id: incident,
      reference,
    },
    null,
    2,
  );
}

const EFFECT: Record<string, string> = {
  allow: "executes",
  deny: "is denied",
  "require approval": "waits for approval",
};

export function TinesTestEvent() {
  const samples = useQuery({ ...readSamplesOptions(), staleTime: 30_000 });
  const operationRef = useQuery({ ...readConnectionOptions(), staleTime: 30_000 }).data?.operation_ref ?? null;
  const hosts = (samples.data?.hosts ?? []).filter((host) => host.incident_id !== null);
  const [chosen, setChosen] = useState<string | null>(null);
  const [reference, setReference] = useState(freshReference);
  const [first] = hosts;
  if (samples.data?.state === undefined || samples.data.state === "absent" || operationRef === null || first === undefined) return null;
  const host = hosts.find((item) => item.hostname === chosen) ?? first;
  // Filtered above, so the incident is there; narrowed again for the type.
  const incident = host.incident_id ?? "";
  return <div className="tines-test-event stack">
    <p>With the sample targets added, this event runs the story on one of them.</p>
    <label>
      Sample target{" "}
      <select value={host.hostname} onChange={(event) => { setChosen(event.target.value); setReference(freshReference()); }}>
        {hosts.map((item) => <option key={item.hostname} value={item.hostname}>{item.hostname} ({EFFECT[item.effect] ?? item.effect})</option>)}
      </select>
    </label>
    <CopyRecipe label="Test event" text={testEvent(host, incident, operationRef, reference)} />
    <p className="muted">Each run needs a new <code>reference</code>: the same one on the same target brings back the request already recorded under it. Reuse it only to send the same request again, as after you approve it.</p>
    <p><button type="button" className="btn btn-small" onClick={() => { setReference(freshReference()); }}>New reference</button></p>
  </div>;
}
