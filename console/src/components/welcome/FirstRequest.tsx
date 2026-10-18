// SPDX-License-Identifier: AGPL-3.0-only
// Waiting for an agent's first request (#678). While the agent is active, holds a live key and
// has made no request, the panel asks for the agent again on the console's one shared timer,
// which asks nothing while the tab is hidden. It stops when a request lands, ten minutes of
// wall-clock time after it started (hidden time included, so a reader who comes back later sees
// it stopped, with Resume), or when the page is left. It names no cause and guesses no hop: a
// request refused before authentication leaves no record here.

import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { readAgentOptions } from "../../api/@tanstack/react-query.gen";
import type { AgentDetail } from "../../api/types.gen";
import { usePolledQuery } from "../../lib/poll";
import { toneFor } from "../../lib/words";
import { principalName, words } from "../directory/format";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";

/** How long the panel listens before it stops and offers Resume. */
export const LISTEN_MS = 10 * 60_000;
const CHECK_MS = 60_000;

export function FirstRequest({ detail }: { detail: AgentDetail }) {
  const agent = detail.agent;
  const live = detail.credentials.some((credential) => credential.state === "live");
  const newest = detail.recent[0];
  const waiting = agent?.active === true && live && newest === undefined;
  // When listening began, by the wall clock; set by the effect, never during render.
  const startedAt = useRef<number | null>(null);
  const [stopped, setStopped] = useState(false);
  const listening = waiting && !stopped;
  usePolledQuery({ ...readAgentOptions({ path: { row_id: detail.row_id } }), enabled: listening });
  useEffect(() => {
    if (!listening) return;
    startedAt.current ??= Date.now();
    const began = startedAt.current;
    const check = () => {
      if (Date.now() - began >= LISTEN_MS) setStopped(true);
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") check();
    };
    check();
    const timer = setInterval(check, CHECK_MS);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [listening]);
  if (agent === null) return null;
  if (newest !== undefined) {
    return <div role="status" className="first-request">
      <p>
        <Badge tone={toneFor(newest.state)}>{words(newest.state)}</Badge>{" "}
        <span className="mono">{newest.request_ref}</span>{" "}
        <Link to="/activity" search={{ open: newest.execution_id }}>Open this decision</Link>
      </p>
      {newest.state === "PENDING_APPROVAL" ? <p>It waits for a reviewer in <Link to="/approvals">Approvals</Link>.</p> : null}
    </div>;
  }
  if (!waiting) return null;
  const name = principalName("Agent", agent.label, agent.number, agent.principal_id);
  return <div role="status" className="first-request">
    {stopped ? <p>
      Stopped listening after 10 minutes.{" "}
      <Button onClick={() => { startedAt.current = null; setStopped(false); }}>Resume</Button>
    </p> : <p>Waiting for the first request from {name}…</p>}
    <p className="muted">Nothing recorded yet. Check the server URL and key in your host. A request refused before authentication leaves no record here.</p>
  </div>;
}
