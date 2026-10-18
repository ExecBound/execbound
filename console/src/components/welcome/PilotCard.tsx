// SPDX-License-Identifier: AGPL-3.0-only
// An optional pilot in Observe only (#678). Enforcing stays the default; the card says plainly
// that a policy is still required, that the mode is the whole workspace's and that the samples'
// approval loop needs Enforcing. Its button opens the existing reasoned, audited mode dialog,
// loaded on the first press, which waits for the server and steps up where the server asks.

import { Link } from "@tanstack/react-router";
import { lazy, Suspense, useState } from "react";

import { useSession } from "../../lib/session";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import "./welcome.css";

const ModeDialog = lazy(async () => ({ default: (await import("../tenant/ModeDialog")).ModeDialog }));

export function PilotCard() {
  const { mode } = useSession();
  const [opened, setOpened] = useState(false);
  const [open, setOpen] = useState(false);
  return <Card title="Pilot in Observe only (optional)">
    <p>
      In Observe only, ExecBound records each request with what it would have done, and nothing is dispatched, approved, reserved or claimed. A policy must still be active: without one, every request is refused in either mode. The mode applies to the whole workspace, every Space in it, and the sample targets&apos; approval loop needs Enforcing. Changing the mode needs a reason and is recorded in the audit log.
    </p>
    <p className="muted">For a wider pilot, your operator&apos;s runbook is Operations, &quot;Onboard a tenant in observe-only mode&quot;.</p>
    {mode === "UNKNOWN" ? <p className="muted">The current mode could not be read.</p> : null}
    <div className="pilot-actions">
      {mode === "UNKNOWN" ? null : <Button onClick={() => { setOpened(true); setOpen(true); }}>{mode === "ENFORCE" ? "Change the mode" : "Return to Enforcing"}</Button>}
      <Link to="/activity" search={{ state: "OBSERVED" }} className="btn">Review what would have happened</Link>
    </div>
    {opened && mode !== "UNKNOWN" ? <Suspense fallback={null}>
      <ModeDialog key={mode} open={open} onClose={() => { setOpen(false); }} current={mode} />
    </Suspense> : null}
  </Card>;
}
