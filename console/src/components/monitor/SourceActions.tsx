// SPDX-License-Identifier: AGPL-3.0-only
import { lazy, Suspense, useState } from "react";

import type { MonitorSource } from "../../api/types.gen";
import { Button } from "../ui/Button";
import { SOURCE_EVENTS } from "./connect";

// Each dialog loads the first time it opens, so the Monitoring page does not carry them.
const RotateSourceDialog = lazy(async () => ({ default: (await import("./SourceDialogs")).RotateSourceDialog }));
const RevokeSourceDialog = lazy(async () => ({ default: (await import("./SourceDialogs")).RevokeSourceDialog }));

/**
 * What an administrator does to one reporting source (#678): rotate its token, with a grace for
 * the previous one, where this deployment mints sources; and revoke it, which is offered whatever
 * the deployment mints, because a source minted earlier must always be revocable. A revoked
 * source offers neither, and neither does one in a Space this administrator only reviews. A source
 * that has kept all its events, which rotating does not reset, says to add its story again first
 * and to revoke it only after: revoking is final and stops its heartbeats, and a full workspace
 * refuses the story's next source. Each change is the server's answer, never optimistic.
 */
export function SourceActions({ source, mintAvailable }: { source: MonitorSource; mintAvailable: boolean }) {
  const [open, setOpen] = useState<"rotate" | "revoke" | null>(null);
  if (source.revoked_at !== null) return null;
  // An administrator narrowed to Spaces reads a source in a Space they only review and changes
  // nothing there, so nothing the server would refuse is offered.
  if (!source.administered) {
    return <p className="muted">You review this source&apos;s Space but do not administer it, so its administrators rotate or revoke it.</p>;
  }
  const close = () => {
    setOpen(null);
  };
  return (
    <div className="monitor-actions-block">
      {source.accepted_count >= SOURCE_EVENTS ? (
        <p className="muted">
          This source has kept its 10,000 events, so intake refuses the story&apos;s further events, though it still takes the
          story&apos;s heartbeats, and rotating its token does not reset that count. To report story {source.story_id}&apos;s
          events again, add a reporting source for the story first, then revoke this one once the story reports through the
          new token. Where the workspace is full, adding is refused and this source carries on as it is.
        </p>
      ) : null}
      <div className="monitor-actions" role="group" aria-label={`Actions for ${source.label}`}>
        {mintAvailable ? (
          <Button
            onClick={() => {
              setOpen("rotate");
            }}
          >
            Rotate token
          </Button>
        ) : null}
        <Button
          variant="danger"
          onClick={() => {
            setOpen("revoke");
          }}
        >
          Revoke
        </Button>
      </div>
      <Suspense fallback={null}>
        {open === "rotate" ? <RotateSourceDialog source={source} onClose={close} /> : null}
        {open === "revoke" ? <RevokeSourceDialog source={source} onClose={close} /> : null}
      </Suspense>
    </div>
  );
}
