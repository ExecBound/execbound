// SPDX-License-Identifier: AGPL-3.0-only
import { useState } from "react";

import { Button } from "../components/ui/Button";
import { approvalLink } from "./link";

/**
 * The approval's own address, to send to whoever should decide it (#678): the server's path when
 * it is an approval path for this approval, else the core address, always on this page's own
 * origin and never read from the address bar. Where the clipboard refuses, the link is shown as
 * text to copy by hand.
 */
export function CopyApprovalLink({ linkPath, approvalId }: { linkPath: string; approvalId: string }) {
  const [message, setMessage] = useState<{ copied: boolean; link: string } | null>(null);
  const copy = async () => {
    const link = approvalLink(linkPath, approvalId, `/approvals/${encodeURIComponent(approvalId)}`, window.location.origin);
    try {
      await navigator.clipboard.writeText(link);
      setMessage({ copied: true, link });
    } catch {
      setMessage({ copied: false, link });
    }
  };
  return (
    <p className="row">
      <Button size="small" onClick={() => { void copy(); }}>
        Copy approval link
      </Button>
      <span className="muted" aria-live="polite">
        {message === null ? null : message.copied ? " Link copied." : (
          <>
            {" Copy this link: "}
            <span className="mono detail-copy-link">{message.link}</span>
          </>
        )}
      </span>
    </p>
  );
}
