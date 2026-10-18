// SPDX-License-Identifier: AGPL-3.0-only
// Copy link and Copy reference (#678): a record's or an agent's own address, and a record's
// reference, to send to a colleague. The address is built by the router from the route and its
// identifiers, resolved on this page's origin, and never read from the address bar, so nothing
// the bar holds beyond the route and its checked search is copied. A link grants nothing: the
// colleague's own session reads the record, and one they cannot see answers "not found". Where
// the clipboard refuses, the value is shown as text to copy by hand.

import { useRouter } from "@tanstack/react-router";
import { useState } from "react";

import { Button } from "./ui/Button";
import "./CopyLink.css";

function useCopy(done: string, fallback: string) {
  const [message, setMessage] = useState<{ copied: boolean; value: string } | null>(null);
  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setMessage({ copied: true, value });
    } catch {
      setMessage({ copied: false, value });
    }
  };
  const status = (
    <span className="muted" role="status">
      {message === null ? null : message.copied ? ` ${done}` : (
        <>
          {` ${fallback} `}
          <span className="mono copy-value">{message.value}</span>
        </>
      )}
    </span>
  );
  return { copy, status };
}

/** "Copy link": the router's address for `to` with `params` and `search`, on this origin. */
export function CopyLink({
  to,
  params,
  search,
  label = "Copy link",
}: {
  to: string;
  params?: Record<string, string>;
  search?: Record<string, string>;
  label?: string;
}) {
  const router = useRouter();
  const { copy, status } = useCopy("Link copied.", "Copy this link:");
  return (
    <span className="copy-control">
      <Button
        size="small"
        onClick={() => {
          const href = router.buildLocation({ to, params, search } as Parameters<typeof router.buildLocation>[0]).href;
          void copy(new URL(href, window.location.origin).href);
        }}
      >
        {label}
      </Button>
      {status}
    </span>
  );
}

/** "Copy reference": a value that is not a secret, such as a request's reference. */
export function CopyText({ value, label = "Copy reference" }: { value: string; label?: string }) {
  const { copy, status } = useCopy("Reference copied.", "Copy this reference:");
  return (
    <span className="copy-control">
      <Button
        size="small"
        onClick={() => {
          void copy(value);
        }}
      >
        {label}
      </Button>
      {status}
    </span>
  );
}
