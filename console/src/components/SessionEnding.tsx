// SPDX-License-Identifier: AGPL-3.0-only
// The notice before a session's hard end (#678). A visible console renews its session on every
// read, so the end after twelve hours without activity is reached only in a tab left alone, where
// nothing would be seen; what can surprise a person is the end no renewal passes: two days after
// signing in, or the setup credential's own expiry when that is sooner. Two minutes before it,
// measured on the server's clock, this says when and what to do. It extends nothing and offers
// nothing that would, never takes focus and cannot be dismissed. When the end passes, the next
// read answers 401 and the person signs in again back to this page.

import { Link } from "@tanstack/react-router";
import { useEffect, useReducer } from "react";

import { serverNow } from "../lib/clock";
import { useKeptFieldMounted } from "../lib/kept";
import { useSession } from "../lib/session";
import { Time } from "./ui/Time";
import "./SessionEnding.css";

/** How long before the hard end the notice shows. */
export const NOTICE_MS = 2 * 60 * 1000;

/** Whether the notice is due: read on the server's clock at each render, and one timer wakes the
 * component at the instant it falls due. */
function useDue(endsAt: string | undefined): boolean {
  const end = endsAt === undefined ? Number.NaN : Date.parse(endsAt);
  const [, wake] = useReducer((count: number) => count + 1, 0);
  useEffect(() => {
    const wait = end - NOTICE_MS - serverNow();
    if (Number.isNaN(wait) || wait <= 0) return;
    const timer = setTimeout(wake, wait);
    return () => {
      clearTimeout(timer);
    };
  }, [end]);
  return !Number.isNaN(end) && serverNow() >= end - NOTICE_MS;
}

/** `signInAgain` is the client's (`lib/client-config.ts`), handed in by the shell, which already
 * holds it, so this chunk adds nothing to the client's own. */
export default function SessionEnding({ signInAgain }: { signInAgain: () => void }) {
  const { endsAt, endReason } = useSession();
  const due = useDue(endsAt);
  if (!due || endsAt === undefined) return null;
  return <Notice endsAt={endsAt} setup={endReason === "setup_credential"} signInAgain={signInAgain} />;
}

/** The notice itself, which watches the page for a keeping field only while it is shown. */
function Notice({ endsAt, setup, signInAgain }: { endsAt: string; setup: boolean; signInAgain: () => void }) {
  const kept = useKeptFieldMounted();
  const at = <Time at={endsAt} />;
  if (setup) {
    return (
      <div className="banner banner-ending" role="status">
        <span>
          The setup credential you signed in with expires at {at}, and you will be signed out then. It cannot be used
          after that: set up your own sign-in before then. Save what you are doing.
        </span>
        <span className="row">
          <Link to="/help" className="btn btn-small">
            How to sign in after setup
          </Link>
        </span>
      </div>
    );
  }
  return (
    <div className="banner banner-ending" role="status">
      <span>
        You will be signed out at {at}, two days after you signed in.{" "}
        {kept
          ? "Sign in again to keep working. What you have typed on this page is kept."
          : "Save what you are doing, then sign in again to keep working."}
      </span>
      <span className="row">
        <button type="button" className="btn btn-small" onClick={signInAgain}>
          Sign in again
        </button>
      </span>
    </div>
  );
}
