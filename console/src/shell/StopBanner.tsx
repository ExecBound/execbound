// SPDX-License-Identifier: AGPL-3.0-only
import { useSession } from "../lib/session";
import { Time } from "../components/ui/Time";

/**
 * The emergency stop across the shell (#333): the banner every page shows
 * today, on every route, read from the session. The reason is an administrator's string and
 * renders as text. An administrator can resume from here; everyone else sees the state.
 */
export function StopBanner({ onResume }: { onResume: () => void }) {
  const session = useSession();
  const stop = session.stop;
  if (stop === null) return null;
  return (
    <div className="banner banner-stop" role="status">
      <span>
        <strong>Emergency stop active.</strong> {stop.reason} · activated by{" "}
        {stop.byName ?? "an administrator"} at <Time at={stop.at} />. New
        actions, approval decisions and dispatch attempts are refused until an administrator resumes this
        workspace.
      </span>
      {session.role !== "APPROVER" ? (
        <button type="button" className="btn btn-small" onClick={onResume}>
          Resume
        </button>
      ) : null}
    </div>
  );
}
