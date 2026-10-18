// SPDX-License-Identifier: AGPL-3.0-only
// The weekly summary under My account (#678): one switch, off until the person turns
// it on, offered only where this deployment sends it. The change is the server's: the card
// shows the new state from the server's answer, never before it.

import { useQueryClient } from "@tanstack/react-query";

import { changeWeeklySummaryMutation, readSettingsQueryKey } from "../../api/@tanstack/react-query.gen";
import type { PersonalSettingsView } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { copyFor } from "../../lib/refusal";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";

export const SUMMARY_COPY = {
  title: "Weekly summary",
  lead: "A plain-text email each Monday with this workspace's counts for the week. It names the workspace but no person, agent or target, links only to the console and to stopping it, and you can stop it from the email itself.",
  noAddress: "No email address is on file for you in this workspace. An administrator can add one on Users.",
} as const;

export function WeeklySummary({ view }: { view: PersonalSettingsView }) {
  const queryClient = useQueryClient();
  const change = useServerMutation({
    ...changeWeeklySummaryMutation(),
    onSuccess: (fresh) => {
      queryClient.setQueryData(readSettingsQueryKey(), fresh);
    },
  });
  // The server's last answer, or the page's read: never a state the server has not said.
  const summary = change.data?.weekly_summary ?? view.weekly_summary;
  if (!summary?.available) return null;
  const on = summary.subscribed;
  return (
    <Card title={SUMMARY_COPY.title} aside={<span className="muted">{on ? "On" : "Off"}</span>}>
      <p>{SUMMARY_COPY.lead}</p>
      {summary.address !== null ? (
        <p className="muted">
          It goes to <span className="mono">{summary.address}</span>.
        </p>
      ) : (
        <p className="muted">{SUMMARY_COPY.noAddress}</p>
      )}
      <div className="row">
        <Button
          type="button"
          aria-pressed={on}
          disabled={change.isPending || (!on && summary.address === null)}
          onClick={() => {
            change.mutate({ body: { subscribed: !on } });
          }}
        >
          {on ? "Turn off the weekly summary" : "Turn on the weekly summary"}
        </Button>
      </div>
      {change.isError ? (
        <p className="problem" role="alert">
          {copyFor(change.error)}
        </p>
      ) : null}
    </Card>
  );
}
