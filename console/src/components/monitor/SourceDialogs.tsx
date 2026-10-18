// SPDX-License-Identifier: AGPL-3.0-only
// The dialogs a reporting source's actions open (#678): rotating its token and revoking it. They
// load the first time one opens. Each waits for the server's answer; a rotation's token is shown
// once through the show-once path and then kept nowhere.

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import {
  readMonitorQueryKey,
  revokeMonitorSourceMutation,
  rotateMonitorSourceMutation,
} from "../../api/@tanstack/react-query.gen";
import type { MonitorSource } from "../../api/types.gen";
import { serverNow } from "../../lib/clock";
import { useServerMutation } from "../../lib/mutation";
import { refusal } from "../../lib/refusal";
import { count } from "../../lib/when";
import { useShowOnce } from "../directory/showOnce";
import { Field } from "../ui/Field";
import { FormDialog } from "../ui/FormDialog";
import { Time } from "../ui/Time";
import { GRACES, INTAKE_ONLY, LIFETIMES, REVOCATION_UNCONFIRMED, ROTATION_UNCONFIRMED, sourceCopy } from "./connect";
import { SourceTokenDialog } from "./SourceTokenDialog";

type Lifetime = (typeof LIFETIMES)[number];
type Grace = (typeof GRACES)[number];

function graceWords(minutes: number): string {
  if (minutes === 0) return "No time: stop it now";
  if (minutes === 60) return "1 hour";
  return count(minutes, "minute");
}

/** A new token for the source: the previous one keeps reporting for the grace chosen, never past
 * its own expiry, so the story's credential can be updated in between. Only one previous token is
 * kept, so the dialog says when rotating again would end an earlier token's grace at once. */
export function RotateSourceDialog({ source, onClose }: { source: MonitorSource; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [lifetime, setLifetime] = useState<Lifetime>(30);
  const [grace, setGrace] = useState<Grace>(10);
  const rotating = useShowOnce(rotateMonitorSourceMutation());
  const unconfirmed = rotating.error !== null && refusal(rotating.error).code === "UNAVAILABLE";
  // An answer that did not arrive may still have rotated the source: it is read again.
  useEffect(() => {
    if (rotating.error !== null) void queryClient.invalidateQueries({ queryKey: readMonitorQueryKey() });
  }, [rotating.error, queryClient]);
  // A source keeps one previous token: rotating while an earlier rotation's grace runs ends it.
  const previous = source.previous_valid_until;
  const graceRunning = previous !== null && Date.parse(previous) > serverNow();
  if (rotating.secret !== null) {
    return (
      <SourceTokenDialog
        minted={rotating.secret}
        onClose={() => {
          rotating.close();
          void queryClient.invalidateQueries({ queryKey: readMonitorQueryKey() });
          onClose();
        }}
      />
    );
  }
  return (
    <FormDialog
      open
      onClose={onClose}
      title="Rotate the source token"
      description="A new token replaces this source's token. The new one is shown once; put it in the story's credential, then let the previous one lapse."
      confirm="Rotate token"
      pending={rotating.pending}
      error={unconfirmed ? ROTATION_UNCONFIRMED : rotating.error !== null ? sourceCopy(rotating.error) : undefined}
      onSubmit={() => {
        void rotating.issue({
          path: { source_id: source.source_id },
          body: { lifetime_days: lifetime, grace_minutes: grace },
        });
      }}
    >
      <Field id="rotate-lifetime" label="New token valid for">
        <select
          id="rotate-lifetime"
          value={lifetime}
          onChange={(event) => {
            setLifetime(Number(event.target.value) as Lifetime);
          }}
        >
          {LIFETIMES.map((days) => (
            <option key={days} value={days}>
              {count(days, "day")}
            </option>
          ))}
        </select>
      </Field>
      {/* Before the grace it bears on, which is the choice "below". */}
      {graceRunning ? (
        <p className="monitor-note">
          The token this source replaced is still accepted until <Time at={previous} />. Rotating again stops it now: only
          the token the source holds now keeps reporting, for the time you choose below.
        </p>
      ) : null}
      <Field id="rotate-grace" label="Keep the previous token reporting for">
        <select
          id="rotate-grace"
          value={grace}
          onChange={(event) => {
            setGrace(Number(event.target.value) as Grace);
          }}
        >
          {GRACES.map((minutes) => (
            <option key={minutes} value={minutes}>
              {graceWords(minutes)}
            </option>
          ))}
        </select>
      </Field>
      <p>{INTAKE_ONLY}</p>
    </FormDialog>
  );
}

/** Revoking stops every token the source ever had at once; it asks first. */
export function RevokeSourceDialog({ source, onClose }: { source: MonitorSource; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const revoking = useServerMutation({
    ...revokeMonitorSourceMutation(),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: readMonitorQueryKey() });
      onClose();
    },
    onError: (error) => {
      // An answer that did not arrive may still have revoked it: the sources are read again.
      void queryClient.invalidateQueries({ queryKey: readMonitorQueryKey() });
      setProblem(refusal(error).code === "UNAVAILABLE" ? REVOCATION_UNCONFIRMED : sourceCopy(error));
    },
  });
  return (
    <FormDialog
      open
      onClose={onClose}
      title="Revoke this source?"
      description="The story's events will be refused from now on. A revoked source cannot be rotated."
      confirm="Revoke source"
      variant="danger"
      pending={revoking.isPending}
      error={problem}
      onSubmit={() => {
        setProblem(undefined);
        revoking.mutate({ path: { source_id: source.source_id }, body: {} });
      }}
    />
  );
}
