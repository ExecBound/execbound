// SPDX-License-Identifier: AGPL-3.0-only
// The dialogs a connection's actions open (#678): its schedule, a replaced sealed key and its
// revocation. They load the first time one opens. Each waits for the server's answer and then
// shows the connection as the server returned it.

import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  replaceMonitorConnectionKeyMutation,
  revokeMonitorConnectionMutation,
  scheduleMonitorConnectionMutation,
} from "../../api/@tanstack/react-query.gen";
import type { MonitorConnection } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { count } from "../../lib/when";
import { Field } from "../ui/Field";
import { FormDialog } from "../ui/FormDialog";
import { answered, connectCopy, ENTRA_ENTERPRISE_APPS, SCHEDULES, validKey } from "./connect";
import type { PlatformApp } from "./ConnectionActions";

function every(seconds: number): string {
  return seconds % 3600 === 0 ? count(seconds / 3600, "hour") : count(seconds / 60, "minute");
}

/** A fixed choice per interval, in every credential mode: Tines's audit records every 5 to 60
 * minutes with its inventory daily, or Entra's whole directory every 1 to 24 hours. */
export function ScheduleDialog({ connection, onClose }: { connection: MonitorConnection; onClose: () => void }) {
  const queryClient = useQueryClient();
  const tines = connection.kind === "tines";
  const options = tines ? SCHEDULES.tines : SCHEDULES.entra_agent_id;
  const current = tines ? connection.activity_interval_seconds : connection.collect_interval_seconds;
  // The connection's own interval where it is one of the choices, else the kind's default.
  const [chosen, setChosen] = useState<number>(
    current !== null && (options as readonly number[]).includes(current) ? current : tines ? 900 : 21600,
  );
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const scheduling = useServerMutation({
    ...scheduleMonitorConnectionMutation(),
    onSuccess: (fresh) => {
      answered(queryClient, fresh);
      onClose();
    },
    onError: (error) => {
      setProblem(connectCopy(error, { activity_interval_seconds: "Choose one of the intervals offered.", collect_interval_seconds: "Choose one of the intervals offered." }));
    },
  });
  return (
    <FormDialog
      open
      onClose={onClose}
      title="Schedule collection"
      description={tines ? "How often the collector reads this connection's audit records. Its inventory is read daily." : "How often the collector reads this directory's identities and grants."}
      confirm="Save schedule"
      pending={scheduling.isPending}
      error={problem}
      onSubmit={() => {
        setProblem(undefined);
        scheduling.mutate({
          path: { connection_id: connection.connection_id },
          body: tines ? { activity_interval_seconds: chosen } : { collect_interval_seconds: chosen },
        });
      }}
    >
      <Field id="schedule-interval" label={tines ? "Read audit records every" : "Collect every"}>
        <select
          id="schedule-interval"
          value={chosen}
          onChange={(event) => {
            setChosen(Number(event.target.value));
          }}
        >
          {options.map((seconds) => (
            <option key={seconds} value={seconds}>
              {every(seconds)}
            </option>
          ))}
        </select>
      </Field>
    </FormDialog>
  );
}

/** Revoking stops collection here and keeps every row; it asks first. A directory's consent is
 * the directory's to withdraw, so for a consented connection the dialog says where. */
export function RevokeDialog({
  connection,
  platformApp = null,
  onClose,
}: {
  connection: MonitorConnection;
  platformApp?: PlatformApp | null;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const revoking = useServerMutation({
    ...revokeMonitorConnectionMutation(),
    onSuccess: (fresh) => {
      answered(queryClient, fresh);
      onClose();
    },
    onError: (error) => {
      setProblem(connectCopy(error));
    },
  });
  return (
    <FormDialog
      open
      onClose={onClose}
      title="Revoke this connection?"
      description="Revoking stops collection from this connection. What it collected is kept, and a revoked connection cannot be turned back on; connect again to collect again."
      confirm="Revoke connection"
      variant="danger"
      pending={revoking.isPending}
      error={problem}
      onSubmit={() => {
        setProblem(undefined);
        revoking.mutate({ path: { connection_id: connection.connection_id }, body: {} });
      }}
    >
      {connection.credential_mode === "platform_app" ? (
        <p>
          {platformApp !== null
            ? `Revoking stops collection here. To withdraw this deployment's access to your directory, remove the ${platformApp.displayName} enterprise application (client ID ${platformApp.clientId}) in Microsoft Entra.`
            : "Revoking stops collection here. To withdraw this deployment's access to your directory, remove its enterprise application in Microsoft Entra."}{" "}
          <a href={ENTRA_ENTERPRISE_APPS} target="_blank" rel="noopener noreferrer">
            Enterprise applications in the Microsoft Entra admin center
          </a>
        </p>
      ) : null}
    </FormDialog>
  );
}

/** A sealed connection's key, pasted again: sealed for the collector like the first, cleared
 * from this dialog whatever the answer, and never shown. */
export function ReplaceKeyDialog({ connection, onClose }: { connection: MonitorConnection; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [key, setKey] = useState("");
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const replacing = useServerMutation({
    ...replaceMonitorConnectionKeyMutation(),
    gcTime: 0,
    onSuccess: (fresh) => {
      setKey("");
      replacing.reset();
      answered(queryClient, fresh);
      onClose();
    },
    onError: (error) => {
      setKey("");
      setProblem(connectCopy(error, { api_key: "Paste the API key without spaces." }));
      replacing.reset();
    },
  });
  return (
    <FormDialog
      open
      onClose={() => {
        setKey("");
        onClose();
      }}
      title="Replace the key"
      description="The new key is sealed for ExecBound's collector and replaces the old one. This web service cannot read it back, and it is never shown again."
      confirm="Replace key"
      pending={replacing.isPending}
      error={problem}
      onSubmit={() => {
        setProblem(undefined);
        if (!validKey(key)) {
          setProblem("Paste the API key without spaces.");
          return;
        }
        replacing.mutate({ path: { connection_id: connection.connection_id }, body: { api_key: key } });
      }}
    >
      <Field id="replace-key" label="New API key">
        <input
          id="replace-key"
          type="password"
          autoComplete="off"
          spellCheck={false}
          maxLength={4096}
          value={key}
          onChange={(event) => {
            setKey(event.target.value);
          }}
        />
      </Field>
    </FormDialog>
  );
}
