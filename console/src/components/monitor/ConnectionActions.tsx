// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useState } from "react";

import { requestMonitorCollectionMutation } from "../../api/@tanstack/react-query.gen";
import type { MonitorConnection } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { PrincipalName } from "../PrincipalName";
import { Button } from "../ui/Button";
import { Time } from "../ui/Time";
import { answered, connectCopy } from "./connect";

// Each dialog loads the first time it opens, so the Monitoring page does not carry them.
const ScheduleDialog = lazy(async () => ({ default: (await import("./ConnectionDialogs")).ScheduleDialog }));
const RevokeDialog = lazy(async () => ({ default: (await import("./ConnectionDialogs")).RevokeDialog }));
const ReplaceKeyDialog = lazy(async () => ({ default: (await import("./ConnectionDialogs")).ReplaceKeyDialog }));
const EgressDialog = lazy(async () => ({ default: (await import("./ConnectionDialogs")).EgressDialog }));
const ConnectEntra = lazy(async () => ({ default: (await import("./ConnectEntra")).ConnectEntra }));

type Open = "schedule" | "revoke" | "key" | "consent" | "egress" | null;

/** The deployment's platform app, as a directory administrator sees it, where it is configured. */
export interface PlatformApp {
  displayName: string;
  clientId: string;
}

/**
 * What an administrator does to one connection (#678): ask for a collection now, change its
 * schedule, replace a sealed key, update a directory's consent once a permission it gave is
 * refused, or revoke it. Each is the server's answer, never optimistic: a button waits for it,
 * and the requested line comes from the connection the server returns. "Collect now" asks; the
 * next scheduled pass collects.
 */
export function ConnectionActions({
  connection,
  connectAvailable,
  platformApp = null,
}: {
  connection: MonitorConnection;
  connectAvailable: boolean;
  /** Where Microsoft Entra connects from the console: the app a revocation tells how to remove. */
  platformApp?: PlatformApp | null;
}) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState<Open>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const asking = useServerMutation({
    ...requestMonitorCollectionMutation(),
    onSuccess: (fresh) => {
      setProblem(null);
      answered(queryClient, fresh);
    },
    onError: (error) => {
      setProblem(connectCopy(error));
    },
  });
  if (connection.revoked_at !== null) return null;
  const sealed = connection.credential_mode === "sealed";
  const consented = connection.credential_mode === "platform_app";
  // The collector opens these itself, so the next scheduled run takes a request up.
  const scheduled = connection.credential_mode !== "key_file";
  const requested = connection.collect_requested_at;
  const close = () => {
    setOpen(null);
  };
  return (
    <div className="monitor-actions-block">
      {requested !== null ? (
        <p className="monitor-requested" role="status">
          {scheduled ? (
            <>
              Requested at <Time at={requested} /> by{" "}
              {connection.collect_requested_by !== null ? <PrincipalName principal={connection.collect_requested_by} kind="ADMIN" /> : "an administrator"}. The
              next scheduled run picks it up within five minutes.
            </>
          ) : (
            <>Requested. The collector picks it up where it holds this connection&apos;s key file.</>
          )}
        </p>
      ) : null}
      {consented && connection.consent_needs_update ? (
        <p className="monitor-note">Consent needs updating: a permission this connection had is now refused.</p>
      ) : null}
      {problem !== null ? (
        <p role="alert" className="problem">
          {problem}
        </p>
      ) : null}
      <div className="monitor-actions" role="group" aria-label={`Actions for ${connection.label}`}>
        <Button
          disabled={asking.isPending}
          aria-busy={asking.isPending}
          onClick={() => {
            asking.mutate({ path: { connection_id: connection.connection_id }, body: {} });
          }}
        >
          {asking.isPending ? "Asking…" : "Collect now"}
        </Button>
        <Button
          onClick={() => {
            setOpen("schedule");
          }}
        >
          Schedule
        </Button>
        {sealed && connection.kind === "tines" && connectAvailable ? (
          <Button
            onClick={() => {
              setOpen("key");
            }}
          >
            Replace key
          </Button>
        ) : null}
        {connection.kind === "tines" ? (
          <Button
            onClick={() => {
              setOpen("egress");
            }}
          >
            Record egress
          </Button>
        ) : null}
        {consented && connection.consent_needs_update && platformApp !== null ? (
          <Button
            onClick={() => {
              setOpen("consent");
            }}
          >
            Update consent
          </Button>
        ) : null}
        <Button
          variant="danger"
          onClick={() => {
            setOpen("revoke");
          }}
        >
          {connection.kind === "fixture" ? "Remove" : "Revoke"}
        </Button>
      </div>
      <Suspense fallback={null}>
        {open === "schedule" ? <ScheduleDialog connection={connection} onClose={close} /> : null}
        {open === "revoke" ? <RevokeDialog connection={connection} platformApp={consented ? platformApp : null} onClose={close} /> : null}
        {open === "key" ? <ReplaceKeyDialog connection={connection} onClose={close} /> : null}
        {open === "egress" ? <EgressDialog connection={connection} onClose={close} /> : null}
        {open === "consent" && platformApp !== null ? (
          <ConnectEntra displayName={platformApp.displayName} connectionId={connection.connection_id} onClose={close} />
        ) : null}
      </Suspense>
    </div>
  );
}
