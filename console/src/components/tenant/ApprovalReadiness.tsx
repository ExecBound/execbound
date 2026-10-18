// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import type { ApprovalWindow, ApprovalWindowSpace, TenantSettingsView } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { useService } from "../../lib/session";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Announcements } from "./Announcements";
import { Changed, WorkspaceOnly } from "./ChangeNotes";
import { DeadlineDialog } from "./DeadlineDialog";
import { announces } from "./delivery";

/** A window shorter than this, announced nowhere, is the one the card warns about. */
export const SHORT_WINDOW_SECONDS = 600;

const KIND_WORDS: Record<ApprovalWindow["source_kinds"][number], string> = {
  inventory: "inventory",
  incident: "incident",
  signal: "security signal",
};

/** A span as a reader says it: seconds under two minutes, else whole minutes rounded up. */
export function spanWords(seconds: number): string {
  if (seconds < 120) return `${String(seconds)} seconds`;
  return `${String(Math.ceil(seconds / 60))} minutes`;
}

function listWords(words: readonly string[]): string {
  return words.length <= 1 ? (words[0] ?? "") : `${words.slice(0, -1).join(", ")} and ${words[words.length - 1] ?? ""}`;
}

/** One action's window as a sentence; the label is the catalog's and renders as text. */
export function windowWords(item: ApprovalWindow): string {
  if (item.bound_seconds === null || item.context_seconds === null || item.limited_by === "unknown") {
    return `${item.action_label}: no figure, because its context contract is not in this deployment's catalog.`;
  }
  if (item.limited_by === "deadline") {
    return `${item.action_label}: at most ${spanWords(item.bound_seconds)}, the approval deadline.`;
  }
  const kinds = listWords(item.source_kinds.map((kind) => KIND_WORDS[kind]));
  return `${item.action_label}: at most about ${spanWords(item.bound_seconds)}. Its ${kinds} facts are valid for ${spanWords(item.context_seconds)} from when they were recorded.`;
}

/**
 * Workspace settings' "Approval readiness" (#678): the approval deadline and its change, how long
 * a held request can wait for each action the active policy can hold, and where approvals are
 * announced. When the workspace enforces, a window is short and nothing announces approvals, it
 * warns once, with the remedy the edition can offer. It reads only the tenant view it is given:
 * nothing here writes anything but the deadline, through its dialog, and every figure is an upper
 * bound the server computed.
 */
export function ApprovalReadiness({ view, workspace }: { view: TenantSettingsView; workspace: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <Card title="Approval readiness">
      <Warning view={view} />
      <p className="figure-value">{view.deadline.seconds === null ? "off" : `${String(view.deadline.seconds)} s`}</p>
      <Changed change={view.deadline.changed} never="The default, never changed." />
      <p className="muted">
        An approval never outlives the frozen plan, so off means the plan's own validity is the only deadline.
        Approvals already pending keep the expiry they were created with.
      </p>
      {workspace ? (
        <div className="row">
          <Button
            onClick={() => {
              setOpen(true);
            }}
          >
            Change deadline
          </Button>
        </div>
      ) : (
        <WorkspaceOnly what="changes the approval deadline" />
      )}
      <h3 className="card-subtitle">How long a held request can wait</h3>
      {view.approval_windows.map((space) => (
        <SpaceWindows key={space.space_id} space={space} named={view.approval_windows.length > 1} />
      ))}
      <p className="muted">
        A request can wait less than this: the time starts when the facts were recorded, not when the request was held,
        and never outlasts the agent&apos;s key or run.
      </p>
      <Announcements view={view} />
      {open ? (
        <DeadlineDialog
          open
          onClose={() => {
            setOpen(false);
          }}
          current={view.deadline}
          destinations={view.destinations}
          delivery={view.delivery}
        />
      ) : null}
    </Card>
  );
}

function SpaceWindows({ space, named }: { space: ApprovalWindowSpace; named: boolean }) {
  return (
    <div className="readiness-space">
      {named ? <h4 className="readiness-space-name">{space.name}</h4> : null}
      {space.bundle_id === null ? (
        <p>No active policy: nothing is held.</p>
      ) : space.actions.length === 0 ? (
        <p>The active policy holds nothing for a person.</p>
      ) : (
        <ul className="readiness-list">
          {space.actions.map((item) => (
            <li key={item.action}>
              {windowWords(item)}
              {item.known ? null : (
                <span className="muted readiness-custom">
                  Custom policy: it may hold this action; which requests it holds cannot be read from the policy.
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * The one warning: held requests that wait under ten minutes, under Enforce, with no destination
 * that announces approvals. A destination's `approvers` filter is not consulted, because which
 * approvals it carries depends on who is assigned to each.
 */
function Warning({ view }: { view: TenantSettingsView }) {
  const { ApprovalRemedy } = useEdition();
  const bounds = view.approval_windows.flatMap((space) => space.actions.map((item) => item.bound_seconds));
  const short = bounds.filter((bound): bound is number => bound !== null && bound < SHORT_WINDOW_SECONDS);
  if (view.mode.value !== "ENFORCE" || short.length === 0 || announces(view.destinations)) return null;
  const all = short.length === bounds.length;
  return (
    <div className="notice notice-hold readiness-warning">
      <p>
        {all ? "Held requests" : "Some held requests"} here wait at most {spanWords(Math.max(...short))} and are announced
        nowhere but this console. Unless a reviewer is watching <Link to="/approvals">Approvals</Link>, they lapse.
      </p>
      {ApprovalRemedy !== null ? <ApprovalRemedy /> : <OperatorRemedy />}
    </div>
  );
}

/** Core's remedy: destinations are this deployment's configuration, and where to read about it. */
function OperatorRemedy() {
  const service = useService();
  return (
    <p>
      Destinations are operator configuration, set in this deployment&apos;s private configuration file (see
      Notifications and webhooks in the operator documentation).
      {service.help_url !== null ? (
        <>
          {" "}
          <a href={service.help_url}>Open the documentation</a>
        </>
      ) : null}
    </p>
  );
}
