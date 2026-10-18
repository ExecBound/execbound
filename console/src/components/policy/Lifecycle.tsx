// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  activatePolicyBundleMutation,
  previewPolicyBundleMutation,
  readPolicyBundleQueryKey,
  retirePolicyBundleMutation,
  validatePolicyBundleMutation,
} from "../../api/@tanstack/react-query.gen";
import type { ActivationNote, BundleDetail, BundlePreviewView } from "../../api/types.gen";
import { useServerMutation, type ServerMutationOptions } from "../../lib/mutation";
import { can, useSession } from "../../lib/session";
import { toast } from "../../lib/toast";
import { ConfirmDialog } from "../directory/ConfirmDialog";
import { when } from "../directory/format";
import { Field, Problem } from "../directory/forms";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { activatedBy, changeSummary, isWindow, policyName, WINDOWS, type Window } from "./format";
import { PreviewResult } from "./Preview";
import "./policy.css";

type Step = "activate" | "retire" | null;

/** Validate and retire are a confirmation; activation also says what changed and why. */
interface Confirmation {
  confirm: true;
}
interface Activation {
  confirm: true;
  reason: string;
}

interface Variables<Body> {
  path: { bundle_id: string };
  body: Body;
}

const NOT_PREVIEWED =
  "Not previewed. Nothing here says what this policy would decide differently from the one in use.";
const REPLAY = "Nothing is dispatched and no budget, approval or execution state changes.";

/** One lifecycle step: the server's answer replaces the detail, and nothing is optimistic. */
function useStep<Body>(
  bundleId: string,
  options: ServerMutationOptions<BundleDetail, Variables<Body>>,
  done: string,
  onDone: () => void,
) {
  const queryClient = useQueryClient();
  return useServerMutation<BundleDetail, Variables<Body>>({
    ...options,
    onSuccess: (data) => {
      toast(done);
      queryClient.setQueryData(readPolicyBundleQueryKey({ path: { bundle_id: bundleId } }), data);
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listPolicy" }] });
      onDone();
    },
  });
}

function windowWords(window: Window): string {
  return WINDOWS.find(([key]) => key === window)?.[1] ?? window;
}

function Activated({ note }: { note: ActivationNote }) {
  return (
    <p>
      Activated {when(note.at)} by {activatedBy(note)}
      {note.reason === null ? "." : `: ${note.reason}`}
    </p>
  );
}

/**
 * Make this policy live, as three ordered steps: validate, preview, activate (#678).
 *
 * The preview sits inside the stepper, before activation, and nothing replays until the person
 * asks: a preview replays the window they choose, and neither arriving here nor validating is
 * that choice. Activation is still offered without a preview, because a tenant may have no
 * history; its confirmation opens on what the preview found, or on saying none was run, and
 * asks what changed and why. Every step waits for the server, whose answer replaces the detail.
 */
export function Lifecycle({
  detail,
  active,
  comparison,
}: {
  detail: BundleDetail;
  /** The bundle that is the selection now, so activation can name what it replaces. */
  active: { bundle_id: string } | null;
  /** How this policy compares with the one in use, as the rules read, when it can be said. */
  comparison?: string | null;
}) {
  const session = useSession();
  const [open, setOpen] = useState<Step>(null);
  const [window, setWindow] = useState<Window>("7d");
  // The last preview run here. It is this page's own state and not the address: a preview
  // is a replay someone asked for, not a place. It counts only for the content it replayed.
  const [counted, setCounted] = useState<BundlePreviewView | null>(null);
  const close = () => {
    setOpen(null);
  };
  const validate = useStep<Confirmation>(
    detail.bundle_id,
    validatePolicyBundleMutation(),
    "Validated. Preview what it would change before activating it.",
    close,
  );
  const activate = useStep<Activation>(
    detail.bundle_id,
    activatePolicyBundleMutation(),
    "Activated. Admission uses this policy for new requests in the selected Space.",
    close,
  );
  const retire = useStep<Confirmation>(
    detail.bundle_id,
    retirePolicyBundleMutation(),
    "Retired.",
    close,
  );
  const preview = useServerMutation({
    ...previewPolicyBundleMutation(),
    onSuccess: setCounted,
  });
  if (detail.state === "RETIRED") return null;

  const confirmed = { confirm: true } as const;
  const path = { bundle_id: detail.bundle_id };
  const result =
    counted?.bundle_id === detail.bundle_id && counted.content_hash === detail.content_hash ? counted : null;
  const live = detail.state === "ACTIVE" && detail.active;
  const activatable = detail.state === "VALIDATED" || (detail.state === "ACTIVE" && !detail.active);
  const previewable = detail.state === "DRAFT" || activatable;
  const current = detail.state === "DRAFT" ? 1 : live || result !== null ? 3 : 2;
  const step = (number: number) => (current === number ? ("step" as const) : undefined);
  const scope = result?.scope ?? (can(session, "workspace.manage") ? "workspace" : "spaces");
  const lead =
    scope === "workspace"
      ? "Over the decisions this workspace recorded."
      : "Over the decisions recorded in the Spaces you manage.";
  const found = result === null ? null : changeSummary(result);

  return (
    <Card title="Make this policy live">
      <ol className="policy-steps" aria-label="Steps to make this policy live">
        <li aria-current={step(1)}>
          <h3>1. Validate</h3>
          <p className="policy-step-status">{detail.state === "DRAFT" ? "Next" : "Done"}</p>
          {detail.state === "DRAFT" ? (
            <>
              <p className="muted">Checks the draft against this workspace&rsquo;s actions and mappings.</p>
              <Button
                variant="primary"
                disabled={validate.isPending}
                onClick={() => {
                  validate.mutate({ path, body: confirmed });
                }}
              >
                Validate
              </Button>
              <Problem error={validate.error} />
            </>
          ) : null}
        </li>
        <li aria-current={step(2)}>
          <h3>2. Preview</h3>
          <p className="policy-step-status">
            {live ? "Done" : result !== null ? "Previewed" : current === 2 ? "Next" : "Not previewed"}
          </p>
          {previewable ? (
            <>
              <p className="muted">
                {lead} {REPLAY}
              </p>
              <div className="policy-step-controls">
                <Field label="Replay over">
                  <select
                    value={window}
                    onChange={(event) => {
                      if (isWindow(event.target.value)) setWindow(event.target.value);
                    }}
                  >
                    {WINDOWS.map(([key, text]) => (
                      <option key={key} value={key}>
                        {text}
                      </option>
                    ))}
                  </select>
                </Field>
                <Button
                  variant={current === 2 ? "primary" : "default"}
                  disabled={preview.isPending}
                  onClick={() => {
                    preview.mutate({ path, body: { window } });
                  }}
                >
                  {preview.isPending ? "Replaying" : `Preview ${windowWords(window)}`}
                </Button>
              </div>
              <Problem error={preview.error} />
              {result !== null ? <PreviewResult bundleId={detail.bundle_id} result={result} /> : null}
            </>
          ) : null}
        </li>
        <li aria-current={step(3)}>
          <h3>3. Activate</h3>
          <p className="policy-step-status">
            {live ? "Active in this Space" : result !== null ? "Previewed" : "Not previewed"}
          </p>
          {live && detail.activation ? <Activated note={detail.activation} /> : null}
          {!live && found !== null ? <p>{found}</p> : null}
          {activatable ? (
            <Button
              variant={current === 3 ? "primary" : "default"}
              onClick={() => {
                setOpen("activate");
              }}
            >
              Activate
            </Button>
          ) : null}
        </li>
      </ol>
      <div className="policy-actions">
        {detail.state !== "ACTIVE" ? (
          <Button
            variant="danger"
            onClick={() => {
              setOpen("retire");
            }}
          >
            Retire
          </Button>
        ) : (
          <p className="muted">
            {detail.active
              ? "Active policy. Activate a replacement before retiring this version."
              : "Selected by another Space. It cannot be retired while a Space uses it."}
          </p>
        )}
      </div>
      <ConfirmDialog
        open={open === "activate"}
        title="Activate this policy"
        confirm="Activate"
        reason="What changed and why"
        reasonHint="Required, up to 500 characters. Shown on the policy list and kept in the audit record."
        pending={activate.isPending}
        error={activate.error}
        onConfirm={(reason) => {
          activate.mutate({ path, body: { confirm: true, reason } });
        }}
        onClose={close}
      >
        <p>{found ?? NOT_PREVIEWED}</p>
        <p>
          Admission uses this policy for every new request in the selected Space from the moment it
          is activated.
        </p>
        {active === null ? (
          <p>There is no active policy in the selected Space, so nothing stops being its selection.</p>
        ) : (
          <p>
            {policyName(active.bundle_id)} stops being the selection in this Space in the same
            step, and can be selected again later.
          </p>
        )}
        {comparison ? <p className="muted">{comparison}</p> : null}
      </ConfirmDialog>
      <ConfirmDialog
        open={open === "retire"}
        title="Retire this policy"
        confirm="Retire"
        danger
        pending={retire.isPending}
        error={retire.error}
        onConfirm={() => {
          retire.mutate({ path, body: confirmed });
        }}
        onClose={close}
      >
        <p>A retired policy cannot be validated or activated again.</p>
      </ConfirmDialog>
    </Card>
  );
}
