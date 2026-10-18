// SPDX-License-Identifier: AGPL-3.0-only
import type { SubmitEvent } from "react";

import type { ApprovalDetail } from "../api/types.gen";
import { Button } from "../components/ui/Button";
import { Deadline } from "../components/ui/Time";
import { useSession } from "../lib/session";

export type Decision = "APPROVE" | "DENY";

/**
 * The decision, restated where the buttons are (#678): which workspace and space it is made in,
 * what approving does and what reverses it, the deadline in the one form every page uses, and
 * the quorum so far. Approve and Refuse carry equal emphasis, each tinted in its own tone, and
 * each says on a second line what it does; their accessible names begin with the visible word
 * and add the target and the workspace from visually hidden text, never `aria-label`. Agent and
 * catalog strings render as text, each isolated in `<bdi>`.
 */
export function DecisionBar({
  detail,
  now,
  phone,
  deciding,
  comment,
  onComment,
  onDecide,
}: {
  detail: ApprovalDetail;
  now: number;
  phone: boolean;
  deciding: boolean;
  comment: string;
  onComment: (text: string) => void;
  onDecide: (decision: Decision) => void;
}) {
  const session = useSession();
  const item = detail.item;
  const workspace = session.tenant.name;
  const space = detail.space !== null && session.spaces > 1 ? detail.space.name : null;
  // A phone's eyebrow can cut the workspace to a few characters, so the bar always names it
  // there; on a wider screen only where the person can hold more than one workspace or space.
  const scoped = phone || session.canSwitchWorkspaces === true || session.spaces > 1;
  const scope = space === null ? `Deciding in ${workspace}` : `Deciding in ${workspace} · ${space}`;
  const approveLine = `${item.action_label} · ${item.target}`;

  const submit = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (deciding) return;
    const submitter = event.nativeEvent.submitter;
    const decision = submitter instanceof HTMLButtonElement ? submitter.value : "";
    if (decision !== "APPROVE" && decision !== "DENY") return;
    onDecide(decision);
  };

  return (
    <form className="decision-bar" onSubmit={submit} aria-label="Your decision">
      <p className="decision-context">
        {scoped ? (
          <span className="decision-scope" title={scope}>
            <span className="decision-workspace">
              Deciding in <bdi>{workspace}</bdi>
            </span>
            {space !== null ? (
              <span className="decision-space">
                {" · "}
                <bdi>{space}</bdi>
              </span>
            ) : null}
          </span>
        ) : null}
        <span className="decision-facts">
          {detail.effect.reversed_by !== null ? (
            <>
              Reversible by <bdi>{detail.effect.reversed_by}</bdi>
            </>
          ) : (
            "No catalog action reverses this"
          )}
          {" · "}
          <Deadline at={item.expires_at} now={now} />
          {` · ${String(detail.quorum.recorded)} of ${String(detail.quorum.required)} approvals recorded`}
        </span>
      </p>
      <div className="decision-comment">
        <label htmlFor="decision-comment">Comment for the audit record (optional)</label>
        <input
          id="decision-comment"
          name="comment"
          maxLength={500}
          placeholder="Why you decided"
          autoComplete="off"
          value={comment}
          onChange={(event) => {
            onComment(event.target.value);
          }}
        />
      </div>
      {/* Spaces sit between elements, never at an element's edge, so every reader joins the
          visible line and the hidden words into the same accessible name. */}
      <Button type="submit" name="decision" value="DENY" variant="danger" size="decision" className="btn-choice" disabled={deciding}>
        <span className="btn-main">
          Refuse<span className="sr-only">.</span>
        </span>{" "}
        <span className="btn-sub">
          Nothing is sent{" "}
          <span className="sr-only">
            to <bdi>{item.target}</bdi> in <bdi>{workspace}</bdi>
          </span>
        </span>
      </Button>
      <Button type="submit" name="decision" value="APPROVE" variant="allow" size="decision" className="btn-choice" disabled={deciding}>
        <span className="btn-main">Approve</span>{" "}
        <span className="btn-sub" title={approveLine}>
          <bdi>{item.action_label}</bdi> · <bdi>{item.target}</bdi>{" "}
          <span className="sr-only">
            in <bdi>{workspace}</bdi>
          </span>
        </span>
      </Button>
    </form>
  );
}
