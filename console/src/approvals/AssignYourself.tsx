// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";

import { readApprovalOptions } from "../api/@tanstack/react-query.gen";
import { assignPersonScope } from "../api/sdk.gen";
import type { ApprovalDetail } from "../api/types.gen";
import { ConfirmDialog } from "../components/directory/ConfirmDialog";
import { explain } from "../components/directory/errors";
import { useServerMutation } from "../lib/mutation";
import { useSession } from "../lib/session";
import { toast } from "../lib/toast";
import { refusalCode } from "./copy";

/**
 * Assign yourself to review this one request, after saying exactly what that does (#678). The
 * write is `assignPersonScope`, the person page's own: behind the step-up, which the client asks
 * for in place, audited as `approval_scope.assigned`, and never optimistic. An assignment is
 * keyed by action and target without the space, so one the reader holds in another space moves
 * here; the dialog says so, and the confirming button says "Move", before anything is written.
 */
export default function AssignYourself({
  detail,
  spaceName,
  onClose,
}: {
  detail: ApprovalDetail;
  spaceName: string;
  onClose: () => void;
}) {
  const session = useSession();
  const queryClient = useQueryClient();
  const item = detail.item;
  const elsewhere = detail.your_review_elsewhere ?? null;
  // The answer is the person page's detail, or no content where the reader may not administer
  // themselves (their seats reach beyond their own spaces); nothing here reads it.
  const assign = useServerMutation<null, undefined>({
    mutationFn: async () => {
      await assignPersonScope({
        path: { principal_id: session.person.id ?? "" },
        body: { target: detail.canonical_target_id, action: item.action },
        throwOnError: true,
      });
      return null;
    },
    onSuccess: async () => {
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listApprovals" }] });
      const fresh = await queryClient
        .query({ ...readApprovalOptions({ path: { approval_id: item.approval_id } }), staleTime: 0 })
        .catch(() => null);
      toast(
        fresh !== null && fresh.continuation !== null
          ? "You can now decide this request."
          : "Your assignment is recorded, but your access does not let you decide here.",
      );
      onClose();
    },
  });
  return (
    <ConfirmDialog
      open
      title="Assign yourself to review"
      confirm={elsewhere !== null ? `Move my review to ${spaceName}` : "Assign me"}
      pending={assign.isPending}
      error={assign.error}
      explain={(error) => assignRefusal(error, spaceName) ?? explain(error)}
      onConfirm={() => {
        assign.mutate(undefined);
      }}
      onClose={onClose}
    >
      <p>
        Assign yourself to review <bdi>{item.action_label}</bdi> on <bdi>{item.target}</bdi> in <bdi>{spaceName}</bdi>?
      </p>
      {elsewhere !== null ? (
        <p>
          This moves your review of <bdi>{item.action_label}</bdi> on <bdi>{item.target}</bdi> from <bdi>{elsewhere.name}</bdi> to{" "}
          <bdi>{spaceName}</bdi>. You will no longer review it in <bdi>{elsewhere.name}</bdi>.
        </p>
      ) : null}
      <p>
        This is recorded in the audit log. If you use a second factor and last verified it more than 30 minutes ago, you will be
        asked for it.
      </p>
    </ConfirmDialog>
  );
}

/** The self-assignment's refusals, in fixed copy; never the server's text. */
function assignRefusal(error: unknown, space: string): string | null {
  switch (refusalCode(error)) {
    case "INVALID_SPACE":
      return `Choose ${space} before assigning yourself.`;
    case "INVALID_ACTION":
      return "This action cannot be assigned for review.";
    case "FORBIDDEN":
      return `Your role in ${space} cannot assign reviewers.`;
    case "MFA_REQUIRED":
      // The step-up's own copy: the code was not given, and the dialog stays open.
      return null;
    default:
      return "Your assignment was not recorded. Try again.";
  }
}
