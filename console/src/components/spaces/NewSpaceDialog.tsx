// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";

import { createSpaceMutation } from "../../api/@tanstack/react-query.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { SpaceFormDialog } from "./SpaceFormDialog";

/**
 * `New space`, from the sidebar switcher and from the Spaces page. A tenant
 * administrator names it and gives it a detail line; membership is assigned afterwards, on
 * the space's own page, because a members table does not fit a sidebar popover at 390 px.
 *
 * It is the default export of its own module so the switcher can fetch it the first time an
 * administrator opens it, which keeps the dialog out of the shell's chunk on every page.
 */
export default function NewSpaceDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated?: (spaceId: string) => void;
}) {
  const queryClient = useQueryClient();
  const create = useServerMutation({
    ...createSpaceMutation(),
    onSuccess: (created) => {
      toast("Space created.");
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listSpaces" }] });
      onCreated?.(created.space_id);
      onClose();
    },
  });
  return (
    <SpaceFormDialog
      open={open}
      title="New space"
      confirm="Create space"
      lead="A space divides ownership and view inside this tenant. The tenant stays the security boundary: a space is not isolation."
      pending={create.isPending}
      error={create.error}
      onSubmit={(name, detail) => {
        create.mutate({ body: { name, detail } });
      }}
      onClose={() => {
        create.reset();
        onClose();
      }}
    />
  );
}
