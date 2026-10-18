// SPDX-License-Identifier: AGPL-3.0-only
import { useRef, useState } from "react";

import { Button } from "../ui/Button";
import { DialogClose, DialogSurface, DialogTitle } from "../ui/dialog";
import { Icon } from "../../shell/icons";
import { Field } from "../directory/forms";
import { NAME_TAKEN, refusal } from "./words";

export const NAME_MAX = 80;
export const DETAIL_MAX = 160;

/**
 * The name and detail of a space, for creating one and for renaming one. The confirming
 * button waits for the server's answer (#333), and while it waits the dialog
 * cannot be dismissed, so a person never wonders whether a change they closed over went
 * through. Every refusal is this dialog's own sentence, never a string from the server.
 */
export function SpaceFormDialog({
  open,
  title,
  confirm,
  lead,
  name: initialName = "",
  detail: initialDetail = "",
  pending,
  error,
  onSubmit,
  onClose,
}: {
  open: boolean;
  title: string;
  confirm: string;
  lead: string;
  name?: string;
  detail?: string;
  pending: boolean;
  error: unknown;
  onSubmit: (name: string, detail: string | null) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(initialName);
  const [detail, setDetail] = useState(initialDetail);
  const [opened, setOpened] = useState(open);
  const field = useRef<HTMLInputElement | null>(null);
  // Reopening the dialog starts from what is there now rather than from the last attempt.
  // Adjusted while rendering rather than in an effect, so there is no second pass to see.
  if (open !== opened) {
    setOpened(open);
    if (open) {
      setName(initialName);
      setDetail(initialDetail);
    }
  }
  const ready = name.trim() !== "";
  const problem = refusal(error, { CONFLICT: NAME_TAKEN });
  return (
    <DialogSurface
      open={open}
      className="dialog"
      initialFocus={field}
      onOpenChange={(next) => {
        if (!next && !pending) onClose();
      }}
    >
      <header className="drawer-head">
        <DialogTitle className="drawer-title">{title}</DialogTitle>
        <DialogClose className="btn btn-icon btn-ghost" aria-label="Close" disabled={pending}>
          <Icon name="close" />
        </DialogClose>
      </header>
      <div className="dialog-body">
        <p>{lead}</p>
        <Field label="Name">
          <input
            ref={field}
            type="text"
            value={name}
            maxLength={NAME_MAX}
            required
            onChange={(event) => {
              setName(event.target.value);
            }}
          />
        </Field>
        <Field label="Detail" hint="One line under the name, for whose work this space holds.">
          <input
            type="text"
            value={detail}
            maxLength={DETAIL_MAX}
            onChange={(event) => {
              setDetail(event.target.value);
            }}
          />
        </Field>
        {problem !== "" ? (
          <p className="problem" role="alert">
            {problem}
          </p>
        ) : null}
      </div>
      <footer className="dialog-foot">
        <DialogClose className="btn" disabled={pending}>
          Cancel
        </DialogClose>
        <Button
          variant="primary"
          disabled={pending || !ready}
          aria-busy={pending}
          onClick={() => {
            onSubmit(name.trim(), detail.trim() === "" ? null : detail.trim());
          }}
        >
          {confirm}
        </Button>
      </footer>
    </DialogSurface>
  );
}
