// SPDX-License-Identifier: AGPL-3.0-only
import { useRef, useState, type ReactNode } from "react";

import { Icon } from "../../shell/icons";
import { Button } from "../ui/Button";
import { DialogClose, DialogSurface, DialogTitle, type DialogSurfaceProps } from "../ui/dialog";
import { Field, Problem } from "./forms";

/**
 * A change that cannot be undone asks first, and the confirming button waits for the server's
 * answer (#333). When the change needs a reason, the dialog carries the field and
 * the button stays disabled until something is written.
 */
export function ConfirmDialog({
  open,
  title,
  confirm,
  danger = false,
  reason,
  reasonHint,
  pending,
  confirmDisabled = false,
  className,
  error,
  onConfirm,
  onClose,
  children,
  initialFocus,
  finalFocus,
  explain,
}: {
  open: boolean;
  title: string;
  confirm: string;
  danger?: boolean;
  /** The label of the reason field, when the change needs one. */
  reason?: string;
  /** A line under the reason field saying what it is for, when the change says so. */
  reasonHint?: string;
  pending: boolean;
  /** Missing required choices block submission, not dismissal. */
  confirmDisabled?: boolean;
  /** Optional feature-specific layout, in addition to the shared dialog styling. */
  className?: string;
  error: unknown;
  onConfirm: (reason: string) => void;
  onClose: () => void;
  children?: ReactNode;
  initialFocus?: DialogSurfaceProps["initialFocus"];
  /** Where the focus goes when the dialog closes, when the control that opened it may be gone. */
  finalFocus?: DialogSurfaceProps["finalFocus"];
  /** The refusal's sentence, when this dialog gives a code a narrower meaning than the shared one. */
  explain?: (error: unknown) => string;
}) {
  const [text, setText] = useState("");
  const field = useRef<HTMLTextAreaElement | null>(null);
  const body = useRef<HTMLDivElement | null>(null);
  const ready = reason === undefined || text.trim() !== "";
  return (
    <DialogSurface
      open={open}
      className={className === undefined ? "dialog" : `dialog ${className}`}
      initialFocus={initialFocus ?? (() => body.current?.querySelector<HTMLElement>("input, select, textarea, button") ?? field.current ?? true)}
      finalFocus={finalFocus}
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
      <div className="dialog-body" ref={body}>
        {children}
        {reason !== undefined ? (
          <Field label={reason} hint={reasonHint}>
            <textarea
              ref={field}
              value={text}
              maxLength={500}
              rows={3}
              required
              onChange={(event) => {
                setText(event.target.value);
              }}
            />
          </Field>
        ) : null}
        <Problem error={error} explain={explain} />
      </div>
      <footer className="dialog-foot">
        <DialogClose className="btn" disabled={pending}>
          Cancel
        </DialogClose>
        <Button
          variant={danger ? "danger" : "primary"}
          disabled={pending || confirmDisabled || !ready}
          onClick={() => {
            onConfirm(text.trim());
          }}
        >
          {confirm}
        </Button>
      </footer>
    </DialogSurface>
  );
}
