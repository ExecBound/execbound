// SPDX-License-Identifier: AGPL-3.0-only
import { Dialog } from "@base-ui/react/dialog";
import type { ReactNode } from "react";

import { Icon } from "../../shell/icons";
import { Button, type ButtonVariant } from "./Button";

/**
 * A change that needs a reason and a confirmation (#253): a dialog holding the form. The page
 * owns the fields and what happens on submit; the dialog owns the frame, Cancel, the pending
 * state and the refusal line. The confirm button waits for the server's answer (#333), and
 * while it waits the dialog cannot be dismissed, so a person never wonders
 * whether a change they closed over went through.
 */
export function FormDialog({
  open,
  onClose,
  title,
  description,
  confirm,
  variant = "primary",
  pending = false,
  error,
  onSubmit,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description: ReactNode;
  confirm: string;
  variant?: ButtonVariant;
  pending?: boolean;
  error?: string;
  onSubmit: () => void;
  children?: ReactNode;
}) {
  return (
    <Dialog.Root
      open={open}
      onOpenChange={(next) => {
        if (!next && !pending) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Backdrop className="scrim" />
        <Dialog.Popup className="dialog">
          <form
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              if (!pending) onSubmit();
            }}
          >
            <header className="drawer-head">
              <div>
                <Dialog.Title className="drawer-title">{title}</Dialog.Title>
                <Dialog.Description className="dialog-lead">{description}</Dialog.Description>
              </div>
              <Dialog.Close className="btn btn-icon btn-ghost" aria-label="Close" disabled={pending}>
                <Icon name="close" />
              </Dialog.Close>
            </header>
            {children !== undefined ? <div className="dialog-body">{children}</div> : null}
            {error !== undefined ? (
              <p className="fault dialog-fault" role="alert">
                {error}
              </p>
            ) : null}
            <footer className="dialog-foot">
              <Dialog.Close className="btn" disabled={pending}>
                Cancel
              </Dialog.Close>
              <Button type="submit" variant={variant} disabled={pending} aria-busy={pending}>
                {confirm}
              </Button>
            </footer>
          </form>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
