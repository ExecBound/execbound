// SPDX-License-Identifier: AGPL-3.0-only
import { Dialog } from "@base-ui/react/dialog";

import { DialogPartsContext, type DialogParts, type DialogSurfaceProps } from "./dialog";

// The only module in the kit that imports Base UI's dialog, and `DialogSurface` reaches it only
// through a dynamic import, so the bundler keeps it out of the shell and out of every route's
// chunk (#333).
const PARTS: DialogParts = { Title: Dialog.Title, Close: Dialog.Close };

/** The scrim and the popup, with the parts a caller renders inside them. */
export default function DialogPanel({
  open,
  onOpenChange,
  className,
  backdropClassName = "scrim",
  initialFocus,
  finalFocus,
  children,
}: DialogSurfaceProps) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Backdrop className={backdropClassName} />
        <Dialog.Popup className={className} initialFocus={initialFocus} finalFocus={finalFocus}>
          <DialogPartsContext.Provider value={PARTS}>{children}</DialogPartsContext.Provider>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
