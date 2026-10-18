// SPDX-License-Identifier: AGPL-3.0-only
import type {
  DialogCloseProps,
  DialogPopupProps,
  DialogRootChangeEventDetails,
  DialogTitleProps,
} from "@base-ui/react/dialog";
import { createContext, lazy, Suspense, useContext, useState, type ReactNode } from "react";

// Base UI's dialog is about 19 KB compressed. Every dialog in the kit reaches it through this
// one dynamic import, so it is fetched the first time a dialog opens instead of riding in the
// shell's chunk on every page (#333). The import above is a type-only import
// and is erased, so this module carries no dialog code of its own.
const DialogPanel = lazy(() => import("./DialogPanel"));

/** Why the dialog is closing, as Base UI reports it; `close-press` is the dialog's own button. */
export type DialogClosing = DialogRootChangeEventDetails;

/**
 * The parts the lazily loaded panel hands down, so a caller can title and close a dialog
 * without importing one itself.
 */
export interface DialogParts {
  Title: (props: DialogTitleProps) => ReactNode;
  Close: (props: DialogCloseProps) => ReactNode;
}

export const DialogPartsContext = createContext<DialogParts | null>(null);

export interface DialogSurfaceProps {
  open: boolean;
  onOpenChange: (open: boolean, closing: DialogClosing) => void;
  /** The class of the popup element itself: `drawer`, `dialog`, `dialog dialog-wide`. */
  className: string;
  /** The class of the scrim; `scrim scrim-over` for a dialog that opens over another one. */
  backdropClassName?: string;
  initialFocus?: DialogPopupProps["initialFocus"];
  /** Where the focus goes on closing; by default, back to what opened the dialog. */
  finalFocus?: DialogPopupProps["finalFocus"];
  children: ReactNode;
}

/**
 * The scrim and the popup. Nothing renders, and nothing is fetched, until `open` is first true;
 * from then on the panel stays mounted, so closing and reopening behave as they always did.
 */
export function DialogSurface({
  open,
  onOpenChange,
  className,
  backdropClassName,
  initialFocus,
  finalFocus,
  children,
}: DialogSurfaceProps) {
  const [reached, setReached] = useState(open);
  if (open && !reached) setReached(true);
  if (!reached) return null;
  return (
    <Suspense fallback={null}>
      <DialogPanel
        open={open}
        onOpenChange={onOpenChange}
        className={className}
        backdropClassName={backdropClassName}
        initialFocus={initialFocus}
        finalFocus={finalFocus}
      >
        {children}
      </DialogPanel>
    </Suspense>
  );
}

function useParts(part: string): DialogParts {
  const parts = useContext(DialogPartsContext);
  if (parts === null) throw new Error(`A dialog ${part} belongs inside a DialogSurface.`);
  return parts;
}

/** The dialog's accessible name. It must be rendered, or the dialog has none. */
export function DialogTitle(props: DialogTitleProps) {
  const { Title } = useParts("title");
  return <Title {...props} />;
}

/** A control that closes the dialog it sits in. */
export function DialogClose(props: DialogCloseProps) {
  const { Close } = useParts("close");
  return <Close {...props} />;
}
