// SPDX-License-Identifier: AGPL-3.0-only
import type { ReactNode } from "react";

import { Icon } from "../../shell/icons";
import { DialogClose, DialogSurface, DialogTitle } from "./dialog";

/**
 * The detail drawer: 468 px from the top bar to the bottom, over the scrim. It is controlled,
 * so a page keeps its open state in the URL (`?open=<id>`) and a link or the back button
 * restores it (#333). The dialog behind it arrives on first open.
 */
export function Drawer({
  open,
  onClose,
  title,
  eyebrow,
  actions,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  eyebrow?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <DialogSurface
      open={open}
      className="drawer"
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <header className="drawer-head">
        <div>
          {eyebrow !== undefined ? <div className="drawer-eyebrow">{eyebrow}</div> : null}
          <DialogTitle className="drawer-title">{title}</DialogTitle>
        </div>
        <DialogClose className="btn btn-icon btn-ghost" aria-label="Close">
          <Icon name="close" />
        </DialogClose>
      </header>
      {/* The body scrolls, so it is a region the keyboard can reach and scroll (axe's
          scrollable-region-focusable), named for what it holds. */}
      <div className="drawer-body" role="region" aria-label={`${title}, details`} tabIndex={0}>
        {children}
      </div>
      {actions !== undefined ? <footer className="drawer-foot">{actions}</footer> : null}
    </DialogSurface>
  );
}
