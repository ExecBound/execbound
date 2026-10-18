// SPDX-License-Identifier: AGPL-3.0-only
import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

import "./surfaces.css";

/**
 * From 768 to 1099 px the bar keeps only the last ancestor beside the current page, so the
 * emergency stop stays on screen; the earlier ancestors are behind this one disclosure, as links,
 * and are hidden only while it stands in for them.
 */
export default function MoreCrumbs({ hidden }: { hidden: readonly ReactNode[] }) {
  const [open, setOpen] = useState(false);
  const button = useRef<HTMLButtonElement>(null);
  const id = useId();
  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) button.current?.focus();
  };
  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape" && open) {
      event.stopPropagation();
      close(true);
    }
  };
  const levels = hidden.length === 1 ? "Show 1 more level" : `Show ${String(hidden.length)} more levels`;
  return (
    <li className="crumb-more" onKeyDown={onKeyDown}>
      <button
        ref={button}
        type="button"
        className="crumb-more-button"
        aria-expanded={open}
        aria-controls={id}
        aria-label={levels}
        onClick={() => {
          setOpen((was) => !was);
        }}
      >
        …
      </button>
      {/* The links are the top bar's, built by the router; choosing one closes the list. */}
      <ul
        id={id}
        className="crumb-more-list"
        hidden={!open}
        onClick={(event) => {
          if (event.target instanceof Element && event.target.closest("a") !== null) close(false);
        }}
      >
        {hidden.map((link, index) => (
          <li key={index}>{link}</li>
        ))}
      </ul>
    </li>
  );
}
