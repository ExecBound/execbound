// SPDX-License-Identifier: AGPL-3.0-only
// The phone's navigation (#678): Menu opens this sheet from the left with the same grouped list
// the sidebar shows, its pills and Ask included where they are, rather than a search box that
// raises the soft keyboard.
// The Close button takes the focus. Choosing an entry closes the sheet and the new page's heading
// takes the focus. The sheet only navigates: no page's own action is in it.

import { useRef } from "react";

import { DialogClose, DialogSurface, DialogTitle } from "../components/ui/dialog";
import { useEdition } from "../edition/context";
import { moveFocusNext } from "../lib/focus";
import { useSession } from "../lib/session";
import { useShellActions } from "./actions";
import { Icon } from "./icons";
import { FOOTER, mainEntries, visible } from "./navigation";
import { NavigationGroups, useNavigationItem } from "./NavigationList";
import { SignOut } from "./SignOut";
import "./surfaces.css";

export default function NavigationSheet({ onClose }: { onClose: () => void }) {
  const session = useSession();
  const { navigation, paletteLinks } = useEdition();
  const { openPalette } = useShellActions();
  const close = useRef<HTMLButtonElement>(null);
  const leaving = useRef(false);
  const features = { assistant: session.assistant, invitations: session.invitations, permissions: session.permissions };
  const entries = visible(mainEntries(navigation), session.role, features);
  const footer = visible(FOOTER, session.role, features);
  // An edition's actions, where the session holds each one's feature, as plain links.
  const links = paletteLinks.filter((link) => session.features.includes(link.feature));
  const choose = () => {
    moveFocusNext();
    leaving.current = true;
    onClose();
  };
  const item = useNavigationItem({ onChoose: choose });
  const name = session.assistant ? "Search or ask" : "Search";
  return (
    <DialogSurface
      open
      className="nav-sheet"
      initialFocus={close}
      finalFocus={() => !leaving.current}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <header className="drawer-head">
        <DialogTitle className="drawer-title">Menu</DialogTitle>
        <DialogClose ref={close} className="btn btn-icon btn-ghost" aria-label="Close">
          <Icon name="close" />
        </DialogClose>
      </header>
      <nav className="nav-sheet-body" aria-label="Menu">
        <button
          type="button"
          className="search"
          onClick={() => {
            leaving.current = true;
            onClose();
            openPalette();
          }}
        >
          <Icon name="search" />
          <span>{name}</span>
        </button>
        <NavigationGroups entries={entries} item={item} />
        <ul className="nav-list nav-sheet-foot">{footer.map(item)}</ul>
        {links.length > 0 ? (
          <div className="nav-section">
            <p className="nav-group">Actions</p>
            <ul className="nav-list" aria-label="Actions">
              {links.map((link) => (
                <li key={link.href}>
                  {/* A server page, not one of the console's: the browser leaves for it. */}
                  <a className="nav-link" href={link.href}>
                    <Icon name={link.icon} />
                    <span className="nav-label">{link.label}</span>
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        <div className="account">
          <span className="nav-label account-name">
            <strong>{session.person.label}</strong>
            {session.person.detail !== "" ? <small>{session.person.detail}</small> : null}
          </span>
          <SignOut className="account-out" />
        </div>
      </nav>
    </DialogSurface>
  );
}
