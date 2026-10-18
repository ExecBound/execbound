// SPDX-License-Identifier: AGPL-3.0-only
import { Dialog } from "@base-ui/react/dialog";

import { useEdition } from "../../edition/context";
import { useSingleKeys } from "../../lib/keys";
import { useSession } from "../../lib/session";
import { Icon } from "../../shell/icons";
import { allEntries, visible } from "../../shell/navigation";
import { SingleKeysSwitch } from "./SingleKeysSwitch";
import "../../shell/surfaces.css";

/**
 * The keyboard list, on `?`, from Help and from the palette (#333, #678): search, the rows, the
 * pages this person can open with `g` and a letter, and the switch that turns the single-key
 * shortcuts off. No decision, stop or settlement is on the keyboard.
 */
export default function Shortcuts({ open, onClose }: { open: boolean; onClose: () => void }) {
  const session = useSession();
  const { navigation } = useEdition();
  const [single] = useSingleKeys();
  const off = single ? "" : " (off)";
  const pages = visible(allEntries(navigation), session.role, {
    assistant: session.assistant,
    invitations: session.invitations,
    permissions: session.permissions,
  }).filter((entry) => entry.key !== undefined);
  const rows: [string, string][] = [
    ["Ctrl K or Cmd K", session.assistant ? "Search or ask" : "Search"],
    ["j and k", `Move down and up the rows on Activity and Approvals${off}`],
    ["Esc", "Close a drawer, a dialog or the palette"],
    ["?", `This list${off}`],
  ];
  return (
    <Dialog.Root
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Backdrop className="scrim" />
        <Dialog.Popup className="dialog">
          <header className="drawer-head">
            <Dialog.Title className="drawer-title">Keyboard</Dialog.Title>
            <Dialog.Close className="btn btn-icon btn-ghost" aria-label="Close">
              <Icon name="close" />
            </Dialog.Close>
          </header>
          <dl className="keys">
            {rows.map(([keys, does]) => (
              <div key={keys}>
                <dt>
                  <kbd>{keys}</kbd>
                </dt>
                <dd>{does}</dd>
              </div>
            ))}
          </dl>
          <h3 className="keys-heading">Go to a page{off}</h3>
          <dl className="keys">
            {pages.map((entry) => (
              <div key={entry.to}>
                <dt>
                  <kbd>g {entry.key}</kbd>
                </dt>
                <dd>{entry.label}</dd>
              </div>
            ))}
          </dl>
          <div className="keys-foot">
            <SingleKeysSwitch />
          </div>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
