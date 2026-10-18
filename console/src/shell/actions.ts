// SPDX-License-Identifier: AGPL-3.0-only
// What the shell can open (#678): the search palette, the keyboard list, the emergency stop
// dialog, the notifications panel and the phone's navigation sheet. The palette, the phone's navigation sheet, Help and the
// keyboard handler all open them through this one context, so each has one way to open.

import { createContext, useContext } from "react";

export interface ShellActions {
  openPalette: () => void;
  openShortcuts: () => void;
  openStop: () => void;
  openNotifications: () => void;
  openSheet: () => void;
}

const nothing = (): void => undefined;

export const ShellActionsContext = createContext<ShellActions>({
  openPalette: nothing,
  openShortcuts: nothing,
  openStop: nothing,
  openNotifications: nothing,
  openSheet: nothing,
});

export function useShellActions(): ShellActions {
  return useContext(ShellActionsContext);
}
