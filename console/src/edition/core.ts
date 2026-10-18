// SPDX-License-Identifier: AGPL-3.0-only
// The core edition (#496): every slot empty, operator commands and watching first offered, and core's own approval remedy (#678). The core build resolves `@edition` here and
// `EditionContext` defaults to it, so a console that names no other edition is exactly core's.

import type { Edition } from "./context";

function Nothing(): null {
  return null;
}

export const edition: Edition = {
  navigation: [],
  TopBarItems: Nothing,
  paletteLinks: [],
  WorkspacePanels: Nothing,
  TenantDefinitions: Nothing,
  AccountPanels: Nothing,
  Welcome: Nothing,
  FixtureHint: Nothing,
  event: () => undefined,
  operatorCommands: true,
  watchFirst: true,
  ApprovalRemedy: null,
};
