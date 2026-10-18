// SPDX-License-Identifier: AGPL-3.0-only
// A test's stand-in for an edition (#496): core's slots with some replaced, so a core
// test can see where a slot sits and what reaches it without any edition's own code.

import type { ReactNode } from "react";

import { EditionContext, type Edition } from "../edition/context";
import { edition as core } from "../edition/core";

export function withEdition(ui: ReactNode, changes: Partial<Edition>): ReactNode {
  return <EditionContext.Provider value={{ ...core, ...changes }}>{ui}</EditionContext.Provider>;
}
